#!/usr/bin/env python3
"""Local loopback OpenAI-compatible shim backed 100% by Antigravity CLI (`agy`).

- Listens on 127.0.0.1:18791 (/v1/chat/completions, /v1/models, /health)
- Uses `--agent pure-llm` (zero tools) + `--model gemini-3.8-flash-low` (stateless rotation)
- Sets `AGY_INTERNAL_OBSERVER=1` and runs inside `$HOME/agy-mem-hub/observer-sandbox`
  to guarantee zero hook recursion
- Reuses a single pinned conversation ID via `--input-format stream-json` for up to
  `ROTATE_MAX_TURNS` turns or `ROTATE_MAX_CONTEXT_TOKENS` (per-step transcript tokens),
  then rotates cleanly to a fresh stateless session with zero `/compact` overhead
- Tracks all historical `observer_cids` in `shim_session.json` so hooks and instinct
  harvesters ignore every rotated observer transcript
- Supports both SSE streaming (`stream: true` with `: keepalive` pings + `usage`)
  and standard JSON (`stream: false`), with 3-attempt OAuth/transient retry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

HOST = os.environ.get("AGY_SHIM_HOST", "127.0.0.1")
PORT = int(os.environ.get("AGY_SHIM_PORT", "18791"))
DEFAULT_MODEL = os.environ.get("AGY_SHIM_MODEL", "gemini-3.8-flash-low")
ALLOW_CALLER_MODEL = os.environ.get("AGY_SHIM_ALLOW_CALLER_MODEL", "0") == "1"
AGY_BIN = os.environ.get("AGY_BIN", str(Path.home() / ".local/bin/agy"))

BASE_DIR = Path(os.environ.get("AGY_MEM_HUB_DIR", str(Path.home() / "agy-mem-hub")))
SANDBOX_DIR = BASE_DIR / "observer-sandbox"
STATE_DIR = BASE_DIR / "state"
STATE_FILE = STATE_DIR / "shim_session.json"
BRAIN_ROOT = Path.home() / ".gemini" / "antigravity-cli" / "brain"

ROTATE_MAX_TURNS = 20
ROTATE_MAX_CONTEXT_TOKENS = 65_000
IDLE_SESSION_TTL = 2400.0  # 40 minutes (avoids 60m OAuth expiry edge)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [agy-llm-shim] %(levelname)s %(message)s",
)
log = logging.getLogger("agy-llm-shim")

TRANSIENT_ERR_MARKERS = (
    "oauth2:",
    "internal_failure",
    "token refresh",
    "error getting token source",
    "context summarization",
    "checkpoint_empty_summary",
    "unavailable",
    "502",
    "503",
    "connection reset",
    "tls handshake timeout",
    "eof",
)


def is_transient_error(msg: str) -> bool:
    low = (msg or "").lower()
    return any(m in low for m in TRANSIENT_ERR_MARKERS)


def load_pinned_cid() -> Optional[str]:
    try:
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            cid = data.get("conversation_id")
            if isinstance(cid, str) and cid.strip():
                return cid.strip()
    except Exception as e:
        log.warning("Failed reading %s: %s", STATE_FILE, e)
    return None


def save_pinned_cid(cid: Optional[str]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        history: list[str] = []
        old_cid: Optional[str] = None
        if STATE_FILE.exists():
            try:
                old_data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                raw_hist = old_data.get("observer_cids") or []
                if isinstance(raw_hist, list):
                    history = [str(x).strip() for x in raw_hist if isinstance(x, str) and x.strip()]
                oc = old_data.get("conversation_id")
                if isinstance(oc, str) and oc.strip():
                    old_cid = oc.strip()
            except Exception:
                pass
        for item in (old_cid, cid):
            if isinstance(item, str) and item.strip():
                clean = item.strip()
                if clean not in history:
                    history.append(clean)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "conversation_id": cid.strip() if isinstance(cid, str) and cid.strip() else None,
                    "observer_cids": history[-200:],
                    "model": DEFAULT_MODEL,
                    "updated_at": time.time(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        tmp.replace(STATE_FILE)
    except Exception as e:
        log.warning("Failed saving %s: %s", STATE_FILE, e)


def _read_latest_step_usage(cid: Optional[str]) -> Optional[tuple[int, int, int]]:
    """Read the last PLANNER_RESPONSE step in transcript.jsonl for single-step (uncached, cache_read, out) tokens."""
    if not cid:
        return None
    tpath = BRAIN_ROOT / cid / ".system_generated" / "logs" / "transcript.jsonl"
    try:
        st_size = tpath.stat().st_size
        if st_size <= 0:
            return None
        tail_bytes = 16384
        seek_pos = max(0, st_size - tail_bytes)
        with open(tpath, "rb") as fb:
            fb.seek(seek_pos)
            chunk = fb.read()
        lines = chunk.splitlines()
        if seek_pos > 0 and lines:
            lines = lines[1:]
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "PLANNER_RESPONSE":
                continue
            u = obj.get("token_usage") or obj.get("usage") or {}
            inp = int(obj.get("input_tokens") or u.get("input_tokens") or 0)
            cr = int(obj.get("cache_read_tokens") or u.get("cache_read_tokens") or 0)
            out = int(obj.get("output_tokens") or u.get("output_tokens") or 0)
            if inp or cr or out:
                return inp, cr, out
    except Exception:
        pass
    return None


def format_messages_as_stateless_prompt(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = [
        "<STATELESS_TASK>",
        "IMPORTANT: Treat this task as completely independent from any prior turns.",
        "Do NOT call any tools. Follow the system/user instructions below strictly and output ONLY the final answer content.",
        "",
    ]
    for msg in messages:
        role = str(msg.get("role") or "user").upper()
        content = msg.get("content", "")
        if isinstance(content, list):
            text_segs = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_segs.append(str(item.get("text", "")))
                elif isinstance(item, str):
                    text_segs.append(item)
            content_str = "\n".join(text_segs)
        else:
            content_str = str(content or "")
        parts.append(f"[{role}]\n{content_str.strip()}\n")
    parts.append("</STATELESS_TASK>")
    return "\n".join(parts)


class AgyObserverPool:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.model: str = DEFAULT_MODEL
        self.cid: Optional[str] = load_pinned_cid()
        self.spawned_at: float = 0.0
        self.last_used_at: float = 0.0
        self.turns_in_session: int = 0
        self.last_step_context_tokens: int = 0
        self._prev_cum_in: int = 0
        self._prev_cum_out: int = 0
        self._stderr_task: Optional[asyncio.Task[None]] = None
        self._stderr_tail: list[str] = []

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    async def _drain_stderr(self, stream: asyncio.StreamReader) -> None:
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                txt = line.decode("utf-8", errors="replace").rstrip()
                if txt:
                    self._stderr_tail.append(txt)
                    if len(self._stderr_tail) > 25:
                        self._stderr_tail = self._stderr_tail[-25:]
        except Exception:
            pass

    async def close_proc(self) -> None:
        proc = self.proc
        self.proc = None
        if self._stderr_task:
            self._stderr_task.cancel()
            self._stderr_task = None
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
        except Exception:
            pass
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
        except Exception:
            pass

    async def ensure_proc(self, model: str) -> None:
        now = time.time()
        if self.is_alive():
            if self.model != model or (now - self.last_used_at) > IDLE_SESSION_TTL:
                await self.close_proc()
            else:
                return

        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
        settings_json = json.dumps({"trustedWorkspaces": [str(SANDBOX_DIR)]})
        cmd = [
            AGY_BIN,
            "--settings",
            settings_json,
            "--agent",
            "pure-llm",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--print-timeout",
            "10m",
            "--dangerously-skip-permissions",
            "--model",
            model,
        ]
        if self.cid:
            # Verify conversation db still exists before resuming
            conv_db = Path.home() / ".gemini" / "antigravity-cli" / "conversations" / f"{self.cid}.db"
            if conv_db.exists():
                cmd.extend(["--conversation", self.cid])
            else:
                self.cid = None
        cmd.extend(["-p", ""])

        env = os.environ.copy()
        env["AGY_INTERNAL_OBSERVER"] = "1"
        env["ECC_SKIP_OBSERVE"] = "1"
        local_bin = str(Path.home() / ".local/bin")
        env["PATH"] = f"{local_bin}:{env.get('PATH', '')}"

        self._stderr_tail = []
        self._prev_cum_in = 0
        self._prev_cum_out = 0
        if self.cid is None:
            self.turns_in_session = 0
            self.last_step_context_tokens = 0
        log.info("Spawning warm agy observer process (model=%s, cid=%s)", model, self.cid or "new")
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(SANDBOX_DIR),
            env=env,
            limit=8 * 1024 * 1024,
        )
        self.model = model
        self.spawned_at = time.time()
        self.last_used_at = self.spawned_at
        if self.proc.stderr:
            self._stderr_task = asyncio.create_task(self._drain_stderr(self.proc.stderr))
        # Allow server_oauth.go (~90ms) to finish loading OAuth token on cold start
        await asyncio.sleep(0.25)

    async def _send_raw_turn(
        self,
        content: str,
        on_delta: Optional[Any] = None,
        timeout_sec: float = 180.0,
    ) -> dict[str, Any]:
        assert self.proc and self.proc.stdin and self.proc.stdout
        payload = json.dumps({"event": "user", "message": {"content": content}}, ensure_ascii=False) + "\n"
        self.proc.stdin.write(payload.encode("utf-8"))
        await self.proc.stdin.drain()

        emitted_len = 0
        latest_text = ""

        async def _read_until_result() -> dict[str, Any]:
            nonlocal emitted_len, latest_text
            assert self.proc and self.proc.stdout
            while True:
                raw_line = await self.proc.stdout.readline()
                if not raw_line:
                    stderr_str = " | ".join(self._stderr_tail[-5:])
                    raise RuntimeError(f"agy stdout EOF (rc={self.proc.returncode}): {stderr_str}")
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ev_type = evt.get("event")
                cid = evt.get("conversation_id")
                if isinstance(cid, str) and cid and cid != self.cid:
                    self.cid = cid
                    save_pinned_cid(cid)

                if ev_type == "assistant_delta":
                    delta = evt.get("delta") or {}
                    resp_chunk = delta.get("response")
                    if isinstance(resp_chunk, str) and resp_chunk:
                        latest_text += resp_chunk
                        if on_delta:
                            await on_delta(resp_chunk)
                        emitted_len = len(latest_text)
                elif ev_type == "step_update":
                    step = evt.get("step") or {}
                    if step.get("step_type") == "planner_response":
                        pr = step.get("planner_response") or {}
                        full = pr.get("modified_response") or pr.get("response") or ""
                        if isinstance(full, str) and len(full) > emitted_len:
                            new_part = full[emitted_len:]
                            latest_text = full
                            emitted_len = len(full)
                            if on_delta and new_part:
                                await on_delta(new_part)
                elif ev_type == "result":
                    res = evt.get("result")
                    result_obj = res if isinstance(res, dict) else evt
                    cid2 = result_obj.get("conversation_id") or evt.get("conversation_id")
                    if isinstance(cid2, str) and cid2 and cid2 != self.cid:
                        self.cid = cid2
                        save_pinned_cid(cid2)
                    final_resp = result_obj.get("response")
                    if isinstance(final_resp, str) and len(final_resp) > emitted_len:
                        new_part = final_resp[emitted_len:]
                        latest_text = final_resp
                        emitted_len = len(final_resp)
                        if on_delta and new_part:
                            await on_delta(new_part)
                    if not isinstance(result_obj.get("response"), str) and latest_text:
                        result_obj["response"] = latest_text
                    return result_obj

        res = await asyncio.wait_for(_read_until_result(), timeout=timeout_sec)
        self.last_used_at = time.time()
        return res

    async def _maybe_rotate(self) -> None:
        if self.turns_in_session < ROTATE_MAX_TURNS and self.last_step_context_tokens < ROTATE_MAX_CONTEXT_TOKENS:
            return
        log.info(
            "Rotating stateless observer session %s (turns=%d, step_ctx_tokens=%d)",
            self.cid,
            self.turns_in_session,
            self.last_step_context_tokens,
        )
        old_cid = self.cid
        self.cid = None
        self.turns_in_session = 0
        self.last_step_context_tokens = 0
        self._prev_cum_in = 0
        self._prev_cum_out = 0
        if old_cid:
            save_pinned_cid(None)
        await self.close_proc()

    async def complete(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
        on_delta: Optional[Any] = None,
    ) -> dict[str, Any]:
        target_model = DEFAULT_MODEL
        if ALLOW_CALLER_MODEL and isinstance(model, str) and model.strip().startswith(("gemini-", "claude-", "gpt-")):
            target_model = model.strip()

        prompt = format_messages_as_stateless_prompt(messages)

        async with self.lock:
            last_err = ""
            for attempt in range(1, 4):
                emitted_any = False

                async def _tracked_delta(chunk: str) -> None:
                    nonlocal emitted_any
                    emitted_any = True
                    if on_delta:
                        await on_delta(chunk)

                try:
                    await self.ensure_proc(target_model)
                    res = await self._send_raw_turn(
                        prompt,
                        on_delta=_tracked_delta if on_delta else None,
                        timeout_sec=180.0,
                    )
                    status = str(res.get("status") or "SUCCESS")
                    if status != "SUCCESS":
                        err_msg = str(res.get("error") or f"agy status={status}")
                        raise RuntimeError(err_msg)

                    # Note: `result["usage"]` is monotonically cumulative across the session; compute delta fallback,
                    # and prefer exact per-step context window size from transcript.jsonl.
                    usage = res.get("usage") or {}
                    cum_in = int(usage.get("input_tokens") or 0) + int(usage.get("cache_read_tokens") or 0)
                    cum_out = int(usage.get("output_tokens") or 0)
                    delta_in = max(0, cum_in - self._prev_cum_in)
                    delta_out = max(0, cum_out - self._prev_cum_out)
                    self._prev_cum_in = cum_in
                    self._prev_cum_out = cum_out

                    step_u = _read_latest_step_usage(self.cid)
                    if step_u is not None:
                        s_in, s_cr, s_out = step_u
                        prompt_tok = s_in + s_cr
                        comp_tok = s_out
                    else:
                        prompt_tok = delta_in
                        comp_tok = delta_out
                    tot_tok = prompt_tok + comp_tok

                    self.turns_in_session += 1
                    self.last_step_context_tokens = prompt_tok

                    # Rotate cleanly to a fresh session on turn/context ceiling (zero /compact overhead)
                    await self._maybe_rotate()

                    return {
                        "model": target_model,
                        "content": str(res.get("response") or ""),
                        "usage": {
                            "prompt_tokens": prompt_tok,
                            "completion_tokens": comp_tok,
                            "total_tokens": tot_tok,
                        },
                    }
                except Exception as e:
                    last_err = str(e)
                    stderr_hint = " | ".join(self._stderr_tail[-4:])
                    combined_err = f"{last_err} {stderr_hint}".strip()
                    log.warning(
                        "Observer attempt %d/3 failed: %s",
                        attempt,
                        combined_err[:300],
                    )
                    await self.close_proc()
                    if "context summarization" in combined_err.lower() or "checkpoint_empty_summary" in combined_err.lower():
                        log.info("Rotating observer session cleanly after context summarization error")
                        self.cid = None
                        self.turns_in_session = 0
                        self.last_step_context_tokens = 0
                        save_pinned_cid(None)
                    if emitted_any or attempt >= 3 or not is_transient_error(combined_err):
                        if attempt >= 3 or emitted_any:
                            break
                        # One extra retry even for unknown cold-start hiccups on attempt 1
                        if attempt > 1:
                            break
                    backoff = 1.4 * attempt + random.uniform(0.15, 0.65)
                    await asyncio.sleep(backoff)

            raise RuntimeError(f"agy observer failed after retries: {last_err}")


POOL = AgyObserverPool()


async def send_json_response(writer: asyncio.StreamWriter, status: int, status_text: str, obj: Any) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    headers = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    writer.write(headers + body)
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        req_line = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if not req_line:
            return
        parts = req_line.decode("latin-1", errors="replace").strip().split(" ")
        if len(parts) < 2:
            return
        method, raw_path = parts[0].upper(), parts[1].split("?", 1)[0]

        headers: dict[str, str] = {}
        while True:
            hline = await asyncio.wait_for(reader.readline(), timeout=15.0)
            if not hline or hline in (b"\r\n", b"\n"):
                break
            decoded = hline.decode("latin-1", errors="replace").strip()
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_len = int(headers.get("content-length", "0") or "0")
        body_bytes = b""
        if content_len > 0:
            body_bytes = await asyncio.wait_for(reader.readexactly(content_len), timeout=30.0)

        if method == "GET" and raw_path in ("/health", "/v1/health"):
            await send_json_response(
                writer,
                200,
                "OK",
                {
                    "status": "ok",
                    "default_model": DEFAULT_MODEL,
                    "pinned_conversation_id": POOL.cid,
                    "warm": POOL.is_alive(),
                    "turns_in_session": POOL.turns_in_session,
                    "last_step_context_tokens": POOL.last_step_context_tokens,
                    "rotate_max_turns": ROTATE_MAX_TURNS,
                },
            )
            return

        if method == "GET" and raw_path in ("/v1/models", "/models"):
            now_int = int(time.time())
            models = [
                DEFAULT_MODEL,
                "gemini-3.8-flash-medium",
                "gemini-3.8-flash-low",
                "gemini-4-hydrogen-low",
            ]
            await send_json_response(
                writer,
                200,
                "OK",
                {
                    "object": "list",
                    "data": [
                        {"id": m, "object": "model", "created": now_int, "owned_by": "antigravity-cli"}
                        for m in dict.fromkeys(models)
                    ],
                },
            )
            return

        if method == "POST" and raw_path in ("/v1/chat/completions", "/chat/completions"):
            try:
                req_json = json.loads(body_bytes.decode("utf-8", errors="replace") or "{}")
            except json.JSONDecodeError as e:
                await send_json_response(
                    writer, 400, "Bad Request", {"error": {"message": f"Invalid JSON: {e}", "type": "invalid_request_error"}}
                )
                return

            messages = req_json.get("messages")
            if not isinstance(messages, list) or not messages:
                await send_json_response(
                    writer, 400, "Bad Request", {"error": {"message": "messages array required", "type": "invalid_request_error"}}
                )
                return

            req_model = req_json.get("model") or DEFAULT_MODEL
            is_stream = bool(req_json.get("stream", False))
            comp_id = f"chatcmpl-{uuid.uuid4().hex[:20]}"
            created_ts = int(time.time())

            if not is_stream:
                try:
                    result = await POOL.complete(messages=messages, model=req_model, on_delta=None)
                    await send_json_response(
                        writer,
                        200,
                        "OK",
                        {
                            "id": comp_id,
                            "object": "chat.completion",
                            "created": created_ts,
                            "model": result["model"],
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {"role": "assistant", "content": result["content"]},
                                    "finish_reason": "stop",
                                }
                            ],
                            "usage": result["usage"],
                        },
                    )
                except Exception as e:
                    log.error("Non-stream completion error: %s", e)
                    await send_json_response(
                        writer,
                        502,
                        "Bad Gateway",
                        {"error": {"message": str(e), "type": "server_error", "code": "agy_upstream_error"}},
                    )
                return

            # Streaming SSE mode (with `: keepalive` heartbeats every 2.5s while queued/thinking)
            sse_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream; charset=utf-8\r\n"
                "Cache-Control: no-cache\r\n"
                "X-Accel-Buffering: no\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(sse_headers)
            await writer.drain()

            write_lock = asyncio.Lock()
            done_event = asyncio.Event()

            async def _sse_write(raw_str: str) -> None:
                async with write_lock:
                    writer.write(raw_str.encode("utf-8"))
                    await writer.drain()

            async def _ping_loop() -> None:
                try:
                    while not done_event.is_set():
                        await asyncio.sleep(2.5)
                        if not done_event.is_set():
                            await _sse_write(": keepalive\n\n")
                except Exception:
                    pass

            ping_task = asyncio.create_task(_ping_loop())
            sent_role = False

            async def _on_delta(chunk_text: str) -> None:
                nonlocal sent_role
                delta_obj: dict[str, Any] = {"content": chunk_text}
                if not sent_role:
                    delta_obj["role"] = "assistant"
                    sent_role = True
                pkt = {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": req_model,
                    "choices": [{"index": 0, "delta": delta_obj, "finish_reason": None}],
                }
                await _sse_write(f"data: {json.dumps(pkt, ensure_ascii=False)}\n\n")

            try:
                result = await POOL.complete(messages=messages, model=req_model, on_delta=_on_delta)
                if not sent_role and result["content"]:
                    await _on_delta(result["content"])
                final_pkt = {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": result["model"],
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": result["usage"],
                }
                await _sse_write(f"data: {json.dumps(final_pkt, ensure_ascii=False)}\n\n")
                await _sse_write("data: [DONE]\n\n")
            except Exception as e:
                log.error("Stream completion error: %s", e)
                err_pkt = {"error": {"message": str(e), "type": "server_error", "code": "agy_upstream_error"}}
                try:
                    await _sse_write(f"data: {json.dumps(err_pkt, ensure_ascii=False)}\n\n")
                except Exception:
                    pass
            finally:
                done_event.set()
                ping_task.cancel()
            return

        await send_json_response(writer, 404, "Not Found", {"error": {"message": f"Unknown route {raw_path}"}})
    except Exception as e:
        log.debug("Client connection handling error: %s", e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    server = await asyncio.start_server(handle_client, HOST, PORT)
    log.info("agy-llm-shim listening on http://%s:%d (default_model=%s, pinned_cid=%s)", HOST, PORT, DEFAULT_MODEL, POOL.cid)

    stop_ev = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_ev.set)
        except NotImplementedError:
            pass

    async with server:
        await stop_ev.wait()

    log.info("Shutting down warm agy observer process...")
    await POOL.close_proc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
