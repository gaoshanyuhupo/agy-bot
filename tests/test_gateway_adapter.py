#!/usr/bin/env python3
"""Offline unit & integration tests for multi-gateway adapter and hybrid routing."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import cli  # noqa: E402
import cost_usage  # noqa: E402
import gateway_adapter  # noqa: E402
import model_failover  # noqa: E402


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "HOME": tmp,
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_ADMIN_USERS": "",
        "AGY_TG_READONLY_USERS": "",
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_FALLBACK_MODELS": "",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_GATEWAY_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_TG_GATEWAYS_FILE": "",
        "AGY_TG_GATEWAYS_JSON": "",
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
    }
    if extra_env:
        env_patch.update(extra_env)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import access_control  # noqa: E402
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(access_control)
        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge


class TestGatewayAdapterCore(unittest.TestCase):
    """Pure unit tests for dialects, URL building, model resolution, and SSE normalization."""

    def test_upstream_url_preserves_versioned_paths(self):
        self.assertEqual(
            "https://api.example.com/api/paas/v4/chat/completions",
            gateway_adapter.build_upstream_url("https://api.example.com/api/paas/v4", "/chat/completions"),
        )
        self.assertEqual(
            "https://api.example.com/api/v3/models",
            gateway_adapter.build_upstream_url("https://api.example.com/api/v3/", "/models"),
        )
        self.assertEqual(
            "https://api.example.com/v1beta/openai/chat/completions",
            gateway_adapter.build_upstream_url("https://api.example.com/v1beta/openai", "/chat/completions"),
        )
        self.assertEqual(
            "http://127.0.0.1:8317/v1/chat/completions",
            gateway_adapter.build_upstream_url("http://127.0.0.1:8317/v1", "/chat/completions"),
        )
        self.assertEqual(
            "http://127.0.0.1:9000/v1/models",
            gateway_adapter.build_upstream_url("http://127.0.0.1:9000", "/models"),
        )

    def test_slash_model_resolution_never_naively_splits_slash(self):
        gws = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "cpa",
                    "name": "CPA",
                    "base_url": "http://127.0.0.1:8317/v1",
                    "dialect": "cpa",
                    "api_key": "MOCK_KEY_CPA_01",
                    "models": ["team/gpt-6.1-sol", "magpie/sub/model-x"],
                    "exclude_models": ["*-image*"],
                },
                {
                    "id": "zhipu",
                    "name": "Zhipu",
                    "base_url": "https://api.example.com/api/paas/v4",
                    "dialect": "zhipu",
                    "api_key": "MOCK_KEY_ZHIPU_01",
                    "models": ["glm-5.3-flash"],
                },
            ]
        )
        native = [
            ("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"),
            ("gemini-3.8-flash-low", "Gemini 3.8 Flash (Low)"),
        ]
        catalogs = {
            "cpa": ["team/gpt-6.1-sol", "magpie/sub/model-x"],
            "zhipu": ["glm-5.3-flash"],
        }

        res1 = gateway_adapter.resolve_model_target(
            "team/gpt-6.1-sol", gateways=gws, native_models=native, gateway_catalogs=catalogs
        )
        self.assertTrue(res1.is_gateway)
        self.assertEqual("cpa", res1.gateway_id)
        self.assertEqual("team/gpt-6.1-sol", res1.upstream_model)

        res2 = gateway_adapter.resolve_model_target(
            "gw:cpa:magpie/sub/model-x", gateways=gws, native_models=native, gateway_catalogs=catalogs
        )
        self.assertTrue(res2.is_gateway)
        self.assertEqual("cpa", res2.gateway_id)
        self.assertEqual("magpie/sub/model-x", res2.upstream_model)

        res3 = gateway_adapter.resolve_model_target(
            "glm-5.3-flash", gateways=gws, native_models=native, gateway_catalogs=catalogs
        )
        self.assertTrue(res3.is_gateway)
        self.assertEqual("zhipu", res3.gateway_id)

        res_nat = gateway_adapter.resolve_model_target(
            "gemini-4-hydrogen-high", gateways=gws, native_models=native, gateway_catalogs=catalogs
        )
        self.assertFalse(res_nat.is_gateway)
        self.assertEqual("native", res_nat.kind)

    def test_resolve_model_target_fallback_respects_include_and_exclude_filters(self):
        gws = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "cpa",
                    "name": "CPA",
                    "base_url": "http://127.0.0.1:8317/v1",
                    "dialect": "cpa",
                    "exclude_models": ["*-image*"],
                },
                {
                    "id": "zhipu",
                    "name": "Zhipu",
                    "base_url": "https://api.example.com/api/paas/v4",
                    "dialect": "zhipu",
                    "include_models": ["glm-*"],
                },
            ]
        )
        # Empty catalogs (cold/offline): team/gpt-image-1 is excluded by cpa and NOT included by zhipu
        res_img = gateway_adapter.resolve_model_target(
            "team/gpt-image-1", gateways=gws, native_models=(), gateway_catalogs={}
        )
        self.assertFalse(res_img.is_gateway)
        self.assertEqual("native", res_img.kind)

        # Unknown non-excluded model when zhipu requires glm-* falls back only to cpa
        res_other = gateway_adapter.resolve_model_target(
            "vendor/custom-model", gateways=gws, native_models=(), gateway_catalogs={}
        )
        self.assertTrue(res_other.is_gateway)
        self.assertEqual("cpa", res_other.gateway_id)

        # glm-5.3-flash matches zhipu include_models cleanly
        res_glm = gateway_adapter.resolve_model_target(
            "glm-5.3-flash", gateways=gws, native_models=(), gateway_catalogs={}
        )
        self.assertTrue(res_glm.is_gateway)
        self.assertEqual("zhipu", res_glm.gateway_id)

    def test_infer_quirk_from_400_no_redundant_retry_when_cap_unchanged(self):
        gw = gateway_adapter.parse_gateways_payload(
            [{"id": "strict", "base_url": "http://127.0.0.1:9001/v1", "dialect": "zhipu", "max_tokens_cap": 2048}]
        )["strict"]
        # parsed_limit=4096 -> halved candidate is 2048, which already equals prev_cap=2048 -> must return None
        res_eq = gateway_adapter.infer_quirk_from_400(
            "max_tokens must be <= 4096",
            {"max_tokens": 2048},
            {},
            gw,
        )
        self.assertIsNone(res_eq)

        # prev_cap=1024 with parsed_limit=2048 -> halved candidate is 1024 == prev_cap -> must return None
        res_floor = gateway_adapter.infer_quirk_from_400(
            "max_tokens must be <= 2048",
            {"max_tokens": 1024},
            {"max_tokens_cap": 1024},
            gw,
        )
        self.assertIsNone(res_floor)

        # prev_cap=1024 with parsed_limit=4096 -> must NOT raise cap back to 2048
        res_no_raise = gateway_adapter.infer_quirk_from_400(
            "max_tokens must be <= 4096",
            {"max_tokens": 1024},
            {"max_tokens_cap": 1024},
            gw,
        )
        self.assertIsNone(res_no_raise)

        # Strictly lower cap (2048 -> 1024) still adapts once
        res_lower = gateway_adapter.infer_quirk_from_400(
            "max_tokens must be <= 2048",
            {"max_tokens": 2048},
            {"max_tokens_cap": 2048},
            gw,
        )
        self.assertEqual(1024, res_lower["max_tokens_cap"])

    def test_runtime_state_invalidates_quirks_and_key_cache_on_config_change(self):
        rt = gateway_adapter.GatewayRuntimeState()
        gw1 = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "vault_gw",
                    "base_url": "http://127.0.0.1:8317/v1",
                    "dialect": "cpa",
                    "api_key_cmd": [sys.executable, "-c", "print('KEY_V1')"],
                }
            ]
        )["vault_gw"]
        self.assertEqual("KEY_V1", rt.resolve_api_key(gw1))
        rt.update_quirks(gw1, {"strip_stream_options": True})
        self.assertEqual({"strip_stream_options": True}, rt.get_quirks(gw1))

        # Changing api_key_cmd / base_url / dialect must invalidate both key cache and learned quirks
        gw2 = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "vault_gw",
                    "base_url": "http://127.0.0.1:8318/v1",
                    "dialect": "openai_strict",
                    "api_key_cmd": [sys.executable, "-c", "print('KEY_V2')"],
                }
            ]
        )["vault_gw"]
        self.assertEqual({}, rt.get_quirks(gw2))
        self.assertEqual("KEY_V2", rt.resolve_api_key(gw2))

    def test_transform_chat_request_dialects(self):
        strict_gw = gateway_adapter.parse_gateways_payload(
            [{"id": "strict", "base_url": "http://127.0.0.1:9001/v1", "dialect": "zhipu", "max_tokens_cap": 4096}]
        )["strict"]
        raw_req = {
            "model": "glm-5.3-flash",
            "stream": True,
            "stream_options": {"include_usage": True},
            "max_completion_tokens": 65535,
            "messages": [
                {"role": "system", "content": [{"type": "text", "text": "sys1"}, {"type": "text", "text": "sys2"}]},
                {"role": "user", "content": [{"type": "text", "text": "hi"}, {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}]},
            ],
        }
        out_strict = gateway_adapter.transform_chat_request(raw_req, strict_gw, upstream_model="glm-5.3-flash", effort="high")
        self.assertEqual("sys1\nsys2", out_strict["messages"][0]["content"])
        self.assertIsInstance(out_strict["messages"][1]["content"], list)
        self.assertNotIn("stream_options", out_strict)
        self.assertNotIn("max_completion_tokens", out_strict)
        self.assertEqual(4096, out_strict["max_tokens"])
        self.assertNotIn("reasoning_effort", out_strict)

        cpa_gw = gateway_adapter.parse_gateways_payload(
            [{"id": "cpa", "base_url": "http://127.0.0.1:8317/v1", "dialect": "cpa"}]
        )["cpa"]
        out_cpa = gateway_adapter.transform_chat_request(raw_req, cpa_gw, upstream_model="team/gpt-6.1-sol", effort="high")
        self.assertEqual("high", out_cpa["reasoning_effort"])
        self.assertEqual("team/gpt-6.1-sol", out_cpa["model"])
        self.assertEqual(65535, out_cpa["max_completion_tokens"])
        self.assertIn("stream_options", out_cpa)

        paren_gw = gateway_adapter.parse_gateways_payload(
            [{"id": "p2api", "base_url": "http://127.0.0.1:9002/v1", "dialect": "openai_2api"}]
        )["p2api"]
        out_paren = gateway_adapter.transform_chat_request(raw_req, paren_gw, upstream_model="gpt-5", effort="high")
        self.assertEqual("gpt-5(high)", out_paren["model"])
        self.assertNotIn("reasoning_effort", out_paren)

    def test_sse_and_json_normalization_fixes_tool_calls_and_indices(self):
        # Non-streaming JSON with tool_calls + finish_reason="stop" -> SSE stream
        completion = {
            "id": "cmpl-1",
            "model": "team/gpt-6.1-sol",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "reasoning_content": "thinking step",
                        "content": "",
                        "tool_calls": [
                            {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}},
                        ],
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        frames = gateway_adapter.json_completion_to_sse_chunks(completion)
        joined = b"".join(frames).decode("utf-8")
        self.assertIn('"reasoning_content": "thinking step"', joined)
        self.assertIn('"index": 0', joined)
        self.assertIn('"finish_reason": "tool_calls"', joined)
        self.assertIn('"choices": []', joined)
        self.assertTrue(joined.endswith("data: [DONE]\n\n"))

        # Streaming SSE normalizer: comment preservation, missing tool_calls index, finish_reason fix, EOF [DONE]
        norm = gateway_adapter.SSEStreamNormalizer()
        lines = [
            ": OPENROUTER PROCESSING",
            'data: {"id":"c1","choices":[{"index":0,"delta":{"reasoning_content":"r1"},"finish_reason":null}]}',
            'data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"id":"tc_a","type":"function","function":{"name":"read_file","arguments":"{\\"Path\\":"}}]},"finish_reason":null}]}',
            'data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"\\"x\\"}"}}]},"finish_reason":null}]}',
            'data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
            'data: {"id":"c1","choices":[],"usage":{"total_tokens":42}}',
        ]
        out_frames = [norm.process_line(ln) for ln in lines]
        tail = norm.finalize()
        if tail:
            out_frames.append(tail)
        text = b"".join(f for f in out_frames if f).decode("utf-8")
        self.assertIn(": OPENROUTER PROCESSING", text)
        self.assertIn('"index": 0', text)
        self.assertIn('"finish_reason": "tool_calls"', text)
        self.assertIn('"total_tokens": 42', text)
        self.assertTrue(text.endswith("data: [DONE]\n\n"))

    def test_secret_never_leaked_in_repr_and_api_key_cmd_resolved(self):
        gw = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "vault_gw",
                    "base_url": "http://127.0.0.1:8317/v1",
                    "dialect": "cpa",
                    "api_key_cmd": [sys.executable, "-c", "print('MOCK_CMD_SECRET_999')"],
                }
            ]
        )["vault_gw"]
        self.assertNotIn("MOCK_CMD_SECRET_999", repr(gw))
        rt = gateway_adapter.GatewayRuntimeState()
        self.assertEqual("MOCK_CMD_SECRET_999", rt.resolve_api_key(gw))


class TestGatewayAdapterHTTPIntegration(unittest.TestCase):
    """End-to-end HTTP loopback tests with strict mock upstream gateways."""

    def test_strict_gateway_adaptive_400_fallback_and_per_route_isolation(self):
        captured: list[dict] = []
        lock = threading.Lock()

        class _StrictHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):  # noqa: A002
                return

            def _reply_json(self, code: int, obj: dict):
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):  # noqa: N802
                if self.path.endswith("/models"):
                    self._reply_json(200, {"object": "list", "data": [{"id": "strict/model-a", "object": "model"}]})
                    return
                self._reply_json(404, {"error": {"message": "not found"}})

            def do_POST(self):  # noqa: N802
                clen = int(self.headers.get("Content-Length") or "0")
                body = json.loads(self.rfile.read(clen).decode("utf-8"))
                auth = self.headers.get("Authorization", "")
                with lock:
                    captured.append({"path": self.path, "auth": auth, "body": body})

                if auth != "Bearer MOCK_UPSTREAM_SECRET":
                    self._reply_json(401, {"error": {"message": "invalid_api_key"}})
                    return
                if isinstance((body.get("messages") or [{}])[0].get("content"), list):
                    self._reply_json(400, {"error": {"message": "messages[0].content must be a string"}})
                    return
                if "stream_options" in body:
                    self._reply_json(400, {"error": {"message": "Unknown parameter: stream_options"}})
                    return
                if "max_completion_tokens" in body:
                    self._reply_json(400, {"error": {"message": "Extra inputs are not permitted: max_completion_tokens"}})
                    return
                if int(body.get("max_tokens") or 0) > 4096:
                    self._reply_json(400, {"error": {"message": "max_tokens must be <= 4096"}})
                    return

                # Return non-streaming JSON despite stream=True + finish_reason="stop" with tool_calls
                self._reply_json(
                    200,
                    {
                        "id": "cmpl-strict",
                        "model": body["model"],
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "",
                                    "tool_calls": [
                                        {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}
                                    ],
                                },
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StrictHandler)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()

        # Deliberately misconfigure dialect as `cpa` so adaptive 400 fallback has to self-heal!
        gws = gateway_adapter.parse_gateways_payload(
            [
                {
                    "id": "strict_mock",
                    "base_url": f"http://127.0.0.1:{up_port}/api/paas/v4",
                    "dialect": "cpa",
                    "api_key": "MOCK_UPSTREAM_SECRET",
                    "adaptive_400_fallback": True,
                }
            ]
        )
        adapter = gateway_adapter.GatewayAdapterServer(gws, port=0)
        adapter.start()
        try:
            route_hi = adapter.register_route("strict_mock", "strict/model-a", effort="high")
            route_lo = adapter.register_route("strict_mock", "strict/model-a", effort="low")
            self.assertNotEqual(route_hi.token, route_lo.token)
            self.assertNotEqual("MOCK_UPSTREAM_SECRET", route_hi.local_api_key)

            m_resp = requests.get(f"{route_hi.url}/models", headers={"Authorization": f"Bearer {route_hi.local_api_key}"}, timeout=5)
            self.assertEqual(200, m_resp.status_code)
            self.assertIn("strict/model-a", [x["id"] for x in m_resp.json()["data"]])

            # Request 1: triggers adaptive 400 self-healing (up to 2 retries? 3 quirks -> let's verify multiple requests converge!)
            req_payload = {
                "model": "strict/model-a",
                "stream": True,
                "stream_options": {"include_usage": True},
                "max_completion_tokens": 65535,
                "messages": [
                    {"role": "system", "content": [{"type": "text", "text": "sys"}]},
                    {"role": "user", "content": "hello"},
                ],
            }
            # First call heals system list + stream_options (or hits cap on 3rd attempt), second call uses learned quirks and succeeds cleanly
            r1 = requests.post(
                f"{route_hi.url}/chat/completions",
                json=req_payload,
                headers={"Authorization": f"Bearer {route_hi.local_api_key}"},
                timeout=5,
            )
            if r1.status_code != 200:
                r1 = requests.post(
                    f"{route_hi.url}/chat/completions",
                    json=req_payload,
                    headers={"Authorization": f"Bearer {route_hi.local_api_key}"},
                    timeout=5,
                )
            self.assertEqual(200, r1.status_code, r1.text)
            self.assertIn("text/event-stream", r1.headers.get("Content-Type", ""))
            self.assertIn('"finish_reason": "tool_calls"', r1.text)
            self.assertIn("data: [DONE]", r1.text)

            with lock:
                self.assertTrue(all(c["path"] == "/api/paas/v4/chat/completions" for c in captured))
                self.assertTrue(all(c["auth"] == "Bearer MOCK_UPSTREAM_SECRET" for c in captured))
                final_body = captured[-1]["body"]
                self.assertEqual("high", final_body["reasoning_effort"])
                self.assertEqual("sys", final_body["messages"][0]["content"])
                self.assertLessEqual(final_body["max_tokens"], 4096)
        finally:
            adapter.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_openai_2api_model_paren_effort_rewrite_over_http(self):
        seen_models: list[str] = []

        class _ParenHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):  # noqa: A002
                return

            def do_POST(self):  # noqa: N802
                clen = int(self.headers.get("Content-Length") or "0")
                body = json.loads(self.rfile.read(clen).decode("utf-8"))
                seen_models.append(str(body.get("model")))
                raw = json.dumps(
                    {
                        "id": "cmpl-paren",
                        "model": body.get("model"),
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

        up = ThreadingHTTPServer(("127.0.0.1", 0), _ParenHandler)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        gws = gateway_adapter.parse_gateways_payload(
            [{"id": "p2api", "base_url": f"http://127.0.0.1:{up.server_address[1]}/v1", "dialect": "openai_2api"}]
        )
        adapter = gateway_adapter.GatewayAdapterServer(gws, port=0)
        adapter.start()
        try:
            rt = adapter.register_route("p2api", "gpt-5", effort="high")
            resp = requests.post(
                f"{rt.url}/chat/completions",
                json={"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}]},
                timeout=5,
            )
            self.assertEqual(200, resp.status_code)
            self.assertEqual(["gpt-5(high)"], seen_models)
        finally:
            adapter.stop()
            up.shutdown()
            up.server_close()

    def test_sse_stream_without_charset_preserves_chinese_and_emoji_utf8(self):
        sample_text = "中文测试通过🚀，多字节边界稳态校验！"

        class _NoCharsetSSEHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):  # noqa: A002
                return

            def do_POST(self):  # noqa: N802
                clen = int(self.headers.get("Content-Length") or "0")
                _ = self.rfile.read(clen)
                self.send_response(200)
                # Intentionally omit `; charset=utf-8` so requests would default to ISO-8859-1 if decode_unicode=True
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                chunk1 = {
                    "id": "cmpl-utf8",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": sample_text}, "finish_reason": None}],
                }
                chunk2 = {
                    "id": "cmpl-utf8",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
                line1 = f"data: {json.dumps(chunk1, ensure_ascii=False)}\n\n".encode("utf-8")
                # Split right in the middle of a multi-byte UTF-8 character and flush separately
                split_idx = len(line1) // 2
                self.wfile.write(line1[:split_idx])
                self.wfile.flush()
                self.wfile.write(line1[split_idx:])
                self.wfile.write(f"data: {json.dumps(chunk2, ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        up = ThreadingHTTPServer(("127.0.0.1", 0), _NoCharsetSSEHandler)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        gws = gateway_adapter.parse_gateways_payload(
            [{"id": "cpa", "base_url": f"http://127.0.0.1:{up.server_address[1]}/v1", "dialect": "cpa"}]
        )
        adapter = gateway_adapter.GatewayAdapterServer(gws, port=0)
        adapter.start()
        try:
            rt = adapter.register_route("cpa", "team/gpt-6.1-sol", effort="high")
            resp = requests.post(
                f"{rt.url}/chat/completions",
                json={"model": "team/gpt-6.1-sol", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
                timeout=5,
            )
            self.assertEqual(200, resp.status_code)
            body_text = resp.content.decode("utf-8")
            self.assertIn(sample_text, body_text)
            self.assertNotIn("Ã", body_text)
        finally:
            adapter.stop()
            up.shutdown()
            up.server_close()

    def test_route_table_lru_eviction(self):
        gws = gateway_adapter.parse_gateways_payload(
            [{"id": "cpa", "base_url": "http://127.0.0.1:8317/v1", "dialect": "cpa"}]
        )
        adapter = gateway_adapter.GatewayAdapterServer(gws, port=0, max_routes=3)
        adapter.start()
        try:
            r1 = adapter.register_route("cpa", "model-1")
            r2 = adapter.register_route("cpa", "model-2")
            r3 = adapter.register_route("cpa", "model-3")
            # Touch r1 so r2 becomes the least-recently-used route
            self.assertIsNotNone(adapter.get_route(r1.token))
            r4 = adapter.register_route("cpa", "model-4")
            self.assertIsNotNone(adapter.get_route(r1.token))
            self.assertIsNone(adapter.get_route(r2.token))
            self.assertIsNotNone(adapter.get_route(r3.token))
            self.assertIsNotNone(adapter.get_route(r4.token))
            self.assertEqual(3, len(adapter._routes_by_token))
        finally:
            adapter.stop()


class TestBridgeHybridRoutingAndCompanionModules(unittest.TestCase):
    """Integration tests for bridge.py hybrid routing, effort coordination, /model UI, failover, cost, and doctor."""

    def test_hybrid_subprocess_env_isolation_and_effort_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            gw_cfg = json.dumps(
                [
                    {
                        "id": "cpa",
                        "name": "CPA",
                        "base_url": "http://127.0.0.1:8317/v1",
                        "dialect": "cpa",
                        "api_key": "MOCK_REAL_CPA_KEY_DO_NOT_LEAK",
                        "models": ["team/gpt-6.1-sol"],
                    }
                ]
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGY_LLM_GATEWAY_URL": "http://127.0.0.1:9999/stale",
                    "AGY_LLM_GATEWAY_API_KEY": "STALE_POLLUTED_KEY",
                    "AGY_LLM_GATEWAY_WIRE_PROTOCOL": "openai",
                    "AGY_LLM_GATEWAY_MODELS": "stale-model=65535",
                },
                clear=False,
            ):
                bridge = _load_isolated_bridge(tmp, extra_env={"AGY_TG_GATEWAYS_JSON": gw_cfg})
                spawned: list[dict] = []
                stop_ev = threading.Event()

                class _FakeProc:
                    def __init__(self, cmd, **kwargs):
                        spawned.append({"cmd": cmd, "env": kwargs.get("env", {})})
                        self.stdin = mock.MagicMock()
                        self.stdout = self._wait_iter()
                        self.stderr = iter([])
                        self.returncode = 0

                    def _wait_iter(self):
                        stop_ev.wait(timeout=5.0)
                        if False:
                            yield ""

                    def poll(self):
                        return None

                    def terminate(self):
                        stop_ev.set()

                    def kill(self):
                        stop_ev.set()

                    def wait(self, timeout=None):
                        return 0

                try:
                    with mock.patch.object(bridge.subprocess, "Popen", side_effect=_FakeProc):
                        # 1. Native Google model MUST strip all AGY_LLM_GATEWAY_* vars and convert effort suffix cleanly
                        s_nat = bridge.AgySession(None, "auto", "gemini-4-hydrogen-high", "low", scope_key="-1001234567890")
                        self.assertEqual("native", s_nat._route_kind)
                        nat_cmd = spawned[-1]["cmd"]
                        nat_env = spawned[-1]["env"]
                        self.assertIn("--model", nat_cmd)
                        self.assertEqual("gemini-4-hydrogen", nat_cmd[nat_cmd.index("--model") + 1])
                        self.assertIn("--effort", nat_cmd)
                        self.assertEqual("low", nat_cmd[nat_cmd.index("--effort") + 1])
                        for k in nat_env:
                            self.assertFalse(k.startswith("AGY_LLM_GATEWAY_"), f"Leaked gateway env to native: {k}")

                        # 2. Gateway model MUST NOT pass --effort to `agy`, MUST strip AGY_LLM_GATEWAY_MODELS,
                        #    and MUST NOT expose real upstream API key in subprocess env
                        s_gw = bridge.AgySession(None, "auto", "team/gpt-6.1-sol", "high", scope_key="-1001234567890")
                        self.assertEqual("gateway", s_gw._route_kind)
                        gw_cmd = spawned[-1]["cmd"]
                        gw_env = spawned[-1]["env"]
                        self.assertIn("--model", gw_cmd)
                        self.assertEqual("team/gpt-6.1-sol", gw_cmd[gw_cmd.index("--model") + 1])
                        self.assertNotIn("--effort", gw_cmd)
                        self.assertIn("/g/", gw_env["AGY_LLM_GATEWAY_URL"])
                        self.assertTrue(gw_env["AGY_LLM_GATEWAY_URL"].endswith("/v1"))
                        self.assertEqual("openai", gw_env["AGY_LLM_GATEWAY_WIRE_PROTOCOL"])
                        self.assertNotEqual("MOCK_REAL_CPA_KEY_DO_NOT_LEAK", gw_env["AGY_LLM_GATEWAY_API_KEY"])
                        self.assertNotIn("AGY_LLM_GATEWAY_MODELS", gw_env)

                        # Session matching detects model / effort changes
                        self.assertTrue(s_gw.matches(None, "auto", "team/gpt-6.1-sol", "high"))
                        self.assertFalse(s_gw.matches(None, "auto", "team/gpt-6.1-sol", "medium"))
                        self.assertFalse(s_gw.matches(None, "auto", "gemini-4-hydrogen", "high"))
                finally:
                    stop_ev.set()
                    bridge._stop_gateway_adapter()

    def test_native_google_effort_conflict_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            native = [
                ("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"),
                ("gemini-4-hydrogen-low", "Gemini 4 Hydrogen (Low)"),
                ("gemini-pro-orchestrator-neon", "Orchestrator (Neon)"),
                ("gpt-oss-120b-medium", "GPT-OSS 120B (Medium)"),
            ]
            self.assertEqual(
                ("gemini-4-hydrogen", "low"),
                bridge._resolve_native_model_and_effort("gemini-4-hydrogen-high", "low", native_models=native),
            )
            self.assertEqual(
                ("gemini-4-hydrogen-high", None),
                bridge._resolve_native_model_and_effort("gemini-4-hydrogen-high", "max", native_models=native),
            )
            self.assertEqual(
                ("gemini-pro-orchestrator-neon", None),
                bridge._resolve_native_model_and_effort("gemini-pro-orchestrator-neon", "high", native_models=native),
            )
            self.assertEqual(
                ("gpt-oss-120b-medium", None),
                bridge._resolve_native_model_and_effort("gpt-oss-120b-medium", "high", native_models=native),
            )
            # Cold-cache boundaries (native_models=[]): must never emit unsupported xhigh/max combos
            self.assertEqual(
                ("gemini-3.8-flash-high", None),
                bridge._resolve_native_model_and_effort("gemini-3.8-flash-high", "xhigh", native_models=[]),
            )
            self.assertEqual(
                ("gemini-3.8-flash", None),
                bridge._resolve_native_model_and_effort("gemini-3.8-flash", "xhigh", native_models=[]),
            )
            self.assertEqual(
                ("gemini-4-carbon-high", None),
                bridge._resolve_native_model_and_effort("gemini-4-carbon-high", "xhigh", native_models=[]),
            )
            self.assertEqual(
                ("gemini-4-hydrogen", "xhigh"),
                bridge._resolve_native_model_and_effort("gemini-4-hydrogen-high", "xhigh", native_models=[]),
            )
            self.assertEqual(
                ("gpt-oss-120b", None),
                bridge._resolve_native_model_and_effort("gpt-oss-120b", "high", native_models=[]),
            )

    def test_model_keyboard_short_callbacks_pagination_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            gw_cfg = json.dumps(
                [
                    {
                        "id": "openrouter",
                        "name": "OR",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "openrouter",
                        "api_key": "MOCK_OR_KEY",
                    }
                ]
            )
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_TG_GATEWAYS_JSON": gw_cfg})
            long_models = [
                (f"vendor/very-long-organization-prefix-model-identifier-number-{i:02d}-thinking", f"[OR] Model {i:02d}")
                for i in range(25)
            ]
            kb0 = bridge.make_model_keyboard(long_models[0][0], page=0, page_size=10, models=long_models)
            rows = kb0["inline_keyboard"]
            self.assertEqual(12, len(rows))  # 10 models + 1 pagination row + 1 reset row
            for row in rows:
                for btn in row:
                    self.assertLessEqual(len(btn["callback_data"].encode("utf-8")), 64)

            nav_callbacks = [b["callback_data"] for b in rows[-2]]
            self.assertIn("mp:1", nav_callbacks)

            # Clicking a short `ms:<digest>` callback switches scope model cleanly
            first_cb = rows[0][0]["callback_data"]
            self.assertTrue(first_cb.startswith("ms:"))
            with (
                mock.patch.object(bridge, "agy_models", return_value=long_models),
                mock.patch.object(bridge, "tg") as m_tg,
            ):
                m_tg.return_value = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
                bridge.handle_callback(
                    {
                        "id": "cb-model-1",
                        "from": {"id": 111},
                        "message": {"chat": {"id": -1001234567890}, "message_id": 77},
                        "data": first_cb,
                    }
                )
            self.assertEqual(long_models[0][0], bridge.get_scope_value("-1001234567890", "model"))

            # /status renders gateway badge + effort note
            bridge.update_scope_state("-1001234567890", model="gw:openrouter:anthropic/claude-sonnet", effort="high")
            sent_status = []
            with mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_status.append(a[1])):
                bridge.cmd_status(-1001234567890)
            self.assertTrue(sent_status)
            self.assertIn("Gateway: <code>openrouter</code>", sent_status[0])
            self.assertIn("gateway reasoning_effort", sent_status[0])

    def test_failover_cost_usage_and_doctor_gateway_checks(self):
        # 1. Failover markers
        for err in (
            '{"error":{"code":"insufficient_quota"}}',
            "HTTP 402 Payment Required",
            "502 Bad Gateway",
            "504 Gateway Timeout",
            "Connection refused by upstream",
            "invalid_api_key provided",
        ):
            self.assertTrue(model_failover.is_failover_eligible_error(err), f"Expected eligible: {err}")

        # 2. cost_usage third-party isolation
        self.assertEqual("gemini-3.8-flash", cost_usage.canonical_model_family("gemini-3.8-flash-high"))
        self.assertEqual("gemini-4-hydrogen", cost_usage.canonical_model_family("Gemini 4 Hydrogen (High)"))
        self.assertEqual("claude-sonnet-5-5", cost_usage.canonical_model_family("claude-sonnet-5-5-medium"))
        self.assertEqual("gpt-oss-120b", cost_usage.canonical_model_family("gpt-oss-120b-medium"))

        self.assertEqual("gateway:glm-5.3-flash", cost_usage.canonical_model_family("glm-5.3-flash"))
        self.assertEqual("gateway:team/gpt-6.1-sol", cost_usage.canonical_model_family("team/gpt-6.1-sol"))
        self.assertEqual("gateway:team/gpt-6.1-sol", cost_usage.canonical_model_family("gw:cpa:team/gpt-6.1-sol"))
        self.assertEqual("gateway:deepseek-pro", cost_usage.canonical_model_family("deepseek-pro"))
        self.assertEqual((0.0, 0.0, 0.0), cost_usage.google_model_rates_per_m("gateway:team/gpt-6.1-sol", "2026-11-19"))

        # 3. cli.py doctor gateway check (masked, no secret leak)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            env_path = tmp_p / ".env"
            gw_path = tmp_p / "gateways.json"
            gw_path.write_text(
                json.dumps(
                    {
                        "gateways": [
                            {
                                "id": "cpa",
                                "base_url": "http://127.0.0.1:8317/v1",
                                "dialect": "cpa",
                                "api_key": "testtesttest",
                                "enabled": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            env_path.write_text(
                "\n".join(
                    [
                        "AGY_TG_BOT_TOKEN=123456789:TEST_VALID_BOT_TOKEN_PAYLOAD_12345",
                        "AGY_TG_ALLOWED_CHATS=-1001234567890",
                        f"AGY_TG_WORKDIR={tmp_p / 'ws'}",
                        f"AGY_TG_STATE_FILE={tmp_p / 'state.json'}",
                        f"AGY_TG_LOCK_DIR={tmp_p / 'locks'}",
                        f"AGY_TG_GATEWAYS_FILE={gw_path}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o600)
            with mock.patch.dict(os.environ, {"HOME": tmp}, clear=False):
                rc, rep = cli.run_doctor(env_file=env_path)
            self.assertEqual(0, rc)
            by_name = {c["name"]: c for c in rep["checks"]}
            self.assertEqual("PASS", by_name["gateways"]["status"])
            self.assertIn("cpa(cpa)", by_name["gateways"]["message"])
            self.assertNotIn("testtesttest", json.dumps(rep))

            # Invalid dialect -> FAIL
            gw_path.write_text('{"gateways":[{"id":"bad","base_url":"http://127.0.0.1:8080/v1","dialect":"unknown_x"}]}', encoding="utf-8")
            with mock.patch.dict(os.environ, {"HOME": tmp}, clear=False):
                rc_bad, rep_bad = cli.run_doctor(env_file=env_path)
            self.assertEqual(1, rc_bad)
            by_name_bad = {c["name"]: c for c in rep_bad["checks"]}
            self.assertEqual("FAIL", by_name_bad["gateways"]["status"])

            # Placeholder api_key -> WARN
            gw_path.write_text(
                '{"gateways":[{"id":"cpa","base_url":"http://127.0.0.1:8317/v1","dialect":"cpa","api_key":"REPLACE_WITH_KEY"}]}',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"HOME": tmp}, clear=False):
                rc_warn, rep_warn = cli.run_doctor(env_file=env_path)
            self.assertEqual(0, rc_warn)
            self.assertEqual("WARN", {c["name"]: c for c in rep_warn["checks"]}["gateways"]["status"])

    def test_fast_reply_bus_job_and_rbac_pagination_callbacks(self):
        import access_control  # noqa: E402

        self.assertTrue(access_control.is_callback_allowed_for_role("readonly", "mp:1")[0])
        self.assertFalse(access_control.is_callback_allowed_for_role("readonly", "ms:1234567890ab")[0])

        with tempfile.TemporaryDirectory() as tmp:
            gw_cfg = json.dumps(
                [
                    {
                        "id": "cpa",
                        "base_url": "http://127.0.0.1:8317/v1",
                        "dialect": "cpa",
                        "api_key": "testtesttest",
                        "models": ["team/gpt-6.1-sol"],
                    }
                ]
            )
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_GATEWAYS_JSON": gw_cfg,
                    "AGY_TG_BOT_MODEL": "team/gpt-6.1-sol",
                    "AGY_TG_BOT_EFFORT": "high",
                },
            )
            captured_cmds: list[tuple[list[str], dict]] = []
            try:
                with (
                    mock.patch.object(
                        bridge,
                        "_run_subprocess_group",
                        side_effect=lambda cmd, **kw: (captured_cmds.append((cmd, kw.get("env", {}))) or (0, '{"response":"ok"}', "")),
                    ),
                    mock.patch.object(bridge, "send_rich", return_value=(101, None)),
                    mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                ):
                    bridge._run_fast_group_reply(-1001234567890, "status?")
                self.assertEqual(1, len(captured_cmds))
                fast_cmd, fast_env = captured_cmds[0]
                self.assertIn("--model", fast_cmd)
                self.assertEqual("team/gpt-6.1-sol", fast_cmd[fast_cmd.index("--model") + 1])
                self.assertNotIn("--effort", fast_cmd)
                self.assertIn("/g/", fast_env["AGY_LLM_GATEWAY_URL"])
                self.assertNotEqual("testtesttest", fast_env["AGY_LLM_GATEWAY_API_KEY"])

                # run_compact() must inherit ENV_BOT_MODEL when scope model is unset
                skey = bridge.scope_key_for(-1001234567890)
                bridge.update_scope_state(skey, conversation_id="conv-compact-1", model=None, effort=None)
                compact_calls: list[tuple] = []
                with (
                    mock.patch.object(
                        bridge,
                        "get_context_stats",
                        return_value={
                            "ctx_tokens": 1000,
                            "total_lines": 10,
                            "just_compacted": False,
                            "steps_since_ckpt": 3,
                            "checkpoints": 1,
                        },
                    ),
                    mock.patch.object(bridge, "LiveDraftStreamer"),
                    mock.patch.object(
                        bridge,
                        "_execute_compact_on_session",
                        side_effect=lambda *a, **kw: (compact_calls.append(a) or (True, 0.2, "")),
                    ),
                    mock.patch.object(bridge, "tg_send_in_route"),
                    mock.patch.object(bridge, "send"),
                ):
                    bridge.run_compact(-1001234567890)
                self.assertEqual(1, len(compact_calls))
                self.assertEqual("team/gpt-6.1-sol", compact_calls[0][3])
                self.assertEqual("high", compact_calls[0][4])
            finally:
                bridge._stop_gateway_adapter()


if __name__ == "__main__":
    unittest.main()
