#!/usr/bin/env python3
"""AGY Studio — Per-Session Worktree Management & Safe Git Workflow (Commit / Push / PR).

Security Invariants (C1–C5):
- All write endpoints (`POST /api/worktrees/{id}/cleanup`, `POST /api/git/{commit,push,pr}`)
  enforce the 4-layer write gate (`Origin` -> `application/json` 415 -> Auth/RBAC/`must_change_password`
  -> CSRF + admin) and record `0600` append-only audit logs with zero secret leakage.
- All endpoints validate `project_id` against the host project whitelist and optional `worktree_id`
  strictly under `<project_root>/.worktrees/<wt_id>` with non-symlink & `is_relative_to` checks.
- All `git` and `gh` subprocesses run via `asyncio.create_subprocess_exec(..., shell=False)` with
  `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/false`, `--` path separators, stdin `-F -` / `--body-file -`,
  and ephemeral OpenBao `GH_TOKEN` injection (NEVER mutating `.git/config`).
- Pre-commit enforcement blocks sensitive paths (`is_sensitive_rel_path`), symlinks (mode `120000`),
  and secret patterns in staged diffs with zero index residue and redacted error messages.
- `POST /api/git/push` bans all force flags/refspecs, hardcodes `origin`, blocks detached HEAD /
  missing remote, and gates protected branches behind strict boolean `confirm_protected: true` (`409`).
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any

from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import bot_bus  # noqa: E402
import studio_ipc  # noqa: E402

from .auth import StudioAuthManager, studio_auth_error  # noqa: E402
from .chat_service import (  # noqa: E402
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive  # noqa: E402
from .data_sources import StudioDataSources, _sanitize_slug  # noqa: E402
from .secrets_config_service import (  # noqa: E402
    DEFAULT_KV_MOUNT,
    OpenBaoSecretBackend,
    SecretsConfigService,
)
from .workspace_files import (  # noqa: E402
    StudioWorkspaceFilesService,
    _resolve_sandboxed_path,
    _resolve_worktree_root,
    is_sensitive_rel_path,
    redact_workspace_text,
)

log = logging.getLogger("agy-studio.git_workflow")

GIT_CMD_TIMEOUT_SEC = 10.0
GIT_REMOTE_TIMEOUT_SEC = 45.0
GH_PR_TIMEOUT_SEC = 30.0
BAO_CLI_TIMEOUT_SEC = 6.0

MAX_COMMIT_MSG_CHARS = 4096
MAX_COMMIT_PATHS = 200
MAX_PR_TITLE_CHARS = 256
MAX_PR_BODY_CHARS = 16384

_PROTECTED_BRANCH_EXACT = frozenset({"main", "master", "production", "prod", "release"})
_GIT_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SAFE_HTTPS_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{1,5})?/[^\s<>\"'`\x00-\x1f\x7f]+$")
_EMPTY_GIT_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_PATHSPEC_WILDCARD_CHARS = ("*", "?", "[", "]")

_ALLOWED_WORKTREE_CLEANUP_KEYS = frozenset({"project_id", "force"})
_FORBIDDEN_WORKTREE_CLEANUP_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "dir_abs",
    "abs_path",
    "path",
    "repo_root",
    "branch",
    "ipc_sock",
    "role",
    "cmd",
    "command",
    "shell",
    "script",
})

_ALLOWED_GIT_COMMIT_KEYS = frozenset({"project_id", "worktree_id", "message", "stage_mode", "paths"})
_FORBIDDEN_GIT_COMMIT_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "dir_abs",
    "abs_path",
    "amend",
    "no_verify",
    "no-verify",
    "args",
    "flags",
    "remote",
    "url",
    "refspec",
    "force",
    "env",
    "command",
    "cmd",
    "shell",
    "ipc_sock",
    "role",
})
_VALID_STAGE_MODES = frozenset({"all", "staged", "paths"})

_ALLOWED_GIT_PUSH_KEYS = frozenset({"project_id", "worktree_id", "confirm_protected"})
_FORBIDDEN_GIT_PUSH_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "dir_abs",
    "abs_path",
    "force",
    "force_with_lease",
    "force-with-lease",
    "remote",
    "url",
    "refspec",
    "args",
    "flags",
    "env",
    "command",
    "cmd",
    "shell",
    "delete",
    "prune",
    "mirror",
    "tags",
    "ipc_sock",
    "role",
})

_ALLOWED_GIT_PR_KEYS = frozenset({"project_id", "worktree_id", "title", "body", "base", "draft"})
_FORBIDDEN_GIT_PR_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "dir_abs",
    "abs_path",
    "remote",
    "url",
    "repo",
    "head",
    "args",
    "flags",
    "env",
    "command",
    "cmd",
    "shell",
    "token",
    "gh_token",
    "ipc_sock",
    "role",
})

_COMMIT_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("openbao_token", re.compile(r"\bhvs\.[A-Za-z0-9_-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b")),
    ("api_secret_key", re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b")),
    ("service_token", re.compile(r"\b(?:cfut|cfsd|cfat|ibk|ibssh|alt)_[A-Za-z0-9_-]{8,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("telegram_bot_token", re.compile(r"(?<![A-Za-z0-9_.-])\d{8,11}:[A-Za-z0-9_-]{24,45}\b")),
)


def is_protected_branch_name(branch: str) -> bool:
    b = str(branch or "").strip()
    if not b:
        return False
    low = b.lower()
    return low in _PROTECTED_BRANCH_EXACT or low.startswith("release/")


def is_valid_git_branch_name(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    s = raw.strip()
    if not s or s != raw:
        return False
    if s.startswith("-") or s.endswith("/") or s.endswith(".lock"):
        return False
    if ".." in s or "//" in s or "@{" in s or "\\" in s or "\x00" in s:
        return False
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in s):
        return False
    return bool(_GIT_BRANCH_RE.fullmatch(s))


def scan_staged_diff_for_secrets(diff_text: str) -> list[str]:
    """Scan added lines of a staged unified diff for high-risk secret patterns.

    Returns deduplicated rule names ONLY — never returns raw matched secret values.
    """
    if not diff_text:
        return []
    hits: list[str] = []
    seen: set[str] = set()
    for line in diff_text.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for rule_name, pat in _COMMIT_SECRET_RULES:
            if rule_name not in seen and pat.search(content):
                seen.add(rule_name)
                hits.append(rule_name)
    return hits


def _scrub_output(raw: str, *, extra_secret: str = "") -> str:
    text = str(raw or "")
    if extra_secret and extra_secret in text:
        text = text.replace(extra_secret, "[REDACTED]")
    return redact_workspace_text(text)


class StudioGitWorkflowService:
    """Provides Studio Worktree management and Safe Git Workflow (Status / Commit / Push / PR)."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        workspace_files: StudioWorkspaceFilesService,
        secrets_config: SecretsConfigService,
        audit: StudioAuditLogger,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.workspace_files = workspace_files
        self.secrets_config = secrets_config
        self.audit = audit

    # ------------------------------------------------------------------ Subprocess Helpers
    @staticmethod
    def _base_safe_env(*, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
        if extra:
            env.update(extra)
        return env

    async def _run_git(
        self,
        root: Path,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        extra_env: dict[str, str] | None = None,
        extra_git_cfg: list[str] | None = None,
        literal_pathspecs: bool = False,
        timeout: float = GIT_CMD_TIMEOUT_SEC,
    ) -> tuple[int, str, str]:
        git_args: list[str] = []
        if literal_pathspecs:
            git_args.append("--literal-pathspecs")
        git_args.extend([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotePath=false",
        ])
        if extra_git_cfg:
            for item in extra_git_cfg:
                git_args.extend(["-c", item])
        git_args.extend(["-C", str(root), *args])

        proc = await asyncio.create_subprocess_exec(
            "git",
            *git_args,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._base_safe_env(extra=extra_env),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
            return 124, "", "git command timed out"
        return (
            int(proc.returncode or 0),
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def _run_gh(
        self,
        root: Path,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        extra_env: dict[str, str] | None = None,
        timeout: float = GH_PR_TIMEOUT_SEC,
    ) -> tuple[int, str, str]:
        gh_bin = shutil.which("gh")
        if not gh_bin:
            return 127, "", "gh CLI not available"
        env_extra = {"GH_PROMPT_DISABLED": "1"}
        if extra_env:
            env_extra.update(extra_env)
        proc = await asyncio.create_subprocess_exec(
            gh_bin,
            *args,
            cwd=str(root),
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._base_safe_env(extra=env_extra),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
            return 124, "", "gh command timed out"
        return (
            int(proc.returncode or 0),
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def _get_github_token(self) -> str | None:
        """Dynamically resolve ephemeral GitHub PAT from OpenBao (never persisted to disk or git config)."""
        raw_env_path = os.environ.get("AGY_STUDIO_GITHUB_BAO_PATH", "").strip().strip("/")
        raw_env_mount = os.environ.get("AGY_STUDIO_GITHUB_BAO_MOUNT", "").strip().strip("/")
        bao_field = os.environ.get("AGY_STUDIO_GITHUB_BAO_FIELD", "token").strip() or "token"

        rt: dict[str, Any] = {}
        try:
            rt = self.secrets_config.resolve_openbao_runtime()
        except Exception:
            rt = {}
        default_mount = str(rt.get("kv_mount") or DEFAULT_KV_MOUNT).strip().strip("/") or DEFAULT_KV_MOUNT

        if raw_env_path:
            if raw_env_mount:
                kv_mount = raw_env_mount
                prefix = f"{kv_mount}/"
                rel_path = raw_env_path[len(prefix) :] if raw_env_path.startswith(prefix) else raw_env_path
            elif "/" in raw_env_path:
                first_seg, rest = raw_env_path.split("/", 1)
                if first_seg == default_mount or first_seg in ("secret", "kv") or "/" in rest:
                    kv_mount, rel_path = first_seg, rest
                else:
                    kv_mount, rel_path = default_mount, raw_env_path
            else:
                kv_mount, rel_path = default_mount, raw_env_path
        else:
            kv_mount = raw_env_mount or default_mount
            rel_path = "services/github"

        full_bao_path = f"{kv_mount}/{rel_path}".strip("/")

        # 1. Try OpenBao HTTP KV v2 via SecretsConfigService runtime
        try:
            backend = OpenBaoSecretBackend(self.secrets_config)
            if backend.is_available():
                tok = await backend.get_secret({
                    "kv_mount": kv_mount,
                    "path": rel_path,
                    "field": bao_field,
                })
                if tok:
                    return tok
        except Exception as exc:
            log.warning("OpenBao HTTP GitHub token lookup failed: %s", type(exc).__name__)

        # 2. Fallback to local `bao` CLI (`bao get <path> --field <field>`)
        bao_bin = shutil.which("bao")
        if not bao_bin:
            cand = _REPO_ROOT / "bin" / "bao"
            if cand.is_file() and os.access(cand, os.X_OK):
                bao_bin = str(cand)
        if not bao_bin:
            return None
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                bao_bin,
                "get",
                full_bao_path,
                "--field",
                bao_field,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(os.environ),
            )
            stdout_b, _stderr_b = await asyncio.wait_for(proc.communicate(), timeout=BAO_CLI_TIMEOUT_SEC)
            if proc.returncode == 0:
                val = stdout_b.decode("utf-8", errors="replace").strip()
                if val:
                    return val
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            log.warning("OpenBao CLI GitHub token lookup timed out")
        except Exception as exc:
            log.warning("OpenBao CLI GitHub token lookup failed: %s", type(exc).__name__)
        return None

    def _resolve_body_project_and_worktree(
        self,
        body: dict[str, Any],
    ) -> tuple[dict[str, str] | None, Path | None, str, int, str]:
        raw_pid = body.get("project_id")
        if not isinstance(raw_pid, str) or not raw_pid.strip():
            return None, None, "", 400, "缺少 project_id 参数"
        pid_s = raw_pid.strip()
        if "\x00" in pid_s or "/" in pid_s or "\\" in pid_s or ".." in pid_s or pid_s.startswith("-"):
            return None, None, "", 400, "非法的 project_id 参数"
        proj = self.data_sources.resolve_allowed_project(pid_s)
        if not proj or not proj.get("workdir"):
            return None, None, "", 404, "未找到对应的白名单项目"
        proj_root = Path(proj["workdir"])
        if not proj_root.is_dir():
            return None, None, "", 404, "项目工作区目录不可访问"

        wt_id = ""
        if "worktree_id" in body and body.get("worktree_id") is not None:
            raw_wt = body.get("worktree_id")
            if not isinstance(raw_wt, str):
                return None, None, "", 400, "非法的 worktree_id 格式"
            eff_root, wt_id, sc_wt, err_wt = _resolve_worktree_root(proj_root, raw_wt)
            if eff_root is None:
                return None, None, "", sc_wt, err_wt
            return proj, eff_root, wt_id, 200, ""
        return proj, proj_root, "", 200, ""

    # ------------------------------------------------------------------ GET /api/worktrees
    async def handle_get_worktrees(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        proj, proj_root, _wt, err_resp = self.workspace_files._resolve_project_root(
            request, allow_worktree=False
        )
        if err_resp is not None or proj is None or proj_root is None:
            assert err_resp is not None
            return err_resp

        is_git = bool((proj_root / ".git").exists())
        proj_real = proj_root.resolve(strict=True)
        wt_parent = proj_real / ".worktrees"
        if os.path.islink(wt_parent):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "禁止访问符号链接 worktree 目录"},
                status=403,
            )

        reg = bot_bus.load_studio_worktrees(str(self.data_sources.bus_dir))
        worktrees_out: list[dict[str, Any]] = []

        # Probe main repo HEAD once for accurate commits_ahead
        main_head = ""
        if is_git:
            rc_mh, out_mh, _ = await self._run_git(proj_real, ["rev-parse", "--verify", "HEAD"])
            if rc_mh == 0 and out_mh.strip():
                main_head = out_mh.strip()

        if wt_parent.is_dir():
            wt_parent_real = wt_parent.resolve(strict=True)
            try:
                entries = sorted(os.scandir(wt_parent_real), key=lambda e: e.name)
            except OSError:
                entries = []
            for ent in entries:
                wt_id = ent.name
                if not studio_ipc.is_valid_worktree_id(wt_id):
                    continue
                try:
                    if ent.is_symlink() or not ent.is_dir(follow_symlinks=False):
                        continue
                    ent_real = Path(ent.path).resolve(strict=True)
                    if not ent_real.is_relative_to(wt_parent_real) or ent_real == wt_parent_real:
                        continue
                except OSError:
                    continue

                meta = reg.get(wt_id) if isinstance(reg.get(wt_id), dict) else {}
                rc_br, out_br, _ = await self._run_git(ent_real, ["symbolic-ref", "--quiet", "--short", "HEAD"])
                branch = out_br.strip() if rc_br == 0 and out_br.strip() else str(meta.get("branch") or "")
                if not branch:
                    rc_ab, out_ab, _ = await self._run_git(ent_real, ["rev-parse", "--abbrev-ref", "HEAD"])
                    if rc_ab == 0:
                        branch = out_ab.strip()

                rc_st, out_st, _ = await self._run_git(ent_real, ["status", "--porcelain=v1", "-uall"])
                dirty_count = len([ln for ln in out_st.splitlines() if ln.strip()]) if rc_st == 0 else 0

                base_ref = str(meta.get("base_commit") or "").strip() or main_head
                commits_ahead = 0
                if base_ref:
                    rc_rev, out_rev, _ = await self._run_git(ent_real, ["rev-list", "--count", f"{base_ref}..HEAD"])
                    if rc_rev == 0:
                        try:
                            commits_ahead = max(0, int(out_rev.strip()))
                        except ValueError:
                            commits_ahead = 0

                cid_val = str(meta.get("cid") or "").strip()
                busy = bool(cid_val and studio_ipc.is_conversation_locked(self.data_sources.bus_dir, cid_val))
                try:
                    created_ts = int(meta.get("created_at") or int(ent.stat(follow_symlinks=False).st_ctime))
                except (OSError, TypeError, ValueError):
                    created_ts = 0

                worktrees_out.append({
                    "worktree_id": wt_id,
                    "project_id": proj["id"],
                    "branch": redact_workspace_text(branch)[:128],
                    "cid": cid_val,
                    "bot": _sanitize_slug(str(meta.get("bot") or ""), max_len=64),
                    "dirty_count": dirty_count,
                    "commits_ahead": commits_ahead,
                    "busy": busy,
                    "created_at": created_ts,
                })

        worktrees_out.sort(key=lambda x: -int(x.get("created_at") or 0))
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "is_git": is_git,
            "worktrees": worktrees_out,
        })

    # ------------------------------------------------------------------ POST /api/worktrees/{worktree_id}/cleanup
    async def handle_cleanup_worktree(self, request: web.Request) -> web.Response:
        wt_id = str(request.match_info.get("worktree_id") or "").strip()
        ok_gate, sess, err_resp = await self.workspace_files._enforce_write_gate(
            request,
            action="worktree.cleanup",
            target_id=wt_id[:64],
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not studio_ipc.is_valid_worktree_id(wt_id):
            self.audit.record(
                action="worktree.cleanup",
                status_code=400,
                outcome="denied_invalid_worktree_id",
                client_ip=client_ip,
                target_id=wt_id[:64],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 worktree_id 格式"},
                status=400,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="worktree.cleanup",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_WORKTREE_CLEANUP_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="worktree.cleanup",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_WORKTREE_CLEANUP_KEYS
        if extra_keys:
            self.audit.record(
                action="worktree.cleanup",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的请求字段: {sorted(extra_keys)[0]}"},
                status=400,
            )

        raw_force = body.get("force", False)
        if not isinstance(raw_force, bool):
            self.audit.record(
                action="worktree.cleanup",
                status_code=400,
                outcome="denied_invalid_force",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "force 必须为布尔值（true/false）"},
                status=400,
            )

        proj, proj_root, _dummy_wt, sc_p, err_p = self._resolve_body_project_and_worktree(
            {"project_id": body.get("project_id")}
        )
        if proj is None or proj_root is None:
            self.audit.record(
                action="worktree.cleanup",
                status_code=sc_p,
                outcome="denied_invalid_project",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )

        # Validate worktree path & non-symlink before delegating
        wt_real_p, _norm_wt, sc_wt, err_wt = _resolve_worktree_root(proj_root, wt_id)
        if wt_real_p is None:
            self.audit.record(
                action="worktree.cleanup",
                status_code=sc_wt,
                outcome="denied_worktree_path",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_wt},
                status=sc_wt,
            )

        # Prefer Bridge IPC when available so Bridge's in-process session_lock & _undo_apply_lock are serialized
        reg = bot_bus.load_studio_worktrees(str(self.data_sources.bus_dir))
        reg_meta = reg.get(wt_id) if isinstance(reg.get(wt_id), dict) else {}
        owner_bot = str(reg_meta.get("bot") or "").strip() or None
        ep = self.workspace_files._resolve_ipc_endpoint(owner_bot) or self.workspace_files._resolve_ipc_endpoint(None)

        if ep is not None:
            bot_h, sock_p, tok = ep
            sc, data = await self.workspace_files._ipc_request_json(
                sock_path=sock_p,
                token=tok,
                method="POST",
                path="/ipc/worktrees/cleanup",
                payload={
                    "user_id": int(sess["user_id"]),
                    "actor_username": str(sess.get("username") or "")[:64],
                    "worktree_id": wt_id,
                    "project_id": proj["id"],
                    "force": raw_force,
                },
                timeout_sec=35.0,
            )
            if sc >= 400 or not data.get("ok"):
                err_code = _sanitize_slug(data.get("code") or "", max_len=40)
                self.audit.record(
                    action="worktree.cleanup",
                    status_code=sc,
                    outcome=f"denied_{err_code}" if err_code else f"error_ipc_{sc}",
                    client_ip=client_ip,
                    target_id=wt_id,
                    sess=sess,
                    bot_override=bot_h,
                )
                out_err: dict[str, Any] = {
                    "ok": False,
                    "source": "upstream",
                    "error": redact_workspace_text(data.get("error") or "清理 worktree 失败"),
                }
                if err_code:
                    out_err["code"] = err_code
                if data.get("dirty_count") is not None:
                    out_err["dirty_count"] = int(data["dirty_count"])
                if data.get("commits_ahead") is not None:
                    out_err["commits_ahead"] = int(data["commits_ahead"])
                return web.json_response(out_err, status=sc)

            self.audit.record(
                action="worktree.cleanup",
                status_code=200,
                outcome="allowed_force" if raw_force else "allowed",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
                bot_override=bot_h,
            )
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "worktree_id": wt_id,
                "branch": redact_workspace_text(data.get("branch") or f"agy-studio/{wt_id}"),
                "branch_deleted": bool(data.get("branch_deleted", False)),
                "cleaned": True,
            })

        # Fallback when Bridge IPC is offline: enforce ConversationLease + safe cleanup directly
        bound_cid = str(reg_meta.get("cid") or "").strip()
        lease = None
        if bound_cid and studio_ipc.is_valid_cid(bound_cid):
            lease = studio_ipc.ConversationLease.try_acquire(self.data_sources.bus_dir, bound_cid)
            if lease is None:
                self.audit.record(
                    action="worktree.cleanup",
                    status_code=409,
                    outcome="denied_session_busy",
                    client_ip=client_ip,
                    target_id=wt_id,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "code": "session_busy",
                        "error": "关联会话正在执行中，暂不可清理 worktree（session_busy）",
                    },
                    status=409,
                )
        try:
            sc_c, res_c = await asyncio.to_thread(
                bot_bus.cleanup_studio_worktree,
                str(proj_root),
                wt_id,
                force=raw_force,
                branch=str(reg_meta.get("branch") or ""),
                base_commit=str(reg_meta.get("base_commit") or ""),
            )
            if sc_c != 200 or not res_c.get("ok"):
                err_code = _sanitize_slug(res_c.get("code") or "", max_len=40)
                self.audit.record(
                    action="worktree.cleanup",
                    status_code=sc_c,
                    outcome=f"denied_{err_code}" if err_code else f"error_{sc_c}",
                    client_ip=client_ip,
                    target_id=wt_id,
                    sess=sess,
                )
                out_err = {
                    "ok": False,
                    "source": "studio_api",
                    "error": redact_workspace_text(res_c.get("error") or "清理 worktree 失败"),
                }
                if err_code:
                    out_err["code"] = err_code
                if res_c.get("dirty_count") is not None:
                    out_err["dirty_count"] = int(res_c["dirty_count"])
                if res_c.get("commits_ahead") is not None:
                    out_err["commits_ahead"] = int(res_c["commits_ahead"])
                return web.json_response(out_err, status=sc_c)

            try:
                bot_bus.remove_studio_worktree_meta(wt_id, bus_dir=str(self.data_sources.bus_dir))
            except Exception:
                pass
            self.audit.record(
                action="worktree.cleanup",
                status_code=200,
                outcome="allowed_force" if raw_force else "allowed",
                client_ip=client_ip,
                target_id=wt_id,
                sess=sess,
            )
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "worktree_id": wt_id,
                "branch": redact_workspace_text(res_c.get("branch") or f"agy-studio/{wt_id}"),
                "branch_deleted": bool(res_c.get("branch_deleted", False)),
                "cleaned": True,
            })
        finally:
            if lease is not None:
                lease.release()

    # ------------------------------------------------------------------ GET /api/git/status
    async def handle_git_status(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        proj, root, wt_id, err_resp = self.workspace_files._resolve_project_root(
            request, allow_worktree=True
        )
        if err_resp is not None or proj is None or root is None:
            assert err_resp is not None
            return err_resp

        gh_avail = bool(shutil.which("gh"))
        if not (root / ".git").exists():
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "worktree_id": wt_id or None,
                "is_git": False,
                "branch": "",
                "detached": False,
                "upstream": "",
                "ahead": 0,
                "behind": 0,
                "staged": [],
                "unstaged": [],
                "untracked": [],
                "is_protected_branch": False,
                "has_remote": False,
                "gh_available": gh_avail,
            })

        rc_wt, out_wt, _ = await self._run_git(root, ["rev-parse", "--is-inside-work-tree"])
        if rc_wt != 0 or out_wt.strip().lower() != "true":
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "worktree_id": wt_id or None,
                "is_git": False,
                "branch": "",
                "detached": False,
                "upstream": "",
                "ahead": 0,
                "behind": 0,
                "staged": [],
                "unstaged": [],
                "untracked": [],
                "is_protected_branch": False,
                "has_remote": False,
                "gh_available": gh_avail,
            })

        rc_sym, out_sym, _ = await self._run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
        if rc_sym == 0 and out_sym.strip():
            branch = out_sym.strip()
            detached = False
        else:
            detached = True
            rc_sh, out_sh, _ = await self._run_git(root, ["rev-parse", "--short", "HEAD"])
            branch = out_sh.strip() if rc_sh == 0 else ""

        upstream = ""
        ahead = 0
        behind = 0
        if not detached:
            rc_up, out_up, _ = await self._run_git(
                root, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]
            )
            if rc_up == 0 and out_up.strip():
                upstream = out_up.strip()
                rc_ab, out_ab, _ = await self._run_git(
                    root, ["rev-list", "--left-right", "--count", "@{u}...HEAD"]
                )
                if rc_ab == 0 and out_ab.strip():
                    parts_ab = out_ab.strip().split()
                    if len(parts_ab) == 2:
                        try:
                            behind = max(0, int(parts_ab[0]))
                            ahead = max(0, int(parts_ab[1]))
                        except ValueError:
                            pass

        rc_rem, out_rem, _ = await self._run_git(root, ["remote", "get-url", "origin"])
        has_remote = bool(rc_rem == 0 and out_rem.strip())

        rc_st, out_st, _ = await self._run_git(root, ["status", "--porcelain=v1", "-uall", "--"])
        staged: list[str] = []
        unstaged: list[str] = []
        untracked: list[str] = []
        if rc_st == 0 and out_st:
            for raw_ln in out_st.splitlines():
                if len(raw_ln) < 4:
                    continue
                xy = raw_ln[:2]
                fp_part = raw_ln[3:].strip()
                if " -> " in fp_part:
                    fp_part = fp_part.split(" -> ", 1)[1].strip()
                fp_part = fp_part.strip('"')
                if not fp_part or is_sensitive_rel_path(fp_part):
                    continue
                if os.path.islink(root / fp_part):
                    continue
                safe_fp = redact_workspace_text(fp_part)
                if xy == "??":
                    if len(untracked) < 300:
                        untracked.append(safe_fp)
                else:
                    if xy[0] not in (" ", "?") and len(staged) < 300:
                        staged.append(safe_fp)
                    if xy[1] != " " and len(unstaged) < 300:
                        unstaged.append(safe_fp)

        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "worktree_id": wt_id or None,
            "is_git": True,
            "branch": redact_workspace_text(branch)[:128],
            "detached": detached,
            "upstream": redact_workspace_text(upstream)[:128],
            "ahead": ahead,
            "behind": behind,
            "staged": staged,
            "unstaged": unstaged,
            "untracked": untracked,
            "is_protected_branch": (not detached) and is_protected_branch_name(branch),
            "has_remote": has_remote,
            "gh_available": gh_avail,
        })

    # ------------------------------------------------------------------ POST /api/git/commit
    async def _unstage_paths(self, root: Path, paths: list[str], *, has_head: bool) -> None:
        if not paths:
            return
        if has_head:
            await self._run_git(root, ["reset", "-q", "HEAD", "--", *paths])
        else:
            await self._run_git(root, ["rm", "--cached", "-q", "--ignore-unmatch", "--", *paths])

    async def _snapshot_index_tree(self, root: Path) -> tuple[bool, str, str]:
        """Snapshot `.git/index` into a Git tree OID via `git write-tree` before staging."""
        rc, out, err = await self._run_git(root, ["write-tree"])
        if rc != 0:
            return False, "", err
        tree_oid = out.strip()
        if not tree_oid or not re.fullmatch(r"[0-9a-f]{40,64}", tree_oid):
            return False, "", err or "invalid write-tree output"
        return True, tree_oid, ""

    async def _restore_index_tree(self, root: Path, pre_tree: str | None) -> None:
        """Atomically restore `.git/index` to `pre_tree` without modifying working-tree files."""
        if pre_tree is None:
            return
        if not pre_tree or pre_tree == _EMPTY_GIT_TREE_OID:
            await self._run_git(root, ["read-tree", "--empty"])
        else:
            await self._run_git(root, ["read-tree", pre_tree])

    async def _inspect_staged_violations(
        self,
        root: Path,
        staged_paths: list[str],
    ) -> tuple[list[str], list[str]]:
        """Check staged files for sensitive paths and mode `120000` symlinks via `git ls-files --stage`."""
        sensitive_hits: list[str] = []
        symlink_hits: list[str] = []
        if not staged_paths:
            return sensitive_hits, symlink_hits

        for p in staged_paths:
            if is_sensitive_rel_path(p):
                sensitive_hits.append(p)
            elif os.path.islink(root / p):
                symlink_hits.append(p)

        rc_ls, out_ls, _ = await self._run_git(root, ["ls-files", "--stage", "--", *staged_paths])
        if rc_ls == 0 and out_ls:
            for ln in out_ls.splitlines():
                if "\t" not in ln:
                    continue
                meta_part, fp = ln.split("\t", 1)
                parts = meta_part.strip().split()
                mode = parts[0] if parts else ""
                if mode == "120000" and fp not in symlink_hits:
                    symlink_hits.append(fp)
                if is_sensitive_rel_path(fp) and fp not in sensitive_hits:
                    sensitive_hits.append(fp)

        rc_raw, out_raw, _ = await self._run_git(root, ["diff", "--cached", "--raw"])
        if rc_raw == 0 and out_raw:
            for ln in out_raw.splitlines():
                if not ln.startswith(":") or "\t" not in ln:
                    continue
                hdr, fp_part = ln.split("\t", 1)
                hdr_fields = hdr.lstrip(":").split()
                new_mode = hdr_fields[1] if len(hdr_fields) >= 2 else ""
                target_fp = fp_part.split("\t")[-1].strip()
                if new_mode == "120000" and target_fp not in symlink_hits:
                    symlink_hits.append(target_fp)
                if is_sensitive_rel_path(target_fp) and target_fp not in sensitive_hits:
                    sensitive_hits.append(target_fp)

        return sensitive_hits, symlink_hits

    async def handle_git_commit(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self.workspace_files._enforce_write_gate(
            request, action="git.commit"
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="git.commit",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_GIT_COMMIT_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_GIT_COMMIT_KEYS
        if extra_keys:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的请求字段: {sorted(extra_keys)[0]}"},
                status=400,
            )

        raw_msg = body.get("message")
        if not isinstance(raw_msg, str) or not raw_msg.strip():
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_empty_message",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "提交信息 message 不能为空"},
                status=400,
            )
        if "\x00" in raw_msg or len(raw_msg) > MAX_COMMIT_MSG_CHARS:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_invalid_message",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "提交信息包含非法字符或超出长度上限"},
                status=400,
            )
        commit_msg = raw_msg.strip()

        raw_mode = body.get("stage_mode")
        if not isinstance(raw_mode, str) or raw_mode.strip().lower() not in _VALID_STAGE_MODES:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_invalid_stage_mode",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "stage_mode 必须为 all / staged / paths"},
                status=400,
            )
        stage_mode = raw_mode.strip().lower()

        proj, root, wt_id, sc_p, err_p = self._resolve_body_project_and_worktree(body)
        if proj is None or root is None:
            self.audit.record(
                action="git.commit",
                status_code=sc_p,
                outcome="denied_invalid_target",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )

        if not (root / ".git").exists():
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_not_git",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标目录不是 Git 仓库"},
                status=400,
            )

        validated_paths: list[str] = []
        raw_paths = body.get("paths")
        if stage_mode == "paths":
            if not isinstance(raw_paths, list) or not raw_paths or len(raw_paths) > MAX_COMMIT_PATHS:
                self.audit.record(
                    action="git.commit",
                    status_code=400,
                    outcome="denied_invalid_paths",
                    client_ip=client_ip,
                    target_id=proj["id"],
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "stage_mode=paths 时必须提供非空文件路径列表"},
                    status=400,
                )
            for item in raw_paths:
                if not isinstance(item, str):
                    self.audit.record(
                        action="git.commit",
                        status_code=400,
                        outcome="denied_invalid_path_item",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "paths 中的每项必须为字符串"},
                        status=400,
                    )
                item_s = item.strip()
                if (
                    item_s.startswith(":")
                    or ":(" in item_s
                    or any(ch in item_s for ch in _PATHSPEC_WILDCARD_CHARS)
                ):
                    self.audit.record(
                        action="git.commit",
                        status_code=400,
                        outcome="denied_invalid_pathspec",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "code": "invalid_pathspec",
                            "error": "stage_mode=paths 禁止使用通配符或 Git pathspec 语法",
                        },
                        status=400,
                    )
                ok_sp, target_p, norm_rel, sc_sp, err_sp = _resolve_sandboxed_path(
                    root, item, allow_root=False
                )
                if not ok_sp or target_p is None:
                    self.audit.record(
                        action="git.commit",
                        status_code=sc_sp,
                        outcome="denied_unsafe_path",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "code": "unsafe_path", "error": err_sp},
                        status=sc_sp,
                    )
                if target_p.is_dir():
                    self.audit.record(
                        action="git.commit",
                        status_code=400,
                        outcome="denied_directory_path",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "code": "directory_not_allowed",
                            "error": "stage_mode=paths 仅允许显式指定具体文件路径，禁止传入目录名",
                        },
                        status=400,
                    )
                if target_p.exists():
                    if not target_p.is_file():
                        self.audit.record(
                            action="git.commit",
                            status_code=400,
                            outcome="denied_non_file_path",
                            client_ip=client_ip,
                            target_id=proj["id"],
                            sess=sess,
                        )
                        return web.json_response(
                            {
                                "ok": False,
                                "source": "studio_api",
                                "code": "invalid_path_target",
                                "error": "stage_mode=paths 仅允许常规文件路径",
                            },
                            status=400,
                        )
                else:
                    rc_tr, out_tr, _ = await self._run_git(
                        root,
                        ["ls-files", "--", norm_rel],
                        literal_pathspecs=True,
                    )
                    tracked_exact = rc_tr == 0 and norm_rel in {
                        ln.strip() for ln in out_tr.splitlines() if ln.strip()
                    }
                    if not tracked_exact:
                        self.audit.record(
                            action="git.commit",
                            status_code=400,
                            outcome="denied_missing_or_directory_path",
                            client_ip=client_ip,
                            target_id=proj["id"],
                            sess=sess,
                        )
                        return web.json_response(
                            {
                                "ok": False,
                                "source": "studio_api",
                                "code": "invalid_path_target",
                                "error": "指定路径不存在且非已跟踪文件，拒绝暂存",
                            },
                            status=400,
                        )
                if norm_rel not in validated_paths:
                    validated_paths.append(norm_rel)
        elif raw_paths is not None and raw_paths != []:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_unexpected_paths",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "仅 stage_mode=paths 允许传入 paths"},
                status=400,
            )

        rc_head, _, _ = await self._run_git(root, ["rev-parse", "--verify", "HEAD"])
        has_head = rc_head == 0

        rc_pre_s, out_pre_s, _ = await self._run_git(root, ["diff", "--cached", "--name-only"])
        pre_staged = [ln.strip() for ln in out_pre_s.splitlines() if ln.strip()] if rc_pre_s == 0 else []

        # Pre-check existing staged files for sensitive files / symlinks
        pre_sens, pre_sym = await self._inspect_staged_violations(root, pre_staged)
        if pre_sens or pre_sym:
            await self._unstage_paths(root, list(dict.fromkeys([*pre_sens, *pre_sym])), has_head=has_head)
            code = "sensitive_file_blocked" if pre_sens else "symlink_blocked"
            msg = "安全拦截：已阻止并取消暂存敏感文件" if pre_sens else "安全拦截：已阻止并取消暂存符号链接文件"
            self.audit.record(
                action="git.commit",
                status_code=403,
                outcome=f"denied_{code}",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": code, "error": msg},
                status=403,
            )

        # Snapshot `.git/index` BEFORE any `git add` so blocked/failed attempts restore atomically
        pre_tree: str | None = None
        if stage_mode in ("all", "paths"):
            ok_snap, snap_tree, snap_err = await self._snapshot_index_tree(root)
            if not ok_snap:
                self.audit.record(
                    action="git.commit",
                    status_code=409,
                    outcome="denied_index_conflict",
                    client_ip=client_ip,
                    target_id=proj["id"],
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "code": "index_conflict",
                        "error": f"暂存区存在未解决的合并冲突或无法快照索引: {redact_workspace_text(snap_err)[:160]}",
                    },
                    status=409,
                )
            pre_tree = snap_tree

        # Stage according to stage_mode (checking BEFORE git add so sensitive/symlink files never touch index)
        if stage_mode == "all":
            rc_ws, out_ws, _ = await self._run_git(root, ["status", "--porcelain=v1", "-uall", "--"])
            if rc_ws != 0:
                self.audit.record(
                    action="git.commit",
                    status_code=500,
                    outcome="error_git_status",
                    client_ip=client_ip,
                    target_id=proj["id"],
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "检查工作区 Git 状态失败"},
                    status=500,
                )
            for raw_ln in out_ws.splitlines():
                if len(raw_ln) < 4:
                    continue
                fp_part = raw_ln[3:].strip()
                if " -> " in fp_part:
                    fp_part = fp_part.split(" -> ", 1)[1].strip()
                fp_part = fp_part.strip('"')
                if not fp_part:
                    continue
                if is_sensitive_rel_path(fp_part):
                    self.audit.record(
                        action="git.commit",
                        status_code=403,
                        outcome="denied_sensitive_file_blocked",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "code": "sensitive_file_blocked",
                            "error": "安全拦截：工作区包含敏感文件，禁止暂存或提交",
                        },
                        status=403,
                    )
                if os.path.islink(root / fp_part):
                    self.audit.record(
                        action="git.commit",
                        status_code=403,
                        outcome="denied_symlink_blocked",
                        client_ip=client_ip,
                        target_id=proj["id"],
                        sess=sess,
                    )
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "code": "symlink_blocked",
                            "error": "安全拦截：工作区包含符号链接，禁止暂存或提交",
                        },
                        status=403,
                    )
            rc_add, _o_add, err_add = await self._run_git(root, ["add", "-A", "--", "."])
            if rc_add != 0:
                await self._restore_index_tree(root, pre_tree)
                self.audit.record(
                    action="git.commit",
                    status_code=500,
                    outcome="error_git_add",
                    client_ip=client_ip,
                    target_id=proj["id"],
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"暂存文件失败: {redact_workspace_text(err_add)[:160]}"},
                    status=500,
                )
        elif stage_mode == "paths":
            rc_add, _o_add, err_add = await self._run_git(
                root,
                ["add", "--", *validated_paths],
                literal_pathspecs=True,
            )
            if rc_add != 0:
                await self._restore_index_tree(root, pre_tree)
                self.audit.record(
                    action="git.commit",
                    status_code=400,
                    outcome="error_git_add_paths",
                    client_ip=client_ip,
                    target_id=proj["id"],
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"暂存指定文件失败: {redact_workspace_text(err_add)[:160]}"},
                    status=400,
                )

        # Post-stage inspection (defense-in-depth + atomic index rollback on violation)
        rc_post_s, out_post_s, _ = await self._run_git(root, ["diff", "--cached", "--name-only"])
        if rc_post_s != 0:
            await self._restore_index_tree(root, pre_tree)
            self.audit.record(
                action="git.commit",
                status_code=500,
                outcome="error_git_diff_cached_names",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "检查暂存区变更文件列表失败"},
                status=500,
            )
        staged_paths = [ln.strip() for ln in out_post_s.splitlines() if ln.strip()]

        post_sens, post_sym = await self._inspect_staged_violations(root, staged_paths)
        if post_sens or post_sym:
            if pre_tree is not None:
                await self._restore_index_tree(root, pre_tree)
            else:
                to_reset = list(dict.fromkeys([*post_sens, *post_sym]))
                await self._unstage_paths(root, to_reset, has_head=has_head)
            code = "sensitive_file_blocked" if post_sens else "symlink_blocked"
            msg = "安全拦截：检测到敏感文件，已中止提交并清理暂存区" if post_sens else "安全拦截：检测到符号链接（120000），已中止提交并清理暂存区"
            self.audit.record(
                action="git.commit",
                status_code=403,
                outcome=f"denied_{code}",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": code, "error": msg},
                status=403,
            )

        if not staged_paths:
            self.audit.record(
                action="git.commit",
                status_code=400,
                outcome="denied_nothing_to_commit",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "nothing_to_commit", "error": "暂存区没有可提交的变更"},
                status=400,
            )

        # Pre-commit secret scan on staged diff
        rc_cd, out_cd, err_cd = await self._run_git(
            root, ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-color"]
        )
        if rc_cd not in (0, 1):
            await self._restore_index_tree(root, pre_tree)
            self.audit.record(
                action="git.commit",
                status_code=500,
                outcome="error_git_diff_cached",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"读取暂存区 Diff 失败: {redact_workspace_text(err_cd)[:160]}"},
                status=500,
            )
        secret_hits = scan_staged_diff_for_secrets(out_cd)
        if secret_hits:
            await self._restore_index_tree(root, pre_tree)
            self.audit.record(
                action="git.commit",
                status_code=403,
                outcome=f"denied_secret_detected:{','.join(secret_hits[:4])}",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "secret_detected",
                    "findings": secret_hits,
                    "error": f"安全拦截：暂存区变更命中敏感密钥规则（{', '.join(secret_hits)}），已中止提交",
                },
                status=403,
            )

        # Commit safely with `-F -` (stdin), strictly forbidding `--amend` / `--no-verify`
        rc_cm, _out_cm, err_cm = await self._run_git(
            root,
            ["commit", "-F", "-"],
            stdin_bytes=(commit_msg + "\n").encode("utf-8"),
        )
        if rc_cm != 0:
            self.audit.record(
                action="git.commit",
                status_code=500,
                outcome="error_git_commit",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"Git 提交失败: {redact_workspace_text(err_cm)[:200]}"},
                status=500,
            )

        rc_sha, out_sha, _ = await self._run_git(root, ["rev-parse", "--short", "HEAD"])
        rc_fsha, out_fsha, _ = await self._run_git(root, ["rev-parse", "HEAD"])
        rc_br, out_br, _ = await self._run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
        short_sha = out_sha.strip() if rc_sha == 0 else ""
        full_sha = out_fsha.strip() if rc_fsha == 0 else ""
        branch = out_br.strip() if rc_br == 0 else ""

        self.audit.record(
            action="git.commit",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=f"{proj['id']}:{short_sha}",
            sess=sess,
        )
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "worktree_id": wt_id or None,
            "commit_sha": short_sha,
            "full_sha": full_sha,
            "branch": redact_workspace_text(branch)[:128],
            "files_committed": [redact_workspace_text(p) for p in staged_paths[:200]],
        })

    # ------------------------------------------------------------------ POST /api/git/push
    async def handle_git_push(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self.workspace_files._enforce_write_gate(
            request, action="git.push"
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="git.push",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_GIT_PUSH_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="git.push",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_GIT_PUSH_KEYS
        if extra_keys:
            self.audit.record(
                action="git.push",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的请求字段: {sorted(extra_keys)[0]}"},
                status=400,
            )

        raw_cp = body.get("confirm_protected", False)
        if not isinstance(raw_cp, bool):
            self.audit.record(
                action="git.push",
                status_code=400,
                outcome="denied_invalid_confirm_protected",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "confirm_protected 必须为布尔值（true/false）"},
                status=400,
            )
        confirm_protected = raw_cp

        proj, root, wt_id, sc_p, err_p = self._resolve_body_project_and_worktree(body)
        if proj is None or root is None:
            self.audit.record(
                action="git.push",
                status_code=sc_p,
                outcome="denied_invalid_target",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )

        if not (root / ".git").exists():
            self.audit.record(
                action="git.push",
                status_code=400,
                outcome="denied_not_git",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标目录不是 Git 仓库"},
                status=400,
            )

        rc_sym, out_sym, _ = await self._run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
        branch = out_sym.strip() if rc_sym == 0 else ""
        if not branch or not is_valid_git_branch_name(branch):
            self.audit.record(
                action="git.push",
                status_code=400,
                outcome="denied_detached_head",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "detached_head", "error": "当前处于 Detached HEAD 或分支名无效，禁止推送"},
                status=400,
            )

        rc_rem, out_rem, _ = await self._run_git(root, ["remote", "get-url", "origin"])
        if rc_rem != 0 or not out_rem.strip():
            self.audit.record(
                action="git.push",
                status_code=404,
                outcome="denied_remote_not_found",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "remote_not_found", "error": "未配置 origin 远端仓库"},
                status=404,
            )

        if is_protected_branch_name(branch) and confirm_protected is not True:
            self.audit.record(
                action="git.push",
                status_code=409,
                outcome="denied_protected_branch",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "protected_branch",
                    "branch": redact_workspace_text(branch),
                    "error": f"分支 {redact_workspace_text(branch)} 受保护，请二次确认后传 confirm_protected=true 推送",
                },
                status=409,
            )

        gh_token = await self._get_github_token()
        if not gh_token:
            self.audit.record(
                action="git.push",
                status_code=503,
                outcome="error_token_unavailable",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "github_token_unavailable",
                    "error": "无法从 OpenBao 动态读取 GitHub 令牌，已中止推送",
                },
                status=503,
            )

        refspec = f"refs/heads/{branch}:refs/heads/{branch}"
        rc_push, out_push, err_push = await self._run_git(
            root,
            ["push", "-u", "origin", refspec],
            extra_git_cfg=["credential.helper=", "credential.helper=!gh auth git-credential"],
            extra_env={"GH_TOKEN": gh_token},
            timeout=GIT_REMOTE_TIMEOUT_SEC,
        )
        safe_out = _scrub_output(out_push, extra_secret=gh_token)[:400]
        safe_err = _scrub_output(err_push, extra_secret=gh_token)[:400]

        if rc_push != 0:
            sc_fail = 504 if rc_push == 124 else 502
            self.audit.record(
                action="git.push",
                status_code=sc_fail,
                outcome="error_git_push",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "error": f"Git Push 失败: {safe_err or safe_out or f'exit {rc_push}'}",
                },
                status=sc_fail,
            )

        self.audit.record(
            action="git.push",
            status_code=200,
            outcome="allowed_protected" if confirm_protected else "allowed",
            client_ip=client_ip,
            target_id=f"{proj['id']}:{branch}",
            sess=sess,
        )
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "worktree_id": wt_id or None,
            "remote": "origin",
            "branch": redact_workspace_text(branch)[:128],
            "output": safe_err or safe_out or "pushed",
        })

    # ------------------------------------------------------------------ POST /api/git/pr
    async def handle_git_pr(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self.workspace_files._enforce_write_gate(
            request, action="git.pr"
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="git.pr",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_GIT_PR_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_GIT_PR_KEYS
        if extra_keys:
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的请求字段: {sorted(extra_keys)[0]}"},
                status=400,
            )

        raw_title = body.get("title")
        if not isinstance(raw_title, str) or not raw_title.strip():
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_empty_title",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "PR 标题 title 不能为空"},
                status=400,
            )
        if "\r" in raw_title or "\n" in raw_title or "\x00" in raw_title or len(raw_title.strip()) > MAX_PR_TITLE_CHARS:
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_invalid_title",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "PR 标题包含非法换行/控制字符或超过长度上限"},
                status=400,
            )
        pr_title = raw_title.strip()

        raw_pr_body = body.get("body", "")
        if raw_pr_body is None:
            pr_body = ""
        elif not isinstance(raw_pr_body, str) or "\x00" in raw_pr_body or len(raw_pr_body) > MAX_PR_BODY_CHARS:
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_invalid_body",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "PR 正文格式无效或超出长度上限"},
                status=400,
            )
        else:
            pr_body = raw_pr_body

        raw_draft = body.get("draft", False)
        if not isinstance(raw_draft, bool):
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_invalid_draft",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "draft 必须为布尔值（true/false）"},
                status=400,
            )
        draft = raw_draft

        raw_base = body.get("base")
        explicit_base = ""
        if raw_base is not None and raw_base != "":
            if not is_valid_git_branch_name(raw_base):
                self.audit.record(
                    action="git.pr",
                    status_code=400,
                    outcome="denied_invalid_base",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "非法的 base 分支名称"},
                    status=400,
                )
            explicit_base = str(raw_base)

        proj, root, wt_id, sc_p, err_p = self._resolve_body_project_and_worktree(body)
        if proj is None or root is None:
            self.audit.record(
                action="git.pr",
                status_code=sc_p,
                outcome="denied_invalid_target",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )

        if not (root / ".git").exists():
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_not_git",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标目录不是 Git 仓库"},
                status=400,
            )

        rc_sym, out_sym, _ = await self._run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
        head_branch = out_sym.strip() if rc_sym == 0 else ""
        if not head_branch or not is_valid_git_branch_name(head_branch):
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_detached_head",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "detached_head", "error": "当前处于 Detached HEAD，无法创建 PR"},
                status=400,
            )

        rc_rem, out_rem, _ = await self._run_git(root, ["remote", "get-url", "origin"])
        if rc_rem != 0 or not out_rem.strip():
            self.audit.record(
                action="git.pr",
                status_code=404,
                outcome="denied_remote_not_found",
                client_ip=client_ip,
                target_id=proj["id"],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "remote_not_found", "error": "未配置 origin 远端仓库"},
                status=404,
            )

        base_branch = explicit_base
        if not base_branch:
            rc_def, out_def, _ = await self._run_git(
                root, ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"]
            )
            if rc_def == 0 and out_def.strip().startswith("origin/"):
                cand = out_def.strip()[len("origin/"):]
                if is_valid_git_branch_name(cand):
                    base_branch = cand
            if not base_branch:
                base_branch = "main"

        if head_branch == base_branch:
            self.audit.record(
                action="git.pr",
                status_code=400,
                outcome="denied_same_branch",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{head_branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "same_branch",
                    "error": f"当前分支 {redact_workspace_text(head_branch)} 与目标分支相同，无法创建 PR",
                },
                status=400,
            )

        gh_token = await self._get_github_token()
        if not gh_token:
            self.audit.record(
                action="git.pr",
                status_code=503,
                outcome="error_token_unavailable",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{head_branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "github_token_unavailable",
                    "error": "无法从 OpenBao 动态读取 GitHub 令牌，已中止创建 PR",
                },
                status=503,
            )

        gh_args = [
            "pr",
            "create",
            "--title",
            pr_title,
            "--base",
            base_branch,
            "--head",
            head_branch,
            "--body-file",
            "-",
        ]
        if draft:
            gh_args.append("--draft")

        rc_pr, out_pr, err_pr = await self._run_gh(
            root,
            gh_args,
            stdin_bytes=pr_body.encode("utf-8"),
            extra_env={"GH_TOKEN": gh_token},
            timeout=GH_PR_TIMEOUT_SEC,
        )
        if rc_pr != 0:
            sc_fail = 504 if rc_pr == 124 else (503 if rc_pr == 127 else 502)
            safe_err = _scrub_output(err_pr or out_pr, extra_secret=gh_token)[:300]
            self.audit.record(
                action="git.pr",
                status_code=sc_fail,
                outcome="error_gh_pr_create",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{head_branch}",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": f"创建 PR 失败: {safe_err or f'exit {rc_pr}'}"},
                status=sc_fail,
            )

        # Extract and strictly validate `pr_url` (`^https://...`)
        pr_url = ""
        for ln in reversed(out_pr.splitlines()):
            cand = ln.strip()
            if cand:
                pr_url = cand
                break
        if not pr_url or not _SAFE_HTTPS_URL_RE.fullmatch(pr_url):
            self.audit.record(
                action="git.pr",
                status_code=502,
                outcome="denied_unsafe_pr_url",
                client_ip=client_ip,
                target_id=f"{proj['id']}:{head_branch}",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "code": "invalid_pr_url",
                    "error": "上游返回的 PR 链接不符合安全 HTTPS 格式，已拒绝展示",
                },
                status=502,
            )

        self.audit.record(
            action="git.pr",
            status_code=200,
            outcome="allowed_draft" if draft else "allowed",
            client_ip=client_ip,
            target_id=f"{proj['id']}:{head_branch}",
            sess=sess,
        )
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "worktree_id": wt_id or None,
            "pr_url": pr_url,
            "head": redact_workspace_text(head_branch)[:128],
            "base": redact_workspace_text(base_branch)[:128],
            "draft": draft,
        })
