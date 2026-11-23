#!/usr/bin/env python3
"""Unit tests for bot isolation guardrails, claude-mem hook gate, and post-compact rehydration.

Covers:
- C4: `bridge/memory_guard.py` bot profile store protection & `hooks/hooks.json` registration
- C5: `hooks/claude_mem_hook_gate.py` non-git sentinel cwd rewriting, coordinator context aggregation,
      and untrusted-session fail-closed blocking
- C3: `hooks/rehydrate_after_compact.py` worker isolation vs coordinator team overview
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
BRIDGE_DIR = REPO_ROOT / "bridge"
HOOKS_DIR = REPO_ROOT / "hooks"

for _p in (str(BRIDGE_DIR), str(HOOKS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bot_profiles  # noqa: E402
import memory_guard  # noqa: E402
import rehydrate_after_compact  # noqa: E402


class TestC4MemoryGuardBotProfilesAndHooksJson(unittest.TestCase):
    """Verify memory_guard protects per-bot profile stores and hooks.json enables bot-isolation-guard."""

    def test_protected_guard_and_download_paths_cover_bot_profiles_and_hook(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_home = Path(td) / "home"
            custom_bots = Path(td) / "custom_bots"
            fake_home.mkdir(parents=True, exist_ok=True)
            custom_bots.mkdir(parents=True, exist_ok=True)

            default_bots = fake_home / ".config" / "agy-tg-bridge" / "bots"
            default_rules = default_bots / "worker_alpha" / "RULES.md"
            custom_soul = custom_bots / "worker_alpha" / "SOUL.md"

            with mock.patch.dict(os.environ, {"AGY_BOT_PROFILES_DIR": str(custom_bots)}):
                ok_def_dir, lbl_def_dir = memory_guard._is_protected_guard_path(
                    str(default_bots), home_dir=str(fake_home)
                )
                self.assertTrue(ok_def_dir)
                self.assertEqual(lbl_def_dir, "bot_profiles_store")

                ok_def_file, lbl_def_file = memory_guard._is_protected_guard_path(
                    str(default_rules), home_dir=str(fake_home)
                )
                self.assertTrue(ok_def_file)
                self.assertEqual(lbl_def_file, "bot_profiles_store")

                ok_cust_dir, lbl_cust_dir = memory_guard._is_protected_guard_path(
                    str(custom_bots), home_dir=str(fake_home)
                )
                self.assertTrue(ok_cust_dir)
                self.assertEqual(lbl_cust_dir, "bot_profiles_store")

                ok_cust_file, lbl_cust_file = memory_guard._is_protected_guard_path(
                    str(custom_soul), home_dir=str(fake_home)
                )
                self.assertTrue(ok_cust_file)
                self.assertEqual(lbl_cust_file, "bot_profiles_store")

                ok_hook_bare, lbl_hook_bare = memory_guard._is_protected_guard_path(
                    "bot_isolation_guard.py", home_dir=str(fake_home)
                )
                self.assertTrue(ok_hook_bare)
                self.assertEqual(lbl_hook_bare, "repo_hooks_guard")

                ok_hook_rel, lbl_hook_rel = memory_guard._is_protected_guard_path(
                    str(Path(td) / "repo" / "hooks" / "bot_isolation_guard.py"),
                    home_dir=str(fake_home),
                )
                self.assertTrue(ok_hook_rel)
                self.assertEqual(lbl_hook_rel, "repo_hooks_guard")

                ok_hook_cfg, lbl_hook_cfg = memory_guard._is_protected_guard_path(
                    str(fake_home / ".gemini" / "config" / "hooks" / "bot_isolation_guard.py"),
                    home_dir=str(fake_home),
                )
                self.assertTrue(ok_hook_cfg)
                self.assertIn(lbl_hook_cfg, ("hooks_config", "repo_hooks_guard"))

                ok_dl_parent, lbl_dl_parent = memory_guard._is_protected_download_target(
                    str(fake_home / ".config" / "agy-tg-bridge"), home_dir=str(fake_home)
                )
                self.assertTrue(ok_dl_parent)
                self.assertEqual(lbl_dl_parent, "bot_profiles_store")

                ok_dl_rel, lbl_dl_rel = memory_guard._is_protected_download_target(
                    ".config/agy-tg-bridge", cwd=str(fake_home), home_dir=str(fake_home)
                )
                self.assertTrue(ok_dl_rel)
                self.assertEqual(lbl_dl_rel, "bot_profiles_store")

    def test_untrusted_session_blocks_self_rules_modification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_home = Path(td) / "home"
            bots_dir = Path(td) / "bots"
            self_rules = bots_dir / "worker_alpha" / "RULES.md"
            self_rules.parent.mkdir(parents=True, exist_ok=True)
            self_rules.write_text("# Original Rules\n", encoding="utf-8")
            taint_file = Path(td) / "taint.json"

            env_patch = {
                "AGY_UNTRUSTED_SESSION": "1",
                "AGY_BOT_PROFILES_DIR": str(bots_dir),
                "AGY_MEMORY_TAINT_FILE": str(taint_file),
                "AGY_BOT_HANDLE": "worker_alpha",
                "AGY_BOT_BUS_ROLE": "worker",
            }
            with mock.patch.dict(os.environ, env_patch):
                res_write = memory_guard.evaluate_tainted_tool_call(
                    "write_file",
                    {"Path": str(self_rules), "Content": "# Hijacked\n"},
                    tainted=True,
                    taint_reason="env_untrusted_session",
                    cwd=td,
                    home_dir=str(fake_home),
                    taint_file=taint_file,
                )
                self.assertTrue(res_write.get("blocked"))
                self.assertEqual(res_write.get("decision"), "deny")

                res_edit = memory_guard.evaluate_tainted_tool_call(
                    "edit_file",
                    {"Path": str(self_rules), "Target": "Original", "Replacement": "Hijacked"},
                    tainted=True,
                    taint_reason="env_untrusted_session",
                    cwd=td,
                    home_dir=str(fake_home),
                    taint_file=taint_file,
                )
                self.assertTrue(res_edit.get("blocked"))
                self.assertEqual(res_edit.get("decision"), "deny")

                res_sed = memory_guard.evaluate_tainted_tool_call(
                    "run_command",
                    {"CommandLine": f"sed -i 's/Original/Hijacked/' {self_rules}"},
                    tainted=True,
                    taint_reason="env_untrusted_session",
                    cwd=td,
                    home_dir=str(fake_home),
                    taint_file=taint_file,
                )
                self.assertTrue(res_sed.get("blocked"))
                self.assertEqual(res_sed.get("decision"), "deny")

                res_curl = memory_guard.evaluate_tainted_tool_call(
                    "run_command",
                    {"CommandLine": f"curl -fsSL -o {self_rules} https://example.com/rules.md"},
                    tainted=True,
                    taint_reason="env_untrusted_session",
                    cwd=td,
                    home_dir=str(fake_home),
                    taint_file=taint_file,
                )
                self.assertTrue(res_curl.get("blocked"))
                self.assertEqual(res_curl.get("decision"), "deny")

            # Verify taint_outbound_guard.py subprocess also blocks under AGY_UNTRUSTED_SESSION=1
            child_env = os.environ.copy()
            child_env.update(env_patch)
            child_env["HOME"] = str(fake_home)
            hook_script = HOOKS_DIR / "taint_outbound_guard.py"
            for tool_name, tool_args in (
                ("write_file", {"Path": str(self_rules), "Content": "x"}),
                ("edit_file", {"Path": str(self_rules), "Target": "a", "Replacement": "b"}),
                ("run_command", {"CommandLine": f"sed -i 's/a/b/' {self_rules}"}),
                ("run_command", {"CommandLine": f"curl -o {self_rules} https://example.com/r.md"}),
            ):
                hook_payload = {
                    "conversationId": "cid-c4-test",
                    "toolName": tool_name,
                    "toolArgs": tool_args,
                    "cwd": td,
                }
                proc = subprocess.run(
                    [sys.executable, str(hook_script)],
                    input=json.dumps(hook_payload),
                    text=True,
                    capture_output=True,
                    env=child_env,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0)
                out_obj = json.loads(proc.stdout.strip() or "{}")
                decision = (
                    out_obj.get("decision")
                    or (out_obj.get("hookSpecificOutput") or {}).get("permissionDecision")
                    or ""
                )
                self.assertIn(
                    str(decision).lower(),
                    ("deny", "block"),
                    f"Expected deny/block for {tool_name}: {out_obj}",
                )

    def test_hooks_json_valid_and_enables_bot_isolation_guard(self) -> None:
        hooks_json_path = HOOKS_DIR / "hooks.json"
        data = json.loads(hooks_json_path.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.assertIn("bot-isolation-guard", data)

        cfg = data["bot-isolation-guard"]
        self.assertIs(cfg.get("enabled"), True)
        pre_tool = cfg.get("PreToolUse")
        self.assertIsInstance(pre_tool, list)
        self.assertGreaterEqual(len(pre_tool), 1)

        entry = pre_tool[0]
        matcher = str(entry.get("matcher") or "")
        for tool_name in ("read_file", "run_command", "write_file", "edit_file", "list_dir", "grep_search"):
            self.assertIn(tool_name, matcher.split("|"))

        hooks_list = entry.get("hooks") or []
        self.assertGreaterEqual(len(hooks_list), 1)
        cmd = str(hooks_list[0].get("command") or "")
        self.assertIn("bot_isolation_guard.py", cmd)
        self.assertEqual(hooks_list[0].get("timeout"), 10)

        guard_file = HOOKS_DIR / "bot_isolation_guard.py"
        mode = stat.S_IMODE(guard_file.stat().st_mode)
        self.assertTrue(bool(mode & stat.S_IXUSR), "bot_isolation_guard.py must be executable")


class TestC5ClaudeMemHookGate(unittest.TestCase):
    """Verify claude_mem_hook_gate per-bot sentinel cwd isolation, coordinator aggregation, and untrusted block."""

    def _make_mock_bun(self, tmp_dir: Path, capture_file: Path) -> Path:
        mock_bun = tmp_dir / "mock_bun.py"
        mock_bun.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"cap = {str(capture_file)!r}\n"
            "raw = sys.stdin.read()\n"
            "record = {\n"
            "  'argv': sys.argv[1:],\n"
            "  'cwd': os.getcwd(),\n"
            "  'GEMINI_CWD': os.environ.get('GEMINI_CWD', ''),\n"
            "  'GEMINI_PROJECT_DIR': os.environ.get('GEMINI_PROJECT_DIR', ''),\n"
            "  'CLAUDE_PROJECT_DIR': os.environ.get('CLAUDE_PROJECT_DIR', ''),\n"
            "  'stdin': json.loads(raw) if raw.strip() else {},\n"
            "}\n"
            "with open(cap, 'w', encoding='utf-8') as fh:\n"
            "  json.dump(record, fh)\n"
            "print(json.dumps({'ok': True, 'event': sys.argv[-1] if sys.argv else ''}))\n",
            encoding="utf-8",
        )
        os.chmod(mock_bun, 0o755)
        return mock_bun

    def _assert_no_git_ancestor(self, path_str: str) -> None:
        cur = Path(path_str).resolve(strict=False)
        for anc in (cur, *cur.parents):
            self.assertFalse(
                (anc / ".git").exists(),
                f"Sentinel cwd ancestor must not contain .git: {anc}",
            )

    def test_worker_session_init_and_summarize_rewrite_to_non_git_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            git_repo = root / "workspace_repo"
            git_repo.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q", str(git_repo)], check=True)
            self.assertTrue((git_repo / ".git").exists())

            # Test both profiles outside git and profiles accidentally inside a git repo
            for label, profiles_dir in (
                ("external_profiles", root / "bots_store"),
                ("inside_git_profiles", git_repo / "nested_bots"),
            ):
                profiles_dir.mkdir(parents=True, exist_ok=True)
                for event in ("session-init", "summarize"):
                    capture_file = root / f"cap_{label}_{event}.json"
                    mock_bun = self._make_mock_bun(root, capture_file)
                    env = os.environ.copy()
                    env.pop("AGY_UNTRUSTED_SESSION", None)
                    env.pop("AGY_MEMORY_READONLY", None)
                    env.pop("AGY_INTERNAL_OBSERVER", None)
                    env.update(
                        {
                            "AGY_BUN_BIN": str(mock_bun),
                            "CLAUDE_MEM_WORKER_CJS": str(root / "fake_worker.cjs"),
                            "AGY_SHIM_STATE_FILE": str(root / "shim.json"),
                            "AGY_MEMORY_TAINT_FILE": str(root / "taint.json"),
                            "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                            "AGY_BOT_HANDLE": "@" + "Worker_Alpha",
                            "AGY_BOT_BUS_ROLE": "worker",
                        }
                    )
                    payload = {
                        "conversationId": f"cid-{label}-{event}",
                        "cwd": str(git_repo),
                        "workspacePaths": [str(git_repo)],
                        "prompt": "Implement feature module and summarize progress",
                    }
                    if event == "session-init":
                        payload["invocationNum"] = 0
                    proc = subprocess.run(
                        [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), event],
                        input=json.dumps(payload),
                        text=True,
                        capture_output=True,
                        env=env,
                        timeout=15,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertTrue(capture_file.is_file(), f"mock bun was not invoked for {label}/{event}")
                    cap = json.loads(capture_file.read_text(encoding="utf-8"))
                    stdin_obj = cap["stdin"]
                    self.assertEqual(Path(stdin_obj["cwd"]).name, "bot-worker_alpha")
                    self.assertEqual(len(stdin_obj["workspacePaths"]), 1)
                    self.assertEqual(Path(stdin_obj["workspacePaths"][0]).name, "bot-worker_alpha")
                    self.assertEqual(stdin_obj["cwd"], stdin_obj["workspacePaths"][0])
                    self.assertEqual(Path(cap["cwd"]).resolve(), Path(stdin_obj["cwd"]).resolve())
                    self.assertEqual(cap["GEMINI_CWD"], stdin_obj["cwd"])
                    self.assertEqual(cap["GEMINI_PROJECT_DIR"], stdin_obj["cwd"])
                    self.assertEqual(cap["CLAUDE_PROJECT_DIR"], stdin_obj["cwd"])
                    self._assert_no_git_ancestor(stdin_obj["cwd"])

    def test_worker_context_routes_only_to_own_bot_project(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profiles_dir = root / "bots"
            profiles_dir.mkdir(parents=True, exist_ok=True)
            capture_file = root / "cap_worker_context.json"
            mock_bun = self._make_mock_bun(root, capture_file)

            env = os.environ.copy()
            env.pop("AGY_UNTRUSTED_SESSION", None)
            env.pop("AGY_MEMORY_READONLY", None)
            env.pop("AGY_INTERNAL_OBSERVER", None)
            env.update(
                {
                    "AGY_BUN_BIN": str(mock_bun),
                    "CLAUDE_MEM_WORKER_CJS": str(root / "fake_worker.cjs"),
                    "AGY_SHIM_STATE_FILE": str(root / "shim.json"),
                    "AGY_MEMORY_TAINT_FILE": str(root / "taint.json"),
                    "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                    "AGY_BOT_HANDLE": "worker_alpha",
                    "AGY_BOT_BUS_ROLE": "worker",
                }
            )
            payload = {
                "conversationId": "cid-worker-ctx",
                "cwd": str(root),
                "workspacePaths": [str(root)],
            }
            proc = subprocess.run(
                [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), "context"],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                env=env,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(capture_file.is_file())
            cap = json.loads(capture_file.read_text(encoding="utf-8"))
            self.assertEqual(Path(cap["stdin"]["cwd"]).name, "bot-worker_alpha")
            self.assertEqual(Path(cap["stdin"]["workspacePaths"][0]).name, "bot-worker_alpha")

    def test_coordinator_context_queries_loopback_with_all_projects(self) -> None:
        received: list[dict[str, object]] = []

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                received.append({"path": parsed.path, "qs": parse_qs(parsed.query)})
                body = "\x1b[32mAggregated team context payload\x1b[0m\n".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        thr = threading.Thread(target=server.serve_forever, daemon=True)
        thr.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                profiles_dir = root / "bots"
                for h in ("coord_main", "worker_alpha", "worker_beta"):
                    (profiles_dir / h).mkdir(parents=True, exist_ok=True)

                db_path = root / "claude-mem.db"
                conn = sqlite3.connect(str(db_path))
                try:
                    conn.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, project TEXT)")
                    conn.execute("CREATE TABLE session_summaries (id INTEGER PRIMARY KEY, project TEXT)")
                    conn.executemany(
                        "INSERT INTO observations (project) VALUES (?)",
                        [
                            ("bot-worker_alpha",),
                            ("legacy-project",),
                            ("tmp_noise_99",),
                            ("agy_pretool_e2e_dummy",),
                            ("",),
                        ],
                    )
                    conn.executemany(
                        "INSERT INTO session_summaries (project) VALUES (?)",
                        [("bot-worker_gamma",), ("legacy-project",)],
                    )
                    conn.commit()
                finally:
                    conn.close()

                capture_file = root / "bun_should_not_run.json"
                mock_bun = self._make_mock_bun(root, capture_file)
                env = os.environ.copy()
                env.pop("AGY_UNTRUSTED_SESSION", None)
                env.pop("AGY_MEMORY_READONLY", None)
                env.pop("AGY_INTERNAL_OBSERVER", None)
                env.update(
                    {
                        "AGY_BUN_BIN": str(mock_bun),
                        "CLAUDE_MEM_WORKER_CJS": str(root / "fake_worker.cjs"),
                        "AGY_SHIM_STATE_FILE": str(root / "shim.json"),
                        "AGY_MEMORY_TAINT_FILE": str(root / "taint.json"),
                        "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                        "AGY_BOT_HANDLE": "coord_main",
                        "AGY_BOT_BUS_ROLE": "coordinator",
                        "CLAUDE_MEM_DB": str(db_path),
                        "CLAUDE_MEM_WORKER_PORT": str(port),
                    }
                )
                proc = subprocess.run(
                    [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), "context"],
                    input=json.dumps({"conversationId": "cid-coord-ctx", "cwd": str(root)}),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                out_obj = json.loads(proc.stdout.strip())
                self.assertEqual(
                    out_obj,
                    {"injectSteps": [{"ephemeralMessage": "Aggregated team context payload"}]},
                )
                self.assertFalse(capture_file.exists(), "Coordinator context should not spawn bun when worker responds")
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0]["path"], "/api/context/inject")
                qs = received[0]["qs"]
                assert isinstance(qs, dict)
                self.assertEqual(qs.get("platformSource"), ["antigravity-cli"])
                projs = qs.get("projects") or []
                self.assertEqual(projs[0], "bot-coord_main")
                self.assertIn("bot-worker_alpha", projs)
                self.assertIn("bot-worker_beta", projs)
                self.assertIn("bot-worker_gamma", projs)
                self.assertIn("legacy-project", projs)
                self.assertNotIn("tmp_noise_99", projs)
                self.assertNotIn("agy_pretool_e2e_dummy", projs)
        finally:
            server.shutdown()
            server.server_close()

    def test_untrusted_worker_blocks_writes_without_spawning_bun(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profiles_dir = root / "bots"
            profiles_dir.mkdir(parents=True, exist_ok=True)
            for event in ("session-init", "summarize"):
                capture_file = root / f"untrusted_{event}.json"
                mock_bun = self._make_mock_bun(root, capture_file)
                env = os.environ.copy()
                env.pop("AGY_INTERNAL_OBSERVER", None)
                env.update(
                    {
                        "AGY_BUN_BIN": str(mock_bun),
                        "CLAUDE_MEM_WORKER_CJS": str(root / "fake_worker.cjs"),
                        "AGY_SHIM_STATE_FILE": str(root / "shim.json"),
                        "AGY_MEMORY_TAINT_FILE": str(root / "taint.json"),
                        "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                        "AGY_BOT_HANDLE": "worker_alpha",
                        "AGY_BOT_BUS_ROLE": "worker",
                        "AGY_UNTRUSTED_SESSION": "1",
                    }
                )
                payload = {
                    "conversationId": f"cid-untrusted-{event}",
                    "cwd": str(root),
                    "prompt": "Normal message in untrusted session",
                }
                proc = subprocess.run(
                    [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), event],
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0)
                self.assertEqual(proc.stdout.strip(), "{}")
                self.assertFalse(capture_file.exists(), f"bun must not run for untrusted {event}")

    def test_coordinator_context_discovers_worker_port_from_pid_and_settings(self) -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        from urllib.parse import parse_qs, urlparse

        received: list[dict[str, object]] = []

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                received.append({"path": parsed.path, "qs": parse_qs(parsed.query)})
                body = b"Pid-discovered team context"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        mock_port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                profiles_dir = root / "bots"
                bot_profiles.ensure_bot_profile("coord_main", role="coordinator", profiles_dir=profiles_dir)
                bot_profiles.ensure_bot_profile("worker_alpha", role="worker", profiles_dir=profiles_dir)
                data_dir = root / "claude-mem-data"
                data_dir.mkdir(parents=True, exist_ok=True)
                capture_file = root / "coord_pid_capture.json"
                mock_bun = self._make_mock_bun(root, capture_file)

                base_env = os.environ.copy()
                base_env.pop("AGY_INTERNAL_OBSERVER", None)
                base_env.pop("CLAUDE_MEM_WORKER_PORT", None)
                base_env.update(
                    {
                        "AGY_BUN_BIN": str(mock_bun),
                        "CLAUDE_MEM_WORKER_CJS": str(root / "fake_worker.cjs"),
                        "AGY_SHIM_STATE_FILE": str(root / "shim.json"),
                        "AGY_MEMORY_TAINT_FILE": str(root / "taint.json"),
                        "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                        "AGY_BOT_HANDLE": "coord_main",
                        "AGY_BOT_BUS_ROLE": "coordinator",
                        "CLAUDE_MEM_DATA_DIR": str(data_dir),
                        "CLAUDE_MEM_DB_PATH": str(data_dir / "missing.db"),
                    }
                )

                # 1) Unset CLAUDE_MEM_WORKER_PORT -> discovers dynamic port from worker.pid (over settings.json)
                (data_dir / "worker.pid").write_text(
                    json.dumps({"pid": 12345, "port": mock_port}), encoding="utf-8"
                )
                (data_dir / "settings.json").write_text(
                    json.dumps({"CLAUDE_MEM_WORKER_PORT": 1}), encoding="utf-8"
                )
                proc = subprocess.run(
                    [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), "context"],
                    input=json.dumps({"conversationId": "cid-coord-pid", "cwd": str(root)}),
                    text=True,
                    capture_output=True,
                    env=base_env,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(
                    json.loads(proc.stdout.strip()),
                    {"injectSteps": [{"ephemeralMessage": "Pid-discovered team context"}]},
                )
                self.assertFalse(capture_file.exists())
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0]["path"], "/api/context/inject")

                # 2) Explicit CLAUDE_MEM_WORKER_PORT env takes priority over worker.pid
                (data_dir / "worker.pid").write_text(
                    json.dumps({"pid": 12345, "port": 1}), encoding="utf-8"
                )
                env_override = dict(base_env)
                env_override["CLAUDE_MEM_WORKER_PORT"] = str(mock_port)
                proc2 = subprocess.run(
                    [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), "context"],
                    input=json.dumps({"conversationId": "cid-coord-env", "cwd": str(root)}),
                    text=True,
                    capture_output=True,
                    env=env_override,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc2.returncode, 0, proc2.stderr)
                self.assertEqual(
                    json.loads(proc2.stdout.strip()),
                    {"injectSteps": [{"ephemeralMessage": "Pid-discovered team context"}]},
                )
                self.assertEqual(len(received), 2)

                # 3) Missing worker.pid -> falls back to settings.json CLAUDE_MEM_WORKER_PORT
                (data_dir / "worker.pid").unlink()
                (data_dir / "settings.json").write_text(
                    json.dumps({"CLAUDE_MEM_WORKER_PORT": mock_port}), encoding="utf-8"
                )
                proc3 = subprocess.run(
                    [sys.executable, str(HOOKS_DIR / "claude_mem_hook_gate.py"), "context"],
                    input=json.dumps({"conversationId": "cid-coord-settings", "cwd": str(root)}),
                    text=True,
                    capture_output=True,
                    env=base_env,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc3.returncode, 0, proc3.stderr)
                self.assertEqual(
                    json.loads(proc3.stdout.strip()),
                    {"injectSteps": [{"ephemeralMessage": "Pid-discovered team context"}]},
                )
                self.assertEqual(len(received), 3)
        finally:
            server.shutdown()
            server.server_close()


class TestC3CompactRehydrate(unittest.TestCase):
    """Verify post-compact rehydration enforces worker isolation and coordinator full visibility."""

    def _setup_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        profiles_dir = root / "bots"
        catalog_dir = root / "workspace" / ".agents" / "skills"
        (catalog_dir / "shared-deploy").mkdir(parents=True, exist_ok=True)
        allowed_skill = catalog_dir / "shared-deploy" / "SKILL.md"
        allowed_skill.write_text(
            "---\nname: shared-deploy\ndescription: Shared deploy helper\n---\n"
            "# Shared Deploy\nSHARED_DEPLOY_UNIQUE_BODY\n",
            encoding="utf-8",
        )
        (catalog_dir / "forbidden-skill").mkdir(parents=True, exist_ok=True)
        forbidden_skill = catalog_dir / "forbidden-skill" / "SKILL.md"
        forbidden_skill.write_text(
            "---\nname: forbidden-skill\ndescription: Forbidden private skill\n---\n"
            "# Forbidden Skill\nFORBIDDEN_SKILL_SECRET_BODY\n",
            encoding="utf-8",
        )

        # Worker Alpha
        bot_profiles.ensure_bot_profile("worker_alpha", role="worker", profiles_dir=profiles_dir)
        sc, res = bot_profiles.update_bot_profile(
            "worker_alpha",
            expected_rev=1,
            docs={
                "SOUL.md": "ALPHA_SOUL_UNIQUE_TOKEN",
                "RULES.md": "ALPHA_RULES_UNIQUE_TOKEN",
                "MEMORY.md": "ALPHA_MEMORY_UNIQUE_TOKEN",
            },
            skills_policy={"mode": "allowlist", "enabled_catalog_skills": ["shared-deploy"]},
            role="worker",
            profiles_dir=profiles_dir,
            catalog_dirs=[catalog_dir],
        )
        self.assertEqual(sc, 200)
        sc, _ = bot_profiles.put_bot_skill(
            "worker_alpha",
            "alpha-own-skill",
            content="---\nname: alpha-own-skill\ndescription: Alpha private skill\n---\n# Alpha\n",
            expected_rev=res["rev"],
            role="worker",
            profiles_dir=profiles_dir,
        )
        self.assertEqual(sc, 200)
        (profiles_dir / "worker_alpha" / "instincts" / "active-instincts.md").write_text(
            "- ALPHA_INSTINCT_UNIQUE_TOKEN\n", encoding="utf-8"
        )

        # Worker Beta
        bot_profiles.ensure_bot_profile("worker_beta", role="worker", profiles_dir=profiles_dir)
        sc, res_b = bot_profiles.update_bot_profile(
            "worker_beta",
            expected_rev=1,
            docs={
                "SOUL.md": "BETA_SECRET_SOUL_TOKEN",
                "RULES.md": "BETA_SECRET_RULES_TOKEN",
                "MEMORY.md": "BETA_SECRET_MEMORY_TOKEN",
            },
            role="worker",
            profiles_dir=profiles_dir,
            catalog_dirs=[catalog_dir],
        )
        self.assertEqual(sc, 200)
        sc, _ = bot_profiles.put_bot_skill(
            "worker_beta",
            "beta-own-skill",
            content="---\nname: beta-own-skill\ndescription: Beta private skill\n---\n# Beta\n",
            expected_rev=res_b["rev"],
            role="worker",
            profiles_dir=profiles_dir,
        )
        self.assertEqual(sc, 200)
        (profiles_dir / "worker_beta" / "instincts" / "active-instincts.md").write_text(
            "- BETA_SECRET_INSTINCT_TOKEN\n", encoding="utf-8"
        )

        # Coordinator
        bot_profiles.ensure_bot_profile("coord_main", role="coordinator", profiles_dir=profiles_dir)
        sc, _ = bot_profiles.update_bot_profile(
            "coord_main",
            expected_rev=1,
            docs={
                "SOUL.md": "COORD_SOUL_UNIQUE_TOKEN",
                "RULES.md": "COORD_RULES_UNIQUE_TOKEN",
                "MEMORY.md": "COORD_MEMORY_UNIQUE_TOKEN",
            },
            role="coordinator",
            profiles_dir=profiles_dir,
            catalog_dirs=[catalog_dir],
        )
        self.assertEqual(sc, 200)

        # Build transcript_full.jsonl with real rehydrate_after_compact protocol
        transcript_dir = root / "conv" / "abc12345" / ".system_generated" / "logs"
        transcript_dir.mkdir(parents=True, exist_ok=True)
        full_path = transcript_dir / "transcript_full.jsonl"

        alpha_soul = profiles_dir / "worker_alpha" / "SOUL.md"
        beta_soul = profiles_dir / "worker_beta" / "SOUL.md"
        mem_db = root / ".claude-mem" / "claude-mem.db"
        mem_db.parent.mkdir(parents=True, exist_ok=True)
        mem_db.write_text("dummy", encoding="utf-8")

        steps = [
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "Please continue implementing the module cleanly.",
            },
            {
                "step_index": 1,
                "type": "PLANNER_RESPONSE",
                "content": "Checking workspace files.",
                "tool_calls": [
                    {"name": "read_file", "args": {"Path": str(alpha_soul)}},
                    {"name": "read_file", "args": {"Path": str(beta_soul)}},
                    {"name": "read_file", "args": {"Path": str(mem_db)}},
                    {"name": "read_file", "args": {"Path": str(allowed_skill)}},
                    {"name": "read_file", "args": {"Path": str(forbidden_skill)}},
                ],
            },
            {
                "step_index": 2,
                "type": "CHECKPOINT",
            },
        ]
        full_path.write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in steps) + "\n",
            encoding="utf-8",
        )
        return profiles_dir, root / "workspace", full_path

    def test_worker_rehydrate_isolates_profile_and_filters_cross_bot_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profiles_dir, ws_dir, full_path = self._setup_fixture(Path(td))
            alpha_soul = profiles_dir / "worker_alpha" / "SOUL.md"
            beta_soul = profiles_dir / "worker_beta" / "SOUL.md"
            allowed_skill = ws_dir / ".agents" / "skills" / "shared-deploy" / "SKILL.md"
            forbidden_skill = ws_dir / ".agents" / "skills" / "forbidden-skill" / "SKILL.md"
            non_tmp_skips = tuple(
                s for s in rehydrate_after_compact.SKIP_PATH_SUBSTRINGS if s != "/tmp/"
            )
            with (
                mock.patch.object(rehydrate_after_compact, "SKIP_PATH_SUBSTRINGS", non_tmp_skips),
                mock.patch.dict(
                    os.environ,
                    {
                        "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                        "AGY_WORKSPACE_DIR": str(ws_dir),
                        "AGY_BOT_HANDLE": "@" + "Worker_Alpha",
                        "AGY_BOT_BUS_ROLE": "worker",
                    },
                ),
            ):
                res = rehydrate_after_compact.build_rehydration(full_path)
                # Direct filter check on index_lines/spec_blocks including .agents/skills root
                f_idx, f_specs = rehydrate_after_compact._filter_rehydration_for_bot(
                    [
                        f"- `{alpha_soul}`",
                        f"- `{beta_soul}`",
                        f"- `{allowed_skill}`",
                        f"- `{forbidden_skill}`",
                        f"- `{ws_dir / '.agents' / 'skills'}`",
                        "- `/home/example/.claude-mem/claude-mem.db`",
                    ],
                    [
                        f"### `{allowed_skill}`\nSHARED_DEPLOY_UNIQUE_BODY",
                        f"### `{forbidden_skill}`\nFORBIDDEN_SKILL_SECRET_BODY",
                    ],
                )
            self.assertEqual(len(f_idx), 2)
            self.assertEqual(len(f_specs), 1)
            self.assertIn("shared-deploy", f_specs[0])

            self.assertIsNotNone(res)
            assert res is not None
            msg, meta = res
            self.assertGreater(meta["indexed_paths"], 0)
            self.assertIn(str(alpha_soul), msg)
            self.assertIn("## 5. Active Bot Identity & Memory Scope", msg)
            self.assertIn("bot-worker_alpha", msg)
            self.assertIn("ALPHA_SOUL_UNIQUE_TOKEN", msg)
            self.assertIn("ALPHA_RULES_UNIQUE_TOKEN", msg)
            self.assertIn("ALPHA_MEMORY_UNIQUE_TOKEN", msg)
            self.assertIn("ALPHA_INSTINCT_UNIQUE_TOKEN", msg)
            self.assertIn("alpha-own-skill", msg)
            self.assertIn("shared-deploy", msg)

            for forbidden in (
                str(beta_soul),
                "BETA_SECRET_SOUL_TOKEN",
                "BETA_SECRET_RULES_TOKEN",
                "BETA_SECRET_MEMORY_TOKEN",
                "BETA_SECRET_INSTINCT_TOKEN",
                "beta-own-skill",
                "worker_beta",
                "/.claude-mem/",
                "forbidden-skill",
                "FORBIDDEN_SKILL_SECRET_BODY",
            ):
                self.assertNotIn(forbidden, msg, f"Worker rehydration leaked {forbidden!r}")

    def test_coordinator_rehydrate_includes_self_and_team_overview(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profiles_dir, ws_dir, full_path = self._setup_fixture(Path(td))
            with mock.patch.dict(
                os.environ,
                {
                    "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                    "AGY_WORKSPACE_DIR": str(ws_dir),
                    "AGY_BOT_HANDLE": "coord_main",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                },
            ):
                res = rehydrate_after_compact.build_rehydration(full_path)
            self.assertIsNotNone(res)
            assert res is not None
            msg, _meta = res
            self.assertIn("## 5. Active Bot Identity & Memory Scope", msg)
            self.assertIn("COORD_SOUL_UNIQUE_TOKEN", msg)
            self.assertIn("COORD_RULES_UNIQUE_TOKEN", msg)
            self.assertIn("COORD_MEMORY_UNIQUE_TOKEN", msg)
            self.assertIn("bot-coord_main", msg)
            self.assertIn("bot-worker_alpha", msg)
            self.assertIn("bot-worker_beta", msg)
            self.assertIn("alpha-own-skill", msg)
            self.assertIn("beta-own-skill", msg)
            self.assertIn("ALPHA_RULES_UNIQUE_TOKEN", msg)
            self.assertIn("BETA_SECRET_RULES_TOKEN", msg)

    def test_unset_bot_handle_keeps_legacy_rehydration_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            profiles_dir, ws_dir, full_path = self._setup_fixture(Path(td))
            env = {
                "AGY_BOT_PROFILES_DIR": str(profiles_dir),
                "AGY_WORKSPACE_DIR": str(ws_dir),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                os.environ.pop("AGY_BOT_HANDLE", None)
                os.environ.pop("AGY_BOT_BUS_ROLE", None)
                res = rehydrate_after_compact.build_rehydration(full_path)
            self.assertIsNotNone(res)
            assert res is not None
            msg, _meta = res
            self.assertNotIn("## 5. Active Bot Identity & Memory Scope", msg)


class TestC4BotIsolationGuardParentAndSelfWrite(unittest.TestCase):
    """Regression suite for P0-1 parent-dir bypasses and P0-2 clean-worker self-write lock."""

    @staticmethod
    def _load_guard_module():
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bot_isolation_guard_r2b",
            str(HOOKS_DIR / "bot_isolation_guard.py"),
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _make_fixture(self, root: Path) -> tuple[Path, Path, Path, dict[str, str]]:
        home_dir = root / "home"
        bridge_cfg = home_dir / ".config" / "agy-tg-bridge"
        profiles_dir = bridge_cfg / "bots"
        (bridge_cfg / "bus" / "ipc").mkdir(parents=True, exist_ok=True)
        (bridge_cfg / "bus" / "ipc" / "coord.token").write_text("tok-secret", encoding="utf-8")
        (bridge_cfg / "state.json").write_text("{}", encoding="utf-8")

        mem_dir = home_dir / ".claude-mem"
        mem_dir.mkdir(parents=True, exist_ok=True)
        (mem_dir / "worker.pid").write_text(json.dumps({"pid": 999, "port": 37701}), encoding="utf-8")
        (mem_dir / "claude-mem.db").write_text("dummy", encoding="utf-8")

        ws_dir = root / "workspace"
        catalog_dir = ws_dir / ".agents" / "skills"
        (catalog_dir / "shared-deploy").mkdir(parents=True, exist_ok=True)
        (catalog_dir / "shared-deploy" / "SKILL.md").write_text("# Shared\n", encoding="utf-8")
        (catalog_dir / "forbidden-skill").mkdir(parents=True, exist_ok=True)
        (catalog_dir / "forbidden-skill" / "SKILL.md").write_text("# Forbidden\n", encoding="utf-8")

        bot_profiles.ensure_bot_profile("worker_alpha", role="worker", profiles_dir=profiles_dir)
        sc, _ = bot_profiles.update_bot_profile(
            "worker_alpha",
            expected_rev=1,
            docs={"SOUL.md": "ALPHA_SOUL", "RULES.md": "ALPHA_RULES"},
            skills_policy={"mode": "allowlist", "enabled_catalog_skills": ["shared-deploy"]},
            role="worker",
            profiles_dir=profiles_dir,
            catalog_dirs=[catalog_dir],
        )
        self.assertEqual(sc, 200)
        bot_profiles.ensure_bot_profile("worker_beta", role="worker", profiles_dir=profiles_dir)

        env = {
            "HOME": str(home_dir),
            "AGY_BOT_PROFILES_DIR": str(profiles_dir),
            "AGY_BOT_HANDLE": "@" + "Worker_Alpha",
            "AGY_BOT_BUS_ROLE": "worker",
        }
        return home_dir, profiles_dir, ws_dir, env

    def test_p0_1_blocks_parent_dir_and_root_enumeration_but_allows_normal_cmds(self) -> None:
        guard = self._load_guard_module()
        with tempfile.TemporaryDirectory() as td:
            home_dir, profiles_dir, ws_dir, env = self._make_fixture(Path(td))
            blocked_cases = [
                ("grep_search", {"SearchPath": str(home_dir / ".config" / "agy-tg-bridge")}),
                ("run_command", {"CommandLine": "grep -rn . ~/.config/agy-tg-bridge"}),
                ("read_file", {"Path": str(home_dir / ".config" / "agy-tg-bridge" / "bus" / "ipc" / "coord.token")}),
                ("read_file", {"Path": str(home_dir / ".config" / "agy-tg-bridge" / "state.json")}),
                ("list_dir", {"DirectoryPath": str(home_dir / ".claude-mem")}),
                ("run_command", {"CommandLine": "tar cf /tmp/m.tar ~/.claude-mem"}),
                ("run_command", {"CommandLine": "ls $CLAUDE_MEM_DATA_DIR"}),
                ("grep_search", {"SearchPath": str(ws_dir / ".agents" / "skills")}),
                ("list_dir", {"DirectoryPath": str(ws_dir / ".agents" / "skills")}),
                ("run_command", {"CommandLine": "grep -rn . .agents/skills"}),
                ("read_file", {"Path": str(ws_dir / ".agents" / "skills" / "forbidden-skill" / "SKILL.md")}),
            ]
            for tool_name, tool_args in blocked_cases:
                res = guard.evaluate_bot_isolation_tool_call(
                    tool_name, tool_args, cwd=str(ws_dir), env=env
                )
                self.assertTrue(
                    res["blocked"],
                    f"Expected blocked=True for {tool_name}({tool_args}), got {res}",
                )

            allowed_cases = [
                ("run_command", {"CommandLine": "git status"}),
                ("run_command", {"CommandLine": "python3 -m unittest"}),
                ("read_file", {"Path": str(ws_dir / ".agents" / "skills" / "shared-deploy" / "SKILL.md")}),
                ("read_file", {"Path": str(profiles_dir / "worker_alpha" / "SOUL.md")}),
            ]
            for tool_name, tool_args in allowed_cases:
                res = guard.evaluate_bot_isolation_tool_call(
                    tool_name, tool_args, cwd=str(ws_dir), env=env
                )
                self.assertFalse(
                    res["blocked"],
                    f"Expected blocked=False for {tool_name}({tool_args}), got {res}",
                )

    def test_p0_2_blocks_clean_worker_self_profile_writes_but_allows_read_and_coordinator(self) -> None:
        guard = self._load_guard_module()
        with tempfile.TemporaryDirectory() as td:
            home_dir, profiles_dir, ws_dir, env = self._make_fixture(Path(td))
            own_profile = profiles_dir / "worker_alpha" / "profile.json"
            own_rules = profiles_dir / "worker_alpha" / "RULES.md"
            own_soul = profiles_dir / "worker_alpha" / "SOUL.md"

            blocked_writes = [
                ("edit_file", {"Path": str(own_profile)}),
                ("write_file", {"Path": str(own_profile)}),
                ("write_file", {"Path": str(own_rules)}),
                ("write_file", {"Path": str(own_soul)}),
                ("run_command", {"CommandLine": f"sed -i 's/allowlist/all/' {own_profile}"}),
                ("run_command", {"CommandLine": f"echo '{{}}' > {own_profile}"}),
                (
                    "run_command",
                    {"CommandLine": f"python3 -c \"open('{own_profile}','w').write('{{}}')\""},
                ),
            ]
            for tool_name, tool_args in blocked_writes:
                res = guard.evaluate_bot_isolation_tool_call(
                    tool_name, tool_args, cwd=str(ws_dir), env=env
                )
                self.assertTrue(
                    res["blocked"],
                    f"Expected worker self-write blocked for {tool_name}({tool_args}), got {res}",
                )
                self.assertIn("Single-Writer", res["reason"])

            # Pure read of own SOUL.md remains allowed
            for tool_name, tool_args in (
                ("read_file", {"Path": str(own_soul)}),
                ("run_command", {"CommandLine": f"cat {own_soul}"}),
            ):
                res = guard.evaluate_bot_isolation_tool_call(
                    tool_name, tool_args, cwd=str(ws_dir), env=env
                )
                self.assertFalse(
                    res["blocked"],
                    f"Expected worker own-profile read allowed for {tool_name}({tool_args}), got {res}",
                )

            # Coordinator role remains allowed
            coord_env = dict(env)
            coord_env["AGY_BOT_HANDLE"] = "coord_main"
            coord_env["AGY_BOT_BUS_ROLE"] = "coordinator"
            for tool_name, tool_args in (
                ("read_file", {"Path": str(own_profile)}),
                ("edit_file", {"Path": str(own_profile)}),
                ("grep_search", {"SearchPath": str(home_dir / ".config" / "agy-tg-bridge")}),
            ):
                res = guard.evaluate_bot_isolation_tool_call(
                    tool_name, tool_args, cwd=str(ws_dir), env=coord_env
                )
                self.assertFalse(
                    res["blocked"],
                    f"Expected coordinator allowed for {tool_name}({tool_args}), got {res}",
                )


if __name__ == "__main__":
    unittest.main()
