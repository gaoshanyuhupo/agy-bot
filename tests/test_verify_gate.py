#!/usr/bin/env python3
"""Isolated unit & integration tests for `scripts/verify_gate.py`.

Covers:
1. CLI argument parsing and scope-to-file / scope-to-unittest mapping (`studio`, `browser`,
   `bridge`, `security`, `all`).
2. `NoRealBrowser` `sys.meta_path` import hook blocking `camoufox` and `playwright` imports
   while preserving `sys.modules` mocks.
3. Temporary Git repo protected-file guard: modifying a protected file fails by default and
   passes when `--allow-protected` is explicitly passed; `git diff --check` catches conflict/ws issues.
4. Non-zero exit code and structured JSON receipt (`ok: false`) when a step fails (e.g., syntax
   error in `py_compile` or failing `unittest`), plus faithful preservation of `AGY_MEMORY_READONLY`.
5. End-to-end execution of `python3 scripts/verify_gate.py --scope security --json` on the real
   repository returning valid JSON and exit code 0.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import verify_gate  # noqa: E402


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_temp_git_repo(repo: Path) -> None:
    _git(repo, "init")
    _git(repo, "config", "user.name", "Test Operator")
    _git(repo, "config", "user.email", "test@example.com")


class TestVerifyGate(unittest.TestCase):
    def test_cli_arg_parsing_and_scope_mappings(self) -> None:
        parser = verify_gate.build_parser()
        defaults = parser.parse_args([])
        self.assertEqual(defaults.scope, "all")
        self.assertEqual(defaults.tier, "mvp")
        self.assertFalse(defaults.no_build)
        self.assertFalse(defaults.allow_protected)
        self.assertFalse(defaults.json)

        parsed = parser.parse_args(
            [
                "--scope",
                "studio",
                "--tier",
                "prod",
                "--no-build",
                "--allow-protected",
                "--json",
                "--root",
                "/tmp/example-root",
            ]
        )
        self.assertEqual(parsed.scope, "studio")
        self.assertEqual(parsed.tier, "prod")
        self.assertTrue(parsed.no_build)
        self.assertTrue(parsed.allow_protected)
        self.assertTrue(parsed.json)
        self.assertEqual(parsed.root, Path("/tmp/example-root"))

        with tempfile.TemporaryDirectory(prefix="vg_scope_map_") as td:
            root = Path(td)
            files_to_create = [
                "studio/server.py",
                "studio/auth.py",
                ".agents/skills/live-browser/scripts/live_browser_server.py",
                ".agents/skills/google-profile/scripts/google_browser.py",
                "bridge/bridge.py",
                "bridge/memory_guard.py",
                "hooks/taint_outbound_guard.py",
                "scripts/benchmark_digest.py",
                "scripts/security_audit.py",
                "scripts/verify_gate.py",
                "scripts/sync_live.py",
                "tests/test_studio_mvp.py",
                "tests/test_security_audit_webui.py",
                "tests/test_live_browser_profiles.py",
                "tests/test_browser_panel.py",
                "tests/test_access_control.py",
                "tests/test_benchmark_digest.py",
                "tests/test_memory_guard_and_dream.py",
                "tests/test_taint_outbound_guard.py",
                "tests/test_verify_gate.py",
            ]
            for rel in files_to_create:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("# sample\n", encoding="utf-8")

            sys_py = "/usr/bin/python3"
            cf_py = "/opt/fake-camoufox-env/bin/python3"

            # File collection per scope
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "studio"),
                [
                    "studio/auth.py",
                    "studio/server.py",
                    "tests/test_security_audit_webui.py",
                    "tests/test_studio_mvp.py",
                ],
            )
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "browser"),
                [
                    ".agents/skills/google-profile/scripts/google_browser.py",
                    ".agents/skills/live-browser/scripts/live_browser_server.py",
                    "tests/test_browser_panel.py",
                    "tests/test_live_browser_profiles.py",
                ],
            )
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "bridge"),
                [
                    "bridge/bridge.py",
                    "bridge/memory_guard.py",
                    "hooks/taint_outbound_guard.py",
                    "scripts/benchmark_digest.py",
                    "tests/test_access_control.py",
                    "tests/test_benchmark_digest.py",
                    "tests/test_memory_guard_and_dream.py",
                    "tests/test_taint_outbound_guard.py",
                ],
            )
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "security"),
                [
                    "hooks/taint_outbound_guard.py",
                    "scripts/security_audit.py",
                    "scripts/sync_live.py",
                    "scripts/verify_gate.py",
                    "tests/test_security_audit_webui.py",
                    "tests/test_taint_outbound_guard.py",
                    "tests/test_verify_gate.py",
                ],
            )
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "all"),
                sorted(files_to_create),
            )

            # Unittest execution plan per scope
            studio_plan = verify_gate.collect_scope_unittest_plan(
                root, "studio", system_py=sys_py, camoufox_py=cf_py
            )
            self.assertEqual(
                studio_plan,
                [
                    (cf_py, "tests/test_studio_mvp.py"),
                    (sys_py, "tests/test_security_audit_webui.py"),
                ],
            )

            browser_plan = verify_gate.collect_scope_unittest_plan(
                root, "browser", system_py=sys_py, camoufox_py=cf_py
            )
            self.assertEqual(
                browser_plan,
                [
                    (sys_py, "tests/test_browser_panel.py"),
                    (sys_py, "tests/test_live_browser_profiles.py"),
                    (cf_py, "tests/test_browser_panel.py"),
                    (cf_py, "tests/test_live_browser_profiles.py"),
                ],
            )

            bridge_plan = verify_gate.collect_scope_unittest_plan(
                root, "bridge", system_py=sys_py, camoufox_py=cf_py
            )
            self.assertEqual(
                bridge_plan,
                [
                    (sys_py, "tests/test_access_control.py"),
                    (sys_py, "tests/test_benchmark_digest.py"),
                    (sys_py, "tests/test_memory_guard_and_dream.py"),
                    (sys_py, "tests/test_taint_outbound_guard.py"),
                ],
            )

            security_plan = verify_gate.collect_scope_unittest_plan(
                root, "security", system_py=sys_py, camoufox_py=cf_py
            )
            self.assertEqual(
                security_plan,
                [
                    (sys_py, "tests/test_security_audit_webui.py"),
                    (sys_py, "tests/test_taint_outbound_guard.py"),
                    (sys_py, "tests/test_verify_gate.py"),
                ],
            )

            all_plan = verify_gate.collect_scope_unittest_plan(
                root, "all", system_py=sys_py, camoufox_py=cf_py
            )
            # test_security_audit_webui.py must be deduplicated across studio & security
            self.assertEqual(
                all_plan.count((sys_py, "tests/test_security_audit_webui.py")),
                1,
            )
            self.assertEqual(len(all_plan), len(set(all_plan)))

    def test_no_real_browser_import_hook_blocks_camoufox_and_playwright(self) -> None:
        finder = verify_gate.NoRealBrowser()
        with self.assertRaises(ImportError):
            finder.find_spec("camoufox", None)
        with self.assertRaises(ImportError):
            finder.find_spec("camoufox.async_api", None)
        with self.assertRaises(ImportError):
            finder.find_spec("playwright", None)
        with self.assertRaises(ImportError):
            finder.find_spec("playwright.sync_api", None)
        self.assertIsNone(finder.find_spec("json", None))

        # Verify actual import interception in a clean subprocess using the inline runner hook
        probe = (
            "import importlib, sys, types\n"
            "from unittest import mock\n"
            "import importlib.abc\n"
            "class NoRealBrowserFinder(importlib.abc.MetaPathFinder):\n"
            "    BLOCKED = ('camoufox', 'playwright')\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        if fullname.split('.', 1)[0] in self.BLOCKED:\n"
            "            raise ImportError(f'Blocked: {fullname}')\n"
            "        return None\n"
            "sys.meta_path.insert(0, NoRealBrowserFinder())\n"
            "for mod_name in ('camoufox', 'camoufox.async_api', 'playwright', 'playwright.async_api'):\n"
            "    try:\n"
            "        importlib.import_module(mod_name)\n"
            "    except ImportError as exc:\n"
            "        assert 'Blocked:' in str(exc), f'unexpected ImportError: {exc}'\n"
            "    else:\n"
            "        raise AssertionError(f'{mod_name} was not blocked')\n"
            "fake_mod = types.ModuleType('camoufox.async_api')\n"
            "with mock.patch.dict(sys.modules, {'camoufox': types.ModuleType('camoufox'), 'camoufox.async_api': fake_mod}):\n"
            "    assert importlib.import_module('camoufox.async_api') is fake_mod\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"Hook probe failed: {proc.stderr}")

        # Verify verify_gate's own unittest runner blocks real camoufox/playwright imports
        with tempfile.TemporaryDirectory(prefix="vg_hook_run_") as td:
            root = Path(td)
            tests_dir = root / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_verify_gate.py").write_text(
                "import unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_blocked(self):\n"
                "        with self.assertRaises(ImportError) as ctx1:\n"
                "            import camoufox  # noqa: F401\n"
                "        self.assertIn('NoRealBrowser', str(ctx1.exception))\n"
                "        with self.assertRaises(ImportError) as ctx2:\n"
                "            import playwright  # noqa: F401\n"
                "        self.assertIn('NoRealBrowser', str(ctx2.exception))\n",
                encoding="utf-8",
            )
            step = verify_gate.step_unittest(
                root,
                "security",
                system_py=sys.executable,
                camoufox_py=None,
            )
            self.assertEqual(step.status, "pass", f"Expected pass, got: {step}")

    def test_protected_file_guard_and_allow_protected_override(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vg_protected_") as td:
            repo = Path(td)
            _init_temp_git_repo(repo)
            for rel in verify_gate.PROTECTED_FILES:
                p = repo / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("# clean baseline\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "initial baseline")

            # Clean repo passes
            clean_res = verify_gate.step_git_hygiene_and_protected(repo, allow_protected=False)
            self.assertEqual(clean_res.status, "pass")
            self.assertEqual(clean_res.exit_code, 0)

            # Modifying a protected file fails by default
            target = repo / verify_gate.PROTECTED_FILES[0]
            target.write_text("# modified baseline\n", encoding="utf-8")
            blocked_res = verify_gate.step_git_hygiene_and_protected(repo, allow_protected=False)
            self.assertEqual(blocked_res.status, "fail")
            self.assertNotEqual(blocked_res.exit_code, 0)
            self.assertIn(verify_gate.PROTECTED_FILES[0], blocked_res.summary)

            # Passing --allow-protected overrides the protected-file block
            allowed_res = verify_gate.step_git_hygiene_and_protected(repo, allow_protected=True)
            self.assertEqual(allowed_res.status, "pass")
            self.assertEqual(allowed_res.exit_code, 0)
            self.assertIn("--allow-protected", allowed_res.summary)

            # Also verify via CLI subprocess with --json
            proc_fail = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "verify_gate.py"),
                    "--scope",
                    "security",
                    "--root",
                    str(repo),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc_fail.returncode, 0)
            data_fail = json.loads(proc_fail.stdout)
            self.assertFalse(data_fail["ok"])

            proc_pass = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "verify_gate.py"),
                    "--scope",
                    "security",
                    "--root",
                    str(repo),
                    "--allow-protected",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_pass.returncode, 0, proc_pass.stdout + proc_pass.stderr)
            data_pass = json.loads(proc_pass.stdout)
            self.assertTrue(data_pass["ok"])

    def test_step_failure_returns_nonzero_json_ok_false_and_preserves_memory_readonly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vg_fail_json_") as td:
            root = Path(td)
            (root / "bridge").mkdir(parents=True)
            (root / "tests").mkdir(parents=True)
            # Intentional syntax error to trigger py_compile failure
            (root / "bridge" / "broken.py").write_text("def bad(:\n    pass\n", encoding="utf-8")
            # Test that checks AGY_MEMORY_READONLY is faithfully preserved when set
            (root / "tests" / "test_memory_guard_and_dream.py").write_text(
                "import os, unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_env_preserved(self):\n"
                "        self.assertEqual(os.environ.get('AGY_MEMORY_READONLY'), '1')\n",
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["AGY_MEMORY_READONLY"] = "1"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "verify_gate.py"),
                    "--scope",
                    "bridge",
                    "--root",
                    str(root),
                    "--json",
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["ok"])
            self.assertGreaterEqual(payload["summary"]["fail"], 1)

            steps_by_name = {s["name"]: s for s in payload["steps"]}
            self.assertEqual(steps_by_name["py_compile"]["status"], "fail")
            self.assertNotEqual(steps_by_name["py_compile"]["exit_code"], 0)
            # Unittest step still ran with AGY_MEMORY_READONLY=1 preserved
            self.assertEqual(steps_by_name["unittest"]["status"], "pass")
            # Zero .pyc pollution in temp repo
            self.assertEqual(list(root.rglob("*.pyc")), [])
            self.assertEqual(list(root.rglob("__pycache__")), [])

    def test_real_repo_security_scope_json_passes(self) -> None:
        if os.environ.get("AGY_VERIFY_GATE_NESTED") == "1":
            self.skipTest("Already running inside verify_gate subprocess; skip recursive self-run")

        cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "verify_gate.py"),
            "--scope",
            "security",
            "--json",
        ]
        if (
            os.environ.get("AGY_EXPORT_PUBLIC_VERIFY") == "1"
            or os.environ.get("AGY_VERIFY_GATE_ALLOW_PROTECTED") == "1"
        ):
            cmd.append("--allow-protected")

        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"verify_gate --scope security --json failed (rc={proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scope"], "security")
        step_names = [s["name"] for s in payload["steps"]]
        self.assertEqual(
            step_names,
            [
                "py_compile",
                "ruff_lint",
                "webui_build",
                "unittest",
                "hooks_agy_canary",
                "audit_secrets",
                "git_hygiene_and_protected",
            ],
        )
        steps_by_name = {s["name"]: s for s in payload["steps"]}
        for required_pass in ("py_compile", "unittest", "audit_secrets", "git_hygiene_and_protected"):
            self.assertEqual(steps_by_name[required_pass]["status"], "pass")
            self.assertEqual(steps_by_name[required_pass]["exit_code"], 0)
        self.assertIn(steps_by_name["hooks_agy_canary"]["status"], ("pass", "skip"))
        self.assertEqual(steps_by_name["hooks_agy_canary"]["exit_code"], 0)

    def test_allow_protected_env_flag_only_set_when_explicitly_enabled(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vg_allow_prot_env_") as td:
            root = Path(td)
            tests_dir = root / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_verify_gate.py").write_text(
                "import os, unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_flag(self):\n"
                "        expected = os.environ.get('EXPECTED_ALLOW_PROTECTED')\n"
                "        self.assertEqual(os.environ.get('AGY_VERIFY_GATE_ALLOW_PROTECTED'), expected)\n",
                encoding="utf-8",
            )
            with unittest.mock.patch.dict(
                os.environ,
                {"EXPECTED_ALLOW_PROTECTED": "", "AGY_VERIFY_GATE_ALLOW_PROTECTED": "1"},
                clear=False,
            ):
                # Pop EXPECTED_ALLOW_PROTECTED so expected is None when allow_protected=False
                os.environ.pop("EXPECTED_ALLOW_PROTECTED", None)
                s_false = verify_gate.step_unittest(
                    root, "security", system_py=sys.executable, camoufox_py=None, allow_protected=False
                )
                self.assertEqual(s_false.status, "pass", f"allow_protected=False should unset env: {s_false}")

            with unittest.mock.patch.dict(os.environ, {"EXPECTED_ALLOW_PROTECTED": "1"}, clear=False):
                s_true = verify_gate.step_unittest(
                    root, "security", system_py=sys.executable, camoufox_py=None, allow_protected=True
                )
                self.assertEqual(s_true.status, "pass", f"allow_protected=True should set env=1: {s_true}")

    def test_c9a_hooks_agy_canary_fail_closed_and_graceful_skip(self) -> None:
        """C9a: Real-protocol fake `agy` verifies pass, bad-protocol failures, timeout fail-closed, and CI skip."""
        # Build a realistic executable fake `agy` that enforces real PreToolUse hook semantics
        fake_agy_code = (
            f"#!{sys.executable}\n"
            "import json, os, pathlib, re, subprocess, sys\n"
            "args = sys.argv[1:]\n"
            "if '--version' in args:\n"
            "    print('1.5.14-canary-sim')\n"
            "    sys.exit(0)\n"
            "# Assert required isolation env vars are set\n"
            "assert os.environ.get('AGY_CLI_DISABLE_AUTO_UPDATE') == '1'\n"
            "assert os.environ.get('AGY_INTERNAL_OBSERVER') == '1'\n"
            "taint_f = os.environ.get('AGY_MEMORY_TAINT_FILE', '')\n"
            "assert taint_f and os.path.dirname(taint_f) == os.getcwd()\n"
            "prompt = args[args.index('-p') + 1]\n"
            "skip_perm = '--dangerously-skip-permissions' in args\n"
            "m_cmd = re.search(r\"CommandLine='([^']+)'\", prompt)\n"
            "cmd_line = m_cmd.group(1) if m_cmd else ''\n"
            "hooks_cfg = json.loads((pathlib.Path.cwd() / '.agents' / 'hooks.json').read_text(encoding='utf-8'))\n"
            "hook_cmd = None\n"
            "for _k, v in hooks_cfg.items():\n"
            "    if isinstance(v, dict) and v.get('enabled', True) and v.get('PreToolUse'):\n"
            "        hook_cmd = v['PreToolUse'][0]['hooks'][0]['command']\n"
            "        break\n"
            "payload = json.dumps({'conversationId': 'conv-sim', 'hookEventName': 'PreToolUse', "
            "'toolCall': {'name': 'run_command', 'args': {'CommandLine': cmd_line}}})\n"
            "hp = subprocess.run(hook_cmd, shell=True, input=payload, text=True, capture_output=True)\n"
            "out = hp.stdout.strip()\n"
            "decision = None\n"
            "reason = ''\n"
            "if hp.returncode != 0:\n"
            "    decision = 'deny'\n"
            "elif out:\n"
            "    data = json.loads(out)\n"
            "    decision = data.get('decision', 'deny')\n"
            "    reason = str(data.get('reason') or '')\n"
            "if decision == 'deny':\n"
            "    msg = f'tool call denied by pre-tool hook: {reason}' if reason else 'tool call denied by pre-tool hook:'\n"
            "    print(json.dumps({'event': 'step_update', 'step_update': {'step_type': 'tool', 'state': 'ERROR', "
            "'tool_name': 'run_command', 'tool_info': {'error': {'type': 'TOOL_ERROR', 'message': msg}}}}))\n"
            "    print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'denied'}}))\n"
            "    sys.exit(0)\n"
            "if skip_perm or decision == 'allow':\n"
            "    subprocess.run(cmd_line, shell=True, check=False)\n"
            "print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'ok'}}))\n"
        )

        with tempfile.TemporaryDirectory(prefix="vg_c9a_") as td:
            root = Path(td)
            fake_agy = root / "fake_agy"
            fake_agy.write_text(fake_agy_code, encoding="utf-8")
            fake_agy.chmod(0o755)

            # 1. Valid candidate hook passes all 4 cases
            res_ok = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                live_mode=False,
                require_enabled=True,
                allow_skip_nested=False,
            )
            self.assertTrue(res_ok["ok"], f"Expected canary pass: {res_ok}")
            self.assertEqual("pass", res_ok["status"])
            self.assertEqual(4, len(res_ok["cases"]))

            # 2. Candidate hook emitting `{}` fails closed
            bad_braces = root / "bad_braces.py"
            bad_braces.write_text("print('{}')\n", encoding="utf-8")
            res_braces = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                hook_script_path=bad_braces,
                live_mode=False,
                require_enabled=True,
            )
            self.assertFalse(res_braces["ok"])
            self.assertEqual("fail", res_braces["status"])

            # 3. Candidate hook emitting `{"decision":"allow"}` breaks /mode safe -> fails closed
            bad_allow = root / "bad_allow.py"
            bad_allow.write_text("import json; print(json.dumps({'decision': 'allow'}))\n", encoding="utf-8")
            res_allow = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                hook_script_path=bad_allow,
                live_mode=False,
                require_enabled=True,
            )
            self.assertFalse(res_allow["ok"])
            self.assertEqual("fail", res_allow["status"])

            # 4. Candidate hook emitting empty-reason deny or non-zero exit fails closed
            bad_empty_reason = root / "bad_empty_reason.py"
            bad_empty_reason.write_text(
                "import json, os; print(json.dumps({'decision': 'deny', 'reason': ''}) if os.environ.get('AGY_UNTRUSTED_SESSION') == '1' else '', end='')\n",
                encoding="utf-8",
            )
            res_empty = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                hook_script_path=bad_empty_reason,
                live_mode=False,
                require_enabled=True,
            )
            self.assertFalse(res_empty["ok"])
            self.assertEqual("fail", res_empty["status"])

            bad_rc = root / "bad_rc.py"
            bad_rc.write_text("import sys; sys.exit(2)\n", encoding="utf-8")
            res_rc = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                hook_script_path=bad_rc,
                live_mode=False,
                require_enabled=True,
            )
            self.assertFalse(res_rc["ok"])
            self.assertEqual("fail", res_rc["status"])

            # 5. Candidate hook that fails to block tainted high-risk command fails closed
            bad_noop = root / "bad_noop.py"
            bad_noop.write_text("pass\n", encoding="utf-8")
            res_noop = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                hook_script_path=bad_noop,
                live_mode=False,
                require_enabled=True,
            )
            self.assertFalse(res_noop["ok"])
            self.assertEqual("fail", res_noop["status"])

            # 6. Timeout in canary MUST fail closed (NEVER degrade to skip)
            slow_agy = root / "slow_agy"
            slow_agy.write_text(
                f"#!{sys.executable}\nimport sys, time\n"
                "if '--version' in sys.argv: print('1.5.14'); sys.exit(0)\n"
                "time.sleep(5)\n",
                encoding="utf-8",
            )
            slow_agy.chmod(0o755)
            res_to = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(slow_agy),
                live_mode=False,
                require_enabled=True,
                timeout_per_case=0.5,
            )
            self.assertFalse(res_to["ok"])
            self.assertEqual("fail", res_to["status"])

            # 7. Missing agy or unauthenticated CI gracefully skips (only when agy_bin not forced)
            with unittest.mock.patch.object(verify_gate, "find_agy_bin", return_value=None):
                res_no_agy = verify_gate.run_hooks_agy_canary(root=REPO_ROOT, live_mode=False)
                self.assertTrue(res_no_agy["ok"])
                self.assertEqual("skip", res_no_agy["status"])

            with (
                unittest.mock.patch.object(verify_gate, "find_agy_bin", return_value=str(fake_agy)),
                unittest.mock.patch.object(verify_gate, "has_agy_auth", return_value=False),
            ):
                res_no_auth = verify_gate.run_hooks_agy_canary(root=REPO_ROOT, live_mode=False)
                self.assertTrue(res_no_auth["ok"])
                self.assertEqual("skip", res_no_auth["status"])

            # 8. Nested verify_gate unittest gracefully skips when allow_skip_nested=True
            with unittest.mock.patch.dict(os.environ, {"AGY_VERIFY_GATE_NESTED": "1"}, clear=False):
                res_nested = verify_gate.run_hooks_agy_canary(
                    root=REPO_ROOT, live_mode=False, allow_skip_nested=True
                )
                self.assertTrue(res_nested["ok"])
                self.assertEqual("skip", res_nested["status"])

    def test_validate_hooks_json_config_rejects_invalid_timeout_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vg_timeout_cfg_") as td:
            root = Path(td)
            for idx, bad_timeout in enumerate(("not-an-int", True, False, {"bad": 1}, [5])):
                hj = root / f"hooks_{idx}.json"
                hj.write_text(
                    json.dumps(
                        {
                            "taint-outbound-guard": {
                                "enabled": True,
                                "PreToolUse": [
                                    {
                                        "matcher": "run_command",
                                        "hooks": [
                                            {
                                                "type": "command",
                                                "command": "/usr/bin/python3 hook.py",
                                                "timeout": bad_timeout,
                                            }
                                        ],
                                    }
                                ],
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                res = verify_gate._validate_hooks_json_config(hj)
                self.assertFalse(res["ok"], f"Expected fail-closed for timeout={bad_timeout!r}, got {res}")
                self.assertIn("timeout", str(res.get("error") or "").lower())

    def test_hooks_agy_canary_isolates_candidate_fake_home_and_preserves_live_home(self) -> None:
        """Candidate canary isolates HOME (empty global hooks.json); live_mode keeps real HOME."""
        with tempfile.TemporaryDirectory(prefix="vg_home_iso_") as td:
            base = Path(td)
            sim_real_home = base / "real_home"
            (sim_real_home / ".gemini" / "antigravity-cli").mkdir(parents=True, exist_ok=True)
            (sim_real_home / ".gemini" / "antigravity-cli" / "auth.marker").write_text("ok", encoding="utf-8")
            (sim_real_home / ".gemini" / "config").mkdir(parents=True, exist_ok=True)
            (sim_real_home / ".gemini" / "config" / "config.json").write_text('{"mode":"test"}\n', encoding="utf-8")
            real_hooks_file = sim_real_home / ".gemini" / "config" / "hooks.json"

            broken_hook_script = base / "broken_global_hook.py"
            broken_hook_script.write_text("print('{}')\n", encoding="utf-8")
            broken_global_cfg = json.dumps(
                {
                    "taint-outbound-guard": {
                        "enabled": True,
                        "PreToolUse": [
                            {
                                "matcher": "run_command",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": f"{sys.executable} {broken_hook_script}",
                                        "timeout": 10,
                                    }
                                ],
                            }
                        ],
                    }
                }
            ) + "\n"
            real_hooks_file.write_text(broken_global_cfg, encoding="utf-8")

            records_file = base / "records.jsonl"
            # Realistic merge-aware fake agy: runs BOTH $HOME/.gemini/config/hooks.json AND <cwd>/.agents/hooks.json
            merge_fake_agy = base / "merge_fake_agy"
            merge_fake_agy.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, re, subprocess, sys\n"
                "args = sys.argv[1:]\n"
                "if '--version' in args:\n"
                "    print('1.5.15-merge-sim')\n"
                "    sys.exit(0)\n"
                "home = pathlib.Path(os.environ['HOME'])\n"
                "global_hooks_path = home / '.gemini' / 'config' / 'hooks.json'\n"
                "global_text = global_hooks_path.read_text(encoding='utf-8') if global_hooks_path.is_file() else ''\n"
                f"with open({str(records_file)!r}, 'a', encoding='utf-8') as rf:\n"
                "    rf.write(json.dumps({\n"
                "        'home': str(home),\n"
                "        'cwd': os.getcwd(),\n"
                "        'global_hooks_text': global_text,\n"
                "        'auth_exists': (home / '.gemini' / 'antigravity-cli' / 'auth.marker').is_file(),\n"
                "        'cfg_exists': (home / '.gemini' / 'config' / 'config.json').is_file(),\n"
                "        'xdg_config': os.environ.get('XDG_CONFIG_HOME'),\n"
                "        'xdg_data': os.environ.get('XDG_DATA_HOME'),\n"
                "    }) + '\\n')\n"
                "prompt = args[args.index('-p') + 1]\n"
                "skip_perm = '--dangerously-skip-permissions' in args\n"
                "m_cmd = re.search(r\"CommandLine='([^']+)'\", prompt)\n"
                "cmd_line = m_cmd.group(1) if m_cmd else ''\n"
                "hook_cmds = []\n"
                "for cfg_path in (global_hooks_path, pathlib.Path.cwd() / '.agents' / 'hooks.json'):\n"
                "    if not cfg_path.is_file():\n"
                "        continue\n"
                "    cfg = json.loads(cfg_path.read_text(encoding='utf-8'))\n"
                "    for _k, v in cfg.items():\n"
                "        if isinstance(v, dict) and v.get('enabled', True) and v.get('PreToolUse'):\n"
                "            hook_cmds.append(v['PreToolUse'][0]['hooks'][0]['command'])\n"
                "payload = json.dumps({'conversationId': 'conv-merge-sim', 'hookEventName': 'PreToolUse',\n"
                "    'toolCall': {'name': 'run_command', 'args': {'CommandLine': cmd_line}}})\n"
                "decision = None\n"
                "reason = ''\n"
                "for hcmd in hook_cmds:\n"
                "    hp = subprocess.run(hcmd, shell=True, input=payload, text=True, capture_output=True)\n"
                "    out = hp.stdout.strip()\n"
                "    if hp.returncode != 0:\n"
                "        decision, reason = 'deny', ''\n"
                "        break\n"
                "    if out:\n"
                "        data = json.loads(out)\n"
                "        decision = data.get('decision', 'deny')\n"
                "        reason = str(data.get('reason') or '')\n"
                "        if decision == 'deny':\n"
                "            break\n"
                "if decision == 'deny':\n"
                "    msg = f'tool call denied by pre-tool hook: {reason}' if reason else 'tool call denied by pre-tool hook:'\n"
                "    print(json.dumps({'event': 'step_update', 'step_update': {'step_type': 'tool', 'state': 'ERROR',\n"
                "        'tool_name': 'run_command', 'tool_info': {'error': {'type': 'TOOL_ERROR', 'message': msg}}}}))\n"
                "    print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'denied'}}))\n"
                "    sys.exit(0)\n"
                "if skip_perm or decision == 'allow':\n"
                "    subprocess.run(cmd_line, shell=True, check=False)\n"
                "print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'ok'}}))\n",
                encoding="utf-8",
            )
            merge_fake_agy.chmod(0o755)

            # 1. Candidate mode (live_mode=False): MUST isolate HOME to fake_home with empty `{}`
            #    so broken global hooks.json does NOT interfere or self-lock, and real hooks.json stays untouched.
            with unittest.mock.patch.dict(
                os.environ,
                {
                    "HOME": str(sim_real_home),
                    "XDG_CONFIG_HOME": str(sim_real_home / ".config"),
                    "XDG_DATA_HOME": str(sim_real_home / ".local" / "share"),
                },
                clear=False,
            ):
                res_cand = verify_gate.run_hooks_agy_canary(
                    root=REPO_ROOT,
                    agy_bin=str(merge_fake_agy),
                    live_mode=False,
                    require_enabled=True,
                    allow_skip_nested=False,
                )
            self.assertTrue(res_cand["ok"], f"Candidate canary should pass despite broken global hook: {res_cand}")
            self.assertEqual("pass", res_cand["status"])
            self.assertEqual(broken_global_cfg, real_hooks_file.read_text(encoding="utf-8"))

            cand_records = [json.loads(line) for line in records_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(4, len(cand_records))
            for rec in cand_records:
                self.assertNotEqual(str(sim_real_home), rec["home"])
                self.assertEqual(str(Path(rec["cwd"]) / "fake_home"), rec["home"])
                self.assertEqual("{}", rec["global_hooks_text"].strip())
                self.assertTrue(rec["auth_exists"])
                self.assertTrue(rec["cfg_exists"])
                self.assertIsNone(rec["xdg_config"])
                self.assertIsNone(rec["xdg_data"])

            # 2. Live mode (live_mode=True): MUST keep real HOME and NOT overwrite hooks.json with `{}`.
            records_file.unlink()
            valid_live_cfg = json.dumps(
                {
                    "taint-outbound-guard": {
                        "enabled": True,
                        "PreToolUse": [
                            {
                                "matcher": "run_command|call_mcp_tool|write_file|edit_file",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": f"{sys.executable} {REPO_ROOT / 'hooks' / 'taint_outbound_guard.py'}",
                                        "timeout": 10,
                                    }
                                ],
                            }
                        ],
                    }
                }
            ) + "\n"
            real_hooks_file.write_text(valid_live_cfg, encoding="utf-8")

            with unittest.mock.patch.dict(os.environ, {"HOME": str(sim_real_home)}, clear=False):
                res_live = verify_gate.run_hooks_agy_canary(
                    agy_bin=str(merge_fake_agy),
                    hooks_json_path=real_hooks_file,
                    hook_script_path=REPO_ROOT / "hooks" / "taint_outbound_guard.py",
                    live_mode=True,
                    require_enabled=True,
                    allow_skip_nested=False,
                )
            self.assertTrue(res_live["ok"], f"Live canary should pass with valid real HOME hooks.json: {res_live}")
            self.assertEqual("pass", res_live["status"])
            self.assertEqual(valid_live_cfg, real_hooks_file.read_text(encoding="utf-8"))

            live_records = [json.loads(line) for line in records_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(4, len(live_records))
            for rec in live_records:
                self.assertEqual(str(sim_real_home), rec["home"])
                self.assertEqual(valid_live_cfg, rec["global_hooks_text"])

    def _write_retry_sim_fake_agy(self, script_path: Path, state_dir: Path, mode: str) -> None:
        """Create an offline fake `agy` script with configurable behavior on `safe_mode_no_auto_allow`."""
        script_path.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, re, subprocess, sys\n"
            "args = sys.argv[1:]\n"
            "if '--version' in args:\n"
            "    print('1.5.15-retry-sim')\n"
            "    sys.exit(0)\n"
            "prompt = args[args.index('-p') + 1]\n"
            "skip_perm = '--dangerously-skip-permissions' in args\n"
            "m_cmd = re.search(r\"CommandLine='([^']+)'\", prompt)\n"
            "cmd_line = m_cmd.group(1) if m_cmd else ''\n"
            "if 'AGY_CANARY_CLEAN_OK' in cmd_line:\n"
            "    case_key = 'clean_pass'\n"
            "elif 'AGY_CANARY_TAINTED_SAFE_OK' in cmd_line:\n"
            "    case_key = 'tainted_safe_pass'\n"
            "elif 'AGY_CANARY_POST_SENT' in cmd_line:\n"
            "    case_key = 'tainted_blocked_deny'\n"
            "elif 'AGY_CANARY_SAFE_BYPASSED' in cmd_line:\n"
            "    case_key = 'safe_mode_no_auto_allow'\n"
            "else:\n"
            "    case_key = 'unknown'\n"
            f"state_dir = pathlib.Path({str(state_dir)!r})\n"
            "state_dir.mkdir(parents=True, exist_ok=True)\n"
            "log_file = state_dir / f'{case_key}.log'\n"
            "with log_file.open('a', encoding='utf-8') as lf:\n"
            "    lf.write(os.getcwd() + '\\n')\n"
            "call_num = len([ln for ln in log_file.read_text(encoding='utf-8').splitlines() if ln.strip()])\n"
            f"mode = {mode!r}\n"
            "if case_key == 'safe_mode_no_auto_allow':\n"
            "    if mode == 'flake_once' and call_num == 1:\n"
            "        print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'plain text without tool call'}}))\n"
            "        sys.exit(0)\n"
            "    if mode == 'flake_always':\n"
            "        print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'still no tool call'}}))\n"
            "        sys.exit(0)\n"
            "    if mode == 'breach_out_file':\n"
            "        subprocess.run(cmd_line, shell=True, check=False)\n"
            "        print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'executed without hook'}}))\n"
            "        sys.exit(0)\n"
            "    if mode == 'empty_reason_denial':\n"
            "        print(json.dumps({'event': 'step_update', 'step_update': {'step_type': 'tool', 'state': 'ERROR',\n"
            "            'tool_name': 'run_command', 'tool_info': {'error': {'type': 'TOOL_ERROR', 'message': 'tool call denied by pre-tool hook:'}}}}))\n"
            "        print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'denied'}}))\n"
            "        sys.exit(0)\n"
            "    if mode == 'stderr_error':\n"
            "        sys.stderr.write('pretool hook protocol error\\n')\n"
            "        print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'plain text'}}))\n"
            "        sys.exit(0)\n"
            "hooks_cfg = json.loads((pathlib.Path.cwd() / '.agents' / 'hooks.json').read_text(encoding='utf-8'))\n"
            "hook_cmd = None\n"
            "for _k, v in hooks_cfg.items():\n"
            "    if isinstance(v, dict) and v.get('enabled', True) and v.get('PreToolUse'):\n"
            "        hook_cmd = v['PreToolUse'][0]['hooks'][0]['command']\n"
            "        break\n"
            "payload = json.dumps({'conversationId': 'conv-retry-sim', 'hookEventName': 'PreToolUse',\n"
            "    'toolCall': {'name': 'run_command', 'args': {'CommandLine': cmd_line}}})\n"
            "hp = subprocess.run(hook_cmd, shell=True, input=payload, text=True, capture_output=True)\n"
            "out = hp.stdout.strip()\n"
            "decision = None\n"
            "reason = ''\n"
            "if hp.returncode != 0:\n"
            "    decision = 'deny'\n"
            "elif out:\n"
            "    data = json.loads(out)\n"
            "    decision = data.get('decision', 'deny')\n"
            "    reason = str(data.get('reason') or '')\n"
            "if decision == 'deny':\n"
            "    msg = f'tool call denied by pre-tool hook: {reason}' if reason else 'tool call denied by pre-tool hook:'\n"
            "    print(json.dumps({'event': 'step_update', 'step_update': {'step_type': 'tool', 'state': 'ERROR',\n"
            "        'tool_name': 'run_command', 'tool_info': {'error': {'type': 'TOOL_ERROR', 'message': msg}}}}))\n"
            "    print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'denied'}}))\n"
            "    sys.exit(0)\n"
            "if skip_perm or decision == 'allow':\n"
            "    subprocess.run(cmd_line, shell=True, check=False)\n"
            "print(json.dumps({'event': 'result', 'result': {'status': 'SUCCESS', 'response': 'ok'}}))\n",
            encoding="utf-8",
        )
        script_path.chmod(0o755)

    def test_hooks_agy_canary_retries_once_on_pure_no_tool_call_flake(self) -> None:
        """Case A: rc=0 + no marker + no out + no denial/stderr -> retries once in fresh tmpdir and passes."""
        with tempfile.TemporaryDirectory(prefix="vg_retry_a_") as td:
            base = Path(td)
            state_dir = base / "state"
            fake_agy = base / "fake_agy_flake_once"
            self._write_retry_sim_fake_agy(fake_agy, state_dir, mode="flake_once")

            res = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                live_mode=False,
                require_enabled=True,
                allow_skip_nested=False,
            )
            self.assertTrue(res["ok"], f"Expected pass after bounded 1x retry: {res}")
            self.assertEqual("pass", res["status"])
            cases_by_name = {c["name"]: c for c in res["cases"]}
            self.assertEqual("pass", cases_by_name["safe_mode_no_auto_allow"]["status"])
            self.assertEqual(2, cases_by_name["safe_mode_no_auto_allow"]["attempts"])

            cwds = [
                ln.strip()
                for ln in (state_dir / "safe_mode_no_auto_allow.log").read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(2, len(cwds))
            self.assertNotEqual(cwds[0], cwds[1], "Retry must use an independent isolated temp directory")
            for other in ("clean_pass", "tainted_safe_pass", "tainted_blocked_deny"):
                self.assertEqual(1, cases_by_name[other]["attempts"])

    def test_hooks_agy_canary_no_retry_on_security_breach_or_empty_denial(self) -> None:
        """Case B: Security breach (out_file written), empty-reason denial, or stderr error MUST NOT retry."""
        for mode in ("breach_out_file", "empty_reason_denial", "stderr_error"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix=f"vg_retry_b_{mode}_") as td:
                base = Path(td)
                state_dir = base / "state"
                fake_agy = base / f"fake_agy_{mode}"
                self._write_retry_sim_fake_agy(fake_agy, state_dir, mode=mode)

                res = verify_gate.run_hooks_agy_canary(
                    root=REPO_ROOT,
                    agy_bin=str(fake_agy),
                    live_mode=False,
                    require_enabled=True,
                    allow_skip_nested=False,
                )
                self.assertFalse(res["ok"], f"Mode {mode} must fail closed: {res}")
                self.assertEqual("fail", res["status"])
                cases_by_name = {c["name"]: c for c in res["cases"]}
                safe_case = cases_by_name["safe_mode_no_auto_allow"]
                self.assertEqual("fail", safe_case["status"])
                self.assertEqual(1, safe_case["attempts"], f"Mode {mode} must NOT retry")
                invocations = [
                    ln.strip()
                    for ln in (state_dir / "safe_mode_no_auto_allow.log").read_text(encoding="utf-8").splitlines()
                    if ln.strip()
                ]
                self.assertEqual(1, len(invocations), f"Mode {mode} invoked agy {len(invocations)} times, expected 1")

    def test_hooks_agy_canary_fails_closed_after_two_consecutive_no_tool_call_flakes(self) -> None:
        """Case C: 2 consecutive no-tool-call runs MUST fail closed (ok=False, status='fail', never 'skip')."""
        with tempfile.TemporaryDirectory(prefix="vg_retry_c_") as td:
            base = Path(td)
            state_dir = base / "state"
            fake_agy = base / "fake_agy_flake_always"
            self._write_retry_sim_fake_agy(fake_agy, state_dir, mode="flake_always")

            res = verify_gate.run_hooks_agy_canary(
                root=REPO_ROOT,
                agy_bin=str(fake_agy),
                live_mode=False,
                require_enabled=True,
                allow_skip_nested=False,
            )
            self.assertFalse(res["ok"], f"2 consecutive no-marker runs must fail closed: {res}")
            self.assertEqual("fail", res["status"])
            cases_by_name = {c["name"]: c for c in res["cases"]}
            safe_case = cases_by_name["safe_mode_no_auto_allow"]
            self.assertEqual("fail", safe_case["status"])
            self.assertEqual(2, safe_case["attempts"])
            self.assertIn("never invoked", safe_case.get("error", ""))

            cwds = [
                ln.strip()
                for ln in (state_dir / "safe_mode_no_auto_allow.log").read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(2, len(cwds))
            self.assertNotEqual(cwds[0], cwds[1])


if __name__ == "__main__":
    unittest.main()
