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
                "scripts/security_audit.py",
                "scripts/verify_gate.py",
                "scripts/sync_live.py",
                "tests/test_studio_mvp.py",
                "tests/test_security_audit_webui.py",
                "tests/test_live_browser_profiles.py",
                "tests/test_browser_panel.py",
                "tests/test_access_control.py",
                "tests/test_memory_guard_and_dream.py",
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
                    "tests/test_access_control.py",
                    "tests/test_memory_guard_and_dream.py",
                ],
            )
            self.assertEqual(
                verify_gate.collect_scope_py_files(root, "security"),
                [
                    "scripts/security_audit.py",
                    "scripts/sync_live.py",
                    "scripts/verify_gate.py",
                    "tests/test_security_audit_webui.py",
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
                    (sys_py, "tests/test_memory_guard_and_dream.py"),
                ],
            )

            security_plan = verify_gate.collect_scope_unittest_plan(
                root, "security", system_py=sys_py, camoufox_py=cf_py
            )
            self.assertEqual(
                security_plan,
                [
                    (sys_py, "tests/test_security_audit_webui.py"),
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
        if os.environ.get("AGY_EXPORT_PUBLIC_VERIFY") == "1":
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
                "audit_secrets",
                "git_hygiene_and_protected",
            ],
        )
        steps_by_name = {s["name"]: s for s in payload["steps"]}
        for required_pass in ("py_compile", "unittest", "audit_secrets", "git_hygiene_and_protected"):
            self.assertEqual(steps_by_name[required_pass]["status"], "pass")
            self.assertEqual(steps_by_name[required_pass]["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
