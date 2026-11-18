#!/usr/bin/env python3
"""Offline unit tests for `bridge/cli.py` (`agy-bot doctor` & `agy-bot setup`)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import cli  # noqa: E402


def _make_fake_agy(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    agy = bin_dir / "agy"
    agy.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    agy.chmod(0o755)
    return agy


def _write_valid_env(env_path: Path, workdir: Path, agy_bin: Path, lock_dir: Path) -> None:
    env_path.write_text(
        "\n".join(
            [
                "AGY_TG_BOT_TOKEN=123456789:TEST_VALID_BOT_TOKEN_PAYLOAD_12345",
                "AGY_TG_ALLOWED_CHATS=-1001234567890",
                f"AGY_TG_WORKDIR={workdir}",
                f"AGY_TG_AGY_BIN={agy_bin}",
                f"AGY_TG_STATE_FILE={workdir / 'state.json'}",
                f"AGY_TG_LOCK_DIR={lock_dir}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(env_path, 0o600)


class TestAgyBotDoctor(unittest.TestCase):
    """Offline tests for `agy-bot doctor` diagnostics."""

    def test_doctor_fails_on_missing_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_env = Path(tmp) / "missing.env"
            with mock.patch.dict(os.environ, {"AGY_TG_BOT_TOKEN": "", "AGY_TG_ALLOWED_CHATS": ""}, clear=False):
                rc, report = cli.run_doctor(env_file=missing_env)
            self.assertEqual(1, rc)
            self.assertEqual("fail", report["status"])
            by_name = {c["name"]: c for c in report["checks"]}
            self.assertEqual("FAIL", by_name["env_file"]["status"])
            self.assertEqual("FAIL", by_name["bot_token"]["status"])
            self.assertEqual("FAIL", by_name["allowed_chats"]["status"])

    def test_doctor_rejects_placeholder_token_and_bad_allowed_chats(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "AGY_TG_BOT_TOKEN=1234567890:REPLACE_WITH_TELEGRAM_BOT_TOKEN",
                        "AGY_TG_ALLOWED_CHATS=not-an-id",
                        f"AGY_TG_WORKDIR={tmp}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o600)
            rc, report = cli.run_doctor(env_file=env_path)
            self.assertEqual(1, rc)
            by_name = {c["name"]: c for c in report["checks"]}
            self.assertEqual("FAIL", by_name["bot_token"]["status"])
            self.assertIn("placeholder", by_name["bot_token"]["message"])
            self.assertEqual("FAIL", by_name["allowed_chats"]["status"])

    def test_doctor_full_pass_and_json_cli_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workdir = root / "workspace"
            workdir.mkdir()
            lock_dir = root / "locks"
            lock_dir.mkdir()
            agy_bin = _make_fake_agy(root / "bin")
            env_path = root / ".env"
            _write_valid_env(env_path, workdir, agy_bin, lock_dir)

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["doctor", "--env-file", str(env_path), "--json"])
            self.assertEqual(0, rc)
            payload = json.loads(buf.getvalue())
            self.assertEqual("ok", payload["status"])
            self.assertFalse(payload["online_checked"])
            self.assertEqual(0, payload["summary"]["fail"])
            self.assertEqual(0, payload["summary"]["warn"])
            self.assertTrue(all(c["status"] == "PASS" for c in payload["checks"]))

    def test_doctor_online_mock_success_and_failure_without_token_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workdir = root / "workspace"
            workdir.mkdir()
            lock_dir = root / "locks"
            lock_dir.mkdir()
            agy_bin = _make_fake_agy(root / "bin")
            env_path = root / ".env"
            _write_valid_env(env_path, workdir, agy_bin, lock_dir)

            class _Resp:
                def __init__(self, status_code, body):
                    self.status_code = status_code
                    self._body = body

                def json(self):
                    return self._body

            ok_get = mock.Mock(
                return_value=_Resp(200, {"ok": True, "result": {"id": 987654321, "username": "example_bot"}})
            )
            rc_ok, rep_ok = cli.run_doctor(env_file=env_path, online=True, http_get=ok_get)
            self.assertEqual(0, rc_ok)
            self.assertEqual("ok", rep_ok["status"])
            by_name_ok = {c["name"]: c for c in rep_ok["checks"]}
            self.assertEqual("PASS", by_name_ok["telegram_online"]["status"])
            self.assertIn("@example_bot", by_name_ok["telegram_online"]["message"])
            ok_get.assert_called_once()

            err_get = mock.Mock(side_effect=RuntimeError("boom with secret TEST_VALID_BOT_TOKEN_PAYLOAD_12345"))
            rc_err, rep_err = cli.run_doctor(env_file=env_path, online=True, http_get=err_get)
            self.assertEqual(1, rc_err)
            by_name_err = {c["name"]: c for c in rep_err["checks"]}
            self.assertEqual("FAIL", by_name_err["telegram_online"]["status"])
            self.assertNotIn("TEST_VALID_BOT_TOKEN_PAYLOAD_12345", json.dumps(rep_err))

    def test_doctor_detects_unwritable_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ro_parent = root / "readonly"
            ro_parent.mkdir()
            agy_bin = _make_fake_agy(root / "bin")
            env_path = root / ".env"
            _write_valid_env(env_path, ro_parent / "ws", agy_bin, root / "locks")
            with mock.patch.object(cli, "_dir_writable_readonly", return_value=(False, ro_parent, "permission denied")):
                rc, rep = cli.run_doctor(env_file=env_path)
            self.assertEqual(1, rc)
            by_name = {c["name"]: c for c in rep["checks"]}
            self.assertEqual("FAIL", by_name["dir_permissions"]["status"])

    def test_doctor_readonly_warns_on_0644_and_fix_tightens_to_0600_and_creates_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_ws = root / "nested" / "workspace"
            missing_state_dir = root / "state_parent"
            lock_dir = root / "locks"
            agy_bin = _make_fake_agy(root / "bin")
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "AGY_TG_BOT_TOKEN=123456789:TEST_VALID_BOT_TOKEN_PAYLOAD_12345",
                        "AGY_TG_ALLOWED_CHATS=-1001234567890",
                        f"AGY_TG_WORKDIR={missing_ws}",
                        f"AGY_TG_AGY_BIN={agy_bin}",
                        f"AGY_TG_STATE_FILE={missing_state_dir / 'state.json'}",
                        f"AGY_TG_LOCK_DIR={lock_dir}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o644)

            # Default doctor stays strictly read-only: reports WARN on 0o644 and does not create missing dirs
            rc_ro, rep_ro = cli.run_doctor(env_file=env_path)
            self.assertEqual(0, rc_ro)
            self.assertEqual("warn", rep_ro["status"])
            by_name_ro = {c["name"]: c for c in rep_ro["checks"]}
            self.assertEqual("WARN", by_name_ro["env_file"]["status"])
            self.assertEqual(0o644, stat.S_IMODE(env_path.stat().st_mode))
            self.assertFalse(missing_ws.exists())
            self.assertFalse(missing_state_dir.exists())

            # `doctor --fix` tightens .env to 0o600 and creates missing writable dirs -> PASS
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_fix = cli.main(["doctor", "--env-file", str(env_path), "--fix", "--json"])
            self.assertEqual(0, rc_fix)
            payload = json.loads(buf.getvalue())
            self.assertEqual("ok", payload["status"])
            self.assertTrue(payload["fix_mode"])
            self.assertEqual(0, payload["summary"]["warn"])
            self.assertEqual(0, payload["summary"]["fail"])
            by_name_fix = {c["name"]: c for c in payload["checks"]}
            self.assertEqual("PASS", by_name_fix["env_file"]["status"])
            self.assertIn("auto-fixed permission -> 0o600", by_name_fix["env_file"]["message"])
            self.assertEqual(0o600, stat.S_IMODE(env_path.stat().st_mode))
            self.assertTrue(missing_ws.is_dir())
            self.assertTrue(missing_state_dir.is_dir())
            self.assertTrue(lock_dir.is_dir())

    def test_doctor_agy_cli_standard_home_discovery_and_missing_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_home = root / "home"
            fake_home.mkdir()
            workdir = root / "ws"
            workdir.mkdir()
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "AGY_TG_BOT_TOKEN=123456789:TEST_VALID_BOT_TOKEN_PAYLOAD_12345",
                        "AGY_TG_ALLOWED_CHATS=-1001234567890",
                        f"AGY_TG_WORKDIR={workdir}",
                        f"AGY_TG_STATE_FILE={workdir / 'state.json'}",
                        f"AGY_TG_LOCK_DIR={workdir}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o600)

            local_agy = _make_fake_agy(fake_home / ".local" / "bin")
            env_patch = {"HOME": str(fake_home), "PATH": "/nonexistent/bin", "AGY_TG_AGY_BIN": ""}
            with mock.patch.dict(os.environ, env_patch, clear=False):
                rc_found, rep_found = cli.run_doctor(env_file=env_path)
            self.assertEqual(0, rc_found)
            by_name_found = {c["name"]: c for c in rep_found["checks"]}
            self.assertEqual("PASS", by_name_found["agy_cli"]["status"])
            self.assertIn(str(local_agy), by_name_found["agy_cli"]["message"])

            # Removing ~/.local/bin/agy and assuming no system-wide /usr/(local/)bin/agy -> WARN
            local_agy.unlink()
            orig_is_file = Path.is_file

            def _hide_system_agy(self: Path) -> bool:
                if self in (Path("/usr/local/bin/agy"), Path("/usr/bin/agy")):
                    return False
                return orig_is_file(self)

            with (
                mock.patch.dict(os.environ, env_patch, clear=False),
                mock.patch.object(Path, "is_file", _hide_system_agy),
            ):
                rc_miss, rep_miss = cli.run_doctor(env_file=env_path)
            self.assertEqual(0, rc_miss)
            by_name_miss = {c["name"]: c for c in rep_miss["checks"]}
            self.assertEqual("WARN", by_name_miss["agy_cli"]["status"])


class TestAgyBotSetup(unittest.TestCase):
    """Offline tests for `agy-bot setup` idempotency and non-overwrite guarantees."""

    def test_setup_copies_runtime_creates_env_600_and_preserves_existing_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "runtime"
            with contextlib.redirect_stdout(io.StringIO()):
                rc1 = cli.main(
                    [
                        "setup",
                        "--target-dir",
                        str(target),
                        "--non-interactive",
                        "--bot-token",
                        "123456789:TEST_SETUP_TOKEN_VALUE_987654321",
                        "--allowed-chats",
                        "-1001234567890",
                        "--workdir",
                        str(Path(tmp) / "ws"),
                    ]
                )
            self.assertEqual(0, rc1)
            for fname in cli.RUNTIME_BRIDGE_FILES:
                self.assertTrue((target / fname).is_file(), f"Expected copied file: {fname}")
            env_file = target / ".env"
            self.assertTrue(env_file.is_file())
            self.assertEqual(0o600, stat.S_IMODE(env_file.stat().st_mode))
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("AGY_TG_BOT_TOKEN=123456789:TEST_SETUP_TOKEN_VALUE_987654321", content)
            self.assertIn("AGY_TG_ALLOWED_CHATS=-1001234567890", content)

            # Mutate .env with custom setting & overly broad permissions; re-running setup without --force MUST preserve it and tighten to 0o600.
            env_file.write_text("AGY_TG_BOT_TOKEN=EXAMPLE_CUSTOM_KEEP_ME_SAFE\n", encoding="utf-8")
            os.chmod(env_file, 0o644)
            rc2, res2 = cli.run_setup(
                target_dir=target,
                non_interactive=True,
                bot_token="123456789:EXAMPLE_DO_NOT_OVERWRITE_1234",
            )
            self.assertEqual(0, rc2)
            self.assertEqual("preserved", res2["env_action"])
            self.assertEqual(0o600, stat.S_IMODE(env_file.stat().st_mode))
            self.assertEqual("AGY_TG_BOT_TOKEN=EXAMPLE_CUSTOM_KEEP_ME_SAFE\n", env_file.read_text(encoding="utf-8"))

            # With --force, .env IS updated cleanly.
            rc3, res3 = cli.run_setup(
                target_dir=target,
                non_interactive=True,
                force=True,
                bot_token="123456789:EXAMPLE_FORCED_NEW_TOKEN_1234",
            )
            self.assertEqual(0, rc3)
            self.assertEqual("overwritten", res3["env_action"])
            self.assertIn("EXAMPLE_FORCED_NEW_TOKEN_1234", env_file.read_text(encoding="utf-8"))

    def test_setup_check_only_writes_zero_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nonexistent-runtime"
            rc, res = cli.run_setup(target_dir=target, non_interactive=True, check_only=True)
            self.assertEqual(0, rc)
            self.assertEqual("check_only", res["status"])
            self.assertFalse(target.exists())

    def test_module_entrypoint_bridge_cli_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "bridge.cli", "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, res.returncode, res.stderr)
        self.assertIn("doctor", res.stdout)
        self.assertIn("setup", res.stdout)


if __name__ == "__main__":
    unittest.main()
