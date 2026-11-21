#!/usr/bin/env python3
"""Offline unit tests for `AGY_CLI_DISABLE_AUTO_UPDATE=1` full-chain guard & `scripts/agy_cli_upgrade.py`.

Covers QA Pre-Flight Contract C1..C7:
- C1: All 6 `bridge/bridge.py` `AGY_BIN` launch sites + 1 `mem-hub/agy_llm_shim.py` site
      apply `_apply_agy_auto_update_env` after `_apply_exec_env`/`_strip_gateway_env`,
      defaulting to `"1"`, popping on `" False "`/`"0"`/`"no"`/`"off"`, and resisting
      blank/stale `exec_plan["env_set"]` overrides.
- C2: Fully isolated from ambient `AGY_CLI_DISABLE_AUTO_UPDATE=0` or `=1` in host shell;
      zero `os.environ` pollution.
- C3: `scripts/agy_cli_upgrade.py` no-args/`--check`/`--backup-only` never call `agy update`;
      backup failure fails closed; only `agy update` child env copy pops the flag; no `shell=True`;
      manifest URL requires `https://` with explicit timeout.
- C4: `--rollback` blocks `../../etc/passwd`, outside paths, symlink backups, symlink targets,
      missing/tampered `.sha256`; atomic same-dir temp file + `fsync` + `0755` + `os.replace`
      + `finally` cleanup; backup dir `0700` & `.sha256` `0600`.
- C5: `export_public.py`, `verify_gate.py`, and zero hardcoded home paths in `agy_cli_upgrade.py`.
- C6: `bridge/.env.example`, `bridge/cli.py`, and systemd units carry `AGY_CLI_DISABLE_AUTO_UPDATE=1`.
- C7: Zero real network calls, zero real `agy update`, zero writes to host `$HOME`.
"""

from __future__ import annotations

import asyncio
import contextlib
from email.message import Message as EmailMessage
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.response

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
MEM_HUB_DIR = REPO_ROOT / "mem-hub"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (BRIDGE_DIR, MEM_HUB_DIR, SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import agy_cli_upgrade  # noqa: E402
import cli as bridge_cli  # noqa: E402


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str | None] | None = None):
    """Reload `bridge` under a deterministic isolated env regardless of host shell env."""
    saved_present = "AGY_CLI_DISABLE_AUTO_UPDATE" in os.environ
    saved_val = os.environ.get("AGY_CLI_DISABLE_AUTO_UPDATE")
    env_patch: dict[str, str] = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_AUTO_UPDATE_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
    }
    unset_keys: list[str] = [
        "AGY_CLI_DISABLE_AUTO_UPDATE",
        "AGY_TG_BOT_MODEL",
        "AGY_TG_BOT_EFFORT",
    ]
    if extra_env:
        for k, v in extra_env.items():
            if v is None:
                if k not in unset_keys:
                    unset_keys.append(k)
                env_patch.pop(k, None)
            else:
                env_patch[k] = v
                if k in unset_keys:
                    unset_keys.remove(k)

    with mock.patch.dict(os.environ, env_patch, clear=False):
        for k in unset_keys:
            os.environ.pop(k, None)
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)

    # Verify host os.environ was not polluted
    if saved_present:
        assert os.environ.get("AGY_CLI_DISABLE_AUTO_UPDATE") == saved_val
    else:
        assert "AGY_CLI_DISABLE_AUTO_UPDATE" not in os.environ
    return bridge


def _load_isolated_shim(extra_env: dict[str, str | None] | None = None):
    env_patch: dict[str, str] = {}
    unset_keys: list[str] = ["AGY_CLI_DISABLE_AUTO_UPDATE"]
    if extra_env:
        for k, v in extra_env.items():
            if v is None:
                if k not in unset_keys:
                    unset_keys.append(k)
                env_patch.pop(k, None)
            else:
                env_patch[k] = v
                if k in unset_keys:
                    unset_keys.remove(k)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        for k in unset_keys:
            os.environ.pop(k, None)
        import agy_llm_shim  # noqa: E402

        importlib.reload(agy_llm_shim)
        return agy_llm_shim


def _make_fake_popen():
    proc = mock.MagicMock()
    proc.pid = 424242
    proc.stdin = io.StringIO()
    proc.stdout = io.StringIO("")
    proc.stderr = io.StringIO("")
    proc.poll.return_value = 0
    proc.wait.return_value = 0
    proc.returncode = 0
    return proc


class TestBridgeAutoUpdateGuard(unittest.TestCase):
    """C1 & C2: Verify helper semantics and all 6 `bridge/bridge.py` `AGY_BIN` launch sites."""

    def test_helper_semantics_and_module_default_across_env_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            self.assertTrue(bridge.DISABLE_AGY_AUTO_UPDATE)

            # Unset or blank -> follows DISABLE_AGY_AUTO_UPDATE ("1")
            for raw_env in ({}, {"AGY_CLI_DISABLE_AUTO_UPDATE": ""}, {"AGY_CLI_DISABLE_AUTO_UPDATE": "   "}):
                env = dict(raw_env)
                bridge._apply_agy_auto_update_env(env)
                self.assertEqual("1", env.get("AGY_CLI_DISABLE_AUTO_UPDATE"))

            # Explicit truthy -> normalized to "1"
            for val in ("1", "true", "TRUE", " yes ", "On"):
                env = {"AGY_CLI_DISABLE_AUTO_UPDATE": val}
                bridge._apply_agy_auto_update_env(env)
                self.assertEqual("1", env.get("AGY_CLI_DISABLE_AUTO_UPDATE"))

            # Explicit falsy -> popped completely (never "0" or "")
            for val in ("0", " False ", "FALSE", "no", " NO ", "off", " OFF "):
                env = {"AGY_CLI_DISABLE_AUTO_UPDATE": val}
                bridge._apply_agy_auto_update_env(env)
                self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", env)

            # Module imported with AGY_CLI_DISABLE_AUTO_UPDATE=0 -> DISABLE_AGY_AUTO_UPDATE=False
            bridge_off = _load_isolated_bridge(tmp, {"AGY_CLI_DISABLE_AUTO_UPDATE": "0"})
            self.assertFalse(bridge_off.DISABLE_AGY_AUTO_UPDATE)
            env_empty: dict[str, str] = {}
            bridge_off._apply_agy_auto_update_env(env_empty)
            self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", env_empty)

    def _run_with_env(self, override: str | None, fn):
        """Execute `fn()` with `AGY_CLI_DISABLE_AUTO_UPDATE` patched to `override` (None = unset)."""
        with mock.patch.dict(os.environ, {}, clear=False):
            if override is None:
                os.environ.pop("AGY_CLI_DISABLE_AUTO_UPDATE", None)
            else:
                os.environ["AGY_CLI_DISABLE_AUTO_UPDATE"] = override
            return fn()

    def test_site1_agy_session_init_all_modes_and_exec_plan_override_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_envs: list[dict[str, str]] = []

            def _fake_popen(cmd, **kwargs):
                captured_envs.append(dict(kwargs["env"]))
                return _make_fake_popen()

            adversarial_plan = {
                "kind": "gateway",
                "cli_model": "demo-model",
                "cli_effort": None,
                "env_set": {
                    "AGY_LLM_GATEWAY_URL": "http://127.0.0.1:19999/v1",
                    "AGY_CLI_DISABLE_AUTO_UPDATE": "",
                },
                "gateway_id": "demo",
                "upstream_model": "demo-model",
                "effort": None,
                "signature": ("gateway", "demo", "demo-model", "", "fp", 19999),
            }
            adversarial_zero_plan = dict(adversarial_plan)
            adversarial_zero_plan["env_set"] = {
                "AGY_LLM_GATEWAY_URL": "http://127.0.0.1:19999/v1",
                "AGY_CLI_DISABLE_AUTO_UPDATE": "0",
            }

            with (
                mock.patch.object(bridge.subprocess, "Popen", side_effect=_fake_popen),
                mock.patch.object(bridge.threading, "Thread", return_value=mock.MagicMock()),
            ):
                # Default unset + blank env_set -> must be "1"
                with mock.patch.object(bridge, "_resolve_exec_target", return_value=adversarial_plan):
                    self._run_with_env(None, lambda: bridge.AgySession(None, "auto", None, None, workdir=tmp))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))
                self.assertEqual("http://127.0.0.1:19999/v1", captured_envs[-1].get("AGY_LLM_GATEWAY_URL"))

                # Default unset + stale "0" in env_set -> must still be "1"
                with mock.patch.object(bridge, "_resolve_exec_target", return_value=adversarial_zero_plan):
                    self._run_with_env(None, lambda: bridge.AgySession(None, "auto", None, None, workdir=tmp))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                # Explicit falsy values in os.environ -> popped completely
                with mock.patch.object(bridge, "_resolve_exec_target", return_value=adversarial_plan):
                    for falsy in (" False ", "0", "no", "off"):
                        self._run_with_env(falsy, lambda: bridge.AgySession(None, "auto", None, None, workdir=tmp))
                        self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

    def test_site2_fast_group_reply_all_modes_and_exec_plan_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_envs: list[dict[str, str]] = []

            def _fake_run_group(cmd, cwd, timeout_s, env=None, shell=False):
                captured_envs.append(dict(env or {}))
                return 0, json.dumps({"response": "ok"}), ""

            plan = {
                "kind": "native",
                "cli_model": None,
                "cli_effort": None,
                "env_set": {"AGY_CLI_DISABLE_AUTO_UPDATE": "   "},
                "gateway_id": None,
                "upstream_model": None,
                "effort": None,
                "signature": ("native", "", ""),
            }
            with (
                mock.patch.object(bridge, "_resolve_exec_target", return_value=plan),
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=_fake_run_group),
                mock.patch.object(bridge, "send_rich", return_value=(101, None)),
                mock.patch.object(bridge, "send", return_value={"ok": True, "result": {"message_id": 101}}),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg", return_value=None),
                mock.patch.object(bridge.bot_bus, "format_unseen_group_history", return_value=""),
            ):
                self._run_with_env(
                    None,
                    lambda: bridge._run_fast_group_reply(
                        -1001234567890,
                        "ping",
                        scope_key="-1001234567890",
                        busy_desc="busy",
                    ),
                )
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                for falsy in (" False ", "0", "no", "off"):
                    self._run_with_env(
                        falsy,
                        lambda: bridge._run_fast_group_reply(
                            -1001234567890,
                            "ping",
                            scope_key="-1001234567890",
                            busy_desc="busy",
                        ),
                    )
                    self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

    def test_site3_scheduled_task_runner_all_modes_and_exec_plan_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_envs: list[dict[str, str]] = []

            def _fake_run_group(cmd, cwd, timeout_s, env=None, shell=False):
                captured_envs.append(dict(env or {}))
                return 0, json.dumps({"response": "[SILENT]"}), ""

            plan = {
                "kind": "native",
                "cli_model": None,
                "cli_effort": None,
                "env_set": {"AGY_CLI_DISABLE_AUTO_UPDATE": ""},
                "gateway_id": None,
                "upstream_model": None,
                "effort": None,
                "signature": ("native", "", ""),
            }
            task = {
                "id": "sched-test-1",
                "name": "Check Guard",
                "task_type": "prompt",
                "payload": {"prompt": "say silent", "use_memory": False},
                "execution": {"workdir": tmp, "timeout_secs": 30},
                "delivery": {"target_chat_id": -1001234567890, "silent_if_empty": True},
            }
            with (
                mock.patch.object(bridge, "_resolve_exec_target", return_value=plan),
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=_fake_run_group),
                mock.patch.object(bridge.scheduler.task_mgr, "record_completion", return_value=None),
            ):
                self._run_with_env(None, lambda: bridge.execute_scheduled_task(task))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                for falsy in (" False ", "0", "no", "off"):
                    self._run_with_env(falsy, lambda: bridge.execute_scheduled_task(task))
                    self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

    def test_site4_execute_bus_job_all_modes_and_exec_plan_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_envs: list[dict[str, str]] = []

            def _fake_popen(cmd, **kwargs):
                captured_envs.append(dict(kwargs["env"]))
                proc = _make_fake_popen()
                proc.stdout = io.StringIO(
                    json.dumps({"event": "result", "result": {"status": "SUCCESS", "response": "done"}}) + "\n"
                )
                return proc

            plan = {
                "kind": "native",
                "cli_model": None,
                "cli_effort": None,
                "env_set": {"AGY_CLI_DISABLE_AUTO_UPDATE": "0"},
                "gateway_id": None,
                "upstream_model": None,
                "effort": None,
                "signature": ("native", "", ""),
            }
            job = {
                "id": "job-test-guard",
                "label": "Test Guard",
                "prompt": "hello",
                "from_bot": "bot_one",
                "to_bot": "bot_two",
                "mode": "auto",
                "workdir": tmp,
                "notify_group": False,
            }
            with (
                mock.patch.object(bridge.bot_bus, "claim_job", return_value=job),
                mock.patch.object(bridge.bot_bus, "finish_job", return_value=None),
                mock.patch.object(bridge.bot_bus, "is_job_cancelled", return_value=False),
                mock.patch.object(bridge, "_publish_bot_heartbeat", return_value=None),
                mock.patch.object(bridge, "_resolve_exec_target", return_value=plan),
                mock.patch.object(bridge.subprocess, "Popen", side_effect=_fake_popen),
            ):
                self._run_with_env(None, lambda: bridge._execute_bus_job("job-test-guard"))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                for falsy in (" False ", "0", "no", "off"):
                    self._run_with_env(falsy, lambda: bridge._execute_bus_job("job-test-guard"))
                    self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

    def test_site5_agy_native_models_all_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_envs: list[dict[str, str]] = []

            def _fake_run(cmd, **kwargs):
                captured_envs.append(dict(kwargs["env"]))
                return subprocess.CompletedProcess(cmd, 0, stdout="gemini-3.8-flash-low\tFlash\n", stderr="")

            with mock.patch.object(bridge.subprocess, "run", side_effect=_fake_run):
                self._run_with_env(None, lambda: bridge.agy_native_models(use_cache=False))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                for falsy in (" False ", "0", "no", "off"):
                    self._run_with_env(falsy, lambda: bridge.agy_native_models(use_cache=False))
                    self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

    def test_site6_fetch_plan_quota_data_all_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.QUOTA_CACHE_FILE = os.path.join(tmp, "quota_cache.json")
            captured_envs: list[dict[str, str]] = []
            fake_payload = json.dumps(
                {"command": {"data": {"groups": [{"label": "Pro", "remainingFraction": 0.9}]}}}
            )

            def _fake_run_group(cmd, cwd, timeout_s, env=None, shell=False):
                captured_envs.append(dict(env or {}))
                return 0, fake_payload, ""

            with mock.patch.object(bridge, "_run_subprocess_group", side_effect=_fake_run_group):
                self._run_with_env(None, lambda: bridge.fetch_plan_quota_data(force_live=True))
                self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                for falsy in (" False ", "0", "no", "off"):
                    Path(bridge.QUOTA_CACHE_FILE).unlink(missing_ok=True)
                    self._run_with_env(falsy, lambda: bridge.fetch_plan_quota_data(force_live=True))
                    self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])


class TestShimAutoUpdateGuard(unittest.TestCase):
    """C1 & C2: Verify `mem-hub/agy_llm_shim.py` warm observer subprocess guard."""

    def test_shim_helper_and_ensure_proc_env(self):
        shim = _load_isolated_shim()
        self.assertTrue(shim.DISABLE_AGY_AUTO_UPDATE)

        for raw in ({}, {"AGY_CLI_DISABLE_AUTO_UPDATE": ""}, {"AGY_CLI_DISABLE_AUTO_UPDATE": "  "}):
            d = dict(raw)
            shim._apply_agy_auto_update_env(d)
            self.assertEqual("1", d.get("AGY_CLI_DISABLE_AUTO_UPDATE"))

        for falsy in (" False ", "0", "no", "off"):
            d = {"AGY_CLI_DISABLE_AUTO_UPDATE": falsy}
            shim._apply_agy_auto_update_env(d)
            self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", d)

        with tempfile.TemporaryDirectory() as tmp:
            shim.SANDBOX_DIR = Path(tmp) / "observer-sandbox"
            captured_envs: list[dict[str, str]] = []

            async def _fake_create(*cmd, **kwargs):
                captured_envs.append(dict(kwargs["env"]))
                proc = mock.MagicMock()
                proc.returncode = None
                proc.stderr = None
                proc.stdin = None
                return proc

            async def _run_cases():
                with (
                    mock.patch.object(shim.asyncio, "create_subprocess_exec", side_effect=_fake_create),
                    mock.patch.object(shim.asyncio, "sleep", new=mock.AsyncMock()),
                ):
                    # Unset -> "1"
                    with mock.patch.dict(os.environ, {}, clear=False):
                        os.environ.pop("AGY_CLI_DISABLE_AUTO_UPDATE", None)
                        pool = shim.AgyObserverPool()
                        pool.cid = None
                        await pool.ensure_proc("gemini-3.8-flash-low")
                    self.assertEqual("1", captured_envs[-1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))

                    # Explicit falsy values -> popped completely
                    for falsy in (" False ", "0", "no", "off"):
                        with mock.patch.dict(os.environ, {"AGY_CLI_DISABLE_AUTO_UPDATE": falsy}, clear=False):
                            pool = shim.AgyObserverPool()
                            pool.cid = None
                            await pool.ensure_proc("gemini-3.8-flash-low")
                        self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", captured_envs[-1])

            asyncio.run(_run_cases())


class TestTemplatesAndSystemdUnits(unittest.TestCase):
    """C6: Verify `.env.example`, `bridge/cli.py`, and systemd units contain `AGY_CLI_DISABLE_AUTO_UPDATE=1`."""

    def test_env_example_and_cli_templates(self):
        env_example = (REPO_ROOT / "bridge" / ".env.example").read_text(encoding="utf-8")
        self.assertIn("AGY_CLI_DISABLE_AUTO_UPDATE=1", env_example)
        self.assertIn("AGY_CLI_DISABLE_AUTO_UPDATE=1", bridge_cli._FALLBACK_ENV_TEMPLATE)

        rendered_unit = bridge_cli._render_systemd_unit(
            unit_desc="test",
            dest_dir=Path("/tmp/demo-bridge"),
            env_path=Path("/tmp/demo-bridge/.env"),
            python_bin=Path("/tmp/demo-bridge/venv/bin/python"),
        )
        self.assertIn("Environment=AGY_CLI_DISABLE_AUTO_UPDATE=1", rendered_unit)

    def test_systemd_units_carry_disable_auto_update_env(self):
        private_units = [
            REPO_ROOT / "systemd" / "agy-tg-bridge.service",
            REPO_ROOT / "systemd" / "agy-tg-bridge-sg.service",
            REPO_ROOT / "systemd" / "agy-tg-bridge-jeff.service",
            REPO_ROOT / "systemd" / "agy-llm-shim.service",
            REPO_ROOT / "systemd" / "user" / "antigravity-cli-daemon.service",
        ]
        existing_private = [u for u in private_units if u.is_file()]
        if existing_private:
            self.assertEqual(5, len(existing_private), "All 5 private systemd units must exist")
            for unit in existing_private:
                txt = unit.read_text(encoding="utf-8")
                self.assertIn(
                    "Environment=AGY_CLI_DISABLE_AUTO_UPDATE=1",
                    txt,
                    f"{unit} must set Environment=AGY_CLI_DISABLE_AUTO_UPDATE=1",
                )
        else:
            # Public mirror repo: verify exact target example units when systemd/examples exists
            examples_dir = REPO_ROOT / "systemd" / "examples"
            if not examples_dir.is_dir():
                self.skipTest("Neither private systemd units nor public examples directory found")
            target_names = {
                "agy-tg-bridge.service.example",
                "agy-llm-shim.service.example",
                "antigravity-cli-daemon.user.service.example",
            }
            matched = {
                unit.name: unit
                for unit in examples_dir.glob("*.service.example")
                if unit.name in target_names
            }
            self.assertEqual(
                target_names,
                set(matched.keys()),
                f"Expected all 3 target public systemd examples in {examples_dir}, found: {sorted(matched.keys())}",
            )
            for name in sorted(target_names):
                unit = matched[name]
                txt = unit.read_text(encoding="utf-8")
                self.assertIn(
                    "Environment=AGY_CLI_DISABLE_AUTO_UPDATE=1",
                    txt,
                    f"{unit} must set Environment=AGY_CLI_DISABLE_AUTO_UPDATE=1",
                )


class TestAgyCliUpgradeScript(unittest.TestCase):
    """C3, C4, C5, C7: Exhaustive offline tests for `scripts/agy_cli_upgrade.py`."""

    def test_no_args_prints_help_and_never_calls_subprocess(self):
        buf = io.StringIO()
        with (
            mock.patch.object(agy_cli_upgrade.subprocess, "run") as mock_run,
            contextlib.redirect_stdout(buf),
        ):
            rc = agy_cli_upgrade.main([])
        self.assertEqual(0, rc)
        self.assertIn("--check", buf.getvalue())
        self.assertIn("--rollback", buf.getvalue())
        mock_run.assert_not_called()

    def test_check_mode_platform_mapping_https_only_and_timeout(self):
        # Platform key mapping
        self.assertEqual("linux_arm64", agy_cli_upgrade.resolve_platform_key("Linux", "aarch64"))
        self.assertEqual("linux_amd64", agy_cli_upgrade.resolve_platform_key("Linux", "x86_64"))
        self.assertEqual("darwin_arm64", agy_cli_upgrade.resolve_platform_key("Darwin", "arm64"))
        self.assertEqual("darwin_amd64", agy_cli_upgrade.resolve_platform_key("Darwin", "x86_64"))
        with self.assertRaises(ValueError):
            agy_cli_upgrade.resolve_platform_key("Windows", "x86_64")

        # Non-HTTPS, credentialed, whitespace, and control-char URLs rejected fail-closed
        for bad_url in (
            "http://example.com/manifests/linux_arm64.json",
            "file:///etc/passwd",
            "ftp://example.com/manifest.json",
            "https://user:pass@example.com/manifest.json",
            "https://example.com/manifests/linux arm64.json",
            "https://example.com/manifests/linux_arm64.json\r\nX-Injected: 1",
            "https://example.com/manifests/linux_arm64.json\n",
            "https://example.com/manifests/linux_arm64.json\r",
            " https://example.com/manifests/linux_arm64.json",
            "https://example.com/manifests/\x00linux_arm64.json",
            "https://example.com/manifests/\x7flinux_arm64.json",
            "",
        ):
            with self.assertRaises(ValueError, msg=f"URL should have been rejected: {bad_url!r}"):
                agy_cli_upgrade.validate_manifest_url(bad_url)

        with tempfile.TemporaryDirectory() as tmp:
            agy_bin = Path(tmp) / "agy"
            agy_bin.write_bytes(b"fake-bin-v1")
            agy_bin.chmod(0o755)

            seen_timeouts: list[float] = []
            seen_cmds: list[tuple[list[str], dict[str, str], bool]] = []

            def _fake_https_open(handler_self, req):
                seen_timeouts.append(req.timeout)
                headers = EmailMessage()
                headers["Content-Type"] = "application/json"
                body = json.dumps({"version": "1.5.15"}).encode("utf-8")
                resp = urllib.response.addinfourl(io.BytesIO(body), headers, req.full_url, code=200)
                resp.msg = "OK"
                return resp

            def _fake_run(cmd, **kwargs):
                seen_cmds.append((list(cmd), dict(kwargs["env"]), bool(kwargs.get("shell", False))))
                return subprocess.CompletedProcess(cmd, 0, stdout="1.5.14\n", stderr="")

            buf = io.StringIO()
            with (
                mock.patch.object(agy_cli_upgrade.urllib.request.HTTPSHandler, "https_open", _fake_https_open),
                mock.patch.object(agy_cli_upgrade.subprocess, "run", side_effect=_fake_run),
                contextlib.redirect_stdout(buf),
            ):
                rc = agy_cli_upgrade.main(
                    [
                        "--check",
                        "--agy-bin",
                        str(agy_bin),
                        "--manifest-url",
                        "https://example.com/manifests/linux_arm64.json",
                        "--timeout",
                        "7.5",
                        "--json",
                    ]
                )
            self.assertEqual(0, rc)
            payload = json.loads(buf.getvalue())
            self.assertEqual("1.5.14", payload["local_version"])
            self.assertEqual("1.5.15", payload["remote_version"])
            self.assertFalse(payload["up_to_date"])
            self.assertEqual([7.5], seen_timeouts)
            self.assertEqual(1, len(seen_cmds))
            self.assertEqual(["--version"], seen_cmds[0][0][1:])
            self.assertEqual("1", seen_cmds[0][1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))
            self.assertFalse(seen_cmds[0][2])

            # Reject http:// and CR/LF URLs via CLI without calling network or subprocess
            for bad_cli_url in (
                "http://example.com/manifests/linux_arm64.json",
                "https://example.com/manifests/linux_arm64.json\r\n",
                "https://example.com/manifests/linux arm64.json",
            ):
                err_buf = io.StringIO()
                with (
                    mock.patch.object(agy_cli_upgrade.urllib.request.HTTPSHandler, "https_open") as m_open,
                    mock.patch.object(agy_cli_upgrade.subprocess, "run") as m_run,
                    contextlib.redirect_stderr(err_buf),
                ):
                    rc_bad = agy_cli_upgrade.main(
                        [
                            "--check",
                            "--agy-bin",
                            str(agy_bin),
                            "--manifest-url",
                            bad_cli_url,
                        ]
                    )
                self.assertNotEqual(0, rc_bad)
                m_open.assert_not_called()
                m_run.assert_not_called()

    def test_check_rejects_http_redirects_and_invalid_timeouts(self):
        # 1. HTTP 302/301 redirect genuinely invokes _NoRedirectHandler.redirect_request and fails closed
        redirect_invocations: list[tuple[int, str]] = []
        orig_redirect_request = agy_cli_upgrade._NoRedirectHandler.redirect_request

        def _spy_redirect_request(handler_self, req, fp, code, msg, headers, newurl):
            redirect_invocations.append((code, newurl))
            return orig_redirect_request(handler_self, req, fp, code, msg, headers, newurl)

        for status_code in (302, 301, 307):
            def _fake_redirect_open(handler_self, req, _code=status_code):
                headers = EmailMessage()
                headers["Location"] = "https://redirected.example.com/evil.json"
                resp = urllib.response.addinfourl(io.BytesIO(b""), headers, req.full_url, code=_code)
                resp.msg = "Found"
                return resp

            with (
                mock.patch.object(
                    agy_cli_upgrade._NoRedirectHandler, "redirect_request", _spy_redirect_request
                ),
                mock.patch.object(
                    agy_cli_upgrade.urllib.request.HTTPSHandler, "https_open", _fake_redirect_open
                ),
            ):
                with self.assertRaisesRegex(ValueError, "redirects are forbidden"):
                    agy_cli_upgrade.fetch_remote_manifest(
                        "https://example.com/manifests/linux_arm64.json",
                        timeout=5.0,
                    )

        self.assertEqual(
            [
                (302, "https://redirected.example.com/evil.json"),
                (301, "https://redirected.example.com/evil.json"),
                (307, "https://redirected.example.com/evil.json"),
            ],
            redirect_invocations,
        )

        # 2. Non-finite / non-positive timeout rejected directly in fetch_remote_manifest
        with mock.patch.object(agy_cli_upgrade.urllib.request.HTTPSHandler, "https_open") as m_open:
            for bad_timeout in (float("nan"), float("inf"), float("-inf"), 0.0, -1.0, True):
                with self.assertRaises(ValueError, msg=f"Timeout should be rejected: {bad_timeout!r}"):
                    agy_cli_upgrade.fetch_remote_manifest(
                        "https://example.com/manifests/linux_arm64.json",
                        timeout=bad_timeout,
                    )
            m_open.assert_not_called()

        # 3. CLI --timeout parser rejects nan / inf / -inf / <= 0 without touching network or subprocess
        with tempfile.TemporaryDirectory() as tmp:
            agy_bin = Path(tmp) / "agy"
            agy_bin.write_bytes(b"fake-bin")
            agy_bin.chmod(0o755)
            for bad_arg in ("nan", "inf", "-inf", "0", "-2.5"):
                err_buf = io.StringIO()
                with (
                    mock.patch.object(agy_cli_upgrade.urllib.request.HTTPSHandler, "https_open") as m_open,
                    mock.patch.object(agy_cli_upgrade.subprocess, "run") as m_run,
                    contextlib.redirect_stderr(err_buf),
                ):
                    with self.assertRaises(SystemExit) as cm:
                        agy_cli_upgrade.main(
                            [
                                "--check",
                                "--agy-bin",
                                str(agy_bin),
                                "--manifest-url",
                                "https://example.com/manifests/linux_arm64.json",
                                "--timeout",
                                bad_arg,
                            ]
                        )
                self.assertNotEqual(0, cm.exception.code)
                m_open.assert_not_called()
                m_run.assert_not_called()

    def test_backup_only_permissions_sha256_and_source_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agy_bin = root / "bin" / "agy"
            agy_bin.parent.mkdir()
            payload_bytes = b"ELF-mock-agy-binary-v1.5.14"
            agy_bin.write_bytes(payload_bytes)
            agy_bin.chmod(0o755)
            backup_dir = root / "backups"

            buf = io.StringIO()
            with (
                mock.patch.object(agy_cli_upgrade, "get_local_version", return_value="1.5.14"),
                mock.patch.object(agy_cli_upgrade.subprocess, "run") as m_run,
                contextlib.redirect_stdout(buf),
            ):
                rc = agy_cli_upgrade.main(
                    ["--backup-only", "--agy-bin", str(agy_bin), "--backup-dir", str(backup_dir), "--json"]
                )
            self.assertEqual(0, rc)
            m_run.assert_not_called()
            res = json.loads(buf.getvalue())
            bpath = Path(res["backup"]["backup_path"])
            spath = Path(res["backup"]["sha256_path"])
            self.assertTrue(bpath.is_file())
            self.assertTrue(spath.is_file())
            self.assertRegex(bpath.name, r"^agy-1\.5\.14-\d{8}T\d{6}Z$")
            self.assertEqual(0o700, stat.S_IMODE(backup_dir.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(spath.stat().st_mode))
            expected_hash = hashlib.sha256(payload_bytes).hexdigest()
            self.assertEqual(expected_hash, res["backup"]["sha256"])
            self.assertIn(expected_hash, spath.read_text(encoding="utf-8"))

            # List backups works
            list_buf = io.StringIO()
            with contextlib.redirect_stdout(list_buf):
                rc_list = agy_cli_upgrade.main(["--list-backups", "--backup-dir", str(backup_dir), "--json"])
            self.assertEqual(0, rc_list)
            listed = json.loads(list_buf.getvalue())
            self.assertEqual(1, len(listed["backups"]))
            self.assertEqual("ok", listed["backups"][0]["sha256_status"])

            # Reject missing source, directory source, and symlink source
            with self.assertRaises(FileNotFoundError):
                agy_cli_upgrade.create_backup(root / "does-not-exist", backup_dir)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.create_backup(root / "bin", backup_dir)
            sym = root / "bin" / "agy-link"
            sym.symlink_to(agy_bin)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.create_backup(sym, backup_dir)

    def test_upgrade_fail_closed_on_backup_error_and_scoped_env_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agy_bin = root / "bin" / "agy"
            agy_bin.parent.mkdir()
            agy_bin.write_bytes(b"v1-binary")
            agy_bin.chmod(0o755)
            backup_dir = root / "backups"

            # 1. Backup failure -> fail-closed, NEVER call `agy update`
            with (
                mock.patch.object(agy_cli_upgrade, "get_local_version", return_value="1.5.14"),
                mock.patch.object(agy_cli_upgrade, "create_backup", side_effect=OSError("disk full")),
                mock.patch.object(agy_cli_upgrade.subprocess, "run") as m_run,
            ):
                rc, res = agy_cli_upgrade.run_upgrade(agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertNotEqual(0, rc)
            self.assertFalse(res["update_invoked"])
            m_run.assert_not_called()

            # 2. Full upgrade path: verify scoped env pop ONLY for `agy update`, parent os.environ untouched
            calls: list[tuple[list[str], dict[str, str], bool]] = []
            ver_counter = {"n": 0}

            def _fake_run(cmd, **kwargs):
                calls.append((list(cmd), dict(kwargs["env"]), bool(kwargs.get("shell", False))))
                if cmd[-1] == "--version":
                    ver_counter["n"] += 1
                    ver = "1.5.14" if ver_counter["n"] == 1 else "1.5.15"
                    return subprocess.CompletedProcess(cmd, 0, stdout=f"{ver}\n", stderr="")
                if cmd[-1] == "update":
                    agy_bin.write_bytes(b"v2-binary")
                    return subprocess.CompletedProcess(cmd, 0, stdout="updated\n", stderr="")
                if "--scope" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")
                raise AssertionError(f"Unexpected cmd: {cmd}")

            with (
                mock.patch.dict(os.environ, {"AGY_CLI_DISABLE_AUTO_UPDATE": "1"}, clear=False),
                mock.patch.object(agy_cli_upgrade.subprocess, "run", side_effect=_fake_run),
            ):
                rc_ok, res_ok = agy_cli_upgrade.run_upgrade(
                    agy_bin=agy_bin,
                    backup_dir=backup_dir,
                    verify_gate_script=root / "fake_verify_gate.py",
                )
                self.assertEqual("1", os.environ.get("AGY_CLI_DISABLE_AUTO_UPDATE"))

            self.assertEqual(0, rc_ok)
            self.assertEqual("1.5.14", res_ok["before_version"])
            self.assertEqual("1.5.15", res_ok["after_version"])
            self.assertEqual(4, len(calls))
            # Pre --version: guard=1, shell=False
            self.assertEqual("1", calls[0][1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))
            self.assertFalse(calls[0][2])
            # `agy update`: guard POPPED, shell=False
            self.assertEqual("update", calls[1][0][-1])
            self.assertNotIn("AGY_CLI_DISABLE_AUTO_UPDATE", calls[1][1])
            self.assertFalse(calls[1][2])
            # Post --version: guard=1
            self.assertEqual("1", calls[2][1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))
            # verify_gate --scope bridge: guard=1
            self.assertEqual("1", calls[3][1].get("AGY_CLI_DISABLE_AUTO_UPDATE"))
            self.assertFalse(calls[3][2])

            # 3. verify_gate failure returns non-zero with explicit rollback command
            def _fake_run_gate_fail(cmd, **kwargs):
                if cmd[-1] == "--version":
                    return subprocess.CompletedProcess(cmd, 0, stdout="1.5.15\n", stderr="")
                if cmd[-1] == "update":
                    return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bridge gate failed")

            with mock.patch.object(agy_cli_upgrade.subprocess, "run", side_effect=_fake_run_gate_fail):
                rc_fail, res_fail = agy_cli_upgrade.run_upgrade(
                    agy_bin=agy_bin,
                    backup_dir=backup_dir,
                    verify_gate_script=root / "fake_verify_gate.py",
                )
            self.assertNotEqual(0, rc_fail)
            self.assertEqual("verify_gate", res_fail["stage"])
            self.assertIn("--rollback", res_fail["rollback_command"])

    def test_rollback_rejects_traversal_symlinks_bad_sha256_and_replaces_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = root / "target_bin"
            backup_dir = root / "backup_store"
            outside_dir = root / "outside"
            target_dir.mkdir()
            outside_dir.mkdir()

            agy_bin = target_dir / "agy"
            v1_bytes = b"ORIGINAL-V1-BINARY-BYTES"
            v2_bytes = b"UPGRADED-V2-BINARY-BYTES"
            agy_bin.write_bytes(v1_bytes)
            agy_bin.chmod(0o755)

            with mock.patch.object(agy_cli_upgrade, "get_local_version", return_value="1.5.14"):
                binfo = agy_cli_upgrade.create_backup(agy_bin, backup_dir)
            bname = binfo["backup_name"]
            bpath = Path(binfo["backup_path"])
            spath = Path(binfo["sha256_path"])

            # Mutate target to v2
            agy_bin.write_bytes(v2_bytes)

            # 1. Path traversal rejected
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary("../../etc/passwd", agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())

            # 2. Outside absolute path rejected even if it has a valid .sha256
            out_file = outside_dir / "agy-fake"
            out_file.write_bytes(b"EVIL")
            out_sha = Path(f"{out_file}.sha256")
            out_sha.write_text(f"{hashlib.sha256(b'EVIL').hexdigest()}  agy-fake\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary(str(out_file), agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())

            # 3. Symlink inside backup_dir pointing outside (or inside) rejected (relative & absolute)
            sym_out = backup_dir / "agy-sym-out"
            sym_out.symlink_to(out_file)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary("agy-sym-out", agy_bin=agy_bin, backup_dir=backup_dir)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary(str(sym_out), agy_bin=agy_bin, backup_dir=backup_dir)
            sym_in = backup_dir / "agy-sym-in"
            sym_in.symlink_to(bpath)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary("agy-sym-in", agy_bin=agy_bin, backup_dir=backup_dir)
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary(str(sym_in), agy_bin=agy_bin, backup_dir=backup_dir)

            # 3b. Intermediate symlink subdirectory inside backup_dir rejected for BOTH absolute & relative paths
            real_sub = backup_dir / "real_sub"
            real_sub.mkdir(mode=0o700)
            nested_file = real_sub / "agy-nested"
            nested_file.write_bytes(v1_bytes)
            Path(f"{nested_file}.sha256").write_text(
                f"{hashlib.sha256(v1_bytes).hexdigest()}  agy-nested\n",
                encoding="utf-8",
            )
            sym_sub_in = backup_dir / "sym_sub_in"
            sym_sub_in.symlink_to(real_sub)
            with self.assertRaisesRegex(ValueError, "symlink"):
                agy_cli_upgrade.rollback_binary(
                    str(sym_sub_in / "agy-nested"),
                    agy_bin=agy_bin,
                    backup_dir=backup_dir,
                )
            with self.assertRaisesRegex(ValueError, "symlink"):
                agy_cli_upgrade.rollback_binary(
                    "sym_sub_in/agy-nested",
                    agy_bin=agy_bin,
                    backup_dir=backup_dir,
                )
            sym_sub_out = backup_dir / "sym_sub_out"
            sym_sub_out.symlink_to(outside_dir)
            with self.assertRaisesRegex(ValueError, "symlink"):
                agy_cli_upgrade.rollback_binary(
                    str(sym_sub_out / "agy-fake"),
                    agy_bin=agy_bin,
                    backup_dir=backup_dir,
                )
            self.assertEqual(v2_bytes, agy_bin.read_bytes())

            # 4. Missing .sha256 rejected
            saved_sha_text = spath.read_text(encoding="utf-8")
            spath.unlink()
            with self.assertRaises(FileNotFoundError):
                agy_cli_upgrade.rollback_binary(bname, agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())

            # 5. Tampered .sha256 rejected
            spath.write_text("0" * 64 + f"  {bname}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary(bname, agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())
            spath.write_text(saved_sha_text, encoding="utf-8")

            # 6. Symlink target agy_bin rejected
            sym_target = target_dir / "agy-sym-target"
            sym_target.symlink_to(outside_dir / "victim")
            with self.assertRaises(ValueError):
                agy_cli_upgrade.rollback_binary(bname, agy_bin=sym_target, backup_dir=backup_dir)
            self.assertFalse((outside_dir / "victim").exists())

            # 7. Simulated failure during os.replace cleans up temp file in target.parent & keeps v2 intact
            with mock.patch.object(agy_cli_upgrade.os, "replace", side_effect=OSError("simulated replace fail")):
                with self.assertRaises(OSError):
                    agy_cli_upgrade.rollback_binary(bname, agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())
            leftover_tmps = list(target_dir.glob(".agy-rollback-*.tmp"))
            self.assertEqual([], leftover_tmps, f"Temp file not cleaned up: {leftover_tmps}")

            # 7b. TOCTOU tampering during rollback copy phase fails SHA256 verification, leaves target intact & cleans tmp
            orig_resolve = agy_cli_upgrade._resolve_verified_backup

            def _tamper_after_verify(arg, bdir):
                verified_path, expected_digest = orig_resolve(arg, bdir)
                verified_path.write_bytes(b"TAMPERED-IN-FLIGHT-BYTES")
                return verified_path, expected_digest

            with mock.patch.object(agy_cli_upgrade, "_resolve_verified_backup", side_effect=_tamper_after_verify):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch during atomic copy"):
                    agy_cli_upgrade.rollback_binary(bname, agy_bin=agy_bin, backup_dir=backup_dir)
            self.assertEqual(v2_bytes, agy_bin.read_bytes())
            self.assertEqual([], list(target_dir.glob(".agy-rollback-*.tmp")))
            # Restore original backup bytes and also verify direct _atomic_copy_file mismatch
            bpath.write_bytes(v1_bytes)
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch during atomic copy"):
                agy_cli_upgrade._atomic_copy_file(
                    bpath,
                    agy_bin,
                    mode=0o755,
                    prefix=".agy-rollback-",
                    expected_sha256="f" * 64,
                )
            self.assertEqual(v2_bytes, agy_bin.read_bytes())
            self.assertEqual([], list(target_dir.glob(".agy-rollback-*.tmp")))

            # 8. Valid atomic rollback: verifies temp file created in target.parent, fsync called, mode 0o755
            fsync_called = {"count": 0}
            orig_fsync = os.fsync
            replace_parents: list[Path] = []
            orig_replace = os.replace

            def _track_fsync(fd):
                fsync_called["count"] += 1
                return orig_fsync(fd)

            def _track_replace(src, dst):
                replace_parents.append(Path(src).parent.resolve())
                return orig_replace(src, dst)

            with (
                mock.patch.object(agy_cli_upgrade.os, "fsync", side_effect=_track_fsync),
                mock.patch.object(agy_cli_upgrade.os, "replace", side_effect=_track_replace),
            ):
                res = agy_cli_upgrade.rollback_binary(bname, agy_bin=agy_bin, backup_dir=backup_dir)

            self.assertEqual("ok", res["status"])
            self.assertEqual(v1_bytes, agy_bin.read_bytes())
            self.assertEqual(0o755, stat.S_IMODE(agy_bin.stat().st_mode))
            self.assertGreaterEqual(fsync_called["count"], 1)
            self.assertEqual([target_dir.resolve()], replace_parents)
            self.assertEqual([], list(target_dir.glob(".agy-rollback-*.tmp")))

    def test_upgrade_script_executable_and_zero_hardcoded_home(self):
        script_path = SCRIPTS_DIR / "agy_cli_upgrade.py"
        self.assertTrue(os.access(script_path, os.X_OK), "scripts/agy_cli_upgrade.py must have +x permission")
        txt = script_path.read_text(encoding="utf-8")
        self.assertNotIn("/home/" + "ubuntu", txt)


if __name__ == "__main__":
    unittest.main()
