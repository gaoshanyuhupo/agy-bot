#!/usr/bin/env python3
"""Offline unit tests for live-browser multi-fingerprint, multi-egress & pinned-profile protection."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_SCRIPTS = REPO_ROOT / ".agents/skills/live-browser/scripts"
if str(LIVE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(LIVE_SCRIPTS))

import live_browser_ctl  # noqa: E402
import live_browser_server as srv  # noqa: E402


class _FakePage:
    def __init__(self, url: str = "https://example.com") -> None:
        self.url = url
        self.viewport_size = {"width": 1280, "height": 800}

    async def title(self) -> str:
        return "Example Page"

    async def screenshot(self, **_kwargs) -> bytes:
        return b"FAKEJPEG"

    async def goto(self, url: str, **_kwargs) -> None:
        self.url = url


class _FakeContext:
    def __init__(self, display_num: int = 7) -> None:
        self.pages = [_FakePage()]
        self._callbacks: dict[str, list] = {}
        holder = types.SimpleNamespace(_display=display_num)

        def _close() -> int:
            return holder._display

        self.close = _close

    def on(self, event: str, cb) -> None:
        self._callbacks.setdefault(event, []).append(cb)

    async def new_page(self) -> _FakePage:
        p = _FakePage()
        self.pages.append(p)
        return p


class _FakeAsyncCamoufoxCM:
    recorded_calls: list[dict] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        type(self).recorded_calls.append(kwargs)
        self.ctx = _FakeContext()
        self.exited = False

    async def __aenter__(self) -> _FakeContext:
        return self.ctx

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        self.exited = True


class TestLiveBrowserProfiles(unittest.TestCase):
    """Offline regression tests for profile isolation, pinned lock, masking & lifecycle."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.cfg_dir = self.root / "config"
        self.profiles_file = self.cfg_dir / "profiles.json"
        self.profiles_data = self.root / "profiles-data"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_data.mkdir(parents=True, exist_ok=True)

        self._orig_env = os.environ.get("AGY_GOOGLE_SKILL_SCRIPTS")
        self._orig_cfg_dir = srv.CONFIG_DIR
        self._orig_cfg_file = srv.CONFIG_FILE
        self._orig_prof_file = srv.PROFILES_FILE
        self._orig_tok_file = srv.LOCAL_TOKEN_FILE
        self._orig_data_dir = srv.PROFILES_DATA_DIR

        srv.CONFIG_DIR = self.cfg_dir
        srv.CONFIG_FILE = self.cfg_dir / "config.json"
        srv.PROFILES_FILE = self.profiles_file
        srv.LOCAL_TOKEN_FILE = self.cfg_dir / "local.token"
        srv.PROFILES_DATA_DIR = self.profiles_data
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = str(self.root / "no-google-skill")
        _FakeAsyncCamoufoxCM.recorded_calls.clear()

    def tearDown(self) -> None:
        srv.CONFIG_DIR = self._orig_cfg_dir
        srv.CONFIG_FILE = self._orig_cfg_file
        srv.PROFILES_FILE = self._orig_prof_file
        srv.LOCAL_TOKEN_FILE = self._orig_tok_file
        srv.PROFILES_DATA_DIR = self._orig_data_dir
        if self._orig_env is None:
            os.environ.pop("AGY_GOOGLE_SKILL_SCRIPTS", None)
        else:
            os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = self._orig_env
        self._tmp.cleanup()

    def _install_mock_google_browser(self, profile_name: str = "pinned_acct") -> Path:
        skill_dir = self.root / "google-profile-scripts"
        skill_dir.mkdir(parents=True, exist_ok=True)
        pinned_dir = self.profiles_data / profile_name
        pinned_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.profiles_data / f"{profile_name}.lock"
        (skill_dir / "google_browser.py").write_text(
            "\n".join(
                [
                    "import os",
                    "from pathlib import Path",
                    f"PROFILE_DIR = Path({str(pinned_dir)!r})",
                    f"LOCK_PATH = Path({str(lock_path)!r})",
                    'PINNED_FINGERPRINT = {"headless": "virtual", "os": "windows", "humanize": True, "i_know_what_im_doing": True}',
                    "def _direct_env():",
                    "    env = dict(os.environ)",
                    '    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):',
                    "        env.pop(k, None)",
                    '    env["NO_PROXY"] = "*"',
                    '    env["no_proxy"] = "*"',
                    "    return env",
                ]
            ),
            encoding="utf-8",
        )
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = str(skill_dir)
        return pinned_dir

    def test_standalone_without_google_browser_works(self) -> None:
        self.assertIsNone(srv.discover_pinned_host_profile())
        items = srv.list_profiles()
        self.assertEqual(1, len(items))
        self.assertEqual("default", items[0]["name"])
        self.assertFalse(items[0]["pinned"])

        spec = srv.resolve_launch_spec(None)
        self.assertEqual("default", spec["name"])
        self.assertFalse(spec["pinned"])
        kwargs, egress = srv.build_camoufox_kwargs(spec, spec["profile_dir"])
        self.assertEqual("direct", egress)
        self.assertEqual("windows", kwargs["os"])
        self.assertEqual({"network.proxy.type": 0}, kwargs["firefox_user_prefs"])
        self.assertEqual("*", kwargs["env"]["NO_PROXY"])

    def test_profile_name_validation_rejects_traversal_and_bad_chars(self) -> None:
        for bad in ("", "../escape", "a/b", "a\\b", "a..b", ".hidden", "has space", "x" * 65):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    srv.validate_profile_name(bad)
        for good in ("us-work", "cf_01.prod", "A1"):
            self.assertEqual(good, srv.validate_profile_name(good))

    def test_host_pinned_profile_invariants_and_fail_closed_overrides(self) -> None:
        pinned_dir = self._install_mock_google_browser("pinned_acct")
        for req in (None, "", "default", "pinned_acct"):
            spec = srv.resolve_launch_spec(req)
            self.assertTrue(spec["pinned"])
            self.assertEqual("pinned_acct", spec["name"])
            self.assertEqual(pinned_dir, spec["profile_dir"])

        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:8080"}, clear=False):
            spec = srv.resolve_launch_spec("default")
            kwargs, egress = srv.build_camoufox_kwargs(spec, spec["profile_dir"])
            self.assertEqual("direct", egress)
            self.assertEqual("windows", kwargs["os"])
            self.assertEqual("virtual", kwargs["headless"])
            self.assertTrue(kwargs["persistent_context"])
            self.assertEqual({"network.proxy.type": 0}, kwargs["firefox_user_prefs"])
            self.assertNotIn("proxy", kwargs)
            self.assertNotIn("HTTP_PROXY", kwargs["env"])
            self.assertEqual("*", kwargs["env"]["NO_PROXY"])

        forbidden_cases = [
            {"proxy": "socks5://proxy.example.com:1080"},
            {"proxy_bao_ref": "kv/proxies/us-west"},
            {"os": "macos"},
            {"mobile": True},
            {"window": "430x932"},
            {"headless": False},
            {"user_data_dir": str(self.root / "other")},
            {"ephemeral": True},
            {"persistent": False},
            {"locale": "ja-JP"},
            {"env": {"HTTPS_PROXY": "http://proxy.example.com:8080"}},
            {"firefox_user_prefs": {"network.proxy.type": 1}},
        ]
        for ov in forbidden_cases:
            with self.subTest(override=ov):
                with self.assertRaises(ValueError):
                    srv.resolve_launch_spec("default", overrides=ov)

        with self.assertRaises(ValueError):
            srv.create_profile("default", {"os": "linux"})
        with self.assertRaises(ValueError):
            srv.create_profile("pinned_acct", {"os": "linux"})
        with self.assertRaises(ValueError):
            srv.delete_profile("pinned_acct")

    def test_multi_fingerprint_proxy_kwargs_and_credential_masking(self) -> None:
        created = srv.create_profile(
            "us-work",
            {
                "os": "macos",
                "locale": "ja-JP",
                "window": "1440x900",
                "webgl_config": "Apple,Apple M2",
                "block_webrtc": True,
                "geoip": "203.0.113.10",
                "proxy": "socks5://MOCK_USER:MOCK_PASS@proxy.example.com:1080",
            },
        )
        self.assertEqual("socks5://***@" + "proxy.example.com:1080", created["egress"])
        self.assertNotIn("MOCK_USER", json.dumps(created))
        self.assertNotIn("MOCK_PASS", json.dumps(created))
        self.assertEqual(0o600, stat.S_IMODE(self.profiles_file.stat().st_mode))

        listed = srv.list_profiles()
        self.assertNotIn("MOCK_USER", json.dumps(listed))
        self.assertNotIn("MOCK_PASS", json.dumps(listed))

        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:7890"}, clear=False):
            spec = srv.resolve_launch_spec("us-work")
            kwargs, egress = srv.build_camoufox_kwargs(spec, spec["profile_dir"])
            self.assertEqual("socks5://***@" + "proxy.example.com:1080", egress)
            self.assertEqual("macos", kwargs["os"])
            self.assertEqual("ja-JP", kwargs["locale"])
            self.assertEqual((1440, 900), kwargs["window"])
            self.assertEqual(("Apple", "Apple M2"), kwargs["webgl_config"])
            self.assertTrue(kwargs["block_webrtc"])
            self.assertEqual("203.0.113.10", kwargs["geoip"])
            self.assertEqual(
                {
                    "server": "socks5://proxy.example.com:1080",
                    "username": "MOCK_USER",
                    "password": "MOCK_PASS",
                },
                kwargs["proxy"],
            )
            self.assertNotIn("firefox_user_prefs", kwargs)
            self.assertNotIn("HTTPS_PROXY", kwargs["env"])

    def test_proxy_bao_ref_resolves_in_memory_without_persisting_secret(self) -> None:
        srv.create_profile(
            "bao-exit",
            {"os": "linux", "proxy_bao_ref": "kv/proxies/us-west#url"},
        )
        raw_saved = self.profiles_file.read_text(encoding="utf-8")
        self.assertIn("kv/proxies/us-west#url", raw_saved)
        self.assertNotIn("MOCK_BAO_PASS", raw_saved)

        fake_proc = subprocess.CompletedProcess(
            args=["bao", "get", "kv/proxies/us-west", "--field", "url"],
            returncode=0,
            stdout="socks5://MOCK_BAO_USER:MOCK_BAO_PASS@proxy.example.com:1080\n",
            stderr="",
        )
        with mock.patch.object(srv.subprocess, "run", return_value=fake_proc) as run_mock:
            spec = srv.resolve_launch_spec("bao-exit")
            kwargs, egress = srv.build_camoufox_kwargs(spec, spec["profile_dir"])
            run_mock.assert_called_once()
            self.assertEqual("socks5://***@" + "proxy.example.com:1080", egress)
            self.assertEqual("MOCK_BAO_USER", kwargs["proxy"]["username"])
            self.assertEqual("MOCK_BAO_PASS", kwargs["proxy"]["password"])

        listed_json = json.dumps(srv.list_profiles())
        self.assertNotIn("MOCK_BAO_USER", listed_json)
        self.assertNotIn("MOCK_BAO_PASS", listed_json)

    def test_hub_lifecycle_switch_restart_and_ephemeral_cleanup(self) -> None:
        srv.create_profile(
            "prof-a",
            {"os": "macos", "proxy": "http://MOCK_USER:MOCK_PASS@proxy.example.com:8080"},
        )
        srv.create_profile(
            "prof-ephem",
            {"os": "linux", "persistent": False},
        )

        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                st = await hub.start_hosted(notify_tg=False, profile="prof-a")
                self.assertTrue(st["running"])
                self.assertEqual("prof-a", st["profile"])
                self.assertEqual("macos", st["os"])
                self.assertEqual("http://***@" + "proxy.example.com:8080", st["egress"])
                self.assertNotIn("MOCK_PASS", json.dumps(st))
                self.assertEqual(":7", hub.x11_display)

                # Cannot delete active running profile
                with self.assertRaises(RuntimeError):
                    srv.delete_profile("prof-a", active_profile=hub.active_profile)

                # Switching without --restart fails cleanly
                with self.assertRaises(RuntimeError) as ctx_err:
                    await hub.start_hosted(notify_tg=False, profile="prof-ephem", restart=False)
                self.assertIn("stop", str(ctx_err.exception))

                # Restarting while takeover=True is blocked
                hub.takeover = True
                with self.assertRaises(RuntimeError):
                    await hub.start_hosted(notify_tg=False, profile="prof-ephem", restart=True)
                hub.takeover = False

                # Safe restart switch to ephemeral profile
                st2 = await hub.start_hosted(notify_tg=False, profile="prof-ephem", restart=True)
                self.assertEqual("prof-ephem", st2["profile"])
                self.assertEqual("linux", st2["os"])
                self.assertEqual("direct", st2["egress"])
                ephem_dir = hub.active_profile_dir
                self.assertIsNotNone(ephem_dir)
                assert ephem_dir is not None
                self.assertTrue(ephem_dir.is_dir())

                await hub.stop_hosted(notify_finished=False)
                self.assertFalse(ephem_dir.exists())
                self.assertEqual("idle", hub.engine_mode)

        asyncio.run(_scenario())

    def test_cli_parser_and_offline_profile_commands(self) -> None:
        parser = live_browser_ctl.build_parser()
        ns_create = parser.parse_args(
            [
                "profile",
                "create",
                "cf-test",
                "--os",
                "macos",
                "--locale",
                "en-US",
                "--window",
                "1366x768",
                "--webgl",
                "Intel Inc.,Iris",
                "--block-webrtc",
                "--geoip",
                "--proxy-bao",
                "kv/proxies/us-west",
                "--ephemeral",
            ]
        )
        self.assertEqual("profile", ns_create.cmd)
        self.assertEqual("create", ns_create.profile_cmd)
        self.assertEqual("cf-test", ns_create.name)
        self.assertTrue(ns_create.ephemeral)

        ns_start = parser.parse_args(
            ["start", "--profile", "cf-test", "--restart", "--mobile", "--proxy", "socks5://proxy.example.com:1080"]
        )
        self.assertEqual("start", ns_start.cmd)
        self.assertEqual("cf-test", ns_start.profile)
        self.assertTrue(ns_start.restart)
        self.assertTrue(ns_start.mobile)

        # Verify non-pinned mobile preset resolves to portrait viewport while pinned rejects it
        srv.create_profile("mob-demo", {"os": "linux", "mobile": True})
        mob_spec = srv.resolve_launch_spec("mob-demo")
        self.assertTrue(mob_spec["mobile"])
        self.assertEqual(srv.MOBILE_WINDOW_PRESET, mob_spec["window"])
        mob_kwargs, _ = srv.build_camoufox_kwargs(mob_spec, mob_spec["profile_dir"])
        self.assertEqual(tuple(srv.MOBILE_WINDOW_PRESET), mob_kwargs["window"])

        client = live_browser_ctl.LiveBrowserClient(bot="sg")
        with mock.patch.object(client, "is_alive", return_value=False):
            res_create = client.create_profile("cli-demo", os="linux", proxy="socks5://proxy.example.com:1080")
            self.assertTrue(res_create["ok"])
            res_list = client.list_profiles()
            self.assertTrue(any(p["name"] == "cli-demo" for p in res_list["profiles"]))
            res_del = client.delete_profile("cli-demo")
            self.assertTrue(res_del["ok"])


if __name__ == "__main__":
    unittest.main()
