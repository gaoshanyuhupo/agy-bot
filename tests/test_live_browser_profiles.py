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
        self._callbacks: dict[str, list] = {}

    def on(self, event: str, cb) -> None:
        self._callbacks.setdefault(event, []).append(cb)

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

    async def route(self, pattern: str, handler) -> None:
        self._callbacks.setdefault("route", []).append((pattern, handler))

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

    def test_private_host_pinned_fail_closed_and_google_destination_policy(self) -> None:
        # 1. Explicit AGY_GOOGLE_SKILL_SCRIPTS="" keeps standalone mode working
        with mock.patch.dict(os.environ, {"AGY_GOOGLE_SKILL_SCRIPTS": "", "AGY_LIVE_BROWSER_REQUIRE_PINNED": ""}, clear=False):
            self.assertIsNone(srv.discover_pinned_host_profile())

        # 2. Private host with existing google-profile skill dir but missing google_browser.py -> RuntimeError (fail-closed)
        empty_skill_scripts = self.root / "google-profile" / "scripts"
        empty_skill_scripts.mkdir(parents=True, exist_ok=True)
        with mock.patch.dict(os.environ, {"AGY_GOOGLE_SKILL_SCRIPTS": str(empty_skill_scripts)}, clear=False):
            with self.assertRaises(RuntimeError):
                srv.discover_pinned_host_profile()
            with self.assertRaises(RuntimeError):
                srv.resolve_launch_spec(None)

        # 3. Private host with broken google_browser.py -> RuntimeError (fail-closed)
        (empty_skill_scripts / "google_browser.py").write_text("raise ImportError('broken pinned module')\n", encoding="utf-8")
        sys.modules.pop("google_browser", None)
        with mock.patch.dict(os.environ, {"AGY_GOOGLE_SKILL_SCRIPTS": str(empty_skill_scripts)}, clear=False):
            with self.assertRaises(RuntimeError):
                srv.discover_pinned_host_profile()

        # 4. AGY_LIVE_BROWSER_REQUIRE_PINNED=1 fails closed even if AGY_GOOGLE_SKILL_SCRIPTS=""
        with mock.patch.dict(
            os.environ,
            {"AGY_GOOGLE_SKILL_SCRIPTS": "", "AGY_LIVE_BROWSER_REQUIRE_PINNED": "1"},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                srv.discover_pinned_host_profile()

        # 5. Valid pinned host: non-pinned profile is blocked from Google/Gmail/YouTube destinations
        pinned_dir = self._install_mock_google_browser("pinned_acct")
        srv.create_profile("nonpin", {"os": "linux"})
        for bad_url in (
            "https://www.google.com/search?q=test",
            "https://mail.google.com/mail/u/0/#inbox",
            "https://accounts.google.com/signin",
            "https://" + ".".join(("accounts", "google", "co", "jp")) + "/signin",
            "https://" + ".".join(("gmail", "com")),
            "https://" + ".".join(("www", "youtube", "com")) + "/watch?v=1",
            "https://generativelanguage.googleapis.com/v1",
        ):
            with self.subTest(bad_url=bad_url):
                self.assertTrue(srv.is_google_destination_url(bad_url))
                with self.assertRaises(ValueError):
                    srv.enforce_google_profile_policy(bad_url, is_pinned=False)
                # Bare is_pinned=True without matching canonical profile_dir MUST ALSO fail closed!
                with self.assertRaises(ValueError):
                    srv.enforce_google_profile_policy(bad_url, is_pinned=True)
                # Verified canonical pinned profile_dir is permitted
                srv.enforce_google_profile_policy(bad_url, is_pinned=True, profile_dir=pinned_dir)

        # Non-Google URL is allowed on non-pinned profile
        self.assertFalse(srv.is_google_destination_url("https://example.com"))
        srv.enforce_google_profile_policy("https://example.com", is_pinned=False)

        # Verify hub start_hosted & AI goto enforce Google destination policy before launch/nav
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                with self.assertRaises(ValueError):
                    await hub.start_hosted(initial_url="https://www.google.com", profile="nonpin", notify_tg=False)
                self.assertEqual("idle", hub.engine_mode)

                await hub.start_hosted(initial_url="https://example.com", profile="nonpin", notify_tg=False)
                self.assertFalse(hub.active_pinned)
                with self.assertRaises(ValueError):
                    await hub.execute_ai_action({"action": "goto", "url": "https://mail.google.com", "notify": False})

                # Human new_tab on non-pinned opens about:blank (NOT Google homepage)
                hub.takeover = True
                await hub._execute_human_cmd_async({"action": "new_tab"})
                self.assertEqual("about:blank", hub._current_page().url)
                await hub.stop_hosted(notify_finished=False)

        asyncio.run(_scenario())

    def test_p0_03_forged_pinned_rejected_and_non_pinned_full_navigation_guard(self) -> None:
        """P0-03: reject forged pinned=True, verify private unit env, and enforce ctx.route + framenavigated Google guard."""
        # 1. Private repo systemd unit must explicitly enforce AGY_LIVE_BROWSER_REQUIRE_PINNED=1 (if present)
        unit_path = REPO_ROOT / "systemd/agy-live-browser.service"
        if unit_path.is_file():
            self.assertIn("AGY_LIVE_BROWSER_REQUIRE_PINNED=1", unit_path.read_text(encoding="utf-8"))

        pinned_dir = self._install_mock_google_browser("pinned_acct")

        # 2. create_profile rejects forged pinned=True
        with self.assertRaises(ValueError):
            srv.create_profile("forged", {"os": "windows", "pinned": True})

        # 3. Manually tampered profiles.json with pinned=True is stripped to unpinned & blocked from Google
        srv.save_profiles({"forged": {"os": "windows", "persistent": True, "pinned": True}})
        spec = srv.resolve_launch_spec("forged")
        self.assertFalse(spec["pinned"])
        self.assertFalse(spec["pinned_verified"])
        with self.assertRaises(ValueError):
            srv.enforce_google_profile_policy(
                "https://mail.google.com",
                is_pinned=True,
                profile_dir=self.profiles_data / "forged",
            )
        # Authentic canonical pinned_dir is allowed
        srv.enforce_google_profile_policy(
            "https://mail.google.com",
            is_pinned=True,
            profile_dir=pinned_dir,
        )

        # 4. Non-pinned context installs ctx.route interceptor blocking redirects/links/popups/history + framenavigated fallback
        routes_registered: list[tuple[str, object]] = []
        nav_callbacks: list[object] = []

        class _RouteAwarePage:
            def __init__(self, url: str = "https://example.com") -> None:
                self.url = url
                self.viewport_size = {"width": 1280, "height": 800}
                self.goto_history: list[str] = []

            def on(self, event: str, cb) -> None:
                if event == "framenavigated":
                    nav_callbacks.append(cb)

            async def title(self) -> str:
                return "Page"

            async def screenshot(self, **_kw) -> bytes:
                return b"JPEG"

            async def goto(self, url: str, **_kw) -> None:
                self.url = url
                self.goto_history.append(url)

        class _RouteAwareCtx:
            def __init__(self) -> None:
                self.pages = [_RouteAwarePage()]
                self._callbacks: dict[str, list] = {}
                holder = types.SimpleNamespace(_display=11)
                self.close = lambda: holder._display

            async def route(self, pattern: str, handler) -> None:
                routes_registered.append((pattern, handler))

            def on(self, event: str, cb) -> None:
                self._callbacks.setdefault(event, []).append(cb)

            async def new_page(self):
                p = _RouteAwarePage("about:blank")
                self.pages.append(p)
                return p

        class _RouteCamoufoxCM:
            def __init__(self, **_kw) -> None:
                self.ctx = _RouteAwareCtx()

            async def __aenter__(self):
                return self.ctx

            async def __aexit__(self, *_args) -> None:
                return None

        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _RouteCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                await hub.start_hosted(initial_url="https://example.com", profile="forged", notify_tg=False)
                self.assertFalse(hub._is_active_pinned_verified())
                self.assertEqual(1, len(routes_registered))
                pattern, handler = routes_registered[0]
                self.assertEqual("**/*", pattern)

                # Simulated 3xx redirect / popup / history nav to Google MUST be aborted with blockedbyclient
                aborted: list[str] = []
                continued: list[str] = []

                class _FakeRoute:
                    def __init__(self, url: str, is_nav: bool = True, res_type: str = "document") -> None:
                        self.request = types.SimpleNamespace(
                            url=url,
                            is_navigation_request=lambda: is_nav,
                            resource_type=res_type,
                        )

                    async def abort(self, reason: str = "") -> None:
                        aborted.append(reason)

                    async def continue_(self) -> None:
                        continued.append(self.request.url)

                r_goog = _FakeRoute("https://accounts.google.com/ServiceLogin", is_nav=True)
                await handler(r_goog, r_goog.request)
                self.assertEqual(["blockedbyclient"], aborted)

                r_ok = _FakeRoute("https://example.org/docs", is_nav=True)
                await handler(r_ok, r_ok.request)
                self.assertEqual(["https://example.org/docs"], continued)

                # Fallback framenavigated to Google forces redirect to about:blank
                self.assertTrue(nav_callbacks)
                yt_url = "https://" + ".".join(("www", "youtube", "com")) + "/watch?v=123"
                nav_callbacks[0](types.SimpleNamespace(url=yt_url))
                await asyncio.sleep(0.03)
                self.assertEqual("about:blank", hub._current_page().url)
                await hub.stop_hosted(notify_finished=False)

        asyncio.run(_scenario())

    def test_round4_p0_03_non_pinned_guard_fail_closed_and_sync_pinned_identity(self) -> None:
        """Round 4 P0-03: non-pinned context fails closed if ctx.route missing/raises; sync never infers pinned."""
        pinned_dir = self._install_mock_google_browser("pinned_acct")
        srv.create_profile("unpinned-ephem", {"os": "linux", "persistent": False})

        # 1. Policy refuses bare is_pinned=True without matching canonical profile_dir
        with self.assertRaises(ValueError):
            srv.enforce_google_profile_policy("https://mail.google.com", is_pinned=True, profile_dir=None)
        with self.assertRaises(ValueError):
            srv.enforce_google_profile_policy(
                "https://mail.google.com", is_pinned=True, profile_dir=self.root / "other-dir"
            )
        srv.enforce_google_profile_policy("https://mail.google.com", is_pinned=True, profile_dir=pinned_dir)

        # 2. Non-pinned startup MUST fail closed (closing CM & leaving hub idle) when ctx lacks route() OR route() raises!
        exited_flags: list[bool] = []

        class _NoRouteCtx:
            pages = [_FakePage("https://example.com")]
            def on(self, _ev, _cb): pass

        class _BoomRouteCtx:
            pages = [_FakePage("https://example.com")]
            def on(self, _ev, _cb): pass
            async def route(self, _pat, _cb):
                raise RuntimeError("route hook unsupported")

        def _make_cm_cls(ctx_cls):
            class _CM:
                def __init__(self, **_kw):
                    self.ctx = ctx_cls()
                async def __aenter__(self):
                    return self.ctx
                async def __aexit__(self, *_a):
                    exited_flags.append(True)
            return _CM

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            for ctx_cls in (_NoRouteCtx, _BoomRouteCtx):
                exited_flags.clear()
                fake_mod = types.ModuleType("camoufox.async_api")
                fake_mod.AsyncCamoufox = _make_cm_cls(ctx_cls)  # type: ignore[attr-defined]
                fake_pkg = types.ModuleType("camoufox")
                fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]
                with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                    with self.assertRaises(RuntimeError):
                        await hub.start_hosted(initial_url="https://example.com", profile="unpinned-ephem", notify_tg=False)
                self.assertEqual([True], exited_flags, "Failed guard install must close context immediately")
                self.assertEqual("idle", hub.engine_mode)
                self.assertIsNone(hub.ctx)
                self.assertIsNone(hub.lock_fd)

            # 3. internal_sync_start NEVER infers pinned=True from host files without explicit verified launch identity!
            fake_web = types.SimpleNamespace(
                json_response=lambda data, status=200: types.SimpleNamespace(data=data, status=status),
                HTTPForbidden=RuntimeError,
            )
            with mock.patch.object(srv, "web", fake_web):
                # Without profile_dir / pinned_launch -> active_pinned=False, active_pinned_verified=False
                r_unverified = await srv.internal_sync_start(
                    types.SimpleNamespace(
                        headers={"X-Live-Token": "sec-tok"},
                        remote="127.0.0.1",
                        app={"hub": hub},
                        json=mock.AsyncMock(return_value={"ai_status": "external sync"}),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_unverified.status)
                self.assertFalse(hub.active_pinned)
                self.assertFalse(hub.active_pinned_verified)
                self.assertFalse(r_unverified.data["pinned"])

                # With forged profile_dir -> still False!
                r_forged = await srv.internal_sync_start(
                    types.SimpleNamespace(
                        headers={"X-Live-Token": "sec-tok"},
                        remote="127.0.0.1",
                        app={"hub": hub},
                        json=mock.AsyncMock(
                            return_value={"profile_dir": str(self.root / "fake"), "pinned_launch": True}
                        ),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_forged.status)
                self.assertFalse(hub.active_pinned)
                self.assertFalse(hub.active_pinned_verified)

                # With authentic host canonical pinned_dir + pinned_launch=True -> True!
                r_verified = await srv.internal_sync_start(
                    types.SimpleNamespace(
                        headers={"X-Live-Token": "sec-tok"},
                        remote="127.0.0.1",
                        app={"hub": hub},
                        json=mock.AsyncMock(
                            return_value={"profile_dir": str(pinned_dir), "pinned_launch": True}
                        ),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_verified.status)
                self.assertTrue(hub.active_pinned)
                self.assertTrue(hub.active_pinned_verified)

        asyncio.run(_scenario())

    def test_round5_p0_03_framenavigated_listener_failure_fails_closed(self) -> None:
        """Round 5 P0-03: non-pinned context fails closed & closes CM if page.on('framenavigated') missing or raises."""
        pinned_dir = self.root / "pinned_r5"
        pinned_dir.mkdir(parents=True, exist_ok=True)
        pinned_lock = self.root / "pinned_r5.lock"
        fake_pinned = {
            "name": "pinned_r5",
            "profile_dir": pinned_dir,
            "lock_path": pinned_lock,
            "fingerprint": {"os": "windows"},
        }
        srv.create_profile("nonpin-r5", {"os": "linux", "persistent": False})

        class _NoOnPage:
            url = "about:blank"
            viewport_size = {"width": 1280, "height": 800}

        class _RaisingOnPage:
            url = "about:blank"
            viewport_size = {"width": 1280, "height": 800}

            def on(self, ev: str, _cb) -> None:
                if ev == "framenavigated":
                    raise RuntimeError("framenavigated unsupported")

        async def _scenario() -> None:
            for page_cls in (_NoOnPage, _RaisingOnPage):
                cm_instances: list[object] = []

                class _BadPageCM:
                    def __init__(self, **_kw) -> None:
                        self.exited = False
                        self.ctx = _FakeContext()
                        self.ctx.pages = [page_cls()]
                        cm_instances.append(self)

                    async def __aenter__(self):
                        return self.ctx

                    async def __aexit__(self, *_a):
                        self.exited = True

                fake_mod = types.SimpleNamespace(AsyncCamoufox=_BadPageCM)
                hub = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
                with (
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                    mock.patch.dict(sys.modules, {"camoufox": types.SimpleNamespace(), "camoufox.async_api": fake_mod}),
                ):
                    with self.assertRaises(RuntimeError):
                        await hub.start_hosted(profile="nonpin-r5", notify_tg=False)
                self.assertEqual("idle", hub.engine_mode)
                self.assertIsNone(hub.ctx)
                self.assertTrue(cm_instances and cm_instances[0].exited, "Failed non-pinned CM must be closed fail-closed")

        asyncio.run(_scenario())


if __name__ == "__main__":
    unittest.main()
