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

        self._saved_environ = dict(os.environ)
        for _k in list(os.environ.keys()):
            if _k.startswith("AGY_"):
                os.environ.pop(_k, None)
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
        os.environ.clear()
        os.environ.update(self._saved_environ)
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

    def test_round6_hosted_subsequent_new_page_guard_failure_fails_closed(self) -> None:
        """Round 6 §2: Non-pinned hosted ctx.on('page') MUST close unguarded new page (or abort session if close fails)."""
        pinned_dir = self.root / "pinned_r6"
        pinned_dir.mkdir(parents=True, exist_ok=True)
        pinned_lock = self.root / "pinned_r6.lock"
        fake_pinned = {
            "name": "pinned_r6",
            "profile_dir": pinned_dir,
            "lock_path": pinned_lock,
            "fingerprint": {"os": "windows"},
        }
        srv.create_profile("nonpin-r6", {"os": "linux", "persistent": False})

        class _GoodPage:
            def __init__(self, url: str = "about:blank") -> None:
                self.url = url
                self.viewport_size = {"width": 1280, "height": 800}
                self.closed = False
                self.listeners: dict[str, list] = {}

            def is_closed(self) -> bool:
                return self.closed

            async def close(self) -> None:
                self.closed = True

            async def goto(self, url: str, **_kw) -> None:
                self.url = url

            async def title(self) -> str:
                return "Good"

            async def screenshot(self, **_kw) -> bytes:
                return b"JPEG"

            def on(self, ev: str, cb) -> None:
                self.listeners.setdefault(ev, []).append(cb)

        class _BadPopupPage(_GoodPage):
            def __init__(self, *, fail_close: bool = False) -> None:
                super().__init__("https://popup.example")
                self._fail_close = fail_close

            def on(self, ev: str, cb) -> None:
                if ev == "framenavigated":
                    raise RuntimeError("popup framenavigated registration failed")
                super().on(ev, cb)

            async def close(self) -> None:
                if self._fail_close:
                    raise RuntimeError("popup close failed")
                self.closed = True

        class _PartialSecondaryPage(_GoodPage):
            def on(self, ev: str, cb) -> None:
                if ev == "load":
                    raise RuntimeError("load unsupported")
                super().on(ev, cb)

        class _EventCtx(_FakeContext):
            def __init__(self, initial_page) -> None:
                super().__init__()
                self.pages = [initial_page]
                self.ctx_listeners: dict[str, list] = {}

            def on(self, ev: str, cb) -> None:
                self.ctx_listeners.setdefault(ev, []).append(cb)

        async def _scenario() -> None:
            # Case A: popup fails framenavigated -> closed fail-closed & NOT kept active/guarded
            cm_a_list: list[object] = []

            class _CM_A:
                def __init__(self, **_kw) -> None:
                    self.exited = False
                    self.init_page = _GoodPage()
                    self.ctx = _EventCtx(self.init_page)
                    cm_a_list.append(self)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            hub = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
            with (
                mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                mock.patch.dict(
                    sys.modules,
                    {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM_A)},
                ),
            ):
                await hub.start_hosted(profile="nonpin-r6", notify_tg=False)
                self.assertEqual("async_hosted", hub.engine_mode)
                cm_a = cm_a_list[0]
                popup = _BadPopupPage(fail_close=False)
                cm_a.ctx.pages.append(popup)  # type: ignore[attr-defined]
                for cb in cm_a.ctx.ctx_listeners.get("page", []):  # type: ignore[attr-defined]
                    cb(popup)
                # Let scheduled fail-closed close task run
                await asyncio.sleep(0.05)
                self.assertTrue(popup.closed, "Unguarded subsequent popup MUST be closed fail-closed")
                self.assertNotIn(id(popup), hub._attached_pages)
                self.assertIs(hub._current_page(), cm_a.init_page)  # type: ignore[attr-defined]

                # Secondary listener isolation: `load` raising MUST NOT skip `close` listener
                partial_p = _PartialSecondaryPage()
                hub._attach_page_listeners(partial_p, require_nav_guard=True)
                self.assertIn("framenavigated", partial_p.listeners)
                self.assertIn("close", partial_p.listeners)

                # Case B: popup fails framenavigated AND close() fails -> hosted session MUST abort to idle!
                unclosable = _BadPopupPage(fail_close=True)
                cm_a.ctx.pages.append(unclosable)  # type: ignore[attr-defined]
                for cb in cm_a.ctx.ctx_listeners.get("page", []):  # type: ignore[attr-defined]
                    cb(unclosable)
                await asyncio.sleep(0.05)
                self.assertEqual("idle", hub.engine_mode, "Session MUST abort fail-closed when unguarded page cannot close")
                self.assertIsNone(hub.ctx)
                self.assertTrue(cm_a.exited)  # type: ignore[attr-defined]

        asyncio.run(_scenario())

    def test_round7_hosted_new_tab_lock_reentry_visible_pages_dedup_and_startup_guard(self) -> None:
        """Round 7 §1: No `_exec_lock <-> _engine_lock` deadlock with held buttons, unified `_visible_pages()`, single deduped close task, and pre-publish startup guard abort."""
        pinned_dir = self.root / "pinned_r7"
        pinned_dir.mkdir(parents=True, exist_ok=True)
        pinned_lock = self.root / "pinned_r7.lock"
        fake_pinned = {
            "name": "pinned_r7",
            "profile_dir": pinned_dir,
            "lock_path": pinned_lock,
            "fingerprint": {"os": "windows"},
        }
        srv.create_profile("nonpin-r7", {"os": "linux", "persistent": False})

        class _MouseSpy:
            def __init__(self) -> None:
                self.ups: list[str] = []

            async def up(self, button: str = "left") -> None:
                self.ups.append(button)

        class _GoodPage:
            def __init__(self, url: str = "about:blank", title_str: str = "Good") -> None:
                self.url = url
                self._title = title_str
                self.viewport_size = {"width": 1280, "height": 800}
                self.closed = False
                self.listeners: dict[str, list] = {}
                self.mouse = _MouseSpy()
                self.front_calls = 0

            def is_closed(self) -> bool:
                return self.closed

            async def close(self) -> None:
                self.closed = True
                for cb in list(self.listeners.get("close", [])):
                    cb()

            async def bring_to_front(self) -> None:
                self.front_calls += 1

            async def goto(self, url: str, **_kw) -> None:
                self.url = url

            async def title(self) -> str:
                return self._title

            async def screenshot(self, **_kw) -> bytes:
                return b"JPEG"

            def on(self, ev: str, cb) -> None:
                self.listeners.setdefault(ev, []).append(cb)

        class _BadPage(_GoodPage):
            def __init__(self, *, fail_close: bool = False, close_gate: asyncio.Event | None = None) -> None:
                super().__init__("https://bad-popup.example", "Bad")
                self._fail_close = fail_close
                self._close_gate = close_gate
                self.close_calls = 0

            def on(self, ev: str, cb) -> None:
                if ev == "framenavigated":
                    raise RuntimeError("framenavigated failed")
                super().on(ev, cb)

            async def close(self) -> None:
                self.close_calls += 1
                if self._close_gate is not None:
                    await self._close_gate.wait()
                if self._fail_close:
                    raise RuntimeError("close failed")
                self.closed = True

        class _RealEventCtx(_FakeContext):
            def __init__(self, pages: list[object], next_new_page_factory=None) -> None:
                super().__init__()
                self.pages = list(pages)
                self.ctx_listeners: dict[str, list] = {}
                self._next_new_page_factory = next_new_page_factory

            def on(self, ev: str, cb) -> None:
                self.ctx_listeners.setdefault(ev, []).append(cb)

            async def new_page(self):
                p = self._next_new_page_factory()
                self.pages.append(p)
                for cb in list(self.ctx_listeners.get("page", [])):
                    cb(p)
                return p

        async def _scenario() -> None:
            # (a) Held mouse button + explicit `new_tab` guard failure + `close()` raises -> NO DEADLOCK,
            #     releases held button, exits CM, transitions cleanly to `idle`!
            # Also checks (c): real `ctx.on('page')` callback + explicit `new_tab` branch merge into ONE close task!
            cm_a_list: list[object] = []
            bad_unclosable = _BadPage(fail_close=True)

            class _CM_A:
                def __init__(self, **_kw) -> None:
                    self.exited = False
                    self.init_page = _GoodPage("https://p0.example", "P0")
                    self.ctx = _RealEventCtx([self.init_page], next_new_page_factory=lambda: bad_unclosable)
                    cm_a_list.append(self)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            hub = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
            with (
                mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                mock.patch.dict(
                    sys.modules,
                    {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM_A)},
                ),
            ):
                await hub.start_hosted(profile="nonpin-r7", notify_tg=False)
                self.assertEqual("async_hosted", hub.engine_mode)
                cm_a = cm_a_list[0]
                hub.takeover = True
                hub._mouse_buttons_down.add("left")
                # Must finish promptly without `_exec_lock <-> _engine_lock` deadlock!
                await asyncio.wait_for(
                    hub._execute_human_cmd_async(
                        {
                            "action": "new_tab",
                            "_session_gen": hub.session_gen,
                            "_takeover_gen": hub.takeover_gen,
                        }
                    ),
                    timeout=3.0,
                )
                self.assertEqual("idle", hub.engine_mode, "Session MUST abort cleanly to idle without deadlocking")
                self.assertIsNone(hub.ctx)
                self.assertTrue(cm_a.exited)  # type: ignore[attr-defined]
                self.assertEqual(["left"], cm_a.init_page.mouse.ups, "Held mouse button MUST be released during stop")  # type: ignore[attr-defined]
                self.assertEqual(
                    1,
                    bad_unclosable.close_calls,
                    "Callback and explicit new_tab branch MUST deduplicate into a single close task!",
                )

            # (b) Unified `_visible_pages()` during pending-close: switch_tab & close_tab never touch quarantined page
            #     and index consistently against the visible page set!
            close_gate = asyncio.Event()
            bad_pending = _BadPage(fail_close=False, close_gate=close_gate)
            p0 = _GoodPage("https://p0.example", "P0")
            p2 = _GoodPage("https://p2.example", "P2")
            cm_b_list: list[object] = []

            class _CM_B:
                def __init__(self, **_kw) -> None:
                    self.exited = False
                    self.ctx = _RealEventCtx([p0])
                    cm_b_list.append(self)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            hub_b = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
            with (
                mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                mock.patch.dict(
                    sys.modules,
                    {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM_B)},
                ),
            ):
                await hub_b.start_hosted(profile="nonpin-r7", notify_tg=False)
                cm_b = cm_b_list[0]
                # Insert quarantined page at raw index 1 (between p0 and p2) and trigger ctx.on('page')
                cm_b.ctx.pages.append(bad_pending)  # type: ignore[attr-defined]
                for cb in list(cm_b.ctx.ctx_listeners.get("page", [])):  # type: ignore[attr-defined]
                    cb(bad_pending)
                await asyncio.sleep(0)  # Let scheduled fail-closed close task enter close_gate.wait()
                cm_b.ctx.pages.append(p2)  # type: ignore[attr-defined]
                hub_b._attach_page_listeners(p2, require_nav_guard=True)
                hub_b.active_tab_index = 0
                hub_b.takeover = True

                # Visible pages MUST exclude bad_pending -> [p0, p2]
                self.assertEqual([p0, p2], hub_b._visible_pages())
                self.assertIs(p0, hub_b._current_page())

                # switch_tab(index=1) MUST switch to p2 (NOT bad_pending!)
                await hub_b._execute_human_cmd_async(
                    {
                        "action": "switch_tab",
                        "index": 1,
                        "_session_gen": hub_b.session_gen,
                        "_takeover_gen": hub_b.takeover_gen,
                    }
                )
                self.assertEqual(1, p2.front_calls, "switch_tab(1) must target visible page p2")
                self.assertEqual(0, bad_pending.front_calls, "switch_tab MUST NEVER call bring_to_front on quarantined page")
                self.assertIs(p2, hub_b._current_page())

                # close_tab(index=1) MUST close p2 (NOT bad_pending!)
                await hub_b._execute_human_cmd_async(
                    {
                        "action": "close_tab",
                        "index": 1,
                        "_session_gen": hub_b.session_gen,
                        "_takeover_gen": hub_b.takeover_gen,
                    }
                )
                self.assertTrue(p2.closed, "close_tab(1) must close visible page p2")
                self.assertEqual(1, bad_pending.close_calls, "close_tab must NOT invoke a second close on quarantined page")
                self.assertIs(p0, hub_b._current_page())

                close_gate.set()
                await hub_b.stop_hosted(notify_finished=False)

            # (d) Startup-phase popup guard failure before publish -> aborts directly inside start_hosted's _engine_lock!
            cm_d_list: list[object] = []
            startup_popup = _BadPage(fail_close=True)

            class _CM_D:
                def __init__(self, **_kw) -> None:
                    self.exited = False
                    self.ctx = _RealEventCtx([_GoodPage("https://start.example", "Start")])
                    cm_d_list.append(self)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            async def _x11_fires_popup(_display):
                cm_d = cm_d_list[-1]
                cm_d.ctx.pages.append(startup_popup)  # type: ignore[attr-defined]
                for cb in list(cm_d.ctx.ctx_listeners.get("page", [])):  # type: ignore[attr-defined]
                    cb(startup_popup)
                await asyncio.sleep(0)
                return ""

            hub_d = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
            with (
                mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=":99"),
                mock.patch.object(srv, "read_x11_clipboard_async", side_effect=_x11_fires_popup),
                mock.patch.dict(
                    sys.modules,
                    {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM_D)},
                ),
            ):
                with self.assertRaises(RuntimeError):
                    await asyncio.wait_for(hub_d.start_hosted(profile="nonpin-r7", notify_tg=False), timeout=3.0)
                self.assertEqual("idle", hub_d.engine_mode, "Startup guard failure MUST block publish fail-closed")
                self.assertIsNone(hub_d.ctx)
                self.assertTrue(cm_d_list[-1].exited)  # type: ignore[attr-defined]

        asyncio.run(_scenario())

    def test_round8_input_loop_survives_stop_hosted_cancelling_cleanup_task(self) -> None:
        """Round 8 Blocker 1: Cancelling a blocked new_tab cleanup task during concurrent stop_hosted() MUST NOT kill service-level _input_loop."""
        pinned_dir = self.root / "pinned_r8"
        pinned_dir.mkdir(parents=True, exist_ok=True)
        pinned_lock = self.root / "pinned_r8.lock"
        fake_pinned = {
            "name": "pinned_r8",
            "profile_dir": pinned_dir,
            "lock_path": pinned_lock,
            "fingerprint": {"os": "windows"},
        }
        srv.create_profile("nonpin-r8", {"os": "linux", "persistent": False})

        class _MouseSpy:
            def __init__(self, on_click: asyncio.Event | None = None) -> None:
                self.clicks: list[tuple[float, float]] = []
                self._on_click = on_click

            async def click(self, x: float, y: float, **_kw) -> None:
                self.clicks.append((x, y))
                if self._on_click is not None:
                    self._on_click.set()

            async def up(self, button: str = "left") -> None:
                pass

        class _GoodPage:
            def __init__(self, url: str = "https://ok.example", on_click: asyncio.Event | None = None) -> None:
                self.url = url
                self.viewport_size = {"width": 1280, "height": 800}
                self.closed = False
                self.listeners: dict[str, list] = {}
                self.mouse = _MouseSpy(on_click=on_click)

            def is_closed(self) -> bool:
                return self.closed

            async def close(self) -> None:
                self.closed = True

            async def goto(self, url: str, **_kw) -> None:
                self.url = url

            async def title(self) -> str:
                return "Good"

            async def screenshot(self, **_kw) -> bytes:
                return b"JPEG"

            async def evaluate(self, _script: str, _arg=None):
                return None

            def on(self, ev: str, cb) -> None:
                self.listeners.setdefault(ev, []).append(cb)

        class _BlockingBadPage(_GoodPage):
            def __init__(self, entered: asyncio.Event, gate: asyncio.Event) -> None:
                super().__init__("https://blocked-close.example")
                self._entered = entered
                self._gate = gate
                self.close_cancelled = False

            def on(self, ev: str, cb) -> None:
                if ev == "framenavigated":
                    raise RuntimeError("framenavigated registration failed")
                super().on(ev, cb)

            async def close(self) -> None:
                self._entered.set()
                try:
                    await self._gate.wait()
                except asyncio.CancelledError:
                    self.close_cancelled = True
                    raise
                self.closed = True

        class _RealEventCtx(_FakeContext):
            def __init__(self, pages: list[object], next_new_page_factory=None) -> None:
                super().__init__()
                self.pages = list(pages)
                self.ctx_listeners: dict[str, list] = {}
                self._next_new_page_factory = next_new_page_factory

            def on(self, ev: str, cb) -> None:
                self.ctx_listeners.setdefault(ev, []).append(cb)

            async def new_page(self):
                p = self._next_new_page_factory()
                self.pages.append(p)
                for cb in list(self.ctx_listeners.get("page", [])):
                    cb(p)
                return p

        async def _scenario() -> None:
            close_entered = asyncio.Event()
            close_gate = asyncio.Event()
            bad_page = _BlockingBadPage(close_entered, close_gate)
            click_done = asyncio.Event()
            page_s2 = _GoodPage("https://session2.example", on_click=click_done)
            cms: list[object] = []

            class _CM:
                def __init__(self, **_kw) -> None:
                    self.exited = False
                    if not cms:
                        self.ctx = _RealEventCtx(
                            [_GoodPage("https://session1.example")],
                            next_new_page_factory=lambda: bad_page,
                        )
                    else:
                        self.ctx = _RealEventCtx([page_s2])
                    cms.append(self)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            hub = srv.LiveBrowserHub({"public_url": ""}, "sec-tok")
            input_task = asyncio.create_task(hub._input_loop())
            try:
                with (
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=fake_pinned),
                    mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                    mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                    mock.patch.dict(
                        sys.modules,
                        {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM)},
                    ),
                ):
                    # 1. Start hosted session #1 and enqueue explicit new_tab whose cleanup blocks on close_gate
                    await hub.start_hosted(profile="nonpin-r8", notify_tg=False)
                    self.assertEqual("async_hosted", hub.engine_mode)
                    hub.takeover = True
                    await hub.input_queue.put(
                        {
                            "action": "new_tab",
                            "_session_gen": hub.session_gen,
                            "_takeover_gen": hub.takeover_gen,
                        }
                    )
                    await asyncio.wait_for(close_entered.wait(), timeout=2.0)
                    await asyncio.sleep(0)

                    # 2. Concurrent stop_hosted() cancels the blocked cleanup task via _cancel_and_await_bg_tasks()
                    await asyncio.wait_for(hub.stop_hosted(notify_finished=False), timeout=3.0)
                    await asyncio.sleep(0)
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.ctx)
                    self.assertTrue(cms[0].exited)  # type: ignore[attr-defined]
                    self.assertTrue(bad_page.close_cancelled, "Blocked cleanup task should be cancelled by stop_hosted")
                    self.assertFalse(
                        input_task.done(),
                        "Service-level _input_loop MUST stay alive after concurrent stop_hosted cancels child cleanup task!",
                    )

                    # 3. Start hosted session #2 and verify _input_loop still consumes & executes new human input!
                    await hub.start_hosted(profile="nonpin-r8", notify_tg=False)
                    self.assertEqual("async_hosted", hub.engine_mode)
                    hub.takeover = True
                    await hub.input_queue.put(
                        {
                            "action": "click",
                            "x": 120,
                            "y": 240,
                            "_session_gen": hub.session_gen,
                            "_takeover_gen": hub.takeover_gen,
                        }
                    )
                    await asyncio.wait_for(click_done.wait(), timeout=2.0)
                    self.assertEqual([(120.0, 240.0)], page_s2.mouse.clicks)
                    self.assertFalse(input_task.done())

                    await hub.stop_hosted(notify_finished=False)

                    # 4. Also verify Sync mode forwarding still works through the same live _input_loop!
                    hub.engine_mode = "sync_external"
                    hub.takeover = True
                    sync_gen = hub.session_gen
                    sync_tgen = hub.takeover_gen
                    await hub.input_queue.put(
                        {
                            "action": "click",
                            "x": 55,
                            "y": 66,
                            "_session_gen": sync_gen,
                            "_takeover_gen": sync_tgen,
                        }
                    )
                    deadline = asyncio.get_running_loop().time() + 2.0
                    while not hub.sync_cmd_queue and asyncio.get_running_loop().time() < deadline:
                        await asyncio.sleep(0.01)
                    self.assertEqual(1, len(hub.sync_cmd_queue))
                    self.assertEqual("click", hub.sync_cmd_queue[0].get("action"))
                    self.assertFalse(input_task.done())
            finally:
                # 5. Direct cancellation of _input_loop itself (shutdown path) MUST still exit cleanly!
                input_task.cancel()
                try:
                    await asyncio.wait_for(input_task, timeout=1.0)
                except asyncio.CancelledError:
                    pass
                self.assertTrue(input_task.done())

        asyncio.run(_scenario())

    # ---------------- C1..C8 Dedicated Multi-Profile Google Isolation Tests ----------------

    @staticmethod
    def _make_fake_web() -> types.SimpleNamespace:
        return types.SimpleNamespace(
            json_response=lambda data, status=200: types.SimpleNamespace(data=data, status=status),
            HTTPForbidden=RuntimeError,
        )

    @staticmethod
    def _make_internal_req(
        hub: srv.LiveBrowserHub,
        *,
        token: str = "sec-tok",
        body: dict | None = None,
        query: dict | None = None,
        match_info: dict | None = None,
    ) -> types.SimpleNamespace:
        async def _json():
            return body if body is not None else {}

        return types.SimpleNamespace(
            headers={"X-Live-Token": token},
            remote="127.0.0.1",
            app={"hub": hub},
            query=query or {},
            match_info=match_info or {},
            json=_json,
        )

    def test_c1_pinned_invariants_zero_regression_and_unit_env(self) -> None:
        """C1: Host-pinned primary profile invariants, forbidden overrides incl. allow_override=True, and systemd unit env."""
        pinned_dir = self._install_mock_google_browser("pinned_acct")

        # 1. Omitting / "" / "default" / pinned name all derive from host canonical google_browser.py
        for req in (None, "", "default", "pinned_acct"):
            spec = srv.resolve_launch_spec(req)
            self.assertTrue(spec["pinned"])
            self.assertTrue(spec["pinned_verified"])
            self.assertEqual("pinned_acct", spec["name"])
            self.assertEqual(pinned_dir, spec["profile_dir"])
            kwargs, egress = srv.build_camoufox_kwargs(spec, spec["profile_dir"])
            self.assertEqual("windows", kwargs["os"])
            self.assertEqual("virtual", kwargs["headless"])
            self.assertEqual("direct", egress)
            self.assertEqual({"network.proxy.type": 0}, kwargs["firefox_user_prefs"])
            self.assertEqual("*", kwargs["env"]["NO_PROXY"])

        # 2. All PINNED_FORBIDDEN_OVERRIDES + proxy env + non-0 prefs + allow_google/account/allow_override=True fail closed
        forbidden_cases: list[tuple[dict | None, bool]] = [
            ({"proxy": "socks5://proxy.example.com:1080"}, False),
            ({"proxy_bao_ref": "kv/proxies/us-west"}, False),
            ({"os": "macos"}, False),
            ({"locale": "ja-JP"}, False),
            ({"window": "1440x900"}, False),
            ({"mobile": True}, False),
            ({"webgl_config": "Apple,Apple M2"}, False),
            ({"block_webrtc": True}, False),
            ({"geoip": True}, False),
            ({"headless": False}, False),
            ({"user_data_dir": str(self.root / "escape")}, False),
            ({"persistent_context": False}, False),
            ({"persistent": False}, False),
            ({"ephemeral": True}, False),
            ({"pinned": False}, False),
            ({"allow_google": False}, False),
            ({"account": "acct-a@example.com"}, False),
            ({"env": {"HTTPS_PROXY": "http://proxy.example.com:8080"}}, False),
            ({"firefox_user_prefs": {"network.proxy.type": 1}}, False),
            ({"firefox_user_prefs": {"network.proxy.http": "proxy.example.com"}}, False),
            (None, True),
            ({"os": "macos"}, True),
        ]
        for ov, ao in forbidden_cases:
            with self.subTest(ov=ov, allow_override=ao):
                with self.assertRaises(ValueError):
                    srv.resolve_launch_spec("default", overrides=ov, allow_override=ao)

        # HTTP POST /internal/start maps pinned overrides & allow_override=True to HTTP 400
        async def _http_check() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            with mock.patch.object(srv, "web", self._make_fake_web()):
                for body in (
                    {"profile": "default", "allow_override": True, "notify": False},
                    {"profile": "default", "allow_google": False, "notify": False},
                    {"profile": "default", "account": "acct@example.com", "notify": False},
                    {"profile": "default", "env": {"HTTP_PROXY": "http://proxy.example.com:8080"}, "notify": False},
                    {"profile": "default", "firefox_user_prefs": {"network.proxy.type": 1}, "notify": False},
                ):
                    r = await srv.internal_start(self._make_internal_req(hub, body=body))  # type: ignore[arg-type]
                    self.assertEqual(400, r.status, f"Expected 400 for body={body!r}, got {r.status}: {r.data}")

        asyncio.run(_http_check())

        # 3. create_profile / delete_profile forbid default & pinned_acct
        for name in ("default", "pinned_acct"):
            with self.assertRaises(ValueError):
                srv.create_profile(name, {"os": "linux"})
            with self.assertRaises(ValueError):
                srv.delete_profile(name)

        # 4. AGY_LIVE_BROWSER_REQUIRE_PINNED=1 with AGY_GOOGLE_SKILL_SCRIPTS="" raises RuntimeError
        with mock.patch.dict(
            os.environ,
            {"AGY_LIVE_BROWSER_REQUIRE_PINNED": "1", "AGY_GOOGLE_SKILL_SCRIPTS": ""},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                srv.discover_pinned_host_profile()

        # 5. systemd unit retains REQUIRE_PINNED=1 and adds ALLOW_DEDICATED_GOOGLE_PROFILES=1
        unit_path = REPO_ROOT / "systemd/agy-live-browser.service"
        if unit_path.is_file():
            unit_txt = unit_path.read_text(encoding="utf-8")
            self.assertIn("Environment=AGY_LIVE_BROWSER_REQUIRE_PINNED=1", unit_txt)
            self.assertIn("Environment=AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES=1", unit_txt)

    def test_c2_host_switch_default_off_and_strict_bool_validation(self) -> None:
        """C2: Host switch defaults off (100% single-pinned fail-closed) and strict bool validation on allow_google/pinned/allow_override."""
        self._install_mock_google_browser("pinned_acct")
        srv.create_profile(
            "google-us-1",
            {
                "os": "macos",
                "locale": "en-US",
                "allow_google": True,
                "persistent": True,
                "account": "acct-us@example.com",
            },
        )
        g_dir = self.profiles_data / "google-us-1"
        g_dir.mkdir(parents=True, exist_ok=True)

        # 1. Host switch unset / 0 / false / invalid keeps dedicated profile 100% blocked from Google
        for raw_switch in (None, "", "0", "false", "no", "invalid", "2"):
            env_patch = {} if raw_switch is None else {"AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES": raw_switch}
            with mock.patch.dict(os.environ, env_patch, clear=False):
                if raw_switch is None:
                    os.environ.pop("AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES", None)
                self.assertFalse(srv.is_dedicated_google_profiles_enabled())
                spec = srv.resolve_launch_spec("google-us-1")
                self.assertTrue(spec["allow_google"])
                self.assertFalse(spec["allow_google_verified"])
                for g_url in (
                    "https://www.google.com",
                    "https://mail.google.com/mail/u/0/#inbox",
                    "https://" + ".".join(("www", "youtube", "com")) + "/watch?v=1",
                ):
                    with self.assertRaises(ValueError):
                        srv.enforce_google_profile_policy(
                            g_url,
                            is_pinned=False,
                            allow_google=True,
                            profile_name="google-us-1",
                            profile_dir=g_dir,
                        )

        # Hosted launch with switch OFF installs ctx.route + framenavigated and opens new_tab to about:blank
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _switch_off_hosted() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                with self.assertRaises(ValueError):
                    await hub.start_hosted(initial_url="https://mail.google.com", profile="google-us-1", notify_tg=False)
                self.assertEqual("idle", hub.engine_mode)

                await hub.start_hosted(initial_url="https://example.com", profile="google-us-1", notify_tg=False)
                self.assertFalse(hub._is_active_google_allowed())
                self.assertTrue(hub.ctx._callbacks.get("route"), "ctx.route guard must be installed when host switch is off")
                self.assertTrue(
                    hub._current_page()._callbacks.get("framenavigated"),
                    "framenavigated guard must be installed when host switch is off",
                )
                hub.takeover = True
                await hub._execute_human_cmd_async({"action": "new_tab"})
                self.assertEqual("about:blank", hub._current_page().url)
                await hub.stop_hosted(notify_finished=False)

        asyncio.run(_switch_off_hosted())

        # 2. Strict bool checks on allow_google, pinned, allow_override (direct & HTTP 400)
        for bad_bool in ("true", "false", 1, 0, "1"):
            with self.subTest(bad_allow_google=bad_bool):
                with self.assertRaises(ValueError):
                    srv.create_profile("bad-ag", {"os": "linux", "allow_google": bad_bool})
            with self.subTest(bad_allow_override=bad_bool):
                with self.assertRaises(ValueError):
                    srv.resolve_launch_spec("google-us-1", allow_override=bad_bool)
        with self.assertRaises(ValueError):
            srv.create_profile("bad-pin", {"os": "windows", "pinned": True})

        async def _http_strict_bool() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            with mock.patch.object(srv, "web", self._make_fake_web()):
                for bad_bool in ("true", "false", 1, 0):
                    r_p = await srv.internal_profiles_create(
                        self._make_internal_req(hub, body={"name": "bad-http-ag", "os": "linux", "allow_google": bad_bool})
                    )  # type: ignore[arg-type]
                    self.assertEqual(400, r_p.status)
                    r_s = await srv.internal_start(
                        self._make_internal_req(
                            hub, body={"profile": "google-us-1", "allow_override": bad_bool, "notify": False}
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(400, r_s.status)
                r_pin = await srv.internal_profiles_create(
                    self._make_internal_req(hub, body={"name": "bad-http-pin", "os": "windows", "pinned": True})
                )  # type: ignore[arg-type]
                self.assertEqual(400, r_pin.status)

        asyncio.run(_http_strict_bool())

    def test_c3_no_bare_bool_tampered_profiles_symlink_and_sync_guard(self) -> None:
        """C3: Reject bare allow_google=True, tampered profiles.json, symlink traversal before mkdir/chmod, and forged sync claims."""
        pinned_dir = self._install_mock_google_browser("pinned_acct")
        with mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES": "1"}, clear=False):
            # 1. Bare allow_google=True with None / unregistered / non-existent / out-of-bounds dir -> ValueError
            srv.create_profile("google-reg", {"os": "macos", "allow_google": True, "persistent": True})
            unregistered_dir = self.profiles_data / "unregistered"
            unregistered_dir.mkdir(parents=True, exist_ok=True)
            outside_dir = self.root / "outside-google-reg"
            outside_dir.mkdir(parents=True, exist_ok=True)
            missing_reg_dir = self.profiles_data / "google-reg"  # does not exist on disk yet!
            for bad_dir in (None, unregistered_dir, outside_dir, missing_reg_dir):
                with self.subTest(bad_dir=bad_dir):
                    with self.assertRaises(ValueError):
                        srv.enforce_google_profile_policy(
                            "https://mail.google.com",
                            is_pinned=False,
                            allow_google=True,
                            profile_dir=bad_dir,
                        )

            # 2. Tampered profiles.json entries (pinned=True, allow_google="true", allow_google=True+persistent=False)
            tampered_raw = {
                "tamper-pin": {"os": "windows", "persistent": True, "pinned": True, "allow_google": True},
                "tamper-str": {"os": "windows", "persistent": True, "allow_google": "true"},
                "tamper-ephem": {"os": "windows", "persistent": False, "allow_google": True},
            }
            srv.save_profiles(tampered_raw)
            for tname in tampered_raw:
                tdir = self.profiles_data / tname
                tdir.mkdir(parents=True, exist_ok=True)
                spec = srv.resolve_launch_spec(tname)
                self.assertFalse(spec["pinned"])
                self.assertFalse(spec["allow_google"])
                self.assertFalse(spec["allow_google_verified"])
                with self.assertRaises(ValueError):
                    srv.enforce_google_profile_policy(
                        "https://accounts.google.com/signin",
                        is_pinned=False,
                        allow_google=True,
                        profile_name=tname,
                        profile_dir=tdir,
                    )
            listed = {p["name"]: p for p in srv.list_profiles()}
            for tname in tampered_raw:
                self.assertFalse(listed[tname]["pinned"])
                self.assertFalse(listed[tname]["allow_google"])

            # 3. Symlink at PROFILES_DATA_DIR/<name> (to outside OR to pinned_dir) rejected BEFORE mkdir/chmod & policy
            srv.create_profile("sym-out", {"os": "linux", "allow_google": True, "persistent": True})
            srv.create_profile("sym-pin", {"os": "linux", "allow_google": True, "persistent": True})
            sym_target = self.root / "symlink-target"
            sym_target.mkdir(parents=True, exist_ok=True)
            os.chmod(sym_target, 0o755)
            (self.profiles_data / "sym-out").symlink_to(sym_target)
            (self.profiles_data / "sym-pin").symlink_to(pinned_dir)

            for sname in ("sym-out", "sym-pin"):
                with self.assertRaises(ValueError):
                    srv.enforce_google_profile_policy(
                        "https://mail.google.com",
                        is_pinned=False,
                        allow_google=True,
                        profile_name=sname,
                        profile_dir=self.profiles_data / sname,
                    )
                with self.assertRaises(ValueError):
                    srv.resolve_launch_spec(sname)

            async def _sym_start_and_sync() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with self.assertRaises(ValueError):
                    await hub.start_hosted(initial_url="https://example.com", profile="sym-out", notify_tg=False)
                self.assertEqual("idle", hub.engine_mode)
                # Verify chmod(0o700) was NOT executed on symlink target!
                self.assertEqual(0o755, stat.S_IMODE(sym_target.stat().st_mode))

                # 4. internal_sync_start rejects forged allow_google=True claims, accepts authentic verified dir
                srv.create_profile("sync-goog", {"os": "macos", "allow_google": True, "persistent": True})
                sync_goog_dir = self.profiles_data / "sync-goog"
                with mock.patch.object(srv, "web", self._make_fake_web()):
                    for bad_body in (
                        {"allow_google": True},
                        {"allow_google": True, "profile_dir": str(unregistered_dir)},
                        {"allow_google": True, "profile_dir": str(self.profiles_data / "sym-out")},
                        {"allow_google": True, "profile_dir": str(sync_goog_dir)},  # dir does not exist yet
                    ):
                        r_bad = await srv.internal_sync_start(
                            self._make_internal_req(hub, body=bad_body)
                        )  # type: ignore[arg-type]
                        self.assertEqual(200, r_bad.status)
                        self.assertFalse(r_bad.data["allow_google_verified"])
                        self.assertFalse(r_bad.data["google_allowed"])
                        self.assertFalse(hub._is_active_google_allowed())

                    # Now create authentic dir -> verified!
                    sync_goog_dir.mkdir(parents=True, exist_ok=True)
                    r_ok = await srv.internal_sync_start(
                        self._make_internal_req(
                            hub,
                            body={"allow_google": True, "profile": "sync-goog", "profile_dir": str(sync_goog_dir)},
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(200, r_ok.status)
                    self.assertTrue(r_ok.data["allow_google_verified"])
                    self.assertTrue(r_ok.data["google_allowed"])
                    self.assertTrue(hub._is_active_google_allowed())

            asyncio.run(_sym_start_and_sync())

    def test_c4_dedicated_google_ephemeral_mutex_drift_guard_and_consented_override(self) -> None:
        """C4: allow_google+ephemeral mutex, default drift fail-closed, consented allow_override=True, immutable keys, and unlimited profiles."""
        self._install_mock_google_browser("pinned_acct")
        with mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES": "1"}, clear=False):
            # 1. allow_google + ephemeral / persistent=False rejected
            for bad_cfg in (
                {"os": "linux", "allow_google": True, "ephemeral": True},
                {"os": "linux", "allow_google": True, "persistent": False},
            ):
                with self.assertRaises(ValueError):
                    srv.create_profile("bad-ephem-g", bad_cfg)

            # Create dedicated Google profile
            srv.create_profile(
                "google-us-1",
                {
                    "os": "macos",
                    "locale": "en-US",
                    "window": "1440x900",
                    "block_webrtc": True,
                    "geoip": "203.0.113.10",
                    "proxy": "socks5://MOCK_U1:MOCK_P1@proxy.example.com:1080",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-us@example.com",
                },
            )
            disk_before = self.profiles_file.read_text(encoding="utf-8")

            # 2. Default (allow_override=False) rejects ALL fingerprint/egress drift overrides incl. NO_PROXY & network.proxy.type=0
            drift_cases = [
                {"proxy": "socks5://proxy.example.org:1080"},
                {"proxy": ""},
                {"proxy_bao_ref": "kv/proxies/alt"},
                {"os": "linux"},
                {"locale": "ja-JP"},
                {"window": "1280x720"},
                {"mobile": True},
                {"webgl_config": "Intel,Iris"},
                {"block_webrtc": False},
                {"geoip": False},
                {"env": {"HTTP_PROXY": "http://proxy.example.org:8080"}},
                {"env": {"NO_PROXY": "*"}},
                {"firefox_user_prefs": {"network.proxy.type": 0}},
                {"firefox_user_prefs": {"network.proxy.socks": "proxy.example.org"}},
            ]
            for ov in drift_cases:
                with self.subTest(default_drift=ov):
                    with self.assertRaises(ValueError) as cm:
                        srv.resolve_launch_spec("google-us-1", overrides=ov)
                    err_txt = str(cm.exception)
                    self.assertIn("--overwrite", err_txt)
                    self.assertIn("--confirm-override", err_txt)

            # 3. Consented strict allow_override=True permits fingerprint/egress overrides without touching profiles.json
            ov_spec = srv.resolve_launch_spec(
                "google-us-1",
                overrides={
                    "proxy": "http://MOCK_OV_U:MOCK_OV_P@proxy.example.com:8081",
                    "os": "linux",
                    "locale": "de-DE",
                    "window": "1600x900",
                    "env": {"TZ": "Europe/Berlin"},
                    "firefox_user_prefs": {"intl.accept_languages": "de-DE"},
                },
                allow_override=True,
            )
            self.assertTrue(ov_spec["allow_google"])
            self.assertTrue(ov_spec["allow_google_verified"])
            self.assertEqual("linux", ov_spec["os"])
            self.assertEqual("de-DE", ov_spec["locale"])
            self.assertEqual([1600, 900], ov_spec["window"])
            kwargs, egress = srv.build_camoufox_kwargs(ov_spec, ov_spec["profile_dir"])
            self.assertEqual("http://***@" + "proxy.example.com:8081", egress)
            self.assertNotIn("MOCK_OV_P", egress)
            self.assertEqual("MOCK_OV_U", kwargs["proxy"]["username"])
            self.assertEqual("MOCK_OV_P", kwargs["proxy"]["password"])
            self.assertEqual("Europe/Berlin", kwargs["env"]["TZ"])
            self.assertEqual("de-DE", kwargs["firefox_user_prefs"]["intl.accept_languages"])
            # Disk profiles.json MUST remain untouched!
            self.assertEqual(disk_before, self.profiles_file.read_text(encoding="utf-8"))

            # Security boundary keys are STILL permanently forbidden even with allow_override=True
            immutable_cases = [
                {"user_data_dir": str(self.root / "hijack")},
                {"persistent_context": False},
                {"persistent": False},
                {"ephemeral": True},
                {"pinned": True},
                {"allow_google": False},
                {"account": "other@example.org"},
                {"headless": False},
            ]
            for imm_ov in immutable_cases:
                with self.subTest(immutable_override=imm_ov):
                    with self.assertRaises(ValueError):
                        srv.resolve_launch_spec("google-us-1", overrides=imm_ov, allow_override=True)

            # P2-1 (C4): overrides passing BOTH non-empty proxy and non-empty proxy_bao_ref MUST fail closed
            for mutex_ov in (
                {"proxy": "http://proxy.example.com:8080", "proxy_bao_ref": "kv/proxies/us-west"},
                {"proxy": {"server": "socks5://proxy.example.com:1080"}, "proxy_bao_ref": "kv/proxies/us-west"},
            ):
                with self.subTest(prof="google-us-1", mutex_ov=mutex_ov):
                    with self.assertRaises(ValueError) as cm_mutex:
                        srv.resolve_launch_spec("google-us-1", overrides=mutex_ov, allow_override=True)
                    self.assertIn("proxy", str(cm_mutex.exception))
                    self.assertIn("proxy_bao_ref", str(cm_mutex.exception))

            # HTTP POST /internal/start verifies both 400 default drift, 400 immutable keys, and 200 consented override
            fake_mod = types.ModuleType("camoufox.async_api")
            fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
            fake_pkg = types.ModuleType("camoufox")
            fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

            async def _http_c4() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with (
                    mock.patch.object(srv, "web", self._make_fake_web()),
                    mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
                ):
                    r_bad_ephem = await srv.internal_profiles_create(
                        self._make_internal_req(
                            hub, body={"name": "ephem-g-http", "os": "linux", "allow_google": True, "ephemeral": True}
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(400, r_bad_ephem.status)

                    r_drift = await srv.internal_start(
                        self._make_internal_req(
                            hub,
                            body={
                                "profile": "google-us-1",
                                "firefox_user_prefs": {"network.proxy.type": 0},
                                "notify": False,
                            },
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(400, r_drift.status)

                    r_imm = await srv.internal_start(
                        self._make_internal_req(
                            hub,
                            body={
                                "profile": "google-us-1",
                                "allow_override": True,
                                "user_data_dir": str(self.root / "bad"),
                                "notify": False,
                            },
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(400, r_imm.status)

                    r_ok = await srv.internal_start(
                        self._make_internal_req(
                            hub,
                            body={
                                "profile": "google-us-1",
                                "allow_override": True,
                                "proxy": "http://MOCK_OV_U:MOCK_OV_P@proxy.example.com:8082",
                                "os": "linux",
                                "notify": False,
                            },
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(200, r_ok.status)
                    self.assertEqual("http://***@" + "proxy.example.com:8082", r_ok.data["egress"])
                    self.assertNotIn("MOCK_OV_P", json.dumps(r_ok.data))
                    await hub.stop_hosted(notify_finished=False)

            asyncio.run(_http_c4())
            self.assertEqual(disk_before, self.profiles_file.read_text(encoding="utf-8"))

            # P2-1 (C4) ordinary profile also rejects simultaneous proxy + proxy_bao_ref overrides
            srv.create_profile("ord-mutex-c4", {"os": "linux"})
            with self.assertRaises(ValueError) as cm_ord_mutex:
                srv.resolve_launch_spec(
                    "ord-mutex-c4",
                    overrides={"proxy": "socks5://proxy.example.com:1080", "proxy_bao_ref": "kv/proxies/us-west"},
                )
            self.assertIn("proxy", str(cm_ord_mutex.exception))
            self.assertIn("proxy_bao_ref", str(cm_ord_mutex.exception))

            # 4. Persistent overwrite while idle + unlimited dedicated Google profiles (4+ distinct profiles)
            updated = srv.create_profile(
                "google-us-1",
                {
                    "os": "macos",
                    "locale": "en-US",
                    "proxy": "socks5://MOCK_NEW_U:MOCK_NEW_P@proxy.example.com:1081",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-us@example.com",
                },
                overwrite=True,
            )
            self.assertEqual("socks5://***@" + "proxy.example.com:1081", updated["egress"])

            srv.create_profile(
                "google-jp-2",
                {
                    "os": "windows",
                    "locale": "ja-JP",
                    "proxy": "http://proxy.example.org:3128",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-jp@example.org",
                },
            )
            srv.create_profile(
                "google-eu-3",
                {
                    "os": "linux",
                    "locale": "de-DE",
                    "proxy_bao_ref": "kv/proxies/eu-res#url",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-eu@example.net",
                },
            )
            srv.create_profile(
                "google-direct-4",
                {
                    "os": "windows",
                    "locale": "en-GB",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-uk@example.com",
                },
            )
            for pname in ("google-us-1", "google-jp-2", "google-eu-3", "google-direct-4"):
                sp = srv.resolve_launch_spec(pname)
                self.assertTrue(sp["allow_google_verified"])
                self.assertFalse(sp["pinned"])

            # Verify CLI parser flags: --allow-google, --account, --confirm-override
            parser = live_browser_ctl.build_parser()
            ns_c = parser.parse_args(
                ["profile", "create", "google-cli-5", "--allow-google", "--account", "acct-cli@example.com", "--os", "macos"]
            )
            self.assertTrue(ns_c.allow_google)
            self.assertEqual("acct-cli@example.com", ns_c.account)
            ns_s = parser.parse_args(
                ["start", "--profile", "google-cli-5", "--confirm-override", "--proxy", "socks5://proxy.example.com:1080"]
            )
            self.assertTrue(ns_s.confirm_override)

    def test_c5_running_profile_overwrite_and_delete_409_conflict(self) -> None:
        """C5: Overwriting or deleting a running profile fails closed with RuntimeError / HTTP 409; succeeds after stop."""
        self._install_mock_google_browser("pinned_acct")
        with mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES": "1"}, clear=False):
            srv.create_profile(
                "google-run",
                {
                    "os": "macos",
                    "proxy": "socks5://proxy.example.com:1080",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-run@example.com",
                },
            )
            before_disk = self.profiles_file.read_text(encoding="utf-8")

            fake_mod = types.ModuleType("camoufox.async_api")
            fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
            fake_pkg = types.ModuleType("camoufox")
            fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with (
                    mock.patch.object(srv, "web", self._make_fake_web()),
                    mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
                ):
                    await hub.start_hosted(initial_url="https://example.com", profile="google-run", notify_tg=False)
                    self.assertEqual("google-run", hub.active_profile)

                    # Direct calls raise RuntimeError
                    with self.assertRaises(RuntimeError):
                        srv.create_profile(
                            "google-run",
                            {"os": "linux", "allow_google": True, "persistent": True},
                            overwrite=True,
                            active_profile=hub.active_profile,
                        )
                    with self.assertRaises(RuntimeError):
                        srv.delete_profile("google-run", active_profile=hub.active_profile)

                    # HTTP POST /internal/profiles (overwrite=true) & DELETE return 409, profiles.json untouched
                    r_ov = await srv.internal_profiles_create(
                        self._make_internal_req(
                            hub,
                            body={
                                "name": "google-run",
                                "overwrite": True,
                                "os": "linux",
                                "allow_google": True,
                                "persistent": True,
                            },
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(409, r_ov.status)

                    r_del = await srv.internal_profiles_delete(
                        self._make_internal_req(hub, match_info={"name": "google-run"})
                    )  # type: ignore[arg-type]
                    self.assertEqual(409, r_del.status)
                    self.assertEqual(before_disk, self.profiles_file.read_text(encoding="utf-8"))

                    # Stop -> idle -> overwrite & delete succeed with 200
                    await hub.stop_hosted(notify_finished=False)
                    self.assertEqual("idle", hub.engine_mode)

                    # P1-1 (C5): Concurrent startup TOCTOU race — AsyncCamoufox.__aenter__ suspended while
                    # POST /internal/profiles (overwrite=True) & DELETE /internal/profiles/<name> arrive.
                    # Both MUST serialize on hub._engine_lock, return 409, and leave profiles.json byte-identical!
                    entered_ev = asyncio.Event()
                    release_ev = asyncio.Event()

                    class _BlockingStartCamoufoxCM(_FakeAsyncCamoufoxCM):
                        async def __aenter__(self) -> _FakeContext:
                            entered_ev.set()
                            await release_ev.wait()
                            return await super().__aenter__()

                    block_mod = types.ModuleType("camoufox.async_api")
                    block_mod.AsyncCamoufox = _BlockingStartCamoufoxCM  # type: ignore[attr-defined]
                    block_pkg = types.ModuleType("camoufox")
                    block_pkg.async_api = block_mod  # type: ignore[attr-defined]

                    with mock.patch.dict(sys.modules, {"camoufox": block_pkg, "camoufox.async_api": block_mod}):
                        start_task = asyncio.create_task(
                            hub.start_hosted(initial_url="https://example.com", profile="google-run", notify_tg=False)
                        )
                        await asyncio.wait_for(entered_ev.wait(), timeout=2.0)
                        self.assertEqual("", hub.active_profile)

                        ov_race_task = asyncio.create_task(
                            srv.internal_profiles_create(
                                self._make_internal_req(
                                    hub,
                                    body={
                                        "name": "google-run",
                                        "overwrite": True,
                                        "os": "linux",
                                        "allow_google": True,
                                        "persistent": True,
                                    },
                                )
                            )  # type: ignore[arg-type]
                        )
                        del_race_task = asyncio.create_task(
                            srv.internal_profiles_delete(
                                self._make_internal_req(hub, match_info={"name": "google-run"})
                            )  # type: ignore[arg-type]
                        )
                        await asyncio.sleep(0.02)
                        self.assertFalse(ov_race_task.done(), "overwrite must block on _engine_lock during startup")
                        self.assertFalse(del_race_task.done(), "delete must block on _engine_lock during startup")

                        release_ev.set()
                        st_race, r_ov_race, r_del_race = await asyncio.gather(start_task, ov_race_task, del_race_task)
                        self.assertTrue(st_race["running"])
                        self.assertEqual("google-run", hub.active_profile)
                        self.assertEqual(409, r_ov_race.status)
                        self.assertEqual(409, r_del_race.status)
                        self.assertEqual(before_disk, self.profiles_file.read_text(encoding="utf-8"))

                    await hub.stop_hosted(notify_finished=False)
                    self.assertEqual("idle", hub.engine_mode)

                    r_ov2 = await srv.internal_profiles_create(
                        self._make_internal_req(
                            hub,
                            body={
                                "name": "google-run",
                                "overwrite": True,
                                "os": "linux",
                                "proxy": "http://proxy.example.org:8080",
                                "allow_google": True,
                                "persistent": True,
                                "account": "acct-run@example.com",
                            },
                        )
                    )  # type: ignore[arg-type]
                    self.assertEqual(200, r_ov2.status)
                    self.assertEqual("http://proxy.example.org:8080", r_ov2.data["profile"]["egress"])

                    r_del2 = await srv.internal_profiles_delete(
                        self._make_internal_req(hub, match_info={"name": "google-run"})
                    )  # type: ignore[arg-type]
                    self.assertEqual(200, r_del2.status)

            asyncio.run(_scenario())

    def test_c6_ordinary_ephemeral_fail_closed_and_dedicated_positive_flow(self) -> None:
        """C6: With host switch ON, ordinary & ephemeral profiles stay 100% blocked while dedicated Google profile works end-to-end."""
        self._install_mock_google_browser("pinned_acct")
        with mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES": "1"}, clear=False):
            srv.create_profile("ord-prof", {"os": "linux", "allow_google": False, "persistent": True})
            srv.create_profile("ephem-prof", {"os": "linux", "persistent": False})
            srv.create_profile(
                "ded-goog",
                {
                    "os": "macos",
                    "locale": "en-US",
                    "proxy": "socks5://proxy.example.com:1080",
                    "allow_google": True,
                    "persistent": True,
                    "account": "acct-ded@example.com",
                },
            )

            fake_mod = types.ModuleType("camoufox.async_api")
            fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
            fake_pkg = types.ModuleType("camoufox")
            fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                    # Ordinary & ephemeral profiles remain blocked across start_hosted, AI goto, human new_tab, ctx.route
                    for blocked_prof in ("ord-prof", "ephem-prof"):
                        with self.assertRaises(ValueError):
                            await hub.start_hosted(
                                initial_url="https://mail.google.com", profile=blocked_prof, notify_tg=False
                            )
                        self.assertEqual("idle", hub.engine_mode)

                        await hub.start_hosted(
                            initial_url="https://example.com", profile=blocked_prof, notify_tg=False
                        )
                        self.assertFalse(hub._is_active_google_allowed())
                        self.assertTrue(hub.ctx._callbacks.get("route"))
                        with self.assertRaises(ValueError):
                            await hub.execute_ai_action(
                                {"action": "goto", "url": "https://accounts.google.com/signin", "notify": False}
                            )
                        hub.takeover = True
                        await hub._execute_human_cmd_async({"action": "new_tab"})
                        self.assertEqual("about:blank", hub._current_page().url)
                        await hub.stop_hosted(notify_finished=False)

                    # Positive flow: dedicated Google profile allowed on start_hosted, AI goto, human goto & new_tab!
                    st = await hub.start_hosted(
                        initial_url="https://mail.google.com/mail/u/0/#inbox",
                        profile="ded-goog",
                        notify_tg=False,
                    )
                    self.assertTrue(st["running"])
                    self.assertTrue(st["allow_google"])
                    self.assertFalse(st["pinned"])
                    self.assertTrue(hub._is_active_google_allowed())
                    self.assertFalse(hub.ctx._callbacks.get("route"))

                    await hub.execute_ai_action(
                        {"action": "goto", "url": "https://myaccount.google.com", "notify": False}
                    )
                    self.assertEqual("https://myaccount.google.com", hub._current_page().url)

                    hub.takeover = True
                    await hub._execute_human_cmd_async({"action": "new_tab"})
                    self.assertEqual("https://www.google.com", hub._current_page().url)
                    await hub.stop_hosted(notify_finished=False)

            asyncio.run(_scenario())

            # SyncLiveBridge consistency check: ordinary/ephemeral blocked, verified dedicated allowed
            ord_dir = self.profiles_data / "ord-prof"
            ord_dir.mkdir(parents=True, exist_ok=True)
            ded_dir = self.profiles_data / "ded-goog"
            ded_dir.mkdir(parents=True, exist_ok=True)

            br_ord = live_browser_ctl.SyncLiveBridge.__new__(live_browser_ctl.SyncLiveBridge)
            br_ord._pinned_verified = False
            br_ord._allow_google_verified = False
            br_ord._profile_name = "ord-prof"
            br_ord._profile_dir = ord_dir
            self.assertTrue(br_ord._is_sync_google_nav_blocked("https://mail.google.com"))

            br_ded = live_browser_ctl.SyncLiveBridge.__new__(live_browser_ctl.SyncLiveBridge)
            br_ded._pinned_verified = False
            br_ded._allow_google_verified = True
            br_ded._profile_name = "ded-goog"
            br_ded._profile_dir = ded_dir
            self.assertFalse(br_ded._is_sync_google_nav_blocked("https://mail.google.com"))

    def test_c7_account_validation_and_group_nonowner_readonly_redaction(self) -> None:
        """C7: Strict account label validation and redaction across group, non-owner & readonly views (HTTP + WS)."""
        self._install_mock_google_browser("pinned_acct")
        # 1. Account validation & secret rejection
        for bad_acct in (123, True, ["a"], "has space", "   ", "line\nbreak", "ctrl\x00char", "a" * 129):
            with self.subTest(bad_account=bad_acct):
                with self.assertRaises(ValueError):
                    srv.create_profile("bad-acct", {"os": "linux", "account": bad_acct})
        for secret_key in ("password", "google_password", "secret", "token"):
            with self.subTest(secret_key=secret_key):
                with self.assertRaises(ValueError):
                    srv.create_profile("bad-sec", {"os": "linux", secret_key: "MOCK_SECRET_VAL"})

        # Empty string normalizes to None
        empty_acct = srv.create_profile("empty-acct", {"os": "linux", "account": ""})
        self.assertNotIn("account", empty_acct)

        # Valid dedicated profile with account + proxy credentials
        created = srv.create_profile(
            "secret-acct-prof",
            {
                "os": "macos",
                "allow_google": True,
                "persistent": True,
                "account": "sensitive-user@example.com",
                "proxy": "socks5://MOCK_U:MOCK_P@proxy.example.com:1080",
            },
        )
        self.assertEqual("sensitive-user@example.com", created["account"])
        self.assertNotIn("MOCK_P", json.dumps(created))
        self.assertEqual(0o600, stat.S_IMODE(self.profiles_file.stat().st_mode))

        # 2. Group / non-owner / readonly redaction across HTTP & WS
        bdir = self.root / "bridge-c7"
        bdir.mkdir(parents=True, exist_ok=True)
        bot_token = "123456789:EXAMPLE_C7_TEST_TOKEN_PAYLOAD_12345"
        (bdir / ".env").write_text(
            f"AGY_TG_BOT_TOKEN={bot_token}\n"
            "AGY_TG_ALLOWED_CHATS=111,112,113,-1001234567890\n"
            "AGY_TG_ADMIN_USERS=111,113\n"
            "AGY_TG_USER_ROLES=111:admin,112:readonly,113:admin\n",
            encoding="utf-8",
        )

        import hashlib
        import hmac
        import time as _time
        import urllib.parse as _urlparse

        def _sign_init(uid: int) -> str:
            user_json = json.dumps({"id": uid, "first_name": "Tester"}, separators=(",", ":"))
            fields = {"auth_date": str(int(_time.time())), "query_id": "Q1", "user": user_json}
            dcs = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
            secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
            fields["hash"] = hmac.new(secret, dcs.encode("utf-8"), hashlib.sha256).hexdigest()
            return _urlparse.urlencode(fields)

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            hub.engine_mode = "async_hosted"
            hub.session_gen = 5
            hub.session_owner = ("main", 111)
            hub.active_profile = "secret-acct-prof"
            hub.active_egress = "socks5://***@" + "proxy.example.com:1080"

            with (
                mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                mock.patch.object(srv, "web", self._make_fake_web()),
            ):
                # _redacted_state_dict & state_dict_for_viewer (non-owner admin 113 & readonly 112)
                for redacted in (
                    hub._redacted_state_dict(),
                    hub.state_dict_for_viewer("main", 113, "admin"),
                    hub.state_dict_for_viewer("main", 112, "readonly"),
                ):
                    blob = json.dumps(redacted)
                    self.assertEqual([], redacted["profiles"])
                    self.assertIsNone(redacted["profile"])
                    self.assertNotIn("sensitive-user@example.com", blob)
                    self.assertNotIn("secret-acct-prof", blob)
                    self.assertNotIn("proxy.example.com", blob)

                # Even when idle, readonly viewer sees profiles=[] and zero account/proxy leak
                hub.engine_mode = "idle"
                ro_idle = hub.state_dict_for_viewer("main", 112, "readonly")
                self.assertEqual([], ro_idle["profiles"])
                self.assertNotIn("sensitive-user@example.com", json.dumps(ro_idle))
                hub.engine_mode = "async_hosted"

                # HTTP /internal/profiles & /internal/status for group, non-owner, readonly
                restricted_queries = [
                    {"source": "tg_cmd", "bot": "main", "user_id": "111", "chat_id": "-1001234567890", "chat_scope": "group"},
                    {"source": "tg_cmd", "bot": "main", "user_id": "113", "chat_id": "113"},
                    {"source": "tg_cmd", "bot": "main", "user_id": "112", "chat_id": "112"},
                ]
                for q in restricted_queries:
                    rp = await srv.internal_profiles_list(self._make_internal_req(hub, query=q))  # type: ignore[arg-type]
                    self.assertEqual([], rp.data["profiles"])
                    self.assertIsNone(rp.data["active_profile"])
                    self.assertNotIn("sensitive-user@example.com", json.dumps(rp.data))

                    rs = await srv.internal_status(self._make_internal_req(hub, query=q))  # type: ignore[arg-type]
                    self.assertEqual([], rs.data["profiles"])
                    self.assertIsNone(rs.data["profile"])
                    self.assertNotIn("sensitive-user@example.com", json.dumps(rs.data))

                # Owner admin DM sees account & masked proxy
                rp_own = await srv.internal_profiles_list(
                    self._make_internal_req(hub, query={"source": "tg_cmd", "bot": "main", "user_id": "111", "chat_id": "111"})
                )  # type: ignore[arg-type]
                by_name = {p["name"]: p for p in rp_own.data["profiles"]}
                self.assertEqual("sensitive-user@example.com", by_name["secret-acct-prof"]["account"])
                self.assertNotIn("MOCK_P", json.dumps(rp_own.data))

                # WS list_profiles for non-owner (113) & readonly (112): returns profiles=[] and zero account leak
                class _FakeWSMsg:
                    def __init__(self, payload: str) -> None:
                        self.type = "TEXT"
                        self.data = payload

                class _FakeWS:
                    def __init__(self, msgs: list[dict]) -> None:
                        self._msgs = [_FakeWSMsg(json.dumps(m)) for m in msgs]
                        self.sent: list[dict] = []
                        self.closed = False

                    async def prepare(self, _req) -> None:
                        return None

                    async def receive(self, timeout=None):  # noqa: ARG002
                        return self._msgs.pop(0)

                    async def send_str(self, s: str) -> None:
                        self.sent.append(json.loads(s))

                    async def send_bytes(self, _b: bytes) -> None:
                        return None

                    async def close(self, **_kw) -> None:
                        self.closed = True

                    def __aiter__(self):
                        return self

                    async def __anext__(self):
                        if self._msgs:
                            return self._msgs.pop(0)
                        raise StopAsyncIteration

                for viewer_uid in (113, 112):
                    ws_inst = _FakeWS(
                        [{"type": "auth", "initData": _sign_init(viewer_uid)}, {"type": "list_profiles"}]
                    )
                    fake_ws_web = types.SimpleNamespace(
                        WebSocketResponse=lambda **_kw: ws_inst,
                        json_response=self._make_fake_web().json_response,
                        HTTPForbidden=RuntimeError,
                    )
                    with (
                        mock.patch.object(srv, "web", fake_ws_web),
                        mock.patch.object(srv, "WSMsgType", types.SimpleNamespace(TEXT="TEXT")),
                    ):
                        await srv.handle_ws(types.SimpleNamespace(remote="127.0.0.1", app={"hub": hub}))  # type: ignore[arg-type]
                    pl_msgs = [m for m in ws_inst.sent if m.get("type") == "profiles_list"]
                    self.assertEqual(1, len(pl_msgs))
                    self.assertEqual([], pl_msgs[0]["profiles"])
                    self.assertIsNone(pl_msgs[0]["active_profile"])
                    self.assertNotIn("sensitive-user@example.com", json.dumps(ws_inst.sent))
                    self.assertNotIn("secret-acct-prof", json.dumps(ws_inst.sent))

                # P0-1 (C7): WS initial state snapshot replay MUST sanitize for readonly viewers in BOTH:
                #   (A) hub.engine_mode == "idle" (readonly user 112)
                #   (B) active session where original owner (111) was demoted to readonly
                hub.engine_mode = "idle"
                ws_ro_idle = _FakeWS([{"type": "auth", "initData": _sign_init(112)}])
                fake_ws_web_idle = types.SimpleNamespace(
                    WebSocketResponse=lambda **_kw: ws_ro_idle,
                    json_response=self._make_fake_web().json_response,
                    HTTPForbidden=RuntimeError,
                )
                with (
                    mock.patch.object(srv, "web", fake_ws_web_idle),
                    mock.patch.object(srv, "WSMsgType", types.SimpleNamespace(TEXT="TEXT")),
                ):
                    await srv.handle_ws(types.SimpleNamespace(remote="127.0.0.1", app={"hub": hub}))  # type: ignore[arg-type]
                idle_states = [m for m in ws_ro_idle.sent if m.get("type") == "state"]
                self.assertEqual(1, len(idle_states))
                self.assertEqual([], idle_states[0]["profiles"])
                self.assertIsNone(idle_states[0]["profile"])
                self.assertEqual("", idle_states[0]["egress"])
                idle_blob = json.dumps(ws_ro_idle.sent)
                self.assertNotIn("sensitive-user@example.com", idle_blob)
                self.assertNotIn("secret-acct-prof", idle_blob)
                self.assertNotIn("proxy.example.com", idle_blob)

                # (B) Demote original owner 111 -> readonly while session is active
                hub.engine_mode = "async_hosted"
                hub.session_owner = ("main", 111)
                hub.active_profile = "secret-acct-prof"
                hub.active_egress = "socks5://***@" + "proxy.example.com:1080"
                orig_env_txt = (bdir / ".env").read_text(encoding="utf-8")
                try:
                    (bdir / ".env").write_text(
                        f"AGY_TG_BOT_TOKEN={bot_token}\n"
                        "AGY_TG_ALLOWED_CHATS=111,112,113,-1001234567890\n"
                        "AGY_TG_ADMIN_USERS=113\n"
                        "AGY_TG_USER_ROLES=111:readonly,112:readonly,113:admin\n",
                        encoding="utf-8",
                    )
                    ws_demoted = _FakeWS([{"type": "auth", "initData": _sign_init(111)}])
                    fake_ws_web_demoted = types.SimpleNamespace(
                        WebSocketResponse=lambda **_kw: ws_demoted,
                        json_response=self._make_fake_web().json_response,
                        HTTPForbidden=RuntimeError,
                    )
                    with (
                        mock.patch.object(srv, "web", fake_ws_web_demoted),
                        mock.patch.object(srv, "WSMsgType", types.SimpleNamespace(TEXT="TEXT")),
                    ):
                        await srv.handle_ws(types.SimpleNamespace(remote="127.0.0.1", app={"hub": hub}))  # type: ignore[arg-type]
                    demoted_states = [m for m in ws_demoted.sent if m.get("type") == "state"]
                    self.assertEqual(1, len(demoted_states))
                    self.assertEqual([], demoted_states[0]["profiles"])
                    self.assertIsNone(demoted_states[0]["profile"])
                    self.assertEqual("", demoted_states[0]["egress"])
                    demoted_blob = json.dumps(ws_demoted.sent)
                    self.assertNotIn("sensitive-user@example.com", demoted_blob)
                    self.assertNotIn("secret-acct-prof", demoted_blob)
                    self.assertNotIn("proxy.example.com", demoted_blob)
                finally:
                    (bdir / ".env").write_text(orig_env_txt, encoding="utf-8")

                # P1-2 (C7): HTTP POST /internal/profiles & DELETE /internal/profiles/<name> RBAC + group error redaction
                r_grp_create = await srv.internal_profiles_create(
                    self._make_internal_req(
                        hub,
                        body={
                            "name": "grp-secret-prof",
                            "os": "macos",
                            "allow_google": True,
                            "persistent": True,
                            "account": "grp-acct@example.com",
                            "proxy": "socks5://MOCK_U:MOCK_P@proxy.example.com:1080",
                            "source": "tg_cmd",
                            "bot": "main",
                            "user_id": 111,
                            "chat_id": -1001234567890,
                            "chat_scope": "group",
                        },
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(403, r_grp_create.status)
                grp_create_blob = json.dumps(r_grp_create.data)
                self.assertNotIn("grp-secret-prof", grp_create_blob)
                self.assertNotIn("grp-acct@example.com", grp_create_blob)
                self.assertNotIn("proxy.example.com", grp_create_blob)
                self.assertNotIn("MOCK_P", grp_create_blob)

                r_ro_create = await srv.internal_profiles_create(
                    self._make_internal_req(
                        hub,
                        body={
                            "name": "ro-secret-prof",
                            "os": "linux",
                            "account": "ro-acct@example.com",
                            "source": "tg_cmd",
                            "bot": "main",
                            "user_id": 112,
                            "chat_id": 112,
                        },
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(403, r_ro_create.status)
                self.assertNotIn("ro-secret-prof", json.dumps(r_ro_create.data))
                self.assertNotIn("ro-acct@example.com", json.dumps(r_ro_create.data))

                r_grp_del = await srv.internal_profiles_delete(
                    self._make_internal_req(
                        hub,
                        match_info={"name": "secret-acct-prof"},
                        query={
                            "source": "tg_cmd",
                            "bot": "main",
                            "user_id": "111",
                            "chat_id": "-1001234567890",
                            "chat_scope": "group",
                        },
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(403, r_grp_del.status)
                self.assertNotIn("secret-acct-prof", json.dumps(r_grp_del.data))
                self.assertNotIn("sensitive-user@example.com", json.dumps(r_grp_del.data))

                r_ro_del = await srv.internal_profiles_delete(
                    self._make_internal_req(
                        hub,
                        match_info={"name": "secret-acct-prof"},
                        query={"source": "tg_cmd", "bot": "main", "user_id": "112", "chat_id": "112"},
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(403, r_ro_del.status)
                self.assertNotIn("secret-acct-prof", json.dumps(r_ro_del.data))

                # Group error-path redaction for internal_profiles_delete (404/409/400) if control passes
                with mock.patch.object(
                    srv, "_verify_internal_caller_control", return_value=(True, "ok", None, {"is_tg": False})
                ):
                    for err_name, expected_status in (
                        ("secret-acct-prof", 409),
                        ("missing-secret-prof", 404),
                        ("pinned_acct", 400),
                    ):
                        r_gerr = await srv.internal_profiles_delete(
                            self._make_internal_req(
                                hub,
                                match_info={"name": err_name},
                                query={"chat_scope": "group", "chat_id": "-1001234567890"},
                            )
                        )  # type: ignore[arg-type]
                        self.assertEqual(expected_status, r_gerr.status)
                        self.assertNotIn(err_name, json.dumps(r_gerr.data))
                        self.assertNotIn("proxy.example.com", json.dumps(r_gerr.data))

                # TG DM owner admin CAN create & delete when idle; pure local CLI unaffected
                hub.engine_mode = "idle"
                hub.active_profile = ""
                r_dm_create = await srv.internal_profiles_create(
                    self._make_internal_req(
                        hub,
                        body={
                            "name": "dm-owner-prof",
                            "os": "linux",
                            "source": "tg_cmd",
                            "bot": "main",
                            "user_id": 111,
                            "chat_id": 111,
                        },
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(200, r_dm_create.status)
                r_dm_del = await srv.internal_profiles_delete(
                    self._make_internal_req(
                        hub,
                        match_info={"name": "dm-owner-prof"},
                        query={"source": "tg_cmd", "bot": "main", "user_id": "111", "chat_id": "111"},
                    )
                )  # type: ignore[arg-type]
                self.assertEqual(200, r_dm_del.status)

        asyncio.run(_scenario())

        # P2-2 (C7): LiveBrowserClient.list_profiles() daemon-offline fallback group/non-DM redaction
        for group_env in (
            {"AGY_BOT_CHAT_ID": "-1001234567890"},
            {"AGY_BOT_CHAT_ID": "-1001234567890", "AGY_LIVE_USER_ID": "111"},
            {"AGY_BOT_CHAT_SCOPE": "group"},
        ):
            with self.subTest(offline_group_env=group_env):
                with mock.patch.dict(os.environ, group_env, clear=False):
                    client = live_browser_ctl.LiveBrowserClient(bot="sg")
                    try:
                        with mock.patch.object(client, "is_alive", return_value=False):
                            res_off = client.list_profiles()
                        self.assertEqual({"ok": True, "active_profile": None, "profiles": []}, res_off)
                        off_blob = json.dumps(res_off)
                        self.assertNotIn("sensitive-user@example.com", off_blob)
                        self.assertNotIn("secret-acct-prof", off_blob)
                        self.assertNotIn("proxy.example.com", off_blob)
                    finally:
                        client.session.close()

        # Pure local CLI offline fallback (no group env) still lists configured profiles
        cli_client = live_browser_ctl.LiveBrowserClient(bot="sg")
        try:
            with mock.patch.object(cli_client, "is_alive", return_value=False):
                res_cli = cli_client.list_profiles()
            self.assertTrue(res_cli["ok"])
            self.assertTrue(any(p["name"] == "secret-acct-prof" for p in res_cli["profiles"]))
        finally:
            cli_client.session.close()

    def test_c8_public_files_sanitization_guard(self) -> None:
        """C8: Public-synced live-browser files contain zero hardcoded host user home paths."""
        forbidden_home = "/" + "home" + "/" + "ubuntu"
        public_files = (
            REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_server.py",
            REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_ctl.py",
            REPO_ROOT / ".agents/skills/live-browser/SKILL.md",
            REPO_ROOT / "tests/test_live_browser_profiles.py",
        )
        for pf in public_files:
            txt = pf.read_text(encoding="utf-8")
            self.assertNotIn(forbidden_home, txt, f"Hardcoded host path found in public file {pf.name}")


if __name__ == "__main__":
    unittest.main()
