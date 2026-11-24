#!/usr/bin/env python3
"""Offline unit tests for Live-Browser Phase 2: X11 XTest Human Pointer Engine + Post-Click Burst (D1–D8)."""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
from typing import Any
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_SCRIPTS = REPO_ROOT / ".agents/skills/live-browser/scripts"
if str(LIVE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(LIVE_SCRIPTS))

import live_browser_ctl  # noqa: E402
import live_browser_server as srv  # noqa: E402


class _FakeCFunc:
    """Fake ctypes C function recording argtypes, restype, and invocations."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self._fn = fn
        self.argtypes: Any = None
        self.restype: Any = None
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        return self._fn(*args)


class _FakeX11Stack:
    """Deterministic fake libX11.so.6 + libXtst.so.6 stack with handle leak & concurrency tracking."""

    def __init__(
        self,
        *,
        scr_w: int = 1920,
        scr_h: int = 1080,
        open_returns_null: bool = False,
        xtest_supported: bool = True,
        fail_motion: bool = False,
        fail_button_on_calls: set[int] | None = None,
        raise_on_release_buttons: set[int] | None = None,
        track_concurrency: bool = False,
        motion_delay_s: float = 0.0,
    ) -> None:
        self.scr_w = scr_w
        self.scr_h = scr_h
        self.open_returns_null = open_returns_null
        self.xtest_supported = xtest_supported
        self.fail_motion = fail_motion
        self.fail_button_on_calls = set(fail_button_on_calls or ())
        self.raise_on_release_buttons = set(raise_on_release_buttons or ())
        self.track_concurrency = track_concurrency
        self.motion_delay_s = motion_delay_s

        self._next_handle = 0x7F0000010000  # 64-bit pointer (> 32-bit int range!)
        self.opened_handles: list[tuple[int, bytes]] = []
        self.closed_handles: list[int] = []
        self.double_closes: list[int] = []
        self.active_handles: set[int] = set()
        self.events: list[tuple[Any, ...]] = []
        self.cdll_loads: list[str] = []
        self._btn_call_seq = 0

        self._conc_lock = threading.Lock()
        self._in_flight = 0
        self.max_concurrent_calls = 0

        self.x11 = types.SimpleNamespace(
            XOpenDisplay=_FakeCFunc("XOpenDisplay", self._open_display),
            XCloseDisplay=_FakeCFunc("XCloseDisplay", self._close_display),
            XFlush=_FakeCFunc("XFlush", self._flush),
            XDefaultScreen=_FakeCFunc("XDefaultScreen", self._default_screen),
            XDisplayWidth=_FakeCFunc("XDisplayWidth", self._display_width),
            XDisplayHeight=_FakeCFunc("XDisplayHeight", self._display_height),
        )
        self.xtst = types.SimpleNamespace(
            XTestQueryExtension=_FakeCFunc("XTestQueryExtension", self._query_ext),
            XTestFakeMotionEvent=_FakeCFunc("XTestFakeMotionEvent", self._fake_motion),
            XTestFakeButtonEvent=_FakeCFunc("XTestFakeButtonEvent", self._fake_button),
        )

    def _enter_call(self) -> None:
        if not self.track_concurrency:
            return
        with self._conc_lock:
            self._in_flight += 1
            if self._in_flight > self.max_concurrent_calls:
                self.max_concurrent_calls = self._in_flight

    def _exit_call(self) -> None:
        if not self.track_concurrency:
            return
        with self._conc_lock:
            self._in_flight -= 1

    def cdll_loader(self, name: str) -> Any:
        self.cdll_loads.append(name)
        if name == "libX11.so.6":
            return self.x11
        if name == "libXtst.so.6":
            return self.xtst
        raise OSError(f"Unexpected library load: {name}")

    def _open_display(self, disp_bytes: bytes) -> int:
        self._enter_call()
        try:
            if self.open_returns_null:
                return 0
            h = self._next_handle
            self._next_handle += 0x100
            self.opened_handles.append((h, disp_bytes))
            self.active_handles.add(h)
            self.events.append(("open", h, disp_bytes))
            return h
        finally:
            self._exit_call()

    def _close_display(self, dpy: int) -> int:
        self._enter_call()
        try:
            if dpy not in self.active_handles:
                self.double_closes.append(dpy)
            else:
                self.active_handles.discard(dpy)
            self.closed_handles.append(dpy)
            self.events.append(("close", dpy))
            return 0
        finally:
            self._exit_call()

    def _flush(self, dpy: int) -> int:
        self._enter_call()
        try:
            self.events.append(("flush", dpy))
            return 1
        finally:
            self._exit_call()

    def _default_screen(self, _dpy: int) -> int:
        return 0

    def _display_width(self, _dpy: int, _scr: int) -> int:
        return self.scr_w

    def _display_height(self, _dpy: int, _scr: int) -> int:
        return self.scr_h

    def _query_ext(self, _dpy: int, _ev: Any, _err: Any, _maj: Any, _min: Any) -> int:
        return 1 if self.xtest_supported else 0

    def _fake_motion(self, dpy: int, scr: int, sx: int, sy: int, delay: int) -> int:
        self._enter_call()
        try:
            if self.motion_delay_s > 0:
                time.sleep(self.motion_delay_s)
            self.events.append(("motion", dpy, scr, sx, sy, delay))
            if self.fail_motion:
                return 0
            return 1
        finally:
            self._exit_call()

    def _fake_button(self, dpy: int, btn: int, is_press: int, delay: int) -> int:
        self._enter_call()
        try:
            self._btn_call_seq += 1
            if not is_press and btn in self.raise_on_release_buttons:
                self.events.append(("button_err", dpy, btn, is_press, delay))
                raise RuntimeError("simulated X11 release error /secret/path?token=XYZ_LEAK_999")
            self.events.append(("button", dpy, btn, bool(is_press), delay))
            if self._btn_call_seq in self.fail_button_on_calls:
                return 0
            return 1
        finally:
            self._exit_call()


class _FakeMouse:
    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []

    async def move(self, x: float, y: float) -> None:
        self.events.append(("move", x, y))

    async def down(self, *, button: str = "left") -> None:
        self.events.append(("down", button))

    async def up(self, *, button: str = "left") -> None:
        self.events.append(("up", button))

    async def click(self, x: float, y: float, **kwargs: Any) -> None:
        self.events.append(("click", x, y, kwargs))

    async def dblclick(self, x: float, y: float, **kwargs: Any) -> None:
        self.events.append(("dblclick", x, y, kwargs))

    async def wheel(self, dx: float, dy: float) -> None:
        self.events.append(("wheel", dx, dy))


class _FakeLocator:
    def __init__(self, page: "_FakePage", selector: str) -> None:
        self._page = page
        self._selector = selector
        self.first = self

    async def bounding_box(self, **_kw: Any) -> dict[str, float]:
        return {"x": 100.0, "y": 200.0, "width": 80.0, "height": 30.0}

    async def click(self, **_kw: Any) -> None:
        self._page.locator_clicks.append(self._selector)


class _FakePage:
    def __init__(
        self,
        url: str = "https://app.example/home",
        title_text: str = "Home",
        *,
        geom: Any = None,
        frames: list[bytes] | None = None,
        hub_ref: Any = None,
    ) -> None:
        self.url = url
        self._title = title_text
        self.viewport_size = {"width": 1280, "height": 800}
        self.mouse = _FakeMouse()
        self.keyboard = types.SimpleNamespace(
            press=mock.AsyncMock(),
            type=mock.AsyncMock(),
            insert_text=mock.AsyncMock(),
        )
        self.geom = (
            geom
            if geom is not None
            else {
                "mozInnerScreenX": 10,
                "mozInnerScreenY": 80,
                "innerWidth": 1280,
                "innerHeight": 800,
                "devicePixelRatio": 1.0,
            }
        )
        self.eval_calls: list[str] = []
        self.locator_clicks: list[str] = []
        self.screenshot_calls = 0
        self.lock_states_during_screenshot: list[bool] = []
        self._frames = list(frames or [b"JPEG_DEFAULT"])
        self._hub_ref = hub_ref
        self._closed = False

    def is_closed(self) -> bool:
        return self._closed

    def on(self, _ev: str, _cb: Any) -> None:
        pass

    async def title(self) -> str:
        return self._title

    async def goto(self, url: str, **_kw: Any) -> None:
        self.url = url

    async def bring_to_front(self) -> None:
        pass

    async def close(self) -> None:
        self._closed = True

    def locator(self, selector: str) -> _FakeLocator:
        return _FakeLocator(self, selector)

    async def evaluate(self, expr: str, *_args: Any) -> Any:
        self.eval_calls.append(expr)
        if "mozInnerScreenX" in expr:
            if callable(self.geom):
                res = self.geom()
                if asyncio.iscoroutine(res):
                    return await res
                return res
            return self.geom
        return None

    async def screenshot(self, **_kw: Any) -> bytes:
        self.screenshot_calls += 1
        if self._hub_ref is not None:
            self.lock_states_during_screenshot.append(bool(self._hub_ref._exec_lock.locked()))
        idx = min(self.screenshot_calls - 1, len(self._frames) - 1)
        return self._frames[idx]


class _FakeCtx:
    def __init__(self, pages: list[_FakePage]) -> None:
        self.pages = pages


class _FakeWSViewer:
    def __init__(self) -> None:
        self.closed = False
        self.sent_json: list[dict[str, Any]] = []
        self.sent_bytes: list[bytes] = []

    async def send_str(self, s: str) -> None:
        self.sent_json.append(json.loads(s))

    async def send_bytes(self, b: bytes) -> None:
        self.sent_bytes.append(b)

    async def close(self, **_kw: Any) -> None:
        self.closed = True


def _make_auth_hub(
    page: _FakePage,
    *,
    display: str | None = ":99",
    sgen: int = 5,
    tgen: int = 2,
    owner: tuple[str, int] = ("main", 111),
) -> tuple[srv.LiveBrowserHub, dict[str, Any]]:
    hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
    hub.engine_mode = "async_hosted"
    hub.ctx = _FakeCtx([page])
    hub.x11_display = display
    hub.session_gen = sgen
    hub.takeover_gen = tgen
    hub.session_owner = owner
    hub.takeover = True
    hub.takeover_owner = owner
    hub.tg.tick_updates = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]
    hub.tg.retire_cards = mock.AsyncMock(return_value=0)  # type: ignore[method-assign]
    base_meta = {
        "_session_gen": sgen,
        "_takeover_gen": tgen,
        "_bot_key": owner[0],
        "_user_id": owner[1],
    }
    return hub, base_meta


class TestPhase2X11XTestPointerAndBurstContractD1ToD8(unittest.TestCase):
    """Phase 2 QA Pre-Flight Contract D1–D8 exhaustive verification."""

    def test_d1_ai_air_gap_forged_human_cmd_rejection_and_compliance_guard(self) -> None:
        # Compliance static check: zero xdotool subprocesses in live_browser_server.py
        server_src = (LIVE_SCRIPTS / "live_browser_server.py").read_text(encoding="utf-8")
        self.assertNotIn("xdotool", server_src)

        async def _scenario() -> None:
            stack = _FakeX11Stack()
            page = _FakePage()
            hub, base_meta = _make_auth_hub(page, display=":99")
            hub.takeover = False
            hub.takeover_owner = None
            hub.ai_allowed_event.set()

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                # 1. AI actions (click coord, click selector, scroll, goto, press, type) -> 0 XTest calls
                await hub.execute_ai_action({"action": "click", "target": "120,240", "notify": False}, auth_ctx={"is_tg": False})
                await hub.execute_ai_action({"action": "click", "target": "#submit-btn", "notify": False}, auth_ctx={"is_tg": False})
                await hub.execute_ai_action({"action": "scroll", "dx": 0, "dy": 300, "notify": False}, auth_ctx={"is_tg": False})
                await hub.execute_ai_action({"action": "goto", "url": "https://app.example/next", "notify": False}, auth_ctx={"is_tg": False})
                await hub.execute_ai_action({"action": "press", "key": "Enter", "notify": False}, auth_ctx={"is_tg": False})
                await hub.execute_ai_action({"action": "type", "text": "hello", "notify": False}, auth_ctx={"is_tg": False})

                self.assertEqual([], stack.events, "AI actions MUST trigger 0 XTest calls even when x11_display=':99'")
                self.assertEqual([], stack.cdll_loads, "AI actions MUST NOT even load libX11/libXtst")
                self.assertIn(("click", 120.0, 240.0, {}), page.mouse.events)
                self.assertIn("#submit-btn", page.locator_clicks)
                self.assertIn(("wheel", 0.0, 300.0), page.mouse.events)

                # 2. SyncLiveBridge -> 0 XTest calls
                sync_events: list[tuple[Any, ...]] = []
                sync_mouse = types.SimpleNamespace(
                    move=lambda x, y: sync_events.append(("move", x, y)),
                    click=lambda x, y, **kw: sync_events.append(("click", x, y, kw)),
                    down=lambda button="left": sync_events.append(("down", button)),
                    up=lambda button="left": sync_events.append(("up", button)),
                    wheel=lambda dx, dy: sync_events.append(("wheel", dx, dy)),
                )
                bridge = object.__new__(live_browser_ctl.SyncLiveBridge)
                bridge.raw_ctx = types.SimpleNamespace(pages=[types.SimpleNamespace(mouse=sync_mouse)])
                bridge.active_idx = 0
                bridge._held_buttons = {}
                bridge._exec_human_sync({"action": "click", "x": 40, "y": 50})
                self.assertEqual([], stack.events, "SyncLiveBridge MUST trigger 0 XTest calls")
                self.assertTrue(len(sync_events) > 0)

                # 3. Forged human commands without valid takeover/auth metadata -> strictly rejected (0 XTest, 0 Playwright)
                page.mouse.events.clear()
                forged_cmds: list[dict[str, Any]] = [
                    {"action": "click", "x": 50, "y": 60},  # missing all auth metadata + takeover=False
                    {"action": "click", "x": 50, "y": 60, "_bot_key": "main", "_user_id": 111},  # missing gens
                    {"action": "click", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2},  # missing owner
                    {"action": "click", "x": 50, "y": 60, **base_meta},  # takeover is False!
                    {"action": "move", "x": 50, "y": 60, **base_meta},  # takeover is False!
                    {"action": "wheel", "dx": 0, "dy": 120, **base_meta},  # takeover is False!
                ]
                for fcmd in forged_cmds:
                    await hub._execute_human_cmd_async(fcmd)

                # Active takeover but forged/mismatched fields
                hub.takeover = True
                hub.takeover_owner = ("main", 111)
                forged_active_cmds: list[dict[str, Any]] = [
                    {"action": "click", "x": 50, "y": 60},
                    {"action": "click", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2, "_bot_key": "sg", "_user_id": 222},
                    {"action": "click", "x": 50, "y": 60, "_session_gen": True, "_takeover_gen": 2, "_bot_key": "main", "_user_id": 111},
                    {"action": "click", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2, "_bot_key": "main", "_user_id": True},
                    {"action": "click", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2, "_bot_key": "", "_user_id": 111},
                    {"action": "click", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 999, "_bot_key": "main", "_user_id": 111},
                    {"action": "mousedown", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2},
                    {"action": "rightclick", "x": 50, "y": 60, "_session_gen": 5, "_takeover_gen": 2},
                ]
                for fcmd in forged_active_cmds:
                    await hub._execute_human_cmd_async(fcmd)

                self.assertEqual([], stack.events, "Forged human cmds MUST trigger 0 XTest calls")
                self.assertEqual([], page.mouse.events, "Forged human cmds MUST trigger 0 Playwright mouse calls")

                # Readonly / denied RBAC on active takeover -> 0 XTest calls
                for bad_role in ("readonly", "denied"):
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    hub.takeover_gen = 2
                    with mock.patch.object(srv, "_check_live_user_role", return_value=bad_role):
                        await hub._execute_human_cmd_async({"action": "click", "x": 50, "y": 60, **base_meta})
                self.assertEqual([], stack.events)
                self.assertEqual([], page.mouse.events)

                await hub._cancel_and_await_bg_tasks()
                await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_d2_viewport_clamping_dpr_invalid_coords_geom_and_wheel_dos_defense(self) -> None:
        async def _scenario() -> None:
            stack = _FakeX11Stack(scr_w=1920, scr_h=1080)
            page = _FakePage()
            hub, base_meta = _make_auth_hub(page, display=":99")

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 1),
            ):
                # 1. Non-finite & illegal coordinate types fail-closed -> 0 XTest, 0 Playwright
                bad_vals: list[Any] = [float("nan"), float("inf"), float("-inf"), None, "100", True, False, [1], {"x": 1}]
                for bad in bad_vals:
                    await hub._execute_human_cmd_async({"action": "click", "x": bad, "y": 50, **base_meta})
                    await hub._execute_human_cmd_async({"action": "move", "x": 50, "y": bad, **base_meta})
                    await hub._execute_human_cmd_async({"action": "mousedown", "x": bad, "y": bad, **base_meta})
                    await hub._execute_human_cmd_async({"action": "mouseup", "x": 50, "y": bad, **base_meta})
                    await hub._execute_human_cmd_async({"action": "rightclick", "x": bad, "y": 50, **base_meta})
                    await hub._execute_human_cmd_async({"action": "wheel", "dx": bad, "dy": 0, **base_meta})
                    await hub._execute_human_cmd_async({"action": "wheel", "dx": 0, "dy": bad, **base_meta})
                self.assertEqual([], stack.events, "Non-finite/invalid coords MUST produce 0 XTest events")
                self.assertEqual([], page.mouse.events, "Non-finite/invalid coords MUST produce 0 Playwright events")

                # 2. Exact DPR (1.0, 1.5, 2.0) & non-zero (mozInnerScreenX, mozInnerScreenY) mapping + clamping
                #    Screen is 1920x1080.
                dpr_cases = [
                    # (dpr, inner_x, inner_y, inner_w, inner_h, css_in, expected_in, css_neg, expected_min, css_big, expected_max)
                    (1.0, 12, 84, 1000, 600, (100, 200), (112, 284), (-50, -90), (12, 84), (9999, 9999), (1011, 683)),
                    (1.5, 10, 80, 1000, 600, (100, 200), (165, 420), (-30, -40), (15, 120), (9999, 9999), (1514, 1019)),
                    # dpr=2.0: origin=(20,160), rect=(2000,1200) -> clipped by X11 root screen (1919, 1079)!
                    (2.0, 10, 80, 1000, 600, (100, 200), (220, 560), (-20, -20), (20, 160), (9999, 9999), (1919, 1079)),
                ]
                for dpr, ix, iy, iw, ih, c_in, exp_in, c_neg, exp_min, c_big, exp_max in dpr_cases:
                    page.geom = {
                        "mozInnerScreenX": ix,
                        "mozInnerScreenY": iy,
                        "innerWidth": iw,
                        "innerHeight": ih,
                        "devicePixelRatio": dpr,
                    }
                    for (cx, cy), (ex, ey) in ((c_in, exp_in), (c_neg, exp_min), (c_big, exp_max)):
                        stack.events.clear()
                        await hub._execute_human_cmd_async({"action": "move", "x": cx, "y": cy, **base_meta})
                        motions = [(e[3], e[4]) for e in stack.events if e[0] == "motion"]
                        self.assertEqual([(ex, ey)], motions, f"DPR={dpr} css=({cx},{cy}) mismatch")
                        # Strictly inside content rect AND inside X11 root screen (never hits chrome/address bar/desktop)
                        ox, oy = int(round(ix * dpr)), int(round(iy * dpr))
                        rw, rh = int(round(iw * dpr)), int(round(ih * dpr))
                        self.assertGreaterEqual(ex, max(0, ox))
                        self.assertGreaterEqual(ey, max(0, oy))
                        self.assertLessEqual(ex, min(1919, ox + rw - 1))
                        self.assertLessEqual(ey, min(1079, oy + rh - 1))

                # 3. Invalid DOM geometry & empty screen intersection -> 0 XTest, graceful fallback to page.mouse
                bad_geoms: list[Any] = [
                    None,
                    lambda: (_ for _ in ()).throw(RuntimeError("eval failed")),
                    {"mozInnerScreenX": 10, "mozInnerScreenY": 80, "innerWidth": 0, "innerHeight": 600, "devicePixelRatio": 1.0},
                    {"mozInnerScreenX": 10, "mozInnerScreenY": 80, "innerWidth": 800, "innerHeight": -5, "devicePixelRatio": 1.0},
                    {"mozInnerScreenX": 10, "mozInnerScreenY": 80, "innerWidth": 800, "innerHeight": 600, "devicePixelRatio": 0},
                    {"mozInnerScreenX": float("nan"), "mozInnerScreenY": 80, "innerWidth": 800, "innerHeight": 600, "devicePixelRatio": 1.0},
                    # Completely off-screen (empty intersection with [0..1919]x[0..1079])
                    {"mozInnerScreenX": 3000, "mozInnerScreenY": 80, "innerWidth": 800, "innerHeight": 600, "devicePixelRatio": 1.0},
                    {"mozInnerScreenX": -900, "mozInnerScreenY": 80, "innerWidth": 800, "innerHeight": 600, "devicePixelRatio": 1.0},
                ]
                for bg in bad_geoms:
                    stack.events.clear()
                    page.mouse.events.clear()
                    page.geom = bg
                    await hub._execute_human_cmd_async({"action": "click", "x": 50, "y": 60, **base_meta})
                    xtest_ptr_events = [e for e in stack.events if e[0] in ("motion", "button")]
                    self.assertEqual([], xtest_ptr_events, f"Invalid/empty geom {bg!r} MUST send 0 XTest pointer events")
                    self.assertTrue(
                        any(e[0] == "click" for e in page.mouse.events),
                        f"Invalid/empty geom {bg!r} MUST gracefully fall back to page.mouse.click",
                    )

                # 4. Wheel DoS defense: dy=1e8 & dx=-1e8 clamped to X11_WHEEL_MAX_STEPS_PER_CMD per axis
                page.geom = {
                    "mozInnerScreenX": 10,
                    "mozInnerScreenY": 80,
                    "innerWidth": 1000,
                    "innerHeight": 600,
                    "devicePixelRatio": 1.0,
                }
                stack.events.clear()
                await hub._execute_human_cmd_async({"action": "wheel", "dx": -1e8, "dy": 1e8, **base_meta})
                down_steps = [e for e in stack.events if e[0] == "button" and e[2] == 5 and e[3] is True]
                left_steps = [e for e in stack.events if e[0] == "button" and e[2] == 6 and e[3] is True]
                self.assertEqual(srv.X11_WHEEL_MAX_STEPS_PER_CMD, len(down_steps))
                self.assertEqual(srv.X11_WHEEL_MAX_STEPS_PER_CMD, len(left_steps))
                # Balanced press/release counts
                all_btn_press = [e for e in stack.events if e[0] == "button" and e[3] is True]
                all_btn_rel = [e for e in stack.events if e[0] == "button" and e[3] is False]
                self.assertEqual(len(all_btn_press), len(all_btn_rel))

                await hub._cancel_and_await_bg_tasks()
                await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_d3_full_action_mapping_and_seven_toctou_races_xtest(self) -> None:
        async def _scenario() -> None:
            stack = _FakeX11Stack(scr_w=1920, scr_h=1080)
            page = _FakePage(
                geom={
                    "mozInnerScreenX": 20,
                    "mozInnerScreenY": 100,
                    "innerWidth": 1000,
                    "innerHeight": 600,
                    "devicePixelRatio": 1.0,
                }
            )
            hub, base_meta = _make_auth_hub(page, display=":99")
            ws_a = _FakeWSViewer()
            ws_b = _FakeWSViewer()
            hub.viewers.update({ws_a, ws_b})  # type: ignore[arg-type]
            hub.viewer_meta[ws_a] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
            hub.viewer_meta[ws_b] = {"bot_key": "sg", "user_id": 222, "role": "admin", "last_frame_seq": 0}

            sleep_calls: list[float] = []
            orig_sleep = asyncio.sleep

            async def _spy_sleep(sec: float) -> None:
                sleep_calls.append(sec)
                await orig_sleep(0)

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv.asyncio, "sleep", side_effect=_spy_sleep),
            ):
                # 1. Full action mapping: move, click(1x, 2x, middle), dblclick, rightclick, mousedown, mouseup, wheel(4/5/6/7)
                await hub._execute_human_cmd_async({"action": "move", "x": 50, "y": 60, **base_meta})
                await hub._execute_human_cmd_async({"action": "click", "x": 10, "y": 20, **base_meta})
                await hub._execute_human_cmd_async({"action": "click", "x": 15, "y": 25, "click_count": 2, **base_meta})
                await hub._execute_human_cmd_async({"action": "click", "x": 18, "y": 28, "button": "middle", **base_meta})
                await hub._execute_human_cmd_async({"action": "dblclick", "x": 30, "y": 40, **base_meta})
                await hub._execute_human_cmd_async({"action": "rightclick", "x": 70, "y": 80, **base_meta})
                await hub._execute_human_cmd_async({"action": "mousedown", "x": 90, "y": 95, "button": "left", **base_meta})
                await hub._execute_human_cmd_async({"action": "mouseup", "x": 95, "y": 100, "button": "left", **base_meta})
                await hub._execute_human_cmd_async({"action": "wheel", "dx": -120, "dy": -120, **base_meta})
                await hub._execute_human_cmd_async({"action": "wheel", "dx": 120, "dy": 120, **base_meta})

                seen_buttons = {e[2] for e in stack.events if e[0] == "button"}
                self.assertEqual({1, 2, 3, 4, 5, 6, 7}, seen_buttons, "All 7 X11 mouse/wheel buttons must be exercised")
                self.assertIn(srv.HUMAN_CLICK_HOLD_DELAY_MS / 1000.0, sleep_calls, "45ms click hold delay must be honored")
                self.assertEqual([], page.mouse.events, "Authenticated XTest actions should not fall back to page.mouse")
                self.assertEqual(set(), hub._x11_buttons_down)

            # 2. All 7 TOCTOU race classes during suspended move / geometry eval
            race_kinds = [
                "takeover_gen_bump",
                "session_gen_bump",
                "takeover_closed",
                "owner_switched",
                "rbac_downgraded",
                "rbac_revoked",
                "page_switched",
                "page_closed",
            ]
            for race_kind in race_kinds:
                for suspend_stage in ("geom", "move"):
                    stack_r = _FakeX11Stack(scr_w=1920, scr_h=1080)
                    page_a = _FakePage("https://app.example/a", "A")
                    page_b = _FakePage("https://app.example/b", "B")
                    hub_r, meta_r = _make_auth_hub(page_a, display=":99", sgen=10, tgen=5, owner=("main", 111))
                    hub_r.ctx = _FakeCtx([page_a, page_b])
                    ws_ra = _FakeWSViewer()
                    ws_rb = _FakeWSViewer()
                    hub_r.viewers.update({ws_ra, ws_rb})  # type: ignore[arg-type]
                    hub_r.viewer_meta[ws_ra] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
                    hub_r.viewer_meta[ws_rb] = {"bot_key": "sg", "user_id": 222, "role": "admin", "last_frame_seq": 0}

                    entered = asyncio.Event()
                    proceed = asyncio.Event()
                    role_map = {("main", 111): "admin", ("sg", 222): "admin"}

                    if suspend_stage == "geom":
                        async def _slow_geom() -> dict[str, Any]:
                            entered.set()
                            await proceed.wait()
                            return {
                                "mozInnerScreenX": 10,
                                "mozInnerScreenY": 80,
                                "innerWidth": 1000,
                                "innerHeight": 600,
                                "devicePixelRatio": 1.0,
                            }
                        page_a.geom = _slow_geom
                    else:
                        orig_move_async = hub_r._x11_pointer.move_async

                        async def _slow_move_async(disp: str | None, sx: int, sy: int, _orig: Any = orig_move_async) -> bool:
                            res = await _orig(disp, sx, sy)
                            entered.set()
                            await proceed.wait()
                            return res

                        hub_r._x11_pointer.move_async = _slow_move_async  # type: ignore[method-assign]

                    with (
                        mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_r.cdll_loader),
                        mock.patch.object(srv, "_check_live_user_role", side_effect=lambda bk, uid: role_map.get((bk, uid), "denied")),
                    ):
                        task = asyncio.create_task(
                            hub_r._execute_human_cmd_async({"action": "click", "x": 100, "y": 120, **meta_r})
                        )
                        await asyncio.wait_for(entered.wait(), timeout=1.0)
                        if race_kind == "takeover_gen_bump":
                            hub_r.takeover_gen += 1
                        elif race_kind == "session_gen_bump":
                            hub_r.session_gen += 1
                        elif race_kind == "takeover_closed":
                            hub_r.takeover = False
                            hub_r.takeover_owner = None
                        elif race_kind == "owner_switched":
                            hub_r.takeover_owner = ("sg", 222)
                        elif race_kind == "rbac_downgraded":
                            role_map[("main", 111)] = "readonly"
                        elif race_kind == "rbac_revoked":
                            role_map[("main", 111)] = "denied"
                        elif race_kind == "page_switched":
                            hub_r.active_tab_index = 1
                        elif race_kind == "page_closed":
                            page_a._closed = True
                        proceed.set()
                        await task

                    btn_events = [e for e in stack_r.events if e[0] == "button"]
                    self.assertEqual(
                        [],
                        btn_events,
                        f"Race {race_kind} during {suspend_stage} MUST emit 0 XTest button events",
                    )
                    self.assertEqual([], page_a.mouse.events, f"Race {race_kind} MUST NOT fall back to page_a.mouse")
                    self.assertEqual([], page_b.mouse.events, f"Race {race_kind} MUST NOT leak click to page_b.mouse")
                    self.assertEqual([], [m for m in ws_rb.sent_json if m.get("type") == "toast"])
                    if race_kind in ("rbac_downgraded", "rbac_revoked"):
                        self.assertEqual([], [m for m in ws_ra.sent_json if m.get("type") == "toast"])
                    await hub_r._cancel_and_await_bg_tasks()
                    await hub_r._x11_pointer.close_async()

            # (g) Illegal button names fail-closed with 0 XTest button-down/press and 0 Playwright mouse calls
            stack_g = _FakeX11Stack()
            page_g = _FakePage()
            hub_g, meta_g = _make_auth_hub(page_g, display=":99")
            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_g.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                for bad_btn in ("bogus", "back", "LEFT", 123, True, ["left"]):
                    for act_name in ("click", "dblclick", "rightclick", "mousedown", "mouseup"):
                        await hub_g._execute_human_cmd_async(
                            {"action": act_name, "x": 50, "y": 60, "button": bad_btn, **meta_g}
                        )
            self.assertEqual([], [e for e in stack_g.events if e[0] in ("motion", "button")])
            self.assertEqual([], page_g.mouse.events)
            await hub_g._cancel_and_await_bg_tasks()
            await hub_g._x11_pointer.close_async()

            await hub._cancel_and_await_bg_tasks()
            await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_d4_x11_button_anti_stuck_cleanup_all_exit_paths(self) -> None:
        async def _scenario() -> None:
            # 1. Multi-button mousedown -> release on takeover off, disconnect, tab switch, auth fail, stop,
            #    closed/None page, AND when releasing first button raises!
            stack = _FakeX11Stack(raise_on_release_buttons={1})
            page1 = _FakePage("https://app.example/1", "P1")
            page2 = _FakePage("https://app.example/2", "P2")
            hub, base_meta = _make_auth_hub(page1, display=":99")
            hub.ctx = _FakeCtx([page1, page2])

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                # Press left(1), middle(2), right(3)
                for b in ("left", "middle", "right"):
                    await hub._execute_human_cmd_async({"action": "mousedown", "x": 50, "y": 60, "button": b, **base_meta})
                self.assertEqual({1, 2, 3}, hub._x11_buttons_down)

                # Even with page closed AND button 1 throwing on release, buttons 2 & 3 MUST still release & set clears!
                page1._closed = True
                stack.events.clear()
                async with hub._exec_lock:
                    await hub._release_held_mouse_buttons_locked(target_page=None)
                self.assertEqual(set(), hub._x11_buttons_down)
                released_btns = [e[2] for e in stack.events if e[0] == "button" and e[3] is False]
                self.assertEqual([2, 3], released_btns, "Exception on btn 1 MUST NOT block releasing btns 2 & 3")
                self.assertTrue(any(e[0] == "flush" for e in stack.events))

            # 2. Clean stack: verify takeover release, disconnect, switch_tab, auth revocation, and _stop_hosted_locked
            stack2 = _FakeX11Stack()
            page_a = _FakePage("https://app.example/a", "A")
            page_b = _FakePage("https://app.example/b", "B")
            hub2, meta2 = _make_auth_hub(page_a, display=":99")
            hub2.ctx = _FakeCtx([page_a, page_b])

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack2.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                # (a) set_takeover(False)
                await hub2._execute_human_cmd_async({"action": "mousedown", "x": 10, "y": 10, "button": "right", **meta2})
                self.assertEqual({3}, hub2._x11_buttons_down)
                stack2.events.clear()
                await hub2.set_takeover(False, emit_bus_event=False)
                self.assertEqual(set(), hub2._x11_buttons_down)
                self.assertIn((3, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])

                # (b) release_takeover_on_disconnect
                ok_tk, _, _, tgen_new = await hub2.set_takeover(True, owner=("main", 111), actor=("main", 111), emit_bus_event=False)
                self.assertTrue(ok_tk)
                meta2["_takeover_gen"] = tgen_new
                await hub2._execute_human_cmd_async({"action": "mousedown", "x": 10, "y": 10, "button": "middle", **meta2})
                self.assertEqual({2}, hub2._x11_buttons_down)
                stack2.events.clear()
                rel_d = await hub2.release_takeover_on_disconnect("main", 111, had_admin_role=True)
                self.assertTrue(rel_d)
                self.assertEqual(set(), hub2._x11_buttons_down)
                self.assertIn((2, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])

                # (c) switch_tab releases held X11 buttons before switching
                ok_tk2, _, _, tgen_new2 = await hub2.set_takeover(True, owner=("main", 111), actor=("main", 111), emit_bus_event=False)
                self.assertTrue(ok_tk2)
                meta2["_takeover_gen"] = tgen_new2
                await hub2._execute_human_cmd_async({"action": "mousedown", "x": 10, "y": 10, "button": "left", **meta2})
                self.assertEqual({1}, hub2._x11_buttons_down)
                stack2.events.clear()
                await hub2._execute_human_cmd_async({"action": "switch_tab", "index": 1, **meta2})
                self.assertEqual(set(), hub2._x11_buttons_down)
                self.assertIn((1, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])

                # (d) click cancelled mid-45ms hold releases button immediately in finally!
                hold_entered = asyncio.Event()
                orig_sleep = asyncio.sleep

                async def _wait_hold(sec: float) -> None:
                    if abs(sec - srv.HUMAN_CLICK_HOLD_DELAY_MS / 1000.0) < 1e-6:
                        hold_entered.set()
                        await orig_sleep(10.0)
                    else:
                        await orig_sleep(sec)

                stack2.events.clear()
                with mock.patch.object(srv.asyncio, "sleep", side_effect=_wait_hold):
                    click_task = asyncio.create_task(
                        hub2._execute_human_cmd_async({"action": "click", "x": 40, "y": 50, "button": "left", **meta2})
                    )
                    await asyncio.wait_for(hold_entered.wait(), timeout=1.0)
                    self.assertIn(1, hub2._x11_buttons_down)
                    click_task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await click_task
                self.assertEqual(set(), hub2._x11_buttons_down, "Cancelled click hold MUST release & clear X11 button")
                self.assertIn((1, True), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])
                self.assertIn((1, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])

                # (e) _stop_hosted_locked releases held X11 buttons even with no pages left, then closes handle
                await hub2._execute_human_cmd_async({"action": "mousedown", "x": 10, "y": 10, "button": "right", **meta2})
                self.assertEqual({3}, hub2._x11_buttons_down)
                hub2.ctx = _FakeCtx([])  # page is None!
                stack2.events.clear()
                await hub2._stop_hosted_locked(notify_finished=False)
                self.assertEqual(set(), hub2._x11_buttons_down)
                self.assertIn((3, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])
                self.assertEqual(set(), stack2.active_handles, "X11 handle MUST be closed after stop")
                self.assertEqual([], stack2.double_closes)

            await hub._cancel_and_await_bg_tasks()
            await hub._x11_pointer.close_async()
            await hub2._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_d5_aarch64_ffi_safety_display_whitelist_serialization_lifecycle_and_offline_fallback(self) -> None:
        # 1. Explicit 64-bit aarch64 FFI argtypes & restype verification
        stack = _FakeX11Stack()
        srv._configure_x11_ffi(stack.x11, stack.xtst)
        self.assertEqual([ctypes.c_char_p], stack.x11.XOpenDisplay.argtypes)
        self.assertIs(ctypes.c_void_p, stack.x11.XOpenDisplay.restype)
        self.assertEqual([ctypes.c_void_p], stack.x11.XCloseDisplay.argtypes)
        self.assertIs(ctypes.c_int, stack.x11.XCloseDisplay.restype)
        self.assertEqual([ctypes.c_void_p], stack.x11.XFlush.argtypes)
        self.assertIs(ctypes.c_int, stack.x11.XFlush.restype)
        self.assertEqual([ctypes.c_void_p], stack.x11.XDefaultScreen.argtypes)
        self.assertIs(ctypes.c_int, stack.x11.XDefaultScreen.restype)
        self.assertEqual([ctypes.c_void_p, ctypes.c_int], stack.x11.XDisplayWidth.argtypes)
        self.assertIs(ctypes.c_int, stack.x11.XDisplayWidth.restype)
        self.assertEqual([ctypes.c_void_p, ctypes.c_int], stack.x11.XDisplayHeight.argtypes)
        self.assertIs(ctypes.c_int, stack.x11.XDisplayHeight.restype)
        self.assertEqual(
            [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
            ],
            stack.xtst.XTestQueryExtension.argtypes,
        )
        self.assertIs(ctypes.c_int, stack.xtst.XTestQueryExtension.restype)
        self.assertEqual(
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong],
            stack.xtst.XTestFakeMotionEvent.argtypes,
        )
        self.assertIs(ctypes.c_int, stack.xtst.XTestFakeMotionEvent.restype)
        self.assertEqual(
            [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong],
            stack.xtst.XTestFakeButtonEvent.argtypes,
        )
        self.assertIs(ctypes.c_int, stack.xtst.XTestFakeButtonEvent.restype)

        # 2. Local display whitelist (Anti-SSRF)
        for valid_d in (":0", ":99", ":1.0", ":12.3"):
            self.assertTrue(srv.is_valid_local_x11_display(valid_d), valid_d)
        for bad_d in ("127.0.0.1:0", "evil.example:0", ":99\nfoo", ":99\n", "", " :99", ":99 ", ":abc", None, 99):
            self.assertFalse(srv.is_valid_local_x11_display(bad_d), repr(bad_d))

        async def _scenario() -> None:
            # 3. Display switch, fault rebuild, idempotent close (0 leaks, 0 double-close), & thread serialization
            stack_ser = _FakeX11Stack(track_concurrency=True, motion_delay_s=0.015)
            eng = srv.X11XTestPointerEngine()
            with mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_ser.cdll_loader):
                # Reject remote SSRF displays with 0 XOpenDisplay calls
                for bad_d in ("127.0.0.1:0", "evil.example:0", ":99\nfoo", ""):
                    self.assertFalse(await eng.move_async(bad_d, 10, 20))
                self.assertEqual([], stack_ser.opened_handles)

                # Parallel calls strictly serialized (max_concurrent_calls == 1)
                results = await asyncio.gather(
                    eng.move_async(":99", 100, 100),
                    eng.move_async(":99", 200, 200),
                    eng.move_async(":99", 300, 300),
                )
                self.assertEqual([True, True, True], results)
                self.assertEqual(1, stack_ser.max_concurrent_calls, "Display* access MUST be strictly serialized")
                self.assertEqual(1, len(stack_ser.opened_handles))

                # Switch display :99 -> :100 closes old handle exactly once before opening new
                self.assertTrue(await eng.move_async(":100", 120, 120))
                self.assertEqual(2, len(stack_ser.opened_handles))
                self.assertEqual(1, len(stack_ser.closed_handles))
                self.assertEqual(stack_ser.opened_handles[0][0], stack_ser.closed_handles[0])

                # Fault rebuild: motion failure closes handle cleanly, subsequent call opens fresh handle
                stack_ser.fail_motion = True
                self.assertFalse(await eng.move_async(":100", 130, 130))
                self.assertEqual(set(), stack_ser.active_handles)
                stack_ser.fail_motion = False
                self.assertTrue(await eng.move_async(":100", 140, 140))
                self.assertEqual(3, len(stack_ser.opened_handles))

                # Repeated close() is strictly idempotent (0 double-close, 0 leaks)
                await eng.close_async()
                await eng.close_async()
                eng.close()
                self.assertEqual(set(), stack_ser.active_handles)
                self.assertEqual(3, len(stack_ser.closed_handles))
                self.assertEqual([], stack_ser.double_closes)

            # 4. Offline fallback invariant: x11_display is None -> 0 CDLL loads, 0 geometry evaluate calls
            page_off = _FakePage()
            hub_off, meta_off = _make_auth_hub(page_off, display=None)
            cdll_spy = mock.MagicMock(side_effect=AssertionError("CDLL must NOT be called when x11_display is None"))
            with (
                mock.patch.object(srv.ctypes, "CDLL", cdll_spy),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                await hub_off._execute_human_cmd_async({"action": "click", "x": 50, "y": 60, **meta_off})
            self.assertEqual(0, cdll_spy.call_count)
            self.assertFalse(any("mozInnerScreenX" in e for e in page_off.eval_calls))
            self.assertTrue(any(e[0] == "click" for e in page_off.mouse.events))
            await hub_off._cancel_and_await_bg_tasks()

            # 5. Graceful fallback on CDLL OSError / XOpenDisplay NULL / XTestQueryExtension False / runtime failure
            for mode in ("cdll_oserror", "open_null", "no_xtest_ext", "motion_fail"):
                page_fb = _FakePage()
                hub_fb, meta_fb = _make_auth_hub(page_fb, display=":99")
                if mode == "cdll_oserror":
                    cm_patch = mock.patch.object(srv.ctypes, "CDLL", side_effect=OSError("libXtst missing"))
                    st_fb = None
                else:
                    st_fb = _FakeX11Stack(
                        open_returns_null=(mode == "open_null"),
                        xtest_supported=(mode != "no_xtest_ext"),
                        fail_motion=(mode == "motion_fail"),
                    )
                    cm_patch = mock.patch.object(srv.ctypes, "CDLL", side_effect=st_fb.cdll_loader)

                with (
                    cm_patch,
                    mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                ):
                    await hub_fb._execute_human_cmd_async({"action": "click", "x": 75, "y": 85, **meta_fb})
                self.assertTrue(
                    any(e[0] == "click" for e in page_fb.mouse.events),
                    f"Failure mode {mode} MUST gracefully fall back to page.mouse.click",
                )
                if st_fb is not None:
                    self.assertEqual(set(), st_fb.active_handles, f"Failure mode {mode} MUST NOT leak Display*")
                    self.assertEqual([], st_fb.double_closes)
                await hub_fb._cancel_and_await_bg_tasks()
                await hub_fb._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_d6_post_click_burst_bounded_single_flight_cancellation_and_low_monotonic_clock(self) -> None:
        async def _scenario() -> None:
            # 1. Single-flight renewal on 10 rapid clicks + bounded frame cap + low positive monotonic clock (0.05)
            #    + lock-free capture + ZERO tg.tick_updates during burst!
            frames = [f"BURST_FRAME_{i}".encode("ascii") for i in range(40)]
            page = _FakePage(frames=frames)
            hub, meta = _make_auth_hub(page, display=None, sgen=11, tgen=3, owner=("main", 111))
            page._hub_ref = hub
            ws_a = _FakeWSViewer()
            ws_b = _FakeWSViewer()
            hub.viewers.update({ws_a, ws_b})  # type: ignore[arg-type]
            hub.viewer_meta[ws_a] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
            hub.viewer_meta[ws_b] = {"bot_key": "sg", "user_id": 222, "role": "admin", "last_frame_seq": 0}

            tg_ticks: list[bool] = []

            async def _spy_tick(finished: bool = False, force: bool = False, **_kw: Any) -> None:
                tg_ticks.append(bool(force))

            hub.tg.tick_updates = _spy_tick  # type: ignore[method-assign]

            fake_clock = [0.05]  # Low positive monotonic baseline (fresh CI host uptime!)

            def _mono() -> float:
                fake_clock[0] += 0.002
                return fake_clock[0]

            with (
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv.time, "monotonic", side_effect=_mono),
                mock.patch.object(srv, "POST_CLICK_BURST_INTERVAL_SECONDS", 0.008),
                mock.patch.object(srv, "POST_CLICK_BURST_DURATION_SECONDS", 2.4),
                mock.patch.object(srv, "POST_CLICK_BURST_MAX_FRAMES", 4),
                mock.patch.object(srv, "SETTLE_RECAPTURE_DELAY_SECONDS", 5.0),  # keep settle out of burst window
            ):
                # Trigger 10 rapid discrete actions: MUST reuse the SAME single-flight burst task!
                burst_task_ids: set[int] = set()
                for i in range(10):
                    act = ("click", "dblclick", "rightclick", "mouseup")[i % 4]
                    await hub._execute_human_cmd_async({"action": act, "x": 40 + i, "y": 50 + i, **meta})
                    self.assertIsNotNone(hub._burst_task)
                    burst_task_ids.add(id(hub._burst_task))
                self.assertEqual(1, len(burst_task_ids), "10 rapid clicks MUST NOT spawn multiple concurrent burst tasks")

                # Drain the 10 per-action tg.tick_updates tasks scheduled synchronously at action end,
                # then verify the burst loop itself triggers ZERO additional tg.tick_updates calls!
                await asyncio.sleep(0)
                tg_count_before_burst = len(tg_ticks)
                self.assertEqual(10, tg_count_before_burst)
                frames_before_burst = len(ws_a.sent_bytes)
                # Let bounded 4-frame burst finish naturally
                burst_ref = hub._burst_task
                self.assertIsNotNone(burst_ref)
                await asyncio.wait_for(burst_ref, timeout=1.0)

                burst_frames_delivered = len(ws_a.sent_bytes) - frames_before_burst
                self.assertEqual(4, burst_frames_delivered, "Burst MUST deliver exactly bounded max frames to WS viewer A")
                self.assertEqual([], ws_b.sent_bytes, "User B MUST receive 0 burst frames")
                self.assertEqual(
                    tg_count_before_burst,
                    len(tg_ticks),
                    "Burst MUST NOT call tg.tick_updates at 8-10 FPS",
                )
                self.assertTrue(
                    all(not locked for locked in page.lock_states_during_screenshot),
                    "Burst captures MUST NEVER hold _exec_lock",
                )

            # 2. Immediate convergence/cancellation on: session_gen, takeover_gen, _tab_select_rev,
            #    takeover=False, all viewers disconnected, owner switch, RBAC downgrade/revoke
            cancel_scenarios = [
                "session_gen",
                "takeover_gen",
                "tab_rev",
                "takeover_off",
                "no_viewers",
                "owner_switch",
                "rbac_revoked",
            ]
            for scen in cancel_scenarios:
                p_c = _FakePage(frames=[f"F_{i}".encode("ascii") for i in range(50)])
                hub_c, meta_c = _make_auth_hub(p_c, display=None, sgen=20, tgen=4, owner=("main", 111))
                ws_ca = _FakeWSViewer()
                ws_cb = _FakeWSViewer()
                hub_c.viewers.update({ws_ca, ws_cb})  # type: ignore[arg-type]
                hub_c.viewer_meta[ws_ca] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
                hub_c.viewer_meta[ws_cb] = {"bot_key": "sg", "user_id": 222, "role": "admin", "last_frame_seq": 0}
                roles_c = {("main", 111): "admin", ("sg", 222): "admin"}

                with (
                    mock.patch.object(srv, "_check_live_user_role", side_effect=lambda bk, uid: roles_c.get((bk, uid), "denied")),
                    mock.patch.object(srv, "POST_CLICK_BURST_INTERVAL_SECONDS", 0.015),
                    mock.patch.object(srv, "POST_CLICK_BURST_DURATION_SECONDS", 3.0),
                    mock.patch.object(srv, "POST_CLICK_BURST_MAX_FRAMES", 30),
                    mock.patch.object(srv, "SETTLE_RECAPTURE_DELAY_SECONDS", 5.0),
                ):
                    task_b = hub_c._schedule_post_click_burst(20, 4, hub_c._tab_select_rev, ("main", 111))
                    self.assertIsNotNone(task_b)
                    assert task_b is not None
                    if scen == "session_gen":
                        hub_c.session_gen += 1
                    elif scen == "takeover_gen":
                        hub_c.takeover_gen += 1
                    elif scen == "tab_rev":
                        hub_c._tab_select_rev += 1
                    elif scen == "takeover_off":
                        hub_c.takeover = False
                    elif scen == "no_viewers":
                        hub_c.viewers.clear()
                    elif scen == "owner_switch":
                        hub_c.takeover_owner = ("sg", 222)
                        hub_c.session_owner = ("sg", 222)
                    elif scen == "rbac_revoked":
                        roles_c[("main", 111)] = "denied"

                    await asyncio.wait_for(task_b, timeout=1.0)
                    self.assertEqual(0, p_c.screenshot_calls, f"Scenario {scen} MUST abort before capturing any frame")
                    self.assertEqual([], ws_cb.sent_bytes, f"Scenario {scen} MUST leak 0 frames to User B")

                await hub_c._cancel_and_await_bg_tasks()
                self.assertEqual(set(), hub_c._bg_tasks, f"Scenario {scen}: 0 pending bg tasks after cleanup")
                self.assertIsNone(hub_c._burst_task)

            await hub._cancel_and_await_bg_tasks()
            self.assertEqual(set(), hub._bg_tasks)

            # 3. Burst deadline expiry auto-convergence (stops before max_frames when duration elapses)
            p_dl = _FakePage(frames=[f"DL_{i}".encode("ascii") for i in range(20)])
            hub_dl, _ = _make_auth_hub(p_dl, display=None, sgen=25, tgen=5, owner=("main", 111))
            ws_dl = _FakeWSViewer()
            hub_dl.viewers.add(ws_dl)  # type: ignore[arg-type]
            hub_dl.viewer_meta[ws_dl] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
            dl_clock = [10.0]
            orig_dl_screenshot = p_dl.screenshot

            async def _deadline_screenshot(**kw: Any) -> bytes:
                frame = await orig_dl_screenshot(**kw)
                if p_dl.screenshot_calls >= 2:
                    dl_clock[0] += 1.0  # expire deadline after 2 captured burst frames
                return frame

            p_dl.screenshot = _deadline_screenshot  # type: ignore[method-assign]

            def _dl_mono() -> float:
                dl_clock[0] += 0.001
                return dl_clock[0]

            with (
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv.time, "monotonic", side_effect=_dl_mono),
                mock.patch.object(srv, "POST_CLICK_BURST_INTERVAL_SECONDS", 0.005),
                mock.patch.object(srv, "POST_CLICK_BURST_DURATION_SECONDS", 0.5),
                mock.patch.object(srv, "POST_CLICK_BURST_MAX_FRAMES", 20),
                mock.patch.object(srv, "SETTLE_RECAPTURE_DELAY_SECONDS", 5.0),
            ):
                task_dl = hub_dl._schedule_post_click_burst(25, 5, hub_dl._tab_select_rev, ("main", 111))
                self.assertIsNotNone(task_dl)
                assert task_dl is not None
                await asyncio.wait_for(task_dl, timeout=1.0)
                self.assertEqual(2, len(ws_dl.sent_bytes), "Burst MUST converge on deadline after 2 frames (< max_frames=20)")
                self.assertIsNone(hub_dl._burst_task)
            await hub_dl._cancel_and_await_bg_tasks()
            self.assertEqual(set(), hub_dl._bg_tasks)

            # 4. Non-burst actions (move, mousedown, wheel) MUST trigger 0 burst tasks
            p_nb = _FakePage(frames=[b"NB_0", b"NB_1", b"NB_2"])
            hub_nb, meta_nb = _make_auth_hub(p_nb, display=None, sgen=26, tgen=6, owner=("main", 111))
            ws_nb = _FakeWSViewer()
            hub_nb.viewers.add(ws_nb)  # type: ignore[arg-type]
            hub_nb.viewer_meta[ws_nb] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
            with (
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "SETTLE_RECAPTURE_DELAY_SECONDS", 5.0),
            ):
                await hub_nb._execute_human_cmd_async({"action": "move", "x": 20, "y": 30, **meta_nb})
                self.assertIsNone(hub_nb._burst_task, "move MUST NOT schedule post-click burst")
                await hub_nb._execute_human_cmd_async({"action": "mousedown", "x": 20, "y": 30, "button": "left", **meta_nb})
                self.assertIsNone(hub_nb._burst_task, "mousedown MUST NOT schedule post-click burst")
                await hub_nb._execute_human_cmd_async({"action": "wheel", "dx": 0, "dy": 120, **meta_nb})
                self.assertIsNone(hub_nb._burst_task, "wheel MUST NOT schedule post-click burst")
            await hub_nb._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_d7_normalize_named_owner_15_malformed_matrix(self) -> None:
        malformed_cases: list[Any] = [
            None,
            (),
            ("main",),
            ("main", 111, "extra"),
            ["main", 111],
            ("", 111),
            ("   ", 111),
            ("\t\n", 111),
            (None, 111),
            (123, 111),
            (b"main", 111),
            ("main", None),
            ("main", True),
            ("main", False),
            ("main", 0),
            ("main", -1),
            ("main", 111.0),
            ("main", 111.5),
            ("main", "111"),
            ("main", float("nan")),
            ("main", float("inf")),
        ]
        self.assertGreaterEqual(len(malformed_cases), 15)
        for bad in malformed_cases:
            self.assertIsNone(
                srv.LiveBrowserHub._normalize_named_owner(bad),
                f"Malformed owner {bad!r} MUST return None",
            )
        self.assertEqual(("main", 111), srv.LiveBrowserHub._normalize_named_owner(("main", 111)))
        self.assertEqual(("main", 111), srv.LiveBrowserHub._normalize_named_owner(("  main\t ", 111)))

    def test_d8_sanitized_x11_logs_and_zero_crosstalk_toast(self) -> None:
        async def _scenario() -> None:
            secret_msg = "X11 boom at /var/private/.secrets/vault.key https://priv.example/cb?token=SECRET_D8_777"
            page = _FakePage()
            page.geom = lambda: (_ for _ in ()).throw(RuntimeError(secret_msg))

            async def _boom_click(*_a: Any, **_kw: Any) -> None:
                raise RuntimeError(secret_msg)

            page.mouse.click = _boom_click  # type: ignore[method-assign]
            hub, meta = _make_auth_hub(page, display=":99", sgen=30, tgen=6, owner=("main", 111))
            ws_a = _FakeWSViewer()
            ws_b = _FakeWSViewer()
            hub.viewers.update({ws_a, ws_b})  # type: ignore[arg-type]
            hub.viewer_meta[ws_a] = {"bot_key": "main", "user_id": 111, "role": "admin", "last_frame_seq": 0}
            hub.viewer_meta[ws_b] = {"bot_key": "sg", "user_id": 222, "role": "admin", "last_frame_seq": 0}

            with (
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                self.assertLogs(srv.log.name, level="DEBUG") as log_cap,
            ):
                await hub._execute_human_cmd_async({"action": "click", "x": 50, "y": 60, **meta})

            joined_logs = "\n".join(log_cap.output)
            for needle in ("SECRET_D8_777", "/var/private/.secrets", "priv.example"):
                self.assertNotIn(needle, joined_logs, "Sanitized logs MUST NEVER leak secret/path/URL")
            toasts_a = [m for m in ws_a.sent_json if m.get("type") == "toast"]
            toasts_b = [m for m in ws_b.sent_json if m.get("type") == "toast"]
            self.assertEqual(1, len(toasts_a))
            self.assertEqual([], toasts_b, "User B MUST receive 0 failure toasts")
            for needle in ("SECRET_D8_777", "/var/private/.secrets", "priv.example"):
                self.assertNotIn(needle, toasts_a[0]["message"])

            # Revoked owner during failure -> 0 toasts to both A and B
            ws_a.sent_json.clear()
            ws_b.sent_json.clear()
            roles = {("main", 111): "admin", ("sg", 222): "admin"}

            async def _revoke_then_boom(*_a: Any, **_kw: Any) -> None:
                roles[("main", 111)] = "denied"
                raise RuntimeError(secret_msg)

            page.mouse.click = _revoke_then_boom  # type: ignore[method-assign]
            with mock.patch.object(srv, "_check_live_user_role", side_effect=lambda bk, uid: roles.get((bk, uid), "denied")):
                await hub._execute_human_cmd_async({"action": "click", "x": 50, "y": 60, **meta})
            self.assertEqual([], [m for m in ws_a.sent_json if m.get("type") == "toast"])
            self.assertEqual([], [m for m in ws_b.sent_json if m.get("type") == "toast"])

            await hub._cancel_and_await_bg_tasks()
            await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_p0_1_forged_mouseup_rejected_when_x11_button_held(self) -> None:
        async def _scenario() -> None:
            stack = _FakeX11Stack()
            page = _FakePage()
            hub, base_meta = _make_auth_hub(page, display=":99")

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
            ):
                # Press left button legitimately via X11
                await hub._execute_human_cmd_async(
                    {"action": "mousedown", "x": 40, "y": 50, "button": "left", **base_meta}
                )
                self.assertEqual({1}, hub._x11_buttons_down)
                stack.events.clear()
                page.mouse.events.clear()

                # 1. Forged mouseup without auth metadata while x11_display=":99" and left button held
                await hub._execute_human_cmd_async({"action": "mouseup", "x": 10, "y": 10, "button": "left"})
                self.assertEqual([], stack.events, "Forged mouseup MUST trigger 0 XTest calls")
                self.assertEqual([], page.mouse.events, "Forged mouseup MUST trigger 0 Playwright calls")
                self.assertEqual({1}, hub._x11_buttons_down, "_x11_buttons_down MUST remain {1}")

                # 2. Even if x11_display became None, was_held_x11=True MUST still enforce strict auth
                hub.x11_display = None
                await hub._execute_human_cmd_async({"action": "mouseup", "x": 10, "y": 10, "button": "left"})
                self.assertEqual([], stack.events)
                self.assertEqual([], page.mouse.events)
                self.assertEqual({1}, hub._x11_buttons_down)

                # 3. Clean release via authenticated mouseup restores empty state
                hub.x11_display = ":99"
                await hub._execute_human_cmd_async(
                    {"action": "mouseup", "x": 45, "y": 55, "button": "left", **base_meta}
                )
                self.assertEqual(set(), hub._x11_buttons_down)
                self.assertIn((1, False), [(e[2], e[3]) for e in stack.events if e[0] == "button"])

                # 4. Offline compatibility: x11_display=None & not was_held_x11 still allows legacy Playwright mouseup
                page_off = _FakePage()
                hub_off, _ = _make_auth_hub(page_off, display=None)
                await hub_off._execute_human_cmd_async({"action": "mouseup", "x": 12, "y": 34, "button": "left"})
                self.assertIn(("up", "left"), page_off.mouse.events)
                await hub_off._cancel_and_await_bg_tasks()

            await hub._cancel_and_await_bg_tasks()
            await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_p0_2_mouseup_cancellation_releases_in_finally_and_failed_release_retains_for_takeover_off(self) -> None:
        async def _scenario() -> None:
            # 1. Cancel authenticated mouseup while page.evaluate (and while move_async) is suspended
            for cancel_stage in ("evaluate", "move"):
                stack = _FakeX11Stack()
                page = _FakePage()
                hub, meta = _make_auth_hub(page, display=":99")

                with (
                    mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                    mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                ):
                    await hub._execute_human_cmd_async(
                        {"action": "mousedown", "x": 30, "y": 40, "button": "left", **meta}
                    )
                    self.assertEqual({1}, hub._x11_buttons_down)
                    stack.events.clear()

                    entered = asyncio.Event()
                    block = asyncio.Event()

                    if cancel_stage == "evaluate":
                        async def _hanging_geom() -> dict[str, Any]:
                            entered.set()
                            await block.wait()
                            return {
                                "mozInnerScreenX": 10,
                                "mozInnerScreenY": 80,
                                "innerWidth": 1280,
                                "innerHeight": 800,
                                "devicePixelRatio": 1.0,
                            }
                        page.geom = _hanging_geom
                    else:
                        async def _hanging_move(disp: str | None, sx: int, sy: int) -> bool:
                            entered.set()
                            await block.wait()
                            return True

                        hub._x11_pointer.move_async = _hanging_move  # type: ignore[method-assign]

                    up_task = asyncio.create_task(
                        hub._execute_human_cmd_async({"action": "mouseup", "x": 60, "y": 70, "button": "left", **meta})
                    )
                    await asyncio.wait_for(entered.wait(), timeout=1.0)
                    # Button MUST still be tracked before release completes!
                    self.assertEqual({1}, hub._x11_buttons_down)
                    up_task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await up_task

                    self.assertEqual(
                        set(),
                        hub._x11_buttons_down,
                        f"Cancelled mouseup ({cancel_stage}) MUST release button in finally and clear set",
                    )
                    self.assertIn(
                        (1, False),
                        [(e[2], e[3]) for e in stack.events if e[0] == "button"],
                        f"Cancelled mouseup ({cancel_stage}) MUST send X11 release (is_press=False)",
                    )

                await hub._cancel_and_await_bg_tasks()
                await hub._x11_pointer.close_async()

            # 2. Failed/raising release_button_async keeps button in _x11_buttons_down so set_takeover(False) cleans it up
            for fail_mode in ("raise", "return_false"):
                stack2 = _FakeX11Stack()
                page2 = _FakePage()
                hub2, meta2 = _make_auth_hub(page2, display=":99")

                with (
                    mock.patch.object(srv.ctypes, "CDLL", side_effect=stack2.cdll_loader),
                    mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                ):
                    await hub2._execute_human_cmd_async(
                        {"action": "mousedown", "x": 30, "y": 40, "button": "left", **meta2}
                    )
                    self.assertEqual({1}, hub2._x11_buttons_down)
                    stack2.events.clear()

                    orig_rel = hub2._x11_pointer.release_button_async
                    should_fail = [True]

                    async def _flaky_rel(
                        disp: str | None,
                        btn: int,
                        _orig: Any = orig_rel,
                        _flag: list[bool] = should_fail,
                        _mode: str = fail_mode,
                    ) -> bool:
                        if _flag[0]:
                            _flag[0] = False
                            if _mode == "raise":
                                raise RuntimeError("transient release error")
                            return False
                        return await _orig(disp, btn)

                    hub2._x11_pointer.release_button_async = _flaky_rel  # type: ignore[method-assign]
                    await hub2._execute_human_cmd_async(
                        {"action": "mouseup", "x": 60, "y": 70, "button": "left", **meta2}
                    )
                    # Button MUST remain tracked because release did not succeed!
                    self.assertEqual({1}, hub2._x11_buttons_down, f"{fail_mode}: button MUST stay in _x11_buttons_down")

                    # Fallback cleanup via set_takeover(False) releases it cleanly
                    await hub2.set_takeover(False, emit_bus_event=False)
                    self.assertEqual(set(), hub2._x11_buttons_down)
                    self.assertIn((1, False), [(e[2], e[3]) for e in stack2.events if e[0] == "button"])

                await hub2._cancel_and_await_bg_tasks()
                await hub2._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_p0_3_stop_hosted_waits_for_in_flight_click_and_mousedown_zero_handle_leak(self) -> None:
        async def _scenario() -> None:
            for act_name in ("click", "mousedown"):
                stack = _FakeX11Stack()
                page = _FakePage()
                hub, meta = _make_auth_hub(page, display=":99")

                btn_entered = asyncio.Event()
                btn_proceed = asyncio.Event()
                orig_button_async = hub._x11_pointer.button_async

                async def _blocking_button_async(
                    disp: str | None,
                    btn_num: int,
                    is_press: bool,
                    _orig: Any = orig_button_async,
                    _entered: asyncio.Event = btn_entered,
                    _proceed: asyncio.Event = btn_proceed,
                ) -> bool:
                    if is_press:
                        _entered.set()
                        await _proceed.wait()
                    return await _orig(disp, btn_num, is_press)

                hub._x11_pointer.button_async = _blocking_button_async  # type: ignore[method-assign]

                with (
                    mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                    mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                    mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 5),
                ):
                    act_task = asyncio.create_task(
                        hub._execute_human_cmd_async(
                            {"action": act_name, "x": 50, "y": 60, "button": "left", **meta}
                        )
                    )
                    await asyncio.wait_for(btn_entered.wait(), timeout=1.0)
                    # At this moment: _exec_lock is held, _x11_buttons_down is STILL empty!
                    self.assertTrue(hub._exec_lock.locked())
                    self.assertEqual(set(), hub._x11_buttons_down)

                    # Concurrently invoke _stop_hosted_locked while action is suspended in button_async(True)
                    stop_task = asyncio.create_task(hub._stop_hosted_locked(notify_finished=False))
                    # Yield so _stop_hosted_locked reaches Step 2 and blocks on _exec_lock
                    await asyncio.sleep(0.02)
                    self.assertFalse(
                        stop_task.done(),
                        f"{act_name}: _stop_hosted_locked MUST wait on _exec_lock barrier before closing Display*",
                    )

                    # Let in-flight button_async(True) finish
                    btn_proceed.set()
                    await asyncio.wait_for(asyncio.gather(act_task, stop_task), timeout=2.0)

                self.assertEqual(set(), hub._x11_buttons_down, f"{act_name}: _x11_buttons_down MUST be empty")
                self.assertIn(
                    (1, False),
                    [(e[2], e[3]) for e in stack.events if e[0] == "button"],
                    f"{act_name}: pressed X11 button MUST be released before shutdown completes",
                )
                self.assertGreaterEqual(len(stack.opened_handles), 1)
                self.assertEqual(
                    len(stack.opened_handles),
                    len(stack.closed_handles),
                    f"{act_name}: every opened Display* handle MUST be closed",
                )
                self.assertEqual(set(), stack.active_handles, f"{act_name}: 0 leaked Display* handles")
                self.assertEqual([], stack.double_closes, f"{act_name}: 0 double-closes")
                await hub._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_p1_1_overflow_clamping_non_ascii_display_and_x11_button_fail_fallback(self) -> None:
        # 1. _parse_finite_coord rejects huge integers that raise OverflowError in float()
        self.assertIsNone(srv._parse_finite_coord(10**400))
        self.assertIsNone(srv._parse_finite_coord(-(10**400)))

        # 2. _compute_clamped_x11_coords gracefully clamps huge finite coords without OverflowError
        geom_dpr2 = {
            "mozInnerScreenX": 10,
            "mozInnerScreenY": 80,
            "innerWidth": 1000,
            "innerHeight": 600,
            "devicePixelRatio": 2.0,
        }
        self.assertEqual((1919, 1079), srv._compute_clamped_x11_coords(geom_dpr2, 1e308, 1e308, 1920, 1080))
        self.assertEqual((20, 160), srv._compute_clamped_x11_coords(geom_dpr2, -1e308, -1e308, 1920, 1080))

        # Partial off-screen viewport (inner_x < 0) with huge/normal/zero coordinates
        geom_neg = {
            "mozInnerScreenX": -100,
            "mozInnerScreenY": -50,
            "innerWidth": 1000,
            "innerHeight": 600,
            "devicePixelRatio": 1.0,
        }
        self.assertEqual((0, 0), srv._compute_clamped_x11_coords(geom_neg, 0.0, 0.0, 1920, 1080))
        self.assertEqual((50, 50), srv._compute_clamped_x11_coords(geom_neg, 150.0, 100.0, 1920, 1080))
        self.assertEqual((899, 549), srv._compute_clamped_x11_coords(geom_neg, 1e308, 1e308, 1920, 1080))

        # Huge geometry values that overflow `inner_* * dpr` safely return None (no OverflowError)
        for bad_geom in (
            {"mozInnerScreenX": 1e308, "mozInnerScreenY": 0, "innerWidth": 1000, "innerHeight": 600, "devicePixelRatio": 2.0},
            {"mozInnerScreenX": 0, "mozInnerScreenY": 0, "innerWidth": 1e308, "innerHeight": 600, "devicePixelRatio": 2.0},
            {"mozInnerScreenX": 0, "mozInnerScreenY": 1e308, "innerWidth": 1000, "innerHeight": 600, "devicePixelRatio": 2.0},
            {"mozInnerScreenX": 0, "mozInnerScreenY": 0, "innerWidth": 1000, "innerHeight": 1e308, "devicePixelRatio": 2.0},
        ):
            self.assertIsNone(srv._compute_clamped_x11_coords(bad_geom, 10.0, 20.0, 1920, 1080))

        # 3. Non-ASCII Unicode digits rejected by local X11 display whitelist
        for bad_unicode_disp in (":\u0669\u0669", ":\u0661.\u0660", ":\uff19\uff19"):
            self.assertFalse(srv.is_valid_local_x11_display(bad_unicode_disp), repr(bad_unicode_disp))

        # 4. Exercise _FakeX11Stack.fail_button_on_calls for click (idx=0 fallback) & dblclick (idx=1 abort, 0 dup click)
        async def _scenario() -> None:
            # (a) click fails on call #1 (idx=0 press) -> graceful fallback to exactly 1 Playwright click
            stack_c = _FakeX11Stack(fail_button_on_calls={1})
            page_c = _FakePage()
            hub_c, meta_c = _make_auth_hub(page_c, display=":99")
            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_c.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 1),
            ):
                await hub_c._execute_human_cmd_async({"action": "click", "x": 60, "y": 70, **meta_c})
            pw_clicks = [e for e in page_c.mouse.events if e[0] == "click"]
            self.assertEqual(1, len(pw_clicks), "idx=0 button_async(True) failure MUST fall back to 1 Playwright click")
            self.assertEqual(set(), stack_c.active_handles)
            self.assertEqual([], stack_c.double_closes)
            await hub_c._cancel_and_await_bg_tasks()
            await hub_c._x11_pointer.close_async()

            # (b) dblclick fails on call #3 (idx=1 second press, after call #1 press & #2 release) -> abort, 0 PW clicks!
            stack_d = _FakeX11Stack(fail_button_on_calls={3})
            page_d = _FakePage()
            hub_d, meta_d = _make_auth_hub(page_d, display=":99")
            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_d.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 1),
                mock.patch.object(srv, "HUMAN_DBLCLICK_GAP_MS", 1),
            ):
                await hub_d._execute_human_cmd_async({"action": "dblclick", "x": 60, "y": 70, **meta_d})
            self.assertEqual(
                [],
                [e for e in page_d.mouse.events if e[0] in ("click", "dblclick")],
                "idx=1 button_async(True) failure on dblclick MUST abort with 0 duplicate Playwright clicks",
            )
            self.assertEqual(set(), hub_d._x11_buttons_down)
            self.assertEqual(set(), stack_d.active_handles)
            self.assertEqual([], stack_d.double_closes)
            await hub_d._cancel_and_await_bg_tasks()
            await hub_d._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_xvfb_virtual_display_size_compute_validate_and_scoped_launch_injection(self) -> None:
        # 1. Strict WxHx24 format validation
        for valid_sz, expected in (
            ("1920x1080x24", (1920, 1080, 24)),
            ("2560x1600x24", (2560, 1600, 24)),
            ("3840x2160x24", (3840, 2160, 24)),
            ("64x64x24", (64, 64, 24)),
        ):
            self.assertEqual(expected, srv.parse_virtual_display_size(valid_sz), valid_sz)

        for bad_sz in (
            None,
            "",
            "1x1x24",
            "63x1080x24",
            "1920x63x24",
            "1920x1080",
            "1920x1080x16",
            "1920x1080x32",
            "0x1080x24",
            "99999x99999x24",
            "1920x1080x24\nfoo",
            " 1920x1080x24 ",
            "1920x1080x24;rm -rf /",
            ":1",
            "１９２０x１０８０x24",
        ):
            self.assertIsNone(srv.parse_virtual_display_size(bad_sz), repr(bad_sz))

        # 2. Default size, small window, large window auto-expansion, cap, and operator override
        default_sz = srv.compute_virtual_display_size()
        parsed_def = srv.parse_virtual_display_size(default_sz)
        self.assertIsNotNone(parsed_def)
        assert parsed_def is not None
        self.assertGreaterEqual(parsed_def[0], 1920)
        self.assertGreaterEqual(parsed_def[1], 1080)
        self.assertEqual(24, parsed_def[2])
        self.assertEqual(default_sz, srv.compute_virtual_display_size((1280, 800)))
        self.assertEqual("2960x1740x24", srv.compute_virtual_display_size((2800, 1500)))
        self.assertEqual("4000x2400x24", srv.compute_virtual_display_size([3840, 2160]))
        self.assertEqual(
            f"{srv.X11_MAX_VIRTUAL_WIDTH}x{srv.X11_MAX_VIRTUAL_HEIGHT}x24",
            srv.compute_virtual_display_size((99999, 99999)),
        )
        # Operator override honored when larger and valid; ignored when degenerate/malformed
        self.assertEqual("3840x2160x24", srv.compute_virtual_display_size((1280, 800), base_env_value="3840x2160x24"))
        self.assertEqual(default_sz, srv.compute_virtual_display_size((1280, 800), base_env_value="1x1x24"))
        self.assertEqual(default_sz, srv.compute_virtual_display_size((1280, 800), base_env_value="invalid;cmd"))
        self.assertEqual(default_sz, srv.compute_virtual_display_size((True, 1500)))

        # 3. Scoped env injection during start_hosted + startup screen probe + env restoration on success & failure
        async def _scenario() -> None:
            with tempfile.TemporaryDirectory(prefix="agy-x11-vd-test-") as td:
                td_path = Path(td)
                seen_vd_envs: list[str | None] = []
                seen_kwargs_envs: list[dict[str, Any]] = []
                fail_enter = [False]

                class _FakeStartCM:
                    def __init__(self, **kw: Any) -> None:
                        seen_kwargs_envs.append(dict(kw.get("env") or {}))
                        self._vd = types.SimpleNamespace(_display=9)

                    async def __aenter__(self) -> Any:
                        seen_vd_envs.append(os.environ.get(srv.X11_VIRTUAL_DISPLAY_ENV))
                        if fail_enter[0]:
                            raise RuntimeError("simulated launch failure")
                        vd_ref = self._vd

                        async def _close() -> None:
                            _ = vd_ref

                        page = _FakePage("https://app.example/start", "Start")
                        ctx = types.SimpleNamespace(
                            pages=[page],
                            on=lambda _ev, _cb: None,
                            close=_close,
                        )
                        return ctx

                    async def __aexit__(self, *_a: Any) -> None:
                        return None

                fake_mod = types.ModuleType("camoufox.async_api")
                fake_mod.AsyncCamoufox = _FakeStartCM  # type: ignore[attr-defined]
                fake_pkg = types.ModuleType("camoufox")
                fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

                stack = _FakeX11Stack(scr_w=2960, scr_h=1740)
                spec = {
                    "name": "vd-test",
                    "profile_dir": td_path / "vd-test",
                    "lock_path": td_path / "vd-test.lock",
                    "persistent": True,
                    "pinned": False,
                    "pinned_verified": False,
                    "allow_google": False,
                    "allow_google_verified": False,
                    "os": "windows",
                    "window": [2800, 1500],
                }
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.tg.retire_cards = mock.AsyncMock(return_value=0)  # type: ignore[method-assign]

                orig_env_val = os.environ.pop(srv.X11_VIRTUAL_DISPLAY_ENV, None)
                try:
                    with (
                        mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
                        mock.patch.object(srv, "PROFILES_DATA_DIR", td_path),
                        mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                        mock.patch.object(srv, "resolve_launch_spec", return_value=spec),
                        mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                        self.assertLogs(srv.log.name, level="INFO") as log_cap,
                    ):
                        await hub.start_hosted(notify_tg=False)
                        self.assertIsNone(
                            os.environ.get(srv.X11_VIRTUAL_DISPLAY_ENV),
                            "CAMOUFOX_VIRTUAL_DISPLAY_SIZE MUST be restored to unset after launch",
                        )
                        self.assertEqual(["2960x1740x24"], seen_vd_envs)
                        self.assertNotIn(
                            srv.X11_VIRTUAL_DISPLAY_ENV,
                            seen_kwargs_envs[0],
                            "Firefox subprocess kwargs['env'] MUST NOT be polluted by host Xvfb env var",
                        )
                        self.assertEqual(":9", hub.x11_display)
                        self.assertEqual([2960, 1740], hub.x11_screen_size)
                        self.assertEqual("", hub.last_human_input_backend)
                        self.assertTrue(
                            any("Resolved Camoufox X11 display=:9 screen=2960x1740" in ln for ln in log_cap.output),
                            f"Expected screen resolution in startup log, got: {log_cap.output}",
                        )
                        await hub.stop_hosted(notify_finished=False)
                        self.assertIsNone(hub.x11_display)
                        self.assertIsNone(hub.x11_screen_size)
                        self.assertEqual("", hub.last_human_input_backend)
                        self.assertEqual(set(), stack.active_handles)

                        # Failure path restores prior env var cleanly
                        os.environ[srv.X11_VIRTUAL_DISPLAY_ENV] = "1x1x24"
                        fail_enter[0] = True
                        with self.assertRaises(RuntimeError):
                            await hub.start_hosted(notify_tg=False)
                        self.assertEqual("1x1x24", os.environ.get(srv.X11_VIRTUAL_DISPLAY_ENV))
                        self.assertEqual("2960x1740x24", seen_vd_envs[-1])
                finally:
                    if orig_env_val is None:
                        os.environ.pop(srv.X11_VIRTUAL_DISPLAY_ENV, None)
                    else:
                        os.environ[srv.X11_VIRTUAL_DISPLAY_ENV] = orig_env_val
                    await hub._cancel_and_await_bg_tasks()
                    await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_degenerate_1x1_and_truncated_screen_never_silently_clamp_and_diag_status_isolation(self) -> None:
        # 1. Degenerate screen (< 64x64, including 1x1 even with mozInnerScreenX/Y == 0) MUST return None!
        geom_zero_origin = {
            "mozInnerScreenX": 0,
            "mozInnerScreenY": 0,
            "innerWidth": 1280,
            "innerHeight": 800,
            "devicePixelRatio": 1.0,
        }
        geom_camoufox_real = {
            "mozInnerScreenX": 0,
            "mozInnerScreenY": 85,
            "innerWidth": 1280,
            "innerHeight": 715,
            "devicePixelRatio": 1.0,
        }
        for deg_w, deg_h in ((1, 1), (0, 0), (16, 16), (63, 1080), (1920, 63)):
            self.assertIsNone(
                srv._compute_clamped_x11_coords(geom_zero_origin, 340.5, 336.5, deg_w, deg_h),
                f"Degenerate screen {deg_w}x{deg_h} MUST return None (never clamp to (0,0))",
            )
            self.assertIsNone(
                srv._compute_clamped_x11_coords(geom_camoufox_real, 340.5, 336.5, deg_w, deg_h),
                f"Degenerate screen {deg_w}x{deg_h} MUST return None",
            )

        # 2. Undersized screen where in-viewport target falls outside [0..scr_w-1]x[0..scr_h-1] (>2px drift) -> None!
        self.assertEqual((340, 422), srv._compute_clamped_x11_coords(geom_camoufox_real, 340.5, 336.5, 800, 600))
        self.assertIsNone(
            srv._compute_clamped_x11_coords(geom_camoufox_real, 900.0, 300.0, 800, 600),
            "In-viewport click past scr_w MUST return None instead of mis-clicking at x=799",
        )
        self.assertIsNone(
            srv._compute_clamped_x11_coords(geom_camoufox_real, 300.0, 550.0, 800, 600),
            "In-viewport click past scr_h (550+85=635 >= 600) MUST return None instead of mis-clicking at y=599",
        )
        # DPR=2.0 on 1920x1080 where in-viewport click (980, 550) -> (1980, 1260) exceeds 1920x1080
        geom_dpr2 = {
            "mozInnerScreenX": 10,
            "mozInnerScreenY": 80,
            "innerWidth": 1000,
            "innerHeight": 600,
            "devicePixelRatio": 2.0,
        }
        self.assertIsNone(srv._compute_clamped_x11_coords(geom_dpr2, 980.0, 550.0, 1920, 1080))

        # 3. Normal 1920x1080 & 2560x1600 screens hit exact mozInnerScreenX/Y target (<= 1px rounding)
        self.assertEqual((340, 422), srv._compute_clamped_x11_coords(geom_camoufox_real, 340.5, 336.5, 1920, 1080))
        geom_moved_dpr125 = {
            "mozInnerScreenX": 96.0,
            "mozInnerScreenY": 144.8,
            "innerWidth": 1000,
            "innerHeight": 627,
            "devicePixelRatio": 1.25,
        }
        self.assertEqual((546, 602), srv._compute_clamped_x11_coords(geom_moved_dpr125, 340.5, 336.5, 2560, 1600))

        # 4. End-to-end: 1x1 Xvfb -> WARNING log, 0 XTest pointer events, Playwright fallback + /internal/status diagnostics
        async def _scenario() -> None:
            stack_1x1 = _FakeX11Stack(scr_w=1, scr_h=1)
            page_1x1 = _FakePage(geom=geom_zero_origin)
            hub, meta = _make_auth_hub(page_1x1, display=":1")

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_1x1.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 1),
                self.assertLogs(srv.log.name, level="WARNING") as warn_cap,
            ):
                await hub._execute_human_cmd_async({"action": "click", "x": 340.5, "y": 336.5, **meta})

            self.assertEqual(
                [],
                [e for e in stack_1x1.events if e[0] in ("motion", "button")],
                "1x1 Xvfb MUST send 0 XTest motion/button events (never silent clamp to (0,0))",
            )
            self.assertTrue(
                any(e[0] == "click" and e[1] == 340.5 and e[2] == 336.5 for e in page_1x1.mouse.events),
                "1x1 Xvfb MUST fall back safely to Playwright click at exact target coords",
            )
            self.assertTrue(any("1x1" in ln and "too small" in ln for ln in warn_cap.output))
            self.assertEqual([1, 1], hub.x11_screen_size)
            self.assertEqual("playwright_fallback", hub.last_human_input_backend)

            # Switch to healthy 1920x1080 screen -> X11 XTest succeeds and updates diagnostics
            await hub._x11_pointer.close_async()
            hub._x11_pointer = srv.X11XTestPointerEngine()
            stack_ok = _FakeX11Stack(scr_w=1920, scr_h=1080)
            page_1x1.geom = geom_camoufox_real
            page_1x1.mouse.events.clear()
            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack_ok.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 1),
            ):
                await hub._execute_human_cmd_async({"action": "click", "x": 340.5, "y": 336.5, **meta})

            motions = [(e[3], e[4]) for e in stack_ok.events if e[0] == "motion"]
            self.assertEqual([(340, 422)], motions)
            self.assertEqual([], page_1x1.mouse.events)
            self.assertEqual([1920, 1080], hub.x11_screen_size)
            self.assertEqual("x11_xtest", hub.last_human_input_backend)

            # /internal/status exposes read-only diagnostics ONLY to local/admin callers, NOT readonly/group/redacted
            if srv.web is not None:
                def _make_req(query: dict[str, str] | None = None) -> Any:
                    return types.SimpleNamespace(
                        app={"hub": hub},
                        headers={"X-Live-Token": "tok"},
                        query=(query or {}),
                        remote="127.0.0.1",
                    )

                resp_local = await srv.internal_status(_make_req())
                data_local = json.loads(resp_local.text)
                self.assertEqual(":1", data_local["x11_display"])
                self.assertEqual([1920, 1080], data_local["x11_screen_size"])
                self.assertEqual("x11_xtest", data_local["last_human_input_backend"])

                with mock.patch.object(srv, "_check_live_user_role", return_value="readonly"):
                    resp_ro = await srv.internal_status(_make_req({"bot": "main", "user_id": "111"}))
                    data_ro = json.loads(resp_ro.text)
                    self.assertNotIn("x11_display", data_ro)
                    self.assertNotIn("x11_screen_size", data_ro)
                    self.assertNotIn("last_human_input_backend", data_ro)

                with mock.patch.object(srv, "_check_live_user_role", return_value="admin"):
                    resp_grp = await srv.internal_status(
                        _make_req({"bot": "main", "user_id": "111", "chat_scope": "group"})
                    )
                    data_grp = json.loads(resp_grp.text)
                    self.assertNotIn("x11_display", data_grp)
                    self.assertNotIn("x11_screen_size", data_grp)
                    self.assertNotIn("last_human_input_backend", data_grp)

                    resp_other = await srv.internal_status(_make_req({"bot": "sg", "user_id": "222"}))
                    data_other = json.loads(resp_other.text)
                    self.assertNotIn("x11_display", data_other)
                    self.assertNotIn("x11_screen_size", data_other)
                    self.assertNotIn("last_human_input_backend", data_other)

            # Stop session clears diagnostics cleanly
            await hub._stop_hosted_locked(notify_finished=False)
            self.assertIsNone(hub.x11_display)
            self.assertIsNone(hub.x11_screen_size)
            self.assertEqual("", hub.last_human_input_backend)
            if srv.web is not None:
                resp_idle = await srv.internal_status(
                    types.SimpleNamespace(
                        app={"hub": hub},
                        headers={"X-Live-Token": "tok"},
                        query={},
                        remote="127.0.0.1",
                    )
                )
                data_idle = json.loads(resp_idle.text)
                self.assertIsNone(data_idle["x11_display"])
                self.assertIsNone(data_idle["x11_screen_size"])
                self.assertEqual("", data_idle["last_human_input_backend"])

            await hub._cancel_and_await_bg_tasks()
            await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_qa_r1_p0_1_poll_clipboard_delayed_probe_concurrent_stop_zero_handle_leak(self) -> None:
        """QA Round 1 [P0-1]: _poll_clipboard_once delayed probe racing with _stop_hosted_locked leaks 0 Display* handles."""
        async def _scenario() -> None:
            # Case A: _stop_hosted_locked runs concurrently while _poll_clipboard_once is suspended in ensure_screen_size_async
            stack = _FakeX11Stack(scr_w=2560, scr_h=1600)
            page = _FakePage()
            hub, _ = _make_auth_hub(page, display=None, sgen=40, tgen=8, owner=("main", 111))

            probe_entered = asyncio.Event()
            probe_release = asyncio.Event()
            orig_probe = hub._x11_pointer.ensure_screen_size_async

            async def _blocking_probe(disp: str | None) -> tuple[int, int] | None:
                probe_entered.set()
                await probe_release.wait()
                return await orig_probe(disp)

            hub._x11_pointer.ensure_screen_size_async = _blocking_probe  # type: ignore[method-assign]

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=":55"),
                mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
            ):
                poll_task = asyncio.create_task(hub._poll_clipboard_once())
                await asyncio.wait_for(probe_entered.wait(), timeout=1.0)
                self.assertTrue(hub._exec_lock.locked(), "Delayed clipboard probe MUST hold _exec_lock")

                stop_task = asyncio.create_task(hub._stop_hosted_locked(notify_finished=False))
                await asyncio.sleep(0.02)
                self.assertEqual("idle", hub.engine_mode)
                self.assertFalse(
                    stop_task.done(),
                    "_stop_hosted_locked MUST wait on _exec_lock barrier until delayed probe finishes",
                )

                probe_release.set()
                await asyncio.wait_for(asyncio.gather(poll_task, stop_task), timeout=2.0)

            self.assertEqual("idle", hub.engine_mode)
            self.assertIsNone(hub.x11_display)
            self.assertIsNone(hub.x11_screen_size)
            self.assertEqual(set(), stack.active_handles, "0 leaked Display* handles after concurrent stop")
            self.assertIsNone(hub._x11_pointer.active_display, "active_display MUST be None after concurrent stop")
            self.assertEqual([], stack.double_closes)

            # Case B: session_gen advances (cross-session transition) before ensure_screen_size_async returns
            stack2 = _FakeX11Stack(scr_w=2560, scr_h=1600)
            page2 = _FakePage()
            hub2, _ = _make_auth_hub(page2, display=None, sgen=50, tgen=9, owner=("main", 111))
            orig_probe2 = hub2._x11_pointer.ensure_screen_size_async

            async def _advancing_gen_probe(disp: str | None) -> tuple[int, int] | None:
                res = await orig_probe2(disp)
                # Simulate stop + restart completing before probe returns
                hub2.session_gen += 2
                return res

            hub2._x11_pointer.ensure_screen_size_async = _advancing_gen_probe  # type: ignore[method-assign]

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack2.cdll_loader),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=":56"),
                mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
            ):
                await hub2._poll_clipboard_once()

            self.assertIsNone(hub2.x11_display, "Stale session probe MUST NOT overwrite new session x11_display")
            self.assertIsNone(hub2.x11_screen_size)
            self.assertEqual(set(), stack2.active_handles, "Stale session probe MUST immediately close Display*")
            self.assertIsNone(hub2._x11_pointer.active_display)
            self.assertEqual([], stack2.double_closes)

            await hub._cancel_and_await_bg_tasks()
            await hub2._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_qa_r1_p1_1_start_hosted_cancelled_during_screen_probe_cleans_all_resources(self) -> None:
        """QA Round 1 [P1-1]: Cancelling start_hosted() during ensure_screen_size_async cleans CM, Display*, flock, tmpdir & env."""
        async def _scenario() -> None:
            with tempfile.TemporaryDirectory(prefix="agy-x11-cancel-test-") as td:
                td_path = Path(td)
                lock_path = td_path / "cancel-test.lock"
                aexit_called = [False]
                created_ephemeral_dirs: list[Path] = []
                probe_entered = asyncio.Event()
                probe_block = asyncio.Event()

                class _FakeCancelCM:
                    def __init__(self, **kw: Any) -> None:
                        ud = kw.get("user_data_dir")
                        if ud:
                            created_ephemeral_dirs.append(Path(ud))
                        self._vd = types.SimpleNamespace(_display=77)

                    async def __aenter__(self) -> Any:
                        vd_ref = self._vd

                        async def _close() -> None:
                            _ = vd_ref

                        page = _FakePage("https://app.example/cancel", "Cancel")
                        return types.SimpleNamespace(
                            pages=[page],
                            on=lambda _ev, _cb: None,
                            close=_close,
                        )

                    async def __aexit__(self, *_a: Any) -> None:
                        await asyncio.sleep(0.01)
                        aexit_called[0] = True
                        return None

                fake_mod = types.ModuleType("camoufox.async_api")
                fake_mod.AsyncCamoufox = _FakeCancelCM  # type: ignore[attr-defined]
                fake_pkg = types.ModuleType("camoufox")
                fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

                stack = _FakeX11Stack(scr_w=2560, scr_h=1600)
                spec = {
                    "name": "cancel-ephem",
                    "profile_dir": td_path / "cancel-ephem",
                    "lock_path": lock_path,
                    "persistent": False,
                    "pinned": False,
                    "pinned_verified": False,
                    "allow_google": False,
                    "allow_google_verified": False,
                    "os": "windows",
                    "window": [1280, 800],
                }
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18796, "public_url": ""}, "tok")
                hub.tg.retire_cards = mock.AsyncMock(return_value=0)  # type: ignore[method-assign]
                orig_probe = hub._x11_pointer.ensure_screen_size_async

                async def _hanging_probe(disp: str | None) -> tuple[int, int] | None:
                    # Open a real handle before suspending so cancellation MUST close it!
                    await orig_probe(disp)
                    probe_entered.set()
                    await probe_block.wait()
                    return (2560, 1600)

                hub._x11_pointer.ensure_screen_size_async = _hanging_probe  # type: ignore[method-assign]

                orig_env_val = os.environ.get(srv.X11_VIRTUAL_DISPLAY_ENV)
                os.environ[srv.X11_VIRTUAL_DISPLAY_ENV] = "1920x1080x24"
                try:
                    with (
                        mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
                        mock.patch.object(srv, "PROFILES_DATA_DIR", td_path),
                        mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                        mock.patch.object(srv, "resolve_launch_spec", return_value=spec),
                        mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                        mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                    ):
                        start_task = asyncio.create_task(hub.start_hosted(notify_tg=False))
                        await asyncio.wait_for(probe_entered.wait(), timeout=1.0)
                        self.assertEqual(1, len(stack.active_handles), "Display* should be open before cancel")
                        self.assertEqual(1, len(created_ephemeral_dirs))
                        self.assertTrue(created_ephemeral_dirs[0].exists())

                        start_task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await start_task

                    self.assertTrue(aexit_called[0], "cm.__aexit__ MUST run when start_hosted() is cancelled")
                    self.assertEqual(set(), stack.active_handles, "Display* handle MUST be closed on CancelledError")
                    self.assertIsNone(hub._x11_pointer.active_display)
                    self.assertEqual([], stack.double_closes)
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.ctx)
                    self.assertIsNone(hub.lock_fd)
                    self.assertFalse(
                        created_ephemeral_dirs[0].exists(),
                        "Ephemeral profile directory MUST be removed on CancelledError",
                    )
                    self.assertEqual(
                        "1920x1080x24",
                        os.environ.get(srv.X11_VIRTUAL_DISPLAY_ENV),
                        "CAMOUFOX_VIRTUAL_DISPLAY_SIZE MUST be restored on CancelledError",
                    )
                    # Verify flock was released cleanly
                    check_fd = os.open(lock_path, os.O_RDWR)
                    try:
                        fcntl.flock(check_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(check_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(check_fd)
                finally:
                    if orig_env_val is None:
                        os.environ.pop(srv.X11_VIRTUAL_DISPLAY_ENV, None)
                    else:
                        os.environ[srv.X11_VIRTUAL_DISPLAY_ENV] = orig_env_val
                    await hub._cancel_and_await_bg_tasks()
                    await hub._x11_pointer.close_async()

        asyncio.run(_scenario())

    def test_qa_r1_p1_2_concurrent_stop_during_click_hold_never_writes_last_human_input_backend(self) -> None:
        """QA Round 1 [P1-2]: Concurrent _stop_hosted_locked during HUMAN_CLICK_HOLD_DELAY_MS keeps last_human_input_backend == ''."""
        async def _scenario() -> None:
            stack = _FakeX11Stack(scr_w=2560, scr_h=1600)
            page = _FakePage()
            hub, meta = _make_auth_hub(page, display=":99", sgen=60, tgen=12, owner=("main", 111))

            hold_entered = asyncio.Event()
            hold_release = asyncio.Event()
            orig_sleep = srv.asyncio.sleep

            async def _hooked_sleep(delay: float, *args: Any, **kwargs: Any) -> Any:
                if abs(delay - (srv.HUMAN_CLICK_HOLD_DELAY_MS / 1000.0)) < 1e-6 and not hold_entered.is_set():
                    hold_entered.set()
                    await hold_release.wait()
                    return None
                return await orig_sleep(delay, *args, **kwargs)

            with (
                mock.patch.object(srv.ctypes, "CDLL", side_effect=stack.cdll_loader),
                mock.patch.object(srv, "_check_live_user_role", return_value="admin"),
                mock.patch.object(srv, "HUMAN_CLICK_HOLD_DELAY_MS", 37),
                mock.patch.object(srv.asyncio, "sleep", side_effect=_hooked_sleep),
            ):
                click_task = asyncio.create_task(
                    hub._execute_human_cmd_async({"action": "click", "x": 120, "y": 140, "button": "left", **meta})
                )
                await asyncio.wait_for(hold_entered.wait(), timeout=1.0)
                self.assertEqual({1}, hub._x11_buttons_down)

                stop_task = asyncio.create_task(hub._stop_hosted_locked(notify_finished=False))
                await orig_sleep(0.02)
                self.assertEqual("idle", hub.engine_mode)
                self.assertEqual("", hub.last_human_input_backend)

                hold_release.set()
                await asyncio.wait_for(asyncio.gather(click_task, stop_task), timeout=2.0)

            self.assertEqual("idle", hub.engine_mode)
            self.assertEqual(
                "",
                hub.last_human_input_backend,
                "In-flight click finishing after concurrent stop MUST NOT write back last_human_input_backend",
            )
            self.assertEqual(set(), hub._x11_buttons_down)
            self.assertEqual(set(), stack.active_handles)
            self.assertIsNone(hub._x11_pointer.active_display)

            # Direct helper guard checks: idle / wrong gen / bool gen / missing gen all rejected
            hub._set_last_human_input_backend("x11_xtest", {"_session_gen": hub.session_gen})
            self.assertEqual("", hub.last_human_input_backend)
            hub.engine_mode = "async_hosted"
            hub._set_last_human_input_backend("x11_xtest", {"_session_gen": hub.session_gen - 1})
            self.assertEqual("", hub.last_human_input_backend)
            hub._set_last_human_input_backend("x11_xtest", {"_session_gen": True})
            self.assertEqual("", hub.last_human_input_backend)
            hub._set_last_human_input_backend("x11_xtest", {})
            self.assertEqual("", hub.last_human_input_backend)
            hub._set_last_human_input_backend("playwright_fallback", {"_session_gen": hub.session_gen})
            self.assertEqual("playwright_fallback", hub.last_human_input_backend)

            await hub._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_qa_r1_p1_3_compute_virtual_display_size_huge_int_overflow_fails_safe(self) -> None:
        """QA Round 1 [P1-3]: compute_virtual_display_size handles 10**400 without OverflowError and falls back to 2560x1600x24."""
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((10**400, 1000)))
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((1000, -(10**400))))
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((10**400, 10**400)))
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((float("nan"), 1000)))
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((float("inf"), 1000)))
        self.assertEqual("2560x1600x24", srv.compute_virtual_display_size((None, 1000)))


if __name__ == "__main__":
    unittest.main()
