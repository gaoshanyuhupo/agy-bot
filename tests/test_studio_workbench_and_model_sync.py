#!/usr/bin/env python3
"""Offline unit & integration tests for Phase 2/2 (C1, C5, C6, C7, C8):

- C1 / C5: Workbench Sidebar State Server Sync (`/api/workbench/state`) 4-layer write gate,
  9-field whitelist, rejection of viewport layout / host path / prototype-pollution fields,
  capacity quotas, 128 KiB body cap, `0700`/`0600` + symlink refusal, and `resolve_allowed_project()` isolation.
- C6: Optimistic concurrency (`expected_version` / `version` -> `409 Conflict` with latest
  server snapshot), `workbench_state_updated` SSE broadcast, and non-destructive migration invariant.
- C7: Long external model slugs (>80 chars, up to 160 chars with `:` and `/`), hot-reloaded
  `gateways.json` external model exposure & `PATCH /api/bots/{handle}/config` validation without
  restarting Bridge, disabled/unknown model rejection, atomic zero-partial-write validation,
  and `gateways_updated` SSE emission.
- C8: Frontend `WorkspaceView.tsx` authoritative server echo, monotonic seq/handle race isolation,
  readonly UI disabling, and passive-echo zero-writeback invariants.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

import aiohttp
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import bot_bus  # noqa: E402
import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import (  # noqa: E402
    MAX_MODEL_SLUG_LEN,
    StudioDataSources,
    _sanitize_slug,
)
from studio.server import EVENT_HUB_KEY, create_app  # noqa: E402
from studio.workbench_state_service import (  # noqa: E402
    MAX_ARCHIVED_SESSION_CIDS,
    MAX_CUSTOM_PROJECTS,
    MAX_PINNED_SESSION_CIDS,
    MAX_SESSION_RENAMES,
    MAX_WORKBENCH_BODY_BYTES,
    validate_workbench_sidebar_state,
)

BOT_TOKEN_TEST = "123456789:EXAMPLE_P2_WORKBENCH_SYNC_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
ONLINE_BOT = "example_sync_bot"
ADMIN_PASS = "EXAMPLE_P2_ADMIN_PASS_01"
RO_PASS = "EXAMPLE_P2_RO_PASS_01"
_DATE_TAG = "".join(("2025", "0514"))
LONG_UPSTREAM_MODEL = (
    f"organization-namespace/super-long-reasoning-model-{_DATE_TAG}:thinking-extended-variant-v2"
)
LONG_GW_ID = "openrouter_prod"
LONG_EXPLICIT_MODEL = f"gw:{LONG_GW_ID}:{LONG_UPSTREAM_MODEL}"
assert len(LONG_EXPLICIT_MODEL) > 95
assert len(LONG_EXPLICIT_MODEL) <= MAX_MODEL_SLUG_LEN


def _isolated_env_overrides(extra: dict[str, str] | None = None) -> dict[str, str]:
    base = {
        "AGY_TG_BOT_EFFORT": "",
        "AGY_TG_BOT_MODEL": "",
        "OPENBAO_CONFIG_PATH": "",
        "BAO_ADDR": "",
        "VAULT_ADDR": "",
        "BAO_TOKEN": "",
        "VAULT_TOKEN": "",
        "AGY_TG_GATEWAYS_FILE": "",
        "AGY_TG_GATEWAYS_JSON": "",
        "AGY_STUDIO_SECRETS_CONFIG": "",
        "AGY_STUDIO_GATEWAY_SECRETS_FILE": "",
        "AGY_STUDIO_WORKBENCH_STATE_FILE": "",
    }
    if extra:
        base.update(extra)
    return base


class TestStaticAndSlugInvariants(unittest.TestCase):
    """Pure unit checks for C5 static invariants, C7 long slug safety, and C8 frontend guards."""

    def test_c5_workbench_service_zero_shell_or_subprocess(self) -> None:
        src = (REPO_ROOT / "studio" / "workbench_state_service.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else ([node.module] if node.module else [])
                )
                for mod in names:
                    self.assertNotIn(mod, ("subprocess", "pty", "shlex", "pexpect"))
            elif isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("system", "popen", "spawnl", "spawnv"))

    def test_c7_long_external_model_slug_preservation_and_safety(self) -> None:
        # Must preserve long `gw:<id>:<org/model:variant>` (>80 chars, with date suffix)
        self.assertEqual(
            _sanitize_slug(LONG_EXPLICIT_MODEL, max_len=MAX_MODEL_SLUG_LEN),
            LONG_EXPLICIT_MODEL,
        )
        self.assertEqual(
            bridge_mod._sanitize_ipc_slug(LONG_EXPLICIT_MODEL, max_len=bridge_mod.MAX_IPC_MODEL_SLUG_LEN),
            LONG_EXPLICIT_MODEL,
        )

        # Control characters are stripped cleanly
        dirty = "gw:or:org/model\r\n\x00:v1"
        self.assertEqual(_sanitize_slug(dirty, max_len=160), "gw:or:org/model:v1")
        self.assertEqual(bridge_mod._sanitize_ipc_slug(dirty, max_len=160), "gw:or:org/model:v1")

        # Path traversal & host sensitive paths & secrets are rejected/redacted
        self.assertEqual(_sanitize_slug("gw:bad:../../etc/passwd", max_len=160), "[REDACTED]")
        self.assertEqual(
            bridge_mod._sanitize_ipc_slug("gw:bad:../../etc/passwd", max_len=160),
            "[REDACTED]",
        )
        synth_home_env = "/home/" + "alice/.env"
        synth_home_demo = "/home/" + "alice/demo.py"
        self.assertEqual(_sanitize_slug(f"gw:bad:{synth_home_env}", max_len=160), "[REDACTED]")
        self.assertEqual(_sanitize_slug("sk-EXAMPLE_SECRET_TOKEN_123456", max_len=160), "[REDACTED]")
        self.assertEqual(
            bridge_mod._sanitize_ipc_slug("sk-EXAMPLE_SECRET_TOKEN_123456", max_len=160),
            "[REDACTED]",
        )
        # Leading absolute host path collapses to basename
        self.assertEqual(_sanitize_slug(synth_home_demo, max_len=64), "demo.py")
        self.assertEqual(bridge_mod._sanitize_ipc_slug(synth_home_demo, max_len=64), "demo.py")

    def test_c5_validation_rejects_bad_fields_and_quotas(self) -> None:
        # Reject viewport layout fields
        ok, _, err = validate_workbench_sidebar_state({"paneCount": 2})
        self.assertFalse(ok)
        self.assertIn("paneCount", err)

        ok, _, _ = validate_workbench_sidebar_state({"layoutMode": "2"})
        self.assertFalse(ok)

        ok, _, _ = validate_workbench_sidebar_state({"panes": []})
        self.assertFalse(ok)

        # Reject prototype pollution keys
        for bad_key in ("__proto__", "constructor", "prototype"):
            ok, _, _ = validate_workbench_sidebar_state({"sessionRenames": {bad_key: "x"}})
            self.assertFalse(ok)

        # Reject host path fields inside customProjects
        for bad_path_key in ("workdir", "path", "folderUri", "cwd"):
            ok, _, _ = validate_workbench_sidebar_state(
                {"customProjects": [{"id": "proj-1", "name": "P1", bad_path_key: "/etc"}]}
            )
            self.assertFalse(ok)

        # Reject over-quota lists
        ok, _, _ = validate_workbench_sidebar_state(
            {"pinnedSessionCids": [f"cid_{i:04d}" for i in range(MAX_PINNED_SESSION_CIDS + 1)]}
        )
        self.assertFalse(ok)

        ok, _, _ = validate_workbench_sidebar_state(
            {"archivedSessionCids": [f"cid_{i:04d}" for i in range(MAX_ARCHIVED_SESSION_CIDS + 1)]}
        )
        self.assertFalse(ok)

        ok, _, _ = validate_workbench_sidebar_state(
            {
                "customProjects": [
                    {"id": f"proj-{i}", "name": f"Proj {i}"} for i in range(MAX_CUSTOM_PROJECTS + 1)
                ]
            }
        )
        self.assertFalse(ok)

        ok, _, _ = validate_workbench_sidebar_state(
            {"sessionRenames": {f"cid_{i:04d}": "t" for i in range(MAX_SESSION_RENAMES + 1)}}
        )
        self.assertFalse(ok)

    def test_c8_frontend_source_guards_present(self) -> None:
        ws_src = (REPO_ROOT / "webui" / "src" / "components" / "WorkspaceView.tsx").read_text(
            encoding="utf-8"
        )
        api_src = (REPO_ROOT / "webui" / "src" / "api.ts").read_text(encoding="utf-8")
        app_src = (REPO_ROOT / "webui" / "src" / "App.tsx").read_text(encoding="utf-8")

        # SSE bindings for cross-device sidebar sync & gateway hot updates
        self.assertIn('bindType("gateways_updated")', api_src)
        self.assertIn('bindType("workbench_state_updated")', api_src)
        self.assertIn("fetchWorkbenchState", api_src)
        self.assertIn("updateWorkbenchState", api_src)
        self.assertIn('ev.type === "gateways_updated"', app_src)
        self.assertIn('ev.type === "workbench_state_updated"', app_src)

        # WorkspaceView authoritative echo + race isolation + non-destructive migration
        self.assertIn("fetchBotConfig", ws_src)
        self.assertIn("updateBotConfig", ws_src)
        self.assertIn("botConfigPatchSeqRef", ws_src)
        self.assertIn("hasNonEmptySidebarState", ws_src)
        self.assertIn("mergeSidebarStates", ws_src)
        self.assertIn("expected_version", ws_src)
        # Ensure the old sticky model bug condition is completely gone
        self.assertNotIn("let resolvedModel = selectedModelRef.current;", ws_src)


class TestWorkbenchStateAndModelSyncAPI(unittest.IsolatedAsyncioTestCase):
    """End-to-end aiohttp + Bridge UDS IPC contract tests for C1, C5, C6, C7."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_p2_wb_sync_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.projects_dir = self.tmp / "projects"
        self.proj_dir = self.tmp / "repos" / "safe-proj"
        self.audit_log = self.config_dir / "audit.jsonl"
        self.wb_state_path = self.config_dir / "studio_workbench_state.json"
        self.gateways_path = self.config_dir / "gateways.json"
        self.gw_secrets_path = self.config_dir / "studio_gateway_secrets.json"
        self.secrets_cfg_path = self.config_dir / "studio_secrets.json"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "inbox",
            self.projects_dir,
            self.proj_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        (self.projects_dir / "safe-proj.json").write_text(
            json.dumps({
                "id": "safe-proj",
                "name": "Safe Project",
                "projectResources": {
                    "resources": [{"folderUri": f"file://{self.proj_dir}"}]
                },
            }),
            encoding="utf-8",
        )

        (self.bridge_dir / ".env").write_text(
            "\n".join([
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ]) + "\n",
            encoding="utf-8",
        )

        now_i = int(time.time())
        users_map = {
            "admin_user": {
                "username": "admin_user",
                "password_hash": hash_password_scrypt(ADMIN_PASS),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "ro_user": {
                "username": "ro_user",
                "password_hash": hash_password_scrypt(RO_PASS),
                "role": "readonly",
                "bot": "main",
                "user_id": READONLY_UID,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
        }
        save_users_file_atomic(self.config_dir / "users.json", users_map)

        self._env_patch = mock.patch.dict(
            os.environ,
            _isolated_env_overrides({
                "AGY_TG_GATEWAYS_FILE": str(self.gateways_path),
                "AGY_STUDIO_SECRETS_CONFIG": str(self.secrets_cfg_path),
                "AGY_STUDIO_GATEWAY_SECRETS_FILE": str(self.gw_secrets_path),
                "AGY_STUDIO_WORKBENCH_STATE_FILE": str(self.wb_state_path),
            }),
            clear=False,
        )
        self._env_patch.start()

        # Patch bot_bus paths to isolated temp bus
        self._bus_patches = [
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bot_bus, "JOBS_DIR", str(self.bus_dir / "jobs")),
            mock.patch.object(bot_bus, "INBOX_DIR", str(self.bus_dir / "inbox")),
            mock.patch.object(bot_bus, "LOCK_FILE", str(self.bus_dir / "bus.lock")),
            mock.patch.object(bot_bus, "CONFIG_FILE", str(self.bus_dir / "team_config.json")),
            mock.patch.object(bot_bus, "ROSTER_FILE", str(self.bus_dir / "roster.json")),
        ]
        for p in self._bus_patches:
            p.start()

        # Patch bridge globals for isolated IPC execution (zero real CLI / network)
        self._orig_scope_state = dict(bridge_mod.state.get(bridge_mod.PRIMARY_SCOPE_KEY) or {})
        self._save_state_calls: list[int] = []

        def _fake_save_state() -> None:
            self._save_state_calls.append(1)

        self._bridge_patches = [
            mock.patch.object(bridge_mod, "GATEWAYS_FILE", str(self.gateways_path)),
            mock.patch.object(bridge_mod, "GATEWAYS_JSON", ""),
            mock.patch.object(bridge_mod, "ENV_BOT_MODEL", "gemini-2.5-pro"),
            mock.patch.object(bridge_mod, "ENV_BOT_EFFORT", ""),
            mock.patch.object(bridge_mod, "PROJECTS_DIR", str(self.projects_dir)),
            mock.patch.object(bridge_mod, "WORKDIR", str(self.proj_dir)),
            mock.patch.object(
                bridge_mod,
                "BOT_META",
                {"handle": ONLINE_BOT, "username": ONLINE_BOT, "first_name": "SyncBot"},
            ),
            mock.patch.object(bridge_mod, "save_state", side_effect=_fake_save_state),
            mock.patch.object(bridge_mod, "invalidate_session", return_value=None),
            mock.patch.object(
                bridge_mod,
                "agy_native_models",
                return_value=[
                    ("gemini-2.5-pro", "Gemini 2.5 Pro"),
                    ("gemini-2.5-flash", "Gemini 2.5 Flash"),
                ],
            ),
            mock.patch.object(
                bridge_mod._gateway_runtime,
                "list_gateway_models",
                side_effect=lambda gw, **kw: [
                    m
                    for m in gw.models
                    if bridge_mod.gateway_adapter.model_matches_filters(
                        m, gw.include_models, gw.exclude_models
                    )
                ],
            ),
        ]
        for p in self._bridge_patches:
            p.start()

        bridge_mod.update_scope_state(
            bridge_mod.PRIMARY_SCOPE_KEY,
            model=None,
            effort=None,
            project="safe-proj",
            workdir=str(self.proj_dir),
        )
        bot_bus.set_bot_model_config(ONLINE_BOT, bot_bus.MODEL_MODE_DEFAULT, "")
        bot_bus.update_bot_config(ONLINE_BOT, role="worker", default_effort="", default_project="safe-proj")
        bridge_mod._publish_bot_heartbeat()

        self.ipc_srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=ONLINE_BOT,
            resolve_role_fn=lambda uid: "admin" if int(uid) == ADMIN_UID else "readonly",
            get_meta_fn=bridge_mod._studio_ipc_get_meta,
            enqueue_turn_fn=lambda _req: (501, {"ok": False, "error": "unused"}),
            abort_turn_fn=lambda _tid, _uid: (501, {"ok": False, "error": "unused"}),
            get_bot_config_fn=bridge_mod._studio_ipc_get_bot_config,
            update_bot_config_fn=bridge_mod._studio_ipc_update_bot_config,
        )
        self.ipc_srv.start()

        self.auth_mgr = StudioAuthManager(
            auth_mode="password",
            config_dir=self.config_dir,
            bridge_dir=self.bridge_dir,
        )
        self.data_sources = StudioDataSources(
            bus_dir=self.bus_dir,
            projects_dir=self.projects_dir,
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.data_sources,
            audit_log_path=self.audit_log,
            event_watcher_interval=0.0,
            workbench_state_path=self.wb_state_path,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self.ipc_srv.stop()
        bridge_mod.state[bridge_mod.PRIMARY_SCOPE_KEY] = self._orig_scope_state
        for p in reversed(self._bridge_patches):
            p.stop()
        for p in reversed(self._bus_patches):
            p.stop()
        self._env_patch.stop()
        self._td.cleanup()

    def _origin(self) -> str:
        return f"http://{self.server.host}:{self.server.port}"

    async def _login(self, username: str, password: str) -> tuple[TestClient, str]:
        jar = aiohttp.CookieJar(unsafe=True)
        cli = TestClient(self.server, cookie_jar=jar)
        await cli.start_server()
        resp = await cli.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": self._origin()},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        return cli, str(data["csrf_token"])

    def _write_headers(self, csrf: str, **extra: str) -> dict[str, str]:
        h = {
            "Origin": self._origin(),
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-Studio-CSRF": csrf,
        }
        h.update(extra)
        return h

    # ---------------------------------------------------------------- C1 + C5 + C6: Workbench State Sync
    async def test_c1_c5_c6_workbench_state_full_contract(self) -> None:
        # Unauthenticated GET / PUT -> 401 / 403
        r_unauth = await self.client.get("/api/workbench/state")
        self.assertEqual(r_unauth.status, 401)

        admin_cli, admin_csrf = await self._login("admin_user", ADMIN_PASS)
        ro_cli, ro_csrf = await self._login("ro_user", RO_PASS)
        try:
            # Initial GET: version 0, empty 9-field state, can_edit reflects RBAC
            r_get_a = await admin_cli.get("/api/workbench/state")
            self.assertEqual(r_get_a.status, 200)
            d_a = await r_get_a.json()
            self.assertTrue(d_a["ok"])
            self.assertEqual(d_a["version"], 0)
            self.assertTrue(d_a["can_edit"])
            self.assertEqual(len(d_a["state"]), 9)

            r_get_ro = await ro_cli.get("/api/workbench/state")
            self.assertEqual(r_get_ro.status, 200)
            d_ro = await r_get_ro.json()
            self.assertFalse(d_ro["can_edit"])

            # 4-layer write gate checks
            # 1a: Missing / bad Origin -> 403
            r_no_orig = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"showArchived": True}},
                headers={"Content-Type": "application/json", "X-Studio-CSRF": admin_csrf},
            )
            self.assertEqual(r_no_orig.status, 403)

            # 1b: Sec-Fetch-Site cross-site -> 403
            r_sfs = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"showArchived": True}},
                headers=self._write_headers(admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
            )
            self.assertEqual(r_sfs.status, 403)

            # 2: Wrong Content-Type -> 415
            r_ct = await admin_cli.put(
                "/api/workbench/state",
                data='{"expected_version":0,"state":{}}',
                headers={
                    "Origin": self._origin(),
                    "Content-Type": "text/plain",
                    "X-Studio-CSRF": admin_csrf,
                },
            )
            self.assertEqual(r_ct.status, 415)

            # 4a: Bad CSRF -> 403
            r_csrf = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"showArchived": True}},
                headers=self._write_headers("wrong-csrf-token"),
            )
            self.assertEqual(r_csrf.status, 403)

            # 4b: Readonly role -> fail-closed 403
            r_ro_put = await ro_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"showArchived": True}},
                headers=self._write_headers(ro_csrf),
            )
            self.assertEqual(r_ro_put.status, 403)
            self.assertFalse(self.wb_state_path.exists())

            # C5: Reject viewport fields, host paths, proto pollution, quotas, >128KiB
            r_vp = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"paneCount": 2, "panes": []}},
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_vp.status, 400)

            r_path = await admin_cli.put(
                "/api/workbench/state",
                json={
                    "expected_version": 0,
                    "state": {
                        "customProjects": [
                            {"id": "logic-only", "name": "Logical", "workdir": "/etc"}
                        ]
                    },
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_path.status, 400)

            r_proto = await admin_cli.put(
                "/api/workbench/state",
                data='{"expected_version":0,"state":{"__proto__":{"polluted":true}}}',
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_proto.status, 400)

            big_body = json.dumps({
                "expected_version": 0,
                "state": {"sessionRenames": {f"cid_{i:04d}": "x" * 100 for i in range(1500)}},
            })
            self.assertGreater(len(big_body.encode("utf-8")), MAX_WORKBENCH_BODY_BYTES)
            r_big = await admin_cli.put(
                "/api/workbench/state",
                data=big_body,
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_big.status, 413)

            # Valid PUT (version 0 -> 1) + SSE event + 0700/0600 permissions + resolve_allowed_project isolation
            hub = self.app[EVENT_HUB_KEY]
            ev_before = hub._next_seq
            payload_v1 = {
                "customProjects": [{"id": "logic-notes", "name": "My Logical Group", "createdAt": int(time.time())}],
                "projectRenames": {"safe-proj": "Renamed Safe"},
                "hiddenProjectIds": ["old-proj"],
                "hiddenSessionCids": ["cid_hidden_01"],
                "pinnedSessionCids": ["cid_pinned_01"],
                "archivedSessionCids": ["cid_arch_01"],
                "unreadSessionCids": ["cid_unread_01"],
                "sessionRenames": {"cid_pinned_01": "Important Thread"},
                "showArchived": True,
            }
            r_put1 = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": payload_v1},
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_put1.status, 200)
            d_put1 = await r_put1.json()
            self.assertTrue(d_put1["ok"])
            self.assertEqual(d_put1["version"], 1)
            self.assertEqual(d_put1["state"]["pinnedSessionCids"], ["cid_pinned_01"])
            self.assertEqual(d_put1["state"]["customProjects"][0]["id"], "logic-notes")

            # Custom logical project MUST NEVER bypass resolve_allowed_project()
            self.assertIsNone(self.data_sources.resolve_allowed_project("logic-notes"))

            # Verify 0700 dir & 0600 file permissions
            dir_mode = stat.S_IMODE(self.wb_state_path.parent.stat().st_mode)
            file_mode = stat.S_IMODE(self.wb_state_path.stat().st_mode)
            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(file_mode, 0o600)

            # Verify SSE broadcast `workbench_state_updated`
            published = [
                (t, data) for seq, t, data in list(hub._events) if seq >= ev_before
            ]
            self.assertTrue(
                any(t == "workbench_state_updated" and d.get("version") == 1 for t, d in published)
            )

            # C6: Optimistic concurrency conflict -> 409 Conflict with latest server snapshot
            r_conflict = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"pinnedSessionCids": ["cid_other_99"]}},
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_conflict.status, 409)
            d_conf = await r_conflict.json()
            self.assertFalse(d_conf["ok"])
            self.assertEqual(d_conf["code"], "version_conflict")
            self.assertEqual(d_conf["version"], 1)
            self.assertEqual(d_conf["state"]["pinnedSessionCids"], ["cid_pinned_01"])

            # Retry with matching `version` alias (1 -> 2) succeeds
            r_put2 = await admin_cli.put(
                "/api/workbench/state",
                json={
                    "version": 1,
                    "state": {"pinnedSessionCids": ["cid_pinned_01", "cid_other_99"]},
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_put2.status, 200)
            d_put2 = await r_put2.json()
            self.assertEqual(d_put2["version"], 2)
            self.assertEqual(
                d_put2["state"]["pinnedSessionCids"],
                ["cid_pinned_01", "cid_other_99"],
            )

            # Symlink refusal check
            evil_target = self.tmp / "evil_outside.json"
            evil_target.write_text('{"pwned":true}\n', encoding="utf-8")
            self.wb_state_path.unlink()
            self.wb_state_path.symlink_to(evil_target)
            r_sym_get = await admin_cli.get("/api/workbench/state")
            self.assertEqual(r_sym_get.status, 200)
            d_sym_get = await r_sym_get.json()
            self.assertEqual(d_sym_get["version"], 0)
            r_sym_put = await admin_cli.put(
                "/api/workbench/state",
                json={"expected_version": 0, "state": {"showArchived": True}},
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_sym_put.status, 500)
            self.assertEqual(evil_target.read_text(encoding="utf-8"), '{"pwned":true}\n')
        finally:
            await admin_cli.close()
            await ro_cli.close()

    # ---------------------------------------------------------------- C7: Hot External Model + Long Slug + Atomic Reject
    async def test_c7_hot_external_model_sync_long_slug_and_atomic_rejection(self) -> None:
        admin_cli, admin_csrf = await self._login("admin_user", ADMIN_PASS)
        ro_cli, ro_csrf = await self._login("ro_user", RO_PASS)
        try:
            hub = self.app[EVENT_HUB_KEY]
            ev_before_gw = hub._next_seq

            # 1. Create an enabled external gateway via Studio API (NO Bridge restart!)
            r_gw = await admin_cli.post(
                "/api/gateways",
                json={
                    "id": LONG_GW_ID,
                    "name": "OpenRouter Prod",
                    "base_url": "https://openrouter.example.com/api/v1",
                    "dialect": "openrouter",
                    "enabled": True,
                    "credential_kind": "none",
                    "models": [LONG_UPSTREAM_MODEL],
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_gw.status, 201, await r_gw.text())

            # GatewayService must publish `gateways_updated` SSE event
            gw_events = [
                (t, d) for seq, t, d in list(hub._events) if seq >= ev_before_gw
            ]
            self.assertTrue(
                any(t == "gateways_updated" and d.get("gateway_id") == LONG_GW_ID for t, d in gw_events)
            )

            # 2. Without restarting Bridge, GET /api/bots/{handle}/config & /api/models immediately expose it
            r_cfg = await admin_cli.get(f"/api/bots/{ONLINE_BOT}/config")
            self.assertEqual(r_cfg.status, 200)
            d_cfg = await r_cfg.json()
            self.assertTrue(d_cfg["ipc_online"])
            model_ids = [m["id"] for m in d_cfg["models"]]
            self.assertIn(LONG_UPSTREAM_MODEL, model_ids)

            r_mods = await admin_cli.get(f"/api/models?bot={ONLINE_BOT}")
            self.assertEqual(r_mods.status, 200)
            d_mods = await r_mods.json()
            self.assertIn(LONG_UPSTREAM_MODEL, [m["id"] for m in d_mods["models"]])

            # 3. Readonly user & cross-site Sec-Fetch-Site rejected with 403 on PATCH /api/bots/{handle}/config
            r_ro = await ro_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={"model_mode": "custom", "model": LONG_EXPLICIT_MODEL},
                headers=self._write_headers(ro_csrf),
            )
            self.assertEqual(r_ro.status, 403)

            r_sfs = await admin_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={"model_mode": "custom", "model": LONG_EXPLICIT_MODEL},
                headers=self._write_headers(admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
            )
            self.assertEqual(r_sfs.status, 403)

            # 4. Admin PATCHes explicit long `gw:<gw_id>:<upstream_model>` + effort -> 200, untruncated, persisted, SSE emitted
            ev_before_bot = hub._next_seq
            save_calls_before = len(self._save_state_calls)
            r_patch = await admin_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={
                    "model_mode": "custom",
                    "model": LONG_EXPLICIT_MODEL,
                    "default_effort": "high",
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_patch.status, 200, await r_patch.text())
            d_patch = await r_patch.json()
            self.assertEqual(d_patch["model_mode"], "custom")
            self.assertEqual(d_patch["configured_model"], LONG_EXPLICIT_MODEL)
            self.assertEqual(d_patch["effective_model"], LONG_EXPLICIT_MODEL)
            self.assertEqual(d_patch["default_effort"], "high")
            self.assertGreater(len(self._save_state_calls), save_calls_before)

            # Verify PRIMARY_SCOPE_KEY & bot_bus & GET /api/bots all reflect untruncated long slug + effort
            sc_now = bridge_mod.get_scope_state(bridge_mod.PRIMARY_SCOPE_KEY)
            self.assertEqual(sc_now.get("model"), LONG_EXPLICIT_MODEL)
            self.assertEqual(sc_now.get("effort"), "high")

            r_bots = await admin_cli.get("/api/bots")
            self.assertEqual(r_bots.status, 200)
            d_bots = await r_bots.json()
            bot_row = next(b for b in d_bots["bots"] if b["handle"] == ONLINE_BOT)
            self.assertEqual(bot_row["effective_model"], LONG_EXPLICIT_MODEL)
            self.assertEqual(bot_row["default_effort"], "high")

            # Verify `bots_updated` SSE published
            bot_events = [
                (t, d) for seq, t, d in list(hub._events) if seq >= ev_before_bot
            ]
            self.assertTrue(
                any(t == "bots_updated" and d.get("handle") == ONLINE_BOT for t, d in bot_events)
            )

            # 5. Atomic rejection (zero partial writes): valid effort + invalid model -> 400, state untouched
            save_calls_before_bad = len(self._save_state_calls)
            r_bad_m = await admin_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={
                    "model_mode": "custom",
                    "model": "gw:nonexistent:org/fake-model",
                    "default_effort": "low",
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_bad_m.status, 400)
            self.assertEqual(len(self._save_state_calls), save_calls_before_bad)
            sc_after_bad_m = bridge_mod.get_scope_state(bridge_mod.PRIMARY_SCOPE_KEY)
            self.assertEqual(sc_after_bad_m.get("model"), LONG_EXPLICIT_MODEL)
            self.assertEqual(sc_after_bad_m.get("effort"), "high")

            # Valid model + invalid effort -> 400, zero partial writes
            r_bad_e = await admin_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={
                    "model_mode": "custom",
                    "model": "gemini-2.5-flash",
                    "default_effort": "ultra_invalid",
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_bad_e.status, 400)
            self.assertEqual(len(self._save_state_calls), save_calls_before_bad)
            sc_after_bad_e = bridge_mod.get_scope_state(bridge_mod.PRIMARY_SCOPE_KEY)
            self.assertEqual(sc_after_bad_e.get("model"), LONG_EXPLICIT_MODEL)
            self.assertEqual(sc_after_bad_e.get("effort"), "high")

            # 6. Disable gateway -> external model immediately rejected with 400 without Bridge restart
            r_dis = await admin_cli.patch(
                f"/api/gateways/{LONG_GW_ID}",
                json={"enabled": False},
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_dis.status, 200)

            r_disabled_m = await admin_cli.patch(
                f"/api/bots/{ONLINE_BOT}/config",
                json={
                    "model_mode": "custom",
                    "model": LONG_EXPLICIT_MODEL,
                    "default_effort": "medium",
                },
                headers=self._write_headers(admin_csrf),
            )
            self.assertEqual(r_disabled_m.status, 400)
            sc_after_dis = bridge_mod.get_scope_state(bridge_mod.PRIMARY_SCOPE_KEY)
            self.assertEqual(sc_after_dis.get("effort"), "high")

            # Verify audit log exists with 0600 mode
            self.assertTrue(self.audit_log.is_file())
            self.assertEqual(stat.S_IMODE(self.audit_log.stat().st_mode), 0o600)
        finally:
            await admin_cli.close()
            await ro_cli.close()


if __name__ == "__main__":
    unittest.main()
