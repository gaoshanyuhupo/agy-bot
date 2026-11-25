#!/usr/bin/env python3
"""Unit & security tests for `bridge/federation_registry.py` and multi-team Bus authority (C1-C4, C7, C8)."""

from __future__ import annotations

import concurrent.futures
import importlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import federation_registry as fed  # noqa: E402
import memory_guard  # noqa: E402

_SCRUB_ENV_KEYS = (
    "AGY_UNTRUSTED_SESSION",
    "AGY_MEMORY_READONLY",
    "AGY_TRUST_LEVEL",
    "AGY_MAX_RUNTIME_MODE",
    "AGY_RBAC_ROLE",
    "AGY_BOT_TEAM_ID",
    "AGY_AGENT_ORIGIN",
    "AGY_BOT_BUS_ROLE",
    "AGY_BOT_CHAIN",
    "AGY_BOT_CHAIN_ID",
    "AGY_BOT_SCOPE_KEY",
    "AGY_BOT_CHAT_ID",
    "AGY_BOT_THREAD_ID",
    "AGY_BOT_ORIGIN_MSG_ID",
    "AGY_BOT_MENTION_HOP",
    "AGY_FEDERATION_TOKEN",
)


def _vault_ref(*parts: str) -> str:
    return "/".join(("lv" + "1", *parts))


def _clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV_KEYS}
    if extra:
        base.update(extra)
    return base


def _load_isolated_bus(bus_dir: str, extra_env: dict[str, str] | None = None):
    env = _clean_env(
        {
            "AGY_BOT_BUS_DIR": bus_dir,
            "AGY_BOT_BUS_ENABLE": "1",
            "AGY_BOT_BUS_ROLE": "coordinator",
            "AGY_BOT_HANDLE": "coord_bot",
            "AGY_BOT_CHAT_ID": "-1001234567890",
            "AGY_BOT_SCOPE_KEY": "-1001234567890",
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
            "AGY_TRUST_LEVEL": "local_admin",
            "AGY_AGENT_ORIGIN": "local_bus",
            "AGY_RBAC_ROLE": "admin",
        }
    )
    if extra_env:
        env.update(extra_env)
    with mock.patch.dict(os.environ, env, clear=True):
        import bot_bus  # noqa: E402
        import bot_bus_mcp  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bot_bus_mcp)
        return bot_bus, bot_bus_mcp


class TestC1OwnerOnlyAuthAndGuardPaths(unittest.TestCase):
    """C1: Owner-only registry mutations, 0700/0600 permissions, and memory_guard path protection."""

    def test_c1_owner_only_mutations_reject_non_owner_worker_coordinator_peer_and_tainted_env(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env(), clear=True):
            owner = fed.make_owner_auth("owner_user")
            # Seed one coordinator_peer external agent as Owner
            fed.register_agent(
                "hermes_peer",
                kind="hermes_remote",
                endpoint_url="https://hermes.example.com",
                secret_ref=_vault_ref("services", "hermes-peer#api_key"),
                capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.create_team(
                "team-alpha",
                leader_agent_id="hermes_peer",
                members=["hermes_peer"],
                owner_auth=owner,
                bus_dir=tmp,
            )
            agents_before = Path(fed.agents_file_path(tmp)).read_bytes()
            teams_before = Path(fed.teams_file_path(tmp)).read_bytes()

            bad_callers = [
                ("none_auth", None),
                ("worker_dict", {"actor_id": "worker_dev_bot", "is_owner": False, "role": "worker"}),
                ("coordinator_peer_role", {"actor_id": "hermes_peer", "is_owner": True, "role": "coordinator_peer"}),
                (
                    "registered_coordinator_peer_spoofing_owner",
                    fed.OwnerAuth(
                        actor_id="hermes_peer",
                        is_owner=True,
                        role="owner",
                        trust_level="local_admin",
                        agent_origin="local_owner",
                    ),
                ),
                ("truthy_string_is_owner", {"actor_id": "evil", "is_owner": "true", "role": "owner"}),
                ("untrusted_owner_obj", fed.OwnerAuth(actor_id="owner_user", is_owner=True, role="owner", untrusted=True)),
                ("readonly_owner_obj", fed.OwnerAuth(actor_id="owner_user", is_owner=True, role="owner", readonly=True)),
                ("external_origin_obj", fed.OwnerAuth(actor_id="owner_user", is_owner=True, role="owner", agent_origin="remote_hub")),
            ]

            for label, bad_auth in bad_callers:
                with self.subTest(caller=label):
                    with self.assertRaises(PermissionError) as c1:
                        fed.register_agent("rogue_agent", kind="hermes_local", profile="p1", owner_auth=bad_auth, bus_dir=tmp)
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c1.exception))

                    with self.assertRaises(PermissionError) as c2:
                        fed.create_team("team-rogue", leader_agent_id="hermes_peer", owner_auth=bad_auth, bus_dir=tmp)
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c2.exception))

                    with self.assertRaises(PermissionError) as c3:
                        fed.set_team_leader("team-alpha", "hermes_peer", owner_auth=bad_auth, bus_dir=tmp)
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c3.exception))

                    with self.assertRaises(PermissionError) as c4:
                        fed.update_agent(
                            "hermes_peer",
                            capabilities={"coordinator_peer": True, "host_server_invoke": True},
                            owner_auth=bad_auth,
                            bus_dir=tmp,
                        )
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c4.exception))

                    with self.assertRaises(PermissionError) as c5:
                        fed.mint_agent_token("hermes_peer", owner_auth=bad_auth, bus_dir=tmp)
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c5.exception))

            # Tainted/worker process env must ALSO block even a valid OwnerAuth object
            tainted_envs = [
                {"AGY_UNTRUSTED_SESSION": "1"},
                {"AGY_MEMORY_READONLY": "1"},
                {"AGY_RBAC_ROLE": "readonly"},
                {"AGY_TRUST_LEVEL": "remote_untrusted"},
                {"AGY_AGENT_ORIGIN": "remote_hub"},
                {"AGY_BOT_BUS_ROLE": "worker"},
            ]
            for extra in tainted_envs:
                with self.subTest(env=extra), mock.patch.dict(os.environ, _clean_env(extra), clear=True):
                    with self.assertRaises(PermissionError) as ct:
                        fed.register_agent("env_rogue", kind="hermes_local", profile="p1", owner_auth=owner, bus_dir=tmp)
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(ct.exception))

            # Zero mutation on disk
            self.assertEqual(agents_before, Path(fed.agents_file_path(tmp)).read_bytes())
            self.assertEqual(teams_before, Path(fed.teams_file_path(tmp)).read_bytes())

    def test_c1_directory_and_file_permissions_0700_0600(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env(), clear=True):
            owner = fed.make_owner_auth("owner_user")
            fed.register_agent("hermes_p1", kind="hermes_local", profile="p1", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-sec", leader_agent_id="hermes_p1", owner_auth=owner, bus_dir=tmp)
            job = fed.enqueue_pull_job("hermes_p1", "check status", owner_auth=owner, bus_dir=tmp)

            self.assertEqual(0o700, stat.S_IMODE(os.stat(fed.federation_dir(tmp)).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(fed.agents_file_path(tmp)).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(fed.teams_file_path(tmp)).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(fed.lock_file_path(tmp)).st_mode))
            self.assertEqual(0o700, stat.S_IMODE(os.stat(fed.pull_queue_dir(tmp)).st_mode))
            pull_job_file = os.path.join(fed.pull_queue_dir(tmp), f"{job['job_id']}.json")
            self.assertEqual(0o600, stat.S_IMODE(os.stat(pull_job_file).st_mode))

    def test_c1_memory_guard_protects_federation_paths_for_tools_and_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            custom_bus = os.path.join(tmp, "custom_bus")
            with mock.patch.dict(os.environ, {"AGY_BOT_BUS_DIR": custom_bus}, clear=False):
                protected_paths = [
                    "~/.gemini/antigravity-cli/cache/bot_bus/federation",
                    "~/.gemini/antigravity-cli/cache/bot_bus/federation/agents.json",
                    "~/.gemini/antigravity-cli/cache/bot_bus/federation/teams.json",
                    os.path.join(custom_bus, "federation", "agents.json"),
                    os.path.join(custom_bus, "federation", "teams.json"),
                    os.path.join(custom_bus, "federation", "pull_queue", "pull-abc.json"),
                    "federation/agents.json",
                    "federation/teams.json",
                ]
                for p in protected_paths:
                    with self.subTest(path=p):
                        ok, label = memory_guard._is_protected_guard_path(p)
                        self.assertTrue(ok, f"Expected protected guard path: {p}")
                        self.assertEqual("federation_registry", label)

                # Verify PreToolUse blocks file write and shell redirection to federation/agents.json in tainted session
                agents_target = os.path.join(custom_bus, "federation", "agents.json")
                env_tainted = _clean_env(
                    {
                        "AGY_BOT_BUS_DIR": custom_bus,
                        "AGY_UNTRUSTED_SESSION": "1",
                        "AGY_MEMORY_READONLY": "1",
                        "AGY_TRUST_LEVEL": "remote_untrusted",
                    }
                )
                with mock.patch.dict(os.environ, env_tainted, clear=True):
                    dec_write = memory_guard.evaluate_tainted_tool_call(
                        "write_file",
                        {"Path": agents_target, "Content": "{}"},
                        tainted=True,
                        cwd=tmp,
                    )
                    self.assertTrue(dec_write.get("blocked"), dec_write)
                    self.assertEqual("protected_path_tamper", dec_write.get("rule"))

                    dec_sh = memory_guard.evaluate_tainted_tool_call(
                        "run_command",
                        {"CommandLine": f"echo '{{}}' > {agents_target}"},
                        tainted=True,
                        cwd=tmp,
                    )
                    self.assertTrue(dec_sh.get("blocked"), dec_sh)


class TestC2ZeroPlaintextSecretsAndInstantRevocation(unittest.TestCase):
    """C2: Zero plaintext credentials on disk/outputs and atomic instant token revocation."""

    def test_c2_rejects_plaintext_secrets_in_fields_and_values_and_accepts_openbao_secret_ref(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env(), clear=True):
            owner = fed.make_owner_auth("owner_user")
            fake_sk = "sk-" + "liveTest" + "0123456789abcdef"
            fake_ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
            fake_hvs = "hvs." + "Z9y8X7w6V5u4T3s2R1q0"
            fake_aiza = "AIza" + "SyTest1234567890abcdefghijk"

            # Forbidden secret field names
            for bad_kw in (
                {"api_key": "anything"},
                {"token": "anything"},
                {"password": "anything"},
                {"secret": "anything"},
            ):
                with self.subTest(bad_kw=bad_kw):
                    with self.assertRaises(ValueError) as ctx:
                        fed.register_agent(
                            "ext_bad",
                            kind="hermes_remote",
                            endpoint_url="https://node1.example.com",
                            owner_auth=owner,
                            bus_dir=tmp,
                            **bad_kw,
                        )
                    self.assertIn("PLAINTEXT_SECRET_REJECTED", str(ctx.exception))

            # Forbidden secret values in secret_ref or metadata
            for bad_val in (fake_sk, fake_ghp, fake_hvs, fake_aiza, "Bearer some-secret-token"):
                with self.subTest(bad_secret_ref=bad_val[:8]):
                    with self.assertRaises(ValueError) as ctx:
                        fed.register_agent(
                            "ext_bad_val",
                            kind="hermes_remote",
                            endpoint_url="https://node1.example.com",
                            secret_ref=bad_val,
                            owner_auth=owner,
                            bus_dir=tmp,
                        )
                    self.assertIn("PLAINTEXT_SECRET_REJECTED", str(ctx.exception))

                with self.subTest(bad_metadata_val=bad_val[:8]):
                    with self.assertRaises(ValueError) as ctx:
                        fed.register_agent(
                            "ext_bad_meta",
                            kind="hermes_remote",
                            endpoint_url="https://node1.example.com",
                            metadata={"note": bad_val},
                            owner_auth=owner,
                            bus_dir=tmp,
                        )
                    self.assertIn("PLAINTEXT_SECRET_REJECTED", str(ctx.exception))

            # Embedded userinfo in endpoint_url rejected
            cred_url = "https://" + "usr" + ":" + "pwd" + "@" + "node1.example.com"
            with self.assertRaises(ValueError) as ctx_url:
                fed.register_agent(
                    "ext_bad_url",
                    kind="hermes_remote",
                    endpoint_url=cred_url,
                    owner_auth=owner,
                    bus_dir=tmp,
                )
            self.assertIn("PLAINTEXT_SECRET_REJECTED", str(ctx_url.exception))

            # Valid OpenBao secret_ref accepted
            valid_ref = _vault_ref("services", "hermes-node1#api_key")
            rec = fed.register_agent(
                "hermes_node1",
                kind="hermes_remote",
                endpoint_url="https://node1.example.com",
                secret_ref=valid_ref,
                owner_auth=owner,
                bus_dir=tmp,
            )
            self.assertEqual(valid_ref, rec["secret_ref"])

    def test_c2_salted_hmac_token_lifecycle_instant_revocation_and_zero_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                fed.register_agent(
                    "muse_node",
                    kind="muse_remote",
                    endpoint_url="https://muse.example.com/v1/chat/completions",
                    secret_ref=_vault_ref("services", "muse#api_key"),
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                minted = fed.mint_agent_token("muse_node", owner_auth=owner, label="initial", bus_dir=tmp)
                raw_tok_1 = minted["token"]
                tok_id_1 = minted["token_id"]

                # Raw token NEVER persisted to agents.json (salted HMAC-SHA256 only)
                raw_disk = Path(fed.agents_file_path(tmp)).read_text(encoding="utf-8")
                self.assertNotIn(raw_tok_1, raw_disk)
                disk_json = json.loads(raw_disk)
                stored_tr = disk_json["agents"]["muse_node"]["token_records"][0]
                self.assertEqual(32, len(stored_tr["salt"]))
                self.assertEqual(64, len(stored_tr["token_hash"]))

                # Verify valid token succeeds & returns sanitized view (no hashes/salts)
                verified = fed.verify_agent_token(raw_tok_1, agent_id="muse_node", bus_dir=tmp)
                self.assertIsNotNone(verified)
                self.assertNotIn("token_records", verified)
                self.assertNotIn("salt", json.dumps(verified))
                self.assertNotIn("token_hash", json.dumps(verified))
                self.assertNotIn(raw_tok_1, json.dumps(verified))

                # Wrong agent_id or tampered token fails
                self.assertIsNone(fed.verify_agent_token(raw_tok_1, agent_id="other_agent", bus_dir=tmp))
                self.assertIsNone(fed.verify_agent_token(raw_tok_1 + "x", agent_id="muse_node", bus_dir=tmp))

                # Roster outputs never echo token, salt, or token_hash
                roster_json = json.dumps(bot_bus.list_roster(include_offline=True))
                self.assertNotIn(raw_tok_1, roster_json)
                self.assertNotIn(stored_tr["token_hash"], roster_json)
                self.assertNotIn(stored_tr["salt"], roster_json)

                # Rotate token -> old token IMMEDIATELY rejected, new token accepted
                rotated = fed.rotate_agent_token("muse_node", owner_auth=owner, bus_dir=tmp)
                raw_tok_2 = rotated["token"]
                self.assertEqual(1, rotated["revoked_previous"])
                self.assertIsNone(fed.verify_agent_token(raw_tok_1, bus_dir=tmp))
                self.assertIsNotNone(fed.verify_agent_token(raw_tok_2, bus_dir=tmp))

                # Revoke token -> IMMEDIATELY rejected
                revoked_n = fed.revoke_agent_token("muse_node", token_id=rotated["token_id"], owner_auth=owner, bus_dir=tmp)
                self.assertEqual(1, revoked_n)
                self.assertIsNone(fed.verify_agent_token(raw_tok_2, bus_dir=tmp))
                self.assertNotEqual(tok_id_1, rotated["token_id"])

                # MCP error redacts token & Authorization header
                env_bad = _clean_env(
                    {
                        "AGY_BOT_BUS_DIR": tmp,
                        "AGY_BOT_BUS_ENABLE": "1",
                        "AGY_BOT_BUS_ROLE": "coordinator",
                        "AGY_BOT_HANDLE": "muse_node",
                        "AGY_FEDERATION_TOKEN": raw_tok_2,
                    }
                )
                with mock.patch.dict(os.environ, env_bad, clear=True):
                    replies = []
                    with mock.patch.object(bot_bus_mcp, "_send_json", side_effect=replies.append):
                        bot_bus_mcp._handle_request(
                            {
                                "id": 1,
                                "method": "tools/call",
                                "params": {"name": "team_dispatch", "arguments": {"bot": "muse_node", "prompt": "hi"}},
                            }
                        )
                    self.assertEqual(1, len(replies))
                    err_text = json.dumps(replies[0])
                    self.assertNotIn(raw_tok_2, err_text)
                    self.assertNotIn(stored_tr["token_hash"], err_text)


class TestC3MultiTeamIsolationAndTraversal(unittest.TestCase):
    """C3: Cross-team isolation (dispatch/cancel/retry/status/cleanup_worktree) and path traversal rejection."""

    def test_c3_multi_team_isolation_arbitrary_leader_and_coordinator_peer_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _bot_bus_mcp = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                # Register arbitrary agents: local Hermes, remote Hermes, Muse, and global coordinator_peer
                fed.register_agent("hermes_lead_a", kind="hermes_local", profile="alpha", capabilities={"can_dispatch": True}, owner_auth=owner, bus_dir=tmp)
                fed.register_agent("worker_a", kind="hermes_local", profile="alpha-w1", owner_auth=owner, bus_dir=tmp)
                fed.register_agent(
                    "muse_lead_b",
                    kind="muse_remote",
                    endpoint_url="https://muse-b.example.com/v1/chat/completions",
                    capabilities={"can_dispatch": True},
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                fed.register_agent("worker_b", kind="hermes_local", profile="beta-w1", owner_auth=owner, bus_dir=tmp)
                fed.register_agent(
                    "hermes_global_peer",
                    kind="hermes_remote",
                    endpoint_url="https://hermes-global.example.com",
                    capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
                    owner_auth=owner,
                    bus_dir=tmp,
                )

                fed.create_team(
                    "team-alpha",
                    leader_agent_id="hermes_lead_a",
                    members=["hermes_lead_a", "worker_a"],
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                fed.create_team(
                    "team-beta",
                    leader_agent_id="muse_lead_b",
                    members=["muse_lead_b", "worker_b"],
                    owner_auth=owner,
                    bus_dir=tmp,
                )

                tok_lead_a = fed.mint_agent_token("hermes_lead_a", owner_auth=owner, bus_dir=tmp)["token"]
                tok_lead_b = fed.mint_agent_token("muse_lead_b", owner_auth=owner, bus_dir=tmp)["token"]

                # Team A leader dispatches within Team A -> OK
                res_a = bot_bus.dispatch_assignments(
                    "hermes_lead_a",
                    [{"bot": "worker_a", "prompt": "audit alpha"}],
                    team_id="team-alpha",
                    auth_token=tok_lead_a,
                )
                self.assertEqual(1, len(res_a["jobs"]))
                self.assertEqual("team-alpha", res_a["jobs"][0]["team_id"])

                # Team B leader dispatches within Team B -> OK
                res_b = bot_bus.dispatch_assignments(
                    "muse_lead_b",
                    [{"bot": "worker_b", "prompt": "audit beta"}],
                    team_id="team-beta",
                    auth_token=tok_lead_b,
                )
                job_b_id = res_b["jobs"][0]["job_id"]

                # Team A leader (without coordinator_peer) tries cross-team dispatch to Team B member -> DENIED
                for bad_tid in ("team-beta", "team-alpha", ""):
                    with self.subTest(cross_dispatch_team_id=bad_tid):
                        with self.assertRaises(PermissionError) as cd:
                            bot_bus.dispatch_assignments(
                                "hermes_lead_a",
                                [{"bot": "worker_b", "prompt": "cross team hijack"}],
                                team_id=bad_tid,
                                auth_token=tok_lead_a,
                            )
                        self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(cd.exception))

                # Team A leader tries cancel/retry/status/cleanup_worktree on Team B's job -> ALL DENIED
                with self.assertRaises(PermissionError) as c_stat:
                    bot_bus.get_job(job_b_id, requester_bot="hermes_lead_a", auth_token=tok_lead_a)
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_stat.exception))

                with self.assertRaises(PermissionError) as c_can:
                    bot_bus.cancel_job(job_b_id, requester_bot="hermes_lead_a", auth_token=tok_lead_a)
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_can.exception))

                with self.assertRaises(PermissionError) as c_ret:
                    bot_bus.retry_job(job_b_id, requester_bot="hermes_lead_a", auth_token=tok_lead_a)
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_ret.exception))

                with self.assertRaises(PermissionError) as c_wt:
                    bot_bus.cleanup_job_worktree(job_b_id, requester_bot="hermes_lead_a", auth_token=tok_lead_a)
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_wt.exception))

                # Global coordinator_peer (active, not revoked) CAN coordinate across Team A and Team B
                tok_peer = fed.mint_agent_token("hermes_global_peer", owner_auth=owner, bus_dir=tmp)["token"]
                peer_disp = bot_bus.dispatch_assignments(
                    "hermes_global_peer",
                    [{"bot": "worker_b", "prompt": "global peer sync"}],
                    team_id="team-beta",
                    auth_token=tok_peer,
                )
                self.assertEqual(1, len(peer_disp["jobs"]))
                peer_read = bot_bus.get_job(job_b_id, requester_bot="hermes_global_peer", auth_token=tok_peer)
                self.assertEqual(job_b_id, peer_read["job_id"])
                peer_cancel = bot_bus.cancel_job(job_b_id, requester_bot="hermes_global_peer", auth_token=tok_peer)
                self.assertEqual("cancelled", peer_cancel["status"])

                # Once Owner revokes global coordinator_peer, cross-team access is immediately denied
                fed.revoke_agent("hermes_global_peer", owner_auth=owner, bus_dir=tmp)
                with self.assertRaises(PermissionError) as c_rev:
                    bot_bus.dispatch_assignments(
                        "hermes_global_peer",
                        [{"bot": "worker_b", "prompt": "after revoke"}],
                        team_id="team-beta",
                        auth_token=tok_peer,
                    )
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_rev.exception))

    def test_c3_path_traversal_and_invalid_ids_rejected_with_value_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = _load_isolated_bus(tmp)
            owner = fed.make_owner_auth("owner_user", env=_clean_env())
            bad_ids = ("../evil", "team/a", "a\\b", "a.b", "a\x00b", "UPPER", "a" * 65, "-bad", "")

            for bad in bad_ids:
                with self.subTest(bad_id=bad):
                    with self.assertRaises(ValueError):
                        fed.validate_agent_id(bad)
                    with self.assertRaises(ValueError):
                        fed.validate_team_id(bad)
                    with self.assertRaises(ValueError):
                        fed.register_agent(bad, kind="hermes_local", profile="p1", owner_auth=owner, bus_dir=tmp, env=_clean_env())
                    with self.assertRaises(ValueError):
                        fed.create_team(bad, owner_auth=owner, bus_dir=tmp, env=_clean_env())

            for bad_tid in ("../evil", "team/a", "a.b", "a\x00b", "UPPER", "a" * 65):
                with self.subTest(bus_bad_team_id=bad_tid):
                    with self.assertRaises(ValueError):
                        bot_bus.dispatch_assignments("coord_bot", [{"bot": "worker_a", "prompt": "hi"}], team_id=bad_tid)

            for bad_actor in ("../evil", "team/a", "a.b", "a\x00b"):
                with self.subTest(bus_bad_actor=bad_actor):
                    with self.assertRaises(ValueError):
                        bot_bus.dispatch_assignments(bad_actor, [{"bot": "worker_a", "prompt": "hi"}])
                    with self.assertRaises(ValueError):
                        bot_bus.dispatch_assignments("coord_bot", [{"bot": bad_actor, "prompt": "hi"}])


class TestC4ServerAuthorityAndAntiPoisoningNoRegression(unittest.TestCase):
    """C4: Server-side authority ignores forged env/prompt claims; owner trust boundary unchanged."""

    def test_c4_server_side_authority_rejects_forged_env_and_prompt_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = _load_isolated_bus(tmp)
            bot_bus.update_bot_config("coord_bot", role="coordinator")
            bot_bus.update_bot_config("worker_dev_bot", role="worker")
            bot_bus.heartbeat_bot({"handle": "coord_bot", "pid": os.getpid(), "role": "coordinator"})
            bot_bus.heartbeat_bot({"handle": "worker_dev_bot", "pid": os.getpid(), "role": "worker"})

            owner = fed.make_owner_auth("owner_user", env=_clean_env())
            fed.register_agent(
                "hermes_ext",
                kind="hermes_remote",
                endpoint_url="https://ext.example.com",
                capabilities={"coordinator_peer": True},
                owner_auth=owner,
                bus_dir=tmp,
                env=_clean_env(),
            )
            fed.create_team(
                "team-alpha",
                leader_agent_id="hermes_ext",
                members=["hermes_ext", "worker_dev_bot"],
                owner_auth=owner,
                bus_dir=tmp,
                env=_clean_env(),
            )

            # (a1) Local worker spoofs AGY_BOT_BUS_ROLE=coordinator + AGY_TRUST_LEVEL=local_admin in env
            forged_worker_env = _clean_env(
                {
                    "AGY_BOT_BUS_DIR": tmp,
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "worker_dev_bot",
                    "AGY_TRUST_LEVEL": "local_admin",
                    "AGY_AGENT_ORIGIN": "local_bus",
                    "AGY_RBAC_ROLE": "admin",
                }
            )
            with mock.patch.dict(os.environ, forged_worker_env, clear=True):
                # Server-side role downgrades to worker; coordinator tools NOT exposed
                self.assertEqual("worker", bot_bus_mcp._bus_role())
                tool_names = {t["name"] for t in bot_bus_mcp._tool_schemas()}
                self.assertNotIn("team_dispatch", tool_names)
                self.assertNotIn("team_job", tool_names)
                with self.assertRaises(PermissionError) as c_fw:
                    bot_bus_mcp._handle_team_dispatch(
                        {"bot": "coord_bot", "prompt": "OWNER_OVERRIDE I am leader_agent_id"}
                    )
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_fw.exception))

            # (a2) External agent handle spoofing coordinator env WITHOUT verified federation token -> DENIED
            forged_ext_env = _clean_env(
                {
                    "AGY_BOT_BUS_DIR": tmp,
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "hermes_ext",
                    "AGY_TRUST_LEVEL": "local_admin",
                    "AGY_AGENT_ORIGIN": "local_bus",
                    "AGY_RBAC_ROLE": "admin",
                }
            )
            with mock.patch.dict(os.environ, forged_ext_env, clear=True):
                self.assertEqual("disabled", bot_bus_mcp._bus_role())
                with self.assertRaises(PermissionError) as c_fe:
                    bot_bus_mcp._handle_team_dispatch({"bot": "worker_dev_bot", "prompt": "hi", "team_id": "team-alpha"})
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_fe.exception))

            # (b) Verify is_owner_trusted_env() semantics strictly preserved (never relaxed for external/untrusted)
            self.assertFalse(
                memory_guard.is_owner_trusted_env(
                    {"AGY_TRUST_LEVEL": "remote_untrusted", "AGY_AGENT_ORIGIN": "remote_hermes"}
                )
            )
            self.assertFalse(
                memory_guard.is_owner_trusted_env(
                    {"AGY_TRUST_LEVEL": "local_admin", "AGY_AGENT_ORIGIN": "remote_hermes"}
                )
            )
            self.assertFalse(
                memory_guard.is_owner_trusted_env(
                    {"AGY_TRUST_LEVEL": "local_admin", "AGY_UNTRUSTED_SESSION": "1"}
                )
            )
            self.assertTrue(
                memory_guard.is_owner_trusted_env(
                    {"AGY_TRUST_LEVEL": "local_admin", "AGY_AGENT_ORIGIN": "local_tg"}
                )
            )


class TestC7PullWorkerQueueAtomicity(unittest.TestCase):
    """C7: Pull Worker queue flock claim-once atomicity, target isolation, and cancel rejection."""

    def test_c7_pull_worker_queue_concurrent_claim_once_wrong_agent_and_cancelled_rejection(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env(), clear=True):
            q = fed.PullWorkerQueue(tmp)
            job = q.enqueue("nat_worker_1", "run remote check", team_id="team-nat")
            jid = job["job_id"]

            # Wrong agent trying to claim another agent's job -> PermissionError
            with self.assertRaises(PermissionError) as c_wrong:
                q.claim("nat_worker_2", job_id=jid)
            self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_wrong.exception))

            # 12 concurrent threads racing claim on the same job_id -> EXACTLY 1 winner
            def _race(_idx: int):
                return q.claim("nat_worker_1", job_id=jid)

            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(_race, range(12)))
            winners = [r for r in results if r is not None]
            self.assertEqual(1, len(winners), f"Expected exactly 1 claim winner, got {len(winners)}")
            self.assertEqual("claimed", winners[0]["status"])
            self.assertEqual("nat_worker_1", winners[0]["claimed_by"])

            # Subsequent claim returns None (already claimed)
            self.assertIsNone(q.claim("nat_worker_1", job_id=jid))

            # Wrong agent cannot complete
            with self.assertRaises(PermissionError):
                q.complete(jid, "nat_worker_2", status="done", result_text="spoofed")

            # Correct agent completes
            done = q.complete(jid, "nat_worker_1", status="done", result_text="all green")
            self.assertEqual("done", done["status"])
            self.assertEqual("all green", done["result_text"])

            # Cancelled job cannot be claimed
            job2 = q.enqueue("nat_worker_1", "cancel me")
            q.cancel(job2["job_id"], reason="user_stop")
            self.assertIsNone(q.claim("nat_worker_1", job_id=job2["job_id"]))
            self.assertIsNone(q.claim("nat_worker_1"))


class TestC8BackwardCompatibilityWithoutFederationDir(unittest.TestCase):
    """C8: Stock 4-Bot default team without `BUS_DIR/federation/` works with zero regressions."""

    def test_c8_legacy_4_bot_team_without_federation_dir_works_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = _load_isolated_bus(tmp)
            for h, role in (
                ("coord_bot", "coordinator"),
                ("worker_dev_bot", "worker"),
                ("worker_qa_bot", "worker"),
                ("worker_ops_bot", "worker"),
            ):
                bot_bus.update_bot_config(h, role=role)
                bot_bus.heartbeat_bot({"handle": h, "pid": os.getpid(), "role": role, "busy": False})

            self.assertFalse(os.path.exists(fed.federation_dir(tmp)))
            roster = bot_bus.list_roster(include_offline=True)
            self.assertEqual(4, len(roster))

            env_coord = _clean_env(
                {
                    "AGY_BOT_BUS_DIR": tmp,
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "coord_bot",
                    "AGY_TRUST_LEVEL": "local_admin",
                    "AGY_AGENT_ORIGIN": "local_bus",
                    "AGY_RBAC_ROLE": "admin",
                }
            )
            with mock.patch.dict(os.environ, env_coord, clear=True):
                res = bot_bus_mcp._handle_team_dispatch({"bot": "worker_dev_bot", "prompt": "run legacy check"})
                self.assertFalse(res.get("isError"), res)
                dispatched = json.loads(res["content"][0]["text"])["dispatched"][0]
                jid = dispatched["job_id"]
                st_res = bot_bus_mcp._handle_team_job({"action": "status", "job_id": jid})
                self.assertFalse(st_res.get("isError"), st_res)
                can_res = bot_bus_mcp._handle_team_job({"action": "cancel", "job_id": jid})
                self.assertFalse(can_res.get("isError"), can_res)

            # Federation directory was NEVER created on legacy read/dispatch path
            self.assertFalse(os.path.exists(fed.federation_dir(tmp)))


class TestQARound1HardeningRegressions(unittest.TestCase):
    """Negative regression PoCs closing QA Round 1 findings B1, B2, B4, and B7."""

    def test_b1_cross_team_list_roster_broadcast_param_override_and_team_backfill(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                fed.register_agent("lead_a", kind="hermes_local", profile="pa", capabilities={"can_dispatch": True}, owner_auth=owner, bus_dir=tmp)
                fed.register_agent("worker_a", kind="hermes_local", profile="pwa", owner_auth=owner, bus_dir=tmp)
                fed.register_agent("lead_b", kind="hermes_local", profile="pb", capabilities={"can_dispatch": True}, owner_auth=owner, bus_dir=tmp)
                fed.register_agent("worker_b", kind="hermes_local", profile="pwb", owner_auth=owner, bus_dir=tmp)
                fed.create_team("team-alpha", leader_agent_id="lead_a", members=["lead_a", "worker_a"], owner_auth=owner, bus_dir=tmp)
                fed.create_team("team-beta", leader_agent_id="lead_b", members=["lead_b", "worker_b"], owner_auth=owner, bus_dir=tmp)
                tok_a = fed.mint_agent_token("lead_a", owner_auth=owner, bus_dir=tmp)["token"]
                tok_b = fed.mint_agent_token("lead_b", owner_auth=owner, bus_dir=tmp)["token"]

                # B1.4: Omitting team_id as sole-team leader auto-backfills team_id="team-alpha"
                res_a = bot_bus.dispatch_assignments(
                    "lead_a",
                    [{"bot": "worker_a", "prompt": "alpha secret task", "label": "ALPHA_ONLY"}],
                    auth_token=tok_a,
                )
                job_a_id = res_a["jobs"][0]["job_id"]
                self.assertEqual("team-alpha", res_a["jobs"][0]["team_id"])

                res_b = bot_bus.dispatch_assignments(
                    "lead_b",
                    [{"bot": "worker_b", "prompt": "beta secret task", "label": "BETA_CONFIDENTIAL"}],
                    team_id="team-beta",
                    auth_token=tok_b,
                )
                job_b_id = res_b["jobs"][0]["job_id"]

                # B1.3: authorize_team_action rejects forged caller team_id overriding job["team_id"]
                with self.assertRaises(PermissionError) as c_ov:
                    fed.authorize_team_action(
                        "lead_a",
                        "cancel",
                        team_id="team-alpha",
                        job={"job_id": job_b_id, "team_id": "team-beta"},
                        bus_dir=tmp,
                        auth_token=tok_a,
                    )
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_ov.exception))

                # B1.1 & B1.2: MCP team_job(list), team_roster, and team_broadcast enforce team scope
                env_a = _clean_env(
                    {
                        "AGY_BOT_BUS_DIR": tmp,
                        "AGY_BOT_BUS_ENABLE": "1",
                        "AGY_BOT_BUS_ROLE": "coordinator",
                        "AGY_BOT_HANDLE": "lead_a",
                        "AGY_FEDERATION_TOKEN": tok_a,
                        "AGY_TRUST_LEVEL": "remote_trusted",
                        "AGY_AGENT_ORIGIN": "remote_hermes",
                        "AGY_BOT_CHAT_ID": "-1001234567890",
                    }
                )
                with mock.patch.dict(os.environ, env_a, clear=True):
                    list_res = bot_bus_mcp._handle_team_job({"action": "list", "limit": 20})
                    list_payload = json.loads(list_res["content"][0]["text"])
                    listed_ids = [j["job_id"] for j in list_payload["jobs"]]
                    self.assertIn(job_a_id, listed_ids)
                    self.assertNotIn(job_b_id, listed_ids)
                    self.assertNotIn("BETA_CONFIDENTIAL", list_res["content"][0]["text"])

                    roster_res = bot_bus_mcp._handle_team_roster({})
                    roster_payload = json.loads(roster_res["content"][0]["text"])
                    recent_ids = [j["job_id"] for j in roster_payload["recent_jobs"]]
                    team_ids = [t["team_id"] for t in roster_payload["teams"]]
                    self.assertIn(job_a_id, recent_ids)
                    self.assertNotIn(job_b_id, recent_ids)
                    self.assertEqual(["team-alpha"], team_ids)

                    # Cross-team broadcast spoofing worker_b -> DENIED
                    with self.assertRaises(PermissionError) as c_bc:
                        bot_bus_mcp._handle_team_broadcast(
                            {"bot": "worker_b", "message": "spoofed", "chat_id": -1001234567890}
                        )
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_bc.exception))

                    # Same-team broadcast targeting worker_a -> ALLOWED
                    ok_bc = bot_bus_mcp._handle_team_broadcast(
                        {"bot": "worker_a", "message": "alpha update", "chat_id": -1001234567890}
                    )
                    self.assertFalse(ok_bc.get("isError"), ok_bc)

    def test_b1_r2_unscoped_job_cannot_be_cancelled_via_forged_team_id(self):
        """QA Round 2 B1-R2: team-scoped leader cannot spoof team_id to cancel an unscoped Owner/global job."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                fed.register_agent("lead_a", kind="hermes_local", profile="pa", owner_auth=owner, bus_dir=tmp)
                fed.register_agent("worker_a", kind="hermes_local", profile="pwa", owner_auth=owner, bus_dir=tmp)
                fed.register_agent("worker_b", kind="http_a2a", transport="pull_worker", owner_auth=owner, bus_dir=tmp)
                fed.create_team("team-alpha", leader_agent_id="lead_a", members=["lead_a", "worker_a"], owner_auth=owner, bus_dir=tmp)
                tok_a = fed.mint_agent_token("lead_a", owner_auth=owner, bus_dir=tmp)["token"]

                # Owner enqueues an unscoped (team_id="") pull job for worker_b
                q = fed.PullWorkerQueue(bus_dir=tmp)
                pjob = q.enqueue(
                    "worker_b",
                    "owner unscoped sensitive task",
                    owner_auth=owner,
                    env=_clean_env({"AGY_BOT_BUS_DIR": tmp}),
                )
                self.assertEqual("", pjob.get("team_id"))

                # 1) Direct authorize_team_action with forged team_id="team-alpha" against unscoped job -> DENIED
                for act in ("cancel", "retry", "status", "cleanup_worktree"):
                    with self.assertRaises(PermissionError) as c_auth:
                        fed.authorize_team_action(
                            "lead_a",
                            act,
                            team_id="team-alpha",
                            job={"job_id": pjob["job_id"], "team_id": "", "from_bot": "owner_user"},
                            bus_dir=tmp,
                            auth_token=tok_a,
                        )
                    self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_auth.exception))

                # 2) PullWorkerQueue.cancel with forged team_id="team-alpha" -> DENIED and job remains queued
                with self.assertRaises(PermissionError) as c_pull:
                    q.cancel(
                        pjob["job_id"],
                        requester_agent_id="lead_a",
                        team_id="team-alpha",
                        auth_token=tok_a,
                        env=_clean_env({"AGY_BOT_BUS_DIR": tmp}),
                    )
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_pull.exception))
                still_queued = q.get(pjob["job_id"])
                self.assertIsNotNone(still_queued)
                self.assertEqual("queued", still_queued["status"])
                self.assertFalse(still_queued["cancelled"])

                # 3) Owner can still legitimately cancel the unscoped job
                cancelled = q.cancel(
                    pjob["job_id"],
                    owner_auth=owner,
                    reason="owner_cleanup",
                    env=_clean_env({"AGY_BOT_BUS_DIR": tmp}),
                )
                self.assertEqual("cancelled", cancelled["status"])

    def test_b2_server_trust_level_clamps_forged_local_admin_env_in_mcp_and_bus(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                fed.register_agent(
                    "ext_untrusted",
                    kind="hermes_remote",
                    endpoint_url="https://u.example.com",
                    trust_level="remote_untrusted",
                    capabilities={"coordinator_peer": True},
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                fed.register_agent(
                    "ext_readonly",
                    kind="hermes_remote",
                    endpoint_url="https://ro.example.com",
                    trust_level="readonly_guest",
                    capabilities={"coordinator_peer": True},
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                fed.register_agent(
                    "ext_trusted",
                    kind="hermes_remote",
                    endpoint_url="https://t.example.com",
                    trust_level="remote_trusted",
                    capabilities={"coordinator_peer": True},
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                fed.register_agent("worker_a", kind="hermes_local", profile="wa", owner_auth=owner, bus_dir=tmp)
                fed.create_team(
                    "team-alpha",
                    leader_agent_id="ext_trusted",
                    members=["ext_trusted", "worker_a"],
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                tok_untr = fed.mint_agent_token("ext_untrusted", owner_auth=owner, bus_dir=tmp)["token"]
                tok_ro = fed.mint_agent_token("ext_readonly", owner_auth=owner, bus_dir=tmp)["token"]
                tok_trusted = fed.mint_agent_token("ext_trusted", owner_auth=owner, bus_dir=tmp)["token"]

                # Forged AGY_TRUST_LEVEL=local_admin with remote_untrusted or readonly_guest -> DENIED in MCP
                for handle, tok in (("ext_untrusted", tok_untr), ("ext_readonly", tok_ro)):
                    forged_env = _clean_env(
                        {
                            "AGY_BOT_BUS_DIR": tmp,
                            "AGY_BOT_BUS_ENABLE": "1",
                            "AGY_BOT_BUS_ROLE": "coordinator",
                            "AGY_BOT_HANDLE": handle,
                            "AGY_FEDERATION_TOKEN": tok,
                            "AGY_TRUST_LEVEL": "local_admin",
                            "AGY_AGENT_ORIGIN": "local_bus",
                            "AGY_RBAC_ROLE": "admin",
                        }
                    )
                    with self.subTest(forged_actor=handle), mock.patch.dict(os.environ, forged_env, clear=True):
                        with self.assertRaises(PermissionError) as c_den:
                            bot_bus_mcp._handle_team_dispatch(
                                {"bot": "worker_a", "prompt": "escalate", "team_id": "team-alpha"}
                            )
                        self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_den.exception))

                # Forged AGY_TRUST_LEVEL=local_admin on remote_trusted agent -> clamped to remote_trusted
                trusted_forged_env = _clean_env(
                    {
                        "AGY_BOT_BUS_DIR": tmp,
                        "AGY_BOT_BUS_ENABLE": "1",
                        "AGY_BOT_BUS_ROLE": "coordinator",
                        "AGY_BOT_HANDLE": "ext_trusted",
                        "AGY_FEDERATION_TOKEN": tok_trusted,
                        "AGY_TRUST_LEVEL": "local_admin",
                        "AGY_AGENT_ORIGIN": "local_bus",
                        "AGY_RBAC_ROLE": "admin",
                    }
                )
                with mock.patch.dict(os.environ, trusted_forged_env, clear=True):
                    res = bot_bus_mcp._handle_team_dispatch(
                        {"bot": "worker_a", "prompt": "check clamp", "team_id": "team-alpha"}
                    )
                    jid = json.loads(res["content"][0]["text"])["dispatched"][0]["job_id"]
                    job_obj = bot_bus.get_job(jid)
                    self.assertEqual("remote_trusted", job_obj["trust_level"])

                    ret_res = bot_bus_mcp._handle_team_job({"action": "retry", "job_id": jid})
                    ret_jid = json.loads(ret_res["content"][0]["text"])["retried"]["job_id"]
                    ret_job = bot_bus.get_job(ret_jid)
                    self.assertEqual("remote_trusted", ret_job["trust_level"])

                # Direct bot_bus calls also clamp against server registry
                with self.assertRaises(PermissionError):
                    bot_bus.dispatch_assignments(
                        "ext_readonly",
                        [{"bot": "worker_a", "prompt": "direct bypass"}],
                        team_id="team-alpha",
                        parent_trust_level="local_admin",
                        auth_token=tok_ro,
                    )
                untr_direct = bot_bus.dispatch_assignments(
                    "ext_untrusted",
                    [{"bot": "worker_a", "prompt": "direct untrusted"}],
                    team_id="team-alpha",
                    parent_trust_level="local_admin",
                    trust_level="local_admin",
                    auth_token=tok_untr,
                )
                self.assertEqual("remote_untrusted", untr_direct["jobs"][0]["trust_level"])
                self.assertTrue(untr_direct["jobs"][0]["untrusted"])
                self.assertTrue(untr_direct["jobs"][0]["tainted"])

    def test_b4_pull_queue_auth_revocation_and_external_token_mandatory(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                fed.register_agent("ext_lead", kind="hermes_remote", endpoint_url="https://l.example.com", capabilities={"can_dispatch": True}, owner_auth=owner, bus_dir=tmp)
                fed.register_agent("nat_ext", kind="http_a2a", transport="pull_worker", owner_auth=owner, bus_dir=tmp)
                fed.register_agent("local_w", kind="agy_local", owner_auth=owner, bus_dir=tmp)
                fed.create_team("team-pull", leader_agent_id="ext_lead", members=["ext_lead", "nat_ext", "local_w"], owner_auth=owner, bus_dir=tmp)
                tok_lead = fed.mint_agent_token("ext_lead", owner_auth=owner, bus_dir=tmp)["token"]
                tok_nat = fed.mint_agent_token("nat_ext", owner_auth=owner, bus_dir=tmp)["token"]

                # Direct bot_bus dispatch by external agent with auth_token=None -> DENIED
                with self.assertRaises(PermissionError) as c_notok:
                    bot_bus.dispatch_assignments(
                        "ext_lead",
                        [{"bot": "nat_ext", "prompt": "no token bypass"}],
                        team_id="team-pull",
                        auth_token=None,
                    )
                self.assertIn("PRIVILEGE_ESCALATION_DENIED", str(c_notok.exception))

                q = fed.PullWorkerQueue(tmp)
                # Unauthenticated enqueue or worker enqueue when federation active -> DENIED
                with self.assertRaises(PermissionError):
                    q.enqueue("nat_ext", "unauth enqueue", team_id="team-pull")
                with self.assertRaises(PermissionError):
                    q.enqueue("nat_ext", "worker enqueue", team_id="team-pull", from_agent_id="local_w")
                # Tainted/readonly env blocks enqueue even with owner_auth
                for bad_env in (
                    {"AGY_UNTRUSTED_SESSION": "1"},
                    {"AGY_MEMORY_READONLY": "1"},
                    {"AGY_RBAC_ROLE": "readonly"},
                ):
                    with self.subTest(bad_env=bad_env), mock.patch.dict(os.environ, _clean_env(bad_env), clear=True):
                        with self.assertRaises(PermissionError):
                            q.enqueue("nat_ext", "tainted", team_id="team-pull", owner_auth=owner)

                # Authorized enqueue via team leader + token succeeds
                job = q.enqueue(
                    "nat_ext",
                    "legit pull task",
                    team_id="team-pull",
                    from_agent_id="ext_lead",
                    auth_token=tok_lead,
                )
                jid = job["job_id"]

                # External pull worker omitting auth_token on claim -> DENIED
                with self.assertRaises(PermissionError):
                    q.claim("nat_ext", job_id=jid)
                # Valid token claims successfully
                claimed = q.claim("nat_ext", job_id=jid, auth_token=tok_nat)
                self.assertIsNotNone(claimed)
                # Omitting auth_token on complete -> DENIED
                with self.assertRaises(PermissionError):
                    q.complete(jid, "nat_ext", status="done", result_text="no tok")

                # Unauthenticated cancel -> DENIED
                job2 = q.enqueue("nat_ext", "cancel target", team_id="team-pull", owner_auth=owner)
                with self.assertRaises(PermissionError):
                    q.cancel(job2["job_id"])
                # Authorized cancel -> OK
                cancelled = q.cancel(job2["job_id"], requester_agent_id="ext_lead", auth_token=tok_lead)
                self.assertEqual("cancelled", cancelled["status"])

                # Revoking agent immediately blocks claim & complete even with prior token or None
                fed.revoke_agent("nat_ext", owner_auth=owner, bus_dir=tmp)
                with self.assertRaises(PermissionError):
                    q.complete(jid, "nat_ext", status="done", result_text="after revoke", auth_token=tok_nat)
                with self.assertRaises(PermissionError):
                    q.claim("nat_ext", auth_token=tok_nat)
                with self.assertRaises(PermissionError):
                    q.claim("nat_ext")

    def test_b7_inline_bearer_update_hermes_profile_and_roster_revocation_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = _load_isolated_bus(tmp)
            with mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
                owner = fed.make_owner_auth("owner_user")
                # B7.1: Inline Bearer and Basic credentials rejected anywhere in string; benign prose allowed
                fake_bearer = "use Bear" + "er mySuperSecretToken123"
                fake_basic = "use Bas" + "ic dXNlcjpwYXNzMTIzNA=="
                for secret_note in (fake_bearer, fake_basic):
                    with self.assertRaises(ValueError) as cb:
                        fed.register_agent(
                            "bad_inline",
                            kind="hermes_remote",
                            endpoint_url="https://n.example.com",
                            metadata={"note": secret_note},
                            owner_auth=owner,
                            bus_dir=tmp,
                        )
                    self.assertIn("PLAINTEXT_SECRET_REJECTED", str(cb.exception))

                ok_agent = fed.register_agent(
                    "switch_agent",
                    kind="muse_remote",
                    endpoint_url="https://m.example.com",
                    metadata={"note": "uses basic plan configuration"},
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                self.assertEqual("muse_remote", ok_agent["kind"])

                # B7.2: Switching kind -> hermes_local without non-empty profile raises ValueError
                with self.assertRaises(ValueError):
                    fed.update_agent("switch_agent", kind="hermes_local", owner_auth=owner, bus_dir=tmp)
                switched = fed.update_agent(
                    "switch_agent",
                    kind="hermes_local",
                    profile="valid_prof",
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                self.assertEqual("hermes_local", switched["kind"])
                self.assertEqual("valid_prof", switched["profile"])

                # B7.3: Legacy live heartbeat overridden by federation enabled=False and revoked=True
                bot_bus.heartbeat_bot({"handle": "shared_bot", "pid": os.getpid(), "role": "worker"})
                fed.register_agent("shared_bot", kind="agy_local", owner_auth=owner, bus_dir=tmp)
                fed.update_agent("shared_bot", enabled=False, owner_auth=owner, bus_dir=tmp)

                all_roster = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
                self.assertIn("shared_bot", all_roster)
                self.assertFalse(all_roster["shared_bot"]["online"])
                online_only = {b["handle"]: b for b in bot_bus.list_roster(include_offline=False)}
                self.assertNotIn("shared_bot", online_only)

                fed.revoke_agent("shared_bot", owner_auth=owner, bus_dir=tmp)
                after_revoke = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
                self.assertNotIn("shared_bot", after_revoke)


if __name__ == "__main__":
    unittest.main()
