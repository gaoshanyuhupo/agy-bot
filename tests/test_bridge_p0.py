#!/usr/bin/env python3
"""Offline unit & integration tests for P0 bridge hardening (P0-1 through P0-5)."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_WORKDIR": tmp,
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_BOT_TOKEN": "1234567890:EXAMPLE_TOKEN_FOR_TEST_ONLY_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
    }
    if extra_env:
        env_patch.update(extra_env)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge


class TestP01DeploymentAndSystemd(unittest.TestCase):
    """P0-1: Verify KillMode=mixed in systemd units and README Quickstart bridge files."""

    def test_systemd_units_use_killmode_mixed(self):
        unit_candidates = list((REPO_ROOT / "systemd").glob("agy-tg-bridge*.service"))
        example_unit = REPO_ROOT / "systemd" / "examples" / "agy-tg-bridge.service.example"
        if example_unit.is_file():
            unit_candidates.append(example_unit)

        self.assertTrue(unit_candidates, "Expected at least one agy-tg-bridge systemd unit file")
        for unit in unit_candidates:
            txt = unit.read_text(encoding="utf-8")
            self.assertIn("KillMode=mixed", txt, f"{unit} must set KillMode=mixed")
            self.assertNotIn("KillMode=process", txt, f"{unit} must not keep KillMode=process")

    def test_public_readme_copies_bridge_runtime_files_when_present(self):
        public_readme = (
            REPO_ROOT / "README.md"
            if (REPO_ROOT / "systemd" / "examples").is_dir()
            else REPO_ROOT.parent / "agy-bot" / "README.md"
        )
        if not public_readme.is_file():
            self.skipTest("Public README.md not present in standalone workspace")
        txt = public_readme.read_text(encoding="utf-8")
        for fname in ("bridge/bridge.py", "bridge/scheduler.py", "bridge/bot_bus.py", "bridge/bot_bus_mcp.py"):
            self.assertIn(fname, txt, f"Quickstart in {public_readme} must copy {fname}")


class TestP02SingleInstanceFlock(unittest.TestCase):
    """P0-2: Per-bot flock prevents duplicate pollers without blocking distinct bots and survives execv."""

    def test_same_bot_blocked_across_processes_and_reacquirable_after_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                **os.environ,
                "PYTHONPATH": str(BRIDGE_DIR),
                "AGY_TG_ENV_FILE": os.path.join(tmp, "none.env"),
                "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
                "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
                "AGY_TG_WORKDIR": tmp,
                "AGY_TG_BOT_TOKEN": "111111111:EXAMPLE_TOKEN_BOT_ONE_AABBCC",
                "AGY_TG_ALLOWED_CHATS": "123456789",
            }
            holder_code = (
                "import sys, time; import bridge; "
                "fh = bridge._acquire_instance_lock(); "
                "print('LOCKED', flush=True); "
                "sys.stdin.readline()"
            )
            with subprocess.Popen(
                [sys.executable, "-c", holder_code],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            ) as proc:
                try:
                    line = proc.stdout.readline().strip()
                    self.assertEqual("LOCKED", line)

                    # Duplicate launch with same token (even different STATE_FILE) must fail non-zero.
                    dup_env = {**env, "AGY_TG_STATE_FILE": os.path.join(tmp, "state_dup.json")}
                    dup = subprocess.run(
                        [sys.executable, "-c", "import bridge; bridge._acquire_instance_lock()"],
                        capture_output=True,
                        text=True,
                        env=dup_env,
                    )
                    self.assertNotEqual(0, dup.returncode)
                    self.assertIn("already running", dup.stderr)

                    # Distinct bot tokens (e.g. bots 2 & 3) must acquire concurrently without conflict.
                    for idx in (2, 3):
                        other_env = {
                            **env,
                            "AGY_TG_STATE_FILE": os.path.join(tmp, f"state_{idx}.json"),
                            "AGY_TG_BOT_TOKEN": f"{idx}22222222:EXAMPLE_TOKEN_BOT_{idx}_XXYYZZ",
                        }
                        other = subprocess.run(
                            [
                                sys.executable,
                                "-c",
                                "import bridge; bridge._acquire_instance_lock(); bridge._release_instance_lock(); print('OK')",
                            ],
                            capture_output=True,
                            text=True,
                            env=other_env,
                        )
                        self.assertEqual(0, other.returncode, other.stderr)
                        self.assertIn("OK", other.stdout)
                finally:
                    proc.stdin.write("\n")
                    proc.stdin.flush()
                    proc.wait(timeout=5)

            # After holder exits, the lock must be cleanly re-acquirable.
            reacq = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import bridge; bridge._acquire_instance_lock(); bridge._release_instance_lock(); print('REACQUIRED')",
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(0, reacq.returncode, reacq.stderr)
            self.assertIn("REACQUIRED", reacq.stdout)

    def test_execv_hot_reload_releases_cloexec_and_reacquires_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                **os.environ,
                "PYTHONPATH": str(BRIDGE_DIR),
                "AGY_TG_ENV_FILE": os.path.join(tmp, "none.env"),
                "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
                "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
                "AGY_TG_WORKDIR": tmp,
                "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_TOKEN_EXECV_TEST_1234",
                "AGY_TG_ALLOWED_CHATS": "123456789",
            }
            script = Path(tmp) / "execv_lock_test.py"
            script.write_text(
                "\n".join(
                    [
                        "import os, sys",
                        "import bridge",
                        "fh = bridge._acquire_instance_lock()",
                        "assert os.get_inheritable(fh.fileno()) is False",
                        "if os.environ.get('REEXEC_STAGE') != '2':",
                        "    os.environ['REEXEC_STAGE'] = '2'",
                        "    os.execv(sys.executable, [sys.executable, __file__])",
                        "print('EXECV_REACQUIRED', flush=True)",
                        "bridge._release_instance_lock()",
                    ]
                ),
                encoding="utf-8",
            )
            res = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env)
            self.assertEqual(0, res.returncode, res.stderr)
            self.assertIn("EXECV_REACQUIRED", res.stdout)

    def test_import_lazy_no_token_leak_state_fallback_and_child_fd_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_dir = os.path.join(tmp, "locks")
            secret_tok = "987654321:EXAMPLE_SECRET_TOKEN_SHOULD_NOT_APPEAR"
            env = {
                **os.environ,
                "PYTHONPATH": str(BRIDGE_DIR),
                "AGY_TG_ENV_FILE": os.path.join(tmp, "none.env"),
                "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
                "AGY_TG_LOCK_DIR": lock_dir,
                "AGY_TG_WORKDIR": tmp,
                "AGY_TG_BOT_TOKEN": secret_tok,
                "AGY_TG_ALLOWED_CHATS": "123456789",
            }
            # 1. Importing bridge must NOT acquire the lock or create lock files.
            imp = subprocess.run(
                [sys.executable, "-c", "import bridge; assert bridge._instance_lock_fh is None; print('LAZY_OK')"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(0, imp.returncode, imp.stderr)
            self.assertIn("LAZY_OK", imp.stdout)
            self.assertFalse(os.path.exists(lock_dir) and os.listdir(lock_dir))

            # 2. Lock path & file contents must hash/redact BOT_TOKEN, and spawned children must not inherit lock fd.
            with mock.patch.dict(os.environ, {"AGY_TG_LOCK_DIR": lock_dir}, clear=False):
                bridge = _load_isolated_bridge(tmp, {"AGY_TG_BOT_TOKEN": secret_tok, "AGY_TG_LOCK_DIR": lock_dir})
                lock_path = bridge._instance_lock_path()
                self.assertTrue(
                    lock_path.startswith(lock_dir + os.sep),
                    f"Expected lock path under {lock_dir}, got {lock_path}",
                )
                self.assertNotIn(secret_tok, lock_path)
                self.assertNotIn("987654321", lock_path)

                bridge._acquire_instance_lock()
                try:
                    lock_txt = Path(lock_path).read_text(encoding="utf-8")
                    self.assertNotIn(secret_tok, lock_txt)
                    self.assertIn(str(os.getpid()), lock_txt)
                    # Spawn a long-lived child process while lock is held; FD_CLOEXEC prevents fd inheritance.
                    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
                    try:
                        bridge._release_instance_lock()
                        # Another process can acquire immediately even while child is still running.
                        reacq = subprocess.run(
                            [
                                sys.executable,
                                "-c",
                                "import bridge; bridge._acquire_instance_lock(); bridge._release_instance_lock(); print('FREE')",
                            ],
                            capture_output=True,
                            text=True,
                            env=env,
                        )
                        self.assertEqual(0, reacq.returncode, reacq.stderr)
                        self.assertIn("FREE", reacq.stdout)
                    finally:
                        child.terminate()
                        child.wait(timeout=5)
                finally:
                    bridge._release_instance_lock()

            # 3. Empty BOT_TOKEN falls back to STATE_FILE isolation.
            no_tok_env = {**env, "AGY_TG_BOT_TOKEN": ""}
            holder_code = (
                "import sys, bridge; "
                "bridge._acquire_instance_lock(); "
                "print('LOCKED', flush=True); "
                "sys.stdin.readline()"
            )
            with subprocess.Popen(
                [sys.executable, "-c", holder_code],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=no_tok_env,
            ) as proc:
                try:
                    self.assertEqual("LOCKED", proc.stdout.readline().strip())
                    dup = subprocess.run(
                        [sys.executable, "-c", "import bridge; bridge._acquire_instance_lock()"],
                        capture_output=True,
                        text=True,
                        env=no_tok_env,
                    )
                    self.assertNotEqual(0, dup.returncode)
                    diff_state = subprocess.run(
                        [sys.executable, "-c", "import bridge; bridge._acquire_instance_lock(); bridge._release_instance_lock()"],
                        capture_output=True,
                        text=True,
                        env={**no_tok_env, "AGY_TG_STATE_FILE": os.path.join(tmp, "other_state.json")},
                    )
                    self.assertEqual(0, diff_state.returncode, diff_state.stderr)
                finally:
                    proc.stdin.write("\n")
                    proc.stdin.flush()
                    proc.wait(timeout=5)


class TestP03ExtendedMediaRouting(unittest.TestCase):
    """P0-3: video, video_note, animation, and sticker routing, 20MB limit, extensions, and metadata."""

    def test_download_extensions_and_20mb_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            downloaded: list[tuple[str, str]] = []

            def fake_dl(file_id, dest):
                downloaded.append((file_id, dest))
                Path(dest).write_bytes(b"mock")

            with mock.patch.object(bridge, "tg_download", side_effect=fake_dl):
                cases = [
                    ({"message_id": 1, "video": {"file_id": "v1", "file_size": 1024, "duration": 5}}, ".mp4"),
                    ({"message_id": 2, "video_note": {"file_id": "vn1", "file_size": 1024, "length": 384}}, ".mp4"),
                    (
                        {
                            "message_id": 3,
                            "animation": {"file_id": "a1", "file_size": 1024, "mime_type": "video/mp4"},
                            "document": {"file_id": "a1", "file_name": "clip.mp4", "mime_type": "video/mp4"},
                        },
                        ".mp4",
                    ),
                    ({"message_id": 4, "sticker": {"file_id": "s1", "is_animated": False, "is_video": False}}, ".webp"),
                    ({"message_id": 5, "sticker": {"file_id": "s2", "is_animated": True, "is_video": False}}, ".tgs"),
                    ({"message_id": 6, "sticker": {"file_id": "s3", "is_animated": False, "is_video": True}}, ".webm"),
                ]
                for msg, expected_ext in cases:
                    dest, rel, err = bridge._download_msg_media(msg)
                    self.assertIsNone(err)
                    self.assertTrue(dest.endswith(expected_ext), f"Expected {expected_ext}, got {dest}")
                    self.assertTrue(rel.startswith("uploads/"))

                # Uniform 20MB limit enforcement across media types
                oversize = 20 * 1024 * 1024 + 1
                for key in ("video", "video_note", "animation", "sticker", "document"):
                    dest, rel, err = bridge._download_msg_media({"message_id": 9, key: {"file_id": "big", "file_size": oversize}})
                    self.assertIsNone(dest)
                    self.assertIsNone(rel)
                    self.assertIn("20MB", err)

                dest, rel, err = bridge._download_msg_media(
                    {"message_id": 10, "photo": [{"file_id": "bigp", "file_size": oversize}]}
                )
                self.assertIsNone(dest)
                self.assertIn("20MB", err)

    def test_captionless_video_and_sticker_inject_metadata_and_record_group_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            enqueued: list[dict] = []
            ledger_calls: list[dict] = []

            def fake_dl(file_id, dest):
                Path(dest).write_bytes(b"media")

            def fake_enqueue(chat_id, prompt, **kwargs):
                enqueued.append({"chat_id": chat_id, "prompt": prompt, **kwargs})

            def fake_record(msg, text_override=None):
                ledger_calls.append({"msg_id": msg.get("message_id"), "text": text_override})
                return "chain-1"

            updates = [
                {
                    "update_id": 101,
                    "message": {
                        "message_id": 501,
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "sticker": {
                            "file_id": "stk1",
                            "emoji": "🚀",
                            "set_name": "RocketPack",
                            "width": 512,
                            "height": 512,
                            "is_animated": False,
                            "is_video": False,
                        },
                    },
                },
                {
                    "update_id": 102,
                    "message": {
                        "message_id": 502,
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "animation": {
                            "file_id": "gif1",
                            "duration": 3,
                            "width": 480,
                            "height": 270,
                            "mime_type": "video/mp4",
                        },
                        "document": {
                            "file_id": "gif1",
                            "file_name": "funny.mp4",
                            "mime_type": "video/mp4",
                        },
                    },
                },
                {
                    "update_id": 103,
                    "message": {
                        "message_id": 503,
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "video": {
                            "file_id": "vid1",
                            "duration": 14,
                            "width": 1280,
                            "height": 720,
                        },
                        "caption": "check this bug",
                    },
                },
            ]

            fake_resp = mock.MagicMock()
            fake_resp.json.return_value = {"ok": True, "result": updates}

            with (
                mock.patch.object(bridge.http_session, "get", return_value=fake_resp),
                mock.patch.object(bridge, "tg_download", side_effect=fake_dl),
                mock.patch.object(bridge, "send"),
                mock.patch.object(bridge, "enqueue", side_effect=fake_enqueue),
                mock.patch.object(bridge, "_record_human_group_msg", side_effect=fake_record),
            ):
                new_off, first_poll, streak = bridge._run_poll_iteration(0, True, 2)

            self.assertEqual(104, new_off)
            self.assertFalse(first_poll)
            self.assertEqual(0, streak)
            self.assertEqual(3, len(enqueued))
            self.assertEqual(3, len(ledger_calls))

            # Sticker metadata injected cleanly
            self.assertIn("emoji=🚀", enqueued[0]["prompt"])
            self.assertIn("set=RocketPack", enqueued[0]["prompt"])
            self.assertIn("emoji=🚀", ledger_calls[0]["text"])
            self.assertIn("[贴纸 ", ledger_calls[0]["text"])

            # Animation prioritized over Telegram's duplicate document field
            self.assertIn("Animation/GIF", enqueued[1]["prompt"])
            self.assertIn("3s", enqueued[1]["prompt"])
            self.assertIn("480x270", enqueued[1]["prompt"])
            self.assertIn("[动图 ", ledger_calls[1]["text"])

            # Video caption + duration/dimensions preserved
            self.assertIn("check this bug", enqueued[2]["prompt"])
            self.assertIn("14s", enqueued[2]["prompt"])
            self.assertIn("1280x720", enqueued[2]["prompt"])
            self.assertIn("[视频 ", ledger_calls[2]["text"])

    def test_video_album_batching_and_flush(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.ALBUM_DEBOUNCE_SECONDS = 0.05
            enqueued: list[dict] = []

            def fake_dl(file_id, dest):
                Path(dest).write_bytes(b"vid")

            updates = [
                {
                    "update_id": 201,
                    "message": {
                        "message_id": 601,
                        "media_group_id": "alb_vid_1",
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "video": {"file_id": "v1", "duration": 6, "width": 640, "height": 360},
                    },
                },
                {
                    "update_id": 202,
                    "message": {
                        "message_id": 602,
                        "media_group_id": "alb_vid_1",
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "photo": [{"file_id": "p1", "width": 800, "height": 600}],
                    },
                },
            ]
            fake_resp = mock.MagicMock()
            fake_resp.json.return_value = {"ok": True, "result": updates}

            with (
                mock.patch.object(bridge.http_session, "get", return_value=fake_resp),
                mock.patch.object(bridge, "tg_download", side_effect=fake_dl),
                mock.patch.object(bridge, "send"),
                mock.patch.object(bridge, "enqueue", side_effect=lambda cid, pr, **kw: enqueued.append({"cid": cid, "prompt": pr, **kw})),
            ):
                bridge._run_poll_iteration(0, False, 0)
                import time

                deadline = time.time() + 2.0
                while not enqueued and time.time() < deadline:
                    time.sleep(0.02)

            self.assertEqual(1, len(enqueued))
            self.assertIn("Album with 2 files", enqueued[0]["prompt"])
            self.assertIn("Video (6s, 640x360)", enqueued[0]["prompt"])

    def test_path_traversal_size_boundaries_captionless_video_note_and_partial_album(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.ALBUM_DEBOUNCE_SECONDS = 0.05
            upload_real = os.path.realpath(bridge.UPLOADDIR)

            def fake_dl(_file_id, dest):
                Path(dest).write_bytes(b"ok")

            # 1. Path traversal / NUL / dot segments stay strictly inside UPLOADDIR
            with mock.patch.object(bridge, "tg_download", side_effect=fake_dl):
                traversal_msgs = [
                    {"message_id": 701, "document": {"file_id": "d1", "file_name": "../../etc/passwd"}},
                    {"message_id": 702, "video": {"file_id": "v1", "file_name": "/tmp/evil\x00clip.mp4"}},
                    {"message_id": 703, "animation": {"file_id": "a1", "file_name": "..", "mime_type": "image/gif"}},
                    {"message_id": 704, "document": {"file_id": "d2", "file_name": "."}},
                    {
                        "message_id": 705,
                        "sticker": {"file_id": "s1", "set_name": "../../etc/shadow", "is_animated": False, "is_video": False},
                    },
                ]
                for m in traversal_msgs:
                    dest, rel, err = bridge._download_msg_media(m)
                    self.assertIsNone(err, f"Unexpected error for {m}: {err}")
                    self.assertTrue(os.path.realpath(dest).startswith(upload_real + os.sep), f"Escaped UPLOADDIR: {dest}")
                    self.assertFalse(rel.startswith(".."))
                    self.assertNotIn("\x00", dest)

                # 2. Size boundaries: None, 0, and exact 20MB succeed; 20MB + 1 fails cleanly
                exact_20mb = 20 * 1024 * 1024
                for fsize in (None, 0, exact_20mb):
                    m = {"message_id": 706, "video": {"file_id": "v_ok", "file_size": fsize}}
                    dest, _rel, err = bridge._download_msg_media(m)
                    self.assertIsNone(err, f"file_size={fsize} should be accepted, got {err}")
                    self.assertTrue(dest.endswith(".mp4"))

                # 3. Over-limit message through handle_media notifies user without crashing
                sent_msgs: list[str] = []
                with mock.patch.object(bridge, "send", side_effect=lambda _cid, txt, **_kw: sent_msgs.append(txt)):
                    bridge.handle_media(
                        {
                            "message_id": 707,
                            "chat": {"id": -1001234567890},
                            "from": {"id": 42, "username": "alice", "is_bot": False},
                            "video": {"file_id": "v_huge", "file_size": exact_20mb + 1},
                        }
                    )
                self.assertEqual(1, len(sent_msgs))
                self.assertIn("20MB", sent_msgs[0])

            # 4. Captionless video_note goes through handle_media -> enqueue (never handle_message)
            enqueued: list[dict] = []
            resp_vn = mock.MagicMock()
            resp_vn.json.return_value = {
                "ok": True,
                "result": [
                    {
                        "update_id": 710,
                        "message": {
                            "message_id": 710,
                            "chat": {"id": -1001234567890},
                            "from": {"id": 42, "username": "alice", "is_bot": False},
                            "video_note": {"file_id": "vn_capless", "duration": 7, "length": 240},
                        },
                    }
                ],
            }
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp_vn),
                mock.patch.object(bridge, "tg_download", side_effect=fake_dl),
                mock.patch.object(bridge, "send"),
                mock.patch.object(bridge, "handle_message") as handle_msg_mock,
                mock.patch.object(bridge, "enqueue", side_effect=lambda cid, pr, **kw: enqueued.append({"cid": cid, "prompt": pr, **kw})),
            ):
                bridge._run_poll_iteration(0, False, 0)
            handle_msg_mock.assert_not_called()
            self.assertEqual(1, len(enqueued))
            self.assertIn("Video Note (7s, 240x240)", enqueued[0]["prompt"])

            # 5. Partial album failure includes Failed items note and still delivers valid item
            album_enq: list[dict] = []
            album_updates = [
                {
                    "update_id": 711,
                    "message": {
                        "message_id": 711,
                        "media_group_id": "alb_mix_err",
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "video": {"file_id": "v_good", "duration": 4, "width": 320, "height": 240},
                    },
                },
                {
                    "update_id": 712,
                    "message": {
                        "message_id": 712,
                        "media_group_id": "alb_mix_err",
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42, "username": "alice", "is_bot": False},
                        "animation": {"file_id": "a_too_big", "file_size": exact_20mb + 5},
                    },
                },
            ]
            resp_alb = mock.MagicMock()
            resp_alb.json.return_value = {"ok": True, "result": album_updates}
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp_alb),
                mock.patch.object(bridge, "tg_download", side_effect=fake_dl),
                mock.patch.object(bridge, "send"),
                mock.patch.object(bridge, "enqueue", side_effect=lambda cid, pr, **kw: album_enq.append({"cid": cid, "prompt": pr, **kw})),
            ):
                bridge._run_poll_iteration(0, False, 0)
                import time

                deadline = time.time() + 2.0
                while not album_enq and time.time() < deadline:
                    time.sleep(0.02)

            self.assertEqual(1, len(album_enq))
            self.assertIn("Album with 1 files", album_enq[0]["prompt"])
            self.assertIn("Failed items:", album_enq[0]["prompt"])
            self.assertIn("20MB", album_enq[0]["prompt"])


class TestP04PollSelfHealing(unittest.TestCase):
    """P0-4: http_session rebuild, exponential backoff, ReadTimeout exemption, and 409 diagnostics."""

    def test_read_timeout_does_not_count_or_reset_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            orig_sess = bridge.http_session
            with (
                mock.patch.object(bridge.http_session, "get", side_effect=requests.exceptions.ReadTimeout("idle")),
                mock.patch.object(bridge, "_reset_http_session") as reset_mock,
                mock.patch.object(bridge, "_sleep_interruptible") as sleep_mock,
            ):
                off, first_poll, streak = bridge._run_poll_iteration(50, True, 0)

            self.assertEqual(50, off)
            self.assertFalse(first_poll)
            self.assertEqual(0, streak)
            self.assertIs(orig_sess, bridge.http_session)
            reset_mock.assert_not_called()
            sleep_mock.assert_not_called()

    def test_poll_error_rebuilds_session_exponential_backoff_and_keeps_inflight_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            first_sess = bridge.http_session
            sleeps: list[float] = []

            def fake_get(*_args, **_kwargs):
                raise requests.exceptions.ConnectionError("network down")

            with (
                mock.patch.object(bridge, "_sleep_interruptible", side_effect=lambda s: sleeps.append(s) or True),
                mock.patch.object(first_sess, "close") as old_close_mock,
            ):
                streak = 0
                prev_sessions = [first_sess]
                for _ in range(6):
                    with mock.patch.object(bridge.http_session, "get", side_effect=fake_get):
                        _off, _fp, streak = bridge._run_poll_iteration(0, False, streak)
                    self.assertIsNot(prev_sessions[-1], bridge.http_session)
                    prev_sessions.append(bridge.http_session)

                old_close_mock.assert_not_called()

            self.assertEqual([2.0, 4.0, 8.0, 16.0, 30.0, 30.0], sleeps)

    def test_409_conflict_logs_diagnostics_and_recovers_streak_on_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            resp_409 = mock.MagicMock(status_code=409)
            resp_409.json.return_value = {
                "ok": False,
                "error_code": 409,
                "description": "Conflict: terminated by other getUpdates request",
            }
            logs: list[str] = []
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp_409),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
                mock.patch.object(bridge, "log", side_effect=logs.append),
            ):
                _off, _fp, streak = bridge._run_poll_iteration(10, False, 0)

            self.assertEqual(1, streak)
            self.assertTrue(any("409 Conflict" in msg for msg in logs), f"Missing 409 log: {logs}")

            resp_ok = mock.MagicMock(status_code=200)
            resp_ok.json.return_value = {"ok": True, "result": []}
            with mock.patch.object(bridge.http_session, "get", return_value=resp_ok):
                _off, _fp, streak = bridge._run_poll_iteration(10, False, streak)
            self.assertEqual(0, streak)

    def test_ssl_chunked_connect_timeout_500_and_shutdown_interrupts_backoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            import threading
            import time

            # 1. SSLError, ChunkedEncodingError, ConnectTimeout all trigger rebuild + backoff
            exc_types = (
                requests.exceptions.SSLError("tls reset"),
                requests.exceptions.ChunkedEncodingError("incomplete read"),
                requests.exceptions.ConnectTimeout("connect timed out"),
            )
            streak = 0
            for exc in exc_types:
                prev = bridge.http_session
                with (
                    mock.patch.object(bridge.http_session, "get", side_effect=exc),
                    mock.patch.object(bridge, "_sleep_interruptible", return_value=True) as sl_mock,
                ):
                    _off, _fp, streak = bridge._run_poll_iteration(10, False, streak)
                self.assertIsNot(prev, bridge.http_session)
                sl_mock.assert_called_once()
            self.assertEqual(3, streak)

            # 2. HTTP 500 API error rebuilds session immediately even at streak=1
            prev = bridge.http_session
            resp_502 = mock.MagicMock(status_code=502)
            resp_502.json.return_value = {"ok": False, "error_code": 502, "description": "Bad Gateway"}
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp_502),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                _off, _fp, streak = bridge._run_poll_iteration(10, False, 0)
            self.assertEqual(1, streak)
            self.assertIsNot(prev, bridge.http_session)

            # 3. _sleep_interruptible exits within <1s when shutting_down is set
            bridge.shutting_down = False
            t0 = time.monotonic()

            def trigger_shutdown():
                time.sleep(0.08)
                bridge.shutting_down = True

            th = threading.Thread(target=trigger_shutdown, daemon=True)
            th.start()
            completed = bridge._sleep_interruptible(30.0)
            elapsed = time.monotonic() - t0
            th.join(timeout=1.0)
            self.assertFalse(completed)
            self.assertLess(elapsed, 1.0)

            # 4. Concurrent tg() call on old session finishes cleanly while _reset_http_session swaps
            bridge.shutting_down = False
            old_sess = bridge.http_session
            in_flight_entered = threading.Event()
            allow_finish = threading.Event()
            worker_results: list = []

            def slow_post(*_a, **_kw):
                in_flight_entered.set()
                allow_finish.wait(timeout=2.0)
                resp = mock.MagicMock(status_code=200)
                resp.json.return_value = {"ok": True}
                return resp

            with mock.patch.object(old_sess, "post", side_effect=slow_post):
                wt = threading.Thread(target=lambda: worker_results.append(bridge.tg("getMe")), daemon=True)
                wt.start()
                self.assertTrue(in_flight_entered.wait(timeout=2.0))
                new_sess = bridge._reset_http_session(reason="concurrent_test")
                self.assertIsNot(old_sess, new_sess)
                self.assertIs(bridge.http_session, new_sess)
                allow_finish.set()
                wt.join(timeout=2.0)

            self.assertEqual(1, len(worker_results))
            self.assertIsNotNone(worker_results[0])


class TestP05StrictFailClosedAllowed(unittest.TestCase):
    """P0-5: Empty ALLOWED fails closed across auth, smg, bus loop, and execute_bus_job."""

    def test_empty_allowed_rejects_auth_and_smg(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, {"AGY_TG_ALLOWED_CHATS": ""})
            self.assertEqual(set(), bridge.ALLOWED)
            self.assertFalse(bridge._is_authorized(-1001234567890, from_user={"id": 42}, allow_uid_fallback=True))
            self.assertFalse(bridge._is_authorized(42, from_user={"id": 42}, allow_uid_fallback=True))

            resp = mock.MagicMock()
            resp.json.return_value = {
                "ok": True,
                "result": [
                    {
                        "update_id": 77,
                        "stopped_message_generation": {"chat": {"id": -1001234567890}, "draft_id": 1},
                    }
                ],
            }
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp),
                mock.patch.object(bridge, "cancel_current_task") as cancel_mock,
            ):
                bridge._run_poll_iteration(0, False, 0)
            cancel_mock.assert_not_called()

    def test_empty_allowed_blocks_bus_loop_and_bus_job_mirroring(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, {"AGY_TG_ALLOWED_CHATS": "", "AGY_BUS_CHAT_MODE": "conversational"})
            bridge.shutting_down = False

            packets = [
                {"type": "broadcast", "chat_id": -1001234567890, "message": "hello"},
                {"type": "group_mention", "chat_id": -1001234567890, "from_bot": "bot_one", "text_excerpt": "hi"},
            ]

            def pop_once(_handle):
                bridge.shutting_down = True
                return packets

            with (
                mock.patch.object(bridge.bot_bus, "pop_inbox_packets", side_effect=pop_once),
                mock.patch.object(bridge, "_init_bot_identity"),
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(bridge, "register_bot_commands"),
                mock.patch.object(bridge, "send_rich") as send_rich_mock,
                mock.patch.object(bridge, "enqueue") as enqueue_mock,
            ):
                bridge._bot_bus_loop()

            send_rich_mock.assert_not_called()
            enqueue_mock.assert_not_called()

            # Also verify _execute_bus_job refuses to mirror into unknown chat when ALLOWED is empty
            bridge.shutting_down = False
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": []}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": []}
            )
            bridge.bot_bus.update_bot_config("bot_two", role="worker", mirror_chat_id=-1001234567890)
            res = bridge.bot_bus.dispatch_assignments(
                "bot_one",
                [{"bot": "bot_two", "prompt": "check", "label": "check-job", "notify_group": True}],
                origin_scope_key="-1001234567890",
                origin_chat_id=-1001234567890,
                origin_msg_id=10,
                default_notify_group=True,
            )
            jid = res["jobs"][0]["job_id"]

            class _FakeProc:
                def __init__(self):
                    self.pid = 99999
                    self.returncode = 0
                    self.stdout = iter(
                        [
                            json.dumps(
                                {
                                    "event": "result",
                                    "result": {"status": "SUCCESS", "conversation_id": "conv-1", "response": "done"},
                                }
                            )
                            + "\n"
                        ]
                    )
                    self.stderr = iter([])

                def wait(self, timeout=None):
                    return 0

            with (
                mock.patch.object(bridge, "tg_send_in_route") as tg_route_mock,
                mock.patch.object(bridge, "send_rich") as send_rich_job_mock,
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(bridge.subprocess, "Popen", return_value=_FakeProc()),
            ):
                bridge._execute_bus_job(jid)

            tg_route_mock.assert_not_called()
            send_rich_job_mock.assert_not_called()

    def test_empty_allowed_blocks_dm_group_edited_callback_voice_media_and_silent_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, {"AGY_TG_ALLOWED_CHATS": ""})
            updates = [
                {
                    "update_id": 801,
                    "message": {"message_id": 1, "chat": {"id": 42}, "from": {"id": 42}, "text": "dm hi"},
                },
                {
                    "update_id": 802,
                    "message": {"message_id": 2, "chat": {"id": -1001234567890}, "from": {"id": 42}, "text": "grp hi"},
                },
                {
                    "update_id": 803,
                    "edited_message": {"message_id": 3, "chat": {"id": -1001234567890}, "from": {"id": 42}, "text": "edited"},
                },
                {
                    "update_id": 804,
                    "message": {
                        "message_id": 4,
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42},
                        "voice": {"file_id": "v1"},
                    },
                },
                {
                    "update_id": 805,
                    "message": {
                        "message_id": 5,
                        "chat": {"id": -1001234567890},
                        "from": {"id": 42},
                        "video": {"file_id": "vid1"},
                    },
                },
                {
                    "update_id": 806,
                    "callback_query": {
                        "id": "cb_1",
                        "from": {"id": 42},
                        "message": {"message_id": 6, "chat": {"id": -1001234567890}},
                        "data": "model:default",
                    },
                },
            ]
            resp = mock.MagicMock()
            resp.json.return_value = {"ok": True, "result": updates}
            with (
                mock.patch.object(bridge.http_session, "get", return_value=resp),
                mock.patch.object(bridge, "tg") as tg_mock,
                mock.patch.object(bridge, "tg_download") as dl_mock,
                mock.patch.object(bridge, "enqueue") as enq_mock,
                mock.patch.object(bridge, "_record_human_group_msg") as rec_mock,
            ):
                new_off, _fp, _streak = bridge._run_poll_iteration(0, False, 0)

            self.assertEqual(807, new_off)
            dl_mock.assert_not_called()
            enq_mock.assert_not_called()
            rec_mock.assert_not_called()
            tg_mock.assert_called_once_with(
                "answerCallbackQuery", callback_query_id="cb_1", text="Unauthorized", show_alert=True
            )

        # Even with ALLOWED populated + conversational mode, notify_group=False stays strictly silent
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp, {"AGY_TG_ALLOWED_CHATS": "-1001234567890", "AGY_BUS_CHAT_MODE": "conversational"}
            )
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )
            res = bridge.bot_bus.dispatch_assignments(
                "bot_one",
                [{"bot": "bot_two", "prompt": "silent check", "label": "silent-job", "notify_group": False}],
                origin_scope_key="-1001234567890",
                origin_chat_id=-1001234567890,
                origin_msg_id=11,
                default_notify_group=False,
            )
            jid = res["jobs"][0]["job_id"]

            class _FakeSilentProc:
                def __init__(self):
                    self.pid = 99998
                    self.returncode = 0
                    self.stdout = iter(
                        [
                            json.dumps(
                                {
                                    "event": "result",
                                    "result": {"status": "SUCCESS", "conversation_id": "conv-s1", "response": "silent ok"},
                                }
                            )
                            + "\n"
                        ]
                    )
                    self.stderr = iter([])

                def wait(self, timeout=None):
                    return 0

            with (
                mock.patch.object(bridge, "tg_send_in_route") as tg_route_mock,
                mock.patch.object(bridge, "send_rich") as send_rich_mock,
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(bridge.subprocess, "Popen", return_value=_FakeSilentProc()),
            ):
                bridge._execute_bus_job(jid)

            tg_route_mock.assert_not_called()
            send_rich_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
