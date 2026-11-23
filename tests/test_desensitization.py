#!/usr/bin/env python3
"""Automated desensitization detection & regression test suite for `agy-bot`.

Verifies:
1. Positive detection of raw secrets, half-masked tokens, APIs/webhooks, URLs/domains,
   numeric/hex/UUID IDs, emails, `@handles`, host paths, IPs, forbidden files, and Git history leaks.
2. Negative/boundary allowlists (placeholders, RFC 5737 doc IPs, RFC 2606 domains, generic decorators/cron).
3. Functional integrity of desensitized core code (`bridge/bridge.py`, `hooks/`, `mem-hub/`, `hooks.json`).
4. Live repository gates (`secret-guard`, `core-public`, `public-release`, and Git history scan).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import security_audit  # noqa: E402


def _rules_hit(text: str, *, strict: bool = True, rel_path: str = "sample.txt") -> set[str]:
    return {f.rule for f in security_audit.scan_text(text, rel_path, strict=strict)}


class TestPositiveKeyAndSecretDetection(unittest.TestCase):
    """Ensure every raw key, masked secret fragment, header literal, and vault ref is caught."""

    def test_raw_vendor_and_platform_keys(self):
        samples = {
            "github_pat": "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1L2",
            "tg_bot_token": "88" + "7766554" + ":" + "AAFakeBotTokenSegment1234567890abcdEF",
            "google_api_key": "AI" + "zaSyDemoKeyValue1234567890abcdef123",
            "aws_access_key": "AK" + "IA" + "9X8W7V6U5T4S3R2Q",
            "openai_anthropic_sk": "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz12",
            "cloudflare_api_token": "cf" + "ut_" + "AbCdEf1234567890",
            "altare_key": "al" + "t_" + "AbCdEf1234567890ab",
            "resend_key": "re" + "_" + "9aBcDeFgHiJkLmNoPq",
            "instabox_key": "ib" + "k_" + "AbCdEf123456",
            "vault_hvs_token": "hv" + "s." + "CAESIGFakeTokenValue98765",
            "pk_prefixed_key": "pk-" + "9182736455abcdef",
            "private_key_pem": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "cf_tunnel_eyJ": "eyJ" + "hIjoi" + "fakeTunnelPayload12345678901234",
            "jwt_token": "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTYifQ" + "." + "SflKxwRJSMeK",
        }
        for expected_rule, secret_val in samples.items():
            with self.subTest(rule=expected_rule):
                rules = _rules_hit(f"SECRET={secret_val}", strict=False)
                self.assertIn(expected_rule, rules, f"Failed to detect {expected_rule}: got {rules}")

    def test_masked_secret_fragments_detected_strictly(self):
        dots = "\u2022" * 6
        samples = [
            "gh" + "p_8X" + dots + "Zz99",
            "cf" + "ut_DemoA" + dots + "77ff",
            "pk" + "-445566" + dots + "99aa",
            "ib" + "k_sample" + dots + "qrst",
            "tokenPrefix" + dots + "tail88",
        ]
        for s in samples:
            with self.subTest(sample=s):
                self.assertIn("masked_secret_fragment", _rules_hit(s, strict=True))

    def test_auth_headers_and_high_entropy_env_assignments(self):
        # Quoted + JSON header
        hdr = '{"Auth' + 'orization": "Bear' + 'er Zx9Yv8Wu7Ts6Rq5Po4Nm3"}'
        self.assertIn("auth_header_literal", _rules_hit(hdr, strict=False))

        # Unquoted .env literal high-entropy assignment
        env_line = "CUSTOM_SIGNING_SECRET=" + "Xp9Kq2Lm8Zr4Vt7Wn3Yb5"
        self.assertIn("high_entropy_credential_assignment", _rules_hit(env_line, strict=False, rel_path=".env.test"))

    def test_vault_paths_and_card_refs_caught_strictly(self):
        txt = "path = " + "lv" + "1/services/tenant-api ; card = " + "acme-" + "lv2-" + "card9"
        rules = _rules_hit(txt, strict=True)
        self.assertIn("vault_secret_path", rules)
        self.assertIn("vault_card_identifier", rules)


class TestPositiveApiUrlIdPiiPathDetection(unittest.TestCase):
    """Ensure APIs, URLs, numeric/hex/UUID IDs, PII, paths, IPs, and bad files are caught."""

    def test_api_and_url_patterns(self):
        creds_url = "http" + "s://deployuser:s3cr3tPass" + "@" + "internal.registry.invalid/repo"
        self.assertIn("url_embedded_credentials", _rules_hit(creds_url, strict=False))

        query_tok = "http" + "s://service.invalid/hook?" + "api_key=AbcDef123456"
        self.assertIn("url_query_secret", _rules_hit(query_tok, strict=False))

        tg_url = "http" + "s://api.telegram.org/b" + "ot88776655:AAFakeToken001122334455/sendMessage"
        self.assertIn("telegram_api_literal_token", _rules_hit(tg_url, strict=False))

        wh_host = "discord." + "c" + "om"
        wh_id = str(998877 * 10**6 + 665544)
        webhook = f"https://{wh_host}/api/webhooks/{wh_id}/AbCdEfGhIjKl"
        self.assertIn("webhook_secret_url", _rules_hit(webhook, strict=False))

        ext_url = "http" + "s://private-gateway." + "tenant-internal" + ".com/v1/call"
        self.assertIn("unallowlisted_external_url", _rules_hit(ext_url, strict=True))

        bare_dom = "endpoint: mail." + "tenant-ops" + ".xyz"
        self.assertIn("unallowlisted_bare_domain", _rules_hit(bare_dom, strict=True))

        ns_dom = "nameserver: alpha." + "ns." + "cloudflare." + "c" + "om"
        rules_ns = _rules_hit(ns_dom, strict=True)
        self.assertIn("cloudflare_nameserver", rules_ns)

        device_hdr = 'headers = {"X-' + 'VendorCustom-Device": "dev-01"}'
        self.assertIn("custom_device_header", _rules_hit(device_hdr, strict=True))

    def test_numeric_hex_and_uuid_identifiers(self):
        tg_grp = "group_id = " + str(-100 * 10**10 - 987654321)
        self.assertIn("telegram_group_or_channel_id", _rules_hit(tg_grp, strict=True))

        json_uid = '{"user_' + 'id": ' + str(9 * 10**8 + 123456) + "}"
        rules = _rules_hit(json_uid, strict=True)
        self.assertIn("contextual_sensitive_id", rules)

        eight_digit = "account alias " + str(45 * 10**6 + 12345)
        self.assertIn("standalone_long_numeric_id", _rules_hit(eight_digit, strict=True))

        hex32 = "zone=" + "".join(["a1b2c3d4", "e5f60718", "293a4b5c", "6d7e8f90"])
        self.assertIn("hex_32_identifier", _rules_hit(hex32, strict=True))

        real_uuid = "uuid=" + "-".join(["8a7b6c5d", "4e3f", "4120", "9abc", "def012345678"])
        self.assertIn("uuid_identifier", _rules_hit(real_uuid, strict=True))

    def test_pii_paths_and_ips(self):
        email = "owner = alice." + "operator@" + "proton" + ".me"
        self.assertIn("personal_or_real_email", _rules_hit(email, strict=True))

        handle = "contact @" + "private_ops_bot in group"
        self.assertIn("unallowlisted_handle", _rules_hit(handle, strict=True))

        home_p = "WORKDIR=/" + "home/alice_operator/work"
        self.assertIn("hardcoded_home_path", _rules_hit(home_p, strict=True))

        sys_u = "Us" + "er=alice_operator"
        self.assertIn("hardcoded_systemd_user", _rules_hit(sys_u, strict=True))

        ip4 = "ssh_host = 198." + "18.25.44"
        self.assertIn("non_doc_ipv4", _rules_hit(ip4, strict=True))

        ip6 = "addr = " + ":".join(["fd12", "3456", "789a", "", "1"])
        self.assertIn("non_loopback_ipv6", _rules_hit(ip6, strict=True))

    def test_forbidden_runtime_files_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.sg").write_text("FOO=bar\n", encoding="utf-8")
            (root / "local.token").write_text("opaque\n", encoding="utf-8")
            _, findings = security_audit.scan_repository(root, mode="secret-guard")
            rules = {f.rule for f in findings}
            self.assertIn("forbidden_runtime_secret_file", rules)
            self.assertIn("forbidden_artifact_suffix", rules)


class TestNegativeAllowlistBoundaries(unittest.TestCase):
    """Ensure benign placeholders, doc IPs/domains, decorators, and cron tags never false-positive."""

    def test_benign_placeholders_and_code_tokens_pass(self):
        safe_text = "\n".join(
            [
                "BOT_TOKEN=" + "123456789:REPLACE_WITH_YOUR_BOT_TOKEN_12345",
                "ALLOWED_CHATS=" + "123456789",
                "HOME_BIN=" + "$HOME/.local/bin",
                "WORKDIR=/" + "home/your-user/agy-workspace",
                "User=" + "your-user",
                "EMAIL=admin@" + "example.com",
                "Author: demo <87654321+demo@users.noreply.github.com>",
                "# e.g. http" + "s://ghp_xxxx@github.com/org/repo",
                "DOC_IP=" + "203.0.113.10",
                "LOCAL_ADDR=" + "http" + "://127.0.0.1:18795",
                "URL_FMT=" + "http" + "://%s:%d/v1",
                "DEFAULT_UUID=" + "00000000-0000-0000-0000-000000000000",
                "**record** and sk_key and re_ascii_flags = True",
                "bucket = ts % 10000000",
                "@contextlib.contextmanager",
                "@daily @hourly @font-face @bot_one @bot_two",
            ]
        )
        hits = security_audit.scan_text(safe_text, "benign.py", strict=True)
        self.assertEqual([], hits, f"Unexpected false positives: {hits}")


class TestLocalBlocklistAndGitHistoryGate(unittest.TestCase):
    """Verify local out-of-repo blocklist support and Git history leak detection."""

    def test_custom_local_blocklist_and_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.md").write_text("internal codename: cobalt_falcon_99\n", encoding="utf-8")
            bl = root.parent / "local_blocklist.txt"
            bl.write_text("# test custom rule\ncobalt_falcon_99\n", encoding="utf-8")
            try:
                rules = security_audit.load_local_blocklist(bl)
                _, findings = security_audit.scan_repository(root, mode="core-public", extra_rules=rules)
                self.assertTrue(any(f.rule.startswith("local_blocklist:") for f in findings))

                res = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPTS_DIR / "security_audit.py"),
                        "--mode",
                        "core-public",
                        "--root",
                        str(root),
                        "--blocklist-file",
                        str(bl),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(1, res.returncode)
                payload = json.loads(res.stdout)
                self.assertEqual(1, len(payload["findings"]))
            finally:
                bl.unlink(missing_ok=True)

    def test_git_history_catches_deleted_secret_and_passes_clean_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "hist_repo"
            repo.mkdir()
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test Bot",
                "GIT_AUTHOR_EMAIL": "tester@example.com",
                "GIT_COMMITTER_NAME": "Test Bot",
                "GIT_COMMITTER_EMAIL": "tester@example.com",
            }
            subprocess.run(["git", "init"], cwd=repo, env=env, check=True, capture_output=True)
            secret_file = repo / "config.env"
            leaked_pat = "gh" + "p_" + "LeakInHistoryToken987654"
            secret_file.write_text(f"GITHUB_TOKEN={leaked_pat}\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, env=env, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "add secret"], cwd=repo, env=env, check=True, capture_output=True)

            # Remove secret in commit 2 — workspace is clean, history still leaks!
            secret_file.write_text("GITHUB_TOKEN=REPLACE_WITH_TOKEN\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, env=env, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "remove secret"], cwd=repo, env=env, check=True, capture_output=True)

            _, ws_hits = security_audit.scan_repository(repo, mode="public-release")
            self.assertEqual([], ws_hits)
            commits, hist_hits = security_audit.scan_git_history(repo, strict=True)
            self.assertEqual(2, commits)
            self.assertTrue(any(h.rule == "github_pat" and h.category == "HISTORY" for h in hist_hits))

            # Clean orphan rewrite passes both workspace and history audit.
            subprocess.run(["git", "checkout", "--orphan", "clean_main"], cwd=repo, env=env, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "clean initial commit"], cwd=repo, env=env, check=True, capture_output=True)
            subprocess.run(["git", "branch", "-D", "master"], cwd=repo, env=env, check=False, capture_output=True)
            subprocess.run(["git", "branch", "-D", "main"], cwd=repo, env=env, check=False, capture_output=True)
            subprocess.run(["git", "branch", "-m", "main"], cwd=repo, env=env, check=True, capture_output=True)
            subprocess.run(["git", "gc", "--prune=now"], cwd=repo, env=env, check=True, capture_output=True)

            clean_commits, clean_hist_hits = security_audit.scan_git_history(repo, strict=True)
            self.assertEqual(1, clean_commits)
            self.assertEqual([], clean_hist_hits)


class TestSanitizedRuntimeBehavior(unittest.TestCase):
    """Verify desensitized core code resolves paths dynamically via HOME without regressions."""

    def test_hooks_json_commands_run_with_custom_home(self):
        hooks_data = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as fake_home:
            hooks_dir = Path(fake_home) / ".gemini" / "config" / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            for script in (REPO_ROOT / "hooks").glob("*.py"):
                shutil.copy2(script, hooks_dir / script.name)

            executed_commands: list[str] = []
            for _group, phases in hooks_data.items():
                if not isinstance(phases, dict):
                    continue
                for _phase, entries in phases.items():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        handlers = (
                            entry["hooks"]
                            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list)
                            else [entry]
                        )
                        for handler in handlers:
                            cmd = handler["command"]
                            executed_commands.append(cmd)
                            out = subprocess.check_output(
                                ["sh", "-c", cmd],
                                input="{}",
                                env={
                                    "HOME": fake_home,
                                    "AGY_INTERNAL_OBSERVER": "1",
                                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                },
                                text=True,
                            )
                            self.assertEqual("{}", out.strip())

            self.assertTrue(
                any("taint_outbound_guard.py" in cmd for cmd in executed_commands),
                f"Expected taint_outbound_guard.py to be executed, got: {executed_commands}",
            )

    def test_hook_scripts_derive_state_file_from_home(self):
        with tempfile.TemporaryDirectory() as fake_home:
            env = {
                "HOME": fake_home,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            }
            code = (
                "import sys; sys.path.insert(0, 'hooks'); "
                "import claude_mem_hook_gate as g, rehydrate_after_compact as r, taint_outbound_guard as t; "
                "print(g.SHIM_STATE_FILE); print(g.BUN_BIN); print(r.SHIM_STATE_FILE); print(t.TAINT_FILE)"
            )
            out = subprocess.check_output(
                [sys.executable, "-c", code],
                cwd=str(REPO_ROOT),
                env=env,
                text=True,
            ).splitlines()
            self.assertEqual(4, len(out))
            for line in out:
                self.assertTrue(line.startswith(fake_home + "/"), f"Expected path under {fake_home}, got {line}")

    def test_bridge_home_regexes_use_runtime_home(self):
        with tempfile.TemporaryDirectory() as fake_home:
            home_p = Path(fake_home)
            fake_env = home_p / "dummy.env"
            fake_env.write_text("", encoding="utf-8")
            fake_state = home_p / "bridge_state.json"
            env = {
                "HOME": fake_home,
                "AGY_TG_ENV_FILE": str(fake_env),
                "AGY_TG_STATE_FILE": str(fake_state),
                "AGY_TG_BOT_TOKEN": "123456789:DummyTestBridgeTokenForRegexOnly_01",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            }
            probe = (
                "import sys; sys.path.insert(0, 'bridge'); import bridge; "
                "p = f'{bridge.HOME}/work/chart.png'; m = bridge._IMG_REF_RE.search(f'img: {p}'); "
                "md = f'file://{bridge.HOME}/notes.md'; m2 = bridge._MD_ARTIFACT_RE.search(md); "
                "print(bridge.HOME); print(m.group(1) if m else ''); print(m2.group(1) if m2 else ''); "
                "import shutil; shutil.rmtree(bridge.BOT_OUTBOX_DIR, ignore_errors=True)"
            )
            out = subprocess.check_output(
                [sys.executable, "-c", probe],
                cwd=str(REPO_ROOT),
                env=env,
                text=True,
            ).splitlines()
            self.assertEqual(fake_home, out[0])
            self.assertEqual(f"{fake_home}/work/chart.png", out[1])
            self.assertEqual(f"{fake_home}/notes.md", out[2])

    def test_mem_hub_paths_derive_from_runtime_home(self):
        with tempfile.TemporaryDirectory() as fake_home:
            env = {
                "HOME": fake_home,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            }
            probe = (
                "import sys; sys.path.insert(0, 'mem-hub'); "
                "import agy_llm_shim as shim, agy_instinct_daemon as d; "
                "print(shim.AGY_BIN); print(shim.BASE_DIR); "
                "print(d.HUB_DIR); print(d.WORKSPACE_AGENTS_DIR)"
            )
            out = subprocess.check_output(
                [sys.executable, "-c", probe],
                cwd=str(REPO_ROOT),
                env=env,
                text=True,
            ).splitlines()
            self.assertEqual(4, len(out))
            for line in out:
                self.assertTrue(line.startswith(fake_home + "/"), f"Expected path under {fake_home}, got {line}")


class TestRepositoryDesensitizationGates(unittest.TestCase):
    """Live gates proving the public repository adheres to strict zero-leak invariants."""

    def test_secret_guard_passes_zero_hits_across_entire_repo(self):
        scanned, findings = security_audit.scan_repository(REPO_ROOT, mode="secret-guard")
        self.assertGreater(scanned, 45)
        self.assertEqual([], findings, f"secret-guard failed: {findings[:5]}")

    def test_core_public_strict_gate_passes_zero_hits(self):
        scanned, findings = security_audit.scan_repository(REPO_ROOT, mode="core-public")
        self.assertGreater(scanned, 45)
        self.assertEqual([], findings, f"core-public strict gate failed: {findings[:5]}")

    def test_public_release_strict_gate_passes_zero_hits(self):
        scanned, findings = security_audit.scan_repository(REPO_ROOT, mode="public-release")
        self.assertGreater(scanned, 45)
        self.assertEqual([], findings, f"public-release gate failed: {findings[:5]}")

    def test_git_history_and_cli_public_release_gate_passes(self):
        has_git = (REPO_ROOT / ".git").is_dir()
        cmd = [sys.executable, str(SCRIPTS_DIR / "security_audit.py"), "--mode", "public-release"]
        if has_git:
            cmd.append("--check-history")
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        self.assertEqual(0, res.returncode, res.stdout + "\n" + res.stderr)


if __name__ == "__main__":
    unittest.main()
