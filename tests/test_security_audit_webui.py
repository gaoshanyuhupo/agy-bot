#!/usr/bin/env python3
"""Positive and negative control tests for `scripts/security_audit.py` WebUI rules.

Verifies that:
1. Clean `webui/package.json`, `webui/package-lock.json`, `webui/vite.config.ts`, and built
   `webui/dist/assets/*.js` + `*.css` produce ZERO false-positive hits.
2. Injecting REAL secrets, private domains, emails, Telegram `@handles`, hardcoded `/home/<user>`
   paths, Telegram group/user numeric IDs, or local blocklist entries into `webui/package-lock.json`
   or `webui/dist/assets/*.js` / `*.css` is STILL strictly caught!
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import security_audit  # noqa: E402


class TestSecurityAuditWebuiControls(unittest.TestCase):
    def test_clean_webui_manifests_and_dist_zero_findings(self) -> None:
        manifests = [
            REPO_ROOT / "webui" / "package.json",
            REPO_ROOT / "webui" / "package-lock.json",
            REPO_ROOT / "webui" / "vite.config.ts",
        ]
        targets = [p for p in manifests if p.is_file()]
        self.assertGreaterEqual(len(targets), 3, "Expected webui manifest files (package.json, lockfile, vite.config)")
        dist_assets = REPO_ROOT / "webui" / "dist" / "assets"
        if dist_assets.is_dir():
            targets.extend(sorted(dist_assets.glob("*.js")))
            targets.extend(sorted(dist_assets.glob("*.css")))

        for fp in targets:
            rel = str(fp.relative_to(REPO_ROOT)).replace("\\", "/")
            text = fp.read_text(encoding="utf-8", errors="ignore")
            hits = security_audit.scan_text(text, rel, strict=True)
            self.assertEqual(
                hits,
                [],
                f"Expected 0 audit hits in clean {rel}, got {len(hits)}: {hits[:5]}",
            )

        # Synthetic clean dist JS & CSS audit (always runs even before `npm run build` in clean CI checkouts)
        lit_license = "@" + "license"
        react_err = "https://" + "react" + ".dev/errors/418"
        tw_lic = "https://" + "tailwindcss" + ".com"
        lane_mask = "10737" + "41824"
        synth_cases = [
            (
                "webui/dist/assets/index-synthetic.js",
                f'/** {lit_license} MIT */ var lane=t&{lane_mask},doc="{react_err}";',
            ),
            (
                "webui/dist/assets/index-synthetic.css",
                f"/*! tailwindcss v4 | MIT License | {tw_lic} */ .btn{{color:#12345678;}}",
            ),
        ]
        for rel, text in synth_cases:
            hits = security_audit.scan_text(text, rel, strict=True)
            self.assertEqual(
                hits,
                [],
                f"Expected 0 audit hits in synthetic clean {rel}, got {len(hits)}: {hits[:5]}",
            )

    def test_real_secrets_and_pii_still_caught_in_lockfile_and_dist_assets(self) -> None:
        fake_ghp = "ghp_" + "AbCdEf1234567890XyZ99"
        fake_sk = "sk-" + "proj-ZyXwVu9876543210AbCdEf"
        fake_tg_tok = "8887" + "77666:" + "AAH_fake_bot_token_1234567890abcdef"
        fake_domain = "https://" + "secret-panel." + "privatecorp." + "xyz/api"
        fake_email = "operator.real" + "@" + "privatecorp.io"
        fake_handle = "@" + "real_operator_bot"
        fake_home = "/" + "home" + "/alice/secrets/config"
        fake_tg_grp = "-100" + "19876" + "54321"
        fake_uid = "81234" + "56789"

        cases = [
            ("webui/package-lock.json", f'{{"token": "{fake_ghp}"}}', "github_pat"),
            ("webui/package-lock.json", f'{{"url": "{fake_domain}"}}', "unallowlisted_external_url"),
            ("webui/package-lock.json", f'{{"author": "{fake_email}"}}', "personal_or_real_email"),
            ("webui/package-lock.json", f'{{"maintainer": "{fake_handle}"}}', "unallowlisted_handle"),
            ("webui/package-lock.json", f'{{"dir": "{fake_home}"}}', "hardcoded_home_path"),
            ("webui/dist/assets/index-test.js", f'const k="{fake_ghp}";', "github_pat"),
            ("webui/dist/assets/index-test.js", f'const s="{fake_sk}";', "openai_anthropic_sk"),
            ("webui/dist/assets/index-test.js", f'const b="{fake_tg_tok}";', "tg_bot_token"),
            ("webui/dist/assets/index-test.js", f'const u="{fake_domain}";', "unallowlisted_external_url"),
            ("webui/dist/assets/index-test.js", f'const e="{fake_email}";', "personal_or_real_email"),
            ("webui/dist/assets/index-test.js", f'const h="{fake_handle}";', "unallowlisted_handle"),
            ("webui/dist/assets/index-test.js", f'const p="{fake_home}";', "hardcoded_home_path"),
            ("webui/dist/assets/index-test.js", f"const g={fake_tg_grp};", "telegram_group_or_channel_id"),
            ("webui/dist/assets/index-test.js", f"const uid={fake_uid};", "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.css", f"/* {fake_domain} */", "unallowlisted_external_url"),
            ("webui/dist/assets/index-test.css", f"/* {fake_home} */", "hardcoded_home_path"),
            ("webui/dist/assets/index-test.css", f"/* chat={fake_uid} */", "standalone_long_numeric_id"),
        ]
        for rel, content, expected_rule in cases:
            hits = security_audit.scan_text(content, rel, strict=True)
            rules = {h.rule for h in hits}
            self.assertIn(
                expected_rule,
                rules,
                f"Expected rule `{expected_rule}` in {rel} for {content!r}, got rules={rules}",
            )

        # Verify local blocklist rules still apply inside webui/dist/assets/*.js
        sentinel = "CUSTOM_PRIVATE_SENTINEL_TOKEN"
        extra = [("local_blocklist:sentinel", re.compile(re.escape(sentinel), re.IGNORECASE))]
        hits_bl = security_audit.scan_text(
            f'console.log("{sentinel}");',
            "webui/dist/assets/index-test.js",
            strict=True,
            extra_rules=extra,
        )
        self.assertTrue(any(h.rule == "local_blocklist:sentinel" for h in hits_bl))

    def test_p0_5_no_false_negatives_on_scoped_handles_license_quoted_ids_and_funding(self) -> None:
        fake_scope = "@" + "alice_real" + "/notes"
        lit_license = "@" + "license"
        oc_url = "https://" + "opencollective" + ".com/leak-org"
        tl_url = "https://" + "tidelift" + ".com/funding/leak"
        react_other = "https://" + "react" + ".dev/blog/2026/private"
        tw_url = "https://" + "tailwindcss" + ".com"
        num_pow2 = "10737" + "41824"
        num_uid = "87654" + "32109"
        hex_num = "23456" + "789"

        # 1) npm-shaped scoped handle MUST be caught everywhere outside real verified dep keys / declared TS imports
        tw_scope = "@" + "tailwindcss/vite"
        scope_cases = [
            ("studio/server.py", f'NOTE = "{fake_scope}"', "unallowlisted_handle"),
            ("webui/src/App.tsx", f'const note = "{fake_scope}";', "unallowlisted_handle"),
            ("webui/src/App.tsx", f"// comment {fake_scope}\nexport const x = 1;", "unallowlisted_handle"),
            ("webui/src/App.tsx", f'import x from "{fake_scope}";', "unallowlisted_handle"),
            ("webui/vite.config.ts", f"// {tw_scope}\nexport default {{}};", "unallowlisted_handle"),
            (
                "webui/package.json",
                f'{{"name":"demo","description":"owner {fake_scope}"}}',
                "unallowlisted_handle",
            ),
            (
                "webui/package-lock.json",
                (
                    '{"packages":{"node_modules/foo":{"version":"1.0.0",'
                    '"resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",'
                    '"integrity":"sha512-abc",'
                    f'"description":"contact {fake_scope}"}}}}'
                ),
                "unallowlisted_handle",
            ),
        ]

        # 2) license tag MUST be caught outside real `/* ... */` block comments in dist JS/CSS
        license_cases = [
            ("studio/server.py", f"# {lit_license} notice", "unallowlisted_handle"),
            ("webui/src/App.tsx", f"/* {lit_license} MIT */", "unallowlisted_handle"),
            ("webui/dist/assets/index-test.js", f'const s = "{lit_license}";', "unallowlisted_handle"),
            ("webui/dist/assets/index-test.js", f'const s = "/* {lit_license} */";', "unallowlisted_handle"),
            ("webui/dist/assets/index-test.js", f"// {lit_license}\nvar x=1;", "unallowlisted_handle"),
        ]

        # 3) Numbers inside quotes in dist JS & inside comments in dist CSS MUST be caught (never bitmask/color exempted!)
        numeric_cases = [
            ("webui/dist/assets/index-test.js", f'const id="{num_pow2}";', "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.js", f"const id='{num_pow2}';", "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.js", f"const id=`{num_pow2}`;", "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.js", f'const id="{num_uid}";', "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.js", f"/* uid {num_pow2} */", "standalone_long_numeric_id"),
            ("webui/dist/assets/index-test.css", f"/* #{hex_num} */", "standalone_long_numeric_id"),
        ]

        # 4) Funding URLs outside validated `funding` field of registry-verified lockfile pkgs & doc URLs outside exact dist context MUST be caught
        url_cases = [
            ("studio/server.py", f'URL = "{oc_url}"', "unallowlisted_external_url"),
            ("webui/src/App.tsx", f'const u = "{tl_url}";', "unallowlisted_external_url"),
            (
                "webui/package-lock.json",
                (
                    '{"packages":{"node_modules/foo":{"version":"1.0.0",'
                    '"resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",'
                    '"integrity":"sha512-abc",'
                    f'"description":"see {oc_url}"}}}}'
                ),
                "unallowlisted_external_url",
            ),
            (
                "webui/package-lock.json",
                (
                    '{"packages":{"node_modules/foo":{"version":"1.0.0",'
                    '"resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",'
                    '"integrity":"sha512-abc",'
                    f'"homepage":"{tl_url}"}}}}'
                ),
                "unallowlisted_external_url",
            ),
            # Unverified lockfile package (missing registry resolved/sha512 integrity) MUST NOT exempt funding URL
            (
                "webui/package-lock.json",
                f'{{"packages":{{"node_modules/fake":{{"version":"1.0.0","funding":{{"url":"{oc_url}"}}}}}}}}',
                "unallowlisted_external_url",
            ),
            # Non-errors/link react doc URL or vendor URL outside dist comment MUST be caught
            ("studio/server.py", f'DOC = "{react_other}"', "unallowlisted_external_url"),
            ("webui/dist/assets/index-test.js", f'const u = "{react_other}";', "unallowlisted_external_url"),
            ("webui/src/App.tsx", f'const u = "{tw_url}";', "unallowlisted_external_url"),
            ("webui/dist/assets/index-test.css", f'a{{background:url("{tw_url}")}}', "unallowlisted_external_url"),
        ]

        for rel, content, expected_rule in scope_cases + license_cases + numeric_cases + url_cases:
            hits = security_audit.scan_text(content, rel, strict=True)
            rules = {h.rule for h in hits}
            self.assertIn(
                expected_rule,
                rules,
                f"Expected `{expected_rule}` in {rel} for {content!r}, got rules={rules}",
            )

        # Positive control: genuine dist JS block-comment license tag and genuine registry-verified lockfile funding pass
        ok_js_lic = security_audit.scan_text(
            f"/** {lit_license} MIT */ var a=t&{num_pow2};",
            "webui/dist/assets/index-test.js",
            strict=True,
        )
        self.assertEqual(ok_js_lic, [])
        ok_lock_fund = security_audit.scan_text(
            (
                '{"packages":{"node_modules/postcss":{"version":"8.5.0",'
                '"resolved":"https://registry.npmjs.org/postcss/-/postcss-8.5.0.tgz",'
                '"integrity":"sha512-abcdef",'
                f'"funding":{{"type":"opencollective","url":"{oc_url}"}}}}}}}}'
            ),
            "webui/package-lock.json",
            strict=True,
        )
        self.assertEqual(ok_lock_fund, [])


if __name__ == "__main__":
    unittest.main()
