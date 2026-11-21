#!/usr/bin/env python3
"""Pure-stdlib static security, offline CSP, and structural tests for `docs/demo/index.html`.

Covers Shift-Left QA Pre-Flight Contract D1, D2, D3, D4, and D8 without external
dependencies or real browser automation imports.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import security_audit  # noqa: E402


DEMO_HTML_PATH = REPO_ROOT / "docs" / "demo" / "index.html"
EXPECTED_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "img-src data: blob:; "
    "font-src data:; "
    "connect-src 'none';"
)


class _DemoHTMLInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp_values: list[str] = []
        self.external_asset_refs: list[tuple[str, str, str]] = []
        self.root_relative_refs: list[tuple[str, str, str]] = []
        self.links: list[str] = []
        self.inline_event_attrs: list[tuple[str, str]] = []
        self.scripts: list[str] = []
        self.styles: list[str] = []
        self._in_script = False
        self._in_style = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        for k, _v in attrs:
            if k.lower().startswith("on"):
                self.inline_event_attrs.append((t, k.lower()))

        if t == "meta" and attr_map.get("http-equiv", "").lower() == "content-security-policy":
            self.csp_values.append(attr_map.get("content", "").strip())

        if t == "script":
            src = attr_map.get("src", "").strip()
            if src:
                if re.match(r"^(?:https?:)?//", src, re.IGNORECASE):
                    self.external_asset_refs.append((t, "src", src))
                if src.startswith("/") and not src.startswith("//"):
                    self.root_relative_refs.append((t, "src", src))
            else:
                self._in_script = True
                self._buf = []
        elif t == "style":
            self._in_style = True
            self._buf = []
        elif t == "link":
            href = attr_map.get("href", "").strip()
            if href:
                if re.match(r"^(?:https?:)?//", href, re.IGNORECASE):
                    self.external_asset_refs.append((t, "href", href))
                if href.startswith("/") and not href.startswith("//"):
                    self.root_relative_refs.append((t, "href", href))
        elif t in ("img", "iframe", "source", "video", "audio"):
            src = attr_map.get("src", "").strip()
            if src:
                if re.match(r"^(?:https?:)?//", src, re.IGNORECASE):
                    self.external_asset_refs.append((t, "src", src))
                if src.startswith("/") and not src.startswith("//"):
                    self.root_relative_refs.append((t, "src", src))
        elif t == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
                if href.startswith("/") and not href.startswith("//"):
                    self.root_relative_refs.append((t, "href", href))

    def handle_data(self, data: str) -> None:
        if self._in_script or self._in_style:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "script" and self._in_script:
            self.scripts.append("".join(self._buf))
            self._in_script = False
            self._buf = []
        elif t == "style" and self._in_style:
            self.styles.append("".join(self._buf))
            self._in_style = False
            self._buf = []


class TestDemoStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not DEMO_HTML_PATH.is_file():
            raise AssertionError(f"Missing standalone demo file: {DEMO_HTML_PATH}")
        cls.html = DEMO_HTML_PATH.read_text(encoding="utf-8")
        cls.inspector = _DemoHTMLInspector()
        cls.inspector.feed(cls.html)
        cls.combined_js = "\n".join(cls.inspector.scripts)
        cls.combined_css = "\n".join(cls.inspector.styles)

    def test_d1_strict_security_audit_zero_hits(self) -> None:
        hits = security_audit.scan_text(self.html, "docs/demo/index.html", strict=True)
        self.assertEqual(
            hits,
            [],
            f"Expected 0 strict security_audit hits in docs/demo/index.html, got: {hits[:8]}",
        )

    def test_d2_no_dangerous_js_apis_or_inline_handlers(self) -> None:
        self.assertEqual(
            self.inspector.inline_event_attrs,
            [],
            f"Inline event handlers must be avoided for strict XSS hygiene: {self.inspector.inline_event_attrs}",
        )
        forbidden_patterns = (
            (r"\beval\s*\(", "eval()"),
            (r"\bnew\s+Function\s*\(", "new Function()"),
            (r"\bdocument\.write(?:ln)?\s*\(", "document.write()"),
            (r"\.innerHTML\s*=", "innerHTML assignment"),
            (r"\.outerHTML\s*=", "outerHTML assignment"),
            (r"\binsertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
        )
        for rx, label in forbidden_patterns:
            self.assertIsNone(
                re.search(rx, self.combined_js),
                f"Forbidden dangerous JS API detected: {label}",
            )
        # Ensure URL protocol guard is present
        self.assertIn("javascript:", self.combined_js)
        self.assertIn("data:", self.combined_js)
        self.assertIn("vbscript:", self.combined_js)
        self.assertIn("isSafeHref", self.combined_js)

    def test_d3_strict_offline_csp_and_zero_external_network(self) -> None:
        self.assertIn(
            EXPECTED_CSP,
            self.inspector.csp_values,
            f"Missing exact offline CSP meta tag; found: {self.inspector.csp_values}",
        )
        self.assertEqual(
            self.inspector.external_asset_refs,
            [],
            f"External CDN/asset references forbidden: {self.inspector.external_asset_refs}",
        )
        self.assertIsNone(
            re.search(r"@import\s+url\s*\(\s*['\"]?https?:", self.combined_css, re.IGNORECASE),
            "External CSS @import forbidden",
        )
        network_apis = (
            (r"\bfetch\s*\(", "fetch()"),
            (r"\bXMLHttpRequest\b", "XMLHttpRequest"),
            (r"\bWebSocket\b", "WebSocket"),
            (r"\bEventSource\b", "EventSource"),
            (r"\bsendBeacon\s*\(", "sendBeacon()"),
        )
        for rx, label in network_apis:
            self.assertIsNone(
                re.search(rx, self.combined_js),
                f"Real outbound network API forbidden in offline demo: {label}",
            )

    def test_d4_dual_hosting_paths_and_storage_resilience(self) -> None:
        self.assertEqual(
            self.inspector.root_relative_refs,
            [],
            f"Root-relative asset/link refs break subpath & file:// hosting: {self.inspector.root_relative_refs}",
        )
        self.assertIsNone(
            re.search(r"\bhistory\.(?:pushState|replaceState)\s*\(", self.combined_js),
            "history.pushState/replaceState breaks file:// and subpath hosting",
        )
        self.assertNotIn("github.io", self.html.lower())
        # Verify links strictly point to allowlisted showcase & open-source repo
        self.assertIn("https://aibigbigworld.com/agy-bot/", self.inspector.links)
        self.assertIn("https://github.com/gaoshanyuhupo/agy-bot", self.inspector.links)
        # Ensure storage access is wrapped in try/catch fallback
        self.assertIn("safeReadPref", self.combined_js)
        self.assertIn("safeWritePref", self.combined_js)
        self.assertRegex(self.combined_js, r"try\s*\{[\s\S]{0,240}localStorage[\s\S]{0,240}\}\s*catch")

    def test_d8_inline_script_syntax_and_six_module_completeness(self) -> None:
        self.assertGreaterEqual(len(self.inspector.scripts), 1, "Expected inline <script> block")
        self.assertGreater(len(self.combined_js.strip()), 2000, "Inline script unexpectedly short")

        required_markers = (
            "workbench",
            "team",
            "camoufox",
            "models",
            "openbao",
            "memory",
            "kv/data/example/gateway-key",
            "policy-card-example",
            "AGY_MEMORY_READONLY=1",
            "198.51.100.42",
            "gw:cpa:6.2sol",
            "482910",
            "@example_main_bot",
            "@your_bot_1",
            "@your_bot_2",
        )
        for marker in required_markers:
            self.assertIn(marker, self.html, f"Expected demo structural marker missing: {marker}")

        node_bin = shutil.which("node")
        if node_bin:
            with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=True) as tmp:
                tmp.write(self.combined_js)
                tmp.flush()
                res = subprocess.run(
                    [node_bin, "--check", tmp.name],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    res.returncode,
                    0,
                    f"node --check failed on inline JS: {res.stderr or res.stdout}",
                )


if __name__ == "__main__":
    unittest.main()
