#!/usr/bin/env python3
"""Pure-stdlib static structural, API parity, and desensitization tests for the v2 AGY Studio Demo.

Validates:
1. Required demo source & build files exist under `webui/` and legacy hand-written `docs/demo/index.html` is removed.
2. `webui/src/demo/mockApi.ts` exports 100% of the symbols exported by `webui/src/api.ts`.
3. `webui/src/demo/mockBootstrapAuth.ts` exports 100% of the symbols exported by `webui/src/bootstrapAuth.ts`
   and never injects third-party Telegram SDK URLs.
4. Every demo file passes strict `security_audit.scan_text(..., strict=True)` with ZERO hits.
5. Production manifests (`webui/package.json`, `webui/vite.config.ts`, `webui/index.html`) remain unpolluted,
   and `.gitignore` excludes `webui/dist-demo/`.
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


WEBUI_DIR = REPO_ROOT / "webui"
DEMO_SRC_DIR = WEBUI_DIR / "src" / "demo"
DEMO_FILES = (
    WEBUI_DIR / "demo.html",
    WEBUI_DIR / "vite.demo.config.ts",
    DEMO_SRC_DIR / "main.demo.tsx",
    DEMO_SRC_DIR / "demoRuntime.ts",
    DEMO_SRC_DIR / "mockApi.ts",
    DEMO_SRC_DIR / "mockBootstrapAuth.ts",
    DEMO_SRC_DIR / "mockEventBus.ts",
)

EXPORT_SYMBOL_RE = re.compile(
    r"^export\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z0-9_]+)\b",
    re.MULTILINE,
)


def _extract_exported_symbols(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(EXPORT_SYMBOL_RE.findall(text))


class TestDemoStatic(unittest.TestCase):
    def test_required_demo_files_exist_and_legacy_demo_removed(self) -> None:
        for fp in DEMO_FILES:
            self.assertTrue(fp.is_file(), f"Missing required demo file: {fp}")
        legacy_demo = REPO_ROOT / "docs" / "demo" / "index.html"
        self.assertFalse(
            legacy_demo.exists(),
            f"Legacy hand-written static demo must be removed: {legacy_demo}",
        )

    def test_mock_api_covers_all_production_api_exports(self) -> None:
        prod_exports = _extract_exported_symbols(WEBUI_DIR / "src" / "api.ts")
        mock_exports = _extract_exported_symbols(DEMO_SRC_DIR / "mockApi.ts")
        self.assertGreaterEqual(len(prod_exports), 50, "Expected full production api.ts export set")
        missing = sorted(prod_exports - mock_exports)
        self.assertEqual(
            missing,
            [],
            f"mockApi.ts is missing production api.ts exports: {missing}",
        )

    def test_mock_bootstrap_auth_parity_and_zero_external_sdk(self) -> None:
        prod_exports = _extract_exported_symbols(WEBUI_DIR / "src" / "bootstrapAuth.ts")
        mock_exports = _extract_exported_symbols(DEMO_SRC_DIR / "mockBootstrapAuth.ts")
        missing = sorted(prod_exports - mock_exports)
        self.assertEqual(
            missing,
            [],
            f"mockBootstrapAuth.ts is missing bootstrapAuth.ts exports: {missing}",
        )
        mock_text = (DEMO_SRC_DIR / "mockBootstrapAuth.ts").read_text(encoding="utf-8")
        self.assertNotIn("telegram.org", mock_text.lower())
        self.assertNotIn("createElement", mock_text)

    def test_all_demo_files_pass_strict_security_audit(self) -> None:
        for fp in DEMO_FILES:
            rel = str(fp.relative_to(REPO_ROOT)).replace("\\", "/")
            text = fp.read_text(encoding="utf-8")
            hits = security_audit.scan_text(text, rel, strict=True)
            self.assertEqual(
                hits,
                [],
                f"Expected 0 strict security_audit hits in {rel}, got: {hits[:8]}",
            )

    def test_demo_runtime_interceptors_and_subpath_guards_present(self) -> None:
        runtime_text = (DEMO_SRC_DIR / "demoRuntime.ts").read_text(encoding="utf-8")
        self.assertIn("replaceState", runtime_text)
        self.assertIn("pushState", runtime_text)
        self.assertIn("/api/chat/stream", runtime_text)
        self.assertIn("/ws/browser", runtime_text)
        self.assertIn("DemoEventSource", runtime_text)
        self.assertIn("DemoWebSocket", runtime_text)
        self.assertIn("installFailClosedFetch", runtime_text)

        vite_demo = (WEBUI_DIR / "vite.demo.config.ts").read_text(encoding="utf-8")
        self.assertIn('base: "./"', vite_demo)
        self.assertIn('outDir: "dist-demo"', vite_demo)
        self.assertIn('format: "iife"', vite_demo)
        self.assertIn("inlineDynamicImports: true", vite_demo)
        self.assertIn("src/demo/mockApi.ts", vite_demo)
        self.assertIn("src/demo/mockBootstrapAuth.ts", vite_demo)

        mock_api_text = (DEMO_SRC_DIR / "mockApi.ts").read_text(encoding="utf-8")
        self.assertIn('room_id: "lobby"', mock_api_text)
        self.assertIn('role: "coordinator"', mock_api_text)
        self.assertIn("gw:", mock_api_text)
        self.assertIn("daily_14d", mock_api_text)

    def test_production_configs_unpolluted_and_gitignore_configured(self) -> None:
        pkg_text = (WEBUI_DIR / "package.json").read_text(encoding="utf-8")
        self.assertNotIn("demo", pkg_text.lower())

        prod_vite = (WEBUI_DIR / "vite.config.ts").read_text(encoding="utf-8")
        self.assertNotIn("dist-demo", prod_vite)
        self.assertNotIn("mockApi", prod_vite)

        prod_html = (WEBUI_DIR / "index.html").read_text(encoding="utf-8")
        self.assertIn("/src/main.tsx", prod_html)
        self.assertNotIn("main.demo", prod_html)

        gitignore_text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("webui/dist-demo/", gitignore_text)

        export_pub = REPO_ROOT / "scripts" / "export_public.py"
        if export_pub.is_file():
            self.assertIn('"dist-demo"', export_pub.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
