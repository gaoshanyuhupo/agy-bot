import assert from "node:assert/strict";
import test from "node:test";
import {
  clampCameraPan,
  computeBaseFitScale,
  computeCameraTransform,
  computeFitHeightScale,
  computeScaleBounds,
  computeViewModeScale,
  cycleMobileViewMode,
  formatCompactUrlLabel,
  getDefaultViewMode,
  isBlankBrowserUrl,
  isPortraitNarrowViewport,
  normalizeNavigableUrl,
  remoteToStagePoint,
  stageToRemotePoint,
  zoomCameraAroundAnchor,
} from "../src/utils/browserCamera.ts";

const REMOTE_W = 1920;
const REMOTE_H = 947;
const PORTRAIT_W = 390;
const PORTRAIT_H = 680;
const DESKTOP_W = 1280;
const DESKTOP_H = 760;

test("adaptive default view mode selects fit_height on narrow portrait and fit on desktop", () => {
  assert.equal(isPortraitNarrowViewport(PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H), true);
  assert.equal(getDefaultViewMode(PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H), "fit_height");

  assert.equal(isPortraitNarrowViewport(DESKTOP_W, DESKTOP_H, REMOTE_W, REMOTE_H), false);
  assert.equal(getDefaultViewMode(DESKTOP_W, DESKTOP_H, REMOTE_W, REMOTE_H), "fit");

  // Portrait remote inside portrait viewport does not need fit_height crop
  assert.equal(isPortraitNarrowViewport(PORTRAIT_W, PORTRAIT_H, 390, 844), false);
  assert.equal(getDefaultViewMode(PORTRAIT_W, PORTRAIT_H, 390, 844), "fit");
});

test("fit mode preserves exact 1920x947 aspect ratio with zero vertical distortion on 390x680", () => {
  const fitScale = computeBaseFitScale(PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H);
  assert.ok(Math.abs(fitScale - PORTRAIT_W / REMOTE_W) < 1e-12);

  const tf = computeCameraTransform({
    mode: "fit",
    customScale: 1,
    panX: 0,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });

  // Exact aspect ratio preservation (zero stretching)
  assert.ok(Math.abs(tf.drawW / tf.drawH - REMOTE_W / REMOTE_H) < 1e-9);
  assert.ok(Math.abs(tf.drawW - PORTRAIT_W) < 1e-9);
  assert.ok(tf.drawH < PORTRAIT_H);
  // Centered vertically with dark letterbox bars top & bottom
  assert.ok(Math.abs(tf.drawX) < 1e-9);
  assert.ok(Math.abs(tf.drawY - (PORTRAIT_H - tf.drawH) / 2) < 1e-9);
  assert.equal(tf.canPanX, false);
  assert.equal(tf.canPanY, false);
  assert.equal(tf.isZoomed, false);
});

test("fit_height mode fills height cleanly and centers horizontally on 390x680", () => {
  const fhScale = computeFitHeightScale(PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H);
  assert.ok(Math.abs(fhScale - PORTRAIT_H / REMOTE_H) < 1e-12);

  const tf = computeCameraTransform({
    mode: "fit_height",
    customScale: 1,
    panX: 0,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });

  assert.ok(Math.abs(tf.drawH - PORTRAIT_H) < 1e-9);
  assert.ok(Math.abs(tf.drawW / tf.drawH - REMOTE_W / REMOTE_H) < 1e-9);
  assert.ok(tf.drawW > PORTRAIT_W);
  assert.ok(Math.abs(tf.drawY) < 1e-9);
  assert.ok(Math.abs(tf.drawX - (PORTRAIT_W - tf.drawW) / 2) < 1e-9);
  assert.equal(tf.canPanX, true);
  assert.equal(tf.canPanY, false);
  assert.equal(tf.isZoomed, true);
});

test("stageToRemotePoint and remoteToStagePoint round-trip within <= 1px across all modes", () => {
  const modes = [
    { mode: "fit", customScale: 1, panX: 0, panY: 0 },
    { mode: "fit_height", customScale: 1, panX: 180, panY: 0 },
    { mode: "1:1", customScale: 1, panX: -420, panY: 110 },
    { mode: "custom", customScale: 1.65, panX: 350, panY: -220 },
  ];

  const sampleRemotePoints = [
    { x: 0, y: 0 },
    { x: 960, y: 473 },
    { x: 1920, y: 947 },
    { x: 412, y: 785 },
    { x: 1500, y: 120 },
  ];

  for (const cfg of modes) {
    const tf = computeCameraTransform({
      ...cfg,
      stageW: PORTRAIT_W,
      stageH: PORTRAIT_H,
      vw: REMOTE_W,
      vh: REMOTE_H,
    });

    for (const pt of sampleRemotePoints) {
      const stagePt = remoteToStagePoint(pt.x, pt.y, tf);
      const back = stageToRemotePoint(stagePt.x, stagePt.y, tf);
      assert.ok(back !== null, `expected in-frame point for mode=${cfg.mode}`);
      assert.ok(Math.abs(back.x - pt.x) <= 1, `x drift > 1px in mode=${cfg.mode}`);
      assert.ok(Math.abs(back.y - pt.y) <= 1, `y drift > 1px in mode=${cfg.mode}`);
    }
  }
});

test("black letterbox bar clicks are rejected unless clampInside is explicitly requested", () => {
  const tf = computeCameraTransform({
    mode: "fit",
    customScale: 1,
    panX: 0,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });

  // Top dark letterbox area (y = 10 is well above tf.drawY ~ 243.8)
  assert.equal(stageToRemotePoint(195, 10, tf), null);
  // Bottom dark letterbox area (y = 670 is well below tf.drawY + tf.drawH ~ 436.2)
  assert.equal(stageToRemotePoint(195, 670, tf), null);

  // Drag-release clampInside maps cleanly to top/bottom edge
  const clampedTop = stageToRemotePoint(195, 10, tf, { clampInside: true });
  assert.ok(clampedTop !== null);
  assert.equal(clampedTop.y, 0);
  const clampedBottom = stageToRemotePoint(195, 670, tf, { clampInside: true });
  assert.ok(clampedBottom !== null);
  assert.equal(clampedBottom.y, REMOTE_H);
});

test("clampCameraPan restricts pan bounds and prevents dragging dark void into view", () => {
  const fhScale = computeViewModeScale("fit_height", PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H);
  const clampedRight = clampCameraPan(99999, 99999, fhScale, PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H);
  assert.equal(clampedRight.panY, 0);
  assert.ok(Math.abs(clampedRight.panX - clampedRight.maxPanX) < 1e-9);

  // At maxPanX, left edge of remote image aligns exactly with x=0 of stage
  const tfLeftEdge = computeCameraTransform({
    mode: "fit_height",
    customScale: 1,
    panX: clampedRight.panX,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });
  assert.ok(Math.abs(tfLeftEdge.drawX - 0) < 1e-9);

  // At -maxPanX, right edge of remote image aligns exactly with stageW
  const tfRightEdge = computeCameraTransform({
    mode: "fit_height",
    customScale: 1,
    panX: -clampedRight.maxPanX,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });
  assert.ok(Math.abs(tfRightEdge.drawX + tfRightEdge.drawW - PORTRAIT_W) < 1e-9);
});

test("zoomCameraAroundAnchor pins anchor content and enforces scale bounds", () => {
  const bounds = computeScaleBounds(PORTRAIT_W, PORTRAIT_H, REMOTE_W, REMOTE_H);
  assert.ok(bounds.maxScale >= 3.0);

  const initialTf = computeCameraTransform({
    mode: "fit_height",
    customScale: 1,
    panX: 0,
    panY: 0,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });

  const anchorX = 140;
  const anchorY = 260;
  const beforeRemote = stageToRemotePoint(anchorX, anchorY, initialTf);
  assert.ok(beforeRemote !== null);

  const zoomed = zoomCameraAroundAnchor({
    currentTransform: initialTf,
    nextScale: 1.5,
    anchorStageX: anchorX,
    anchorStageY: anchorY,
  });
  const afterTf = computeCameraTransform({
    mode: "custom",
    customScale: zoomed.scale,
    panX: zoomed.panX,
    panY: zoomed.panY,
    stageW: PORTRAIT_W,
    stageH: PORTRAIT_H,
    vw: REMOTE_W,
    vh: REMOTE_H,
  });
  const afterRemote = stageToRemotePoint(anchorX, anchorY, afterTf);
  assert.ok(afterRemote !== null);
  assert.ok(Math.abs(afterRemote.x - beforeRemote.x) <= 1);
  assert.ok(Math.abs(afterRemote.y - beforeRemote.y) <= 1);

  // Clamping above maxScale & below minScale
  const over = zoomCameraAroundAnchor({
    currentTransform: initialTf,
    nextScale: 99,
    anchorStageX: 195,
    anchorStageY: 340,
  });
  assert.equal(over.scale, bounds.maxScale);

  const under = zoomCameraAroundAnchor({
    currentTransform: initialTf,
    nextScale: 0.01,
    anchorStageX: 195,
    anchorStageY: 340,
  });
  assert.equal(under.scale, bounds.minScale);
});

test("cycleMobileViewMode and formatCompactUrlLabel behave predictably", () => {
  assert.equal(cycleMobileViewMode("fit_height"), "fit");
  assert.equal(cycleMobileViewMode("fit"), "1:1");
  assert.equal(cycleMobileViewMode("1:1"), "fit_height");
  assert.equal(cycleMobileViewMode("custom"), "fit");

  assert.equal(formatCompactUrlLabel("https://example.com/search?q=1", "Search", true), "example.com/search");
  assert.equal(formatCompactUrlLabel("https://example.com/", "Home", true), "example.com");
  assert.equal(formatCompactUrlLabel("", "My Tab", true), "My Tab");
  assert.equal(formatCompactUrlLabel("https://example.com", "Home", false), "浏览器待机中");
});

test("isBlankBrowserUrl detects blank and new-tab URLs case-insensitively with trailing slashes", () => {
  for (const blank of [
    "",
    "   ",
    null,
    undefined,
    "about:blank",
    "ABOUT:BLANK",
    "  about:blank/  ",
    "about:newtab",
    "About:NewTab/",
    "chrome://newtab",
    "CHROME://NEWTAB/",
    "chrome://newtab///",
  ]) {
    assert.equal(isBlankBrowserUrl(blank), true, `Expected blank for ${String(blank)}`);
  }

  for (const nonBlank of [
    "https://example.com",
    "http://localhost:3000/app",
    "about:blank?x=1",
    "chrome://settings",
    "example.com",
  ]) {
    assert.equal(isBlankBrowserUrl(nonBlank), false, `Expected non-blank for ${nonBlank}`);
  }
});

test("normalizeNavigableUrl accepts valid URLs and rejects dangerous schemes, control chars, and invalid hosts", () => {
  const validCases = [
    ["https://example.com/path?q=1", "https://example.com/path?q=1"],
    ["http://example.com:8080/test", "http://example.com:8080/test"],
    ["  ABOUT:BLANK  ", "about:blank"],
    ["example.com", "https://example.com/"],
    ["example.com/search?q=1", "https://example.com/search?q=1"],
    ["example.com:8443/login", "https://example.com:8443/login"],
    ["localhost:3000/dashboard", "https://localhost:3000/dashboard"],
    ["127.0.0.1:8080/health", "https://127.0.0.1:8080/health"],
  ];
  for (const [input, expected] of validCases) {
    const res = normalizeNavigableUrl(input);
    assert.equal(res.ok, true, `Expected valid for ${JSON.stringify(input)}, got ${JSON.stringify(res)}`);
    if (res.ok) {
      assert.equal(res.url, expected);
    }
  }

  const invalidCases = [
    "",
    "   ",
    "javascript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "DATA:text/plain;base64,SGVsbG8=",
    "file:///etc/passwd",
    "FILE:///etc/hosts",
    "vbscript:msgbox(1)",
    "blob:https://example.com/uuid",
    "chrome://settings",
    "about:srcdoc",
    "ftp://example.com/file",
    "http://",
    "https://",
    "https://:80",
    "http:example.com",
    "foo bar",
    "example.com/a b",
    "https://example.com\nX-Injected: 1",
    "https://example.com\r\n",
    "\x00https://example.com",
    "//example.com",
    "\\\\example.com",
    "\\\\example.com/path",
    "\\example.com",
    "https:///example.com",
    "http:///example.com",
    "https://\\example.com",
    "http://\\example.com",
    "https:/\\example.com",
    "https://example.com:0",
    "http://example.com:0/path",
    "example.com:0",
    "example.com:0/app",
    "localhost:0",
    ":8080",
    "justword",
  ];
  for (const bad of invalidCases) {
    const res = normalizeNavigableUrl(bad);
    assert.equal(res.ok, false, `Expected invalid for ${JSON.stringify(bad)}, got ${JSON.stringify(res)}`);
    if (!res.ok) {
      assert.ok(res.error.length > 0, `Expected non-empty error for ${JSON.stringify(bad)}`);
      assert.ok(!/https?:\/\//i.test(res.error), `Error message must not contain raw external URL: ${res.error}`);
    }
  }

  // P1-3: Oversized unsupported scheme name must be truncated in error message (<= 24 chars + ellipsis)
  const longScheme = "a".repeat(200);
  const longSchemeRes = normalizeNavigableUrl(`${longScheme}:payload`);
  assert.equal(longSchemeRes.ok, false);
  if (!longSchemeRes.ok) {
    assert.ok(longSchemeRes.error.includes(`${"a".repeat(24)}…`), `Expected truncated scheme in ${longSchemeRes.error}`);
    assert.ok(!longSchemeRes.error.includes("a".repeat(30)), `Scheme must not echo >24 chars: ${longSchemeRes.error}`);
    assert.ok(longSchemeRes.error.length < 80, `Error message too long: ${longSchemeRes.error.length}`);
  }
});
