export type CameraViewMode = "fit" | "fit_height" | "1:1" | "custom";

export interface CameraTransform {
  mode: CameraViewMode;
  scale: number;
  fitScale: number;
  fitHeightScale: number;
  minScale: number;
  maxScale: number;
  panX: number;
  panY: number;
  maxPanX: number;
  maxPanY: number;
  drawX: number;
  drawY: number;
  drawW: number;
  drawH: number;
  stageW: number;
  stageH: number;
  vw: number;
  vh: number;
  canPanX: boolean;
  canPanY: boolean;
  isZoomed: boolean;
  relativeZoomPct: number;
}

export interface RemotePoint {
  x: number;
  y: number;
}

export interface StagePoint {
  x: number;
  y: number;
}

function sanitizePositive(value: number, fallback: number): number {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

/**
 * Returns true when rendering a landscape remote desktop inside a narrow portrait viewport
 * (e.g., iPhone portrait viewing 1920x947 desktop).
 */
export function isPortraitNarrowViewport(
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
  breakpointPx = 768,
): boolean {
  if (
    !Number.isFinite(stageW) ||
    !Number.isFinite(stageH) ||
    !Number.isFinite(vw) ||
    !Number.isFinite(vh)
  ) {
    return false;
  }
  return stageW > 0 && stageH > 0 && vw > 0 && vh > 0 && stageW < breakpointPx && stageW < stageH && vw > vh;
}

/**
 * Adaptive default camera view mode:
 * - Portrait narrow viewport viewing landscape desktop -> `fit_height` (readable & tappable centered crop)
 * - Desktop / landscape / matching aspect -> `fit` (full frame)
 */
export function getDefaultViewMode(
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
  breakpointPx = 768,
): CameraViewMode {
  return isPortraitNarrowViewport(stageW, stageH, vw, vh, breakpointPx) ? "fit_height" : "fit";
}

/**
 * Uniform full-fit scale factor with zero aspect-ratio distortion.
 */
export function computeBaseFitScale(
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
): number {
  const sw = sanitizePositive(stageW, 1);
  const sh = sanitizePositive(stageH, 1);
  const rw = sanitizePositive(vw, 1280);
  const rh = sanitizePositive(vh, 800);
  return Math.min(sw / rw, sh / rh);
}

/**
 * Uniform height-fit scale factor (clamped to never be smaller than base fit scale).
 */
export function computeFitHeightScale(
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
): number {
  const fitScale = computeBaseFitScale(stageW, stageH, vw, vh);
  const sh = sanitizePositive(stageH, 1);
  const rh = sanitizePositive(vh, 800);
  return Math.max(fitScale, sh / rh);
}

/**
 * Allowed free-zoom scale range `[fitScale, max(3.0, fitScale * 4)]`.
 */
export function computeScaleBounds(
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
): { minScale: number; maxScale: number } {
  const fitScale = computeBaseFitScale(stageW, stageH, vw, vh);
  return {
    minScale: fitScale,
    maxScale: Math.max(3.0, fitScale * 4),
  };
}

/**
 * Resolves the uniform scale factor for a given camera view mode.
 */
export function computeViewModeScale(
  mode: CameraViewMode,
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
  customScale?: number,
): number {
  const fitScale = computeBaseFitScale(stageW, stageH, vw, vh);
  const { minScale, maxScale } = computeScaleBounds(stageW, stageH, vw, vh);
  if (mode === "fit") return fitScale;
  if (mode === "fit_height") return clamp(computeFitHeightScale(stageW, stageH, vw, vh), minScale, maxScale);
  if (mode === "1:1") return 1.0;
  const target = typeof customScale === "number" && Number.isFinite(customScale) ? customScale : fitScale;
  return clamp(target, minScale, maxScale);
}

/**
 * Clamps centered pan offsets `(panX, panY)` so the projected image never drifts off-stage
 * and stays centered whenever it is smaller than the stage along an axis.
 */
export function clampCameraPan(
  panX: number,
  panY: number,
  scale: number,
  stageW: number,
  stageH: number,
  vw: number,
  vh: number,
): { panX: number; panY: number; maxPanX: number; maxPanY: number } {
  const sw = sanitizePositive(stageW, 1);
  const sh = sanitizePositive(stageH, 1);
  const rw = sanitizePositive(vw, 1280);
  const rh = sanitizePositive(vh, 800);
  const s = sanitizePositive(scale, 1);

  const drawW = rw * s;
  const drawH = rh * s;
  const maxPanX = Math.max(0, (drawW - sw) / 2);
  const maxPanY = Math.max(0, (drawH - sh) / 2);

  return {
    panX: clamp(panX, -maxPanX, maxPanX),
    panY: clamp(panY, -maxPanY, maxPanY),
    maxPanX,
    maxPanY,
  };
}

/**
 * Computes the complete zero-distortion virtual camera projection matrix/rectangle.
 */
export function computeCameraTransform(params: {
  mode: CameraViewMode;
  customScale: number;
  panX: number;
  panY: number;
  stageW: number;
  stageH: number;
  vw: number;
  vh: number;
}): CameraTransform {
  const sw = sanitizePositive(params.stageW, 1);
  const sh = sanitizePositive(params.stageH, 1);
  const rw = sanitizePositive(params.vw, 1280);
  const rh = sanitizePositive(params.vh, 800);

  const fitScale = computeBaseFitScale(sw, sh, rw, rh);
  const fitHeightScale = computeFitHeightScale(sw, sh, rw, rh);
  const { minScale, maxScale } = computeScaleBounds(sw, sh, rw, rh);
  const scale = computeViewModeScale(params.mode, sw, sh, rw, rh, params.customScale);

  const clamped = clampCameraPan(params.panX, params.panY, scale, sw, sh, rw, rh);
  const drawW = rw * scale;
  const drawH = rh * scale;
  const drawX = (sw - drawW) / 2 + clamped.panX;
  const drawY = (sh - drawH) / 2 + clamped.panY;

  return {
    mode: params.mode,
    scale,
    fitScale,
    fitHeightScale,
    minScale,
    maxScale,
    panX: clamped.panX,
    panY: clamped.panY,
    maxPanX: clamped.maxPanX,
    maxPanY: clamped.maxPanY,
    drawX,
    drawY,
    drawW,
    drawH,
    stageW: sw,
    stageH: sh,
    vw: rw,
    vh: rh,
    canPanX: clamped.maxPanX > 1,
    canPanY: clamped.maxPanY > 1,
    isZoomed: scale > fitScale * 1.04,
    relativeZoomPct: Math.max(1, Math.round((scale / fitScale) * 100)),
  };
}

/**
 * Computes new `(scale, panX, panY)` when zooming around a stage-space anchor point
 * (e.g., pinch midpoint or viewport center), keeping the remote content under the anchor stationary.
 */
export function zoomCameraAroundAnchor(params: {
  currentTransform: CameraTransform;
  nextScale: number;
  anchorStageX: number;
  anchorStageY: number;
}): { scale: number; panX: number; panY: number } {
  const { currentTransform, anchorStageX, anchorStageY } = params;
  const targetScale = clamp(
    params.nextScale,
    currentTransform.minScale,
    currentTransform.maxScale,
  );

  const remoteX = (anchorStageX - currentTransform.drawX) / currentTransform.scale;
  const remoteY = (anchorStageY - currentTransform.drawY) / currentTransform.scale;

  const newDrawW = currentTransform.vw * targetScale;
  const newDrawH = currentTransform.vh * targetScale;
  const rawPanX = anchorStageX - remoteX * targetScale - (currentTransform.stageW - newDrawW) / 2;
  const rawPanY = anchorStageY - remoteY * targetScale - (currentTransform.stageH - newDrawH) / 2;

  const clamped = clampCameraPan(
    rawPanX,
    rawPanY,
    targetScale,
    currentTransform.stageW,
    currentTransform.stageH,
    currentTransform.vw,
    currentTransform.vh,
  );

  return {
    scale: targetScale,
    panX: clamped.panX,
    panY: clamped.panY,
  };
}

/**
 * Maps stage CSS coordinates `(stageX, stageY)` to remote browser viewport pixel coordinates.
 * Returns `null` when the point lies outside the projected remote frame (dark letterbox bars),
 * unless `options.clampInside` is true (e.g. when releasing an active drag outside the frame).
 */
export function stageToRemotePoint(
  stageX: number,
  stageY: number,
  transform: CameraTransform,
  options?: { clampInside?: boolean },
): RemotePoint | null {
  if (!Number.isFinite(stageX) || !Number.isFinite(stageY) || transform.scale <= 0) {
    return null;
  }
  const inside =
    stageX >= transform.drawX &&
    stageX <= transform.drawX + transform.drawW &&
    stageY >= transform.drawY &&
    stageY <= transform.drawY + transform.drawH;

  if (!inside && !options?.clampInside) {
    return null;
  }

  const rx = (stageX - transform.drawX) / transform.scale;
  const ry = (stageY - transform.drawY) / transform.scale;
  return {
    x: Math.round(clamp(rx, 0, transform.vw)),
    y: Math.round(clamp(ry, 0, transform.vh)),
  };
}

/**
 * Maps remote browser viewport pixel coordinates `(remoteX, remoteY)` back into stage CSS coordinates.
 */
export function remoteToStagePoint(
  remoteX: number,
  remoteY: number,
  transform: CameraTransform,
): StagePoint {
  const rx = clamp(remoteX, 0, transform.vw);
  const ry = clamp(remoteY, 0, transform.vh);
  return {
    x: transform.drawX + rx * transform.scale,
    y: transform.drawY + ry * transform.scale,
  };
}

/**
 * Cycles the mobile bottom-bar preset camera view mode: `fit_height -> fit -> 1:1 -> fit_height`.
 */
export function cycleMobileViewMode(current: CameraViewMode): CameraViewMode {
  if (current === "fit_height") return "fit";
  if (current === "fit") return "1:1";
  if (current === "1:1") return "fit_height";
  return "fit";
}

/**
 * Formats a concise human-readable host/label for the compact mobile URL pill.
 */
export function formatCompactUrlLabel(url: string, title: string, running: boolean): string {
  if (!running) return "浏览器待机中";
  const trimmedUrl = (url || "").trim();
  if (trimmedUrl) {
    try {
      const parsed = new URL(trimmedUrl);
      if (parsed.hostname) {
        const path = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "";
        return `${parsed.hostname}${path}`;
      }
    } catch {
      // Fallback to raw url or title
    }
    return trimmedUrl;
  }
  return (title || "").trim() || "空白标签页";
}
