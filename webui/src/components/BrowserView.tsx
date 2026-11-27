import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Bot,
  ChevronDown,
  Eye,
  Hand,
  Keyboard,
  Loader2,
  Lock,
  Maximize2,
  Minimize2,
  MoreHorizontal,
  MousePointerClick,
  Move,
  Plus,
  RefreshCw,
  Rocket,
  RotateCcw,
  RotateCw,
  Scan,
  SlidersHorizontal,
  Square,
  Wifi,
  WifiOff,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  fetchBrowserBots,
  fetchBrowserEngines,
  fetchBrowserProfiles,
  fetchEgressNodes,
  launchBrowser,
  setBrowserOwnerBot,
  setBrowserTakeover,
  stopBrowser,
} from "../api";
import { BrowserConfigDrawer } from "./BrowserConfigDrawer";
import {
  clampCameraPan,
  computeCameraTransform,
  cycleMobileViewMode,
  formatCompactUrlLabel,
  getDefaultViewMode,
  remoteToStagePoint,
  stageToRemotePoint,
  zoomCameraAroundAnchor,
  type CameraViewMode,
} from "../utils/browserCamera";
import type {
  BrowserBotItem,
  BrowserEngineId,
  BrowserEngineInfo,
  BrowserProfileItem,
  EgressNodeItem,
  LiveBrowserState,
  StudioSession,
} from "../types";

interface BrowserViewProps {
  session: StudioSession;
  compact: boolean;
  variant?: "full" | "drawer";
  onExpandFull?: () => void;
  onCloseDrawer?: () => void;
  onSessionRevoked: (reason: string) => void;
  onRoleChanged?: (role: "admin" | "readonly") => void;
}

type TouchInteractMode = "tap_scroll" | "drag";

interface PendingDialog {
  dialog_id: string;
  dialog_type: string;
  message: string;
  default_value?: string;
}

interface CameraState {
  mode: CameraViewMode;
  customScale: number;
  panX: number;
  panY: number;
}

interface ClickRipple {
  id: number;
  remoteX: number;
  remoteY: number;
  kind: "left" | "right";
}

interface ActivePointerInfo {
  x: number;
  y: number;
  pointerType: string;
}

interface PinchGestureState {
  startDist: number;
  startScale: number;
  lastMidX: number;
  lastMidY: number;
}

interface SingleTouchGestureState {
  pointerId: number;
  startX: number;
  startY: number;
  lastX: number;
  lastY: number;
  startTs: number;
  mode: "pending" | "pan" | "scroll" | "drag" | "longpress_done";
  longPressTimer: number | null;
  lastWheelTs: number;
  accumWheelDx: number;
  accumWheelDy: number;
}

const DEFAULT_STATE: LiveBrowserState = {
  running: false,
  engine_mode: "idle",
  session_gen: 0,
  takeover_gen: 0,
  profile: null,
  pinned: false,
  egress: "direct",
  os: "",
  takeover: false,
  takeover_reason: "",
  ai_status: "",
  ai_busy: false,
  url: "",
  title: "",
  vw: 1280,
  vh: 800,
  tabs: [],
  quality_preset: "balanced",
  viewers: 0,
};

const INITIAL_CAMERA: CameraState = {
  mode: "fit",
  customScale: 1,
  panX: 0,
  panY: 0,
};

function mapKeyToPlaywright(e: KeyboardEvent): string | null {
  const key = e.key;
  if (key === "Shift" || key === "Control" || key === "Alt" || key === "Meta") {
    return null;
  }
  const mods: string[] = [];
  if (e.ctrlKey) mods.push("Control");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey && key.length > 1) mods.push("Shift");
  if (e.metaKey) mods.push("Meta");

  let base = key;
  if (key === " ") base = "Space";
  else if (key === "Esc") base = "Escape";

  if (mods.length > 0) {
    return `${mods.join("+")}+${base}`;
  }
  return base;
}

function viewModeShortLabel(mode: CameraViewMode, relativeZoomPct: number): string {
  if (mode === "fit_height") return "适高";
  if (mode === "fit") return "全图";
  if (mode === "1:1") return "1:1";
  return `${relativeZoomPct}%`;
}

export function BrowserView({
  session,
  compact,
  variant = "full",
  onExpandFull,
  onCloseDrawer,
  onSessionRevoked,
  onRoleChanged,
}: BrowserViewProps) {
  const isDrawer = variant === "drawer";
  const forceMobileChrome = compact || isDrawer;

  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [state, setState] = useState<LiveBrowserState>(DEFAULT_STATE);
  const [liveRole, setLiveRole] = useState<"admin" | "readonly">(session.role);
  const [urlInput, setUrlInput] = useState("");
  const [editingUrl, setEditingUrl] = useState(false);
  const [mobileUrlEditing, setMobileUrlEditing] = useState(false);
  const [tabsOpen, setTabsOpen] = useState(false);
  const [mobileTabsOpen, setMobileTabsOpen] = useState(false);
  const [mobileMoreOpen, setMobileMoreOpen] = useState(false);
  const [confirmMobileStop, setConfirmMobileStop] = useState(false);
  const [stopConfirmModalOpen, setStopConfirmModalOpen] = useState(false);
  const [desktopPillCollapsed, setDesktopPillCollapsed] = useState(false);

  // Virtual camera projection & touch interaction state
  const [stageSize, setStageSize] = useState<{ width: number; height: number }>({
    width: 0,
    height: 0,
  });
  const [cameraState, setCameraState] = useState<CameraState>(INITIAL_CAMERA);
  const [touchMode, setTouchMode] = useState<TouchInteractMode>("tap_scroll");
  const [clickRipple, setClickRipple] = useState<ClickRipple | null>(null);

  // Top-anchored smart soft keyboard overlay state
  const [kbSheetOpen, setKbSheetOpen] = useState(false);
  const [kbText, setKbText] = useState("");
  const [kbViewportBox, setKbViewportBox] = useState<{ top: number; maxHeight: number }>({
    top: 8,
    maxHeight: 280,
  });

  const [isFullscreen, setIsFullscreen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [pendingDialog, setPendingDialog] = useState<PendingDialog | null>(null);
  const [dialogPromptValue, setDialogPromptValue] = useState("");
  const [hasFrame, setHasFrame] = useState(false);

  // Stage 2: Dual-engine, Full-Roster AI selector, Manual Launch, Handback Note & Config Drawer
  const [engines, setEngines] = useState<BrowserEngineInfo[]>([
    { id: "camoufox", label: "Camoufox", available: true },
    { id: "external_chromium", label: "External Chromium", available: false },
  ]);
  const [rosterBots, setRosterBots] = useState<BrowserBotItem[]>([]);
  const [selectedBot, setSelectedBot] = useState<string>("");
  const [switchingBot, setSwitchingBot] = useState(false);
  const [profiles, setProfiles] = useState<BrowserProfileItem[]>([]);
  const [egressNodes, setEgressNodes] = useState<EgressNodeItem[]>([]);
  const [egressVaultReady, setEgressVaultReady] = useState(false);
  const [egressVaultError, setEgressVaultError] = useState("");
  const [drawSupported, setDrawSupported] = useState(false);
  const [pruneSupported, setPruneSupported] = useState(false);

  const [launchEngine, setLaunchEngine] = useState<BrowserEngineId>("camoufox");
  const [launchProfile, setLaunchProfile] = useState<string>("default");
  const [launchUrl, setLaunchUrl] = useState<string>("");
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState(false);

  const [configDrawerOpen, setConfigDrawerOpen] = useState(false);
  const [handbackModalOpen, setHandbackModalOpen] = useState(false);
  const [handbackNote, setHandbackNote] = useState("");
  const [submittingHandback, setSubmittingHandback] = useState(false);

  const stageWrapRef = useRef<HTMLDivElement | null>(null);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mobileUrlInputRef = useRef<HTMLInputElement | null>(null);
  const kbInputRef = useRef<HTMLInputElement | null>(null);
  const kbComposingRef = useRef<boolean>(false);

  const wsRef = useRef<WebSocket | null>(null);
  const connGenRef = useRef<number>(0);
  const stateRef = useRef<LiveBrowserState>(DEFAULT_STATE);
  const roleRef = useRef<"admin" | "readonly">(session.role);
  const latestBitmapRef = useRef<ImageBitmap | null>(null);

  const cameraRef = useRef<CameraState>(INITIAL_CAMERA);
  const userSelectedViewRef = useRef<boolean>(false);
  const lastSessionGenRef = useRef<number>(0);
  const lastTakeoverGenRef = useRef<number>(0);
  const lastActiveTabKeyRef = useRef<string>("");
  const touchModeRef = useRef<TouchInteractMode>("tap_scroll");

  const heldModifiersRef = useRef<Set<string>>(new Set());
  const heldMouseButtonsRef = useRef<Set<string>>(new Set());
  const heldPointerButtonsRef = useRef<Map<number, string>>(new Map());
  const activePointersRef = useRef<Map<number, ActivePointerInfo>>(new Map());
  const pinchStateRef = useRef<PinchGestureState | null>(null);
  const singleTouchRef = useRef<SingleTouchGestureState | null>(null);
  const gestureConsumedRef = useRef<boolean>(false);

  const lastMoveTsRef = useRef<number>(0);
  const lastTouchActivityTsRef = useRef<number>(0);
  const lastHintToastTsRef = useRef<number>(0);
  const prevTouchModeRef = useRef<TouchInteractMode>("tap_scroll");
  const toastTimerRef = useRef<number | null>(null);
  const rippleTimerRef = useRef<number | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const unmountedRef = useRef(false);

  useEffect(() => {
    stateRef.current = state;
    if (!editingUrl && !mobileUrlEditing && state.url) {
      setUrlInput(state.url);
    }
  }, [state, editingUrl, mobileUrlEditing]);

  useEffect(() => {
    roleRef.current = liveRole;
  }, [liveRole]);

  const canStopBrowser =
    liveRole === "admin" && state.running && !state.session_restricted;

  useEffect(() => {
    if (!canStopBrowser) {
      setStopConfirmModalOpen(false);
      setConfirmMobileStop(false);
    }
  }, [canStopBrowser]);

  const activeEngineLabel = useMemo(() => {
    const matched = engines.find((e) => e.id === state.engine);
    if (matched?.label) return matched.label;
    if (state.engine === "external_chromium") return "External Chromium";
    if (state.engine === "camoufox") return "Camoufox";
    return state.engine_mode === "sync_external" ? "External Chromium" : "Camoufox";
  }, [engines, state.engine, state.engine_mode]);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
    const durationMs = msg.startsWith("⚠️") ? 5200 : 3200;
    toastTimerRef.current = window.setTimeout(() => setToast(null), durationMs);
  }, []);

  const showDebouncedHint = useCallback(
    (msg: string) => {
      const now = performance.now();
      if (now - lastHintToastTsRef.current < 1600) return;
      lastHintToastTsRef.current = now;
      showToast(msg);
    },
    [showToast],
  );

  const triggerClickRipple = useCallback((remoteX: number, remoteY: number, kind: "left" | "right") => {
    setClickRipple({ id: Date.now() + Math.random(), remoteX, remoteY, kind });
    if (rippleTimerRef.current) window.clearTimeout(rippleTimerRef.current);
    rippleTimerRef.current = window.setTimeout(() => setClickRipple(null), 420);
  }, []);

  const refreshControlMetadata = useCallback(async () => {
    const [engRes, botsRes, profRes, egRes] = await Promise.allSettled([
      fetchBrowserEngines(),
      fetchBrowserBots(),
      fetchBrowserProfiles("all"),
      fetchEgressNodes(),
    ]);
    if (unmountedRef.current) return;

    if (engRes.status === "fulfilled" && engRes.value.ok) {
      setEngines(engRes.value.engines);
      const actOwner = engRes.value.active_session?.owner_bot;
      if (actOwner) {
        setSelectedBot(actOwner);
      }
    }
    if (botsRes.status === "fulfilled" && botsRes.value.ok) {
      const bData = botsRes.value;
      setRosterBots(bData.bots);
      const preferred =
        bData.active_owner_bot ||
        bData.default_owner_bot ||
        bData.bots[0]?.handle ||
        "";
      setSelectedBot((cur) => cur || preferred);
    }
    if (profRes.status === "fulfilled" && profRes.value.ok) {
      setProfiles(profRes.value.profiles);
    }
    if (egRes.status === "fulfilled" && egRes.value.ok) {
      setEgressNodes(egRes.value.nodes);
      setEgressVaultReady(egRes.value.vault_ready);
      setEgressVaultError(egRes.value.vault_error || "");
      setDrawSupported(egRes.value.draw_supported);
      setPruneSupported(egRes.value.prune_supported);
    }
  }, []);

  useEffect(() => {
    void refreshControlMetadata();
  }, [refreshControlMetadata, liveRole]);

  useEffect(() => {
    if (state.owner_bot) {
      setSelectedBot(state.owner_bot);
    }
  }, [state.owner_bot]);

  useEffect(() => {
    const engineProfs = profiles.filter((p) => p.engine === launchEngine);
    if (engineProfs.length > 0 && !engineProfs.some((p) => p.name === launchProfile)) {
      setLaunchProfile(engineProfs[0].name);
    }
  }, [launchEngine, launchProfile, profiles]);

  const sendWsJson = useCallback((payload: Record<string, unknown>) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(payload));
    return true;
  }, []);

  const sendInput = useCallback(
    (actionPayload: Record<string, unknown>) => {
      const st = stateRef.current;
      if (roleRef.current !== "admin" || !st.takeover || !st.running) return false;
      return sendWsJson({
        type: "input",
        session_gen: st.session_gen,
        takeover_gen: st.takeover_gen,
        ...actionPayload,
      });
    },
    [sendWsJson],
  );

  const cancelAllTouchGestures = useCallback(() => {
    if (singleTouchRef.current?.longPressTimer) {
      window.clearTimeout(singleTouchRef.current.longPressTimer);
    }
    singleTouchRef.current = null;
    pinchStateRef.current = null;
    activePointersRef.current.clear();
    gestureConsumedRef.current = false;
  }, []);

  const releaseAllHeldInputs = useCallback(() => {
    cancelAllTouchGestures();
    const st = stateRef.current;
    if (heldMouseButtonsRef.current.size > 0 && st.takeover && roleRef.current === "admin") {
      for (const btn of Array.from(heldMouseButtonsRef.current)) {
        sendWsJson({
          type: "input",
          action: "mouseup",
          button: btn,
          x: 0,
          y: 0,
          session_gen: st.session_gen,
          takeover_gen: st.takeover_gen,
        });
      }
    }
    heldMouseButtonsRef.current.clear();
    heldPointerButtonsRef.current.clear();
    heldModifiersRef.current.clear();
  }, [cancelAllTouchGestures, sendWsJson]);

  // Sync touchMode ref & release any active timers/held drag inputs whenever touchMode switches
  useEffect(() => {
    touchModeRef.current = touchMode;
    if (prevTouchModeRef.current !== touchMode) {
      prevTouchModeRef.current = touchMode;
      releaseAllHeldInputs();
    }
  }, [touchMode, releaseAllHeldInputs]);

  const clearCanvasFrame = useCallback(() => {
    if (latestBitmapRef.current) {
      latestBitmapRef.current.close();
      latestBitmapRef.current = null;
    }
    setHasFrame(false);
    const canvas = canvasRef.current;
    if (canvas) {
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#070a10";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      }
    }
  }, []);

  const getLiveStageRect = useCallback((): { left: number; top: number; width: number; height: number } | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return null;
    return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
  }, []);

  const computeLiveCameraTransform = useCallback(
    (camOverride?: CameraState) => {
      const cam = camOverride ?? cameraRef.current;
      const rect = getLiveStageRect();
      const sw = rect ? rect.width : stageSize.width || 1;
      const sh = rect ? rect.height : stageSize.height || 1;
      const st = stateRef.current;
      return computeCameraTransform({
        mode: cam.mode,
        customScale: cam.customScale,
        panX: cam.panX,
        panY: cam.panY,
        stageW: sw,
        stageH: sh,
        vw: st.vw || 1280,
        vh: st.vh || 800,
      });
    },
    [getLiveStageRect, stageSize.height, stageSize.width],
  );

  const drawLatestFrame = useCallback(
    (camOverride?: CameraState) => {
      const canvas = canvasRef.current;
      const bmp = latestBitmapRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) return;

      const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 3));
      const targetW = Math.max(1, Math.round(rect.width * dpr));
      const targetH = Math.max(1, Math.round(rect.height * dpr));
      if (canvas.width !== targetW || canvas.height !== targetH) {
        canvas.width = targetW;
        canvas.height = targetH;
      }
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.fillStyle = "#070a10";
      ctx.fillRect(0, 0, targetW, targetH);
      if (!bmp) return;

      const cam = camOverride ?? cameraRef.current;
      const st = stateRef.current;
      const tf = computeCameraTransform({
        mode: cam.mode,
        customScale: cam.customScale,
        panX: cam.panX,
        panY: cam.panY,
        stageW: rect.width,
        stageH: rect.height,
        vw: st.vw || 1280,
        vh: st.vh || 800,
      });

      // Use true backing-store ratios rather than nominal DPR to prevent rounding drift
      const ratioX = targetW / rect.width;
      const ratioY = targetH / rect.height;

      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = "high";
      ctx.drawImage(
        bmp,
        tf.drawX * ratioX,
        tf.drawY * ratioY,
        tf.drawW * ratioX,
        tf.drawH * ratioY,
      );
    },
    [],
  );

  const applyCameraState = useCallback(
    (next: CameraState, markUserSelected: boolean) => {
      if (markUserSelected) {
        userSelectedViewRef.current = true;
      }
      cameraRef.current = next;
      setCameraState(next);
      drawLatestFrame(next);
    },
    [drawLatestFrame],
  );

  // Measure stage dimensions via ResizeObserver
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const measure = () => {
      const rect = el.getBoundingClientRect();
      const w = Math.round(rect.width);
      const h = Math.round(rect.height);
      setStageSize((prev) => (prev.width === w && prev.height === h ? prev : { width: w, height: h }));
      drawLatestFrame();
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [drawLatestFrame]);

  // Adaptive default view mode (portrait narrow -> fit_height; desktop -> fit) until user overrides
  useEffect(() => {
    if (stageSize.width < 2 || stageSize.height < 2) return;
    if (state.vw <= 0 || state.vh <= 0) return;

    if (!userSelectedViewRef.current) {
      const desired = getDefaultViewMode(stageSize.width, stageSize.height, state.vw, state.vh);
      if (cameraRef.current.mode !== desired || cameraRef.current.panX !== 0 || cameraRef.current.panY !== 0) {
        const next: CameraState = {
          mode: desired,
          customScale: 1,
          panX: 0,
          panY: 0,
        };
        cameraRef.current = next;
        setCameraState(next);
        drawLatestFrame(next);
        return;
      }
    }
    drawLatestFrame();
  }, [stageSize.width, stageSize.height, state.vw, state.vh, drawLatestFrame]);

  // Release held inputs / cancel gestures and close transient overlays on session/takeover/real-tab transitions
  useEffect(() => {
    const activeTabIdx = state.tabs.findIndex((t) => t.active);
    const activeTab = activeTabIdx >= 0 ? state.tabs[activeTabIdx] : undefined;
    const activeTabId =
      activeTab && "id" in activeTab && (activeTab as { id?: string | number }).id != null
        ? String((activeTab as { id?: string | number }).id)
        : "";
    // Track only real tab switches (active index / count / optional stable tab id) — NEVER tab.url,
    // so SPA history.replaceState updates do not interrupt portrait scrolling or pinch-zoom.
    const activeTabKey = `${activeTabIdx}:${state.tabs.length}:${activeTabId}`;

    const sessionChanged = state.session_gen !== lastSessionGenRef.current;
    const takeoverChanged = state.takeover_gen !== lastTakeoverGenRef.current;
    const tabChanged = activeTabKey !== lastActiveTabKeyRef.current;

    if (sessionChanged) {
      lastSessionGenRef.current = state.session_gen;
      userSelectedViewRef.current = false;
      setKbSheetOpen(false);
      setMobileUrlEditing(false);
      setConfirmMobileStop(false);
    }
    if (takeoverChanged) {
      lastTakeoverGenRef.current = state.takeover_gen;
    }
    if (tabChanged) {
      lastActiveTabKeyRef.current = activeTabKey;
    }
    if (sessionChanged || takeoverChanged || tabChanged) {
      releaseAllHeldInputs();
    }
  }, [state.session_gen, state.takeover_gen, state.tabs, releaseAllHeldInputs]);

  const canControl = liveRole === "admin" && state.takeover && state.running;

  // Auto-close keyboard sheet & mobile URL editor when control is lost
  useEffect(() => {
    if (!canControl) {
      setKbSheetOpen(false);
      setMobileUrlEditing(false);
    }
  }, [canControl]);

  // Track window.visualViewport for top-anchored smart keyboard overlay
  useEffect(() => {
    kbComposingRef.current = false;
    if (!kbSheetOpen) return;
    const syncVv = () => {
      const vv = window.visualViewport;
      if (vv) {
        setKbViewportBox({
          top: Math.max(8, Math.round(vv.offsetTop + 8)),
          maxHeight: Math.max(180, Math.round(vv.height - 16)),
        });
      } else {
        setKbViewportBox({
          top: 8,
          maxHeight: Math.max(180, window.innerHeight - 16),
        });
      }
    };
    syncVv();
    const vv = window.visualViewport;
    if (vv) {
      vv.addEventListener("resize", syncVv);
      vv.addEventListener("scroll", syncVv);
    }
    window.addEventListener("resize", syncVv);
    const focusTimer = window.setTimeout(() => {
      kbInputRef.current?.focus();
    }, 30);
    return () => {
      kbComposingRef.current = false;
      window.clearTimeout(focusTimer);
      if (vv) {
        vv.removeEventListener("resize", syncVv);
        vv.removeEventListener("scroll", syncVv);
      }
      window.removeEventListener("resize", syncVv);
    };
  }, [kbSheetOpen]);

  useEffect(() => {
    if (!mobileUrlEditing) return;
    const t = window.setTimeout(() => {
      mobileUrlInputRef.current?.focus();
      mobileUrlInputRef.current?.select();
    }, 20);
    return () => window.clearTimeout(t);
  }, [mobileUrlEditing]);

  // Connect same-origin WebSocket `/ws/browser`
  const connectWs = useCallback(() => {
    if (unmountedRef.current) return;
    // Advance monotonic connection generation to invalidate all callbacks & in-flight bitmap decodes from prior sockets
    const gen = ++connGenRef.current;
    const prevWs = wsRef.current;
    wsRef.current = null;
    if (prevWs && prevWs.readyState <= WebSocket.OPEN) {
      prevWs.close();
    }
    clearCanvasFrame();
    setWsStatus("connecting");
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/browser`);
    ws.binaryType = "blob";
    wsRef.current = ws;

    const isCurrentConn = () =>
      !unmountedRef.current && wsRef.current === ws && connGenRef.current === gen;

    ws.onopen = () => {
      if (!isCurrentConn()) return;
      setWsStatus("connected");
    };

    ws.onmessage = async (ev) => {
      if (!isCurrentConn()) return;
      if (ev.data instanceof Blob) {
        try {
          const bmp = await createImageBitmap(ev.data);
          // Re-check connection generation AFTER async decode to discard stale frames from revoked/closed sockets
          if (!isCurrentConn()) {
            bmp.close();
            return;
          }
          if (latestBitmapRef.current) {
            latestBitmapRef.current.close();
          }
          latestBitmapRef.current = bmp;
          setHasFrame(true);
          drawLatestFrame();
        } catch {
          // Ignore malformed frame
        }
        return;
      }
      if (typeof ev.data !== "string") return;
      try {
        const msg = JSON.parse(ev.data) as Record<string, unknown>;
        if (!isCurrentConn()) return;
        const mtype = String(msg.type || "");
        if (mtype === "auth_ok") {
          const r = msg.role === "admin" ? "admin" : "readonly";
          roleRef.current = r;
          setLiveRole(r);
          onRoleChanged?.(r);
        } else if (mtype === "role_changed") {
          const r = msg.role === "admin" ? "admin" : "readonly";
          releaseAllHeldInputs();
          clearCanvasFrame();
          roleRef.current = r;
          setLiveRole(r);
          onRoleChanged?.(r);
          setState((prev) => ({ ...prev, takeover: false }));
          setKbSheetOpen(false);
          setMobileUrlEditing(false);
          setStopConfirmModalOpen(false);
          setConfirmMobileStop(false);
          const infoMsg =
            typeof msg.message === "string" && msg.message
              ? msg.message
              : `权限已变更为 ${r}，正在重新连接`;
          showToast(`🔒 ${infoMsg}`);
        } else if (mtype === "auth_error") {
          const errMsg = String(msg.error || "访问权限已被撤销");
          if (msg.source === "studio_auth") {
            connGenRef.current += 1;
            releaseAllHeldInputs();
            clearCanvasFrame();
            onSessionRevoked(errMsg);
          } else {
            showToast(`⚠️ ${errMsg}`);
          }
        } else if (mtype === "state") {
          const prevTakeover = stateRef.current.takeover;
          const nextState: LiveBrowserState = {
            ...DEFAULT_STATE,
            ...(msg as unknown as Partial<LiveBrowserState>),
            vw: Number(msg.vw) || 1280,
            vh: Number(msg.vh) || 800,
            tabs: Array.isArray(msg.tabs) ? (msg.tabs as LiveBrowserState["tabs"]) : [],
          };
          if (prevTakeover && !nextState.takeover) {
            releaseAllHeldInputs();
          }
          if (nextState.session_restricted || !nextState.running) {
            clearCanvasFrame();
            setStopConfirmModalOpen(false);
            setConfirmMobileStop(false);
          }
          setState(nextState);
        } else if (mtype === "toast" && typeof msg.message === "string") {
          showToast(msg.message);
        } else if (mtype === "takeover_ack") {
          if (!msg.ok && typeof msg.error === "string") {
            showToast(`⚠️ ${msg.error}`);
          }
        } else if (mtype === "dialog_open") {
          setPendingDialog({
            dialog_id: String(msg.dialog_id || ""),
            dialog_type: String(msg.dialog_type || "alert"),
            message: String(msg.message || ""),
            default_value: typeof msg.default_value === "string" ? msg.default_value : "",
          });
          setDialogPromptValue(typeof msg.default_value === "string" ? msg.default_value : "");
        } else if (mtype === "dialog_closed") {
          setPendingDialog((cur) =>
            cur && cur.dialog_id === String(msg.dialog_id || "") ? null : cur,
          );
        }
      } catch {
        // Ignore parse error
      }
    };

    ws.onclose = (ev) => {
      if (!isCurrentConn()) return;
      // Invalidate this generation so any still-decoding async ImageBitmap is discarded immediately
      connGenRef.current += 1;
      wsRef.current = null;
      releaseAllHeldInputs();
      clearCanvasFrame();
      setWsStatus("disconnected");
      if (ev.code === 4003) {
        setState((prev) => ({ ...prev, takeover: false }));
        setStopConfirmModalOpen(false);
        setConfirmMobileStop(false);
        onSessionRevoked("会话权限已被撤销或已退出登录");
        return;
      }
      if (ev.code === 4008) {
        // Role downgraded (e.g. admin -> readonly): reset takeover immediately & reconnect fast
        roleRef.current = "readonly";
        setLiveRole("readonly");
        onRoleChanged?.("readonly");
        setState((prev) => ({ ...prev, takeover: false }));
        setKbSheetOpen(false);
        setMobileUrlEditing(false);
        setStopConfirmModalOpen(false);
        setConfirmMobileStop(false);
        if (reconnectTimerRef.current) window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = window.setTimeout(() => {
          if (!unmountedRef.current) connectWs();
        }, 250);
        return;
      }
      if (reconnectTimerRef.current) window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = window.setTimeout(() => {
        if (!unmountedRef.current) connectWs();
      }, 2500);
    };

    ws.onerror = () => {
      // Handled by onclose
    };
  }, [clearCanvasFrame, drawLatestFrame, onRoleChanged, onSessionRevoked, releaseAllHeldInputs, showToast]);

  useEffect(() => {
    unmountedRef.current = false;
    connectWs();
    return () => {
      unmountedRef.current = true;
      connGenRef.current += 1;
      cancelAllTouchGestures();
      if (reconnectTimerRef.current) window.clearTimeout(reconnectTimerRef.current);
      if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
      if (rippleTimerRef.current) window.clearTimeout(rippleTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      clearCanvasFrame();
    };
  }, [cancelAllTouchGestures, clearCanvasFrame, connectWs]);

  // Automatic modifier & mouse release on window blur / visibility change
  useEffect(() => {
    const onBlur = () => releaseAllHeldInputs();
    const onVis = () => {
      if (document.hidden) releaseAllHeldInputs();
    };
    const onFsChange = () => {
      setIsFullscreen(Boolean(document.fullscreenElement));
    };
    window.addEventListener("blur", onBlur);
    document.addEventListener("visibilitychange", onVis);
    document.addEventListener("fullscreenchange", onFsChange);
    return () => {
      window.removeEventListener("blur", onBlur);
      document.removeEventListener("visibilitychange", onVis);
      document.removeEventListener("fullscreenchange", onFsChange);
    };
  }, [releaseAllHeldInputs]);

  // Keyboard listener when takeover active & not typing in URL/dialog/keyboard-sheet input
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const st = stateRef.current;
      if (roleRef.current !== "admin" || !st.takeover || !st.running) return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable)
      ) {
        return;
      }
      if (e.key === "Control" || e.key === "Shift" || e.key === "Alt" || e.key === "Meta") {
        heldModifiersRef.current.add(e.key);
        return;
      }
      const mapped = mapKeyToPlaywright(e);
      if (!mapped) return;
      e.preventDefault();
      if (mapped.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
        sendInput({ action: "type", text: mapped });
      } else {
        sendInput({ action: "press", key: mapped });
      }
    };
    const onKeyUp = (e: KeyboardEvent) => {
      if (e.key === "Control" || e.key === "Shift" || e.key === "Alt" || e.key === "Meta") {
        heldModifiersRef.current.delete(e.key);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
    };
  }, [sendInput]);

  // Helper: map client coordinates to stage CSS coordinates
  const getStageCoords = useCallback(
    (clientX: number, clientY: number): { x: number; y: number } | null => {
      const rect = getLiveStageRect();
      if (!rect) return null;
      return {
        x: clientX - rect.left,
        y: clientY - rect.top,
      };
    },
    [getLiveStageRect],
  );

  // Map client coordinates -> remote browser coordinates via unified camera projection
  const mapClientToRemote = useCallback(
    (
      clientX: number,
      clientY: number,
      options?: { clampInside?: boolean },
    ): { x: number; y: number } | null => {
      const stagePt = getStageCoords(clientX, clientY);
      if (!stagePt) return null;
      const tf = computeLiveCameraTransform();
      return stageToRemotePoint(stagePt.x, stagePt.y, tf, options);
    },
    [computeLiveCameraTransform, getStageCoords],
  );

  const resolvePointerButton = (e: React.PointerEvent<HTMLCanvasElement>): string => {
    if (e.pointerType === "touch" || e.button < 0) return "left";
    return e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
  };

  // ---------------- Unified Pointer Events (Desktop Mouse + Mobile Multi-Touch State Machine) ----------------

  const handleCanvasPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!state.running || state.session_restricted) return;

    // 1. Desktop mouse: preserve 100% native mouse semantics
    if (e.pointerType === "mouse") {
      if (!canControl) {
        if (liveRole === "admin" && state.running && !state.takeover) {
          showDebouncedHint("请先点击【人工接管】再操作页面");
        }
        return;
      }
      if (!e.isPrimary) return;
      e.preventDefault();
      const pos = mapClientToRemote(e.clientX, e.clientY);
      if (!pos) return;
      try {
        e.currentTarget.setPointerCapture(e.pointerId);
      } catch {
        // Ignore capture errors on synthetic pointers
      }
      const btn = resolvePointerButton(e);
      heldPointerButtonsRef.current.set(e.pointerId, btn);
      heldMouseButtonsRef.current.add(btn);
      sendInput({ action: "mousedown", button: btn, x: pos.x, y: pos.y });
      triggerClickRipple(pos.x, pos.y, btn === "right" ? "right" : "left");
      return;
    }

    // 2. Touch / Pen: full multi-touch camera + tap/scroll/longpress/drag state machine
    lastTouchActivityTsRef.current = performance.now();
    e.preventDefault();
    const stagePt = getStageCoords(e.clientX, e.clientY);
    if (!stagePt) return;

    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      // Ignore capture errors
    }

    activePointersRef.current.set(e.pointerId, {
      x: stagePt.x,
      y: stagePt.y,
      pointerType: e.pointerType,
    });

    // Multi-touch (2+ fingers): enter pinch-zoom + two-finger pan; NEVER emit remote click
    if (activePointersRef.current.size >= 2) {
      if (singleTouchRef.current?.longPressTimer) {
        window.clearTimeout(singleTouchRef.current.longPressTimer);
      }
      // If a drag was already holding mouse down, release it cleanly at the 1st finger's last drag point before pinching
      if (singleTouchRef.current?.mode === "drag" && heldMouseButtonsRef.current.has("left")) {
        const lastPos =
          stageToRemotePoint(
            singleTouchRef.current.lastX,
            singleTouchRef.current.lastY,
            computeLiveCameraTransform(),
            { clampInside: true },
          ) ?? mapClientToRemote(e.clientX, e.clientY, { clampInside: true });
        if (lastPos) {
          sendInput({ action: "mouseup", button: "left", x: lastPos.x, y: lastPos.y });
        }
        heldMouseButtonsRef.current.delete("left");
        heldPointerButtonsRef.current.delete(singleTouchRef.current.pointerId);
      }
      singleTouchRef.current = null;
      gestureConsumedRef.current = true;

      const pts = Array.from(activePointersRef.current.values());
      const p1 = pts[0];
      const p2 = pts[1];
      const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
      const midX = (p1.x + p2.x) / 2;
      const midY = (p1.y + p2.y) / 2;
      const tf = computeLiveCameraTransform();
      pinchStateRef.current = {
        startDist: Math.max(10, dist),
        startScale: tf.scale,
        lastMidX: midX,
        lastMidY: midY,
      };
      return;
    }

    // Single finger started after a pinch released one finger -> wait until all fingers lift
    if (gestureConsumedRef.current) return;

    // Single finger in Drag Mode while controlling -> immediate remote mousedown
    if (canControl && touchModeRef.current === "drag") {
      const pos = stageToRemotePoint(stagePt.x, stagePt.y, computeLiveCameraTransform());
      if (!pos) return;
      singleTouchRef.current = {
        pointerId: e.pointerId,
        startX: stagePt.x,
        startY: stagePt.y,
        lastX: stagePt.x,
        lastY: stagePt.y,
        startTs: performance.now(),
        mode: "drag",
        longPressTimer: null,
        lastWheelTs: 0,
        accumWheelDx: 0,
        accumWheelDy: 0,
      };
      heldPointerButtonsRef.current.set(e.pointerId, "left");
      heldMouseButtonsRef.current.add("left");
      sendInput({ action: "mousedown", button: "left", x: pos.x, y: pos.y });
      triggerClickRipple(pos.x, pos.y, "left");
      return;
    }

    // Single finger in View-Only OR Tap-Scroll mode
    let longPressTimer: number | null = null;
    if (canControl && touchModeRef.current === "tap_scroll") {
      const downPointerId = e.pointerId;
      const downX = stagePt.x;
      const downY = stagePt.y;
      longPressTimer = window.setTimeout(() => {
        if (touchModeRef.current !== "tap_scroll") return;
        const cur = singleTouchRef.current;
        if (!cur || cur.pointerId !== downPointerId || cur.mode !== "pending") return;
        if (activePointersRef.current.size !== 1 || gestureConsumedRef.current) return;
        const st = stateRef.current;
        if (roleRef.current !== "admin" || !st.takeover || !st.running) return;
        const pos = stageToRemotePoint(downX, downY, computeLiveCameraTransform());
        if (!pos) return;
        cur.mode = "longpress_done";
        cur.longPressTimer = null;
        gestureConsumedRef.current = true;
        lastTouchActivityTsRef.current = performance.now();
        sendInput({ action: "rightclick", x: pos.x, y: pos.y });
        triggerClickRipple(pos.x, pos.y, "right");
        if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
          try {
            navigator.vibrate(12);
          } catch {
            // Ignore vibrate restriction
          }
        }
      }, 500);
    }

    singleTouchRef.current = {
      pointerId: e.pointerId,
      startX: stagePt.x,
      startY: stagePt.y,
      lastX: stagePt.x,
      lastY: stagePt.y,
      startTs: performance.now(),
      mode: "pending",
      longPressTimer,
      lastWheelTs: 0,
      accumWheelDx: 0,
      accumWheelDy: 0,
    };
  };

  const handleCanvasPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!state.running || state.session_restricted) return;

    // 1. Desktop mouse
    if (e.pointerType === "mouse") {
      if (!canControl || !e.isPrimary) return;
      const now = performance.now();
      if (now - lastMoveTsRef.current < 32) return;
      lastMoveTsRef.current = now;
      const pos = mapClientToRemote(e.clientX, e.clientY, {
        clampInside: heldMouseButtonsRef.current.size > 0,
      });
      if (!pos) return;
      sendInput({ action: "move", x: pos.x, y: pos.y });
      return;
    }

    // 2. Touch / Pen
    lastTouchActivityTsRef.current = performance.now();
    if (!activePointersRef.current.has(e.pointerId)) return;
    const stagePt = getStageCoords(e.clientX, e.clientY);
    if (!stagePt) return;

    activePointersRef.current.set(e.pointerId, {
      x: stagePt.x,
      y: stagePt.y,
      pointerType: e.pointerType,
    });

    // Two-finger pinch zoom & pan
    if (activePointersRef.current.size >= 2) {
      const pts = Array.from(activePointersRef.current.values());
      const p1 = pts[0];
      const p2 = pts[1];
      const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
      const midX = (p1.x + p2.x) / 2;
      const midY = (p1.y + p2.y) / 2;
      const pinch = pinchStateRef.current;
      if (!pinch) {
        const tf = computeLiveCameraTransform();
        pinchStateRef.current = {
          startDist: Math.max(10, dist),
          startScale: tf.scale,
          lastMidX: midX,
          lastMidY: midY,
        };
        return;
      }

      const dMidX = midX - pinch.lastMidX;
      const dMidY = midY - pinch.lastMidY;
      pinch.lastMidX = midX;
      pinch.lastMidY = midY;

      const curCam = cameraRef.current;
      const curTf = computeLiveCameraTransform(curCam);
      const panned = clampCameraPan(
        curTf.panX + dMidX,
        curTf.panY + dMidY,
        curTf.scale,
        curTf.stageW,
        curTf.stageH,
        curTf.vw,
        curTf.vh,
      );
      const pannedTf = computeLiveCameraTransform({
        mode: "custom",
        customScale: curTf.scale,
        panX: panned.panX,
        panY: panned.panY,
      });

      const nextScale = pinch.startScale * (Math.max(10, dist) / pinch.startDist);
      const zoomed = zoomCameraAroundAnchor({
        currentTransform: pannedTf,
        nextScale,
        anchorStageX: midX,
        anchorStageY: midY,
      });

      applyCameraState(
        {
          mode: "custom",
          customScale: zoomed.scale,
          panX: zoomed.panX,
          panY: zoomed.panY,
        },
        true,
      );
      return;
    }

    const stTouch = singleTouchRef.current;
    if (!stTouch || stTouch.pointerId !== e.pointerId || gestureConsumedRef.current) return;

    const stepDx = stagePt.x - stTouch.lastX;
    const stepDy = stagePt.y - stTouch.lastY;
    stTouch.lastX = stagePt.x;
    stTouch.lastY = stagePt.y;

    // Drag mode -> send throttled remote move
    if (stTouch.mode === "drag") {
      if (!canControl) return;
      const now = performance.now();
      if (now - lastMoveTsRef.current < 28) return;
      lastMoveTsRef.current = now;
      const pos = stageToRemotePoint(stagePt.x, stagePt.y, computeLiveCameraTransform(), {
        clampInside: true,
      });
      if (!pos) return;
      sendInput({ action: "move", x: pos.x, y: pos.y });
      return;
    }

    const totalDx = stagePt.x - stTouch.startX;
    const totalDy = stagePt.y - stTouch.startY;
    const dist = Math.hypot(totalDx, totalDy);

    if (stTouch.mode === "pending") {
      if (dist < 8) return;
      if (stTouch.longPressTimer) {
        window.clearTimeout(stTouch.longPressTimer);
        stTouch.longPressTimer = null;
      }
      const tf = computeLiveCameraTransform();
      if (!canControl) {
        stTouch.mode = "pan";
      } else if (tf.canPanX && Math.abs(totalDx) > Math.abs(totalDy) * 1.25) {
        stTouch.mode = "pan";
      } else {
        stTouch.mode = "scroll";
      }
    }

    if (stTouch.mode === "pan") {
      const curTf = computeLiveCameraTransform();
      const clamped = clampCameraPan(
        curTf.panX + stepDx,
        curTf.panY + (canControl && !curTf.canPanY ? 0 : stepDy),
        curTf.scale,
        curTf.stageW,
        curTf.stageH,
        curTf.vw,
        curTf.vh,
      );
      applyCameraState(
        {
          mode: cameraRef.current.mode,
          customScale: cameraRef.current.customScale,
          panX: clamped.panX,
          panY: clamped.panY,
        },
        false,
      );
      return;
    }

    if (stTouch.mode === "scroll" && canControl) {
      stTouch.accumWheelDx += stepDx;
      stTouch.accumWheelDy += stepDy;
      const now = performance.now();
      if (now - stTouch.lastWheelTs < 28) return;
      const tf = computeLiveCameraTransform();
      const factor = Math.max(0.35, tf.scale);
      // Natural scroll mapping: swipe finger UP (dy < 0) scrolls page DOWN (wheelDy > 0)
      const wheelDy = Math.round((-stTouch.accumWheelDy / factor) * 1.15);
      const wheelDx = tf.canPanX ? 0 : Math.round((-stTouch.accumWheelDx / factor) * 1.0);
      stTouch.accumWheelDx = 0;
      stTouch.accumWheelDy = 0;
      stTouch.lastWheelTs = now;
      if (wheelDy !== 0 || wheelDx !== 0) {
        const remotePt = stageToRemotePoint(stagePt.x, stagePt.y, tf, { clampInside: true });
        sendInput({
          action: "wheel",
          dx: wheelDx,
          dy: wheelDy,
          ...(remotePt ? { x: remotePt.x, y: remotePt.y } : {}),
        });
      }
    }
  };

  const finishCanvasPointer = (
    e: React.PointerEvent<HTMLCanvasElement>,
    isCancelOrLost: boolean,
  ) => {
    try {
      if (e.currentTarget.hasPointerCapture(e.pointerId)) {
        e.currentTarget.releasePointerCapture(e.pointerId);
      }
    } catch {
      // Ignore release errors
    }

    // 1. Desktop mouse release
    if (e.pointerType === "mouse") {
      const heldBtn = heldPointerButtonsRef.current.get(e.pointerId);
      heldPointerButtonsRef.current.delete(e.pointerId);
      if (isCancelOrLost && !heldBtn) return;
      const btn = heldBtn || resolvePointerButton(e);
      heldMouseButtonsRef.current.delete(btn);
      if (!canControl) return;
      const pos = mapClientToRemote(e.clientX, e.clientY, { clampInside: true });
      if (!pos) return;
      sendInput({ action: "mouseup", button: btn, x: pos.x, y: pos.y });
      return;
    }

    // 2. Touch / Pen release
    lastTouchActivityTsRef.current = performance.now();
    activePointersRef.current.delete(e.pointerId);
    const stTouch = singleTouchRef.current;

    if (stTouch && stTouch.pointerId === e.pointerId) {
      if (stTouch.longPressTimer) {
        window.clearTimeout(stTouch.longPressTimer);
        stTouch.longPressTimer = null;
      }

      if (stTouch.mode === "drag") {
        const heldBtn = heldPointerButtonsRef.current.get(e.pointerId);
        heldPointerButtonsRef.current.delete(e.pointerId);
        if (heldBtn) {
          heldMouseButtonsRef.current.delete(heldBtn);
          if (canControl) {
            const pos = mapClientToRemote(e.clientX, e.clientY, { clampInside: true });
            if (pos) {
              sendInput({ action: "mouseup", button: heldBtn, x: pos.x, y: pos.y });
            }
          }
        }
      } else if (!isCancelOrLost && !gestureConsumedRef.current && stTouch.mode === "pending") {
        const elapsed = performance.now() - stTouch.startTs;
        const stagePt = getStageCoords(e.clientX, e.clientY) ?? {
          x: stTouch.lastX,
          y: stTouch.lastY,
        };
        const dist = Math.hypot(stagePt.x - stTouch.startX, stagePt.y - stTouch.startY);
        if (dist < 8 && elapsed < 450) {
          if (canControl) {
            const pos = stageToRemotePoint(stagePt.x, stagePt.y, computeLiveCameraTransform());
            if (pos) {
              sendInput({ action: "mousedown", button: "left", x: pos.x, y: pos.y });
              sendInput({ action: "mouseup", button: "left", x: pos.x, y: pos.y });
              triggerClickRipple(pos.x, pos.y, "left");
            }
          } else if (liveRole === "admin" && state.running && !state.takeover) {
            showDebouncedHint("点击底部【接管】按钮即可触控操作页面");
          }
        }
      }
      singleTouchRef.current = null;
    } else {
      // Ensure any stray held drag pointer is released on cancel/lost
      const heldBtn = heldPointerButtonsRef.current.get(e.pointerId);
      if (heldBtn) {
        heldPointerButtonsRef.current.delete(e.pointerId);
        heldMouseButtonsRef.current.delete(heldBtn);
        if (canControl) {
          const pos = mapClientToRemote(e.clientX, e.clientY, { clampInside: true });
          if (pos) {
            sendInput({ action: "mouseup", button: heldBtn, x: pos.x, y: pos.y });
          }
        }
      }
    }

    if (activePointersRef.current.size < 2) {
      pinchStateRef.current = null;
    }
    if (activePointersRef.current.size === 0) {
      gestureConsumedRef.current = false;
    }
  };

  const handleCanvasPointerUp = (e: React.PointerEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    finishCanvasPointer(e, false);
  };

  const handleCanvasPointerCancel = (e: React.PointerEvent<HTMLCanvasElement>) => {
    finishCanvasPointer(e, true);
  };

  const handleCanvasLostPointerCapture = (e: React.PointerEvent<HTMLCanvasElement>) => {
    finishCanvasPointer(e, true);
  };

  const handleCanvasDoubleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!canControl) return;
    e.preventDefault();
    const pos = mapClientToRemote(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "dblclick", x: pos.x, y: pos.y });
    triggerClickRipple(pos.x, pos.y, "left");
  };

  const handleCanvasContextMenu = (e: React.MouseEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const nativePointerType = (e.nativeEvent as PointerEvent | undefined)?.pointerType;
    if (
      nativePointerType === "touch" ||
      nativePointerType === "pen" ||
      activePointersRef.current.size > 0 ||
      (lastTouchActivityTsRef.current > 0 &&
        performance.now() - lastTouchActivityTsRef.current < 700)
    ) {
      return;
    }
    if (!canControl) return;
    const pos = mapClientToRemote(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "rightclick", x: pos.x, y: pos.y });
    triggerClickRipple(pos.x, pos.y, "right");
  };

  const handleCanvasWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    if (!canControl) return;
    e.preventDefault();
    const pos = mapClientToRemote(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({
      action: "wheel",
      dx: Math.round(e.deltaX),
      dy: Math.round(e.deltaY),
      x: pos.x,
      y: pos.y,
    });
  };

  // ---------------- Camera Controls ----------------

  const handleSelectViewMode = (mode: CameraViewMode) => {
    applyCameraState(
      {
        mode,
        customScale: 1,
        panX: 0,
        panY: 0,
      },
      true,
    );
  };

  const handleStepZoom = (factorDelta: number) => {
    const tf = computeLiveCameraTransform();
    const zoomed = zoomCameraAroundAnchor({
      currentTransform: tf,
      nextScale: tf.scale * factorDelta,
      anchorStageX: tf.stageW / 2,
      anchorStageY: tf.stageH / 2,
    });
    applyCameraState(
      {
        mode: "custom",
        customScale: zoomed.scale,
        panX: zoomed.panX,
        panY: zoomed.panY,
      },
      true,
    );
  };

  const handleCycleMobileView = () => {
    const nextMode = cycleMobileViewMode(cameraRef.current.mode);
    applyCameraState(
      {
        mode: nextMode,
        customScale: 1,
        panX: 0,
        panY: 0,
      },
      true,
    );
  };

  const handleResetZoomBadge = () => {
    applyCameraState(
      {
        mode: "fit",
        customScale: 1,
        panX: 0,
        panY: 0,
      },
      true,
    );
  };

  // ---------------- Smart Top-Anchored Soft Keyboard Actions ----------------

  const handleKbSend = (submit: boolean) => {
    if (!canControl) return;
    const text = kbText;
    if (!text && !submit) return;
    if (!text && submit) {
      sendInput({ action: "press", key: "Enter" });
      return;
    }
    const ok = sendInput({ action: "type", text, submit });
    if (ok) {
      setKbText("");
      if (submit) {
        kbInputRef.current?.blur();
        setKbSheetOpen(false);
      }
    }
  };

  const handleKbQuickKey = async (key: string) => {
    if (!canControl) return;
    if (key === "__PASTE__") {
      try {
        if (navigator.clipboard && typeof navigator.clipboard.readText === "function") {
          const clipText = await navigator.clipboard.readText();
          if (clipText) {
            sendInput({ action: "type", text: clipText, submit: false });
            showToast("📋 已粘贴文本到远端焦点框");
            return;
          }
        }
      } catch {
        // Fallback to remote Ctrl+V
      }
      sendInput({ action: "press", key: "Control+v" });
      return;
    }
    sendInput({ action: "press", key });
  };

  const closeKbSheet = () => {
    kbComposingRef.current = false;
    kbInputRef.current?.blur();
    setKbSheetOpen(false);
  };

  // ---------------- Browser Lifecycle & Takeover Actions ----------------

  const toggleTakeover = () => {
    if (liveRole !== "admin") return;
    if (state.takeover) {
      setHandbackModalOpen(true);
      return;
    }
    sendWsJson({
      type: "set_takeover",
      active: true,
      reason: "Studio 人工接管",
      session_gen: state.session_gen,
      takeover_gen: state.takeover_gen,
      req_id: `tk-${Date.now()}`,
    });
  };

  const handleConfirmHandback = async (withInstruction: boolean) => {
    if (liveRole !== "admin" || submittingHandback) return;
    releaseAllHeldInputs();
    setSubmittingHandback(true);
    try {
      const note = withInstruction ? handbackNote.trim() : "";
      await setBrowserTakeover({
        active: false,
        reason: "Studio 交还 AI",
        instruction: note || undefined,
        expected_session_gen: state.session_gen || undefined,
        expected_takeover_gen: state.takeover_gen || undefined,
      });
      setHandbackNote("");
      setHandbackModalOpen(false);
      const targetHandle = (state.owner_bot || selectedBot || "").replace(/^@/, "");
      showToast(
        targetHandle
          ? `▶️ 已交还给 @${targetHandle}${note ? "（已附带下一步指令）" : ""}`
          : "▶️ 已交还给 AI 继续执行",
      );
    } catch (err) {
      showToast(`⚠️ 交还失败: ${err instanceof Error ? err.message : "未知错误"}`);
    } finally {
      setSubmittingHandback(false);
    }
  };

  const handleSelectOwnerBot = async (nextHandle: string) => {
    if (liveRole !== "admin" || !nextHandle || switchingBot) return;
    setSwitchingBot(true);
    try {
      const resp = await setBrowserOwnerBot({ owner_bot: nextHandle });
      setSelectedBot(resp.owner_bot);
      setState((prev) => ({
        ...prev,
        owner_bot: resp.owner_bot,
        owner_bot_id: resp.owner_bot_id,
      }));
      showToast(
        resp.running
          ? `🤖 运行中已原子热改绑至 @${resp.owner_bot}（未重启浏览器）`
          : `🤖 默认操作 AI 已切换为 @${resp.owner_bot}`,
      );
    } catch (err) {
      showToast(`⚠️ 切换 AI 失败: ${err instanceof Error ? err.message : "未知错误"}`);
    } finally {
      setSwitchingBot(false);
    }
  };

  const handleManualLaunch = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (liveRole !== "admin" || launching) return;
    setLaunching(true);
    try {
      const rawUrl = launchUrl.trim();
      const normalizedUrl = rawUrl
        ? /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl)
          ? rawUrl
          : `https://${rawUrl}`
        : undefined;
      await launchBrowser({
        engine: launchEngine,
        profile: launchProfile || "default",
        url: normalizedUrl,
        owner_bot: selectedBot || undefined,
        manual_launch: true,
      });
      showToast(
        `🚀 已手动拉起 ${launchEngine}/${launchProfile || "default"}，已唤醒 @${(selectedBot || "AI").replace(/^@/, "")} 待命`,
      );
      await refreshControlMetadata();
    } catch (err) {
      showToast(`⚠️ 手动拉起失败: ${err instanceof Error ? err.message : "未知错误"}`);
    } finally {
      setLaunching(false);
    }
  };

  const handleStopBrowser = async () => {
    if (
      roleRef.current !== "admin" ||
      liveRole !== "admin" ||
      !stateRef.current.running ||
      stateRef.current.session_restricted ||
      stopping
    ) {
      setStopConfirmModalOpen(false);
      setConfirmMobileStop(false);
      return;
    }
    releaseAllHeldInputs();
    setStopping(true);
    try {
      await stopBrowser();
      setStopConfirmModalOpen(false);
      setConfirmMobileStop(false);
      setMobileMoreOpen(false);
      showToast("⏹ 浏览器已安全停止");
      await refreshControlMetadata();
    } catch (err) {
      showToast(`⚠️ 停止失败: ${err instanceof Error ? err.message : "未知错误"}`);
    } finally {
      setStopping(false);
    }
  };

  const handleSetQuality = (preset: "hd" | "balanced" | "smooth") => {
    if (liveRole !== "admin") {
      showToast("只读模式不可修改流画质");
      return;
    }
    sendWsJson({ type: "set_quality", preset });
  };

  const handleNavigate = (e: React.FormEvent) => {
    e.preventDefault();
    setEditingUrl(false);
    setMobileUrlEditing(false);
    const raw = urlInput.trim();
    if (!raw) return;
    const dest = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw) ? raw : `https://${raw}`;
    sendInput({ action: "goto", url: dest });
  };

  const toggleFullscreen = async () => {
    const el = stageWrapRef.current;
    if (!el) return;
    try {
      if (!document.fullscreenElement) {
        await el.requestFullscreen();
      } else {
        await document.exitFullscreen();
      }
    } catch {
      showToast("当前浏览器环境不支持全屏 API");
    }
  };

  const handleDialogReply = (accept: boolean) => {
    if (!pendingDialog) return;
    sendWsJson({
      type: "dialog_response",
      dialog_id: pendingDialog.dialog_id,
      accept,
      prompt_text: dialogPromptValue,
    });
    setPendingDialog(null);
  };

  // ---------------- Derived Projection & Display Metadata ----------------

  const cameraTransform = useMemo(
    () =>
      computeCameraTransform({
        mode: cameraState.mode,
        customScale: cameraState.customScale,
        panX: cameraState.panX,
        panY: cameraState.panY,
        stageW: stageSize.width || 1,
        stageH: stageSize.height || 1,
        vw: state.vw || 1280,
        vh: state.vh || 800,
      }),
    [cameraState, stageSize.height, stageSize.width, state.vh, state.vw],
  );

  const cursorX = state.cursor?.x;
  const cursorY = state.cursor?.y;
  const showCursor =
    state.running &&
    !state.session_restricted &&
    stageSize.width > 1 &&
    stageSize.height > 1 &&
    typeof cursorX === "number" &&
    typeof cursorY === "number" &&
    state.vw > 0 &&
    state.vh > 0;
  const cursorStagePt = showCursor
    ? remoteToStagePoint(cursorX, cursorY, cameraTransform)
    : null;
  const isAiCursor = state.cursor?.actor !== "human";

  const rippleStagePt = clickRipple
    ? remoteToStagePoint(clickRipple.remoteX, clickRipple.remoteY, cameraTransform)
    : null;

  const activeOwnerHandle = (state.owner_bot || selectedBot || "").replace(/^@/, "");
  const availableEngines = engines.filter((e) => e.available || e.id === "camoufox");
  const launchProfilesForEngine = profiles.filter((p) => p.engine === launchEngine);
  const extEngineLabel =
    engines.find((e) => e.id === "external_chromium")?.label || "External Chromium";
  const activeEngineDisplay =
    state.engine === "external_chromium" || state.engine_mode === "sync_external"
      ? extEngineLabel
      : "Camoufox";
  const compactUrlLabel = formatCompactUrlLabel(state.url, state.title, state.running);
  const statusModeText = !state.running
    ? "待机中"
    : state.takeover
      ? state.manual_launch
        ? "手动接管中（AI 待命）"
        : "人工接管中"
      : state.ai_busy
        ? state.ai_status || "AI 操作中"
        : "实时镜像";

  return (
    <div
      ref={stageWrapRef}
      className="flex flex-col h-full w-full bg-slate-950 overflow-hidden select-none"
    >
      {/* ==================== DESKTOP TOP TOOLBAR (>= md, non-compact, non-drawer) ==================== */}
      <div
        className={`${
          forceMobileChrome ? "hidden" : "hidden md:flex"
        } h-11 shrink-0 border-b border-slate-800/90 bg-slate-900/95 px-2.5 items-center gap-1.5 z-20`}
      >
        {/* Nav buttons */}
        <div className="flex items-center gap-0.5 shrink-0">
          <button
            type="button"
            disabled={!canControl}
            onClick={() => sendInput({ action: "back" })}
            title="后退"
            className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            disabled={!canControl}
            onClick={() => sendInput({ action: "forward" })}
            title="前进"
            className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
          >
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            disabled={!canControl}
            onClick={() => sendInput({ action: "reload" })}
            title="刷新页面"
            className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
          >
            <RotateCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Address bar */}
        <form onSubmit={handleNavigate} className="flex-1 min-w-0">
          <input
            type="text"
            value={editingUrl ? urlInput : state.url || ""}
            onFocus={() => {
              setUrlInput(state.url || "");
              setEditingUrl(true);
            }}
            onBlur={() => setEditingUrl(false)}
            onChange={(e) => setUrlInput(e.target.value)}
            disabled={!canControl}
            placeholder={state.running ? "输入网址并回车跳转…" : "浏览器待机中（未启动）"}
            className="w-full h-7 rounded-lg bg-slate-950/90 border border-slate-700/80 px-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 disabled:opacity-75 select-text"
          />
        </form>

        {/* Tabs dropdown */}
        <div className="relative shrink-0">
          <button
            type="button"
            onClick={() => setTabsOpen((v) => !v)}
            className="h-7 px-2 rounded-md border border-slate-700/80 bg-slate-800/70 hover:bg-slate-800 text-xs text-slate-200 inline-flex items-center gap-1 cursor-pointer"
            title="标签页"
          >
            <span className="font-mono text-[11px]">{state.tabs.length || 0}</span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>
          {tabsOpen && (
            <div className="absolute right-0 mt-1.5 w-72 rounded-xl border border-slate-700 bg-slate-900 shadow-2xl p-1.5 z-40">
              <div className="flex items-center justify-between px-2 py-1 border-b border-slate-800 mb-1">
                <span className="text-[11px] font-medium text-slate-400">
                  打开的标签页 ({state.tabs.length})
                </span>
                {canControl && (
                  <button
                    type="button"
                    onClick={() => {
                      sendInput({ action: "new_tab", cmd_id: `nt-${Date.now()}` });
                      setTabsOpen(false);
                    }}
                    className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                  >
                    <Plus className="w-3 h-3" /> 新建
                  </button>
                )}
              </div>
              <div className="max-h-56 overflow-y-auto space-y-0.5">
                {state.tabs.length === 0 ? (
                  <div className="px-2 py-3 text-xs text-slate-500 text-center">暂无活动标签页</div>
                ) : (
                  state.tabs.map((tab, idx) => (
                    <div
                      key={`${idx}-${tab.url}`}
                      className={`flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs ${
                        tab.active
                          ? "bg-sky-500/15 text-sky-200 border border-sky-500/30"
                          : "text-slate-300 hover:bg-slate-800"
                      }`}
                    >
                      <button
                        type="button"
                        disabled={!canControl}
                        onClick={() => {
                          sendInput({
                            action: "switch_tab",
                            index: idx,
                            cmd_id: `st-${Date.now()}`,
                          });
                          setTabsOpen(false);
                        }}
                        className="flex-1 text-left truncate cursor-pointer disabled:cursor-default"
                      >
                        {tab.title || tab.url || `Tab ${idx + 1}`}
                      </button>
                      {canControl && state.tabs.length > 1 && (
                        <button
                          type="button"
                          onClick={() => {
                            sendInput({
                              action: "close_tab",
                              index: idx,
                              cmd_id: `ct-${Date.now()}`,
                            });
                          }}
                          className="p-0.5 text-slate-400 hover:text-rose-400 cursor-pointer"
                          title="关闭标签"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Quality preset */}
        <div className="hidden md:flex items-center rounded-md border border-slate-700/80 bg-slate-950/70 p-0.5 shrink-0">
          {(
            [
              ["hd", "高清"],
              ["balanced", "均衡"],
              ["smooth", "流畅"],
            ] as const
          ).map(([preset, label]) => (
            <button
              key={preset}
              type="button"
              disabled={liveRole !== "admin"}
              onClick={() => handleSetQuality(preset)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer disabled:cursor-default ${
                state.quality_preset === preset
                  ? "bg-sky-600 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Camera Scale Controls: Fit / Fit-Height / 1:1 / Zoom */}
        <div className="hidden lg:flex items-center gap-0.5 rounded-md border border-slate-700/80 bg-slate-950/70 p-0.5 shrink-0">
          <button
            type="button"
            onClick={() => handleSelectViewMode("fit")}
            className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
              cameraState.mode === "fit"
                ? "bg-slate-700 text-slate-100"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            全图
          </button>
          <button
            type="button"
            onClick={() => handleSelectViewMode("fit_height")}
            className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
              cameraState.mode === "fit_height"
                ? "bg-slate-700 text-slate-100"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            适高
          </button>
          <button
            type="button"
            onClick={() => handleSelectViewMode("1:1")}
            className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
              cameraState.mode === "1:1"
                ? "bg-slate-700 text-slate-100"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            1:1
          </button>
          <button
            type="button"
            onClick={() => handleStepZoom(1 / 1.2)}
            className="h-5 w-5 inline-flex items-center justify-center rounded text-slate-400 hover:text-slate-100 cursor-pointer"
            title="缩小"
          >
            <ZoomOut className="w-3 h-3" />
          </button>
          <span className="text-[10px] font-mono text-slate-400 w-9 text-center">
            {cameraState.mode === "fit" ? "FIT" : `${cameraTransform.relativeZoomPct}%`}
          </span>
          <button
            type="button"
            onClick={() => handleStepZoom(1.2)}
            className="h-5 w-5 inline-flex items-center justify-center rounded text-slate-400 hover:text-slate-100 cursor-pointer"
            title="放大"
          >
            <ZoomIn className="w-3 h-3" />
          </button>
        </div>

        {/* Unrestricted Full-Roster AI Selector (permanent in desktop top toolbar) */}
        <div
          className="flex items-center gap-1 shrink-0 rounded-md border border-slate-700/80 bg-slate-950/80 px-1.5 h-7"
          title={
            liveRole === "admin"
              ? "选择操作 AI（待机设默认，运行/接管中原子热改绑，不重启浏览器）"
              : "当前绑定操作 AI（只读）"
          }
        >
          <Bot className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <select
            aria-label="绑定操作 AI"
            value={selectedBot}
            disabled={liveRole !== "admin" || switchingBot || rosterBots.length === 0}
            onChange={(e) => void handleSelectOwnerBot(e.target.value)}
            className="bg-transparent text-xs text-slate-200 focus:outline-none max-w-[145px] truncate cursor-pointer disabled:cursor-default disabled:opacity-75"
          >
            {rosterBots.length === 0 ? (
              <option value="" className="bg-slate-900">
                {activeOwnerHandle ? `@${activeOwnerHandle}` : "加载 AI…"}
              </option>
            ) : (
              rosterBots.map((b) => (
                <option key={b.handle} value={b.handle} className="bg-slate-900 text-slate-100">
                  {b.online ? "● " : "○ "}@{b.handle} ({b.display_name} · {b.role})
                </option>
              ))
            )}
          </select>
        </div>

        {/* Profile & Egress Config Drawer Trigger */}
        <button
          type="button"
          onClick={() => {
            void refreshControlMetadata();
            setConfigDrawerOpen(true);
          }}
          title="双浏览器 Profile 与 SOCKS5 出口 IP 池配置"
          className="h-7 px-2 rounded-md border border-slate-700/80 bg-slate-800/70 hover:bg-slate-800 text-xs text-slate-200 inline-flex items-center gap-1 shrink-0 cursor-pointer"
        >
          <SlidersHorizontal className="w-3.5 h-3.5 text-sky-400" />
          <span>配置</span>
        </button>

        {/* Takeover / Stop / Readonly indicator */}
        {liveRole === "admin" ? (
          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              disabled={!state.running || Boolean(state.session_restricted)}
              onClick={toggleTakeover}
              className={`h-7 px-2.5 rounded-md text-xs font-medium inline-flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer disabled:opacity-40 disabled:pointer-events-none ${
                state.takeover
                  ? "bg-emerald-600 hover:bg-emerald-500 text-white"
                  : "bg-sky-600/90 hover:bg-sky-500 text-white"
              }`}
            >
              {state.takeover ? (
                <>
                  <Bot className="w-3.5 h-3.5" />
                  <span>交还 AI</span>
                </>
              ) : (
                <>
                  <Hand className="w-3.5 h-3.5" />
                  <span>人工接管</span>
                </>
              )}
            </button>
            {state.running && !state.session_restricted && (
              <button
                type="button"
                disabled={stopping}
                onClick={() => void handleStopBrowser()}
                title="停止当前浏览器会话"
                className="h-7 w-7 rounded-md border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 inline-flex items-center justify-center cursor-pointer disabled:opacity-40"
              >
                {stopping ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Square className="w-3 h-3 fill-current" />
                )}
              </button>
            )}
          </div>
        ) : (
          <span className="h-7 px-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs font-medium inline-flex items-center gap-1 shrink-0">
            <Eye className="w-3.5 h-3.5" />
            只读观摩
          </span>
        )}

        {/* WS status + Fullscreen */}
        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={connectWs}
            title={
              wsStatus === "connected" ? "实时流已连接（点击重连）" : "连接断开（点击重连）"
            }
            className={`h-7 w-7 rounded-md inline-flex items-center justify-center cursor-pointer ${
              wsStatus === "connected"
                ? "text-emerald-400 hover:bg-slate-800"
                : "text-amber-400 hover:bg-slate-800"
            }`}
          >
            {wsStatus === "connected" ? (
              <Wifi className="w-3.5 h-3.5" />
            ) : (
              <WifiOff className="w-3.5 h-3.5" />
            )}
          </button>
          <button
            type="button"
            onClick={toggleFullscreen}
            title={isFullscreen ? "退出全屏" : "全屏工作台"}
            className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 cursor-pointer"
          >
            {isFullscreen ? (
              <Minimize2 className="w-3.5 h-3.5" />
            ) : (
              <Maximize2 className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* ==================== MOBILE / COMPACT TOP TOOLBAR (< md or compact/drawer) ==================== */}
      <div
        className={`${
          forceMobileChrome ? "flex" : "flex md:hidden"
        } min-h-11 shrink-0 border-b border-slate-800/90 bg-slate-900/95 px-2 py-1.5 items-center gap-1.5 z-20 w-full min-w-0`}
      >
        {mobileUrlEditing && canControl ? (
          <form onSubmit={handleNavigate} className="flex items-center gap-1.5 w-full min-w-0">
            <input
              ref={mobileUrlInputRef}
              type="text"
              inputMode="url"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="go"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  e.preventDefault();
                  setMobileUrlEditing(false);
                }
              }}
              placeholder="输入网址并前往…"
              className="flex-1 min-w-0 h-9 rounded-lg bg-slate-950 border border-sky-500/80 px-2.5 text-[16px] text-slate-100 placeholder:text-slate-500 focus:outline-none select-text"
            />
            <button
              type="submit"
              className="h-9 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white shrink-0 cursor-pointer"
            >
              前往
            </button>
            <button
              type="button"
              onClick={() => setMobileUrlEditing(false)}
              aria-label="取消输入网址"
              className="h-9 w-9 rounded-lg border border-slate-700 bg-slate-800/80 text-slate-300 inline-flex items-center justify-center shrink-0 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </form>
        ) : (
          <>
            {/* Compact Back & Reload */}
            <div className="flex items-center gap-0.5 shrink-0">
              <button
                type="button"
                disabled={!canControl}
                onClick={() => sendInput({ action: "back" })}
                aria-label="后退"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 active:bg-slate-700 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
              <button
                type="button"
                disabled={!canControl}
                onClick={() => sendInput({ action: "reload" })}
                aria-label="刷新页面"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 active:bg-slate-700 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
              >
                <RotateCw className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Center URL Pill (flex-1 min-w-0, never overflows) */}
            <button
              type="button"
              onClick={() => {
                if (canControl) {
                  setUrlInput(state.url || "");
                  setMobileUrlEditing(true);
                } else if (liveRole === "admin" && state.running && !state.takeover) {
                  showDebouncedHint("请先点击底部【接管】后再编辑网址");
                } else if (liveRole !== "admin") {
                  showDebouncedHint("当前为只读观摩模式");
                }
              }}
              className="flex-1 min-w-0 h-8 rounded-lg border border-slate-700/80 bg-slate-950/90 px-2.5 flex items-center gap-1.5 text-left active:bg-slate-900 cursor-pointer"
              title={state.url || compactUrlLabel}
            >
              <span
                className={`h-2 w-2 rounded-full shrink-0 ${
                  wsStatus !== "connected"
                    ? "bg-amber-400"
                    : !state.running
                      ? "bg-slate-500"
                      : state.takeover
                        ? "bg-emerald-400"
                        : state.ai_busy
                          ? "bg-sky-400 animate-pulse"
                          : "bg-sky-300"
                }`}
              />
              <span className="text-xs text-slate-200 truncate font-medium">
                {compactUrlLabel}
              </span>
            </button>

            {/* Right: Tabs Square Count + Compact AI Identity Badge */}
            <button
              type="button"
              onClick={() => {
                setMobileMoreOpen(false);
                setMobileTabsOpen(true);
              }}
              aria-label={`标签页 (${state.tabs.length})`}
              className="h-8 min-w-8 px-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 hover:bg-slate-800 text-xs font-mono font-semibold text-slate-100 inline-flex items-center justify-center shrink-0 cursor-pointer"
            >
              {state.tabs.length || 0}
            </button>

            <button
              type="button"
              onClick={() => {
                setMobileTabsOpen(false);
                setConfirmMobileStop(false);
                setMobileMoreOpen(true);
              }}
              title={activeOwnerHandle ? `当前绑定 AI: @${activeOwnerHandle}` : "切换操作 AI / 更多"}
              className="h-8 max-w-[76px] px-1.5 rounded-lg border border-slate-700/80 bg-slate-950/85 hover:bg-slate-800 text-[11px] text-sky-300 inline-flex items-center gap-1 shrink-0 cursor-pointer"
            >
              <Bot className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate font-mono">
                {activeOwnerHandle ? activeOwnerHandle.replace(/_bot$/i, "") : "AI"}
              </span>
            </button>

            {liveRole === "admin" && state.running && !state.session_restricted && (
              <button
                type="button"
                disabled={stopping}
                onClick={() => {
                  setMobileTabsOpen(false);
                  setMobileMoreOpen(false);
                  setStopConfirmModalOpen(true);
                }}
                aria-label="关闭浏览器"
                title="关闭当前浏览器会话"
                data-testid="mobile-topbar-stop-btn"
                className="h-8 px-2 rounded-lg border border-rose-500/70 bg-rose-600/90 hover:bg-rose-500 active:bg-rose-700 text-white text-[11px] font-semibold inline-flex items-center gap-1 shrink-0 cursor-pointer disabled:opacity-45 disabled:pointer-events-none"
              >
                {stopping ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
                ) : (
                  <Square className="w-3 h-3 fill-current shrink-0" />
                )}
                <span>关闭</span>
              </button>
            )}

            {isDrawer && onExpandFull && (
              <button
                type="button"
                onClick={onExpandFull}
                title="展开全屏浏览器视图"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 shrink-0 cursor-pointer"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
            )}
            {isDrawer && onCloseDrawer && (
              <button
                type="button"
                onClick={onCloseDrawer}
                title="收起浏览器抽屉"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 shrink-0 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </>
        )}
      </div>

      {/* ==================== MAIN ZERO-DISTORTION VIRTUAL CAMERA STAGE ==================== */}
      <div
        ref={viewportRef}
        className="relative flex-1 min-h-0 w-full bg-[#070a10] overflow-hidden"
      >
        <canvas
          ref={canvasRef}
          onPointerDown={handleCanvasPointerDown}
          onPointerMove={handleCanvasPointerMove}
          onPointerUp={handleCanvasPointerUp}
          onPointerCancel={handleCanvasPointerCancel}
          onLostPointerCapture={handleCanvasLostPointerCapture}
          onDoubleClick={handleCanvasDoubleClick}
          onContextMenu={handleCanvasContextMenu}
          onWheel={handleCanvasWheel}
          className={`block w-full h-full touch-none ${
            canControl ? "cursor-crosshair" : "cursor-default"
          }`}
        />

        {/* AI / Human Cursor Overlay (projected through identical virtual camera matrix) */}
        {showCursor && cursorStagePt && (
          <div
            className="pointer-events-none absolute z-20 transition-[left,top] duration-75"
            style={{
              left: `${cursorStagePt.x.toFixed(1)}px`,
              top: `${cursorStagePt.y.toFixed(1)}px`,
            }}
          >
            <svg width="18" height="22" viewBox="0 0 18 22" fill="none">
              <path
                d="M1 1L1 17L5.5 13L9.5 20L12 18.7L8 11.7L14 11.5L1 1Z"
                fill={isAiCursor ? "#38bdf8" : "#ffffff"}
                stroke="#020617"
                strokeWidth="1.5"
              />
            </svg>
            {isAiCursor && (
              <span className="ml-3 -mt-2 inline-block px-1.5 py-0.5 rounded bg-sky-500/90 text-[10px] font-semibold text-slate-950 shadow">
                AI
              </span>
            )}
          </div>
        )}

        {/* Click Feedback Ring (projected through identical virtual camera matrix) */}
        {clickRipple && rippleStagePt && (
          <div
            key={clickRipple.id}
            className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-1/2"
            style={{
              left: `${rippleStagePt.x.toFixed(1)}px`,
              top: `${rippleStagePt.y.toFixed(1)}px`,
            }}
          >
            <span
              className={`block h-7 w-7 rounded-full border-2 animate-ping opacity-80 ${
                clickRipple.kind === "right"
                  ? "border-amber-400 bg-amber-400/20"
                  : "border-sky-400 bg-sky-400/20"
              }`}
            />
          </div>
        )}

        {/* Lightweight Zoom Reset Badge when zoomed in (> 104% of base fit) */}
        {state.running && !state.session_restricted && cameraTransform.isZoomed && (
          <button
            type="button"
            onClick={handleResetZoomBadge}
            className="absolute top-2 right-2 z-20 inline-flex items-center gap-1 rounded-full border border-slate-700/70 bg-slate-900/75 backdrop-blur-sm px-2.5 py-1 text-[11px] font-mono text-slate-200 hover:bg-slate-800/90 active:scale-95 shadow-lg cursor-pointer"
            title="点击复位全图视野"
          >
            <RotateCcw className="w-3 h-3 text-sky-400" />
            <span>{cameraTransform.relativeZoomPct}% · 复位</span>
          </button>
        )}

        {/* Idle / Restricted / Connecting Overlay */}
        {state.session_restricted ? (
          <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-sm flex flex-col items-center justify-center gap-3 p-6 text-center z-30">
            <Lock className="w-8 h-8 text-amber-400" />
            <div className="text-sm font-semibold text-slate-100">当前浏览器会话已被隔离</div>
            <p className="text-xs text-slate-400 max-w-sm">
              {state.restricted_reason ||
                "当前浏览器由其他授权会话占用，画面与状态已自动脱敏隔离。"}
            </p>
          </div>
        ) : !state.running ? (
          <div className="absolute inset-0 bg-slate-950/92 backdrop-blur-sm flex flex-col items-center justify-start sm:justify-center gap-3.5 px-4 pb-4 pt-12 sm:px-5 sm:pb-5 sm:pt-6 text-center z-30 overflow-y-auto">
            <div className="h-10 w-10 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center text-sky-400 shrink-0 mt-2 sm:mt-0">
              <RefreshCw className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-100">
                Live-Browser 当前处于待机状态
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-md">
                {liveRole === "admin"
                  ? "无需先唤醒 AI，可直接选择引擎、Profile 与操作 AI 手动拉起浏览器；拉起后即进入人工接管态并首帧唤醒所选 AI 待命。"
                  : "当前为只读观摩角色，等待管理员或 AI 启动浏览器会话。"}
              </p>
            </div>
            {liveRole === "admin" && (
              <form
                onSubmit={(e) => void handleManualLaunch(e)}
                className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-3.5 text-left space-y-3 shadow-xl select-text"
              >
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">浏览器引擎</label>
                    <select
                      value={launchEngine}
                      onChange={(e) => setLaunchEngine(e.target.value as BrowserEngineId)}
                      className="w-full h-10 sm:h-8 rounded-lg bg-slate-950 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                    >
                      {availableEngines.map((eng) => (
                        <option key={eng.id} value={eng.id}>
                          {eng.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">指纹 Profile</label>
                    <select
                      value={launchProfile}
                      onChange={(e) => setLaunchProfile(e.target.value)}
                      className="w-full h-10 sm:h-8 rounded-lg bg-slate-950 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                    >
                      {launchProfilesForEngine.length === 0 ? (
                        <option value="default">default</option>
                      ) : (
                        launchProfilesForEngine.map((p) => (
                          <option key={p.name} value={p.name}>
                            {p.pinned ? "🔒 " : p.allow_google ? "⭐ " : ""}
                            {p.name} ({p.egress || "direct"})
                          </option>
                        ))
                      )}
                    </select>
                  </div>
                </div>

                {/* Mobile inline AI selector on idle screen */}
                <div className={forceMobileChrome ? "block" : "block md:hidden"}>
                  <label className="block text-[11px] text-slate-400 mb-1">待命操作 AI</label>
                  <select
                    aria-label="待命操作 AI"
                    value={selectedBot}
                    disabled={switchingBot || rosterBots.length === 0}
                    onChange={(e) => void handleSelectOwnerBot(e.target.value)}
                    className="w-full h-10 sm:h-8 rounded-lg bg-slate-950 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                  >
                    {rosterBots.length === 0 ? (
                      <option value="">
                        {activeOwnerHandle ? `@${activeOwnerHandle}` : "加载 AI…"}
                      </option>
                    ) : (
                      rosterBots.map((b) => (
                        <option key={b.handle} value={b.handle}>
                          {b.online ? "● " : "○ "}@{b.handle} ({b.display_name} · {b.role})
                        </option>
                      ))
                    )}
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">起始网址（可选）</label>
                  <input
                    type="text"
                    inputMode="url"
                    value={launchUrl}
                    onChange={(e) => setLaunchUrl(e.target.value)}
                    placeholder="https://example.com（留空打开默认页）"
                    className="w-full h-10 sm:h-8 rounded-lg bg-slate-950 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 placeholder:text-slate-500"
                  />
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <span className="text-[11px] text-slate-400">
                    待命 AI:{" "}
                    <span className="font-mono text-sky-300">
                      @{activeOwnerHandle || "默认"}
                    </span>
                  </span>
                  <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto justify-end">
                    <button
                      type="button"
                      onClick={() => {
                        void refreshControlMetadata();
                        setConfigDrawerOpen(true);
                      }}
                      className="h-9 sm:h-8 px-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs text-slate-300 cursor-pointer flex-1 sm:flex-initial"
                    >
                      管理 Profile / 出口池
                    </button>
                    <button
                      type="submit"
                      disabled={launching}
                      className="h-9 sm:h-8 px-3.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium inline-flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer flex-1 sm:flex-initial"
                    >
                      {launching ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Rocket className="w-3.5 h-3.5" />
                      )}
                      手动拉起浏览器
                    </button>
                  </div>
                </div>
              </form>
            )}
          </div>
        ) : !hasFrame ? (
          <div className="absolute inset-0 bg-slate-950/75 flex items-center justify-center text-xs text-slate-400 z-20">
            等待首帧画面传输… ({state.vw}×{state.vh})
          </div>
        ) : null}

        {/* Desktop-Only Floating Status Pill (hidden on mobile; clickable to collapse/expand) */}
        {state.running && !state.session_restricted && !forceMobileChrome && (
          <button
            type="button"
            onClick={() => setDesktopPillCollapsed((v) => !v)}
            title={desktopPillCollapsed ? "点击展开状态信息" : "点击收起状态胶囊"}
            className="hidden md:flex absolute bottom-3 left-3 z-20 flex-wrap items-center gap-1.5 rounded-full border border-slate-800/90 bg-slate-900/90 hover:bg-slate-900 backdrop-blur px-2.5 py-1 text-[11px] text-slate-300 cursor-pointer shadow-lg"
          >
            <span
              className={`h-2 w-2 rounded-full ${
                state.takeover
                  ? "bg-emerald-400"
                  : state.ai_busy
                    ? "bg-sky-400 animate-pulse"
                    : "bg-slate-400"
              }`}
            />
            {desktopPillCollapsed ? (
              <span className="font-mono text-[10px] text-slate-400">
                {state.takeover ? "接管" : "镜像"} · {state.vw}×{state.vh}
              </span>
            ) : (
              <>
                <span>{statusModeText}</span>
                <span className="text-sky-300 font-mono">· {activeEngineDisplay}</span>
                {activeOwnerHandle && (
                  <span className="text-emerald-300 font-mono">· @{activeOwnerHandle}</span>
                )}
                {state.profile && (
                  <span className="text-slate-400 font-mono">· {state.profile}</span>
                )}
                {state.egress && (
                  <span className="text-slate-500 font-mono">· {state.egress}</span>
                )}
                <span className="text-slate-500 font-mono">
                  · {state.vw}×{state.vh}
                </span>
              </>
            )}
          </button>
        )}

        {/* Floating Toast */}
        {toast && (
          <div className="pointer-events-none absolute top-2.5 left-1/2 -translate-x-1/2 z-40 max-w-[92%] rounded-2xl border border-slate-700 bg-slate-900/95 px-3.5 py-1.5 text-xs text-slate-100 text-center leading-snug break-words line-clamp-2 shadow-xl">
            {toast}
          </div>
        )}
      </div>

      {/* ==================== MOBILE BOTTOM ACTION BAR (In-Flow, Zero Canvas Occlusion!) ==================== */}
      <div
        aria-label="移动端浏览器操作栏"
        className={`${
          forceMobileChrome ? "grid" : "grid md:hidden"
        } grid-cols-5 gap-1 shrink-0 border-t border-slate-800/90 bg-slate-900/98 px-1.5 py-1 z-20`}
      >
        {/* 1. Takeover / Handback / Readonly */}
        {liveRole === "admin" ? (
          <button
            type="button"
            disabled={!state.running || Boolean(state.session_restricted)}
            onClick={toggleTakeover}
            className={`min-h-[44px] rounded-xl px-1 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium transition-colors cursor-pointer disabled:opacity-35 disabled:pointer-events-none ${
              state.takeover
                ? "bg-emerald-600/90 active:bg-emerald-500 text-white"
                : "bg-sky-600/85 active:bg-sky-500 text-white"
            }`}
          >
            {state.takeover ? (
              <>
                <Bot className="w-4 h-4 shrink-0" />
                <span className="truncate">交还 AI</span>
              </>
            ) : (
              <>
                <Hand className="w-4 h-4 shrink-0" />
                <span className="truncate">接管</span>
              </>
            )}
          </button>
        ) : (
          <div className="min-h-[44px] rounded-xl px-1 border border-amber-500/30 bg-amber-500/10 text-amber-300 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium">
            <Eye className="w-4 h-4 shrink-0" />
            <span className="truncate">只读观摩</span>
          </div>
        )}

        {/* 2. View Mode Cycle: Fit-Height -> Fit -> 1:1 */}
        <button
          type="button"
          disabled={!state.running || Boolean(state.session_restricted)}
          onClick={handleCycleMobileView}
          className="min-h-[44px] rounded-xl px-1 bg-slate-800/80 active:bg-slate-700 text-slate-200 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium cursor-pointer disabled:opacity-35 disabled:pointer-events-none"
        >
          <Scan className="w-4 h-4 text-sky-400 shrink-0" />
          <span className="truncate">
            {viewModeShortLabel(cameraState.mode, cameraTransform.relativeZoomPct)}
          </span>
        </button>

        {/* 3. Touch Mode Toggle: Tap+Scroll vs Drag */}
        <button
          type="button"
          disabled={!canControl}
          onClick={() => {
            releaseAllHeldInputs();
            const next: TouchInteractMode = touchMode === "tap_scroll" ? "drag" : "tap_scroll";
            touchModeRef.current = next;
            setTouchMode(next);
            showToast(
              next === "drag"
                ? "已切换【拖拽模式】：单指按住可直接拖动滑块/框选"
                : "已切换【点滑模式】：轻点点击、长按右键、滑动滚动/平移",
            );
          }}
          className={`min-h-[44px] rounded-xl px-1 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium transition-colors cursor-pointer disabled:opacity-35 disabled:pointer-events-none ${
            touchMode === "drag" && canControl
              ? "bg-amber-500/20 border border-amber-500/50 text-amber-200"
              : "bg-slate-800/80 active:bg-slate-700 text-slate-200"
          }`}
        >
          {touchMode === "drag" ? (
            <>
              <Move className="w-4 h-4 text-amber-300 shrink-0" />
              <span className="truncate">拖拽</span>
            </>
          ) : (
            <>
              <MousePointerClick className="w-4 h-4 text-sky-400 shrink-0" />
              <span className="truncate">点滑</span>
            </>
          )}
        </button>

        {/* 4. Top-Anchored Smart Keyboard Trigger */}
        <button
          type="button"
          disabled={!canControl}
          onClick={() => setKbSheetOpen((v) => !v)}
          className={`min-h-[44px] rounded-xl px-1 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium transition-colors cursor-pointer disabled:opacity-35 disabled:pointer-events-none ${
            kbSheetOpen && canControl
              ? "bg-sky-500/25 border border-sky-500/50 text-sky-200"
              : "bg-slate-800/80 active:bg-slate-700 text-slate-200"
          }`}
        >
          <Keyboard className="w-4 h-4 shrink-0" />
          <span className="truncate">键盘</span>
        </button>

        {/* 5. More Bottom Sheet Trigger */}
        <button
          type="button"
          onClick={() => {
            setMobileTabsOpen(false);
            setConfirmMobileStop(false);
            setMobileMoreOpen(true);
          }}
          className="min-h-[44px] rounded-xl px-1 bg-slate-800/80 active:bg-slate-700 text-slate-200 flex flex-col items-center justify-center gap-0.5 text-[10px] font-medium cursor-pointer"
        >
          <MoreHorizontal className="w-4 h-4 shrink-0" />
          <span className="truncate">更多</span>
        </button>
      </div>

      {/* ==================== TOP-ANCHORED SMART SOFT KEYBOARD OVERLAY (visualViewport-aware) ==================== */}
      {kbSheetOpen && canControl && (
        <div
          role="dialog"
          aria-label="智能软键盘输入浮层"
          style={{
            top: `${kbViewportBox.top}px`,
            maxHeight: `${kbViewportBox.maxHeight}px`,
          }}
          className="fixed left-2 right-2 z-50 mx-auto max-w-xl rounded-2xl border border-sky-500/45 bg-slate-900/98 backdrop-blur-md p-3 shadow-2xl space-y-2.5 overflow-y-auto select-text"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-300">
              <Keyboard className="w-4 h-4" />
              <span>智能键盘输入（向当前网页焦点发送）</span>
            </div>
            <button
              type="button"
              onClick={closeKbSheet}
              aria-label="关闭软键盘输入"
              className="h-7 w-7 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex items-center gap-1.5">
            <input
              ref={kbInputRef}
              type="text"
              enterKeyHint="send"
              autoComplete="off"
              value={kbText}
              onChange={(e) => setKbText(e.target.value)}
              onCompositionStart={() => {
                kbComposingRef.current = true;
              }}
              onCompositionEnd={() => {
                kbComposingRef.current = false;
              }}
              onKeyDown={(e) => {
                e.stopPropagation();
                if (
                  e.key === "Enter" &&
                  !e.nativeEvent.isComposing &&
                  !kbComposingRef.current &&
                  e.keyCode !== 229
                ) {
                  e.preventDefault();
                  handleKbSend(true);
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  closeKbSheet();
                }
              }}
              placeholder="输入中文 / 英文 / 验证码…"
              className="flex-1 min-w-0 h-10 rounded-xl border border-slate-700 bg-slate-950 px-3 text-[16px] text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
            {kbText && (
              <button
                type="button"
                onClick={() => setKbText("")}
                className="h-10 px-2.5 rounded-xl border border-slate-700 bg-slate-800 text-xs text-slate-300 shrink-0 cursor-pointer"
              >
                清空
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleKbSend(false)}
              className="flex-1 h-9 rounded-xl border border-sky-500/40 bg-sky-500/15 hover:bg-sky-500/25 text-xs font-medium text-sky-200 cursor-pointer"
            >
              发送
            </button>
            <button
              type="button"
              onClick={() => handleKbSend(true)}
              className="flex-1 h-9 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white cursor-pointer"
            >
              发送 + 回车
            </button>
          </div>

          {/* Quick Keys Bar */}
          <div className="flex flex-wrap gap-1.5 pt-1 border-t border-slate-800">
            {(
              [
                ["Enter", "↵ 回车"],
                ["Backspace", "⌫ 退格"],
                ["Tab", "Tab"],
                ["Escape", "Esc"],
                ["ArrowUp", "↑"],
                ["ArrowDown", "↓"],
                ["ArrowLeft", "←"],
                ["ArrowRight", "→"],
                ["Control+a", "全选"],
                ["Control+c", "复制"],
                ["__PASTE__", "粘贴"],
              ] as const
            ).map(([keyCode, label]) => (
              <button
                key={keyCode}
                type="button"
                onClick={() => void handleKbQuickKey(keyCode)}
                className="h-8 px-2.5 rounded-lg border border-slate-700/80 bg-slate-800/80 active:bg-slate-700 text-xs text-slate-200 cursor-pointer"
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ==================== MOBILE TABS BOTTOM SHEET ==================== */}
      {mobileTabsOpen && (
        <div
          className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60 backdrop-blur-xs"
          onClick={() => setMobileTabsOpen(false)}
        >
          <div
            className="rounded-t-2xl border-t border-slate-700/80 bg-slate-900 px-4 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] space-y-3 shadow-2xl max-h-[75dvh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-2 shrink-0">
              <span className="text-sm font-semibold text-slate-100">
                标签页 ({state.tabs.length})
              </span>
              <div className="flex items-center gap-2">
                {canControl && (
                  <button
                    type="button"
                    onClick={() => {
                      sendInput({ action: "new_tab", cmd_id: `nt-${Date.now()}` });
                      setMobileTabsOpen(false);
                    }}
                    className="h-8 px-3 rounded-lg bg-sky-600 text-xs font-medium text-white inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" /> 新建标签
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setMobileTabsOpen(false)}
                  aria-label="关闭标签页列表"
                  className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-1.5">
              {state.tabs.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500">暂无活动标签页</div>
              ) : (
                state.tabs.map((tab, idx) => (
                  <div
                    key={`${idx}-${tab.url}`}
                    className={`flex items-center gap-2 rounded-xl px-3 py-2.5 text-xs ${
                      tab.active
                        ? "bg-sky-500/15 text-sky-200 border border-sky-500/35"
                        : "bg-slate-950/70 text-slate-200 border border-slate-800"
                    }`}
                  >
                    <button
                      type="button"
                      disabled={!canControl}
                      onClick={() => {
                        sendInput({
                          action: "switch_tab",
                          index: idx,
                          cmd_id: `st-${Date.now()}`,
                        });
                        setMobileTabsOpen(false);
                      }}
                      className="flex-1 min-w-0 text-left cursor-pointer disabled:cursor-default"
                    >
                      <div className="font-medium truncate">
                        {tab.title || tab.url || `Tab ${idx + 1}`}
                      </div>
                      {tab.url && (
                        <div className="text-[11px] text-slate-400 truncate mt-0.5 font-mono">
                          {tab.url}
                        </div>
                      )}
                    </button>
                    {canControl && state.tabs.length > 1 && (
                      <button
                        type="button"
                        onClick={() => {
                          sendInput({
                            action: "close_tab",
                            index: idx,
                            cmd_id: `ct-${Date.now()}`,
                          });
                        }}
                        aria-label="关闭此标签"
                        className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:text-rose-400 hover:bg-slate-800 shrink-0 cursor-pointer"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== MOBILE MORE BOTTOM SHEET (Zero Canvas Occlusion Status & Tools) ==================== */}
      {mobileMoreOpen && (
        <div
          className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60 backdrop-blur-xs"
          onClick={() => setMobileMoreOpen(false)}
        >
          <div
            className="rounded-t-2xl border-t border-slate-700/80 bg-slate-900 px-4 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] space-y-3.5 shadow-2xl max-h-[82dvh] overflow-y-auto select-text"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold text-slate-100">浏览器控制与状态</span>
              <button
                type="button"
                onClick={() => setMobileMoreOpen(false)}
                aria-label="关闭更多面板"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Compact Status Summary Strip (Replaces Canvas-Occluding Pill) */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3 space-y-1.5 text-xs">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                      !state.running
                        ? "bg-slate-500"
                        : state.takeover
                          ? "bg-emerald-400"
                          : state.ai_busy
                            ? "bg-sky-400 animate-pulse"
                            : "bg-sky-300"
                    }`}
                  />
                  <span className="font-medium text-slate-100 truncate">{statusModeText}</span>
                </div>
                <span
                  className={`text-[11px] font-mono shrink-0 ${
                    wsStatus === "connected" ? "text-emerald-400" : "text-amber-400"
                  }`}
                >
                  {wsStatus === "connected" ? "WS 已连" : "WS 断开"}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] font-mono text-slate-400">
                <span className="text-sky-300">{activeEngineDisplay}</span>
                {state.profile && <span>· {state.profile}</span>}
                {state.egress && <span>· {state.egress}</span>}
                <span>
                  · {state.vw}×{state.vh}
                </span>
              </div>
            </div>

            {/* Full-Roster AI Selector (16px on mobile to prevent iOS Safari zoom) */}
            <div className="space-y-1.5">
              <label className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
                <Bot className="w-3.5 h-3.5 text-sky-400" />
                <span>操作 AI 绑定（待机设默认 · 运行中原子热改绑）</span>
              </label>
              <select
                aria-label="移动端绑定操作 AI"
                value={selectedBot}
                disabled={liveRole !== "admin" || switchingBot || rosterBots.length === 0}
                onChange={(e) => void handleSelectOwnerBot(e.target.value)}
                className="w-full h-10 sm:h-8 rounded-xl border border-slate-700 bg-slate-950 px-3 text-[16px] sm:text-xs text-slate-100 focus:outline-none focus:border-sky-500 disabled:opacity-60"
              >
                {rosterBots.length === 0 ? (
                  <option value="">
                    {activeOwnerHandle ? `@${activeOwnerHandle}` : "加载 AI…"}
                  </option>
                ) : (
                  rosterBots.map((b) => (
                    <option key={b.handle} value={b.handle}>
                      {b.online ? "● " : "○ "}@{b.handle} ({b.display_name} · {b.role})
                    </option>
                  ))
                )}
              </select>
            </div>

            {/* Quality Preset Switcher */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-medium text-slate-400">实时流画质</div>
              <div className="grid grid-cols-3 gap-1.5">
                {(
                  [
                    ["hd", "高清"],
                    ["balanced", "均衡"],
                    ["smooth", "流畅"],
                  ] as const
                ).map(([preset, label]) => (
                  <button
                    key={preset}
                    type="button"
                    disabled={liveRole !== "admin"}
                    onClick={() => handleSetQuality(preset)}
                    className={`h-9 rounded-xl text-xs font-medium border cursor-pointer disabled:opacity-50 ${
                      state.quality_preset === preset
                        ? "border-sky-500 bg-sky-600 text-white"
                        : "border-slate-700 bg-slate-950/70 text-slate-300"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* 4-Column Quick Tool Grid */}
            <div className="grid grid-cols-4 gap-2">
              <button
                type="button"
                disabled={!canControl}
                onClick={() => {
                  sendInput({ action: "back" });
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 disabled:opacity-35 cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>后退</span>
              </button>
              <button
                type="button"
                disabled={!canControl}
                onClick={() => {
                  sendInput({ action: "forward" });
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 disabled:opacity-35 cursor-pointer"
              >
                <ArrowRight className="w-4 h-4" />
                <span>前进</span>
              </button>
              <button
                type="button"
                disabled={!canControl}
                onClick={() => {
                  sendInput({ action: "reload" });
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 disabled:opacity-35 cursor-pointer"
              >
                <RotateCw className="w-4 h-4" />
                <span>刷新</span>
              </button>
              <button
                type="button"
                disabled={!canControl}
                onClick={() => {
                  sendInput({ action: "new_tab", cmd_id: `nt-${Date.now()}` });
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 disabled:opacity-35 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>新标签</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setMobileMoreOpen(false);
                  void refreshControlMetadata();
                  setConfigDrawerOpen(true);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-sky-300 cursor-pointer"
              >
                <SlidersHorizontal className="w-4 h-4" />
                <span>配置</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  connectWs();
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 cursor-pointer"
              >
                {wsStatus === "connected" ? (
                  <Wifi className="w-4 h-4 text-emerald-400" />
                ) : (
                  <WifiOff className="w-4 h-4 text-amber-400" />
                )}
                <span>重连流</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setMobileMoreOpen(false);
                  void toggleFullscreen();
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 cursor-pointer"
              >
                {isFullscreen ? (
                  <Minimize2 className="w-4 h-4" />
                ) : (
                  <Maximize2 className="w-4 h-4" />
                )}
                <span>{isFullscreen ? "退全屏" : "全屏"}</span>
              </button>
              <button
                type="button"
                disabled={!state.running || Boolean(state.session_restricted)}
                onClick={() => {
                  handleResetZoomBadge();
                  setMobileMoreOpen(false);
                }}
                className="h-14 rounded-xl border border-slate-800 bg-slate-950/70 active:bg-slate-800 flex flex-col items-center justify-center gap-1 text-[11px] text-slate-200 disabled:opacity-35 cursor-pointer"
              >
                <RotateCcw className="w-4 h-4" />
                <span>复位全图</span>
              </button>
            </div>

            {/* Danger Zone: Stop Browser (2-step confirmation) */}
            {liveRole === "admin" && state.running && !state.session_restricted && (
              <div className="pt-2 border-t border-slate-800">
                {confirmMobileStop ? (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setConfirmMobileStop(false)}
                      className="flex-1 h-10 rounded-xl border border-slate-700 text-xs text-slate-300 cursor-pointer"
                    >
                      取消
                    </button>
                    <button
                      type="button"
                      disabled={stopping}
                      onClick={() => void handleStopBrowser()}
                      className="flex-1 h-10 rounded-xl bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      {stopping ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Square className="w-3.5 h-3.5 fill-current" />
                      )}
                      确认停止浏览器
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmMobileStop(true)}
                    className="w-full h-10 rounded-xl border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 text-xs font-medium text-rose-300 inline-flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    停止当前浏览器会话
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================== PORTRAIT TOP-BAR STOP CONFIRM MODAL ==================== */}
      {stopConfirmModalOpen && liveRole === "admin" && state.running && !state.session_restricted && (
        <div
          className="fixed inset-0 bg-black/65 backdrop-blur-xs z-50 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-label="确认关闭浏览器"
          data-testid="mobile-stop-confirm-modal"
          onClick={() => {
            if (!stopping) setStopConfirmModalOpen(false);
          }}
        >
          <div
            className="w-full max-w-sm rounded-2xl border border-rose-500/40 bg-slate-900 p-4 shadow-2xl space-y-3"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-rose-300 min-w-0">
                <Square className="w-3.5 h-3.5 fill-current shrink-0" />
                <span className="truncate">关闭当前浏览器会话</span>
              </div>
              <button
                type="button"
                disabled={stopping}
                onClick={() => setStopConfirmModalOpen(false)}
                aria-label="取消关闭弹窗"
                className="text-slate-400 hover:text-slate-200 cursor-pointer shrink-0 disabled:opacity-40"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-slate-300 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400 shrink-0">引擎</span>
                <span className="font-mono text-slate-100 truncate">{activeEngineLabel}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400 shrink-0">Profile</span>
                <span className="font-mono text-slate-100 truncate">{state.profile || "default"}</span>
              </div>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              关闭后将断开当前实时画面并回收浏览器进程，确认继续吗？
            </p>
            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                type="button"
                disabled={stopping}
                onClick={() => setStopConfirmModalOpen(false)}
                className="h-9 px-3.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer disabled:opacity-40"
              >
                取消
              </button>
              <button
                type="button"
                disabled={stopping}
                onClick={() => void handleStopBrowser()}
                data-testid="mobile-stop-confirm-submit"
                className="h-9 px-4 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {stopping ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Square className="w-3 h-3 fill-current" />
                )}
                <span>确认关闭</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================== HANDBACK TO AI MODAL (Portrait Keyboard-Safe) ==================== */}
      {handbackModalOpen && liveRole === "admin" && state.running && state.takeover && (
        <div className="fixed inset-0 bg-black/65 backdrop-blur-xs z-50 flex items-start sm:items-center justify-center p-3 sm:p-4 pt-6 sm:pt-4 overflow-y-auto">
          <div className="w-full max-w-md max-h-[85dvh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-4 shadow-2xl space-y-3 select-text">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 min-w-0">
                <Bot className="w-4 h-4 shrink-0" />
                <span className="truncate">
                  交还控制权给 AI：@{activeOwnerHandle || "当前绑定 AI"}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setHandbackModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              可填写下一步工作指令（留空可直接一键交还）。如需改由其他 AI 接手，请先切换操作 AI。
            </p>
            <textarea
              rows={3}
              maxLength={2000}
              value={handbackNote}
              onChange={(e) => setHandbackNote(e.target.value)}
              placeholder="例如：我已完成登录验证，请继续抓取当前页面订单并导出摘要（选填）"
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-[16px] sm:text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setHandbackModalOpen(false)}
                className="h-9 sm:h-8 px-3 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={submittingHandback}
                onClick={() => void handleConfirmHandback(false)}
                className="h-9 sm:h-8 px-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-xs text-emerald-300 cursor-pointer disabled:opacity-50"
              >
                直接交还
              </button>
              <button
                type="button"
                disabled={submittingHandback}
                onClick={() => void handleConfirmHandback(true)}
                className="h-9 sm:h-8 px-3.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-medium text-white inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {submittingHandback && <Loader2 className="w-3 h-3 animate-spin" />}
                {handbackNote.trim() ? "附带指令交还给 AI" : "确认交还给 AI"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================== DUAL-ENGINE PROFILE & EGRESS POOL CONFIG DRAWER ==================== */}
      <BrowserConfigDrawer
        open={configDrawerOpen}
        onClose={() => setConfigDrawerOpen(false)}
        canEdit={liveRole === "admin"}
        engines={engines}
        profiles={profiles}
        egressNodes={egressNodes}
        egressVaultReady={egressVaultReady}
        egressVaultError={egressVaultError}
        drawSupported={drawSupported}
        pruneSupported={pruneSupported}
        onRefreshAll={refreshControlMetadata}
        onNotify={showToast}
      />

      {/* ==================== JS DIALOG MODAL (Portrait Keyboard-Safe) ==================== */}
      {pendingDialog && liveRole === "admin" && (
        <div className="fixed inset-0 bg-black/65 backdrop-blur-xs z-50 flex items-start sm:items-center justify-center p-3 sm:p-4 pt-6 sm:pt-4 overflow-y-auto">
          <div className="w-full max-w-sm max-h-[85dvh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-4 shadow-2xl space-y-3">
            <div className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              网页弹窗 ({pendingDialog.dialog_type})
            </div>
            <p className="text-sm text-slate-200 whitespace-pre-wrap break-words">
              {pendingDialog.message}
            </p>
            {pendingDialog.dialog_type === "prompt" && (
              <input
                type="text"
                value={dialogPromptValue}
                onChange={(e) => setDialogPromptValue(e.target.value)}
                className="w-full h-10 sm:h-9 rounded-lg border border-slate-700 bg-slate-950 px-3 text-[16px] sm:text-sm text-slate-100 select-text"
              />
            )}
            <div className="flex justify-end gap-2 pt-1">
              {pendingDialog.dialog_type !== "alert" && (
                <button
                  type="button"
                  onClick={() => handleDialogReply(false)}
                  className="h-9 sm:h-8 px-3 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
                >
                  取消
                </button>
              )}
              <button
                type="button"
                onClick={() => handleDialogReply(true)}
                className="h-9 sm:h-8 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white cursor-pointer"
              >
                确定
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
