import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  ChevronDown,
  Eye,
  Hand,
  Bot,
  Loader2,
  Maximize2,
  Minimize2,
  Plus,
  RefreshCw,
  Rocket,
  RotateCw,
  SlidersHorizontal,
  Square,
  X,
  ZoomIn,
  ZoomOut,
  Lock,
  Wifi,
  WifiOff,
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

type ScaleMode = "fit" | "1:1" | "zoom";

interface PendingDialog {
  dialog_id: string;
  dialog_type: string;
  message: string;
  default_value?: string;
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

function clamp01(v: number): number {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

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
  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");
  const [state, setState] = useState<LiveBrowserState>(DEFAULT_STATE);
  const [liveRole, setLiveRole] = useState<"admin" | "readonly">(session.role);
  const [urlInput, setUrlInput] = useState("");
  const [editingUrl, setEditingUrl] = useState(false);
  const [tabsOpen, setTabsOpen] = useState(false);
  const [scaleMode, setScaleMode] = useState<ScaleMode>("fit");
  const [zoomPct, setZoomPct] = useState(100);
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
  const wsRef = useRef<WebSocket | null>(null);
  const connGenRef = useRef<number>(0);
  const stateRef = useRef<LiveBrowserState>(DEFAULT_STATE);
  const roleRef = useRef<"admin" | "readonly">(session.role);
  const latestBitmapRef = useRef<ImageBitmap | null>(null);
  const heldModifiersRef = useRef<Set<string>>(new Set());
  const heldMouseButtonsRef = useRef<Set<string>>(new Set());
  const heldPointerButtonsRef = useRef<Map<number, string>>(new Map());
  const lastMoveTsRef = useRef<number>(0);
  const toastTimerRef = useRef<number | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const unmountedRef = useRef(false);

  useEffect(() => {
    stateRef.current = state;
    if (!editingUrl && state.url) {
      setUrlInput(state.url);
    }
  }, [state, editingUrl]);

  useEffect(() => {
    roleRef.current = liveRole;
  }, [liveRole]);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
    toastTimerRef.current = window.setTimeout(() => setToast(null), 3200);
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

  const releaseAllHeldInputs = useCallback(() => {
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
  }, [sendWsJson]);

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
        ctx.clearRect(0, 0, canvas.width, canvas.height);
      }
    }
  }, []);

  const drawLatestFrame = useCallback(() => {
    const canvas = canvasRef.current;
    const bmp = latestBitmapRef.current;
    if (!canvas || !bmp) return;
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
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = "high";
    ctx.clearRect(0, 0, targetW, targetH);
    ctx.drawImage(bmp, 0, 0, targetW, targetH);
  }, []);

  useEffect(() => {
    const ro = new ResizeObserver(() => drawLatestFrame());
    if (viewportRef.current) ro.observe(viewportRef.current);
    if (canvasRef.current) ro.observe(canvasRef.current);
    return () => ro.disconnect();
  }, [drawLatestFrame, scaleMode, zoomPct, state.vw, state.vh]);

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
          const infoMsg =
            typeof msg.message === "string" && msg.message
              ? msg.message
              : `权限已变更为 ${r}，正在重新连接`;
          showToast(`🔒 ${infoMsg}`);
        } else if (mtype === "auth_error") {
          const errMsg = String(msg.error || "访问权限已被撤销");
          if (msg.source === "studio_auth") {
            connGenRef.current += 1;
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
        onSessionRevoked("会话权限已被撤销或已退出登录");
        return;
      }
      if (ev.code === 4008) {
        // Role downgraded (e.g. admin -> readonly): reset takeover immediately & reconnect fast
        roleRef.current = "readonly";
        setLiveRole("readonly");
        onRoleChanged?.("readonly");
        setState((prev) => ({ ...prev, takeover: false }));
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
      if (reconnectTimerRef.current) window.clearTimeout(reconnectTimerRef.current);
      if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      clearCanvasFrame();
    };
  }, [clearCanvasFrame, connectWs]);

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

  // Keyboard listener when takeover active & not typing in URL/dialog input
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const st = stateRef.current;
      if (roleRef.current !== "admin" || !st.takeover || !st.running) return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
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

  // Normalized 0..1 -> remote viewport pixel coordinates
  const mapClientCoords = (clientX: number, clientY: number): { x: number; y: number } | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return null;
    const nx = clamp01((clientX - rect.left) / rect.width);
    const ny = clamp01((clientY - rect.top) / rect.height);
    return {
      x: Math.round(nx * (stateRef.current.vw || 1280)),
      y: Math.round(ny * (stateRef.current.vh || 800)),
    };
  };

  const resolvePointerButton = (e: React.PointerEvent<HTMLCanvasElement>): string => {
    if (e.pointerType === "touch" || e.button < 0) return "left";
    return e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
  };

  const handleCanvasPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (liveRole !== "admin" || !state.takeover || !state.running) {
      if (liveRole === "admin" && state.running && !state.takeover) {
        showToast("请先点击顶栏【🖐 人工接管】再操作页面");
      }
      return;
    }
    if (!e.isPrimary) return;
    e.preventDefault();
    const pos = mapClientCoords(e.clientX, e.clientY);
    if (!pos) return;
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      // Ignore capture errors on synthetic or unsupported pointers
    }
    const btn = resolvePointerButton(e);
    heldPointerButtonsRef.current.set(e.pointerId, btn);
    heldMouseButtonsRef.current.add(btn);
    sendInput({ action: "mousedown", button: btn, x: pos.x, y: pos.y });
  };

  const handleCanvasPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (liveRole !== "admin" || !state.takeover || !state.running) return;
    if (!e.isPrimary) return;
    const now = performance.now();
    if (now - lastMoveTsRef.current < 32) return;
    lastMoveTsRef.current = now;
    const pos = mapClientCoords(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "move", x: pos.x, y: pos.y });
  };

  const finishCanvasPointer = (
    e: React.PointerEvent<HTMLCanvasElement>,
    forceReleaseOnlyIfHeld: boolean,
  ) => {
    try {
      if (e.currentTarget.hasPointerCapture(e.pointerId)) {
        e.currentTarget.releasePointerCapture(e.pointerId);
      }
    } catch {
      // Ignore release errors
    }
    const heldBtn = heldPointerButtonsRef.current.get(e.pointerId);
    heldPointerButtonsRef.current.delete(e.pointerId);
    if (forceReleaseOnlyIfHeld && !heldBtn) return;
    const btn = heldBtn || resolvePointerButton(e);
    heldMouseButtonsRef.current.delete(btn);
    if (liveRole !== "admin" || !state.takeover || !state.running) return;
    const pos = mapClientCoords(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "mouseup", button: btn, x: pos.x, y: pos.y });
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
    if (liveRole !== "admin" || !state.takeover || !state.running) return;
    e.preventDefault();
    const pos = mapClientCoords(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "dblclick", x: pos.x, y: pos.y });
  };

  const handleCanvasContextMenu = (e: React.MouseEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    if (liveRole !== "admin" || !state.takeover || !state.running) return;
    const pos = mapClientCoords(e.clientX, e.clientY);
    if (!pos) return;
    sendInput({ action: "rightclick", x: pos.x, y: pos.y });
  };

  const handleCanvasWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    if (liveRole !== "admin" || !state.takeover || !state.running) return;
    e.preventDefault();
    sendInput({ action: "wheel", dx: Math.round(e.deltaX), dy: Math.round(e.deltaY) });
  };

  const toggleTakeover = () => {
    if (liveRole !== "admin") return;
    if (state.takeover) {
      setHandbackModalOpen(true);
      return;
    }
    sendWsJson({
      type: "set_takeover",
      active: true,
      reason: "Studio 桌面端人工接管",
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
    if (liveRole !== "admin" || stopping) return;
    releaseAllHeldInputs();
    setStopping(true);
    try {
      await stopBrowser();
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

  // Compute CSS canvas box dimensions based on scaleMode
  const aspectRatio = `${state.vw || 1280} / ${state.vh || 800}`;
  const canvasStyle: React.CSSProperties =
    scaleMode === "1:1"
      ? { width: `${state.vw}px`, height: `${state.vh}px` }
      : scaleMode === "zoom"
        ? {
            width: `${Math.round((state.vw * zoomPct) / 100)}px`,
            height: `${Math.round((state.vh * zoomPct) / 100)}px`,
          }
        : {
            aspectRatio,
            maxWidth: "100%",
            maxHeight: "100%",
            width: "auto",
            height: "100%",
          };

  const cursorX = state.cursor?.x;
  const cursorY = state.cursor?.y;
  const showCursor =
    state.running &&
    typeof cursorX === "number" &&
    typeof cursorY === "number" &&
    state.vw > 0 &&
    state.vh > 0;
  const cursorLeftPct = showCursor ? clamp01(cursorX / state.vw) * 100 : 0;
  const cursorTopPct = showCursor ? clamp01(cursorY / state.vh) * 100 : 0;
  const isAiCursor = state.cursor?.actor !== "human";
  const canControl = liveRole === "admin" && state.takeover && state.running;
  const activeOwnerHandle = (state.owner_bot || selectedBot || "").replace(/^@/, "");
  const availableEngines = engines.filter((e) => e.available || e.id === "camoufox");
  const launchProfilesForEngine = profiles.filter((p) => p.engine === launchEngine);
  const extEngineLabel =
    engines.find((e) => e.id === "external_chromium")?.label || "External Chromium";
  const activeEngineDisplay =
    state.engine === "external_chromium" || state.engine_mode === "sync_external"
      ? extEngineLabel
      : "Camoufox";

  return (
    <div
      ref={stageWrapRef}
      className="flex flex-col h-full w-full bg-slate-950 overflow-hidden select-none"
    >
      {/* Minimal Single-Row Top Toolbar (~44px so canvas >90% of viewport) */}
      <div className="h-11 shrink-0 border-b border-slate-800/90 bg-slate-900/95 px-2.5 flex items-center gap-1.5 z-20">
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
            placeholder={
              state.running
                ? "输入网址并回车跳转…"
                : "浏览器待机中（未启动）"
            }
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
                  <div className="px-2 py-3 text-xs text-slate-500 text-center">
                    暂无活动标签页
                  </div>
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
        {!compact && !isDrawer && (
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
        )}

        {/* Scale mode: Fit / 1:1 / Zoom */}
        {!compact && !isDrawer && (
          <div className="hidden lg:flex items-center gap-0.5 rounded-md border border-slate-700/80 bg-slate-950/70 p-0.5 shrink-0">
            <button
              type="button"
              onClick={() => setScaleMode("fit")}
              className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                scaleMode === "fit"
                  ? "bg-slate-700 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              适屏
            </button>
            <button
              type="button"
              onClick={() => {
                setScaleMode("1:1");
                setZoomPct(100);
              }}
              className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                scaleMode === "1:1"
                  ? "bg-slate-700 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              1:1
            </button>
            <button
              type="button"
              onClick={() => {
                setScaleMode("zoom");
                setZoomPct((z) => Math.max(50, z - 15));
              }}
              className="h-5 w-5 inline-flex items-center justify-center rounded text-slate-400 hover:text-slate-100 cursor-pointer"
              title="缩小"
            >
              <ZoomOut className="w-3 h-3" />
            </button>
            <span className="text-[10px] font-mono text-slate-400 w-8 text-center">
              {scaleMode === "fit" ? "FIT" : `${zoomPct}%`}
            </span>
            <button
              type="button"
              onClick={() => {
                setScaleMode("zoom");
                setZoomPct((z) => Math.min(200, z + 15));
              }}
              className="h-5 w-5 inline-flex items-center justify-center rounded text-slate-400 hover:text-slate-100 cursor-pointer"
              title="放大"
            >
              <ZoomIn className="w-3 h-3" />
            </button>
          </div>
        )}

        {/* Unrestricted Full-Roster AI Selector (permanent in top toolbar) */}
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
          {!compact && !isDrawer && <span>配置</span>}
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
              wsStatus === "connected"
                ? "实时流已连接（点击重连）"
                : "连接断开（点击重连）"
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
            onClick={isDrawer && onExpandFull ? onExpandFull : toggleFullscreen}
            title={
              isDrawer && onExpandFull
                ? "展开全屏浏览器视图"
                : isFullscreen
                  ? "退出全屏"
                  : "全屏工作台"
            }
            className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-300 hover:bg-slate-800 cursor-pointer"
          >
            {isFullscreen && !isDrawer ? (
              <Minimize2 className="w-3.5 h-3.5" />
            ) : (
              <Maximize2 className="w-3.5 h-3.5" />
            )}
          </button>
          {isDrawer && onCloseDrawer && (
            <button
              type="button"
              onClick={onCloseDrawer}
              title="收起浏览器抽屉"
              className="h-7 w-7 rounded-md inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main High-Clarity Viewport Canvas (>90% of screen) */}
      <div
        ref={viewportRef}
        className={`relative flex-1 min-h-0 w-full bg-[#070a10] flex items-center justify-center ${
          scaleMode === "fit" ? "overflow-hidden p-1.5" : "overflow-auto p-3"
        }`}
      >
        <div
          className="relative flex items-center justify-center shadow-2xl ring-1 ring-slate-800/80 rounded-md overflow-hidden bg-slate-950"
          style={canvasStyle}
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

          {/* AI / Human Cursor Overlay */}
          {showCursor && (
            <div
              className="pointer-events-none absolute z-20 transition-[left,top] duration-75"
              style={{
                left: `${cursorLeftPct}%`,
                top: `${cursorTopPct}%`,
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

          {/* Idle / Restricted / Connecting Overlay */}
          {state.session_restricted ? (
            <div className="absolute inset-0 bg-slate-950/90 backdrop-blur-sm flex flex-col items-center justify-center gap-3 p-6 text-center z-30">
              <Lock className="w-8 h-8 text-amber-400" />
              <div className="text-sm font-semibold text-slate-100">
                当前浏览器会话已被隔离
              </div>
              <p className="text-xs text-slate-400 max-w-sm">
                {state.restricted_reason ||
                  "当前浏览器由其他授权会话占用，画面与状态已自动脱敏隔离。"}
              </p>
            </div>
          ) : !state.running ? (
            <div className="absolute inset-0 bg-slate-950/92 backdrop-blur-sm flex flex-col items-center justify-center gap-3.5 p-5 text-center z-30 overflow-y-auto">
              <div className="h-10 w-10 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center text-sky-400 shrink-0">
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
                  className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/90 p-3.5 text-left space-y-2.5 shadow-xl select-text"
                >
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">浏览器引擎</label>
                      <select
                        value={launchEngine}
                        onChange={(e) => setLaunchEngine(e.target.value as BrowserEngineId)}
                        className="w-full h-8 rounded-lg bg-slate-950 border border-slate-700 px-2 text-xs text-slate-100"
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
                        className="w-full h-8 rounded-lg bg-slate-950 border border-slate-700 px-2 text-xs text-slate-100"
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
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">起始网址（可选）</label>
                    <input
                      type="text"
                      value={launchUrl}
                      onChange={(e) => setLaunchUrl(e.target.value)}
                      placeholder="https://example.com（留空打开默认页）"
                      className="w-full h-8 rounded-lg bg-slate-950 border border-slate-700 px-2.5 text-xs text-slate-100 placeholder:text-slate-500"
                    />
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <span className="text-[11px] text-slate-400">
                      待命 AI:{" "}
                      <span className="font-mono text-sky-300">
                        @{activeOwnerHandle || "默认"}
                      </span>
                    </span>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          void refreshControlMetadata();
                          setConfigDrawerOpen(true);
                        }}
                        className="h-8 px-2.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs text-slate-300 cursor-pointer"
                      >
                        管理 Profile / 出口池
                      </button>
                      <button
                        type="submit"
                        disabled={launching}
                        className="h-8 px-3.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium inline-flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
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
        </div>

        {/* Subtle Floating Status Pill */}
        {state.running && !state.session_restricted && (
          <div className="pointer-events-none absolute bottom-3 left-3 z-20 flex flex-wrap items-center gap-1.5 rounded-full border border-slate-800/90 bg-slate-900/90 backdrop-blur px-2.5 py-1 text-[11px] text-slate-300">
            <span
              className={`h-2 w-2 rounded-full ${
                state.takeover
                  ? "bg-emerald-400"
                  : state.ai_busy
                    ? "bg-sky-400 animate-pulse"
                    : "bg-slate-400"
              }`}
            />
            <span>
              {state.takeover
                ? state.manual_launch
                  ? "手动接管中（AI 待命）"
                  : "人工接管中"
                : state.ai_busy
                  ? state.ai_status || "AI 操作中"
                  : "实时镜像"}
            </span>
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
          </div>
        )}

        {/* Handback to AI Modal with optional next-step instruction */}
        {handbackModalOpen && liveRole === "admin" && state.running && state.takeover && (
          <div className="absolute inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
            <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-4 shadow-2xl space-y-3 select-text">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                  <Bot className="w-4 h-4" />
                  <span>
                    交还控制权给 AI：@{activeOwnerHandle || "当前绑定 AI"}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setHandbackModalOpen(false)}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <p className="text-xs text-slate-400">
                可填写下一步工作指令（留空可直接一键交还）。如需改由其他 AI 接手，请先在顶栏切换操作 AI。
              </p>
              <textarea
                rows={3}
                maxLength={2000}
                value={handbackNote}
                onChange={(e) => setHandbackNote(e.target.value)}
                placeholder="例如：我已完成登录验证，请继续抓取当前页面订单并导出摘要（选填）"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setHandbackModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
                >
                  取消
                </button>
                <button
                  type="button"
                  disabled={submittingHandback}
                  onClick={() => void handleConfirmHandback(false)}
                  className="px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-xs text-emerald-300 cursor-pointer disabled:opacity-50"
                >
                  直接交还
                </button>
                <button
                  type="button"
                  disabled={submittingHandback}
                  onClick={() => void handleConfirmHandback(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-medium text-white inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  {submittingHandback && <Loader2 className="w-3 h-3 animate-spin" />}
                  {handbackNote.trim() ? "附带指令交还给 AI" : "确认交还给 AI"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Dual-Engine Profile & Egress Pool Config Drawer */}
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

        {/* Floating Toast */}
        {toast && (
          <div className="absolute top-3 left-1/2 -translate-x-1/2 z-40 rounded-full border border-slate-700 bg-slate-900/95 px-3.5 py-1.5 text-xs text-slate-100 shadow-xl">
            {toast}
          </div>
        )}

        {/* JS Dialog Modal */}
        {pendingDialog && liveRole === "admin" && (
          <div className="absolute inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
            <div className="w-full max-w-sm rounded-2xl border border-slate-700 bg-slate-900 p-4 shadow-2xl space-y-3">
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
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-100 select-text"
                />
              )}
              <div className="flex justify-end gap-2 pt-1">
                {pendingDialog.dialog_type !== "alert" && (
                  <button
                    type="button"
                    onClick={() => handleDialogReply(false)}
                    className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
                  >
                    取消
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => handleDialogReply(true)}
                  className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white cursor-pointer"
                >
                  确定
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
