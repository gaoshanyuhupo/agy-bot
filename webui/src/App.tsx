import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  Bell,
  Bot,
  Clock,
  CreditCard,
  DollarSign,
  FileCode,
  Globe,
  KeyRound,
  Layers,
  LayoutDashboard,
  LogOut,
  MessageSquare,
  MoreHorizontal,
  Shield,
  ShieldCheck,
} from "lucide-react";
import {
  StudioApiError,
  StudioEventClient,
  authChangePassword,
  authLogout,
  authRedeemMagic,
  authTelegram,
  fetchMe,
  setCsrfToken,
} from "./api";
import {
  captureAndScrubMagicFragment,
  hasTelegramWebViewHint,
  loadTelegramSdkOnce,
} from "./bootstrapAuth";
import { AttentionPanel } from "./components/AttentionPanel";
import { BotsView } from "./components/BotsView";
import { BrowserView } from "./components/BrowserView";
import { ChangePasswordModal } from "./components/ChangePasswordModal";
import { CostsView } from "./components/CostsView";
import { ExternalModelsView } from "./components/ExternalModelsView";
import { FilesDiffPanel } from "./components/FilesDiffPanel";
import { JobsView } from "./components/JobsView";
import { LoginView } from "./components/LoginView";
import { MobileMoreSheet } from "./components/MobileMoreSheet";
import { OpenBaoConfigView } from "./components/OpenBaoConfigView";
import { OverviewView } from "./components/OverviewView";
import { SchedulesView } from "./components/SchedulesView";
import { SecurityCardView } from "./components/SecurityCardView";
import { WorkspaceView } from "./components/WorkspaceView";
import type {
  AuthMode,
  BrowserOwner,
  EventStreamStatus,
  NavTab,
  RoomLiveEvent,
  RoomMessageItem,
  SessionUpdatedEvent,
  StudioSession,
} from "./types";

const DESKTOP_NAV_ITEMS: {
  id: NavTab;
  label: string;
  icon: typeof LayoutDashboard;
  badge?: string;
}[] = [
  { id: "workspace", label: "工作台", icon: MessageSquare },
  { id: "attention", label: "审批中心", icon: Bell },
  { id: "files", label: "文件审查", icon: FileCode },
  { id: "jobs", label: "派工流水", icon: Activity },
  { id: "schedules", label: "定时任务", icon: Clock },
  { id: "bots", label: "Bot 团队", icon: Bot },
  { id: "models", label: "外部模型", icon: Layers },
  { id: "openbao", label: "OpenBao", icon: ShieldCheck },
  { id: "security-card", label: "安全卡", icon: CreditCard, badge: "预留" },
  { id: "costs", label: "用量账单", icon: DollarSign },
  { id: "overview", label: "总览", icon: LayoutDashboard },
];

const MOBILE_PRIMARY_TABS: { id: NavTab; label: string; icon: typeof MessageSquare }[] = [
  { id: "workspace", label: "对话", icon: MessageSquare },
  { id: "jobs", label: "派工", icon: Activity },
  { id: "browser", label: "浏览器", icon: Globe },
  { id: "schedules", label: "调度", icon: Clock },
];

function detectInitialTab(): NavTab {
  const path = window.location.pathname.replace(/^\/+|\/+$/g, "");
  if (path === "rooms") {
    return "workspace";
  }
  if (
    path === "workspace" ||
    path === "attention" ||
    path === "files" ||
    path === "overview" ||
    path === "browser" ||
    path === "bots" ||
    path === "models" ||
    path === "openbao" ||
    path === "security-card" ||
    path === "jobs" ||
    path === "schedules" ||
    path === "costs"
  ) {
    return path;
  }
  return "workspace";
}

function parseTelegramInitUserId(initData: string): number | null {
  try {
    const params = new URLSearchParams(initData);
    const rawUser = params.get("user");
    if (!rawUser) return null;
    const obj = JSON.parse(rawUser) as { id?: unknown };
    return typeof obj.id === "number" && Number.isInteger(obj.id) && obj.id > 0
      ? obj.id
      : null;
  } catch {
    return null;
  }
}

// React 19 StrictMode-safe shared one-shot magic redeem promise (legacy mode only)
let inflightMagicRedeem: Promise<StudioSession> | null = null;

function redeemMagicOnce(token: string): Promise<StudioSession> {
  if (!inflightMagicRedeem) {
    inflightMagicRedeem = authRedeemMagic(token);
  }
  return inflightMagicRedeem;
}

export function App() {
  const [authMode, setAuthMode] = useState<AuthMode>("password");
  const [session, setSession] = useState<StudioSession | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isMagicFlow, setIsMagicFlow] = useState(false);
  const [activeTab, setActiveTab] = useState<NavTab>(detectInitialTab);
  const [isTelegramEnv, setIsTelegramEnv] = useState(false);
  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [browserOwner, setBrowserOwner] = useState<BrowserOwner>(() =>
    detectInitialTab() === "browser" ? "tab" : "none",
  );
  const [moreSheetOpen, setMoreSheetOpen] = useState(false);
  const [wsSessionEpoch, setWsSessionEpoch] = useState(0);
  const [eventStatus, setEventStatus] = useState<EventStreamStatus>("disconnected");
  const [jobsEventVer, setJobsEventVer] = useState(0);
  const [schedulesEventVer, setSchedulesEventVer] = useState(0);
  const [botsEventVer, setBotsEventVer] = useState(0);
  const [overviewEventVer, setOverviewEventVer] = useState(0);
  const [attentionEventVer, setAttentionEventVer] = useState(0);
  const [pendingAttentionCount, setPendingAttentionCount] = useState(0);
  const [roomEvents, setRoomEvents] = useState<RoomLiveEvent[]>([]);
  const roomEventSeqRef = useRef(0);
  const [sessionSyncEvent, setSessionSyncEvent] = useState<SessionUpdatedEvent | null>(null);
  const passwordChangingRef = useRef(false);

  const pushRoomEvent = useCallback((ev: Omit<RoomLiveEvent, "ver">) => {
    const ver = ++roomEventSeqRef.current;
    setRoomEvents((prev) => [...prev.slice(-23), { ...ev, ver }]);
  }, []);

  const applySession = useCallback((sess: StudioSession) => {
    if (sess.auth_mode === "password" || sess.auth_mode === "legacy") {
      setAuthMode(sess.auth_mode);
    }
    setCsrfToken(sess.csrf_token);
    setSession(sess);
    setAuthError(null);
  }, []);

  const runTelegramAuth = useCallback(async () => {
    const initData = window.Telegram?.WebApp?.initData || "";
    if (!initData) return false;
    setAuthLoading(true);
    setAuthError(null);
    try {
      const sess = await authTelegram(initData);
      applySession(sess);
      return true;
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : "Telegram Mini App 身份验证失败");
      return false;
    } finally {
      setAuthLoading(false);
    }
  }, [applySession]);

  useEffect(() => {
    let cancelled = false;
    const magicTok = captureAndScrubMagicFragment();

    const runBootstrap = async () => {
      let detectedMode: AuthMode = "password";
      let existingSession: StudioSession | null = null;

      try {
        const me = await fetchMe();
        if (cancelled) return;
        detectedMode = me.auth_mode === "legacy" ? "legacy" : "password";
        existingSession = me;
      } catch (err) {
        if (cancelled) return;
        if (err instanceof StudioApiError && err.authMode === "legacy") {
          detectedMode = "legacy";
        } else {
          detectedMode = "password";
        }
      }

      setAuthMode(detectedMode);

      if (detectedMode === "password") {
        if (window.location.pathname === "/auth/magic") {
          window.history.replaceState(null, "", "/");
        }
        if (existingSession) {
          applySession(existingSession);
        }
        setAuthLoading(false);
        return;
      }

      // Legacy dual-track mode only (`auth_mode === "legacy"`)
      if (magicTok) {
        setIsMagicFlow(true);
        setAuthLoading(true);
        try {
          const sess = await redeemMagicOnce(magicTok);
          if (cancelled) return;
          applySession(sess);
          setActiveTab("workspace");
          window.history.replaceState(null, "", "/");
        } catch (e) {
          if (cancelled) return;
          setAuthError(
            e instanceof Error ? e.message : "一次性登录链接无效或已过期",
          );
        } finally {
          if (!cancelled) {
            setIsMagicFlow(false);
            setAuthLoading(false);
          }
        }
        return;
      }

      const tgHint = hasTelegramWebViewHint();
      const sdkPromise = loadTelegramSdkOnce();
      if (tgHint) {
        await sdkPromise;
        if (cancelled) return;
      }

      const tgApp = window.Telegram?.WebApp;
      let tgInitData = tgApp?.initData || "";
      let hasTgInit = Boolean(tgInitData);
      setIsTelegramEnv(hasTgInit);
      if (hasTgInit) {
        tgApp?.ready?.();
        tgApp?.expand?.();
      }

      const expectedTgUid = hasTgInit ? parseTelegramInitUserId(tgInitData) : null;

      if (existingSession) {
        if (
          hasTgInit &&
          (existingSession.auth_track !== "telegram" ||
            (expectedTgUid !== null && existingSession.user_id !== expectedTgUid))
        ) {
          await runTelegramAuth();
          return;
        }
        applySession(existingSession);
        setAuthLoading(false);
        return;
      }

      if (!hasTgInit) {
        await sdkPromise;
        if (cancelled) return;
        const lateTg = window.Telegram?.WebApp;
        tgInitData = lateTg?.initData || "";
        hasTgInit = Boolean(tgInitData);
        setIsTelegramEnv(hasTgInit);
        if (hasTgInit) {
          lateTg?.ready?.();
          lateTg?.expand?.();
        }
      }
      if (hasTgInit) {
        await runTelegramAuth();
      } else {
        setAuthLoading(false);
      }
    };

    void runBootstrap();

    return () => {
      cancelled = true;
    };
  }, [applySession, runTelegramAuth]);

  const handleNavigate = (tab: NavTab) => {
    setActiveTab(tab);
    if (tab === "browser") {
      setBrowserOwner("tab");
    } else if (browserOwner === "tab") {
      setBrowserOwner("none");
    }
    if (window.location.pathname !== `/${tab}`) {
      window.history.replaceState({}, "", `/${tab}`);
    }
  };

  const handleToggleBrowserDrawer = useCallback(() => {
    setBrowserOwner((cur) => (cur === "drawer" ? "none" : "drawer"));
  }, []);

  const handleLogout = async () => {
    try {
      await authLogout();
    } catch {
      // Ignore network errors on logout
    }
    setPasswordModalOpen(false);
    setBrowserOwner("none");
    setMoreSheetOpen(false);
    setCsrfToken("");
    setSession(null);
    setAuthError(null);
  };

  const handleSessionRevoked = useCallback(
    (reason: string) => {
      if (passwordChangingRef.current) {
        return;
      }
      if (reason === "password_change_required") {
        void fetchMe()
          .then((me) => {
            applySession(me);
          })
          .catch(() => {
            setCsrfToken("");
            setSession(null);
            setAuthError("需要重新修改密码后方可继续访问");
          });
        return;
      }
      setPasswordModalOpen(false);
      setBrowserOwner("none");
      setMoreSheetOpen(false);
      setCsrfToken("");
      setSession(null);
      setAuthError(reason);
    },
    [applySession],
  );

  const handlePasswordChange = useCallback(
    async (currentPassword: string, newPassword: string) => {
      passwordChangingRef.current = true;
      let succeeded = false;
      try {
        const rotated = await authChangePassword(currentPassword, newPassword);
        succeeded = true;
        applySession(rotated);
        setWsSessionEpoch((n) => n + 1);
      } catch (err) {
        passwordChangingRef.current = false;
        if (err instanceof StudioApiError && (err.status === 401 || err.status === 403)) {
          try {
            const me = await fetchMe();
            applySession(me);
          } catch (meErr) {
            if (meErr instanceof StudioApiError && (meErr.status === 401 || meErr.status === 403)) {
              handleSessionRevoked(err.message || meErr.message || "会话已失效，请重新登录");
            }
          }
        }
        throw err;
      } finally {
        if (succeeded) {
          window.setTimeout(() => {
            passwordChangingRef.current = false;
          }, 300);
        } else {
          passwordChangingRef.current = false;
        }
      }
    },
    [applySession, handleSessionRevoked],
  );

  const handleRoleChanged = useCallback((nextRole: "admin" | "readonly") => {
    setSession((cur) => (cur ? { ...cur, role: nextRole } : cur));
  }, []);

  // Global SSE `/api/events` subscription for real-time Jobs/Schedules/Bots/Overview updates
  const sessionReady = Boolean(session && !session.must_change_password);
  useEffect(() => {
    if (!sessionReady) {
      setEventStatus("disconnected");
      return;
    }
    const client = new StudioEventClient({
      onStatus: (st) => setEventStatus(st),
      onEvent: (ev) => {
        if (ev.type === "job_updated") {
          const d = ev.data || {};
          setJobsEventVer((n) => n + 1);
          setOverviewEventVer((n) => n + 1);
          pushRoomEvent({
            type: "job_updated",
            room_id: "lobby",
            job_id: typeof d.job_id === "string" ? d.job_id : undefined,
            bot: typeof d.bot === "string" ? d.bot : undefined,
            status: typeof d.status === "string" ? d.status : undefined,
            label: typeof d.label === "string" ? d.label : undefined,
            phase: typeof d.phase === "string" ? d.phase : undefined,
            duration_s: typeof d.duration_s === "number" ? d.duration_s : null,
            source: typeof d.source === "string" ? d.source : undefined,
            ts: typeof d.ts === "number" ? d.ts : Math.floor(Date.now() / 1000),
          });
        } else if (ev.type === "schedule_updated") {
          setSchedulesEventVer((n) => n + 1);
          setOverviewEventVer((n) => n + 1);
        } else if (ev.type === "bots_updated") {
          const d = ev.data || {};
          setBotsEventVer((n) => n + 1);
          setOverviewEventVer((n) => n + 1);
          pushRoomEvent({
            type: "bots_updated",
            room_id: "lobby",
            ts: typeof d.ts === "number" ? d.ts : Math.floor(Date.now() / 1000),
          });
        } else if (ev.type === "session_updated") {
          const d = ev.data || {};
          setSessionSyncEvent((prev) => ({
            ver: (prev?.ver || 0) + 1,
            type: "session_updated",
            cid: typeof d.cid === "string" ? d.cid : undefined,
            bot: typeof d.bot === "string" ? d.bot : undefined,
            source: typeof d.source === "string" ? d.source : undefined,
            status: typeof d.status === "string" ? d.status : undefined,
            busy: typeof d.busy === "boolean" ? d.busy : undefined,
            updated_at: typeof d.updated_at === "number" ? d.updated_at : undefined,
          }));
        } else if (ev.type === "room_message") {
          const d = ev.data || {};
          const msgObj: RoomMessageItem | undefined =
            typeof d.room_id === "string" && typeof d.msg_id === "string"
              ? {
                  seq: typeof d.seq === "number" ? d.seq : 0,
                  msg_id: d.msg_id,
                  room_id: d.room_id,
                  ts: typeof d.ts === "number" ? d.ts : Math.floor(Date.now() / 1000),
                  sender_type:
                    d.sender_type === "human" || d.sender_type === "bot" || d.sender_type === "system"
                      ? d.sender_type
                      : "system",
                  sender: typeof d.sender === "string" ? d.sender : "",
                  sender_role: typeof d.sender_role === "string" ? d.sender_role : undefined,
                  source: typeof d.source === "string" ? d.source : undefined,
                  stage_tag: typeof d.stage_tag === "string" ? d.stage_tag : undefined,
                  job_id: typeof d.job_id === "string" ? d.job_id : undefined,
                  content: typeof d.text === "string" ? d.text : "",
                  attachments: Array.isArray(d.attachments)
                    ? (d.attachments as RoomMessageItem["attachments"])
                    : undefined,
                  context_files: Array.isArray(d.context_files)
                    ? d.context_files.filter((x): x is string => typeof x === "string")
                    : undefined,
                  truncated: Boolean(d.truncated),
                  mentions: Array.isArray(d.mentions)
                    ? d.mentions.filter((x): x is string => typeof x === "string")
                    : [],
                  chain_id: typeof d.chain_id === "string" ? d.chain_id : "",
                  hop: typeof d.hop === "number" ? d.hop : 0,
                  status: typeof d.status === "string" ? d.status : "done",
                  blocked_reason: typeof d.blocked_reason === "string" ? d.blocked_reason : "",
                }
              : undefined;
          pushRoomEvent({
            type: "room_message",
            room_id: typeof d.room_id === "string" ? d.room_id : undefined,
            message: msgObj,
          });
        } else if (ev.type === "room_typing") {
          const d = ev.data || {};
          pushRoomEvent({
            type: "room_typing",
            room_id: typeof d.room_id === "string" ? d.room_id : undefined,
            bot: typeof d.bot === "string" ? d.bot : undefined,
            typing: Boolean(d.typing),
            ts: typeof d.ts === "number" ? d.ts : Math.floor(Date.now() / 1000),
          });
        } else if (ev.type === "room_activity") {
          const d = ev.data || {};
          pushRoomEvent({
            type: "room_activity",
            room_id: typeof d.room_id === "string" ? d.room_id : undefined,
            bot: typeof d.bot === "string" ? d.bot : undefined,
            from_bot: typeof d.from_bot === "string" ? d.from_bot : undefined,
            display_name: typeof d.display_name === "string" ? d.display_name : undefined,
            role: typeof d.role === "string" ? d.role : undefined,
            busy: typeof d.busy === "boolean" ? d.busy : undefined,
            phase: typeof d.phase === "string" ? d.phase : undefined,
            target_bots: Array.isArray(d.target_bots)
              ? d.target_bots.filter((x): x is string => typeof x === "string")
              : undefined,
            job_id: typeof d.job_id === "string" ? d.job_id : undefined,
            group_id: typeof d.group_id === "string" ? d.group_id : undefined,
            status: typeof d.status === "string" ? d.status : undefined,
            label: typeof d.label === "string" ? d.label : undefined,
            stage_label: typeof d.stage_label === "string" ? d.stage_label : undefined,
            duration_s: typeof d.duration_s === "number" ? d.duration_s : null,
            queue_depth: typeof d.queue_depth === "number" ? d.queue_depth : undefined,
            source: typeof d.source === "string" ? d.source : undefined,
            ts: typeof d.ts === "number" ? d.ts : Math.floor(Date.now() / 1000),
          });
        } else if (ev.type === "attention_updated") {
          const d = ev.data || {};
          setAttentionEventVer((n) => n + 1);
          if (typeof d.pending_count === "number" && Number.isFinite(d.pending_count)) {
            setPendingAttentionCount(Math.max(0, Math.floor(d.pending_count)));
          }
        } else if (ev.type === "resync_required") {
          setJobsEventVer((n) => n + 1);
          setSchedulesEventVer((n) => n + 1);
          setBotsEventVer((n) => n + 1);
          setOverviewEventVer((n) => n + 1);
          setAttentionEventVer((n) => n + 1);
          pushRoomEvent({
            type: "resync_required",
          });
          setSessionSyncEvent((prev) => ({
            ver: (prev?.ver || 0) + 1,
            type: "resync_required",
          }));
        }
      },
      onAuthError: (reason, code) => {
        if (code === "role_changed") {
          void fetchMe()
            .then((me) => {
              applySession(me);
              setWsSessionEpoch((n) => n + 1);
            })
            .catch(() => {
              handleSessionRevoked(reason);
            });
          return;
        }
        handleSessionRevoked(reason);
      },
    });
    client.start();
    return () => {
      client.stop();
    };
  }, [sessionReady, wsSessionEpoch, applySession, handleSessionRevoked, pushRoomEvent]);

  if (authLoading || !session) {
    return (
      <LoginView
        authMode={authMode}
        loading={authLoading}
        isMagicFlow={isMagicFlow}
        isTelegramEnv={isTelegramEnv}
        error={authError}
        onLoginSuccess={applySession}
        onRetryTelegram={
          authMode === "legacy" && isTelegramEnv
            ? () => void runTelegramAuth()
            : undefined
        }
      />
    );
  }

  if (session.must_change_password) {
    return (
      <ChangePasswordModal
        session={session}
        forced
        onSubmitPasswordChange={handlePasswordChange}
        onLogout={() => void handleLogout()}
      />
    );
  }

  const compactMode = authMode === "legacy" && isTelegramEnv;
  const isPasswordTrack = session.auth_track === "password";
  const accountLabel = session.username
    ? session.username
    : `${session.bot} · #${session.user_id}`;
  const isMoreTabActive =
    activeTab === "attention" ||
    activeTab === "files" ||
    activeTab === "overview" ||
    activeTab === "bots" ||
    activeTab === "models" ||
    activeTab === "openbao" ||
    activeTab === "security-card" ||
    activeTab === "costs";
  const showDesktopBrowserDrawer =
    !compactMode && browserOwner === "drawer" && activeTab !== "browser";

  return (
    <div className="h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 flex flex-col md:flex-row">
      {/* Desktop Left Sidebar (hidden on mobile & TG Mini App compact mode) */}
      {!compactMode && (
        <aside className="hidden md:flex w-52 shrink-0 flex-col border-r border-slate-800/90 bg-slate-900/80">
          <div className="h-11 px-3.5 border-b border-slate-800/90 flex items-center gap-2">
            <Shield className="w-4 h-4 text-sky-400" />
            <span className="font-semibold text-sm tracking-tight">AGY Studio</span>
            <span
              title={
                eventStatus === "connected"
                  ? "实时事件流已连接"
                  : eventStatus === "reconnecting"
                    ? "实时事件流重连中"
                    : "实时事件流未连接"
              }
              className={`ml-auto inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded ${
                eventStatus === "connected"
                  ? "bg-emerald-500/15 text-emerald-300"
                  : eventStatus === "reconnecting" || eventStatus === "connecting"
                    ? "bg-amber-500/15 text-amber-300"
                    : "bg-slate-800 text-slate-400"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  eventStatus === "connected"
                    ? "bg-emerald-400"
                    : eventStatus === "reconnecting" || eventStatus === "connecting"
                      ? "bg-amber-400 animate-pulse"
                      : "bg-slate-500"
                }`}
              />
              {eventStatus === "connected"
                ? "LIVE"
                : eventStatus === "reconnecting" || eventStatus === "connecting"
                  ? "SYNC"
                  : "OFF"}
            </span>
          </div>

          <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
            {DESKTOP_NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNavigate(item.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                    active
                      ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                      : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                  {item.id === "attention" && pendingAttentionCount > 0 && (
                    <span className="ml-auto px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 text-[10px] font-mono">
                      {pendingAttentionCount}
                    </span>
                  )}
                  {item.badge && (
                    <span className="ml-auto px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/25 text-[10px] font-medium">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}

            <div className="pt-2 mt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={() => {
                  if (activeTab === "browser") {
                    handleNavigate("workspace");
                  } else {
                    handleToggleBrowserDrawer();
                  }
                }}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  activeTab === "browser" || browserOwner === "drawer"
                    ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                    : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
                }`}
              >
                <Globe className="w-4 h-4 shrink-0" />
                <span>实时浏览器</span>
              </button>
            </div>
          </nav>

          <div className="p-3 border-t border-slate-800/90 space-y-2">
            <div className="flex items-center justify-between text-[11px] gap-1.5">
              <span className="font-mono text-slate-300 truncate" title={accountLabel}>
                {accountLabel}
              </span>
              <span
                className={`shrink-0 px-1.5 py-0.5 rounded font-semibold uppercase text-[10px] ${
                  session.role === "admin"
                    ? "bg-emerald-500/15 text-emerald-300"
                    : "bg-amber-500/15 text-amber-300"
                }`}
              >
                {session.role}
              </span>
            </div>
            {isPasswordTrack && (
              <button
                type="button"
                onClick={() => setPasswordModalOpen(true)}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 py-1.5 text-xs text-slate-300 hover:text-slate-100 cursor-pointer"
              >
                <KeyRound className="w-3.5 h-3.5" />
                修改密码
              </button>
            )}
            <button
              type="button"
              onClick={() => void handleLogout()}
              className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 py-1.5 text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              退出登录
            </button>
          </div>
        </aside>
      )}

      {/* Center Stage + Desktop Right Collapsible Browser Drawer */}
      <div className="flex-1 min-w-0 min-h-0 flex overflow-hidden">
        <main className="flex-1 min-w-0 min-h-0 overflow-hidden flex flex-col">
          {activeTab === "workspace" ? (
            <WorkspaceView
              session={session}
              compactMode={compactMode}
              browserOwner={browserOwner}
              wsSessionEpoch={wsSessionEpoch}
              sessionSyncEvent={sessionSyncEvent}
              roomEvent={roomEvents[roomEvents.length - 1] || null}
              roomEvents={roomEvents}
              jobsEventVer={jobsEventVer}
              attentionEventVer={attentionEventVer}
              onClaimBrowserOwner={setBrowserOwner}
              onToggleBrowserDrawer={handleToggleBrowserDrawer}
              onPendingAttentionCount={setPendingAttentionCount}
              onRoleChanged={handleRoleChanged}
              onSessionRevoked={handleSessionRevoked}
            />
          ) : activeTab === "attention" ? (
            <AttentionPanel
              session={session}
              eventVersion={attentionEventVer}
              onOpenBrowser={() => handleNavigate("browser")}
              onPendingCountChange={setPendingAttentionCount}
              onSessionRevoked={handleSessionRevoked}
            />
          ) : activeTab === "files" ? (
            <FilesDiffPanel
              session={session}
              onSessionRevoked={handleSessionRevoked}
            />
          ) : activeTab === "browser" ? (
            <BrowserView
              key={`full-${wsSessionEpoch}`}
              session={session}
              compact={compactMode}
              variant="full"
              onSessionRevoked={handleSessionRevoked}
              onRoleChanged={handleRoleChanged}
            />
          ) : (
            <div className="flex-1 min-h-0 overflow-y-auto">
              {activeTab === "overview" && (
                <OverviewView
                  onNavigate={handleNavigate}
                  eventVersion={overviewEventVer}
                />
              )}
              {activeTab === "bots" && (
                <BotsView
                  session={session}
                  eventVersion={botsEventVer}
                  onSessionRevoked={handleSessionRevoked}
                />
              )}
              {activeTab === "models" && (
                <ExternalModelsView
                  session={session}
                  onNavigate={handleNavigate}
                  onSessionRevoked={handleSessionRevoked}
                />
              )}
              {activeTab === "openbao" && (
                <OpenBaoConfigView
                  session={session}
                  onNavigate={handleNavigate}
                  onSessionRevoked={handleSessionRevoked}
                />
              )}
              {activeTab === "security-card" && (
                <SecurityCardView onNavigate={handleNavigate} />
              )}
              {activeTab === "jobs" && (
                <JobsView
                  session={session}
                  eventVersion={jobsEventVer}
                  onSessionRevoked={handleSessionRevoked}
                />
              )}
              {activeTab === "schedules" && (
                <SchedulesView
                  session={session}
                  eventVersion={schedulesEventVer}
                  onSessionRevoked={handleSessionRevoked}
                />
              )}
              {activeTab === "costs" && <CostsView />}
            </div>
          )}
        </main>

        {/* Desktop Right Collapsible Live-Browser Companion Drawer (unmounted when collapsed) */}
        {showDesktopBrowserDrawer && (
          <aside className="hidden md:flex w-[440px] xl:w-[540px] shrink-0 border-l border-slate-800/90 bg-slate-950 flex-col min-h-0">
            <BrowserView
              key={`drawer-${wsSessionEpoch}`}
              session={session}
              compact={false}
              variant="drawer"
              onExpandFull={() => {
                handleNavigate("browser");
              }}
              onCloseDrawer={() => setBrowserOwner("none")}
              onSessionRevoked={handleSessionRevoked}
              onRoleChanged={handleRoleChanged}
            />
          </aside>
        )}
      </div>

      {/* Mobile / TG Mini App Bottom Bar: STRICTLY 5 Items */}
      <nav
        aria-label="移动端主导航"
        className={`${
          compactMode ? "flex" : "flex md:hidden"
        } shrink-0 h-13 border-t border-slate-800 bg-slate-900/95 items-center justify-around px-1`}
      >
        {MOBILE_PRIMARY_TABS.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleNavigate(item.id)}
              className={`flex-1 flex flex-col items-center justify-center gap-0.5 py-1 rounded-lg text-[10px] cursor-pointer ${
                active ? "text-sky-400 font-semibold" : "text-slate-400"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{item.label}</span>
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => setMoreSheetOpen(true)}
          className={`flex-1 flex flex-col items-center justify-center gap-0.5 py-1 rounded-lg text-[10px] cursor-pointer ${
            isMoreTabActive || moreSheetOpen ? "text-sky-400 font-semibold" : "text-slate-400"
          }`}
        >
          <MoreHorizontal className="w-4 h-4" />
          <span>更多</span>
        </button>
      </nav>

      <MobileMoreSheet
        open={moreSheetOpen}
        activeTab={activeTab}
        session={session}
        isPasswordTrack={isPasswordTrack}
        onClose={() => setMoreSheetOpen(false)}
        onNavigate={handleNavigate}
        onOpenPasswordModal={() => setPasswordModalOpen(true)}
        onLogout={() => void handleLogout()}
      />

      {passwordModalOpen && isPasswordTrack && (
        <ChangePasswordModal
          session={session}
          forced={false}
          onSubmitPasswordChange={handlePasswordChange}
          onClose={() => setPasswordModalOpen(false)}
        />
      )}
    </div>
  );
}
export default App;
