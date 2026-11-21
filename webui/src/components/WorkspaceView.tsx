import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  ChevronDown,
  ChevronRight,
  Columns2,
  Columns3,
  FileCode,
  Globe,
  Grid2x2,
  Loader2,
  Lock,
  MessageSquare,
  PanelLeft,
  Plus,
  RefreshCw,
  Search,
  Send,
  Square,
  Users,
  Wrench,
} from "lucide-react";
import {
  StudioApiError,
  abortChatTurn,
  fetchActiveSessionTurn,
  fetchBots,
  fetchModels,
  fetchSessionMessages,
  fetchSessions,
  sendChatTurn,
} from "../api";
import {
  MAX_CLIENT_CHAT_STREAMS,
  releaseStreamSlot as releaseStreamSlotById,
  useStreamBudget,
} from "../streamBudget";
import type {
  BotRosterItem,
  BrowserOwner,
  ChatMessageItem,
  ChatToolCall,
  ModelsResponse,
  PaneKind,
  RoomLiveEvent,
  SessionSummaryItem,
  SessionUpdatedEvent,
  StudioSession,
  WorkbenchLayoutPrefs,
  WorkbenchPaneConfig,
} from "../types";
import { AttentionPanel } from "./AttentionPanel";
import { BrowserView } from "./BrowserView";
import { FilesDiffPanel } from "./FilesDiffPanel";
import { JobsView } from "./JobsView";
import { RoomPanel } from "./RoomPanel";
import { SafeMarkdown } from "./SafeMarkdown";

const SYNC_TG_STORAGE_KEY = "agy_studio_sync_tg";
const WORKBENCH_STORAGE_KEY = "agy_studio_workbench_v1";

const VALID_PANE_KINDS: ReadonlySet<PaneKind> = new Set<PaneKind>([
  "chat",
  "room",
  "jobs_attention",
  "files",
  "browser",
]);

const DEFAULT_PANES: WorkbenchPaneConfig[] = [
  { id: "pane-1", kind: "chat" },
  { id: "pane-2", kind: "room", roomId: "lobby" },
  { id: "pane-3", kind: "jobs_attention" },
  { id: "pane-4", kind: "files" },
];

const DEFAULT_LAYOUT: WorkbenchLayoutPrefs = {
  paneCount: 1,
  layoutMode: "1",
  panes: DEFAULT_PANES,
};

function sanitizeShortSlug(raw: unknown, maxLen = 64): string | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.trim();
  if (!s || s.length > maxLen) return undefined;
  if (!/^[A-Za-z0-9._-]+$/.test(s)) return undefined;
  return s;
}

function loadWorkbenchPrefs(): WorkbenchLayoutPrefs {
  try {
    const raw = window.localStorage.getItem(WORKBENCH_STORAGE_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") return DEFAULT_LAYOUT;

    const rawCount = parsed.paneCount;
    const paneCount: 1 | 2 | 3 | 4 =
      rawCount === 2 || rawCount === 3 || rawCount === 4 ? rawCount : 1;
    const layoutMode: "1" | "2" | "3" | "4" = String(paneCount) as "1" | "2" | "3" | "4";

    const rawPanes = Array.isArray(parsed.panes) ? parsed.panes : [];
    const panes: WorkbenchPaneConfig[] = [];
    for (let i = 0; i < 4; i += 1) {
      const item = rawPanes[i] as Record<string, unknown> | undefined;
      const fallback = DEFAULT_PANES[i];
      if (!item || typeof item !== "object") {
        panes.push({ ...fallback });
        continue;
      }
      const rawKind = item.kind;
      const kind: PaneKind =
        typeof rawKind === "string" && VALID_PANE_KINDS.has(rawKind as PaneKind)
          ? (rawKind as PaneKind)
          : fallback.kind;
      const id = `pane-${i + 1}`;
      panes.push({
        id,
        kind,
        bot: sanitizeShortSlug(item.bot, 64),
        project: sanitizeShortSlug(item.project, 64),
        roomId: sanitizeShortSlug(item.roomId, 32) || (kind === "room" ? "lobby" : undefined),
      });
    }
    return { paneCount, layoutMode, panes };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

function saveWorkbenchPrefs(prefs: WorkbenchLayoutPrefs): void {
  try {
    // Strictly persist ONLY non-sensitive layout metadata (never prompts, messages, tokens, or paths)
    const clean: WorkbenchLayoutPrefs = {
      paneCount: prefs.paneCount,
      layoutMode: prefs.layoutMode,
      panes: prefs.panes.slice(0, 4).map((p, idx) => ({
        id: `pane-${idx + 1}`,
        kind: VALID_PANE_KINDS.has(p.kind) ? p.kind : "chat",
        ...(sanitizeShortSlug(p.bot, 64) ? { bot: sanitizeShortSlug(p.bot, 64) } : {}),
        ...(sanitizeShortSlug(p.project, 64) ? { project: sanitizeShortSlug(p.project, 64) } : {}),
        ...(sanitizeShortSlug(p.roomId, 32) ? { roomId: sanitizeShortSlug(p.roomId, 32) } : {}),
      })),
    };
    const serialized = JSON.stringify(clean);
    window.localStorage.setItem(WORKBENCH_STORAGE_KEY, serialized);
  } catch {
    // Ignore storage failures
  }
}

export interface PendingQuotePayload {
  id: number;
  text: string;
}

export interface ChatPaneProps {
  paneId: string;
  session: StudioSession;
  initialBot?: string;
  initialProject?: string;
  defaultSidebarOpen?: boolean;
  compactHeader?: boolean;
  sessionSyncEvent?: SessionUpdatedEvent | null;
  pendingQuote?: PendingQuotePayload | null;
  onQuoteConsumed?: (quoteId: number) => void;
  onBotChange?: (bot: string) => void;
  onProjectChange?: (projectId: string) => void;
  onActiveCidChange?: (cid: string | null) => void;
  onFocusPane?: (paneId: string) => void;
  extraHeaderActions?: ReactNode;
  onSessionRevoked: (reason: string) => void;
}

export function ChatPane({
  paneId,
  session,
  initialBot,
  initialProject,
  defaultSidebarOpen = true,
  compactHeader = false,
  sessionSyncEvent,
  pendingQuote,
  onQuoteConsumed,
  onBotChange,
  onProjectChange,
  onActiveCidChange,
  onFocusPane,
  extraHeaderActions,
  onSessionRevoked,
}: ChatPaneProps) {
  const isReadonly = session.role !== "admin";
  const { acquire: acquireStreamSlot, release: releaseStreamSlot } = useStreamBudget(paneId);

  const [sidebarOpen, setSidebarOpen] = useState(defaultSidebarOpen);
  const [sessions, setSessions] = useState<SessionSummaryItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [botFilter, setBotFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [selectedBot, setSelectedBot] = useState<string>(initialBot || "");
  const [meta, setMeta] = useState<ModelsResponse | null>(null);
  const [selectedProject, setSelectedProject] = useState<string>(initialProject || "");
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [selectedEffort, setSelectedEffort] = useState<string>("");

  // Admin-only Web -> TG DM mirror toggle (browser-persisted, default true)
  const [syncTg, setSyncTg] = useState<boolean>(() => {
    try {
      const saved = window.localStorage.getItem(SYNC_TG_STORAGE_KEY);
      if (saved === "false") return false;
      if (saved === "true") return true;
    } catch {
      // Ignore storage access failures
    }
    return true;
  });

  const [activeCid, setActiveCid] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [expandedThinking, setExpandedThinking] = useState<Record<string, boolean>>({});

  const [draft, setDraft] = useState("");
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [streamDegraded, setStreamDegraded] = useState(false);
  const [remoteSyncSource, setRemoteSyncSource] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [resyncNeeded, setResyncNeeded] = useState(false);

  const mountedRef = useRef(true);
  const esRef = useRef<EventSource | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const activeAssistantIdRef = useRef<string | null>(null);
  const genRef = useRef<number>(0);
  const activeCidRef = useRef<string | null>(null);
  const selectedBotRef = useRef<string>(selectedBot);
  selectedBotRef.current = selectedBot;
  const streamingRef = useRef<boolean>(false);
  const streamingSourceRef = useRef<"local" | "remote" | null>(null);
  const activeTurnIdRef = useRef<string | null>(null);
  const attachInFlightRef = useRef<string | null>(null);
  const lastSyncVerRef = useRef<number>(0);
  const historyLoadSeqRef = useRef<number>(0);
  const sessionsSeqRef = useRef<number>(0);
  const modelsSeqRef = useRef<number>(0);
  const botsSeqRef = useRef<number>(0);
  const consumedQuoteIdRef = useRef<number>(0);
  const degradePollRef = useRef<number | null>(null);
  const onBotChangeRef = useRef(onBotChange);
  onBotChangeRef.current = onBotChange;
  const onProjectChangeRef = useRef(onProjectChange);
  onProjectChangeRef.current = onProjectChange;
  const onQuoteConsumedRef = useRef(onQuoteConsumed);
  onQuoteConsumedRef.current = onQuoteConsumed;

  const setActiveCidSynced = useCallback(
    (cid: string | null) => {
      activeCidRef.current = cid;
      setActiveCid(cid);
      onActiveCidChange?.(cid);
    },
    [onActiveCidChange],
  );

  useEffect(() => {
    if (initialProject !== undefined && initialProject !== selectedProject && !streamingRef.current) {
      setSelectedProject(initialProject);
    }
  }, [initialProject, selectedProject]);

  useEffect(() => {
    if (!pendingQuote || pendingQuote.id === consumedQuoteIdRef.current) return;
    consumedQuoteIdRef.current = pendingQuote.id;
    const snippet = pendingQuote.text;
    if (snippet) {
      setDraft((prev) => (prev.trim() ? `${prev}\n\n${snippet}` : snippet));
    }
    onQuoteConsumedRef.current?.(pendingQuote.id);
  }, [pendingQuote]);

  const stopDegradePoll = useCallback(() => {
    if (degradePollRef.current !== null) {
      window.clearInterval(degradePollRef.current);
      degradePollRef.current = null;
    }
  }, []);

  const closeEventSource = useCallback(() => {
    stopDegradePoll();
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    releaseStreamSlot();
  }, [stopDegradePoll, releaseStreamSlot]);

  const closeEventSourceRef = useRef(closeEventSource);
  closeEventSourceRef.current = closeEventSource;

  const resetStreamState = useCallback(() => {
    closeEventSource();
    streamingRef.current = false;
    streamingSourceRef.current = null;
    activeTurnIdRef.current = null;
    if (mountedRef.current) {
      setStreaming(false);
      setStreamDegraded(false);
      setActiveTurnId(null);
      setRemoteSyncSource(null);
    }
  }, [closeEventSource]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      closeEventSourceRef.current();
    };
  }, []);

  useEffect(() => {
    const activePaneId = paneId;
    return () => {
      stopDegradePoll();
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      releaseStreamSlotById(activePaneId);
    };
  }, [paneId, stopDegradePoll]);

  const handleToggleSyncTg = () => {
    if (isReadonly) return;
    setSyncTg((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(SYNC_TG_STORAGE_KEY, next ? "true" : "false");
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  };

  const handleApiAuthError = useCallback(
    (err: unknown) => {
      if (err instanceof StudioApiError && (err.status === 401 || err.status === 403)) {
        if (err.source === "studio_auth") {
          onSessionRevoked(err.message || "会话已失效，请重新登录");
          return true;
        }
      }
      return false;
    },
    [onSessionRevoked],
  );

  useEffect(() => {
    const seq = ++botsSeqRef.current;
    void fetchBots()
      .then((res) => {
        if (!mountedRef.current || botsSeqRef.current !== seq) return;
        setBots(res.bots || []);
        setSelectedBot((cur) => {
          if (cur) return cur;
          const online = (res.bots || []).find((b) => b.online);
          const pick = online?.handle || res.bots?.[0]?.handle || "";
          if (pick) onBotChangeRef.current?.(pick);
          return pick;
        });
      })
      .catch((err) => {
        if (mountedRef.current && botsSeqRef.current === seq) {
          handleApiAuthError(err);
        }
      });
  }, [handleApiAuthError]);

  useEffect(() => {
    const seq = ++modelsSeqRef.current;
    const reqBot = selectedBot || "";
    void fetchModels(reqBot || undefined)
      .then((res) => {
        if (!mountedRef.current || modelsSeqRef.current !== seq || selectedBotRef.current !== reqBot) {
          return;
        }
        setMeta(res);
        setSelectedModel((cur) => cur || res.active_model || "");
        setSelectedProject((cur) => {
          const next = cur || res.default_project || "";
          if (!cur && next) onProjectChangeRef.current?.(next);
          return next;
        });
      })
      .catch((err) => {
        if (mountedRef.current && modelsSeqRef.current === seq) {
          handleApiAuthError(err);
        }
      });
  }, [selectedBot, handleApiAuthError]);

  const loadSessions = useCallback(async () => {
    const seq = ++sessionsSeqRef.current;
    setSessionsLoading(true);
    try {
      const res = await fetchSessions({
        limit: 50,
        bot: botFilter || undefined,
        source: sourceFilter,
        q: searchQuery || undefined,
      });
      if (!mountedRef.current || sessionsSeqRef.current !== seq) return;
      setSessions(res.sessions || []);
    } catch (err) {
      if (!mountedRef.current || sessionsSeqRef.current !== seq) return;
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "加载会话列表失败");
      }
    } finally {
      if (mountedRef.current && sessionsSeqRef.current === seq) {
        setSessionsLoading(false);
      }
    }
  }, [botFilter, sourceFilter, searchQuery, handleApiAuthError]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadSessions();
    }, 150);
    return () => window.clearTimeout(timer);
  }, [loadSessions]);

  const loadSessionHistory = useCallback(
    async (
      cid: string,
      beforeCursor?: number | null,
      opts?: { expectedGen?: number; silent?: boolean },
    ) => {
      const reqGen = opts?.expectedGen ?? genRef.current;
      let loadSeq = 0;
      if (!opts?.silent) {
        historyLoadSeqRef.current += 1;
        loadSeq = historyLoadSeqRef.current;
        setHistoryLoading(true);
        setErrorBanner(null);
        setResyncNeeded(false);
      }
      try {
        const res = await fetchSessionMessages(cid, {
          limit: 40,
          before: beforeCursor ?? undefined,
        });
        if (!mountedRef.current) return;
        if (genRef.current !== reqGen || activeCidRef.current !== cid || (!beforeCursor && streamingRef.current)) {
          return;
        }
        setHasMoreHistory(Boolean(res.has_more));
        setNextBefore(res.next_before ?? null);
        if (beforeCursor) {
          setMessages((prev) => [...(res.messages || []), ...prev]);
        } else {
          setMessages(res.messages || []);
          window.setTimeout(() => {
            if (
              mountedRef.current &&
              genRef.current === reqGen &&
              activeCidRef.current === cid &&
              !streamingRef.current
            ) {
              timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
            }
          }, 40);
        }
      } catch (err) {
        if (!mountedRef.current || genRef.current !== reqGen || activeCidRef.current !== cid) {
          return;
        }
        if (!handleApiAuthError(err) && !opts?.silent) {
          setErrorBanner(err instanceof Error ? err.message : "加载历史消息失败");
        }
      } finally {
        if (mountedRef.current && !opts?.silent && historyLoadSeqRef.current === loadSeq) {
          setHistoryLoading(false);
        }
      }
    },
    [handleApiAuthError],
  );

  const updateAssistantBubble = useCallback(
    (updater: (msg: ChatMessageItem) => ChatMessageItem) => {
      const targetId = activeAssistantIdRef.current;
      if (!targetId || !mountedRef.current) return;
      setMessages((prev) => prev.map((m) => (m.id === targetId ? updater(m) : m)));
    },
    [],
  );

  const attachStream = useCallback(
    (turnId: string, botHandle: string, streamGen: number, mode: "local" | "remote") => {
      closeEventSource();

      if (!acquireStreamSlot()) {
        setStreamDegraded(true);
        setStatusNotice("并发流已达上限（3/3），自动降级为全局事件与历史同步…");
        degradePollRef.current = window.setInterval(() => {
          if (!mountedRef.current || genRef.current !== streamGen) {
            stopDegradePoll();
            return;
          }
          const cidNow = activeCidRef.current;
          if (!cidNow) return;
          void fetchActiveSessionTurn(cidNow, botHandle || undefined)
            .then((st) => {
              if (!mountedRef.current || genRef.current !== streamGen) return;
              if (!st.active) {
                resetStreamState();
                setStatusNotice(null);
                void loadSessions();
                void loadSessionHistory(cidNow, null, { expectedGen: streamGen, silent: true });
              }
            })
            .catch(() => {
              // Ignore transient poll errors
            });
        }, 2500);
        return;
      }

      setStreamDegraded(false);
      const qs = new URLSearchParams({ turn_id: turnId });
      if (botHandle) qs.set("bot", botHandle);
      const es = new EventSource(`/api/chat/stream?${qs.toString()}`);
      esRef.current = es;

      const isStale = () => !mountedRef.current || genRef.current !== streamGen || esRef.current !== es;

      const parseData = (ev: MessageEvent): Record<string, unknown> => {
        try {
          return JSON.parse(String(ev.data || "{}")) as Record<string, unknown>;
        } catch {
          return {};
        }
      };

      const finishAndAlign = (cidHint?: string | null) => {
        resetStreamState();
        if (!mountedRef.current) return;
        setStatusNotice(null);
        void loadSessions();
        const alignCid = cidHint || activeCidRef.current;
        if (mode === "remote" && alignCid && genRef.current === streamGen) {
          void loadSessionHistory(alignCid, null, { expectedGen: streamGen, silent: true });
        }
      };

      es.addEventListener("turn_start", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCidSynced(d.conversation_id);
        }
        setStatusNotice(mode === "remote" ? "TG 实时同步中…" : "正在思考与执行…");
      });

      es.addEventListener("init", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCidSynced(d.conversation_id);
        }
      });

      es.addEventListener("status", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.message === "string" && d.message) {
          setStatusNotice(d.message);
        }
      });

      es.addEventListener("thinking", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        updateAssistantBubble((m) => ({
          ...m,
          thinking: (m.thinking || "") + delta,
        }));
      });

      es.addEventListener("tool_use", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const tname = typeof d.tool_name === "string" ? d.tool_name : "tool";
        setStatusNotice(mode === "remote" ? `TG 同步 · 执行工具：${tname}` : `执行工具：${tname}`);
        updateAssistantBubble((m) => {
          const prevTools: ChatToolCall[] = [...(m.tool_calls || [])];
          prevTools.push({ name: tname, active: true });
          return { ...m, tool_calls: prevTools };
        });
      });

      es.addEventListener("tool_result", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const tname = typeof d.tool_name === "string" ? d.tool_name : "tool";
        const dur = typeof d.duration_seconds === "number" ? d.duration_seconds : null;
        updateAssistantBubble((m) => {
          const nextTools = (m.tool_calls || []).map((tc) =>
            tc.name === tname && tc.active ? { ...tc, active: false, duration_seconds: dur } : tc,
          );
          return { ...m, tool_calls: nextTools };
        });
      });

      es.addEventListener("text_delta", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        if (mode !== "remote") {
          setStatusNotice(null);
        }
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || "") + delta,
        }));
        timelineEndRef.current?.scrollIntoView({ behavior: "auto" });
      });

      es.addEventListener("done", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const resolvedCid =
          typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
        if (resolvedCid) {
          setActiveCidSynced(resolvedCid);
        }
        const finalResp = typeof d.response === "string" ? d.response : "";
        updateAssistantBubble((m) => ({
          ...m,
          content: m.content.trim() ? m.content : finalResp || "(无文本输出)",
          status: typeof d.status === "string" ? d.status : "DONE",
        }));
        finishAndAlign(resolvedCid);
      });

      es.addEventListener("aborted", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const partial = typeof d.partial_text === "string" ? d.partial_text : "";
        const resolvedCid =
          typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || partial) + "\n\n*[已停止生成]*",
          status: "ABORTED",
        }));
        finishAndAlign(resolvedCid);
      });

      es.addEventListener("error", (ev) => {
        if (isStale()) return;
        const mev = ev as MessageEvent;
        if (typeof mev.data === "string" && mev.data) {
          const d = parseData(mev);
          const msg = typeof d.error === "string" ? d.error : "对话执行出错";
          const resolvedCid =
            typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
          setErrorBanner(msg);
          updateAssistantBubble((m) => ({
            ...m,
            content: m.content || `⚠️ ${msg}`,
            status: "ERROR",
          }));
          finishAndAlign(resolvedCid);
        } else if (mode === "remote") {
          finishAndAlign(activeCidRef.current);
        }
      });

      es.addEventListener("resync_required", () => {
        if (isStale()) return;
        resetStreamState();
        const curCid = activeCidRef.current;
        if (curCid) {
          setStatusNotice(null);
          void loadSessionHistory(curCid, null, { expectedGen: streamGen, silent: true });
        } else {
          setResyncNeeded(true);
          setStatusNotice("事件流超出缓冲窗口，请重新同步历史记录。");
        }
      });

      es.addEventListener("auth_error", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const reason = typeof d.error === "string" ? d.error : "会话鉴权已失效";
        resetStreamState();
        onSessionRevoked(reason);
      });
    },
    [
      acquireStreamSlot,
      closeEventSource,
      loadSessionHistory,
      loadSessions,
      onSessionRevoked,
      resetStreamState,
      setActiveCidSynced,
      stopDegradePoll,
      updateAssistantBubble,
    ],
  );

  const probeAndAttachActiveTurn = useCallback(
    async (cid: string, botHint?: string) => {
      if (isReadonly || !cid || streamingRef.current) return;
      if (attachInFlightRef.current === cid) return;
      const reqGen = genRef.current;
      let expectedGen = reqGen;
      attachInFlightRef.current = cid;
      try {
        const res = await fetchActiveSessionTurn(cid, botHint || undefined);
        if (
          !mountedRef.current ||
          genRef.current !== reqGen ||
          activeCidRef.current !== cid ||
          streamingRef.current
        ) {
          return;
        }
        if (!res.active || !res.turn_id) {
          return;
        }
        if (activeTurnIdRef.current === res.turn_id) {
          return;
        }
        genRef.current += 1;
        const attachGen = genRef.current;
        expectedGen = attachGen;
        const src = res.source || "tg";
        const assistantMsgId = `remote-a-${res.turn_id}`;
        const userMsgId = `remote-u-${res.turn_id}`;
        activeAssistantIdRef.current = assistantMsgId;
        activeTurnIdRef.current = res.turn_id;
        streamingRef.current = true;
        streamingSourceRef.current = "remote";
        setActiveTurnId(res.turn_id);
        setStreaming(true);
        setRemoteSyncSource(src);
        setStatusNotice(src === "tg" ? "TG 实时同步中…" : "多端实时同步中…");

        const promptPreview = (res.prompt_preview || "").trim();
        setMessages((prev) => {
          const filtered = prev.filter((m) => m.id !== assistantMsgId && m.id !== userMsgId);
          const lastMsg = filtered[filtered.length - 1];
          const needUserBubble =
            Boolean(promptPreview) &&
            !(
              lastMsg &&
              lastMsg.role === "user" &&
              lastMsg.content.trim().startsWith(promptPreview.slice(0, 60))
            );
          const next: ChatMessageItem[] = [...filtered];
          if (needUserBubble) {
            next.push({ id: userMsgId, role: "user", content: promptPreview });
          }
          next.push({
            id: assistantMsgId,
            role: "assistant",
            content: "",
            thinking: "",
            tool_calls: [],
          });
          return next;
        });

        attachStream(res.turn_id, res.bot || botHint || selectedBot, attachGen, "remote");
      } catch (err) {
        if (!mountedRef.current || genRef.current !== expectedGen) return;
        handleApiAuthError(err);
      } finally {
        if (attachInFlightRef.current === cid) {
          attachInFlightRef.current = null;
        }
      }
    },
    [attachStream, handleApiAuthError, isReadonly, selectedBot],
  );

  // React to global `session_updated` / `resync_required` SSE signals from App
  useEffect(() => {
    if (!sessionSyncEvent || sessionSyncEvent.ver === lastSyncVerRef.current) {
      return;
    }
    lastSyncVerRef.current = sessionSyncEvent.ver;
    void loadSessions();

    const curCid = activeCidRef.current;
    if (!curCid) return;

    if (sessionSyncEvent.type === "resync_required") {
      if (!streamingRef.current) {
        const curGen = genRef.current;
        void loadSessionHistory(curCid, null, { expectedGen: curGen, silent: true }).then(() => {
          if (
            mountedRef.current &&
            !isReadonly &&
            genRef.current === curGen &&
            activeCidRef.current === curCid &&
            !streamingRef.current
          ) {
            void probeAndAttachActiveTurn(curCid, selectedBotRef.current || undefined);
          }
        });
      }
      return;
    }

    if (sessionSyncEvent.cid !== curCid) return;

    if (sessionSyncEvent.status === "running") {
      if (!isReadonly && !streamingRef.current) {
        void probeAndAttachActiveTurn(curCid, sessionSyncEvent.bot || undefined);
      }
    } else if (
      sessionSyncEvent.status === "done" ||
      sessionSyncEvent.status === "aborted" ||
      sessionSyncEvent.status === "error"
    ) {
      if (!streamingRef.current || streamingSourceRef.current === "remote" || streamDegraded) {
        if (streamingSourceRef.current === "remote" || streamDegraded) {
          resetStreamState();
          setStatusNotice(null);
        }
        void loadSessionHistory(curCid, null, { expectedGen: genRef.current, silent: true });
      }
    }
  }, [
    isReadonly,
    loadSessionHistory,
    loadSessions,
    probeAndAttachActiveTurn,
    resetStreamState,
    sessionSyncEvent,
    streamDegraded,
  ]);

  const handleSelectSession = (item: SessionSummaryItem) => {
    if (streamingRef.current && streamingSourceRef.current === "local") return;
    onFocusPane?.(paneId);
    genRef.current += 1;
    const nextGen = genRef.current;
    attachInFlightRef.current = null;
    resetStreamState();
    setActiveCidSynced(item.cid);
    setStatusNotice(null);
    setErrorBanner(null);
    void loadSessionHistory(item.cid, null, { expectedGen: nextGen }).then(() => {
      if (
        mountedRef.current &&
        !isReadonly &&
        item.busy &&
        genRef.current === nextGen &&
        activeCidRef.current === item.cid &&
        !streamingRef.current
      ) {
        void probeAndAttachActiveTurn(item.cid, item.bot || undefined);
      }
    });
  };

  const handleNewChat = () => {
    if (streamingRef.current && streamingSourceRef.current === "local") return;
    onFocusPane?.(paneId);
    genRef.current += 1;
    attachInFlightRef.current = null;
    resetStreamState();
    setActiveCidSynced(null);
    setMessages([]);
    setHasMoreHistory(false);
    setNextBefore(null);
    setStatusNotice(null);
    setErrorBanner(null);
    setResyncNeeded(false);
  };

  const handleSend = async () => {
    const text = draft.trim();
    if (!text || streamingRef.current || isReadonly) return;
    onFocusPane?.(paneId);

    genRef.current += 1;
    const sendGen = genRef.current;
    attachInFlightRef.current = null;
    setErrorBanner(null);
    setResyncNeeded(false);
    setDraft("");

    const userMsgId = `u-${Date.now()}`;
    const assistantMsgId = `a-${Date.now() + 1}`;
    activeAssistantIdRef.current = assistantMsgId;
    streamingRef.current = true;
    streamingSourceRef.current = "local";

    setMessages((prev) => [
      ...prev,
      { id: userMsgId, role: "user", content: text },
      { id: assistantMsgId, role: "assistant", content: "", thinking: "", tool_calls: [] },
    ]);
    setStreaming(true);
    setRemoteSyncSource(null);
    setStatusNotice("正在提交至 Bridge 队列…");

    try {
      const res = await sendChatTurn({
        bot: selectedBot || undefined,
        prompt: text,
        cid: activeCidRef.current || undefined,
        project: selectedProject || undefined,
        model: selectedModel || undefined,
        effort: selectedEffort || undefined,
        sync_tg: !isReadonly && syncTg,
      });
      if (!mountedRef.current || genRef.current !== sendGen) {
        resetStreamState();
        return;
      }
      activeTurnIdRef.current = res.turn_id;
      setActiveTurnId(res.turn_id);
      if (res.cid) setActiveCidSynced(res.cid);
      attachStream(res.turn_id, res.bot || selectedBot, sendGen, "local");
    } catch (err) {
      if (!mountedRef.current || genRef.current !== sendGen) {
        return;
      }
      resetStreamState();
      setStatusNotice(null);
      if (handleApiAuthError(err)) return;
      const errMsg =
        err instanceof StudioApiError && err.status === 409
          ? "当前会话正被占用（409 session_busy），请稍后再试或新建会话。"
          : err instanceof Error
            ? err.message
            : "发送消息失败";
      setErrorBanner(errMsg);
      setMessages((prev) => prev.filter((m) => m.id !== assistantMsgId));
    }
  };

  const handleAbort = async () => {
    if (!activeTurnId) return;
    setStatusNotice("正在请求停止当前轮次…");
    try {
      await abortChatTurn(activeTurnId, selectedBot || undefined);
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "停止任务失败");
      }
    }
  };

  const isLocalStreaming = streaming && !remoteSyncSource;

  return (
    <div
      className="flex-1 min-h-0 min-w-0 flex overflow-hidden bg-slate-950"
      onMouseDown={() => onFocusPane?.(paneId)}
    >
      {/* Left Collapsible Sessions Sidebar */}
      {sidebarOpen && (
        <aside
          className={`${
            compactHeader ? "w-48" : "w-64 lg:w-72"
          } shrink-0 border-r border-slate-800/90 bg-slate-900/50 flex flex-col min-h-0`}
        >
          <div className="p-2 border-b border-slate-800/80 space-y-1.5">
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={isLocalStreaming}
                onClick={handleNewChat}
                className="flex-1 inline-flex items-center justify-center gap-1 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium py-1.5 px-2 transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                新建对话
              </button>
              <button
                type="button"
                onClick={() => void loadSessions()}
                title="刷新会话列表"
                className="h-7 w-7 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${sessionsLoading ? "animate-spin" : ""}`} />
              </button>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="搜索会话…"
                className="w-full h-7 rounded-lg bg-slate-950 border border-slate-800 pl-7 pr-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="flex items-center gap-1">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                aria-label="来源筛选"
                className="flex-1 min-w-0 h-7 rounded-lg bg-slate-950 border border-slate-800 px-1.5 text-[11px] text-slate-300 focus:outline-none focus:border-sky-500"
              >
                <option value="all">全部</option>
                <option value="session">Web</option>
                <option value="tg">TG</option>
              </select>
              <select
                value={botFilter}
                onChange={(e) => setBotFilter(e.target.value)}
                aria-label="Bot 筛选"
                className="flex-1 min-w-0 h-7 rounded-lg bg-slate-950 border border-slate-800 px-1.5 text-[11px] text-slate-300 focus:outline-none focus:border-sky-500"
              >
                <option value="">全部 Bot</option>
                {bots.map((b) => (
                  <option key={b.handle} value={b.handle}>
                    {b.display_name || b.handle}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto p-1.5 space-y-1">
            {sessions.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-slate-500">
                {sessionsLoading ? "加载会话中…" : "暂无可恢复会话"}
              </div>
            ) : (
              sessions.map((item) => {
                const selected = activeCid === item.cid;
                return (
                  <button
                    key={item.cid}
                    type="button"
                    onClick={() => handleSelectSession(item)}
                    className={`w-full text-left rounded-lg px-2 py-1.5 transition-colors cursor-pointer border ${
                      selected
                        ? "bg-sky-500/15 border-sky-500/35 text-slate-100"
                        : "border-transparent hover:bg-slate-800/60 text-slate-300"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-medium truncate">
                        {item.title || item.cid.slice(0, 10)}
                      </span>
                      {item.busy && (
                        <span
                          title="会话正在其他终端运行"
                          className="shrink-0 inline-flex items-center gap-0.5 px-1 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px] font-medium"
                        >
                          <Lock className="w-2.5 h-2.5" />
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1 text-[10px] text-slate-500 font-mono">
                      <span>{item.cid.slice(0, 8)}</span>
                      {item.project_id && (
                        <span className="truncate text-slate-400">· {item.project_id}</span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </aside>
      )}

      {/* Main Conversation Stage */}
      <section className="flex-1 min-w-0 min-h-0 flex flex-col">
        <header className="shrink-0 min-h-10 px-2.5 py-1.5 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setSidebarOpen((v) => !v)}
            title={sidebarOpen ? "收起会话列表" : "展开会话列表"}
            className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer shrink-0"
          >
            <PanelLeft className="w-3.5 h-3.5" />
          </button>

          <div className="flex items-center gap-1.5 flex-wrap flex-1 min-w-0">
            <select
              value={selectedBot}
              onChange={(e) => {
                setSelectedBot(e.target.value);
                onBotChange?.(e.target.value);
              }}
              disabled={streaming}
              aria-label="选择 Bot"
              className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-32"
            >
              {bots.length === 0 && <option value="">默认 Bot</option>}
              {bots.map((b) => (
                <option key={b.handle} value={b.handle}>
                  {b.online ? "● " : "○ "}
                  {b.display_name || b.handle}
                </option>
              ))}
            </select>

            <select
              value={selectedProject}
              onChange={(e) => {
                setSelectedProject(e.target.value);
                onProjectChange?.(e.target.value);
              }}
              disabled={streaming}
              aria-label="选择项目"
              className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-32"
            >
              <option value="">默认项目</option>
              {(meta?.projects || []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id}
                </option>
              ))}
            </select>

            {!compactHeader && (
              <>
                <select
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  disabled={streaming}
                  aria-label="选择模型"
                  className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-40"
                >
                  <option value="">Bot 默认模型</option>
                  {(meta?.models || []).map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.label || m.id}
                    </option>
                  ))}
                </select>

                <select
                  value={selectedEffort}
                  onChange={(e) => setSelectedEffort(e.target.value)}
                  disabled={streaming}
                  aria-label="思考强度"
                  className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                >
                  <option value="">默认强度</option>
                  {(meta?.efforts || ["low", "medium", "high", "xhigh", "max"]).map((ef) => (
                    <option key={ef} value={ef}>
                      {ef}
                    </option>
                  ))}
                </select>
              </>
            )}
          </div>

          {/* Admin-only Web -> TG DM Mirror Toggle */}
          {!isReadonly && (
            <button
              type="button"
              role="switch"
              aria-checked={syncTg}
              aria-label="同步到 TG"
              onClick={handleToggleSyncTg}
              title="将 Web Studio 对话同步镜像到你的 Telegram 私聊并对齐活跃会话"
              className={`inline-flex items-center gap-1 h-7 px-2 rounded-md text-xs font-medium border transition-colors cursor-pointer shrink-0 ${
                syncTg
                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                  : "bg-slate-950/70 border-slate-800 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  syncTg ? "bg-emerald-400" : "bg-slate-500"
                }`}
              />
              <span>同步到 TG</span>
            </button>
          )}

          {extraHeaderActions}
        </header>

        {isReadonly && (
          <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 shrink-0" />
            <span>只读权限（readonly）：可浏览会话历史，发送与中止操作已禁用。</span>
          </div>
        )}

        {streamDegraded && (
          <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-[11px] text-amber-200">
            并发 SSE 预算已满（3/3），本栏自动降级为全局事件与终态历史同步。
          </div>
        )}

        {errorBanner && (
          <div className="shrink-0 px-3 py-1.5 border-b border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {errorBanner}
            </span>
            <button
              type="button"
              onClick={() => setErrorBanner(null)}
              className="text-rose-300 hover:text-rose-100 underline cursor-pointer shrink-0"
            >
              关闭
            </button>
          </div>
        )}

        {resyncNeeded && activeCid && (
          <div className="shrink-0 px-3 py-1.5 border-b border-sky-500/30 bg-sky-500/10 text-xs text-sky-200 flex items-center justify-between gap-2">
            <span>实时事件流超出缓冲窗口，可重新加载最新持久化历史。</span>
            <button
              type="button"
              onClick={() => void loadSessionHistory(activeCid)}
              className="px-2 py-0.5 rounded bg-sky-600 hover:bg-sky-500 text-white cursor-pointer"
            >
              重新同步
            </button>
          </div>
        )}

        <div className="flex-1 min-h-0 overflow-y-auto px-3.5 py-3 space-y-3">
          {hasMoreHistory && activeCid && (
            <div className="flex justify-center">
              <button
                type="button"
                disabled={historyLoading}
                onClick={() => void loadSessionHistory(activeCid, nextBefore)}
                className="px-3 py-1 rounded-full border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 cursor-pointer disabled:opacity-50"
              >
                {historyLoading ? "加载中…" : "加载更早消息"}
              </button>
            </div>
          )}

          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center py-8 px-4">
              <div className="h-10 w-10 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center text-sky-400 mb-2.5">
                <MessageSquare className="w-5 h-5" />
              </div>
              <h2 className="text-sm font-semibold text-slate-100">AGY Studio 对话栏</h2>
              <p className="text-xs text-slate-400 mt-1 max-w-sm">
                通过 Bridge Single-Writer IPC 直连 Bot，支持与 Telegram 私聊双向实时同步。
              </p>
            </div>
          ) : (
            messages.map((msg) => {
              const isUser = msg.role === "user";
              const thinkOpen = Boolean(expandedThinking[msg.id]);
              return (
                <div key={msg.id} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`max-w-[92%] md:max-w-[85%] rounded-2xl px-3.5 py-2.5 border ${
                      isUser
                        ? "bg-sky-600/20 border-sky-500/35 text-slate-100"
                        : "bg-slate-900/80 border-slate-800/90 text-slate-100"
                    }`}
                  >
                    {!isUser && (
                      <div className="flex items-center gap-1.5 mb-1.5 text-[11px] text-slate-400">
                        <Bot className="w-3.5 h-3.5 text-sky-400" />
                        <span>{selectedBot || "Assistant"}</span>
                        {msg.truncated && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                            已截断 (32 KiB)
                          </span>
                        )}
                      </div>
                    )}

                    {!isUser && msg.thinking && msg.thinking.trim() && (
                      <div className="mb-2 rounded-lg border border-slate-800 bg-slate-950/60">
                        <button
                          type="button"
                          onClick={() =>
                            setExpandedThinking((prev) => ({
                              ...prev,
                              [msg.id]: !prev[msg.id],
                            }))
                          }
                          className="w-full flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                        >
                          {thinkOpen ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                          <span>思考过程</span>
                        </button>
                        {thinkOpen && (
                          <div className="px-3 pb-2 text-xs text-slate-400 whitespace-pre-wrap break-words border-t border-slate-800/80 pt-2">
                            {msg.thinking}
                          </div>
                        )}
                      </div>
                    )}

                    {!isUser && msg.tool_calls && msg.tool_calls.length > 0 && (
                      <div className="mb-2 flex flex-wrap gap-1.5">
                        {msg.tool_calls.map((tc, idx) => (
                          <span
                            key={`${msg.id}-tc-${idx}`}
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                              tc.active
                                ? "border-sky-500/40 bg-sky-500/15 text-sky-300"
                                : "border-slate-700/80 bg-slate-950/70 text-slate-300"
                            }`}
                          >
                            {tc.active ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              <Wrench className="w-3 h-3 text-slate-400" />
                            )}
                            <span>{tc.name}</span>
                            {typeof tc.duration_seconds === "number" && (
                              <span className="text-slate-500">{tc.duration_seconds.toFixed(1)}s</span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}

                    {isUser ? (
                      <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                        {msg.content}
                      </div>
                    ) : msg.content ? (
                      <SafeMarkdown content={msg.content} />
                    ) : (
                      <div className="inline-flex items-center gap-2 text-xs text-slate-400">
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-400" />
                        <span>{statusNotice || "正在生成…"}</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
          <div ref={timelineEndRef} />
        </div>

        <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5">
          {streaming && (remoteSyncSource || statusNotice) && (
            <div className="mb-1.5 flex items-center gap-2 text-[11px] text-sky-300">
              <Loader2 className="w-3 h-3 animate-spin shrink-0" />
              {remoteSyncSource === "tg" && (
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 text-[10px] font-medium shrink-0">
                  TG 实时同步中
                </span>
              )}
              <span>{statusNotice || "正在实时同步…"}</span>
            </div>
          )}
          <div className="flex items-end gap-2">
            <textarea
              rows={2}
              value={draft}
              disabled={isReadonly || streaming}
              onFocus={() => onFocusPane?.(paneId)}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void handleSend();
                }
              }}
              placeholder={
                isReadonly
                  ? "只读角色已禁用输入"
                  : remoteSyncSource === "tg"
                    ? "TG 私聊实时同步中…"
                    : "输入指令或问题…（Enter 发送，Shift+Enter 换行）"
              }
              className="flex-1 resize-none rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 disabled:opacity-50"
            />
            {isLocalStreaming ? (
              <button
                type="button"
                onClick={() => void handleAbort()}
                className="h-10 px-3 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                停止
              </button>
            ) : (
              <button
                type="button"
                disabled={isReadonly || streaming || !draft.trim()}
                onClick={() => void handleSend()}
                className="h-10 px-3 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                发送
              </button>
            )}
          </div>
        </footer>
      </section>
    </div>
  );
}

export interface WorkspaceViewProps {
  session: StudioSession;
  compactMode: boolean;
  browserOwner: BrowserOwner;
  wsSessionEpoch: number;
  sessionSyncEvent?: SessionUpdatedEvent | null;
  roomEvent?: RoomLiveEvent | null;
  jobsEventVer: number;
  attentionEventVer: number;
  onClaimBrowserOwner: (next: BrowserOwner) => void;
  onToggleBrowserDrawer: () => void;
  onPendingAttentionCount?: (count: number) => void;
  onRoleChanged?: (role: "admin" | "readonly") => void;
  onSessionRevoked: (reason: string) => void;
}

export function WorkspaceView({
  session,
  compactMode,
  browserOwner,
  wsSessionEpoch,
  sessionSyncEvent,
  roomEvent,
  jobsEventVer,
  attentionEventVer,
  onClaimBrowserOwner,
  onToggleBrowserDrawer,
  onPendingAttentionCount,
  onRoleChanged,
  onSessionRevoked,
}: WorkspaceViewProps) {
  const isReadonly = session.role !== "admin";
  const { activeCount: activeChatStreams } = useStreamBudget();

  const [isDesktopViewport, setIsDesktopViewport] = useState<boolean>(() =>
    typeof window !== "undefined" ? window.innerWidth >= 768 : true,
  );
  const [layout, setLayout] = useState<WorkbenchLayoutPrefs>(() => loadWorkbenchPrefs());
  const [filesDrawerOpen, setFilesDrawerOpen] = useState(false);
  const [singlePaneCid, setSinglePaneCid] = useState<string | null>(null);
  const [jobsAttentionSubTab, setJobsAttentionSubTab] = useState<Record<string, "attention" | "jobs">>({});
  const [lastFocusedChatPaneId, setLastFocusedChatPaneId] = useState<string>("pane-1");
  const [quoteMap, setQuoteMap] = useState<Record<string, PendingQuotePayload | null>>({});
  const [handoffPendingPaneId, setHandoffPendingPaneId] = useState<string | null>(null);

  const quoteCounterRef = useRef(0);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    const onResize = () => {
      setIsDesktopViewport(window.innerWidth >= 768);
    };
    window.addEventListener("resize", onResize);
    return () => {
      mountedRef.current = false;
      window.removeEventListener("resize", onResize);
    };
  }, []);

  useEffect(() => {
    saveWorkbenchPrefs(layout);
  }, [layout]);

  const multiPaneEnabled = !compactMode && isDesktopViewport;
  const effectivePaneCount: 1 | 2 | 3 | 4 = multiPaneEnabled ? layout.paneCount : 1;
  const visiblePanes = layout.panes.slice(0, effectivePaneCount);

  useEffect(() => {
    if (!browserOwner.startsWith("pane:")) return;
    const ownerPaneId = browserOwner.slice("pane:".length);
    const stillVisibleBrowser = visiblePanes.some(
      (p) => p.id === ownerPaneId && p.kind === "browser",
    );
    if (!stillVisibleBrowser) {
      onClaimBrowserOwner("none");
    }
  }, [browserOwner, visiblePanes, onClaimBrowserOwner]);

  useEffect(() => {
    if (effectivePaneCount <= 1 || browserOwner !== "none" || handoffPendingPaneId) {
      return;
    }
    const firstVisibleBrowser = visiblePanes.find((p) => p.kind === "browser");
    if (firstVisibleBrowser) {
      onClaimBrowserOwner(`pane:${firstVisibleBrowser.id}`);
    }
  }, [effectivePaneCount, browserOwner, handoffPendingPaneId, visiblePanes, onClaimBrowserOwner]);

  useEffect(() => {
    if (!handoffPendingPaneId) return;
    const targetId = handoffPendingPaneId;
    const timer = window.setTimeout(() => {
      if (!mountedRef.current) return;
      onClaimBrowserOwner(`pane:${targetId}`);
      setHandoffPendingPaneId(null);
    }, 60);
    return () => window.clearTimeout(timer);
  }, [handoffPendingPaneId, onClaimBrowserOwner]);

  const handleSetPaneCount = (count: 1 | 2 | 3 | 4) => {
    setLayout((prev) => ({
      ...prev,
      paneCount: count,
      layoutMode: String(count) as "1" | "2" | "3" | "4",
    }));
    if (count > 1) {
      setFilesDrawerOpen(false);
    }
  };

  const updatePane = useCallback(
    (paneId: string, patch: Partial<WorkbenchPaneConfig>) => {
      setLayout((prev) => ({
        ...prev,
        panes: prev.panes.map((p) => (p.id === paneId ? { ...p, ...patch } : p)),
      }));
    },
    [],
  );

  const handleChangePaneKind = (paneId: string, nextKind: PaneKind) => {
    if (nextKind === "browser") {
      if (browserOwner === "none" || browserOwner === "drawer" || browserOwner === "tab") {
        onClaimBrowserOwner(`pane:${paneId}`);
      }
    } else if (browserOwner === `pane:${paneId}`) {
      onClaimBrowserOwner("none");
    }
    updatePane(paneId, {
      kind: nextKind,
      ...(nextKind === "room" ? { roomId: "lobby" } : {}),
    });
  };

  const handleTransferBrowserToPane = (targetPaneId: string) => {
    setLayout((prev) => ({
      ...prev,
      panes: prev.panes.map((p) =>
        p.id !== targetPaneId && p.kind === "browser" ? { ...p, kind: "chat" } : p,
      ),
    }));
    onClaimBrowserOwner("none");
    setHandoffPendingPaneId(targetPaneId);
  };

  const handleQuoteToActiveChat = useCallback(
    (snippet: string) => {
      if (isReadonly || !snippet) return;
      const visibleChats = visiblePanes.filter((p) => p.kind === "chat");
      const target =
        visibleChats.find((p) => p.id === lastFocusedChatPaneId) || visibleChats[0];
      if (!target) return;
      const nextId = ++quoteCounterRef.current;
      setQuoteMap((prev) => ({
        ...prev,
        [target.id]: { id: nextId, text: snippet },
      }));
    },
    [isReadonly, lastFocusedChatPaneId, visiblePanes],
  );

  const handleQuoteConsumed = useCallback((paneId: string, quoteId: number) => {
    setQuoteMap((prev) => {
      const cur = prev[paneId];
      if (!cur || cur.id !== quoteId) return prev;
      return { ...prev, [paneId]: null };
    });
  }, []);

  const primaryPane = visiblePanes[0];
  const browserDrawerOpen = browserOwner === "drawer";

  const gridClass =
    effectivePaneCount === 1
      ? "grid-cols-1 grid-rows-1"
      : effectivePaneCount === 2
        ? "grid-cols-2 grid-rows-1"
        : effectivePaneCount === 3
          ? "grid-cols-3 grid-rows-1"
          : "grid-cols-2 grid-rows-2";

  return (
    <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden bg-slate-950">
      {multiPaneEnabled && (
        <div className="shrink-0 h-9 px-3 border-b border-slate-800/90 bg-slate-900/90 flex items-center gap-2 text-xs">
          <span className="text-[11px] font-medium text-slate-400">工作台分屏</span>
          <div className="inline-flex items-center rounded-lg border border-slate-800 bg-slate-950 p-0.5 gap-0.5">
            {(
              [
                { count: 1, label: "1 栏", icon: Square },
                { count: 2, label: "2 栏", icon: Columns2 },
                { count: 3, label: "3 栏", icon: Columns3 },
                { count: 4, label: "4 栏", icon: Grid2x2 },
              ] as const
            ).map(({ count, label, icon: Icon }) => {
              const active = layout.paneCount === count;
              return (
                <button
                  key={count}
                  type="button"
                  onClick={() => handleSetPaneCount(count)}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] transition-colors cursor-pointer ${
                    active
                      ? "bg-sky-500/20 text-sky-300 font-medium"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/70"
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  <span>{label}</span>
                </button>
              );
            })}
          </div>

          <span
            title="客户端并发对话流预算（最多 3 条 /api/chat/stream SSE）"
            className="ml-2 px-1.5 py-0.5 rounded border border-slate-800 bg-slate-950 text-[10px] font-mono text-slate-400"
          >
            SSE {activeChatStreams}/{MAX_CLIENT_CHAT_STREAMS}
          </span>

          <div className="ml-auto flex items-center gap-1.5">
            {effectivePaneCount === 1 && primaryPane.kind === "chat" && (
              <button
                type="button"
                onClick={() => setFilesDrawerOpen((v) => !v)}
                className={`inline-flex items-center gap-1 h-6 px-2 rounded-md text-[11px] font-medium border transition-colors cursor-pointer ${
                  filesDrawerOpen
                    ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                    : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
                }`}
              >
                <FileCode className="w-3 h-3" />
                <span>{filesDrawerOpen ? "收起文件" : "文件/Diff"}</span>
              </button>
            )}

            <button
              type="button"
              onClick={onToggleBrowserDrawer}
              className={`inline-flex items-center gap-1 h-6 px-2 rounded-md text-[11px] font-medium border transition-colors cursor-pointer ${
                browserDrawerOpen
                  ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                  : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
              }`}
            >
              <Globe className="w-3 h-3" />
              <span>{browserDrawerOpen ? "收起浏览器抽屉" : "浏览器抽屉"}</span>
            </button>
          </div>
        </div>
      )}

      {effectivePaneCount === 1 ? (
        <div className="flex-1 min-h-0 min-w-0 flex overflow-hidden">
          <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden">
            <ChatPane
              paneId={primaryPane.id}
              session={session}
              initialBot={primaryPane.bot}
              initialProject={primaryPane.project}
              defaultSidebarOpen={!compactMode && isDesktopViewport}
              sessionSyncEvent={sessionSyncEvent}
              pendingQuote={quoteMap[primaryPane.id] || null}
              onQuoteConsumed={(qid) => handleQuoteConsumed(primaryPane.id, qid)}
              onBotChange={(bot) => updatePane(primaryPane.id, { bot })}
              onProjectChange={(project) => updatePane(primaryPane.id, { project })}
              onActiveCidChange={setSinglePaneCid}
              onFocusPane={setLastFocusedChatPaneId}
              extraHeaderActions={
                !multiPaneEnabled ? (
                  <button
                    type="button"
                    onClick={() => setFilesDrawerOpen((v) => !v)}
                    className={`inline-flex items-center gap-1 h-7 px-2 rounded-md text-xs font-medium border transition-colors cursor-pointer shrink-0 ${
                      filesDrawerOpen
                        ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                        : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>文件</span>
                  </button>
                ) : undefined
              }
              onSessionRevoked={onSessionRevoked}
            />
          </div>

          {filesDrawerOpen && (
            <aside className="w-full md:w-[400px] xl:w-[460px] shrink-0 border-l border-slate-800/90 bg-slate-950 flex flex-col min-h-0">
              <FilesDiffPanel
                session={session}
                selectedProject={primaryPane.project || undefined}
                selectedBot={primaryPane.bot || undefined}
                activeCid={singlePaneCid}
                onProjectChange={(pid) => updatePane(primaryPane.id, { project: pid })}
                onQuoteToChat={isReadonly ? undefined : handleQuoteToActiveChat}
                onClose={() => setFilesDrawerOpen(false)}
                onSessionRevoked={onSessionRevoked}
              />
            </aside>
          )}
        </div>
      ) : (
        <div className={`flex-1 min-h-0 min-w-0 grid ${gridClass} gap-px bg-slate-800/90 overflow-hidden`}>
          {visiblePanes.map((pane, idx) => {
            const subTab = jobsAttentionSubTab[pane.id] || "attention";
            const ownsBrowser = browserOwner === `pane:${pane.id}`;
            const otherBrowserOwner =
              pane.kind === "browser" && browserOwner !== "none" && !ownsBrowser;

            return (
              <div
                key={pane.id}
                className="min-h-0 min-w-0 flex flex-col bg-slate-950 overflow-hidden"
              >
                <div className="shrink-0 h-8 px-2 border-b border-slate-800/90 bg-slate-900/80 flex items-center gap-1.5 text-[11px]">
                  <span className="font-mono text-[10px] text-slate-500 px-1">#{idx + 1}</span>
                  <select
                    value={pane.kind}
                    onChange={(e) => handleChangePaneKind(pane.id, e.target.value as PaneKind)}
                    aria-label={`分栏 ${idx + 1} 视图类型`}
                    className="h-6 rounded bg-slate-950 border border-slate-800 px-1.5 text-[11px] text-slate-200 focus:outline-none focus:border-sky-500"
                  >
                    <option value="chat">对话 (Chat)</option>
                    <option value="room">群聊室 (Room)</option>
                    <option value="jobs_attention">审批 / 派工</option>
                    <option value="files">文件审查 (Files/Diff)</option>
                    <option value="browser">实时浏览器 (Browser)</option>
                  </select>

                  {pane.kind === "jobs_attention" && (
                    <div className="ml-auto inline-flex rounded border border-slate-800 bg-slate-950 p-0.5">
                      <button
                        type="button"
                        onClick={() =>
                          setJobsAttentionSubTab((prev) => ({ ...prev, [pane.id]: "attention" }))
                        }
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] cursor-pointer ${
                          subTab === "attention"
                            ? "bg-amber-500/20 text-amber-300"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        <Bell className="w-2.5 h-2.5" />
                        审批
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setJobsAttentionSubTab((prev) => ({ ...prev, [pane.id]: "jobs" }))
                        }
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] cursor-pointer ${
                          subTab === "jobs"
                            ? "bg-sky-500/20 text-sky-300"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        <Activity className="w-2.5 h-2.5" />
                        派工
                      </button>
                    </div>
                  )}

                  {pane.kind === "chat" && lastFocusedChatPaneId === pane.id && (
                    <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-sky-400">
                      <MessageSquare className="w-2.5 h-2.5" />
                      活跃对话
                    </span>
                  )}

                  {pane.kind === "room" && (
                    <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-emerald-400">
                      <Users className="w-2.5 h-2.5" />
                      #{pane.roomId || "lobby"}
                    </span>
                  )}
                </div>

                <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden">
                  {pane.kind === "chat" && (
                    <ChatPane
                      paneId={pane.id}
                      session={session}
                      initialBot={pane.bot}
                      initialProject={pane.project}
                      defaultSidebarOpen={false}
                      compactHeader
                      sessionSyncEvent={sessionSyncEvent}
                      pendingQuote={quoteMap[pane.id] || null}
                      onQuoteConsumed={(qid) => handleQuoteConsumed(pane.id, qid)}
                      onBotChange={(bot) => updatePane(pane.id, { bot })}
                      onProjectChange={(project) => updatePane(pane.id, { project })}
                      onFocusPane={setLastFocusedChatPaneId}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "room" && (
                    <RoomPanel
                      session={session}
                      initialRoomId={pane.roomId || "lobby"}
                      onRoomChange={(roomId) => updatePane(pane.id, { roomId })}
                      roomEvent={roomEvent}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "jobs_attention" &&
                    (subTab === "attention" ? (
                      <AttentionPanel
                        session={session}
                        eventVersion={attentionEventVer}
                        onOpenBrowser={() => handleChangePaneKind(pane.id, "browser")}
                        onPendingCountChange={onPendingAttentionCount}
                        onSessionRevoked={onSessionRevoked}
                      />
                    ) : (
                      <div className="flex-1 min-h-0 overflow-y-auto">
                        <JobsView
                          session={session}
                          eventVersion={jobsEventVer}
                          onSessionRevoked={onSessionRevoked}
                        />
                      </div>
                    ))}

                  {pane.kind === "files" && (
                    <FilesDiffPanel
                      session={session}
                      selectedProject={pane.project || undefined}
                      selectedBot={pane.bot || undefined}
                      onProjectChange={(pid) => updatePane(pane.id, { project: pid })}
                      onQuoteToChat={isReadonly ? undefined : handleQuoteToActiveChat}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "browser" &&
                    (ownsBrowser ? (
                      <BrowserView
                        key={`pane-${pane.id}-${wsSessionEpoch}`}
                        session={session}
                        compact={false}
                        variant="drawer"
                        onCloseDrawer={() => handleChangePaneKind(pane.id, "chat")}
                        onSessionRevoked={onSessionRevoked}
                        onRoleChanged={onRoleChanged}
                      />
                    ) : (
                      <div className="flex-1 min-h-0 flex flex-col items-center justify-center text-center p-6 space-y-3 bg-slate-950">
                        <div className="h-10 w-10 rounded-xl border border-amber-500/35 bg-amber-500/10 flex items-center justify-center text-amber-300">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div className="text-sm font-medium text-slate-100">
                          {handoffPendingPaneId
                            ? "正在移交实时浏览器连接…"
                            : otherBrowserOwner
                              ? "实时浏览器已由另一视图持有"
                              : "实时浏览器尚未在此栏激活"}
                        </div>
                        <p className="text-xs text-slate-400 max-w-xs">
                          同一会话仅允许单实例实时浏览器 WebSocket 连接（防双栏抢占接管）。
                        </p>
                        {!handoffPendingPaneId && (
                          <button
                            type="button"
                            onClick={() => handleTransferBrowserToPane(pane.id)}
                            className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium cursor-pointer"
                          >
                            {otherBrowserOwner ? "将浏览器移至此栏" : "在此栏启用浏览器"}
                          </button>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
