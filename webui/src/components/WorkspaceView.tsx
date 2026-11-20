import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronRight,
  Globe,
  Loader2,
  Lock,
  MessageSquare,
  PanelLeft,
  Plus,
  RefreshCw,
  Search,
  Send,
  Square,
  Wrench,
} from "lucide-react";
import {
  StudioApiError,
  abortChatTurn,
  fetchBots,
  fetchModels,
  fetchSessionMessages,
  fetchSessions,
  sendChatTurn,
} from "../api";
import type {
  BotRosterItem,
  ChatMessageItem,
  ChatToolCall,
  ModelsResponse,
  SessionSummaryItem,
  StudioSession,
} from "../types";
import { SafeMarkdown } from "./SafeMarkdown";

interface WorkspaceViewProps {
  session: StudioSession;
  browserDrawerOpen: boolean;
  onToggleBrowserDrawer: () => void;
  onSessionRevoked: (reason: string) => void;
}

export function WorkspaceView({
  session,
  browserDrawerOpen,
  onToggleBrowserDrawer,
  onSessionRevoked,
}: WorkspaceViewProps) {
  const isReadonly = session.role !== "admin";

  // Left session sidebar state
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sessions, setSessions] = useState<SessionSummaryItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [botFilter, setBotFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Bot / Project / Model / Effort selectors
  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [selectedBot, setSelectedBot] = useState<string>("");
  const [meta, setMeta] = useState<ModelsResponse | null>(null);
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [selectedEffort, setSelectedEffort] = useState<string>("");

  // Active conversation & timeline
  const [activeCid, setActiveCid] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [expandedThinking, setExpandedThinking] = useState<Record<string, boolean>>({});

  // Composer & active streaming turn
  const [draft, setDraft] = useState("");
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [resyncNeeded, setResyncNeeded] = useState(false);

  const esRef = useRef<EventSource | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const activeAssistantIdRef = useRef<string | null>(null);

  const closeEventSource = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      closeEventSource();
    };
  }, [closeEventSource]);

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

  // Load roster bots once
  useEffect(() => {
    let cancelled = false;
    void fetchBots()
      .then((res) => {
        if (cancelled) return;
        setBots(res.bots || []);
        setSelectedBot((cur) => {
          if (cur) return cur;
          const online = (res.bots || []).find((b) => b.online);
          return online?.handle || res.bots?.[0]?.handle || "";
        });
      })
      .catch((err) => {
        if (!cancelled) handleApiAuthError(err);
      });
    return () => {
      cancelled = true;
    };
  }, [handleApiAuthError]);

  // Load models/projects when target bot changes
  useEffect(() => {
    let cancelled = false;
    void fetchModels(selectedBot || undefined)
      .then((res) => {
        if (cancelled) return;
        setMeta(res);
        setSelectedModel((cur) => cur || res.active_model || "");
        setSelectedProject((cur) => cur || res.default_project || "");
      })
      .catch((err) => {
        if (!cancelled) handleApiAuthError(err);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedBot, handleApiAuthError]);

  const loadSessions = useCallback(async () => {
    setSessionsLoading(true);
    try {
      const res = await fetchSessions({
        limit: 50,
        bot: botFilter || undefined,
        source: sourceFilter,
        q: searchQuery || undefined,
      });
      setSessions(res.sessions || []);
    } catch (err) {
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "加载会话列表失败");
      }
    } finally {
      setSessionsLoading(false);
    }
  }, [botFilter, sourceFilter, searchQuery, handleApiAuthError]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadSessions();
    }, 150);
    return () => window.clearTimeout(timer);
  }, [loadSessions]);

  const loadSessionHistory = useCallback(
    async (cid: string, beforeCursor?: number | null) => {
      setHistoryLoading(true);
      setErrorBanner(null);
      setResyncNeeded(false);
      try {
        const res = await fetchSessionMessages(cid, {
          limit: 40,
          before: beforeCursor ?? undefined,
        });
        setHasMoreHistory(Boolean(res.has_more));
        setNextBefore(res.next_before ?? null);
        if (beforeCursor) {
          setMessages((prev) => [...(res.messages || []), ...prev]);
        } else {
          setMessages(res.messages || []);
          window.setTimeout(() => {
            timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
          }, 40);
        }
      } catch (err) {
        if (!handleApiAuthError(err)) {
          setErrorBanner(err instanceof Error ? err.message : "加载历史消息失败");
        }
      } finally {
        setHistoryLoading(false);
      }
    },
    [handleApiAuthError],
  );

  const handleSelectSession = (item: SessionSummaryItem) => {
    if (streaming) return;
    closeEventSource();
    setActiveCid(item.cid);
    setStatusNotice(null);
    setErrorBanner(null);
    void loadSessionHistory(item.cid);
  };

  const handleNewChat = () => {
    if (streaming) return;
    closeEventSource();
    setActiveCid(null);
    setMessages([]);
    setHasMoreHistory(false);
    setNextBefore(null);
    setStatusNotice(null);
    setErrorBanner(null);
    setResyncNeeded(false);
  };

  const updateAssistantBubble = useCallback(
    (updater: (msg: ChatMessageItem) => ChatMessageItem) => {
      const targetId = activeAssistantIdRef.current;
      if (!targetId) return;
      setMessages((prev) =>
        prev.map((m) => (m.id === targetId ? updater(m) : m)),
      );
    },
    [],
  );

  const attachStream = useCallback(
    (turnId: string, botHandle: string) => {
      closeEventSource();
      const qs = new URLSearchParams({ turn_id: turnId });
      if (botHandle) qs.set("bot", botHandle);
      const es = new EventSource(`/api/chat/stream?${qs.toString()}`);
      esRef.current = es;

      const parseData = (ev: MessageEvent): Record<string, unknown> => {
        try {
          return JSON.parse(String(ev.data || "{}")) as Record<string, unknown>;
        } catch {
          return {};
        }
      };

      es.addEventListener("turn_start", (ev) => {
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCid(d.conversation_id);
        }
        setStatusNotice("正在思考与执行…");
      });

      es.addEventListener("init", (ev) => {
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCid(d.conversation_id);
        }
      });

      es.addEventListener("status", (ev) => {
        const d = parseData(ev as MessageEvent);
        if (typeof d.message === "string" && d.message) {
          setStatusNotice(d.message);
        }
      });

      es.addEventListener("thinking", (ev) => {
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        updateAssistantBubble((m) => ({
          ...m,
          thinking: (m.thinking || "") + delta,
        }));
      });

      es.addEventListener("tool_use", (ev) => {
        const d = parseData(ev as MessageEvent);
        const tname = typeof d.tool_name === "string" ? d.tool_name : "tool";
        setStatusNotice(`执行工具：${tname}`);
        updateAssistantBubble((m) => {
          const prevTools: ChatToolCall[] = [...(m.tool_calls || [])];
          prevTools.push({ name: tname, active: true });
          return { ...m, tool_calls: prevTools };
        });
      });

      es.addEventListener("tool_result", (ev) => {
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
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        setStatusNotice(null);
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || "") + delta,
        }));
        timelineEndRef.current?.scrollIntoView({ behavior: "auto" });
      });

      es.addEventListener("done", (ev) => {
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCid(d.conversation_id);
        }
        const finalResp = typeof d.response === "string" ? d.response : "";
        updateAssistantBubble((m) => ({
          ...m,
          content: m.content.trim() ? m.content : finalResp || "(无文本输出)",
          status: typeof d.status === "string" ? d.status : "DONE",
        }));
        setStreaming(false);
        setActiveTurnId(null);
        setStatusNotice(null);
        closeEventSource();
        void loadSessions();
      });

      es.addEventListener("aborted", (ev) => {
        const d = parseData(ev as MessageEvent);
        const partial = typeof d.partial_text === "string" ? d.partial_text : "";
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || partial) + "\n\n*[已停止生成]*",
          status: "ABORTED",
        }));
        setStreaming(false);
        setActiveTurnId(null);
        setStatusNotice(null);
        closeEventSource();
        void loadSessions();
      });

      es.addEventListener("error", (ev) => {
        const mev = ev as MessageEvent;
        if (typeof mev.data === "string" && mev.data) {
          const d = parseData(mev);
          const msg = typeof d.error === "string" ? d.error : "对话执行出错";
          setErrorBanner(msg);
          updateAssistantBubble((m) => ({
            ...m,
            content: m.content || `⚠️ ${msg}`,
            status: "ERROR",
          }));
          setStreaming(false);
          setActiveTurnId(null);
          setStatusNotice(null);
          closeEventSource();
        }
      });

      es.addEventListener("resync_required", () => {
        setResyncNeeded(true);
        setStreaming(false);
        setActiveTurnId(null);
        setStatusNotice("事件流超出缓冲窗口，请重新同步历史记录。");
        closeEventSource();
      });

      es.addEventListener("auth_error", (ev) => {
        const d = parseData(ev as MessageEvent);
        const reason = typeof d.error === "string" ? d.error : "会话鉴权已失效";
        setStreaming(false);
        setActiveTurnId(null);
        closeEventSource();
        onSessionRevoked(reason);
      });
    },
    [closeEventSource, loadSessions, onSessionRevoked, updateAssistantBubble],
  );

  const handleSend = async () => {
    const text = draft.trim();
    if (!text || streaming || isReadonly) return;

    setErrorBanner(null);
    setResyncNeeded(false);
    setDraft("");

    const userMsgId = `u-${Date.now()}`;
    const assistantMsgId = `a-${Date.now() + 1}`;
    activeAssistantIdRef.current = assistantMsgId;

    setMessages((prev) => [
      ...prev,
      { id: userMsgId, role: "user", content: text },
      { id: assistantMsgId, role: "assistant", content: "", thinking: "", tool_calls: [] },
    ]);
    setStreaming(true);
    setStatusNotice("正在提交至 Bridge 队列…");

    try {
      const res = await sendChatTurn({
        bot: selectedBot || undefined,
        prompt: text,
        cid: activeCid || undefined,
        project: selectedProject || undefined,
        model: selectedModel || undefined,
        effort: selectedEffort || undefined,
      });
      setActiveTurnId(res.turn_id);
      if (res.cid) setActiveCid(res.cid);
      attachStream(res.turn_id, res.bot || selectedBot);
    } catch (err) {
      setStreaming(false);
      setActiveTurnId(null);
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
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "停止任务失败");
      }
    }
  };

  return (
    <div className="flex-1 min-h-0 flex overflow-hidden bg-slate-950">
      {/* Left Collapsible Sessions Sidebar */}
      {sidebarOpen && (
        <aside className="w-64 lg:w-72 shrink-0 border-r border-slate-800/90 bg-slate-900/50 flex flex-col min-h-0">
          <div className="p-2.5 border-b border-slate-800/80 space-y-2">
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                disabled={streaming}
                onClick={handleNewChat}
                className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium py-1.5 px-2.5 transition-colors cursor-pointer"
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
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="搜索会话标题或 ID…"
                className="w-full h-7 rounded-lg bg-slate-950 border border-slate-800 pl-8 pr-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                aria-label="来源筛选"
                className="flex-1 h-7 rounded-lg bg-slate-950 border border-slate-800 px-2 text-[11px] text-slate-300 focus:outline-none focus:border-sky-500"
              >
                <option value="all">全部来源</option>
                <option value="session">Web / 会话</option>
                <option value="tg">Telegram</option>
              </select>
              <select
                value={botFilter}
                onChange={(e) => setBotFilter(e.target.value)}
                aria-label="Bot 筛选"
                className="flex-1 h-7 rounded-lg bg-slate-950 border border-slate-800 px-2 text-[11px] text-slate-300 focus:outline-none focus:border-sky-500"
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
              <div className="px-3 py-8 text-center text-xs text-slate-500">
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
                    className={`w-full text-left rounded-lg px-2.5 py-2 transition-colors cursor-pointer border ${
                      selected
                        ? "bg-sky-500/15 border-sky-500/35 text-slate-100"
                        : "border-transparent hover:bg-slate-800/60 text-slate-300"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="text-xs font-medium truncate">
                        {item.title || item.cid.slice(0, 10)}
                      </span>
                      {item.busy && (
                        <span
                          title="会话正在其他终端运行"
                          className="shrink-0 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px] font-medium"
                        >
                          <Lock className="w-2.5 h-2.5" />
                          占用中
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
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
        {/* Top Bar: Sidebar toggle + Bot/Project/Model/Effort + Browser Drawer toggle */}
        <header className="shrink-0 min-h-11 px-3 py-1.5 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setSidebarOpen((v) => !v)}
            title={sidebarOpen ? "收起会话列表" : "展开会话列表"}
            className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
          >
            <PanelLeft className="w-3.5 h-3.5" />
          </button>

          <div className="flex items-center gap-1.5 flex-wrap flex-1 min-w-0">
            <select
              value={selectedBot}
              onChange={(e) => setSelectedBot(e.target.value)}
              disabled={streaming}
              aria-label="选择 Bot"
              className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-36"
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
              onChange={(e) => setSelectedProject(e.target.value)}
              disabled={streaming}
              aria-label="选择项目"
              className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-36"
            >
              <option value="">默认项目</option>
              {(meta?.projects || []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name || p.id}
                </option>
              ))}
            </select>

            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              disabled={streaming}
              aria-label="选择模型"
              className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-44"
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
          </div>

          {/* Desktop Right-side Live-Browser Drawer Switch */}
          <button
            type="button"
            onClick={onToggleBrowserDrawer}
            className={`hidden md:inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md text-xs font-medium border transition-colors cursor-pointer shrink-0 ${
              browserDrawerOpen
                ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>{browserDrawerOpen ? "收起浏览器" : "实时浏览器"}</span>
          </button>
        </header>

        {/* Alerts & Readonly Banner */}
        {isReadonly && (
          <div className="shrink-0 px-4 py-2 border-b border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 shrink-0" />
            <span>当前为只读权限（readonly），可浏览会话历史与系统观测，发送消息和中断操作已禁用。</span>
          </div>
        )}

        {errorBanner && (
          <div className="shrink-0 px-4 py-2 border-b border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center justify-between gap-2">
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
          <div className="shrink-0 px-4 py-2 border-b border-sky-500/30 bg-sky-500/10 text-xs text-sky-200 flex items-center justify-between gap-2">
            <span>实时事件流超出缓冲窗口，可重新加载最新持久化历史。</span>
            <button
              type="button"
              onClick={() => void loadSessionHistory(activeCid)}
              className="px-2.5 py-1 rounded bg-sky-600 hover:bg-sky-500 text-white cursor-pointer"
            >
              重新同步历史
            </button>
          </div>
        )}

        {/* Streaming Message Timeline */}
        <div className="flex-1 min-h-0 overflow-y-auto px-4 py-4 space-y-4">
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
            <div className="h-full flex flex-col items-center justify-center text-center py-12 px-4">
              <div className="h-12 w-12 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center text-sky-400 mb-3">
                <MessageSquare className="w-6 h-6" />
              </div>
              <h2 className="text-base font-semibold text-slate-100">AGY Studio Workspace</h2>
              <p className="text-xs text-slate-400 mt-1.5 max-w-md">
                通过 Bridge Single-Writer IPC 安全直连 Bot 对话引擎。可直接在下方输入开启新对话，或在左侧点选历史会话无缝 /resume。
              </p>
            </div>
          ) : (
            messages.map((msg) => {
              const isUser = msg.role === "user";
              const thinkOpen = Boolean(expandedThinking[msg.id]);
              return (
                <div
                  key={msg.id}
                  className={`flex ${isUser ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[90%] md:max-w-[82%] rounded-2xl px-3.5 py-2.5 border ${
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

                    {/* Collapsible Thinking Block */}
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
                          <div className="px-3 pb-2.5 text-xs text-slate-400 whitespace-pre-wrap break-words border-t border-slate-800/80 pt-2">
                            {msg.thinking}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Tool Capsules */}
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
                              <span className="text-slate-500">
                                {tc.duration_seconds.toFixed(1)}s
                              </span>
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

        {/* Multi-line Composer */}
        <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-3">
          {statusNotice && streaming && (
            <div className="mb-2 flex items-center gap-1.5 text-[11px] text-sky-300">
              <Loader2 className="w-3 h-3 animate-spin" />
              <span>{statusNotice}</span>
            </div>
          )}
          <div className="flex items-end gap-2">
            <textarea
              rows={2}
              value={draft}
              disabled={isReadonly || streaming}
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
                  : "输入指令或问题…（Enter 发送，Shift+Enter 换行）"
              }
              className="flex-1 resize-none rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 disabled:opacity-50"
            />
            {streaming ? (
              <button
                type="button"
                onClick={() => void handleAbort()}
                className="h-10 px-3.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                停止
              </button>
            ) : (
              <button
                type="button"
                disabled={isReadonly || !draft.trim()}
                onClick={() => void handleSend()}
                className="h-10 px-3.5 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
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
