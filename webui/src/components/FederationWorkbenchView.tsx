import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  Bell,
  CheckCircle2,
  Clock,
  Inbox,
  Network,
  PanelRightClose,
  PanelRightOpen,
  Radio,
  RefreshCw,
  Send,
  ShieldAlert,
  Square,
  Terminal,
  X,
} from "lucide-react";
import {
  StudioApiError,
  cancelFederationWorkbenchJob,
  dispatchFederationWorkbenchJob,
  fetchFederationWorkbench,
  fetchFederationWorkbenchTimeline,
} from "../api";
import { SafeMarkdown } from "./SafeMarkdown";
import type {
  FederationHubConfig,
  FederationLeaderEventSummary,
  FederationPullInboxItem,
  FederationRuntimeStatus,
  FederationTimelineJobItem,
  FederationTimelineSource,
  FederationWorkbenchAgentItem,
  NavTab,
  StudioSession,
} from "../types";

interface FederationWorkbenchViewProps {
  session: StudioSession;
  federationEventVer?: number;
  jobsEventVer?: number;
  onNavigate?: (tab: NavTab) => void;
  onSessionRevoked?: (reason: string) => void;
}

type MobilePane = "agents" | "timeline" | "telemetry";

const POLL_ACTIVE_INTERVAL_MS = 4000;
const POLL_IDLE_INTERVAL_MS = 30000;

const HEARTBEAT_ACTION_LABELS: Record<string, string> = {
  peek: "peek",
  inbox: "inbox",
  claim: "claim",
  result: "result",
  events_ack: "events_ack",
  mcp: "mcp",
};

function formatHeartbeatLabel(
  lastHeartbeatAt?: number | null,
  lastHeartbeatAction?: string | null,
): string {
  if (
    typeof lastHeartbeatAt !== "number" ||
    !Number.isFinite(lastHeartbeatAt) ||
    lastHeartbeatAt <= 0
  ) {
    return "";
  }
  const deltaSec = Math.max(0, Math.floor(Date.now() / 1000 - lastHeartbeatAt));
  let agoText: string;
  if (deltaSec < 60) {
    agoText = `${deltaSec}s 前`;
  } else if (deltaSec < 3600) {
    agoText = `${Math.floor(deltaSec / 60)}m 前`;
  } else if (deltaSec < 86400) {
    agoText = `${Math.floor(deltaSec / 3600)}h 前`;
  } else {
    agoText = `${Math.floor(deltaSec / 86400)}d 前`;
  }
  const rawAct =
    typeof lastHeartbeatAction === "string" ? lastHeartbeatAction.trim().toLowerCase() : "";
  const safeAct = Object.prototype.hasOwnProperty.call(HEARTBEAT_ACTION_LABELS, rawAct)
    ? HEARTBEAT_ACTION_LABELS[rawAct]
    : "";
  return safeAct ? `心跳 ${agoText} · ${safeAct}` : `心跳 ${agoText}`;
}

function formatTs(ts?: number | null): string {
  if (!ts || !Number.isFinite(ts)) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

function formatElapsed(sec?: number | null): string {
  if (sec == null || !Number.isFinite(sec)) return "";
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${s}s`;
}

function runtimeStatusMeta(status: FederationRuntimeStatus): {
  label: string;
  dot: string;
  badge: string;
} {
  switch (status) {
    case "online":
      return {
        label: "在线",
        dot: "bg-emerald-400",
        badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
      };
    case "stale":
      return {
        label: "静默",
        dot: "bg-amber-400",
        badge: "bg-amber-500/15 text-amber-300 border-amber-500/30",
      };
    case "disabled":
      return {
        label: "已停用",
        dot: "bg-slate-500",
        badge: "bg-slate-800 text-slate-400 border-slate-700",
      };
    case "revoked":
      return {
        label: "已吊销",
        dot: "bg-rose-500",
        badge: "bg-rose-500/15 text-rose-300 border-rose-500/30",
      };
    default:
      return {
        label: "离线",
        dot: "bg-slate-500",
        badge: "bg-slate-800/80 text-slate-300 border-slate-700",
      };
  }
}

function sourceBadgeMeta(source: FederationTimelineSource): { label: string; cls: string } {
  switch (source) {
    case "studio":
      return { label: "Studio", cls: "bg-sky-500/15 text-sky-300 border-sky-500/30" };
    case "telegram":
      return { label: "Telegram", cls: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30" };
    case "bus":
      return { label: "Bus", cls: "bg-violet-500/15 text-violet-300 border-violet-500/30" };
    default:
      return { label: "Pull", cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" };
  }
}

function jobStatusBadge(status: string): { label: string; cls: string } {
  switch (status) {
    case "done":
      return { label: "已完成", cls: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" };
    case "running":
      return { label: "执行中", cls: "bg-sky-500/15 text-sky-300 border-sky-500/30" };
    case "claimed":
      return { label: "已认领", cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" };
    case "queued":
      return { label: "排队中", cls: "bg-amber-500/15 text-amber-300 border-amber-500/30" };
    case "cancelled":
      return { label: "已取消", cls: "bg-slate-700/60 text-slate-300 border-slate-600" };
    case "error":
      return { label: "错误", cls: "bg-rose-500/15 text-rose-300 border-rose-500/30" };
    default:
      return { label: status || "未知", cls: "bg-slate-800 text-slate-300 border-slate-700" };
  }
}

export function FederationWorkbenchView({
  session,
  federationEventVer = 0,
  jobsEventVer = 0,
  onNavigate,
  onSessionRevoked,
}: FederationWorkbenchViewProps) {
  const [agents, setAgents] = useState<FederationWorkbenchAgentItem[]>([]);
  const [hubConfig, setHubConfig] = useState<FederationHubConfig | null>(null);
  const [serverCanEdit, setServerCanEdit] = useState(session.role === "admin");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [timeline, setTimeline] = useState<FederationTimelineJobItem[]>([]);
  const [pullInbox, setPullInbox] = useState<FederationPullInboxItem[]>([]);
  const [leaderEvents, setLeaderEvents] = useState<FederationLeaderEventSummary[]>([]);
  const [hasActiveJobs, setHasActiveJobs] = useState(false);

  const [loadingList, setLoadingList] = useState(true);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [sending, setSending] = useState(false);
  const [cancellingJobId, setCancellingJobId] = useState<string | null>(null);
  const [promptInput, setPromptInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [showTelemetry, setShowTelemetry] = useState(true);
  const [mobilePane, setMobilePane] = useState<MobilePane>("timeline");

  const reqGenRef = useRef(0);
  const listGenRef = useRef(0);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);

  const canEdit = session.role === "admin" && serverCanEdit;

  const selectedAgent = useMemo(
    () => agents.find((a) => a.agent_id === selectedAgentId) || null,
    [agents, selectedAgentId],
  );

  const handleApiError = useCallback(
    (err: unknown, fallback: string) => {
      if (err instanceof StudioApiError) {
        if (
          err.status === 401 ||
          (err.status === 403 && err.source === "studio_auth" && err.message.includes("会话"))
        ) {
          onSessionRevoked?.(err.message);
        }
        setError(err.message || fallback);
        return;
      }
      setError(err instanceof Error ? err.message : fallback);
    },
    [onSessionRevoked],
  );

  const loadWorkbench = useCallback(
    async (silent = false) => {
      const gen = ++listGenRef.current;
      if (!silent) {
        setLoadingList(true);
      }
      try {
        const res = await fetchFederationWorkbench();
        if (gen !== listGenRef.current) return;
        setAgents(res.agents || []);
        setHubConfig(res.hub_config || null);
        setServerCanEdit(Boolean(res.can_edit));
        setSelectedAgentId((prev) => {
          if (prev && (res.agents || []).some((a) => a.agent_id === prev)) {
            return prev;
          }
          return res.agents?.[0]?.agent_id || "";
        });
      } catch (err) {
        if (gen !== listGenRef.current) return;
        handleApiError(err, "加载联邦工作台节点失败");
      } finally {
        if (gen === listGenRef.current) {
          setLoadingList(false);
        }
      }
    },
    [handleApiError],
  );

  const loadTimeline = useCallback(
    async (agentId: string, silent = false) => {
      const gen = ++reqGenRef.current;
      if (!agentId) {
        setTimeline([]);
        setPullInbox([]);
        setLeaderEvents([]);
        setHasActiveJobs(false);
        setLoadingTimeline(false);
        return;
      }
      if (!silent) {
        setLoadingTimeline(true);
      }
      try {
        const res = await fetchFederationWorkbenchTimeline(agentId, { limit: 100 });
        if (gen !== reqGenRef.current) return;
        setTimeline(res.timeline || []);
        setPullInbox(res.pull_inbox || []);
        setLeaderEvents(res.leader_events || []);
        setHasActiveJobs(Boolean(res.has_active_jobs));
        setServerCanEdit(Boolean(res.can_edit));
        if (res.agent) {
          setAgents((prev) =>
            prev.map((a) => (a.agent_id === res.agent.agent_id ? { ...a, ...res.agent } : a)),
          );
        }
      } catch (err) {
        if (gen !== reqGenRef.current) return;
        handleApiError(err, "加载联邦节点时间线失败");
      } finally {
        if (gen === reqGenRef.current) {
          setLoadingTimeline(false);
        }
      }
    },
    [handleApiError],
  );

  // Initial & SSE-triggered refresh
  useEffect(() => {
    void loadWorkbench(federationEventVer > 0 || jobsEventVer > 0);
  }, [loadWorkbench, federationEventVer, jobsEventVer]);

  useEffect(() => {
    if (!selectedAgentId) {
      reqGenRef.current += 1;
      setTimeline([]);
      setPullInbox([]);
      setLeaderEvents([]);
      setHasActiveJobs(false);
      return;
    }
    void loadTimeline(selectedAgentId, false);
  }, [selectedAgentId, loadTimeline]);

  useEffect(() => {
    if (!selectedAgentId || (federationEventVer === 0 && jobsEventVer === 0)) return;
    void loadTimeline(selectedAgentId, true);
  }, [selectedAgentId, federationEventVer, jobsEventVer, loadTimeline]);

  // Controlled lightweight polling ONLY while active jobs exist (cleaned up on unmount / idle)
  const anyActiveInRoster = useMemo(
    () =>
      hasActiveJobs ||
      agents.some(
        (a) =>
          (a.pull_queue_counts?.queued || 0) +
            (a.pull_queue_counts?.claimed || 0) +
            (a.bus_job_counts?.queued || 0) +
            (a.bus_job_counts?.running || 0) >
          0,
      ),
    [hasActiveJobs, agents],
  );

  // Single mutually-exclusive polling loop: 4s while active jobs exist (list + timeline),
  // 30s silent presence refresh while idle (list only); always cleared on unmount or transition.
  useEffect(() => {
    const intervalMs = anyActiveInRoster ? POLL_ACTIVE_INTERVAL_MS : POLL_IDLE_INTERVAL_MS;
    const timer = window.setInterval(() => {
      void loadWorkbench(true);
      if (anyActiveInRoster && selectedAgentId) {
        void loadTimeline(selectedAgentId, true);
      }
    }, intervalMs);
    return () => {
      window.clearInterval(timer);
    };
  }, [anyActiveInRoster, selectedAgentId, loadWorkbench, loadTimeline]);

  const handleSelectAgent = (agentId: string) => {
    if (agentId !== selectedAgentId) {
      setError(null);
      setNotice(null);
      setSelectedAgentId(agentId);
    }
    setMobilePane("timeline");
  };

  const handleDispatch = async () => {
    if (!canEdit || !selectedAgent || !selectedAgent.can_dispatch) return;
    const trimmed = promptInput.trim();
    if (!trimmed) return;
    setSending(true);
    setError(null);
    setNotice(null);
    try {
      const res = await dispatchFederationWorkbenchJob(selectedAgent.agent_id, {
        prompt: trimmed,
        label: labelInput.trim() || undefined,
      });
      setPromptInput("");
      setLabelInput("");
      setNotice(
        res.dispatch_mode === "pull"
          ? `已入队 Pull 任务 ${res.job.job_id}（外部节点将自动拉取）`
          : `已派发任务 ${res.job.job_id} 至 ${selectedAgent.agent_id}`,
      );
      await Promise.all([loadWorkbench(true), loadTimeline(selectedAgent.agent_id, true)]);
      window.setTimeout(() => {
        timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 60);
    } catch (err) {
      handleApiError(err, "派发任务失败");
    } finally {
      setSending(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    if (!canEdit || !selectedAgent) return;
    setCancellingJobId(jobId);
    setError(null);
    setNotice(null);
    try {
      const res = await cancelFederationWorkbenchJob(
        selectedAgent.agent_id,
        jobId,
        "cancelled_by_studio",
      );
      if (res.already_terminal) {
        setNotice(`任务 ${jobId} 已处于终态 (${res.status})，未修改结果`);
      } else {
        setNotice(`已取消任务 ${jobId}`);
      }
      await Promise.all([loadWorkbench(true), loadTimeline(selectedAgent.agent_id, true)]);
    } catch (err) {
      handleApiError(err, "取消任务失败");
    } finally {
      setCancellingJobId(null);
    }
  };

  const hubEndpointLabel =
    hubConfig?.public_url ||
    hubConfig?.mcp_url ||
    hubConfig?.loopback_mcp_url ||
    "未配置 Hub";

  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden bg-slate-950">
      {/* Top Bar */}
      <header className="shrink-0 h-12 px-3 md:px-4 border-b border-slate-800/90 bg-slate-900/75 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <Radio className="w-4 h-4 text-sky-400 shrink-0" />
          <h1 className="text-sm font-semibold text-slate-100 truncate">联邦工作台</h1>
          <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono border border-slate-700 bg-slate-950/70 text-slate-300 truncate max-w-[260px]">
            {hubConfig?.public_url ? "公网" : "回环"}: {hubEndpointLabel}
          </span>
          {anyActiveInRoster && (
            <span className="hidden md:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-sky-500/15 text-sky-300 border border-sky-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
              活跃任务轮询中
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {/* Mobile Pane Switcher */}
          <div className="flex md:hidden items-center rounded-lg border border-slate-800 bg-slate-950/80 p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setMobilePane("agents")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "agents" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              节点 ({agents.length})
            </button>
            <button
              type="button"
              onClick={() => setMobilePane("timeline")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "timeline" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              对话
            </button>
            <button
              type="button"
              onClick={() => setMobilePane("telemetry")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "telemetry" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              遥测
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              void loadWorkbench(false);
              if (selectedAgentId) void loadTimeline(selectedAgentId, false);
            }}
            disabled={loadingList || loadingTimeline}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2.5 py-1.5 text-xs text-slate-200 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${loadingList || loadingTimeline ? "animate-spin" : ""}`}
            />
            <span className="hidden sm:inline">刷新</span>
          </button>

          <button
            type="button"
            onClick={() => setShowTelemetry((v) => !v)}
            title={showTelemetry ? "收起遥测面板" : "展开遥测面板"}
            className="hidden lg:inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2.5 py-1.5 text-xs text-slate-300 cursor-pointer"
          >
            {showTelemetry ? (
              <PanelRightClose className="w-3.5 h-3.5" />
            ) : (
              <PanelRightOpen className="w-3.5 h-3.5" />
            )}
            <span>遥测</span>
          </button>

          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate("federation")}
              className="inline-flex items-center gap-1 rounded-lg border border-sky-500/35 bg-sky-500/15 hover:bg-sky-500/25 px-2.5 py-1.5 text-xs font-medium text-sky-200 cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">外部联邦设置</span>
            </button>
          )}
        </div>
      </header>

      {/* Main 3-Pane Responsive Body */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* Left Pane: External Agents Roster */}
        <aside
          className={`${
            mobilePane === "agents" ? "flex w-full" : "hidden"
          } md:flex md:w-72 shrink-0 flex-col border-r border-slate-800/90 bg-slate-900/40 min-h-0`}
        >
          <div className="px-3 py-2.5 border-b border-slate-800/80 flex items-center justify-between text-xs">
            <span className="font-medium text-slate-300">外部联邦节点 ({agents.length})</span>
            {!canEdit && (
              <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                只读
              </span>
            )}
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto p-2 space-y-1.5">
            {loadingList && agents.length === 0 ? (
              <div className="p-4 text-center text-xs text-slate-500">加载外部节点中…</div>
            ) : agents.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-800 p-4 text-center space-y-2.5">
                <div className="text-xs text-slate-400">尚未注册外部联邦 Agent</div>
                {onNavigate && (
                  <button
                    type="button"
                    onClick={() => onNavigate("federation")}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
                  >
                    <Network className="w-3.5 h-3.5" />
                    前往外部联邦设置注册
                  </button>
                )}
              </div>
            ) : (
              agents.map((ag) => {
                const stMeta = runtimeStatusMeta(ag.runtime_status);
                const active = ag.agent_id === selectedAgentId;
                const activeCount =
                  (ag.pull_queue_counts?.queued || 0) +
                  (ag.pull_queue_counts?.claimed || 0) +
                  (ag.bus_job_counts?.queued || 0) +
                  (ag.bus_job_counts?.running || 0);
                const hbLabel = formatHeartbeatLabel(
                  ag.last_heartbeat_at,
                  ag.last_heartbeat_action,
                );
                return (
                  <button
                    key={ag.agent_id}
                    type="button"
                    onClick={() => handleSelectAgent(ag.agent_id)}
                    className={`w-full text-left rounded-xl p-2.5 border transition-colors cursor-pointer space-y-1.5 ${
                      active
                        ? "bg-sky-500/15 border-sky-500/40"
                        : "bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/60"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${stMeta.dot}`} />
                        <span className="text-xs font-semibold text-slate-100 truncate">
                          {ag.display_name || ag.agent_id}
                        </span>
                      </div>
                      <span
                        className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] font-medium ${stMeta.badge}`}
                      >
                        {stMeta.label}
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-1 text-[11px] font-mono text-slate-400">
                      <span className="truncate">{ag.agent_id}</span>
                      <span className="shrink-0 px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {ag.adapter_type}
                      </span>
                    </div>

                    {hbLabel && (
                      <div
                        className={`text-[10px] font-mono truncate ${
                          ag.runtime_status === "online"
                            ? "text-emerald-300/90"
                            : ag.runtime_status === "stale"
                              ? "text-amber-300/90"
                              : "text-slate-400"
                        }`}
                        title={formatTs(ag.last_heartbeat_at)}
                      >
                        {hbLabel}
                      </div>
                    )}

                    <div className="flex items-center flex-wrap gap-1.5 text-[10px]">
                      <span className="px-1.5 py-0.5 rounded bg-slate-950/70 border border-slate-800 text-slate-300">
                        模式: {ag.dispatch_mode}
                      </span>
                      {activeCount > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 font-mono">
                          活跃 {activeCount}
                        </span>
                      )}
                      {ag.leader_events_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 font-mono">
                          事件 {ag.leader_events_count}
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </aside>

        {/* Center Pane: Cross-Source Timeline + Dispatch Composer */}
        <section
          className={`${
            mobilePane === "timeline" ? "flex" : "hidden"
          } md:flex flex-1 min-w-0 min-h-0 flex-col bg-slate-950`}
        >
          {/* Selected Agent Header */}
          {selectedAgent ? (
            <div className="shrink-0 px-4 py-2.5 border-b border-slate-800/80 bg-slate-900/40 flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-sky-400 shrink-0" />
                  <span className="text-sm font-semibold text-slate-100 truncate">
                    {selectedAgent.display_name || selectedAgent.agent_id}
                  </span>
                  <code className="text-[11px] text-slate-400 font-mono">
                    {selectedAgent.agent_id}
                  </code>
                  <span
                    className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${
                      runtimeStatusMeta(selectedAgent.runtime_status).badge
                    }`}
                  >
                    {runtimeStatusMeta(selectedAgent.runtime_status).label}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5 flex flex-wrap items-center gap-2">
                  <span>类型: {selectedAgent.adapter_type}</span>
                  <span>·</span>
                  <span>派单通道: {selectedAgent.dispatch_mode}</span>
                  <span>·</span>
                  <span>最近活跃: {formatTs(selectedAgent.last_activity_at)}</span>
                  {(() => {
                    const selectedHbLabel = formatHeartbeatLabel(
                      selectedAgent.last_heartbeat_at,
                      selectedAgent.last_heartbeat_action,
                    );
                    if (!selectedHbLabel) return null;
                    return (
                      <>
                        <span>·</span>
                        <span
                          className={`font-mono ${
                            selectedAgent.runtime_status === "online"
                              ? "text-emerald-300/90"
                              : selectedAgent.runtime_status === "stale"
                                ? "text-amber-300/90"
                                : "text-slate-400"
                          }`}
                          title={formatTs(selectedAgent.last_heartbeat_at)}
                        >
                          {selectedHbLabel}
                        </span>
                      </>
                    );
                  })()}
                </div>
              </div>
              <div className="text-[11px] font-mono text-slate-400">
                共 {timeline.length} 条去重记录
              </div>
            </div>
          ) : (
            <div className="shrink-0 px-4 py-2.5 border-b border-slate-800/80 bg-slate-900/40 text-xs text-slate-400">
              请在左侧选择一个外部联邦节点查看跨来源对话时间线
            </div>
          )}

          {/* Alerts */}
          <div className="shrink-0 px-4 pt-2 space-y-1.5">
            {!canEdit && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                当前账号为只读权限（readonly），仅可查看脱敏后的跨来源时间线与队列遥测，派单与取消操作已隐藏。
              </div>
            )}
            {error && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {error}
                </span>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="text-rose-300 hover:text-rose-100 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            {notice && (
              <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  {notice}
                </span>
                <button
                  type="button"
                  onClick={() => setNotice(null)}
                  className="text-emerald-300 hover:text-emerald-100 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {/* Timeline Messages Stream */}
          <div className="flex-1 min-h-0 overflow-y-auto px-4 py-3 space-y-3">
            {!selectedAgent ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                暂无选中的外部节点
              </div>
            ) : loadingTimeline && timeline.length === 0 ? (
              <div className="py-10 text-center text-xs text-slate-500">加载跨来源时间线中…</div>
            ) : timeline.length === 0 ? (
              <div className="py-10 text-center space-y-1.5">
                <div className="text-xs text-slate-400">该外部节点尚无派单或拉取执行记录</div>
                <div className="text-[11px] text-slate-500">
                  来自 Studio、Telegram、Bot Bus 与 Pull Queue 的任务会按 job_id 自动去重汇总于此。
                </div>
              </div>
            ) : (
              timeline.map((item) => {
                const srcMeta = sourceBadgeMeta(item.source);
                const stBadge = jobStatusBadge(item.status);
                const elapsedLabel = formatElapsed(item.elapsed_s);
                return (
                  <article
                    key={item.job_id}
                    className="rounded-xl border border-slate-800/90 bg-slate-900/50 overflow-hidden"
                  >
                    {/* Card Header */}
                    <div className="px-3.5 py-2 border-b border-slate-800/80 bg-slate-900/80 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                      <div className="flex items-center flex-wrap gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded border font-medium ${srcMeta.cls}`}>
                          {srcMeta.label}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border font-medium ${stBadge.cls}`}>
                          {stBadge.label}
                        </span>
                        {item.bridged && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                            桥接去重
                          </span>
                        )}
                        <code className="font-mono text-slate-400">{item.job_id}</code>
                        {item.label && (
                          <span className="text-slate-300 font-medium truncate max-w-[220px]">
                            · {item.label}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-slate-400">
                        {elapsedLabel && (
                          <span className="inline-flex items-center gap-1 font-mono text-[10px]">
                            <Clock className="w-3 h-3" />
                            {elapsedLabel}
                          </span>
                        )}
                        <span className="text-[10px]">{formatTs(item.created_at)}</span>
                        {canEdit && item.can_cancel && (
                          <button
                            type="button"
                            disabled={cancellingJobId === item.job_id}
                            onClick={() => void handleCancelJob(item.job_id)}
                            className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/15 hover:bg-rose-500/25 px-2 py-0.5 text-[10px] font-medium text-rose-200 cursor-pointer disabled:opacity-50"
                          >
                            <Square className="w-2.5 h-2.5" />
                            {cancellingJobId === item.job_id ? "取消中…" : "取消任务"}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Prompt */}
                    <div className="px-3.5 py-2.5 border-b border-slate-800/60 bg-slate-950/40">
                      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-400 mb-1">
                        指令 {item.from_actor ? `(${item.from_actor})` : ""}
                      </div>
                      <SafeMarkdown content={item.prompt || "(空指令)"} className="text-xs" />
                    </div>

                    {/* Response / Error / Active indicator */}
                    <div className="px-3.5 py-2.5">
                      {item.result_text ? (
                        <div>
                          <div className="text-[10px] font-semibold uppercase tracking-wide text-emerald-400/90 mb-1">
                            节点回复
                          </div>
                          <SafeMarkdown content={item.result_text} className="text-xs" />
                        </div>
                      ) : item.error || item.cancel_reason ? (
                        <div className="rounded-lg border border-rose-500/30 bg-rose-950/30 px-3 py-2 text-xs text-rose-200 whitespace-pre-wrap break-words">
                          {item.error || item.cancel_reason}
                        </div>
                      ) : item.is_active ? (
                        <div className="flex items-center gap-2 text-xs text-sky-300/90">
                          <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
                          <span>
                            {item.status === "queued"
                              ? "已入队，等待外部节点拉取/接单…"
                              : item.status === "claimed"
                                ? "外部 Pull Worker 已认领，执行中…"
                                : "外部节点正在执行中…"}
                          </span>
                        </div>
                      ) : (
                        <div className="text-xs text-slate-500">（无输出正文）</div>
                      )}
                    </div>
                  </article>
                );
              })
            )}
            <div ref={timelineEndRef} />
          </div>

          {/* Bottom Dispatch Composer (Admin Only) */}
          {canEdit && selectedAgent && (
            <div className="shrink-0 p-3 border-t border-slate-800/90 bg-slate-900/60 space-y-2">
              {!selectedAgent.can_dispatch ? (
                <div className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-xs text-slate-400">
                  当前节点不可直接派单：{selectedAgent.dispatch_disabled_reason || "不满足派单条件"}
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={labelInput}
                      onChange={(e) => setLabelInput(e.target.value)}
                      placeholder="可选任务标签（例如：健康巡检 / 报表生成）"
                      maxLength={120}
                      disabled={sending}
                      className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500/50"
                    />
                    <span className="text-[10px] font-mono text-slate-400 shrink-0">
                      通道: {selectedAgent.dispatch_mode === "pull" ? "PullQueue 直写" : "BotBus 推送"}
                    </span>
                  </div>
                  <div className="flex items-end gap-2">
                    <textarea
                      value={promptInput}
                      onChange={(e) => setPromptInput(e.target.value)}
                      onKeyDown={(e) => {
                        if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                          e.preventDefault();
                          void handleDispatch();
                        }
                      }}
                      rows={2}
                      disabled={sending}
                      placeholder={`向 ${selectedAgent.display_name || selectedAgent.agent_id} 发送指令（Ctrl/Cmd + Enter 派发）…`}
                      className="flex-1 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 resize-none focus:outline-none focus:border-sky-500/60"
                    />
                    <button
                      type="button"
                      disabled={sending || !promptInput.trim()}
                      onClick={() => void handleDispatch()}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-sky-600 hover:bg-sky-500 px-3.5 py-2 text-xs font-medium text-white cursor-pointer disabled:opacity-50 shrink-0"
                    >
                      <Send className="w-3.5 h-3.5" />
                      {sending ? "派发中…" : "派单"}
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </section>

        {/* Right Collapsible Pane: Pull Inbox & leader_events Telemetry */}
        <aside
          className={`${
            mobilePane === "telemetry"
              ? "flex w-full"
              : showTelemetry
                ? "hidden lg:flex lg:w-80"
                : "hidden"
          } shrink-0 flex-col border-l border-slate-800/90 bg-slate-900/40 min-h-0 overflow-y-auto`}
        >
          {/* Pull Inbox Section */}
          <div className="p-3 border-b border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Inbox className="w-3.5 h-3.5 text-cyan-400" />
                Pull Inbox 待拉取/在途 ({pullInbox.length})
              </span>
            </div>
            {pullInbox.length === 0 ? (
              <div className="text-[11px] text-slate-500 py-2">当前无待处理 Pull 队列任务</div>
            ) : (
              <div className="space-y-1.5">
                {pullInbox.map((pq) => (
                  <div
                    key={pq.job_id}
                    className="rounded-lg border border-slate-800 bg-slate-950/70 p-2 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-1 text-[10px]">
                      <code className="font-mono text-sky-300 truncate">{pq.job_id}</code>
                      <span
                        className={`px-1.5 py-0.2 rounded border ${jobStatusBadge(pq.status).cls}`}
                      >
                        {jobStatusBadge(pq.status).label}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-300 line-clamp-2 break-words">
                      {pq.prompt_preview || pq.label || "-"}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>{formatTs(pq.created_at)}</span>
                      {canEdit && pq.can_cancel && (
                        <button
                          type="button"
                          disabled={cancellingJobId === pq.job_id}
                          onClick={() => void handleCancelJob(pq.job_id)}
                          className="text-rose-300 hover:text-rose-200 cursor-pointer"
                        >
                          取消
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Leader Events Telemetry Section */}
          <div className="p-3 border-b border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Bell className="w-3.5 h-3.5 text-indigo-400" />
                Leader Events 摘要 ({leaderEvents.length})
              </span>
            </div>
            {leaderEvents.length === 0 ? (
              <div className="text-[11px] text-slate-500 py-2">暂无待消费的 leader_events</div>
            ) : (
              <div className="space-y-1.5">
                {leaderEvents.map((ev) => (
                  <div
                    key={ev.event_id}
                    className="rounded-lg border border-slate-800 bg-slate-950/70 p-2 space-y-1 text-[11px]"
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-mono text-indigo-300 text-[10px] truncate">
                        {ev.type} · {ev.event_id}
                      </span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {ev.status}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 flex flex-wrap gap-2">
                      <span>关联任务: {ev.jobs_count}</span>
                      {ev.team_id && <span>团队: {ev.team_id}</span>}
                      {ev.tainted && <span className="text-amber-300">tainted</span>}
                    </div>
                    {ev.job_ids.length > 0 && (
                      <div className="text-[10px] font-mono text-slate-500 truncate">
                        {ev.job_ids.join(", ")}
                      </div>
                    )}
                    <div className="text-[10px] text-slate-500">{formatTs(ev.created_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Hub Endpoint Info */}
          <div className="p-3 space-y-1.5 text-[11px]">
            <div className="text-xs font-semibold text-slate-300">Hub 接入信息</div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 space-y-1 font-mono text-[10px]">
              <div className="text-slate-400">
                公网 URL:{" "}
                <span className="text-emerald-300 break-all">
                  {hubConfig?.public_url || "未配置（回退本地回环）"}
                </span>
              </div>
              <div className="text-slate-400">
                MCP URL:{" "}
                <span className="text-sky-300 break-all">{hubConfig?.mcp_url || "-"}</span>
              </div>
              <div className="text-slate-500">
                回环探活: {hubConfig?.loopback_mcp_url || "-"}
              </div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
