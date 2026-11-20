import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  Send,
  X,
  XCircle,
} from "lucide-react";
import {
  StudioApiError,
  cancelJob,
  dispatchJobs,
  fetchBots,
  fetchJobDetail,
  fetchJobs,
  fetchModels,
  retryJob,
} from "../api";
import type {
  BotRosterItem,
  JobDetail,
  JobsResponse,
  ProjectOption,
  StudioSession,
} from "../types";
import { SafeMarkdown } from "./SafeMarkdown";

const STATUS_FILTERS = ["", "running", "queued", "done", "error", "cancelled"] as const;
const MAX_DISPATCH_BOTS = 6;

interface JobsViewProps {
  session: StudioSession;
  eventVersion?: number;
  onSessionRevoked: (reason: string) => void;
}

export function JobsView({
  session,
  eventVersion = 0,
  onSessionRevoked,
}: JobsViewProps) {
  const isAdmin = session.role === "admin";
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [data, setData] = useState<JobsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Detail drawer state
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [detail, setDetail] = useState<JobDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [actionBusyId, setActionBusyId] = useState<string | null>(null);

  // Dispatch modal state
  const [dispatchOpen, setDispatchOpen] = useState(false);
  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [selectedBots, setSelectedBots] = useState<string[]>([]);
  const [dispatchProject, setDispatchProject] = useState<string>("");
  const [dispatchLabel, setDispatchLabel] = useState<string>("");
  const [dispatchPrompt, setDispatchPrompt] = useState<string>("");
  const [dispatchBusy, setDispatchBusy] = useState(false);
  const [dispatchErr, setDispatchErr] = useState<string | null>(null);

  const handleAuthErr = useCallback(
    (err: unknown): boolean => {
      if (
        err instanceof StudioApiError &&
        (err.status === 401 || err.status === 403) &&
        err.source === "studio_auth"
      ) {
        onSessionRevoked(err.message || "会话已失效，请重新登录");
        return true;
      }
      return false;
    },
    [onSessionRevoked],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await fetchJobs({ limit: 50, status: statusFilter || undefined }));
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "加载派工流水失败");
      }
    } finally {
      setLoading(false);
    }
  }, [statusFilter, handleAuthErr]);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  const loadDetail = useCallback(
    async (jobId: string) => {
      setSelectedJobId(jobId);
      setDetailLoading(true);
      setDetailError(null);
      try {
        const res = await fetchJobDetail(jobId);
        setDetail(res.job);
      } catch (e) {
        if (!handleAuthErr(e)) {
          setDetailError(e instanceof Error ? e.message : "加载任务详情失败");
        }
      } finally {
        setDetailLoading(false);
      }
    },
    [handleAuthErr],
  );

  useEffect(() => {
    if (selectedJobId && eventVersion > 0) {
      void loadDetail(selectedJobId);
    }
  }, [selectedJobId, eventVersion, loadDetail]);

  const openDispatchModal = async () => {
    if (!isAdmin) return;
    setDispatchOpen(true);
    setDispatchErr(null);
    try {
      const [botsRes, modelsRes] = await Promise.all([fetchBots(), fetchModels()]);
      const onlineBots = (botsRes.bots || []).filter((b) => b.online);
      setBots(botsRes.bots || []);
      setProjects(modelsRes.projects || []);
      if (onlineBots.length > 0) {
        setSelectedBots((prev) => (prev.length > 0 ? prev : [onlineBots[0].handle]));
      }
    } catch (e) {
      if (!handleAuthErr(e)) {
        setDispatchErr(e instanceof Error ? e.message : "加载在线 Bot / 项目列表失败");
      }
    }
  };

  const toggleBotSelection = (handle: string) => {
    setSelectedBots((prev) => {
      if (prev.includes(handle)) {
        return prev.filter((h) => h !== handle);
      }
      if (prev.length >= MAX_DISPATCH_BOTS) {
        return prev;
      }
      return [...prev, handle];
    });
  };

  const handleSubmitDispatch = async () => {
    if (!isAdmin || dispatchBusy) return;
    setDispatchErr(null);
    if (selectedBots.length === 0) {
      setDispatchErr("请至少选择 1 个在线目标 Bot");
      return;
    }
    if (selectedBots.length > MAX_DISPATCH_BOTS) {
      setDispatchErr(`单次最多派发 ${MAX_DISPATCH_BOTS} 个任务`);
      return;
    }
    const cleanPrompt = dispatchPrompt.trim();
    if (!cleanPrompt) {
      setDispatchErr("任务指令 Prompt 不能为空");
      return;
    }
    setDispatchBusy(true);
    try {
      const assignments = selectedBots.map((bot) => ({
        bot,
        prompt: cleanPrompt,
        label: dispatchLabel.trim() || undefined,
        project: dispatchProject || undefined,
      }));
      const res = await dispatchJobs(
        assignments.length === 1 ? assignments[0] : { assignments },
      );
      setDispatchOpen(false);
      setDispatchLabel("");
      setDispatchPrompt("");
      setNotice(`已派发 ${res.jobs.length} 条任务（批次 ${res.group_id}）`);
      await load();
    } catch (e) {
      if (!handleAuthErr(e)) {
        setDispatchErr(e instanceof Error ? e.message : "派发任务失败");
      }
    } finally {
      setDispatchBusy(false);
    }
  };

  const handleCancel = async (jobId: string) => {
    if (!isAdmin || actionBusyId) return;
    setActionBusyId(jobId);
    setError(null);
    try {
      const res = await cancelJob(jobId);
      setNotice(
        res.already_terminal
          ? `任务 ${jobId} 已处于终态（${res.status}）`
          : `已发送取消请求：${jobId}（${res.status}）`,
      );
      await load();
      if (selectedJobId === jobId) {
        await loadDetail(jobId);
      }
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "取消任务失败");
      }
    } finally {
      setActionBusyId(null);
    }
  };

  const handleRetry = async (jobId: string) => {
    if (!isAdmin || actionBusyId) return;
    setActionBusyId(jobId);
    setError(null);
    try {
      const res = await retryJob(jobId);
      setNotice(`已重新入队：${res.job_id}（来自 ${jobId}）`);
      await load();
      if (selectedJobId === jobId) {
        await loadDetail(res.job_id);
      }
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "重试任务失败");
      }
    } finally {
      setActionBusyId(null);
    }
  };

  const onlineBots = bots.filter((b) => b.online);

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">派工单流水</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            点击任务查看脱敏详情 ·{" "}
            {isAdmin ? "管理员可派发、取消或重试任务" : "当前为只读模式（写操作已禁用）"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin ? (
            <button
              type="button"
              onClick={() => void openDispatchModal()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              派发新任务
            </button>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[11px] text-amber-300">
              <Lock className="w-3 h-3" />
              只读权限
            </span>
          )}
          <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900 p-0.5">
            {STATUS_FILTERS.map((st) => (
              <button
                key={st || "all"}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-md text-xs cursor-pointer ${
                  statusFilter === st
                    ? "bg-sky-600 text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {st || "全部"}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新
          </button>
        </div>
      </div>

      {notice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200 flex items-center justify-between gap-2">
          <span>{notice}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-emerald-300 hover:text-white cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </div>
      )}

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
        {!data || data.jobs.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-500">
            暂无匹配的派工单记录
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {data.jobs.map((j) => {
              const isActive = j.status === "queued" || j.status === "running";
              const isTerminal =
                j.status === "done" ||
                j.status === "error" ||
                j.status === "failed" ||
                j.status === "cancelled";
              const isSelected = selectedJobId === j.job_id;
              return (
                <div
                  key={j.job_id}
                  onClick={() => void loadDetail(j.job_id)}
                  className={`p-4 space-y-1.5 transition-colors cursor-pointer ${
                    isSelected ? "bg-sky-500/10" : "hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-[11px] text-slate-500">
                        {j.job_id}
                      </span>
                      <span className="text-sm font-medium text-slate-100 truncate">
                        {j.label || "未命名派工"}
                      </span>
                    </div>
                    <div
                      className="flex items-center gap-2 shrink-0"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {j.duration_sec !== null && (
                        <span className="text-[11px] font-mono text-slate-500">
                          {j.duration_sec}s
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${
                          j.status === "done"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : j.status === "running"
                              ? "bg-sky-500/15 text-sky-300"
                              : j.status === "error" || j.status === "failed"
                                ? "bg-rose-500/15 text-rose-300"
                                : "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {j.status}
                      </span>
                      {isAdmin && isActive && (
                        <button
                          type="button"
                          disabled={actionBusyId === j.job_id}
                          onClick={() => void handleCancel(j.job_id)}
                          className="inline-flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 px-2 py-0.5 text-[11px] text-rose-200 disabled:opacity-50 cursor-pointer"
                        >
                          <XCircle className="w-3 h-3" />
                          取消
                        </button>
                      )}
                      {isAdmin && isTerminal && (
                        <button
                          type="button"
                          disabled={actionBusyId === j.job_id}
                          onClick={() => void handleRetry(j.job_id)}
                          className="inline-flex items-center gap-1 rounded-md border border-sky-500/30 bg-sky-500/10 hover:bg-sky-500/20 px-2 py-0.5 text-[11px] text-sky-200 disabled:opacity-50 cursor-pointer"
                        >
                          <RotateCcw className="w-3 h-3" />
                          重试
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    {j.from_bot} → {j.target_bot}
                    {j.project ? ` · project=${j.project}` : ""}
                    {j.model ? ` · model=${j.model}` : ""}
                  </div>
                  {j.has_error && (
                    <div className="inline-flex items-center gap-1.5 text-[11px] font-mono text-rose-300 bg-rose-500/10 border border-rose-500/25 rounded px-2 py-0.5">
                      错误类型：{j.error_code || "execution_error"}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Job Detail Drawer */}
      {selectedJobId && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/50 backdrop-blur-[1px]">
          <div className="w-full max-w-2xl h-full bg-slate-950 border-l border-slate-800 flex flex-col">
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-100 truncate">
                  {detail?.label || selectedJobId}
                </div>
                <div className="text-[11px] font-mono text-slate-500 truncate">
                  {selectedJobId}
                  {detail ? ` · ${detail.from_bot} → ${detail.target_bot}` : ""}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {isAdmin &&
                  detail &&
                  (detail.status === "queued" || detail.status === "running") && (
                    <button
                      type="button"
                      disabled={actionBusyId === detail.job_id}
                      onClick={() => void handleCancel(detail.job_id)}
                      className="inline-flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/15 hover:bg-rose-500/25 px-2.5 py-1 text-xs text-rose-200 cursor-pointer"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      取消任务
                    </button>
                  )}
                {isAdmin &&
                  detail &&
                  detail.status !== "queued" &&
                  detail.status !== "running" && (
                    <button
                      type="button"
                      disabled={actionBusyId === detail.job_id}
                      onClick={() => void handleRetry(detail.job_id)}
                      className="inline-flex items-center gap-1 rounded-lg border border-sky-500/40 bg-sky-500/15 hover:bg-sky-500/25 px-2.5 py-1 text-xs text-sky-200 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      重试任务
                    </button>
                  )}
                <button
                  type="button"
                  onClick={() => {
                    setSelectedJobId(null);
                    setDetail(null);
                  }}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {detailLoading && (
                <div className="text-xs text-slate-400">正在加载脱敏任务详情…</div>
              )}
              {detailError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
                  {detailError}
                </div>
              )}
              {detail && (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                      <div className="text-[11px] text-slate-500">状态</div>
                      <div className="font-mono text-slate-100 mt-0.5">{detail.status}</div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                      <div className="text-[11px] text-slate-500">项目</div>
                      <div className="font-mono text-slate-200 mt-0.5 truncate">
                        {detail.project || "—"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                      <div className="text-[11px] text-slate-500">模型</div>
                      <div className="font-mono text-slate-200 mt-0.5 truncate">
                        {detail.model || "default"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5">
                      <div className="text-[11px] text-slate-500">耗时</div>
                      <div className="font-mono text-slate-200 mt-0.5">
                        {detail.duration_sec !== null ? `${detail.duration_sec}s` : "—"}
                      </div>
                    </div>
                  </div>

                  {detail.truncated && (
                    <div className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[11px] text-amber-200">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      部分超长字段已按 32 KiB 安全上限截断
                      {detail.truncated_fields && detail.truncated_fields.length > 0
                        ? `（${detail.truncated_fields.join(", ")}）`
                        : ""}
                    </div>
                  )}

                  <section className="space-y-1.5">
                    <h3 className="text-xs font-semibold text-slate-300">派工指令（Prompt）</h3>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5 text-xs text-slate-200">
                      <SafeMarkdown content={detail.prompt || "（空）"} />
                    </div>
                  </section>

                  {detail.result && (
                    <section className="space-y-1.5">
                      <h3 className="text-xs font-semibold text-slate-300">执行回执（Result）</h3>
                      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5 text-xs text-slate-200">
                        <SafeMarkdown content={detail.result} />
                      </div>
                    </section>
                  )}

                  {detail.error && (
                    <section className="space-y-1.5">
                      <h3 className="text-xs font-semibold text-rose-300">异常信息（Error）</h3>
                      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-200">
                        <SafeMarkdown content={detail.error} />
                      </div>
                    </section>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Admin Dispatch Modal */}
      {dispatchOpen && isAdmin && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">派发新任务</h3>
                <p className="text-[11px] text-slate-400">
                  最多选择 {MAX_DISPATCH_BOTS} 个在线 Bot 并发执行，目录由白名单项目映射
                </p>
              </div>
              <button
                type="button"
                onClick={() => setDispatchOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              {dispatchErr && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200">
                  {dispatchErr}
                </div>
              )}

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">
                  目标在线 Bot（已选 {selectedBots.length}/{MAX_DISPATCH_BOTS}）
                </label>
                {onlineBots.length === 0 ? (
                  <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-2.5">
                    当前暂无在线 Bot，请确认 Bridge 服务正在运行。
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {onlineBots.map((b) => {
                      const checked = selectedBots.includes(b.handle);
                      return (
                        <button
                          key={b.handle}
                          type="button"
                          onClick={() => toggleBotSelection(b.handle)}
                          className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono cursor-pointer transition-colors ${
                            checked
                              ? "border-sky-500 bg-sky-500/20 text-sky-200"
                              : "border-slate-700 bg-slate-950/60 text-slate-300 hover:border-slate-600"
                          }`}
                        >
                          {b.handle}
                          <span className="ml-1.5 text-[10px] text-slate-400">
                            {b.role}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block text-xs font-medium text-slate-300">
                    白名单项目（可选）
                  </label>
                  <select
                    value={dispatchProject}
                    onChange={(e) => setDispatchProject(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                  >
                    <option value="">使用 Bot 默认工作区</option>
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.id})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="block text-xs font-medium text-slate-300">
                    任务标签（可选）
                  </label>
                  <input
                    type="text"
                    maxLength={120}
                    value={dispatchLabel}
                    onChange={(e) => setDispatchLabel(e.target.value)}
                    placeholder="例如：巡检构建状态"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  任务指令 Prompt（必填，上限 16 KiB）
                </label>
                <textarea
                  rows={5}
                  value={dispatchPrompt}
                  onChange={(e) => setDispatchPrompt(e.target.value)}
                  placeholder="请输入要分派给所选 Bot 的具体执行指令…"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>
            </div>
            <div className="px-5 py-3 border-t border-slate-800 flex items-center justify-end gap-2 bg-slate-950/50">
              <button
                type="button"
                onClick={() => setDispatchOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={dispatchBusy || onlineBots.length === 0}
                onClick={() => void handleSubmitDispatch()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3.5 py-1.5 text-xs font-medium text-white disabled:opacity-50 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                {dispatchBusy ? "正在派发…" : "确认派发"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
