import { useCallback, useEffect, useState } from "react";
import {
  Edit3,
  Lock,
  Play,
  Plus,
  Power,
  RefreshCw,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import {
  StudioApiError,
  createSchedule,
  deleteSchedule,
  fetchModels,
  fetchSchedules,
  runScheduleNow,
  updateSchedule,
} from "../api";
import type {
  ProjectOption,
  ScheduleItem,
  SchedulesResponse,
  StudioSession,
} from "../types";

interface SchedulesViewProps {
  session: StudioSession;
  eventVersion?: number;
  onSessionRevoked: (reason: string) => void;
}

const CRON_PRESETS = [
  { label: "每 5 分钟", expr: "*/5 * * * *" },
  { label: "每小时整点", expr: "@hourly" },
  { label: "每天 09:00", expr: "0 9 * * *" },
  { label: "每周一 09:00", expr: "0 9 * * 1" },
];

export function SchedulesView({
  session,
  eventVersion = 0,
  onSessionRevoked,
}: SchedulesViewProps) {
  const isAdmin = session.role === "admin";
  const [data, setData] = useState<SchedulesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // Create / Edit modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState<"prompt" | "reminder">("prompt");
  const [formExpr, setFormExpr] = useState("0 9 * * *");
  const [formProject, setFormProject] = useState("");
  const [formPrompt, setFormPrompt] = useState("");
  const [formSilent, setFormSilent] = useState(true);
  const [formEnabled, setFormEnabled] = useState(true);
  const [formBusy, setFormBusy] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);

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
      setData(await fetchSchedules());
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "加载定时任务失败");
      }
    } finally {
      setLoading(false);
    }
  }, [handleAuthErr]);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  const loadProjectsOnce = useCallback(async () => {
    try {
      const m = await fetchModels();
      setProjects(m.projects || []);
    } catch (e) {
      handleAuthErr(e);
    }
  }, [handleAuthErr]);

  const openCreateModal = () => {
    if (!isAdmin) return;
    setEditingId(null);
    setFormName("");
    setFormType("prompt");
    setFormExpr("0 9 * * *");
    setFormProject("");
    setFormPrompt("");
    setFormSilent(true);
    setFormEnabled(true);
    setFormErr(null);
    setModalOpen(true);
    void loadProjectsOnce();
  };

  const openEditModal = (item: ScheduleItem) => {
    if (!isAdmin || item.read_only_cli) return;
    setEditingId(item.id);
    setFormName(item.name);
    setFormType(item.task_type === "reminder" ? "reminder" : "prompt");
    setFormExpr(item.schedule_expr);
    setFormProject(item.project || "");
    setFormPrompt(item.prompt || "");
    setFormSilent(item.silent_if_empty ?? true);
    setFormEnabled(item.enabled);
    setFormErr(null);
    setModalOpen(true);
    void loadProjectsOnce();
  };

  const handleSaveModal = async () => {
    if (!isAdmin || formBusy) return;
    setFormErr(null);
    if (!formName.trim()) {
      setFormErr("请输入任务名称");
      return;
    }
    if (!formExpr.trim()) {
      setFormErr("请输入有效的 Cron 表达式（最小间隔 5 分钟）");
      return;
    }
    if (!formPrompt.trim()) {
      setFormErr("请输入任务指令或提醒内容");
      return;
    }
    setFormBusy(true);
    try {
      if (editingId) {
        await updateSchedule(editingId, {
          name: formName.trim(),
          task_type: formType,
          schedule_expr: formExpr.trim(),
          project: formProject,
          prompt: formPrompt.trim(),
          silent_if_empty: formSilent,
          enabled: formEnabled,
        });
        setNotice(`已更新定时任务：${formName.trim()}`);
      } else {
        await createSchedule({
          name: formName.trim(),
          task_type: formType,
          schedule_expr: formExpr.trim(),
          project: formProject || undefined,
          prompt: formPrompt.trim(),
          silent_if_empty: formSilent,
          enabled: formEnabled,
        });
        setNotice(`已创建定时任务：${formName.trim()}`);
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      if (!handleAuthErr(e)) {
        setFormErr(e instanceof Error ? e.message : "保存定时任务失败");
      }
    } finally {
      setFormBusy(false);
    }
  };

  const handleToggle = async (item: ScheduleItem, nextEnabled: boolean) => {
    if (!isAdmin || busyId) return;
    if (item.read_only_cli && nextEnabled) return;
    setBusyId(item.id);
    setError(null);
    try {
      await updateSchedule(item.id, { enabled: nextEnabled });
      setNotice(
        nextEnabled ? `已启用定时任务：${item.name}` : `已停用定时任务：${item.name}`,
      );
      await load();
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "更新任务状态失败");
      }
    } finally {
      setBusyId(null);
    }
  };

  const handleRunNow = async (item: ScheduleItem) => {
    if (!isAdmin || item.read_only_cli || busyId) return;
    setBusyId(item.id);
    setError(null);
    try {
      await runScheduleNow(item.id);
      setNotice(`已触发立即执行：${item.name}`);
      await load();
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "触发任务执行失败");
      }
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (item: ScheduleItem) => {
    if (!isAdmin || item.read_only_cli || busyId) return;
    setBusyId(item.id);
    setError(null);
    try {
      await deleteSchedule(item.id);
      setNotice(`已删除定时任务：${item.name}`);
      await load();
    } catch (e) {
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "删除任务失败");
      }
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">定时任务调度表</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            时区 {data?.tz_label || "UTC+8"} · WebUI 仅支持安全{" "}
            <span className="font-mono text-slate-300">prompt / reminder</span>{" "}
            任务（最小间隔 5 分钟；CLI 脚本任务为只读保护）
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin ? (
            <button
              type="button"
              onClick={openCreateModal}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              新建定时任务
            </button>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[11px] text-amber-300">
              <Lock className="w-3 h-3" />
              只读权限
            </span>
          )}
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

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-x-auto">
        {!data || data.schedules.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-500">
            当前暂无配置的定时任务
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400 bg-slate-950/40">
              <tr>
                <th className="px-4 py-3 font-medium">任务名称</th>
                <th className="px-4 py-3 font-medium">状态</th>
                <th className="px-4 py-3 font-medium">计划表达式</th>
                <th className="px-4 py-3 font-medium">类型 / 项目</th>
                <th className="px-4 py-3 font-medium">下次触发</th>
                <th className="px-4 py-3 font-medium">执行次数</th>
                {isAdmin && <th className="px-4 py-3 font-medium text-right">操作</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {data.schedules.map((s) => {
                const isRoCli = Boolean(s.read_only_cli);
                const isBusy = busyId === s.id;
                return (
                  <tr key={s.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium text-slate-100">{s.name}</span>
                        {isRoCli && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[10px] font-medium text-amber-300">
                            <ShieldAlert className="w-3 h-3" />
                            CLI 只读
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">{s.id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${
                          s.enabled
                            ? "bg-emerald-500/15 text-emerald-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {s.enabled ? "运行中" : "已暂停"}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-200">
                      {s.schedule_expr}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      <span className="font-mono">{s.task_type}</span>
                      {(s.project || s.model) && (
                        <div className="text-[11px] text-slate-500 font-mono">
                          {[s.project, s.model].filter(Boolean).join(" · ")}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-slate-200">{s.countdown}</div>
                      {s.next_run_local && (
                        <div className="text-[11px] font-mono text-slate-500">
                          {s.next_run_local}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-200">
                      {s.run_count} 次
                      <div className="text-[11px] text-slate-500">{s.last_status}</div>
                    </td>
                    {isAdmin && (
                      <td className="px-4 py-3 text-right">
                        {isRoCli ? (
                          s.enabled ? (
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleToggle(s, false)}
                              className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/15 hover:bg-amber-500/25 px-2.5 py-1 text-[11px] text-amber-200 disabled:opacity-50 cursor-pointer"
                            >
                              <Power className="w-3 h-3" />
                              紧急停用
                            </button>
                          ) : (
                            <span className="text-[11px] text-slate-500">受 CLI 保护</span>
                          )
                        ) : (
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleRunNow(s)}
                              title="立即运行一次"
                              className="inline-flex items-center gap-1 rounded-md border border-sky-500/30 bg-sky-500/10 hover:bg-sky-500/20 px-2 py-1 text-[11px] text-sky-200 disabled:opacity-50 cursor-pointer"
                            >
                              <Play className="w-3 h-3" />
                              运行
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleToggle(s, !s.enabled)}
                              title={s.enabled ? "暂停" : "启用"}
                              className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 hover:bg-slate-700 px-2 py-1 text-[11px] text-slate-200 disabled:opacity-50 cursor-pointer"
                            >
                              <Power className="w-3 h-3" />
                              {s.enabled ? "停用" : "启用"}
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => openEditModal(s)}
                              title="编辑"
                              className="p-1 rounded-md border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                            >
                              <Edit3 className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void handleDelete(s)}
                              title="删除"
                              className="p-1 rounded-md border border-rose-500/30 text-rose-300 hover:bg-rose-500/15 disabled:opacity-50 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Create / Edit Safe Schedule Modal */}
      {modalOpen && isAdmin && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {editingId ? "编辑定时任务" : "新建定时任务"}
                </h3>
                <p className="text-[11px] text-slate-400">
                  仅允许安全类型（prompt / reminder），最小触发间隔 5 分钟
                </p>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-3.5">
              {formErr && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200">
                  {formErr}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block text-xs font-medium text-slate-300">任务名称</label>
                  <input
                    type="text"
                    maxLength={120}
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="例如：每日构建巡检"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block text-xs font-medium text-slate-300">任务类型</label>
                  <select
                    value={formType}
                    onChange={(e) =>
                      setFormType(e.target.value === "reminder" ? "reminder" : "prompt")
                    }
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                  >
                    <option value="prompt">prompt（AI 代理执行）</option>
                    <option value="reminder">reminder（零 Token 定时提醒）</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  计划表达式（5 段 Cron 或宏，最小间隔 5 分钟）
                </label>
                <input
                  type="text"
                  value={formExpr}
                  onChange={(e) => setFormExpr(e.target.value)}
                  placeholder="0 9 * * *"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 focus:border-sky-500 focus:outline-none"
                />
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {CRON_PRESETS.map((p) => (
                    <button
                      key={p.expr}
                      type="button"
                      onClick={() => setFormExpr(p.expr)}
                      className="px-2 py-0.5 rounded border border-slate-700 bg-slate-950 text-[11px] text-slate-400 hover:text-slate-200 hover:border-slate-600 cursor-pointer"
                    >
                      {p.label} ({p.expr})
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  白名单项目（可选）
                </label>
                <select
                  value={formProject}
                  onChange={(e) => setFormProject(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                >
                  <option value="">默认项目</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.id})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">
                  {formType === "reminder" ? "提醒内容" : "AI 执行指令（Prompt）"}
                </label>
                <textarea
                  rows={4}
                  value={formPrompt}
                  onChange={(e) => setFormPrompt(e.target.value)}
                  placeholder={
                    formType === "reminder"
                      ? "请输入到期推送的提醒文案…"
                      : "请输入定时触发时交给 Agent 的任务说明…"
                  }
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-5 pt-1 text-xs text-slate-300">
                <label className="inline-flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formEnabled}
                    onChange={(e) => setFormEnabled(e.target.checked)}
                    className="rounded border-slate-700"
                  />
                  <span>立即启用</span>
                </label>
                <label className="inline-flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formSilent}
                    onChange={(e) => setFormSilent(e.target.checked)}
                    className="rounded border-slate-700"
                  />
                  <span>无增量结果时静默</span>
                </label>
              </div>
            </div>
            <div className="px-5 py-3 border-t border-slate-800 flex items-center justify-end gap-2 bg-slate-950/50">
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={formBusy}
                onClick={() => void handleSaveModal()}
                className="rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-1.5 text-xs font-medium text-white disabled:opacity-50 cursor-pointer"
              >
                {formBusy ? "保存中…" : "保存任务"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
