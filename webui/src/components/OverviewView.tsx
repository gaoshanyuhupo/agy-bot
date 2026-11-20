import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Bot,
  Clock,
  DollarSign,
  Globe,
  RefreshCw,
  ArrowUpRight,
} from "lucide-react";
import { fetchOverview, formatTokens, formatUsd } from "../api";
import type { NavTab, OverviewResponse } from "../types";

interface OverviewViewProps {
  onNavigate: (tab: NavTab) => void;
  eventVersion?: number;
}

export function OverviewView({ onNavigate, eventVersion = 0 }: OverviewViewProps) {
  const [data, setData] = useState<OverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchOverview();
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "加载总览失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">系统总览</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Phase 1 只读观测面 · 实时聚合多 Bot、派工流水、定时任务、账单与 Live-Browser 状态
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          刷新
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            <button
              type="button"
              onClick={() => onNavigate("bots")}
              className="text-left rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 p-4 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>在线 Bot 节点</span>
                <Bot className="w-4 h-4 text-sky-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-semibold text-slate-100">
                  {data.summary.bots_online}
                </span>
                <span className="text-xs text-slate-500">
                  / {data.summary.bots_total} 总计 · {data.summary.bots_busy} 忙碌
                </span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate("jobs")}
              className="text-left rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 p-4 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>派工单队列</span>
                <Activity className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-semibold text-slate-100">
                  {data.summary.jobs_running + data.summary.jobs_queued}
                </span>
                <span className="text-xs text-slate-500">
                  活跃 · {data.summary.jobs_total} 历史 · {data.summary.jobs_error} 异常
                </span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate("schedules")}
              className="text-left rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 p-4 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>定时任务</span>
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-semibold text-slate-100">
                  {data.summary.schedules_active}
                </span>
                <span className="text-xs text-slate-500">
                  运行中 / {data.summary.schedules_total} 总计
                </span>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate("costs")}
              className="text-left rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 p-4 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>今日估算费用</span>
                <DollarSign className="w-4 h-4 text-violet-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-semibold text-slate-100">
                  {formatUsd(data.summary.today_cost_usd)}
                </span>
                <span className="text-xs text-slate-500">
                  {formatTokens(data.summary.today_tokens)} · 缓存{" "}
                  {data.summary.today_cache_hit_pct}%
                </span>
              </div>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Live Browser card */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 flex flex-col justify-between gap-4">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <Globe className="w-4 h-4 text-sky-400" />
                    Live-Browser 实时引擎
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${
                      data.browser.running
                        ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                        : data.browser.reachable
                          ? "bg-slate-800 text-slate-300"
                          : "bg-rose-500/15 text-rose-300"
                    }`}
                  >
                    {data.browser.running
                      ? data.browser.takeover
                        ? "人工接管中"
                        : "运行中"
                      : data.browser.reachable
                        ? "待机中"
                        : "离线"}
                  </span>
                </div>
                <dl className="mt-3 space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <dt className="text-slate-500">运行模式</dt>
                    <dd className="text-slate-200 font-mono">
                      {data.browser.engine_mode}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">活动指纹</dt>
                    <dd className="text-slate-200 font-mono">
                      {data.browser.profile || "—"}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">画质 / 在线观看</dt>
                    <dd className="text-slate-200 font-mono">
                      {data.browser.quality_preset || "balanced"} ·{" "}
                      {data.browser.viewers ?? 0} 人
                    </dd>
                  </div>
                  {data.browser.url && (
                    <div className="pt-1 text-slate-400 truncate font-mono text-[11px]">
                      {data.browser.url}
                    </div>
                  )}
                </dl>
              </div>
              <button
                type="button"
                onClick={() => onNavigate("browser")}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium py-2 transition-colors cursor-pointer"
              >
                打开全屏浏览器工作台
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Recent Jobs card */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-semibold text-slate-100">
                  最近派工记录
                </span>
                <button
                  type="button"
                  onClick={() => onNavigate("jobs")}
                  className="text-xs text-sky-400 hover:text-sky-300 cursor-pointer"
                >
                  查看全部 →
                </button>
              </div>
              {data.recent_jobs.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500">
                  暂无团队派工记录
                </div>
              ) : (
                <div className="divide-y divide-slate-800/80">
                  {data.recent_jobs.map((j) => (
                    <div
                      key={j.job_id}
                      className="py-2.5 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="font-medium text-slate-200 truncate">
                          {j.label || j.job_id}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                          {j.from_bot} → {j.target_bot}
                          {j.project ? ` · ${j.project}` : ""}
                        </div>
                      </div>
                      <span
                        className={`shrink-0 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                          j.status === "done"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : j.status === "running"
                              ? "bg-sky-500/15 text-sky-300"
                              : j.status === "error"
                                ? "bg-rose-500/15 text-rose-300"
                                : "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {j.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
