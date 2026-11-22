import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { fetchCosts, formatTokens, formatUsd } from "../api";
import type { CostsResponse, GoogleAccountsResponse, StudioSession } from "../types";
import { GoogleAccountsPanel } from "./GoogleAccountsPanel";

const PLAN_FILTER_OPTIONS = [
  { value: "all", label: "全部套餐" },
  { value: "ultra", label: "Google AI Ultra" },
  { value: "pro", label: "Google AI Pro" },
  { value: "enterprise", label: "Enterprise" },
  { value: "free", label: "Free" },
  { value: "unknown", label: "Unknown" },
];

interface CostsViewProps {
  session?: StudioSession;
  eventVersion?: number;
  onSessionRevoked?: (reason: string) => void;
}

export function CostsView({
  session,
  eventVersion = 0,
  onSessionRevoked,
}: CostsViewProps = {}) {
  const [scope, setScope] = useState<"all" | "agent" | "sched">("all");
  const [accountFilter, setAccountFilter] = useState<string>("all");
  const [planFilter, setPlanFilter] = useState<string>("all");
  const [accountOptions, setAccountOptions] = useState<{ id: string; label: string }[]>([]);
  const [data, setData] = useState<CostsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetchCosts(scope, {
        account_id: accountFilter === "all" ? undefined : accountFilter,
        plan_tier: planFilter === "all" ? undefined : planFilter,
      });
      setData(resp);
    } catch (e) {
      setError(e instanceof Error ? e.message : "加载用量账单失败");
    } finally {
      setLoading(false);
    }
  }, [scope, accountFilter, planFilter]);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  const handleAccountsLoaded = useCallback((snap: GoogleAccountsResponse) => {
    const opts = snap.accounts.map((a) => ({
      id: a.account_id,
      label: `${a.alias || a.account_id} (${a.plan_label})`,
    }));
    setAccountOptions(opts);
  }, []);

  const maxDailyCost = Math.max(
    0.01,
    ...(data?.daily_14d.map((d) => d.cost_usd) || [0.01]),
  );

  const byAccountMonth = data?.by_account_month || [];
  const byPlanMonth = data?.by_plan_month || [];

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-6">
      {/* Multi-Google-Account & Multi-Plan Quota Panel */}
      <GoogleAccountsPanel
        session={session}
        eventVersion={eventVersion}
        onAccountsChanged={() => void load()}
        onAccountsLoaded={handleAccountsLoaded}
        onSessionRevoked={onSessionRevoked}
      />

      {/* Divider */}
      <div className="border-t border-slate-800/80 pt-5 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">用量与缓存账单</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              只读账本统计 · 时区 {data?.tz_label || "UTC+8"}
              {data?.week_window.remaining ? ` · 本周配额 ${data.week_window.remaining}` : ""}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Account Filter */}
            <select
              aria-label="按账号筛选"
              value={accountFilter}
              onChange={(e) => setAccountFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="all">全部账号</option>
              {accountOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
              <option value="unassigned">未归属 (历史)</option>
            </select>

            {/* Plan Filter */}
            <select
              aria-label="按套餐筛选"
              value={planFilter}
              onChange={(e) => setPlanFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            >
              {PLAN_FILTER_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900 p-0.5">
              {(
                [
                  ["all", "全部"],
                  ["agent", "仅主对话"],
                  ["sched", "定时任务"],
                ] as const
              ).map(([sc, lbl]) => (
                <button
                  key={sc}
                  type="button"
                  onClick={() => setScope(sc)}
                  className={`px-2.5 py-1 rounded-md text-xs cursor-pointer ${
                    scope === sc
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {lbl}
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

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
            {error}
          </div>
        )}

        {data && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(
                [
                  ["今日累计", data.today],
                  ["本周配额周期", data.week],
                  ["本月累计", data.month],
                ] as const
              ).map(([title, agg]) => (
                <div
                  key={title}
                  className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-2"
                >
                  <div className="text-xs text-slate-400">{title}</div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-2xl font-semibold text-slate-100">
                      {formatUsd(agg.cost_usd)}
                    </span>
                    <span className="text-xs text-emerald-400 font-mono">
                      缓存省 {formatUsd(agg.saved_usd)}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    {formatTokens(agg.total_tokens)} tok · 缓存命中{" "}
                    {agg.cache_hit_pct}% · {agg.calls} 次
                  </div>
                </div>
              ))}
            </div>

            {/* 14-day Bar Chart */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="text-sm font-semibold text-slate-100 mb-4">
                近 14 天费用趋势 (USD)
              </div>
              <div className="grid grid-cols-14 gap-1.5 items-end h-36 pt-2">
                {data.daily_14d.map((d) => {
                  const pct = Math.max(4, Math.round((d.cost_usd / maxDailyCost) * 100));
                  return (
                    <div
                      key={d.date}
                      className="flex flex-col items-center gap-1.5 h-full justify-end"
                      title={`${d.date}: ${formatUsd(d.cost_usd)} (${formatTokens(d.total_tokens)})`}
                    >
                      <div
                        className="w-full max-w-6 rounded-t bg-sky-500/75 hover:bg-sky-400 transition-colors"
                        style={{ height: `${pct}%` }}
                      />
                      <span className="text-[10px] font-mono text-slate-500">
                        {d.label.slice(3)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Per-Account & Per-Plan Monthly Comparison Tables */}
            {(byAccountMonth.length > 0 || byPlanMonth.length > 0) && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-slate-100">
                    本月各账号费用与 Token 对比
                  </div>
                  {byAccountMonth.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">暂无账号费用记录</div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-800 text-slate-400 bg-slate-950/40">
                        <tr>
                          <th className="px-3.5 py-2 font-medium">账号</th>
                          <th className="px-3.5 py-2 font-medium">套餐</th>
                          <th className="px-3.5 py-2 font-medium">Token</th>
                          <th className="px-3.5 py-2 font-medium">费用</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70 font-mono">
                        {byAccountMonth.map((row) => (
                          <tr key={row.account_id}>
                            <td className="px-3.5 py-2 font-sans text-slate-200">
                              {row.alias}
                            </td>
                            <td className="px-3.5 py-2 font-sans text-slate-400">
                              {row.plan_label}
                            </td>
                            <td className="px-3.5 py-2 text-slate-300">
                              {formatTokens(row.total_tokens)}
                            </td>
                            <td className="px-3.5 py-2 text-slate-100">
                              {formatUsd(row.cost_usd)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-slate-100">
                    本月各套餐费用与 Token 汇总
                  </div>
                  {byPlanMonth.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">暂无套餐费用记录</div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-800 text-slate-400 bg-slate-950/40">
                        <tr>
                          <th className="px-3.5 py-2 font-medium">套餐</th>
                          <th className="px-3.5 py-2 font-medium">账号数</th>
                          <th className="px-3.5 py-2 font-medium">Token</th>
                          <th className="px-3.5 py-2 font-medium">费用</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70 font-mono">
                        {byPlanMonth.map((row) => (
                          <tr key={row.plan_tier}>
                            <td className="px-3.5 py-2 font-sans text-slate-200">
                              {row.plan_label}
                            </td>
                            <td className="px-3.5 py-2 text-slate-400">{row.account_count}</td>
                            <td className="px-3.5 py-2 text-slate-300">
                              {formatTokens(row.total_tokens)}
                            </td>
                            <td className="px-3.5 py-2 text-slate-100">
                              {formatUsd(row.cost_usd)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}

            {/* Model Breakdown */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 text-sm font-semibold text-slate-100">
                本月模型费用构成
              </div>
              {data.by_model_month.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  本月暂无账本记录
                </div>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-slate-400 bg-slate-950/40">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">模型家族</th>
                      <th className="px-4 py-2.5 font-medium">总 Token</th>
                      <th className="px-4 py-2.5 font-medium">缓存命中率</th>
                      <th className="px-4 py-2.5 font-medium">估算费用</th>
                      <th className="px-4 py-2.5 font-medium">缓存节省</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 font-mono">
                    {data.by_model_month.map((m) => (
                      <tr key={m.family}>
                        <td className="px-4 py-2.5 font-sans text-slate-200">
                          {m.label}
                        </td>
                        <td className="px-4 py-2.5 text-slate-300">
                          {formatTokens(m.total_tokens)}
                        </td>
                        <td className="px-4 py-2.5 text-emerald-400">
                          {m.cache_hit_pct}%
                        </td>
                        <td className="px-4 py-2.5 text-slate-100">
                          {formatUsd(m.cost_usd)}
                        </td>
                        <td className="px-4 py-2.5 text-slate-400">
                          {formatUsd(m.saved_usd)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Cached Plan Quota */}
            {data.quota_groups.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {data.quota_groups.map((grp) => (
                  <div
                    key={grp.name}
                    className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3"
                  >
                    <div className="text-sm font-semibold text-slate-100">
                      {grp.name}
                    </div>
                    {grp.buckets.map((b) => (
                      <div key={`${grp.name}-${b.name}`} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-300">{b.name}</span>
                          <span className="font-mono text-slate-400">
                            余 {b.remaining_pct}% · {b.reset_countdown}
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className="h-full rounded-full bg-sky-500"
                            style={{ width: `${Math.max(2, b.remaining_pct)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
