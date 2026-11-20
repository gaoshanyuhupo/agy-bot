import { useCallback, useEffect, useState } from "react";
import { Bot, RefreshCw } from "lucide-react";
import { fetchBots } from "../api";
import type { BotsResponse } from "../types";

interface BotsViewProps {
  eventVersion?: number;
}

export function BotsView({ eventVersion = 0 }: BotsViewProps) {
  const [data, setData] = useState<BotsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await fetchBots());
    } catch (e) {
      setError(e instanceof Error ? e.message : "加载 Bot 列表失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Bot 团队花名册</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            只读状态视图 · 角色、在线心跳、当前队列与生效模型
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

      {data && data.bots.length === 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-10 text-center text-xs text-slate-500">
          暂无注册到 Bot Bus 的成员节点
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {data?.bots.map((b) => (
          <div
            key={b.handle}
            className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5 min-w-0">
                <div
                  className={`h-8 w-8 rounded-lg flex items-center justify-center shrink-0 ${
                    b.online
                      ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                      : "bg-slate-800 text-slate-500"
                  }`}
                >
                  <Bot className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-100 truncate">
                    {b.display_name || b.handle}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    {b.handle}
                  </div>
                </div>
              </div>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] font-medium shrink-0 ${
                  b.role === "coordinator"
                    ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                    : b.role === "worker"
                      ? "bg-violet-500/15 text-violet-300 border border-violet-500/30"
                      : "bg-slate-800 text-slate-300"
                }`}
              >
                {b.role}
              </span>
            </div>

            {b.specialty && (
              <p className="text-xs text-slate-400 line-clamp-2">{b.specialty}</p>
            )}

            <dl className="space-y-1.5 text-xs border-t border-slate-800/80 pt-3">
              <div className="flex justify-between">
                <dt className="text-slate-500">运行状态</dt>
                <dd className={b.online ? "text-emerald-400" : "text-slate-500"}>
                  {b.online ? (b.busy ? "在线 · 执行中" : "在线 · 空闲") : "离线"}
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-500 shrink-0">生效模型</dt>
                <dd className="text-slate-200 font-mono truncate">
                  {b.effective_model}
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-slate-500 shrink-0">默认项目</dt>
                <dd className="text-slate-300 font-mono truncate">
                  {b.default_project || "—"}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">排队任务</dt>
                <dd className="text-slate-200 font-mono">{b.queue_depth}</dd>
              </div>
            </dl>
          </div>
        ))}
      </div>
    </div>
  );
}
