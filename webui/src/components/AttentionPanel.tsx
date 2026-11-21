import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Clock,
  Globe,
  Loader2,
  Lock,
  RefreshCw,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { StudioApiError, decideAttentionItem, fetchAttention } from "../api";
import type { AttentionItem, StudioSession } from "../types";

export interface AttentionPanelProps {
  session: StudioSession;
  eventVersion?: number;
  onOpenBrowser?: () => void;
  onPendingCountChange?: (count: number) => void;
  onSessionRevoked: (reason: string) => void;
}

function formatTs(ts: number | null): string {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString([], {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return String(ts);
  }
}

function kindLabel(kind: AttentionItem["kind"]): string {
  switch (kind) {
    case "browser_takeover":
      return "浏览器人工接管";
    case "plan":
      return "计划审批";
    case "undo_force":
      return "强制回滚审批";
    default:
      return "高危动作审批";
  }
}

export function AttentionPanel({
  session,
  eventVersion = 0,
  onOpenBrowser,
  onPendingCountChange,
  onSessionRevoked,
}: AttentionPanelProps) {
  const isReadonly = session.role !== "admin";

  const [filter, setFilter] = useState<"pending" | "all">("pending");
  const [items, setItems] = useState<AttentionItem[]>([]);
  const [pendingCount, setPendingCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busyIds, setBusyIds] = useState<Record<string, boolean>>({});
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [noticeMsg, setNoticeMsg] = useState<string | null>(null);

  const mountedRef = useRef(true);
  const loadSeqRef = useRef(0);
  const filterRef = useRef<"pending" | "all">(filter);
  filterRef.current = filter;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const handleAuthErr = useCallback(
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

  const loadAttention = useCallback(
    async (opts?: { silent?: boolean }) => {
      const seq = ++loadSeqRef.current;
      const reqFilter = filterRef.current;
      if (!opts?.silent) {
        setLoading(true);
        setErrorMsg(null);
      }
      try {
        const res = await fetchAttention(reqFilter);
        if (!mountedRef.current || loadSeqRef.current !== seq || filterRef.current !== reqFilter) {
          return;
        }
        setItems(res.items || []);
        setPendingCount(res.pending_count || 0);
        onPendingCountChange?.(res.pending_count || 0);
      } catch (err) {
        if (!mountedRef.current || loadSeqRef.current !== seq) return;
        if (!handleAuthErr(err) && !opts?.silent) {
          setErrorMsg(err instanceof Error ? err.message : "加载审批队列失败");
        }
      } finally {
        if (mountedRef.current && !opts?.silent && loadSeqRef.current === seq) {
          setLoading(false);
        }
      }
    },
    [handleAuthErr, onPendingCountChange],
  );

  useEffect(() => {
    void loadAttention();
  }, [filter, loadAttention]);

  useEffect(() => {
    if (eventVersion > 0) {
      void loadAttention({ silent: true });
    }
  }, [eventVersion, loadAttention]);

  const handleDecide = async (item: AttentionItem, decision: "approved" | "rejected") => {
    if (isReadonly || item.readonly_signal || item.status !== "pending" || busyIds[item.item_id]) {
      return;
    }
    setBusyIds((prev) => ({ ...prev, [item.item_id]: true }));
    setErrorMsg(null);
    setNoticeMsg(null);
    try {
      const note = (notes[item.item_id] || "").trim();
      await decideAttentionItem(item.item_id, {
        decision,
        note: note || undefined,
      });
      if (!mountedRef.current) return;
      setNoticeMsg(
        `已完成审批（${item.item_id}）：${decision === "approved" ? "已批准" : "已拒绝"}`,
      );
      await loadAttention({ silent: true });
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        if (err instanceof StudioApiError && err.status === 409) {
          setErrorMsg(err.message || "该审批项已处理或已过期（409 Conflict）");
          await loadAttention({ silent: true });
        } else {
          setErrorMsg(err instanceof Error ? err.message : "提交审批决议失败");
        }
      }
    } finally {
      if (mountedRef.current) {
        setBusyIds((prev) => {
          const next = { ...prev };
          delete next[item.item_id];
          return next;
        });
      }
    }
  };

  return (
    <div className="flex-1 min-h-0 min-w-0 flex flex-col bg-slate-950 overflow-hidden">
      <header className="shrink-0 px-3 py-2 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-100">
          <Bell className="w-4 h-4 text-amber-400" />
          <span>统一审批中心</span>
          {pendingCount > 0 && (
            <span className="px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 text-[10px] font-mono">
              {pendingCount} 待处理
            </span>
          )}
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <div className="inline-flex rounded-md border border-slate-800 bg-slate-950 p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setFilter("pending")}
              className={`px-2 py-0.5 rounded cursor-pointer ${
                filter === "pending"
                  ? "bg-sky-500/20 text-sky-300 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              待处理
            </button>
            <button
              type="button"
              onClick={() => setFilter("all")}
              className={`px-2 py-0.5 rounded cursor-pointer ${
                filter === "all"
                  ? "bg-sky-500/20 text-sky-300 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              全部
            </button>
          </div>
          <button
            type="button"
            onClick={() => void loadAttention()}
            title="刷新审批中心"
            className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {isReadonly && (
        <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-center gap-2">
          <Lock className="w-3.5 h-3.5 shrink-0" />
          <span>只读权限（readonly）：可查看审批队列与浏览器接管状态，批准/拒绝操作已禁用。</span>
        </div>
      )}

      {errorMsg && (
        <div className="shrink-0 px-3 py-1.5 border-b border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            {errorMsg}
          </span>
          <button type="button" onClick={() => setErrorMsg(null)} className="underline cursor-pointer">
            关闭
          </button>
        </div>
      )}

      {noticeMsg && (
        <div className="shrink-0 px-3 py-1.5 border-b border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-200 flex items-center justify-between gap-2">
          <span>{noticeMsg}</span>
          <button type="button" onClick={() => setNoticeMsg(null)} className="underline cursor-pointer">
            关闭
          </button>
        </div>
      )}

      <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-2.5">
        {items.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-10 px-4">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/70 mb-2" />
            <div className="text-sm font-medium text-slate-200">
              {loading ? "加载审批项中…" : "当前无待处理的审批或接管请求"}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              计划确认、高危动作、强制回滚与实时浏览器人工接管会统一汇总到此队列。
            </p>
          </div>
        ) : (
          items.map((item) => {
            const isBrowser = item.kind === "browser_takeover" || Boolean(item.readonly_signal);
            const isPending = item.status === "pending";
            const isBusy = Boolean(busyIds[item.item_id]);

            return (
              <div
                key={item.item_id}
                className={`rounded-xl border p-3 space-y-2 ${
                  isBrowser
                    ? "border-sky-500/40 bg-sky-500/10"
                    : item.risk_level === "high" && isPending
                      ? "border-rose-500/40 bg-rose-500/10"
                      : "border-slate-800 bg-slate-900/70"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {isBrowser ? (
                        <Globe className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                      ) : (
                        <ShieldAlert
                          className={`w-3.5 h-3.5 shrink-0 ${
                            item.risk_level === "high" ? "text-rose-400" : "text-amber-400"
                          }`}
                        />
                      )}
                      <span className="text-xs font-semibold text-slate-100 truncate">
                        {item.title}
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">
                        {kindLabel(item.kind)}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${
                          item.risk_level === "high"
                            ? "bg-rose-500/20 text-rose-300"
                            : "bg-amber-500/20 text-amber-300"
                        }`}
                      >
                        {item.risk_level}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-400 font-mono flex-wrap">
                      <span>{item.item_id}</span>
                      {item.bot && <span>· @{item.bot}</span>}
                      {item.expires_at && (
                        <span className="inline-flex items-center gap-0.5">
                          <Clock className="w-2.5 h-2.5" />
                          截止 {formatTs(item.expires_at)}
                        </span>
                      )}
                    </div>
                  </div>

                  <span
                    className={`shrink-0 px-2 py-0.5 rounded-full text-[10px] font-medium ${
                      item.status === "pending"
                        ? "bg-amber-500/20 text-amber-300"
                        : item.status === "approved"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : item.status === "rejected"
                            ? "bg-rose-500/20 text-rose-300"
                            : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {item.status}
                  </span>
                </div>

                <div className="text-xs text-slate-200 whitespace-pre-wrap break-words bg-slate-950/60 border border-slate-800/80 rounded-lg px-2.5 py-2">
                  {item.summary}
                </div>

                {isBrowser && (
                  <div className="flex items-center justify-between gap-2 text-[11px] text-sky-200 flex-wrap">
                    <div className="truncate font-mono text-slate-300">
                      {item.origin || "浏览器会话运行中"}
                      {item.page_title ? ` · ${item.page_title}` : ""}
                    </div>
                    {onOpenBrowser && (
                      <button
                        type="button"
                        onClick={onOpenBrowser}
                        className="px-2.5 py-1 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium inline-flex items-center gap-1 cursor-pointer"
                      >
                        <Globe className="w-3 h-3" />
                        前往实时浏览器接管
                      </button>
                    )}
                  </div>
                )}

                {!isBrowser && isPending && !isReadonly && (
                  <div className="space-y-2 pt-1">
                    <input
                      type="text"
                      value={notes[item.item_id] || ""}
                      onChange={(e) =>
                        setNotes((prev) => ({ ...prev, [item.item_id]: e.target.value }))
                      }
                      placeholder="审批备注（可选）"
                      className="w-full h-7 rounded-lg bg-slate-950 border border-slate-800 px-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                    />
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => void handleDecide(item, "approved")}
                        className="flex-1 h-8 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center justify-center gap-1 cursor-pointer"
                      >
                        {isBusy ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        )}
                        批准
                      </button>
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => void handleDecide(item, "rejected")}
                        className="flex-1 h-8 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center justify-center gap-1 cursor-pointer"
                      >
                        {isBusy ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5" />
                        )}
                        拒绝
                      </button>
                    </div>
                  </div>
                )}

                {!isBrowser && !isPending && (
                  <div className="text-[11px] text-slate-400 flex items-center gap-2 flex-wrap">
                    {item.decided_by && <span>审批人：{item.decided_by}</span>}
                    {item.decided_at && <span>时间：{formatTs(item.decided_at)}</span>}
                    {item.decision_note && <span className="truncate">备注：{item.decision_note}</span>}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
