import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  KeyRound,
  LogOut,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserCheck,
  Users,
  X,
} from "lucide-react";
import {
  StudioApiError,
  activateGoogleAccount,
  addGoogleAccount,
  cancelGoogleLoginFlow,
  deleteGoogleAccount,
  fetchGoogleAccounts,
  logoutGoogleAccount,
  refreshAllGoogleAccountsQuota,
  refreshGoogleAccountQuota,
  startGoogleAccountLogin,
  submitGoogleLoginCode,
  updateGoogleAccount,
} from "../api";
import type {
  GoogleAccountItem,
  GoogleAccountsResponse,
  GoogleLoginFlowState,
  PlanTierQuotaSummary,
  StudioSession,
} from "../types";

const WEEKDAY_LABELS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];

const ACCOUNT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function planBadgeStyle(tier: string): string {
  switch (tier) {
    case "ultra":
      return "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/35";
    case "pro":
      return "bg-sky-500/15 text-sky-300 border-sky-500/35";
    case "enterprise":
      return "bg-indigo-500/15 text-indigo-300 border-indigo-500/35";
    case "free":
      return "bg-slate-700/60 text-slate-300 border-slate-600/60";
    default:
      return "bg-slate-800 text-slate-400 border-slate-700";
  }
}

function quotaBarColor(pct: number | null): string {
  if (pct === null) return "bg-slate-600";
  if (pct <= 15) return "bg-rose-500";
  if (pct <= 45) return "bg-amber-400";
  return "bg-emerald-400";
}

function formatResetCountdown(iso: string | null): string {
  if (!iso) return "";
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return "";
  const diffMs = ts - Date.now();
  if (diffMs <= 0) return "即将重置";
  const totalMin = Math.floor(diffMs / 60_000);
  const days = Math.floor(totalMin / (24 * 60));
  const hours = Math.floor((totalMin % (24 * 60)) / 60);
  const mins = totalMin % 60;
  if (days > 0) return `${days}d ${hours}h 后重置`;
  if (hours > 0) return `${hours}h ${mins}m 后重置`;
  return `${mins}m 后重置`;
}

function formatCountdownSeconds(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const mm = String(Math.floor(s / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

interface QuotaMiniBarProps {
  label: string;
  pct: number | null;
  resetAt: string | null;
  poolHint?: string;
}

function QuotaMiniBar({ label, pct, resetAt, poolHint }: QuotaMiniBarProps) {
  const countdown = formatResetCountdown(resetAt);
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2 text-[11px]">
        <span className="text-slate-300 truncate">{label}</span>
        <span className="font-mono text-slate-400 shrink-0">
          {pct !== null ? `${pct.toFixed(0)}%` : "待刷新"}
          {poolHint ? ` · ${poolHint}` : ""}
          {countdown ? ` · ${countdown}` : ""}
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${quotaBarColor(pct)}`}
          style={{ width: `${pct !== null ? Math.max(2, Math.min(100, pct)) : 0}%` }}
        />
      </div>
    </div>
  );
}

interface GoogleAccountsPanelProps {
  session?: StudioSession;
  eventVersion?: number;
  onAccountsChanged?: () => void;
  onAccountsLoaded?: (snapshot: GoogleAccountsResponse) => void;
  onSessionRevoked?: (reason: string) => void;
}

export function GoogleAccountsPanel({
  session,
  eventVersion = 0,
  onAccountsChanged,
  onAccountsLoaded,
  onSessionRevoked,
}: GoogleAccountsPanelProps) {
  const [snapshot, setSnapshot] = useState<GoogleAccountsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Add account form
  const [addOpen, setAddOpen] = useState(false);
  const [newAccountId, setNewAccountId] = useState("");
  const [newAlias, setNewAlias] = useState("");

  // Edit account modal (alias + weekly reset anchor)
  const [editingAccount, setEditingAccount] = useState<GoogleAccountItem | null>(null);
  const [editAlias, setEditAlias] = useState("");
  const [editResetEnabled, setEditResetEnabled] = useState(false);
  const [editWeekday, setEditWeekday] = useState(4);
  const [editHour, setEditHour] = useState(23);

  // Headless OAuth login modal
  const [loginFlow, setLoginFlow] = useState<GoogleLoginFlowState | null>(null);
  const [loginCodeInput, setLoginCodeInput] = useState("");
  const [loginSubmitting, setLoginSubmitting] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [copiedAuthUrl, setCopiedAuthUrl] = useState(false);
  const [flowRemainingSec, setFlowRemainingSec] = useState(300);
  const activeFlowIdRef = useRef<string | null>(null);

  const canEdit = Boolean(
    snapshot?.can_edit && (!session || session.role === "admin"),
  );

  const handleApiError = useCallback(
    (err: unknown, fallback: string): string => {
      if (err instanceof StudioApiError && (err.status === 401 || (err.status === 403 && err.source === "studio_auth"))) {
        if (onSessionRevoked && err.status === 401) {
          onSessionRevoked(err.message || "会话已失效，请重新登录");
        }
      }
      return err instanceof Error ? err.message : fallback;
    },
    [onSessionRevoked],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchGoogleAccounts();
      setSnapshot(data);
      onAccountsLoaded?.(data);
    } catch (e) {
      setError(handleApiError(e, "加载 Google 多账号状态失败"));
    } finally {
      setLoading(false);
    }
  }, [handleApiError, onAccountsLoaded]);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  // Live 5-minute OAuth countdown
  useEffect(() => {
    if (!loginFlow || loginFlow.status !== "awaiting_code") {
      activeFlowIdRef.current = null;
      return;
    }
    activeFlowIdRef.current = loginFlow.flow_id;
    const totalSec = Math.max(
      1,
      Math.min(300, Math.round(loginFlow.expires_at - loginFlow.created_at) || 300),
    );
    const startedAtMs = Date.now();
    setFlowRemainingSec(totalSec);
    const timer = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - startedAtMs) / 1000);
      const rem = Math.max(0, totalSec - elapsed);
      setFlowRemainingSec(rem);
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [loginFlow]);

  // Cancel lingering OAuth flow on unmount
  useEffect(() => {
    return () => {
      const fid = activeFlowIdRef.current;
      if (fid) {
        activeFlowIdRef.current = null;
        void cancelGoogleLoginFlow(fid).catch(() => {});
      }
    };
  }, []);

  const applySnapshot = useCallback(
    (nextSnap: GoogleAccountsResponse) => {
      setSnapshot(nextSnap);
      onAccountsLoaded?.(nextSnap);
      onAccountsChanged?.();
    },
    [onAccountsChanged, onAccountsLoaded],
  );

  const handleAddAccount = async () => {
    const aid = newAccountId.trim().toLowerCase();
    if (!ACCOUNT_ID_PATTERN.test(aid)) {
      setError("账号 ID 仅允许小写字母、数字、下划线或连字符（最长 48 位），如 ultra_main");
      return;
    }
    setBusyAction("add");
    setError(null);
    setNotice(null);
    try {
      const res = await addGoogleAccount({
        account_id: aid,
        alias: newAlias.trim() || undefined,
      });
      applySnapshot(res.snapshot);
      setNewAccountId("");
      setNewAlias("");
      setAddOpen(false);
      setNotice(`已添加账号槽位 ${aid}，可点击「登录授权」完成 OAuth 登录。`);
    } catch (e) {
      setError(handleApiError(e, "添加账号槽位失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleRefreshAll = async () => {
    setBusyAction("refresh_all");
    setError(null);
    setNotice(null);
    try {
      const res = await refreshAllGoogleAccountsQuota();
      applySnapshot(res.snapshot);
      const errCount = Object.keys(res.errors || {}).length;
      setNotice(
        errCount === 0
          ? `已刷新 ${res.refreshed.length} 个账号的套餐与配额状态。`
          : `已刷新 ${res.refreshed.length} 个账号，${errCount} 个账号刷新异常。`,
      );
    } catch (e) {
      setError(handleApiError(e, "批量刷新配额失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleActivate = async (accountId: string) => {
    setBusyAction(`activate:${accountId}`);
    setError(null);
    setNotice(null);
    try {
      const res = await activateGoogleAccount(accountId);
      applySnapshot(res.snapshot);
      const recycledCount = (res.recycle_results || []).filter((r) => r.ok).length;
      setNotice(
        `已切换活跃账号至 ${res.account.alias || accountId}` +
          (recycledCount > 0 ? `（已联动通知 ${recycledCount} 个 Bridge 节点温和回收）` : ""),
      );
    } catch (e) {
      setError(handleApiError(e, "切换活跃账号失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleRefreshOne = async (accountId: string) => {
    setBusyAction(`refresh:${accountId}`);
    setError(null);
    setNotice(null);
    try {
      const res = await refreshGoogleAccountQuota(accountId);
      applySnapshot(res.snapshot);
      setNotice(`已更新 ${accountId} 的套餐与实时配额。`);
    } catch (e) {
      setError(handleApiError(e, "刷新单账号配额失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleLogoutOne = async (accountId: string) => {
    setBusyAction(`logout:${accountId}`);
    setError(null);
    setNotice(null);
    try {
      const res = await logoutGoogleAccount(accountId);
      applySnapshot(res.snapshot);
      setNotice(`已清除账号 ${accountId} 的本地 OAuth 凭据。`);
    } catch (e) {
      setError(handleApiError(e, "登出账号失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeleteOne = async (accountId: string) => {
    setBusyAction(`delete:${accountId}`);
    setError(null);
    setNotice(null);
    try {
      const res = await deleteGoogleAccount(accountId);
      applySnapshot(res.snapshot);
      setNotice(`已删除账号槽位 ${accountId}。`);
    } catch (e) {
      setError(handleApiError(e, "删除账号失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const openEditModal = (acct: GoogleAccountItem) => {
    setEditingAccount(acct);
    setEditAlias(acct.alias || acct.account_id);
    if (acct.weekly_reset_utc) {
      setEditResetEnabled(true);
      setEditWeekday(acct.weekly_reset_utc.weekday);
      setEditHour(acct.weekly_reset_utc.hour);
    } else {
      setEditResetEnabled(false);
      setEditWeekday(4);
      setEditHour(23);
    }
  };

  const handleSaveEdit = async () => {
    if (!editingAccount) return;
    setBusyAction(`edit:${editingAccount.account_id}`);
    setError(null);
    setNotice(null);
    try {
      const payload: {
        alias?: string;
        weekly_reset_utc_weekday?: number;
        weekly_reset_utc_hour?: number;
      } = {};
      if (editAlias.trim()) {
        payload.alias = editAlias.trim();
      }
      if (editResetEnabled) {
        payload.weekly_reset_utc_weekday = editWeekday;
        payload.weekly_reset_utc_hour = editHour;
      }
      const res = await updateGoogleAccount(editingAccount.account_id, payload);
      applySnapshot(res.snapshot);
      setEditingAccount(null);
      setNotice(`已保存账号 ${editingAccount.account_id} 的配置。`);
    } catch (e) {
      setError(handleApiError(e, "更新账号配置失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleStartLogin = async (acct: GoogleAccountItem) => {
    setBusyAction(`login:${acct.account_id}`);
    setError(null);
    setNotice(null);
    setLoginError(null);
    setLoginCodeInput("");
    setCopiedAuthUrl(false);
    try {
      const res = await startGoogleAccountLogin(acct.account_id, { alias: acct.alias });
      setLoginFlow(res.flow);
    } catch (e) {
      setError(handleApiError(e, "启动无头 OAuth 登录失败"));
    } finally {
      setBusyAction(null);
    }
  };

  const handleCloseLoginModal = useCallback(async () => {
    const flow = loginFlow;
    setLoginFlow(null);
    setLoginCodeInput("");
    setLoginError(null);
    setCopiedAuthUrl(false);
    activeFlowIdRef.current = null;
    if (flow && flow.status === "awaiting_code") {
      try {
        await cancelGoogleLoginFlow(flow.flow_id);
      } catch {
        // Ignore cleanup errors
      }
    }
  }, [loginFlow]);

  const handleSubmitLoginCode = async () => {
    if (!loginFlow) return;
    const raw = loginCodeInput.trim();
    if (!raw) {
      setLoginError("请粘贴授权码或完整的官方回调 URL（https://antigravity.google/oauth-callback?...）");
      return;
    }
    setLoginSubmitting(true);
    setLoginError(null);
    try {
      const res = await submitGoogleLoginCode(loginFlow.flow_id, raw);
      activeFlowIdRef.current = null;
      if (res.snapshot) {
        applySnapshot(res.snapshot);
      } else {
        await load();
      }
      setLoginFlow(null);
      setLoginCodeInput("");
      setNotice(`账号 ${loginFlow.account_id} 已完成无头 OAuth 登录授权。`);
    } catch (e) {
      setLoginError(handleApiError(e, "提交 OAuth 授权码失败"));
    } finally {
      setLoginSubmitting(false);
    }
  };

  const handleCopyAuthUrl = async () => {
    if (!loginFlow?.auth_url) return;
    try {
      await navigator.clipboard.writeText(loginFlow.auth_url);
      setCopiedAuthUrl(true);
      window.setTimeout(() => setCopiedAuthUrl(false), 1800);
    } catch {
      setCopiedAuthUrl(false);
    }
  };

  const tiers: PlanTierQuotaSummary[] = snapshot?.by_plan?.tiers || [];
  const accounts: GoogleAccountItem[] = snapshot?.accounts || [];
  const recClaudeGpt = snapshot?.recommendation?.claude_gpt?.recommended || null;
  const recGemini = snapshot?.recommendation?.gemini?.recommended || null;
  const activeId = snapshot?.active_account_id || null;
  const switchSuggestion =
    recClaudeGpt && recClaudeGpt.account_id !== activeId
      ? { groupLabel: "Claude & GPT", target: recClaudeGpt, reason: snapshot?.recommendation?.claude_gpt?.reason || "" }
      : recGemini && recGemini.account_id !== activeId
        ? { groupLabel: "Gemini", target: recGemini, reason: snapshot?.recommendation?.gemini?.reason || "" }
        : null;

  return (
    <section className="space-y-4">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-300">
            <Users className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-100">
                Google 多账号与多套餐额度池
              </h3>
              {snapshot && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  {snapshot.by_plan.total_unique_accounts} 个独立账号
                  {snapshot.by_plan.duplicate_slot_count > 0
                    ? ` · 已去重 ${snapshot.by_plan.duplicate_slot_count} 槽位`
                    : ""}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              参考 T3 Code 无头 PKCE 登录与凭据指纹去重 · 按 Ultra / Pro / Enterprise / Free 独立统计额度
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {canEdit && (
            <>
              <button
                type="button"
                onClick={() => setAddOpen((v) => !v)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 hover:bg-sky-500/25 px-3 py-1.5 text-xs font-medium text-sky-200 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                添加账号
              </button>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void handleRefreshAll()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${busyAction === "refresh_all" ? "animate-spin" : ""}`}
                />
                全部刷新
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-2.5 py-1.5 text-xs text-slate-300 cursor-pointer"
            title="重新拉取账号快照"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200 flex items-center justify-between gap-2">
          <span>{error}</span>
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
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 text-xs text-emerald-200 flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
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

      {/* Inline Add Account Form (Admin Only) */}
      {canEdit && addOpen && (
        <div className="rounded-xl border border-sky-500/30 bg-slate-900/90 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">新增 Google 账号槽位</span>
            <button
              type="button"
              onClick={() => setAddOpen(false)}
              className="text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">
                账号 ID（小写字母/数字/_/-）
              </label>
              <input
                type="text"
                value={newAccountId}
                onChange={(e) => setNewAccountId(e.target.value)}
                placeholder="例如 ultra_backup"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">显示别名（可选）</label>
              <input
                type="text"
                value={newAlias}
                onChange={(e) => setNewAlias(e.target.value)}
                placeholder="例如 Ultra 备用号"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>
            <div className="flex items-end gap-2">
              <button
                type="button"
                disabled={busyAction === "add"}
                onClick={() => void handleAddAccount()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                {busyAction === "add" ? "创建中…" : "确认创建"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Smart Switch Recommendation Banner */}
      {switchSuggestion && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 text-xs text-amber-100">
            <Sparkles className="w-4 h-4 text-amber-300 shrink-0" />
            <div>
              <span className="font-semibold">智能切换推荐（{switchSuggestion.groupLabel}）：</span>
              <span>
                当前更充裕账号为{" "}
                <strong className="font-mono text-amber-200">
                  {switchSuggestion.target.alias}
                </strong>{" "}
                ({switchSuggestion.target.plan_label})
              </span>
              {switchSuggestion.reason && (
                <span className="text-amber-200/80 ml-1.5">· {switchSuggestion.reason}</span>
              )}
            </div>
          </div>
          {canEdit && (
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleActivate(switchSuggestion.target.account_id)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-400/40 px-3 py-1 text-xs font-medium text-amber-100 cursor-pointer"
            >
              <UserCheck className="w-3.5 h-3.5" />
              切换到 {switchSuggestion.target.alias}
            </button>
          )}
        </div>
      )}

      {/* Multi-Plan Deduplicated Pool Summary Cards */}
      {tiers.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {tiers.map((tier) => (
            <div
              key={tier.plan_tier}
              className="rounded-xl border border-slate-800 bg-slate-900/75 p-4 space-y-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${planBadgeStyle(
                    tier.plan_tier,
                  )}`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  {tier.plan_label}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  独立账号 ×{tier.unique_accounts}
                  {tier.duplicate_slots > 0 ? ` (去重 ${tier.duplicate_slots})` : ""}
                </span>
              </div>
              <div className="space-y-2">
                <QuotaMiniBar
                  label="Gemini 5h"
                  pct={tier.pools.gemini_5h.avg_remaining_pct}
                  resetAt={tier.pools.gemini_5h.earliest_reset_at}
                  poolHint={
                    tier.unique_accounts > 1 && tier.pools.gemini_5h.accounts_with_data > 0
                      ? `池 ${(tier.pools.gemini_5h.total_remaining_fraction * 100).toFixed(0)}%`
                      : undefined
                  }
                />
                <QuotaMiniBar
                  label="Gemini 周额度"
                  pct={tier.pools.gemini_weekly.avg_remaining_pct}
                  resetAt={tier.pools.gemini_weekly.earliest_reset_at}
                  poolHint={
                    tier.unique_accounts > 1 && tier.pools.gemini_weekly.accounts_with_data > 0
                      ? `池 ${(tier.pools.gemini_weekly.total_remaining_fraction * 100).toFixed(0)}%`
                      : undefined
                  }
                />
                <QuotaMiniBar
                  label="Claude / GPT 5h"
                  pct={tier.pools.claude_gpt_5h.avg_remaining_pct}
                  resetAt={tier.pools.claude_gpt_5h.earliest_reset_at}
                  poolHint={
                    tier.unique_accounts > 1 && tier.pools.claude_gpt_5h.accounts_with_data > 0
                      ? `池 ${(tier.pools.claude_gpt_5h.total_remaining_fraction * 100).toFixed(0)}%`
                      : undefined
                  }
                />
                <QuotaMiniBar
                  label="Claude / GPT 周额度"
                  pct={tier.pools.claude_gpt_weekly.avg_remaining_pct}
                  resetAt={tier.pools.claude_gpt_weekly.earliest_reset_at}
                  poolHint={
                    tier.unique_accounts > 1 && tier.pools.claude_gpt_weekly.accounts_with_data > 0
                      ? `池 ${(tier.pools.claude_gpt_weekly.total_remaining_fraction * 100).toFixed(0)}%`
                      : undefined
                  }
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Account List Cards */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <span className="text-sm font-semibold text-slate-100">已纳管 Google 账号列表</span>
          <span className="text-[11px] text-slate-400">
            {canEdit ? "管理员可新增、授权、切换与校准每周重置锚点" : "只读视图（仅管理员可执行账号变更）"}
          </span>
        </div>

        {accounts.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            {loading ? "正在加载账号状态…" : "尚未添加任何 Google 账号槽位"}
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {accounts.map((acct) => {
              const qs = acct.quota_summary;
              const isBusyThis = busyAction !== null && busyAction.endsWith(`:${acct.account_id}`);
              return (
                <div
                  key={acct.account_id}
                  className={`p-4 space-y-3 transition-colors ${
                    acct.is_active ? "bg-sky-500/[0.05]" : ""
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-100">
                          {acct.alias || acct.account_id}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          @{acct.account_id}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${planBadgeStyle(
                            acct.plan_tier,
                          )}`}
                        >
                          {acct.plan_label}
                        </span>
                        {acct.is_active && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                            <CheckCircle2 className="w-3 h-3" />
                            当前活跃
                          </span>
                        )}
                        {acct.is_duplicate && (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/35"
                            title={`与 ${acct.duplicate_of} 共享同一 Google 凭据指纹，多套餐汇总已自动去重`}
                          >
                            <AlertTriangle className="w-3 h-3" />
                            重复账号 · 同 {acct.duplicate_of}
                          </span>
                        )}
                        {acct.status !== "ready" && (
                          <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                            {acct.status === "pending_login"
                              ? "待登录授权"
                              : acct.status === "logged_out"
                                ? "已登出"
                                : acct.status}
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400 font-mono">
                        <span>{acct.email_masked || "未绑定邮箱（待授权）"}</span>
                        {acct.weekly_reset_utc && (
                          <span className="text-slate-500">
                            周重置锚点: UTC {WEEKDAY_LABELS[acct.weekly_reset_utc.weekday % 7]}{" "}
                            {String(acct.weekly_reset_utc.hour).padStart(2, "0")}:
                            {String(acct.weekly_reset_utc.minute || 0).padStart(2, "0")}
                          </span>
                        )}
                        {acct.last_checked_at && (
                          <span className="text-slate-500">
                            更新于 {acct.last_checked_at.replace("T", " ").replace("Z", " UTC")}
                          </span>
                        )}
                      </div>
                      {acct.last_error && (
                        <div className="text-[11px] text-rose-300">{acct.last_error}</div>
                      )}
                    </div>

                    {/* Admin Controls */}
                    {canEdit && (
                      <div className="flex flex-wrap items-center gap-1.5">
                        {!acct.is_active && acct.status === "ready" && (
                          <button
                            type="button"
                            disabled={busyAction !== null}
                            onClick={() => void handleActivate(acct.account_id)}
                            className="inline-flex items-center gap-1 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-2.5 py-1 text-xs font-medium text-white cursor-pointer"
                          >
                            <UserCheck className="w-3.5 h-3.5" />
                            设为活跃
                          </button>
                        )}
                        {acct.status === "ready" && (
                          <button
                            type="button"
                            disabled={busyAction !== null}
                            onClick={() => void handleRefreshOne(acct.account_id)}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 px-2.5 py-1 text-xs text-slate-200 cursor-pointer"
                          >
                            <RefreshCw className={`w-3 h-3 ${isBusyThis ? "animate-spin" : ""}`} />
                            刷新额度
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onClick={() => void handleStartLogin(acct)}
                          className="inline-flex items-center gap-1 rounded-lg border border-sky-500/40 bg-sky-500/10 hover:bg-sky-500/20 disabled:opacity-50 px-2.5 py-1 text-xs text-sky-200 cursor-pointer"
                        >
                          <KeyRound className="w-3 h-3" />
                          {acct.status === "ready" ? "重新授权" : "登录授权"}
                        </button>
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onClick={() => openEditModal(acct)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 px-2 py-1 text-xs text-slate-300 cursor-pointer"
                          title="编辑别名与每周重置锚点"
                        >
                          <Pencil className="w-3 h-3" />
                          编辑
                        </button>
                        {acct.status === "ready" && (
                          <button
                            type="button"
                            disabled={busyAction !== null}
                            onClick={() => void handleLogoutOne(acct.account_id)}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-amber-500/15 hover:text-amber-200 disabled:opacity-50 px-2 py-1 text-xs text-slate-400 cursor-pointer"
                            title="清除本地 OAuth Token"
                          >
                            <LogOut className="w-3 h-3" />
                            登出
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onClick={() => void handleDeleteOne(acct.account_id)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 hover:bg-rose-500/15 hover:text-rose-300 disabled:opacity-50 px-2 py-1 text-xs text-slate-400 cursor-pointer"
                          title="删除账号槽位"
                        >
                          <Trash2 className="w-3 h-3" />
                          删除
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Per-Account Quota Bars */}
                  {qs.has_quota && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
                      <QuotaMiniBar
                        label="Gemini 5h"
                        pct={qs.gemini_5h_pct}
                        resetAt={qs.gemini_5h_reset_at}
                      />
                      <QuotaMiniBar
                        label="Gemini 周额度"
                        pct={qs.gemini_weekly_pct}
                        resetAt={qs.gemini_weekly_reset_at}
                      />
                      <QuotaMiniBar
                        label="Claude / GPT 5h"
                        pct={qs.claude_gpt_5h_pct}
                        resetAt={qs.claude_gpt_5h_reset_at}
                      />
                      <QuotaMiniBar
                        label="Claude / GPT 周额度"
                        pct={qs.claude_gpt_weekly_pct}
                        resetAt={qs.claude_gpt_weekly_reset_at}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Edit Alias & Weekly Reset Anchor Modal */}
      {editingAccount && (
        <div className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-slate-100">
                编辑账号 · <span className="font-mono text-sky-300">{editingAccount.account_id}</span>
              </h4>
              <button
                type="button"
                onClick={() => setEditingAccount(null)}
                className="text-slate-400 hover:text-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">显示别名</label>
                <input
                  type="text"
                  value={editAlias}
                  onChange={(e) => setEditAlias(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editResetEnabled}
                  onChange={(e) => setEditResetEnabled(e.target.checked)}
                  className="rounded border-slate-600 bg-slate-950"
                />
                为该账号配置独立每周重置锚点（UTC，不影响全局默认）
              </label>

              {editResetEnabled && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">UTC 星期</label>
                    <select
                      value={editWeekday}
                      onChange={(e) => setEditWeekday(Number(e.target.value))}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 text-xs text-slate-100"
                    >
                      {WEEKDAY_LABELS.map((lbl, idx) => (
                        <option key={lbl} value={idx}>
                          {lbl} (weekday={idx})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">UTC 小时 (0-23)</label>
                    <input
                      type="number"
                      min={0}
                      max={23}
                      value={editHour}
                      onChange={(e) =>
                        setEditHour(Math.max(0, Math.min(23, Number(e.target.value) || 0)))
                      }
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setEditingAccount(null)}
                className="rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={busyAction !== null}
                onClick={() => void handleSaveEdit()}
                className="rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 px-4 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                保存配置
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Headless OAuth Login Modal (T3 Code Parity) */}
      {loginFlow && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-sky-400" />
                <h4 className="text-sm font-semibold text-slate-100">
                  无头 Google OAuth 授权 ·{" "}
                  <span className="font-mono text-sky-300">{loginFlow.account_id}</span>
                </h4>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-300">
                  倒计时 {formatCountdownSeconds(flowRemainingSec)}
                </span>
                <button
                  type="button"
                  onClick={() => void handleCloseLoginModal()}
                  className="text-slate-400 hover:text-slate-100 cursor-pointer"
                  title="关闭并自动取消授权流"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <p>
                1. 点击下方链接在新标签页完成 Google 账号登录授权；2. 授权后会跳转至{" "}
                <code className="text-sky-300">https://antigravity.google/oauth-callback?...</code>
                ，将完整回调 URL 或授权码粘贴到下方提交。
              </p>
              {loginFlow.auth_url && (
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3 space-y-2">
                  <div className="text-[11px] font-mono text-slate-400 break-all max-h-20 overflow-y-auto">
                    {loginFlow.auth_url}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => void handleCopyAuthUrl()}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2.5 py-1 text-xs text-slate-200 cursor-pointer"
                    >
                      {copiedAuthUrl ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          已复制链接
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          复制授权链接
                        </>
                      )}
                    </button>
                    <a
                      href={loginFlow.auth_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1 text-xs font-medium text-white"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      新标签打开授权
                    </a>
                  </div>
                </div>
              )}
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs text-slate-300">
                粘贴授权码（code）或完整回调 URL
              </label>
              <textarea
                rows={3}
                value={loginCodeInput}
                onChange={(e) => setLoginCodeInput(e.target.value)}
                placeholder="https://antigravity.google/oauth-callback?state=...&code=..."
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
              />
              {loginError && (
                <div className="text-xs text-rose-300">{loginError}</div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => void handleCloseLoginModal()}
                className="rounded-lg border border-slate-700 bg-slate-800/70 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消登录
              </button>
              <button
                type="button"
                disabled={loginSubmitting || flowRemainingSec <= 0}
                onClick={() => void handleSubmitLoginCode()}
                className="rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                {loginSubmitting ? "验证交换中…" : "提交完成登录"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
