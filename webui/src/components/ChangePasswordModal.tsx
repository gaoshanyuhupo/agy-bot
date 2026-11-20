import { type FormEvent, useState } from "react";
import { AlertTriangle, CheckCircle2, KeyRound, Loader2, LogOut, ShieldAlert, X } from "lucide-react";
import { StudioApiError } from "../api";
import type { StudioSession } from "../types";

interface ChangePasswordModalProps {
  session: StudioSession;
  forced: boolean;
  onSubmitPasswordChange: (currentPassword: string, newPassword: string) => Promise<void>;
  onClose?: () => void;
  onLogout?: () => void;
}

export function ChangePasswordModal({
  session,
  forced,
  onSubmitPasswordChange,
  onClose,
  onLogout,
}: ChangePasswordModalProps) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const displayUsername = session.username || session.user?.username || "";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!currentPassword) {
      setError("请输入当前密码");
      return;
    }
    if (newPassword.length < 8 || newPassword.length > 128) {
      setError("新密码长度须在 8 到 128 个字符之间");
      return;
    }
    if (!newPassword.trim()) {
      setError("新密码不能为纯空白字符");
      return;
    }
    if (newPassword === currentPassword) {
      setError("新密码不得与当前密码相同");
      return;
    }
    if (
      displayUsername &&
      newPassword.trim().toLowerCase() === displayUsername.trim().toLowerCase()
    ) {
      setError("新密码不得与用户名相同");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("两次输入的新密码不一致");
      return;
    }

    setSubmitting(true);
    try {
      await onSubmitPasswordChange(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      if (!forced) {
        setSuccessMsg("密码修改成功，其他已登录会话已自动下线");
        window.setTimeout(() => {
          onClose?.();
        }, 900);
      }
    } catch (err) {
      if (err instanceof StudioApiError && err.status === 429 && err.retryAfter) {
        setError(`${err.message}（约 ${err.retryAfter} 秒后可重试）`);
      } else {
        setError(err instanceof Error ? err.message : "密码修改失败，请重试");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const card = (
    <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/95 backdrop-blur-xl p-6 shadow-2xl">
      <div className="flex items-start gap-3 mb-5">
        <div
          className={`h-10 w-10 shrink-0 rounded-xl border flex items-center justify-center ${
            forced
              ? "bg-amber-500/15 border-amber-500/30 text-amber-400"
              : "bg-sky-500/15 border-sky-500/30 text-sky-400"
          }`}
        >
          {forced ? <ShieldAlert className="w-5 h-5" /> : <KeyRound className="w-5 h-5" />}
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-base font-semibold tracking-tight text-slate-100">
            {forced ? "修改初始密码" : "修改登录密码"}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
            {forced
              ? "首次登录或管理员重置后，须先设置新的安全密码方可进入 AGY Studio 工作台。"
              : "修改成功后将轮换当前会话并立即驱逐该账号在其他设备上的会话。"}
          </p>
        </div>
        {!forced && onClose && (
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            aria-label="关闭"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 flex items-start gap-2.5 text-sm text-rose-200">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">{error}</div>
        </div>
      )}

      {successMsg && (
        <div className="mb-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 flex items-start gap-2.5 text-sm text-emerald-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">{successMsg}</div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-3.5">
        {displayUsername && (
          <div>
            <label
              htmlFor="studio-chg-username"
              className="block text-xs font-medium text-slate-400 mb-1"
            >
              当前账号
            </label>
            <input
              id="studio-chg-username"
              name="username"
              type="text"
              readOnly
              tabIndex={-1}
              autoComplete="username"
              value={displayUsername}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/60 px-3.5 py-2 text-sm text-slate-400 font-mono"
            />
          </div>
        )}

        <div>
          <label
            htmlFor="studio-chg-current"
            className="block text-xs font-medium text-slate-300 mb-1"
          >
            当前密码
          </label>
          <input
            id="studio-chg-current"
            name="current-password"
            type="password"
            required
            maxLength={128}
            autoComplete="current-password"
            autoFocus
            disabled={submitting}
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="请输入当前密码"
            className="w-full rounded-xl border border-slate-700/80 bg-slate-950/80 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 disabled:opacity-60"
          />
        </div>

        <div>
          <label
            htmlFor="studio-chg-new"
            className="block text-xs font-medium text-slate-300 mb-1"
          >
            新密码（8–128 位，不可与用户名或原密码相同）
          </label>
          <input
            id="studio-chg-new"
            name="new-password"
            type="password"
            required
            minLength={8}
            maxLength={128}
            autoComplete="new-password"
            disabled={submitting}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="请输入新密码"
            className="w-full rounded-xl border border-slate-700/80 bg-slate-950/80 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 disabled:opacity-60"
          />
        </div>

        <div>
          <label
            htmlFor="studio-chg-confirm"
            className="block text-xs font-medium text-slate-300 mb-1"
          >
            确认新密码
          </label>
          <input
            id="studio-chg-confirm"
            name="confirm-password"
            type="password"
            required
            minLength={8}
            maxLength={128}
            autoComplete="new-password"
            disabled={submitting}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="请再次输入新密码"
            className="w-full rounded-xl border border-slate-700/80 bg-slate-950/80 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 disabled:opacity-60"
          />
        </div>

        <div className="pt-1 flex items-center gap-2.5">
          {!forced && onClose && (
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="flex-1 rounded-xl border border-slate-700 hover:bg-slate-800 text-slate-300 text-sm font-medium py-2.5 px-4 transition-colors cursor-pointer"
            >
              取消
            </button>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="flex-1 inline-flex items-center justify-center gap-2 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white text-sm font-medium py-2.5 px-4 transition-colors cursor-pointer"
          >
            {submitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                提交中…
              </>
            ) : (
              "确认修改密码"
            )}
          </button>
        </div>
      </form>

      {forced && onLogout && (
        <button
          type="button"
          onClick={onLogout}
          disabled={submitting}
          className="mt-3 w-full inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-800 hover:bg-slate-800 py-2 text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
        >
          <LogOut className="w-3.5 h-3.5" />
          退出登录
        </button>
      )}
    </div>
  );

  if (forced) {
    return (
      <div className="min-h-screen w-full bg-slate-950 flex items-center justify-center p-4">
        {card}
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label="修改登录密码"
    >
      {card}
    </div>
  );
}
