import { type FormEvent, useState } from "react";
import { AlertTriangle, KeyRound, Loader2, Lock, Send, ShieldCheck, User } from "lucide-react";
import { StudioApiError, authLogin } from "../api";
import type { AuthMode, StudioSession } from "../types";

interface LoginViewProps {
  authMode: AuthMode;
  loading: boolean;
  isMagicFlow: boolean;
  isTelegramEnv: boolean;
  error: string | null;
  onLoginSuccess: (session: StudioSession) => void;
  onRetryTelegram?: () => void;
}

export function LoginView({
  authMode,
  loading,
  isMagicFlow,
  isTelegramEnv,
  error,
  onLoginSuccess,
  onRetryTelegram,
}: LoginViewProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const cleanUser = username.trim();
    if (!cleanUser || !password) {
      setFormError("请输入账号和密码");
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      const sess = await authLogin(cleanUser, password);
      setPassword("");
      onLoginSuccess(sess);
    } catch (err) {
      if (err instanceof StudioApiError && err.status === 429 && err.retryAfter) {
        setFormError(`${err.message}（约 ${err.retryAfter} 秒后可重试）`);
      } else {
        setFormError(err instanceof Error ? err.message : "登录失败，请重试");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const displayError = formError || error;

  return (
    <div className="min-h-screen w-full bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-xl p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-5">
          <div className="h-10 w-10 rounded-xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-slate-100">
              AGY Studio
            </h1>
            <p className="text-xs text-slate-400">
              {authMode === "password"
                ? "零信任账号密码鉴权 · 只读观测与同域浏览器工作台"
                : "零信任双轨鉴权 · Phase 1 只读观测与同域浏览器工作台"}
            </p>
          </div>
        </div>

        {loading ? (
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5 flex flex-col items-center gap-3 text-center">
            <Loader2 className="w-6 h-6 text-sky-400 animate-spin" />
            <p className="text-sm text-slate-200 font-medium">
              {authMode === "legacy" && isMagicFlow
                ? "正在验证并消费一次性桌面登录令牌…"
                : authMode === "legacy" && isTelegramEnv
                  ? "正在通过 Telegram Mini App 校验身份签名…"
                  : "正在检查登录会话状态…"}
            </p>
            <p className="text-xs text-slate-500">
              所有会话均受 HttpOnly 安全 Cookie 与实时 RBAC 保护
            </p>
          </div>
        ) : authMode === "password" ? (
          <>
            {displayError && (
              <div className="mb-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 flex items-start gap-2.5 text-sm text-rose-200">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">{displayError}</div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label
                  htmlFor="studio-login-username"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  账号
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    id="studio-login-username"
                    name="username"
                    type="text"
                    required
                    maxLength={64}
                    autoComplete="username"
                    autoFocus
                    disabled={submitting}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="请输入账号"
                    className="w-full rounded-xl border border-slate-700/80 bg-slate-950/80 pl-9 pr-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 disabled:opacity-60"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="studio-login-password"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  密码
                </label>
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    id="studio-login-password"
                    name="password"
                    type="password"
                    required
                    maxLength={128}
                    autoComplete="current-password"
                    disabled={submitting}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="请输入密码"
                    className="w-full rounded-xl border border-slate-700/80 bg-slate-950/80 pl-9 pr-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 disabled:opacity-60"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white text-sm font-medium py-2.5 px-4 transition-colors cursor-pointer"
              >
                {submitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    正在验证…
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    安全登录
                  </>
                )}
              </button>
            </form>

            <p className="mt-4 text-[11px] text-slate-500 text-center leading-relaxed">
              未认证访问不返回任何业务数据 · 首次登录需修改初始密码 · 权限撤销实时生效
            </p>
          </>
        ) : (
          <>
            {displayError && (
              <div className="mb-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 flex items-start gap-2.5 text-sm text-rose-200">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">{displayError}</div>
              </div>
            )}

            <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                <Lock className="w-3.5 h-3.5 text-sky-400" />
                桌面端安全登录指引
              </div>
              <ol className="space-y-2.5 text-sm text-slate-300 leading-relaxed list-decimal list-inside">
                <li>
                  打开已授权的 Telegram 机器人<strong className="text-slate-100">私聊窗口</strong>
                  （群聊禁止签发登录链接）。
                </li>
                <li>
                  发送{" "}
                  <code className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-xs">
                    /webui
                  </code>{" "}
                  或{" "}
                  <code className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-xs">
                    /studio
                  </code>{" "}
                  获取 60 秒单次有效登录链接。
                </li>
                <li>
                  在桌面浏览器中打开该链接，即可进入与自身 RBAC 角色一致的工作台。
                </li>
              </ol>
            </div>

            {isTelegramEnv && onRetryTelegram && (
              <button
                type="button"
                onClick={onRetryTelegram}
                className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium py-2.5 px-4 transition-colors cursor-pointer"
              >
                <Send className="w-4 h-4" />
                使用 Telegram Mini App 重新验证
              </button>
            )}

            <p className="mt-4 text-[11px] text-slate-500 text-center leading-relaxed">
              未认证访问不返回任何业务数据 · 双轨鉴权互不回退 · 权限撤销实时生效
            </p>
          </>
        )}
      </div>
    </div>
  );
}
