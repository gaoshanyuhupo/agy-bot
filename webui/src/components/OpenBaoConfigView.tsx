import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CreditCard,
  Eye,
  EyeOff,
  HardDrive,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  StudioApiError,
  fetchOpenBaoConfig,
  testOpenBaoConnection,
  updateOpenBaoConfig,
} from "../api";
import type {
  NavTab,
  OpenBaoAuthMode,
  OpenBaoConfigResponse,
  OpenBaoTestResponse,
  StudioSession,
} from "../types";

interface OpenBaoConfigViewProps {
  session?: StudioSession;
  onNavigate?: (tab: NavTab) => void;
  onSessionRevoked?: (reason: string) => void;
}

const AUTH_MODE_OPTIONS: {
  id: OpenBaoAuthMode;
  label: string;
  desc: string;
}[] = [
  {
    id: "host_card",
    label: "本机 OpenBao 卡",
    desc: "自动复用宿主本机 0600 卡片配置（AppRole + 缓存 Token）",
  },
  {
    id: "token",
    label: "Client Token",
    desc: "手动填入专用 Token，仅加密/0600 保存于服务端且不回显",
  },
  {
    id: "approle",
    label: "AppRole",
    desc: "手动配置自定义 Role ID 与 Secret ID，自动换取租约 Token",
  },
];

function cleanPathSegmentPreview(val: string, fallback: string): string {
  const cleaned = val.trim().replace(/^\/+|\/+$/g, "");
  return cleaned || fallback;
}

export function OpenBaoConfigView({
  session,
  onNavigate,
  onSessionRevoked,
}: OpenBaoConfigViewProps) {
  const isReadonly = !session || session.role !== "admin";

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [config, setConfig] = useState<OpenBaoConfigResponse | null>(null);
  const [testResult, setTestResult] = useState<OpenBaoTestResponse | null>(null);

  // Editable form state (transient secrets never stored in localStorage)
  const [enabled, setEnabled] = useState(true);
  const [addr, setAddr] = useState("");
  const [authMode, setAuthMode] = useState<OpenBaoAuthMode>("host_card");
  const [authLabel, setAuthLabel] = useState("");
  const [kvMount, setKvMount] = useState("secret");
  const [gatewayPathPrefix, setGatewayPathPrefix] = useState("agy-studio/gateways");

  // Transient credential inputs (blank = keep existing host/stored credentials)
  const [tokenInput, setTokenInput] = useState("");
  const [roleIdInput, setRoleIdInput] = useState("");
  const [secretIdInput, setSecretIdInput] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [showSecretId, setShowSecretId] = useState(false);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const handleAuthErr = useCallback(
    (err: unknown) => {
      if (err instanceof StudioApiError && (err.status === 401 || err.status === 403)) {
        if (err.source === "studio_auth" && onSessionRevoked) {
          onSessionRevoked(err.message || "会话已失效，请重新登录");
          return true;
        }
      }
      return false;
    },
    [onSessionRevoked],
  );

  const hydrateFromServer = useCallback((data: OpenBaoConfigResponse) => {
    setConfig(data);
    setEnabled(Boolean(data.enabled));
    setAddr(data.addr || "");
    setAuthMode(
      data.auth_mode === "token" || data.auth_mode === "approle" ? data.auth_mode : "host_card",
    );
    setAuthLabel(data.auth_label || "");
    setKvMount(data.kv_mount || "secret");
    setGatewayPathPrefix(data.gateway_path_prefix || "agy-studio/gateways");
    // Always clear transient secret fields after loading/saving
    setTokenInput("");
    setRoleIdInput("");
    setSecretIdInput("");
    setShowToken(false);
    setShowSecretId(false);
  }, []);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchOpenBaoConfig();
      if (!mountedRef.current) return;
      hydrateFromServer(data);
    } catch (e) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "加载 OpenBao 配置失败");
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [handleAuthErr, hydrateFromServer]);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const previewMount = useMemo(() => cleanPathSegmentPreview(kvMount, "secret"), [kvMount]);
  const previewPrefix = useMemo(
    () => cleanPathSegmentPreview(gatewayPathPrefix, "agy-studio/gateways"),
    [gatewayPathPrefix],
  );

  const canEdit = Boolean(!isReadonly && (config ? config.can_edit : true));

  const handleTest = async () => {
    if (!canEdit || testing) return;
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const res = await testOpenBaoConnection({
        addr: addr.trim() || undefined,
        auth_mode: authMode,
      });
      if (!mountedRef.current) return;
      setTestResult(res);
    } catch (e) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "连通性测试失败");
      }
    } finally {
      if (mountedRef.current) {
        setTesting(false);
      }
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canEdit || saving) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await updateOpenBaoConfig({
        enabled,
        addr: addr.trim(),
        kv_mount: kvMount.trim(),
        gateway_path_prefix: gatewayPathPrefix.trim(),
        auth_mode: authMode,
        auth_label: authLabel.trim(),
        token: authMode === "token" && tokenInput.trim() ? tokenInput.trim() : undefined,
        role_id: authMode === "approle" && roleIdInput.trim() ? roleIdInput.trim() : undefined,
        secret_id:
          authMode === "approle" && secretIdInput.trim() ? secretIdInput.trim() : undefined,
      });
      if (!mountedRef.current) return;
      hydrateFromServer(updated);
      setNotice("已安全保存 OpenBao 配置（0600 权限原子写入，明文凭据绝不回显）。");
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        setError(err instanceof Error ? err.message : "保存 OpenBao 配置失败");
      }
    } finally {
      if (mountedRef.current) {
        setSaving(false);
      }
    }
  };

  const handleResetToHostAuto = async () => {
    if (!canEdit || resetting) return;
    setResetting(true);
    setError(null);
    setNotice(null);
    setTestResult(null);
    try {
      const updated = await updateOpenBaoConfig({ reset_to_host_auto: true });
      if (!mountedRef.current) return;
      hydrateFromServer(updated);
      setNotice(
        updated.source === "host_auto"
          ? "已恢复本机 OpenBao 自动探测配置。"
          : "已重置为自动探测模式（当前本机未检测到现成 OpenBao 配置）。",
      );
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        setError(err instanceof Error ? err.message : "恢复本机自动探测失败");
      }
    } finally {
      if (mountedRef.current) {
        setResetting(false);
      }
    }
  };

  const sourceBadge = useMemo(() => {
    if (!config) return null;
    if (config.source === "host_auto") {
      return {
        label: "已自动载入本机 OpenBao 配置",
        cls: "border-emerald-500/35 bg-emerald-500/15 text-emerald-300",
      };
    }
    if (config.source === "custom") {
      return {
        label: "已保存自定义配置",
        cls: "border-sky-500/35 bg-sky-500/15 text-sky-300",
      };
    }
    return {
      label: "未配置",
      cls: "border-amber-500/35 bg-amber-500/15 text-amber-300",
    };
  }, [config]);

  const openBaoActive = Boolean(config?.enabled && config?.credential_configured);

  return (
    <div className="p-4 sm:p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
              OpenBao 凭据托管
            </h2>
            {sourceBadge && (
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${sourceBadge.cls}`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-current" />
                {sourceBadge.label}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            启动时自动探测宿主本机 OpenBao 配置并回填非敏感参数，为「外部模型」等敏感凭据提供集中密码库转存能力。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void loadConfig()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新状态
          </button>
          {canEdit && (
            <button
              type="button"
              onClick={() => void handleTest()}
              disabled={testing || loading || !addr.trim()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 px-3 py-1.5 text-xs font-medium text-emerald-200 disabled:opacity-50 cursor-pointer"
            >
              {testing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Activity className="w-3.5 h-3.5" />
              )}
              测试连通性
            </button>
          )}
        </div>
      </div>

      {/* Readonly Notice */}
      {isReadonly && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 flex items-start gap-2.5 text-xs text-amber-200">
          <Lock className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
          <span>
            当前为只读权限（readonly）：已自动隐藏 OpenBao 服务地址与认证卡片标识，仅展示托管启用状态与脱敏摘要，禁止修改配置或发起连通性测试。
          </span>
        </div>
      )}

      {/* Feedback Banners */}
      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs text-rose-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            className="text-rose-300/80 hover:text-rose-100 cursor-pointer"
            aria-label="关闭错误提示"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {notice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs text-emerald-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{notice}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-emerald-300/80 hover:text-emerald-100 cursor-pointer"
            aria-label="关闭通知"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Connectivity Test Result */}
      {testResult && (
        <div
          className={`rounded-xl border px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs ${
            testResult.ok
              ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-200"
              : "border-amber-500/35 bg-amber-500/10 text-amber-200"
          }`}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            {testResult.ok ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
            )}
            <div className="space-y-1">
              <div className="font-medium">{testResult.message}</div>
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono opacity-90">
                <span>延迟 {testResult.latency_ms} ms</span>
                <span>·</span>
                <span>可达: {testResult.reachable ? "是" : "否"}</span>
                {testResult.initialized !== null && (
                  <>
                    <span>·</span>
                    <span>初始化: {testResult.initialized ? "是" : "否"}</span>
                  </>
                )}
                {testResult.sealed !== null && (
                  <>
                    <span>·</span>
                    <span>封印状态: {testResult.sealed ? "已封印" : "已解封"}</span>
                  </>
                )}
                {testResult.auth_verified !== null && testResult.auth_verified !== undefined && (
                  <>
                    <span>·</span>
                    <span>卡片鉴权: {testResult.auth_verified ? "通过" : "待刷新"}</span>
                  </>
                )}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setTestResult(null)}
            className="opacity-70 hover:opacity-100 cursor-pointer"
            aria-label="关闭测试结果"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {loading && !config ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-10 flex items-center justify-center gap-2 text-xs text-slate-400">
          <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
          正在探测本机 OpenBao 运行时配置…
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left 8 cols: Configuration Form */}
          <form
            onSubmit={(e) => void handleSave(e)}
            className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5 space-y-5"
          >
            {/* Enable Toggle */}
            <div className="flex items-center justify-between gap-4 pb-4 border-b border-slate-800/90">
              <div className="space-y-0.5">
                <div className="text-sm font-semibold text-slate-100">启用 OpenBao 密钥托管</div>
                <p className="text-xs text-slate-400">
                  开启后，通过 WebUI 提交的外部模型 API Key 与中转站凭据将优先自动转存至 OpenBao，不留明文在配置中。
                </p>
              </div>
              {canEdit ? (
                <button
                  type="button"
                  role="switch"
                  aria-checked={enabled}
                  onClick={() => setEnabled((v) => !v)}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer ${
                    enabled ? "bg-emerald-500" : "bg-slate-700"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              ) : (
                <span
                  className={`shrink-0 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                    enabled
                      ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                      : "bg-slate-800 text-slate-400 border border-slate-700"
                  }`}
                >
                  {enabled ? "已启用" : "未启用"}
                </span>
              )}
            </div>

            {/* Server Address */}
            <div className="space-y-1.5">
              <label
                htmlFor="openbao-addr"
                className="block text-xs font-medium text-slate-300"
              >
                OpenBao 服务地址 <span className="text-slate-500 font-normal">(`addr`)</span>
              </label>
              {canEdit ? (
                <input
                  id="openbao-addr"
                  type="url"
                  value={addr}
                  onChange={(e) => setAddr(e.target.value)}
                  placeholder="https://bao.example.com 或 http://127.0.0.1:8200"
                  className="w-full rounded-xl border border-slate-800 bg-slate-950/90 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/60"
                />
              ) : (
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 px-3.5 py-2 text-xs font-mono text-slate-500 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-slate-500" />
                  [只读模式已隐藏服务地址]
                </div>
              )}
              <p className="text-[11px] text-slate-500">
                仅允许 <code className="font-mono text-slate-400">https://</code> 或本机 loopback{" "}
                <code className="font-mono text-slate-400">http://127.0.0.1</code> /{" "}
                <code className="font-mono text-slate-400">http://localhost</code>。
              </p>
            </div>

            {/* Auth Mode Selector */}
            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">认证方式</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                {AUTH_MODE_OPTIONS.map((opt) => {
                  const selected = authMode === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      disabled={!canEdit}
                      onClick={() => setAuthMode(opt.id)}
                      className={`text-left rounded-xl border p-3 transition-colors space-y-1 ${
                        selected
                          ? "border-sky-500/50 bg-sky-500/12 text-sky-100"
                          : "border-slate-800 bg-slate-950/60 text-slate-300 hover:border-slate-700"
                      } ${canEdit ? "cursor-pointer" : "opacity-80 cursor-default"}`}
                    >
                      <div className="text-xs font-semibold flex items-center justify-between gap-1">
                        <span>{opt.label}</span>
                        {selected && <span className="w-2 h-2 rounded-full bg-sky-400" />}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-snug">{opt.desc}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Auth Label */}
            <div className="space-y-1.5">
              <label
                htmlFor="openbao-auth-label"
                className="block text-xs font-medium text-slate-300"
              >
                卡片 / 认证标识 <span className="text-slate-500 font-normal">（非敏感显示名称）</span>
              </label>
              {canEdit ? (
                <input
                  id="openbao-auth-label"
                  type="text"
                  value={authLabel}
                  onChange={(e) => setAuthLabel(e.target.value)}
                  placeholder="例如：本机 OpenBao 卡名或专用凭据备注"
                  maxLength={64}
                  className="w-full rounded-xl border border-slate-800 bg-slate-950/90 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/60"
                />
              ) : (
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 px-3.5 py-2 text-xs font-mono text-slate-500 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-slate-500" />
                  [只读模式已隐藏认证标识]
                </div>
              )}
            </div>

            {/* Credential Protection & Optional Update */}
            <div className="rounded-xl border border-slate-800/90 bg-slate-950/60 p-3.5 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs font-medium text-slate-200">
                  <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                  <span>凭据状态</span>
                </div>
                <span
                  className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium border ${
                    config?.credential_configured
                      ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                  }`}
                >
                  <Lock className="w-3 h-3" />
                  {config?.credential_configured ? "已保护就绪（不回显明文）" : "待配置凭据"}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed">
                {config?.credential_hint || "凭据仅存于服务端 0600 受保护文件中，前端永不落盘或回显明文。"}
              </p>

              {canEdit && authMode === "host_card" && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] text-slate-400">
                  当前采用「本机 OpenBao 卡」模式：后端自动读取宿主受保护的本地卡片凭据，无需在浏览器中输入任何明文密钥。
                </div>
              )}

              {canEdit && authMode === "token" && (
                <div className="space-y-1.5">
                  <label htmlFor="openbao-token" className="block text-[11px] text-slate-300">
                    Client Token <span className="text-slate-500">（留空即保留当前已存凭据）</span>
                  </label>
                  <div className="relative">
                    <input
                      id="openbao-token"
                      type={showToken ? "text" : "password"}
                      value={tokenInput}
                      onChange={(e) => setTokenInput(e.target.value)}
                      autoComplete="off"
                      placeholder={
                        config?.credential_configured
                          ? "••••••••••••（留空保持现有凭据不变）"
                          : "粘贴 OpenBao Client Token"
                      }
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 pr-9 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/60"
                    />
                    <button
                      type="button"
                      onClick={() => setShowToken((v) => !v)}
                      aria-label={showToken ? "隐藏 Token" : "显示 Token"}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              )}

              {canEdit && authMode === "approle" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label htmlFor="openbao-role-id" className="block text-[11px] text-slate-300">
                      Role ID <span className="text-slate-500">（留空保留现有）</span>
                    </label>
                    <input
                      id="openbao-role-id"
                      type="text"
                      value={roleIdInput}
                      onChange={(e) => setRoleIdInput(e.target.value)}
                      autoComplete="off"
                      placeholder={
                        config?.credential_configured ? "留空保持现有 Role ID" : "输入 AppRole Role ID"
                      }
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/60"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label htmlFor="openbao-secret-id" className="block text-[11px] text-slate-300">
                      Secret ID <span className="text-slate-500">（留空保留现有）</span>
                    </label>
                    <div className="relative">
                      <input
                        id="openbao-secret-id"
                        type={showSecretId ? "text" : "password"}
                        value={secretIdInput}
                        onChange={(e) => setSecretIdInput(e.target.value)}
                        autoComplete="off"
                        placeholder={
                          config?.credential_configured ? "••••••••（留空保持不变）" : "输入 AppRole Secret ID"
                        }
                        className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 pr-9 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/60"
                      />
                      <button
                        type="button"
                        onClick={() => setShowSecretId((v) => !v)}
                        aria-label={showSecretId ? "隐藏 Secret ID" : "显示 Secret ID"}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
                      >
                        {showSecretId ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* KV Mount & Gateway Path Prefix */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div className="space-y-1.5">
                <label htmlFor="openbao-kv-mount" className="block text-xs font-medium text-slate-300">
                  KV 引擎挂载点 <span className="text-slate-500 font-normal">(`kv_mount`)</span>
                </label>
                <input
                  id="openbao-kv-mount"
                  type="text"
                  value={kvMount}
                  disabled={!canEdit}
                  onChange={(e) => setKvMount(e.target.value)}
                  placeholder="secret"
                  className="w-full rounded-xl border border-slate-800 bg-slate-950/90 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 disabled:opacity-60 focus:outline-none focus:border-sky-500/60"
                />
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="openbao-gw-prefix"
                  className="block text-xs font-medium text-slate-300"
                >
                  外部模型存储前缀 <span className="text-slate-500 font-normal">(`gateway_path_prefix`)</span>
                </label>
                <input
                  id="openbao-gw-prefix"
                  type="text"
                  value={gatewayPathPrefix}
                  disabled={!canEdit}
                  onChange={(e) => setGatewayPathPrefix(e.target.value)}
                  placeholder="agy-studio/gateways"
                  className="w-full rounded-xl border border-slate-800 bg-slate-950/90 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 disabled:opacity-60 focus:outline-none focus:border-sky-500/60"
                />
              </div>
            </div>

            {/* Target Path Preview */}
            <div className="rounded-xl border border-sky-500/20 bg-sky-500/8 px-3.5 py-3 space-y-1.5">
              <div className="text-[11px] font-medium text-sky-300">实际目标存储路径预览</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="rounded-lg bg-slate-950/80 border border-slate-800/90 px-2.5 py-1.5 text-slate-200 truncate">
                  <span className="text-slate-500 mr-1.5">CLI:</span>
                  {previewPrefix}/&lt;gateway_id&gt;
                </div>
                <div className="rounded-lg bg-slate-950/80 border border-slate-800/90 px-2.5 py-1.5 text-slate-200 truncate">
                  <span className="text-slate-500 mr-1.5">KV v2:</span>
                  /v1/{previewMount}/data/{previewPrefix}/&lt;gateway_id&gt;
                </div>
              </div>
            </div>

            {/* Form Actions */}
            {canEdit && (
              <div className="pt-2 border-t border-slate-800/90 flex flex-wrap items-center justify-between gap-2.5">
                <button
                  type="button"
                  onClick={() => void handleResetToHostAuto()}
                  disabled={resetting || saving}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-2 text-xs text-slate-300 disabled:opacity-50 cursor-pointer"
                >
                  {resetting ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <RotateCcw className="w-3.5 h-3.5" />
                  )}
                  恢复本机自动探测
                </button>

                <button
                  type="submit"
                  disabled={saving || resetting}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-2 text-xs font-medium text-white disabled:opacity-50 cursor-pointer"
                >
                  {saving ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Save className="w-3.5 h-3.5" />
                  )}
                  保存 OpenBao 配置
                </button>
              </div>
            )}
          </form>

          {/* Right 4 cols: Secret Storage Priority & Quick Navigation */}
          <div className="lg:col-span-4 space-y-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 space-y-3.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                <Server className="w-4 h-4 text-sky-400" />
                密钥托管优先级联动
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                在「外部模型」粘贴明文 API Key 后，后端 <code className="font-mono text-slate-300">SecretStore</code> 将按以下优先级自动选择落盘引擎：
              </p>

              <div className="space-y-2">
                <div
                  className={`rounded-xl border p-3 space-y-1 ${
                    openBaoActive
                      ? "border-emerald-500/40 bg-emerald-500/10"
                      : "border-slate-800 bg-slate-950/60"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 text-xs font-medium">
                    <span className="text-slate-100">1. OpenBao 密码库</span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        openBaoActive
                          ? "bg-emerald-500/20 text-emerald-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {openBaoActive ? "当前生效" : "未激活"}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    配置且启用后最高优先，明文自动转存至 <code className="font-mono">{previewPrefix}/&lt;id&gt;</code>。
                  </p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 space-y-1">
                  <div className="flex items-center justify-between gap-2 text-xs font-medium">
                    <span className="text-slate-200">2. 内置安全卡</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/25">
                      预留中
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    无 OpenBao 用户的项目内置加密卡片槽位（LV1/LV2 分级权限与轮换吊销）。
                  </p>
                </div>

                <div
                  className={`rounded-xl border p-3 space-y-1 ${
                    !openBaoActive
                      ? "border-sky-500/35 bg-sky-500/10"
                      : "border-slate-800 bg-slate-950/60"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 text-xs font-medium">
                    <span className="text-slate-200 flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-slate-400" />
                      3. 服务器 0600 兜底
                    </span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                        !openBaoActive
                          ? "bg-sky-500/20 text-sky-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {!openBaoActive ? "当前兜底" : "备用"}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    无 OpenBao 时由服务端按 0700 目录 / 0600 权限文件受控保存，前端绝不落 localStorage。
                  </p>
                </div>
              </div>
            </div>

            {/* Quick Links Card */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 space-y-2.5">
              <div className="text-xs font-semibold text-slate-200">快捷联动入口</div>
              <button
                type="button"
                onClick={() => onNavigate?.("models")}
                className="w-full flex items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-950/70 hover:bg-slate-800/80 px-3.5 py-2.5 text-left transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <Layers className="w-4 h-4 text-sky-400 shrink-0" />
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-slate-100">外部模型与中转站</div>
                    <div className="text-[11px] text-slate-400 truncate">
                      粘贴 API Key 与 Base URL 接入第三方模型
                    </div>
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              </button>

              <button
                type="button"
                onClick={() => onNavigate?.("security-card")}
                className="w-full flex items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-950/70 hover:bg-slate-800/80 px-3.5 py-2.5 text-left transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <CreditCard className="w-4 h-4 text-amber-400 shrink-0" />
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-slate-100 flex items-center gap-1.5">
                      <span>安全卡</span>
                      <span className="px-1.5 py-0.2 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                        预留
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      查看无 OpenBao 用户的内置卡片规划
                    </div>
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
