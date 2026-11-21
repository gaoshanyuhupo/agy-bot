import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  Loader2,
  Lock,
  Power,
  RefreshCw,
  Save,
  Server,
  Sliders,
  Sparkles,
} from "lucide-react";
import {
  StudioApiError,
  fetchBotConfig,
  fetchBots,
  reloadBot,
  updateBotConfig,
} from "../api";
import type {
  BotConfigResponse,
  BotsResponse,
  StudioSession,
} from "../types";

interface BotsViewProps {
  session?: StudioSession;
  eventVersion?: number;
  onSessionRevoked?: (reason: string) => void;
}

export function BotsView({
  session,
  eventVersion = 0,
  onSessionRevoked,
}: BotsViewProps) {
  const isReadonly = !session || session.role !== "admin";

  const [data, setData] = useState<BotsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  const [botConfig, setBotConfig] = useState<BotConfigResponse | null>(null);
  const [cfgLoading, setCfgLoading] = useState(false);
  const [cfgError, setCfgError] = useState<string | null>(null);
  const [cfgNotice, setCfgNotice] = useState<string | null>(null);

  // Editable form state
  const [modelMode, setModelMode] = useState<"default" | "follow" | "custom">("default");
  const [customModel, setCustomModel] = useState<string>("");
  const [defaultEffort, setDefaultEffort] = useState<string>("");
  const [defaultProject, setDefaultProject] = useState<string>("");
  const [isDirty, setIsDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  // Safe hot-reload confirm + cooldown per bot handle
  const [confirmReload, setConfirmReload] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [cooldownUntil, setCooldownUntil] = useState<Record<string, number>>({});
  const [nowSec, setNowSec] = useState<number>(() => Math.floor(Date.now() / 1000));

  // Async race & unmount guards
  const mountedRef = useRef(true);
  const selectedHandleRef = useRef<string | null>(selectedHandle);
  selectedHandleRef.current = selectedHandle;
  const isDirtyRef = useRef(isDirty);
  isDirtyRef.current = isDirty;
  const listReqSeqRef = useRef(0);
  const cfgReqSeqRef = useRef(0);
  const prevHandleRef = useRef<string | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const hasActive = Object.values(cooldownUntil).some((ts) => ts > nowSec);
    if (!hasActive) return;
    const timer = window.setInterval(() => {
      setNowSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [cooldownUntil, nowSec]);

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

  const load = useCallback(async () => {
    const reqSeq = ++listReqSeqRef.current;
    setLoading(true);
    setError(null);
    try {
      const res = await fetchBots();
      if (!mountedRef.current || listReqSeqRef.current !== reqSeq) {
        return;
      }
      setData(res);
      setSelectedHandle((cur) => {
        if (cur && res.bots.some((b) => b.handle === cur)) return cur;
        const firstOnline = res.bots.find((b) => b.online);
        return firstOnline?.handle || res.bots[0]?.handle || null;
      });
    } catch (e) {
      if (!mountedRef.current || listReqSeqRef.current !== reqSeq) {
        return;
      }
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "加载 Bot 列表失败");
      }
    } finally {
      if (mountedRef.current && listReqSeqRef.current === reqSeq) {
        setLoading(false);
      }
    }
  }, [handleAuthErr]);

  useEffect(() => {
    void load();
  }, [load, eventVersion]);

  const syncFormFromConfig = useCallback((cfg: BotConfigResponse) => {
    setModelMode(cfg.model_mode || "default");
    setCustomModel(cfg.configured_model || "");
    setDefaultEffort(cfg.default_effort || "");
    setDefaultProject(cfg.default_project || "");
    setIsDirty(false);
    isDirtyRef.current = false;
  }, []);

  const loadConfig = useCallback(
    async (handle: string, opts?: { background?: boolean }) => {
      const isBg = Boolean(opts?.background);
      const reqSeq = ++cfgReqSeqRef.current;
      if (!isBg) {
        setCfgLoading(true);
        setCfgError(null);
        setCfgNotice(null);
        setConfirmReload(false);
      }
      try {
        const res = await fetchBotConfig(handle);
        if (
          !mountedRef.current ||
          cfgReqSeqRef.current !== reqSeq ||
          selectedHandleRef.current !== handle
        ) {
          return;
        }
        setBotConfig(res);
        // Preserve in-progress user draft on background refresh or when form is dirty
        if (!isDirtyRef.current) {
          syncFormFromConfig(res);
        }
      } catch (err) {
        if (
          !mountedRef.current ||
          cfgReqSeqRef.current !== reqSeq ||
          selectedHandleRef.current !== handle
        ) {
          return;
        }
        if (!handleAuthErr(err)) {
          setCfgError(err instanceof Error ? err.message : "加载 Bot 配置失败");
        }
      } finally {
        if (
          mountedRef.current &&
          cfgReqSeqRef.current === reqSeq &&
          selectedHandleRef.current === handle &&
          !isBg
        ) {
          setCfgLoading(false);
        }
      }
    },
    [handleAuthErr, syncFormFromConfig],
  );

  useEffect(() => {
    const handleChanged = prevHandleRef.current !== selectedHandle;
    prevHandleRef.current = selectedHandle;
    if (!selectedHandle) {
      cfgReqSeqRef.current += 1;
      setBotConfig(null);
      setIsDirty(false);
      isDirtyRef.current = false;
      setSaving(false);
      setReloading(false);
      setConfirmReload(false);
      return;
    }
    if (handleChanged) {
      setIsDirty(false);
      isDirtyRef.current = false;
      setSaving(false);
      setReloading(false);
      setConfirmReload(false);
      void loadConfig(selectedHandle, { background: false });
    } else {
      void loadConfig(selectedHandle, { background: true });
    }
  }, [selectedHandle, loadConfig, eventVersion]);

  const handleSaveConfig = async () => {
    const reqHandle = selectedHandle;
    if (!reqHandle || !botConfig || isReadonly || !botConfig.ipc_online) return;
    setSaving(true);
    setCfgError(null);
    setCfgNotice(null);
    try {
      const payload: {
        model_mode: "default" | "follow" | "custom";
        model?: string;
        default_effort: string;
        default_project: string;
      } = {
        model_mode: modelMode,
        default_effort: defaultEffort,
        default_project: defaultProject,
      };
      if (modelMode === "custom") {
        payload.model = customModel;
      }
      const updated = await updateBotConfig(reqHandle, payload);
      if (!mountedRef.current) return;
      void load();
      if (selectedHandleRef.current !== reqHandle) {
        return;
      }
      cfgReqSeqRef.current += 1;
      setBotConfig(updated);
      syncFormFromConfig(updated);
      setCfgNotice("配置已通过 Bridge Single-Writer 保存并刷新心跳。");
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) {
        return;
      }
      if (!handleAuthErr(err)) {
        setCfgError(err instanceof Error ? err.message : "保存配置失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setSaving(false);
      }
    }
  };

  const handleConfirmReload = async () => {
    const reqHandle = selectedHandle;
    if (!reqHandle || isReadonly) return;
    setReloading(true);
    setCfgError(null);
    setCfgNotice(null);
    try {
      const res = await reloadBot(reqHandle);
      if (!mountedRef.current) return;
      const cd = res.cooldown_sec || 15;
      const until = Math.floor(Date.now() / 1000) + cd;
      setNowSec(Math.floor(Date.now() / 1000));
      setCooldownUntil((prev) => ({ ...prev, [reqHandle]: until }));
      if (selectedHandleRef.current !== reqHandle) {
        return;
      }
      setConfirmReload(false);
      setCfgNotice("前置自检通过，已排程零中断安全热重载。");
    } catch (err) {
      if (!mountedRef.current) return;
      if (handleAuthErr(err)) return;
      if (err instanceof StudioApiError && err.status === 429 && err.retryAfter) {
        const until = Math.floor(Date.now() / 1000) + err.retryAfter;
        setNowSec(Math.floor(Date.now() / 1000));
        setCooldownUntil((prev) => ({ ...prev, [reqHandle]: until }));
      }
      if (selectedHandleRef.current !== reqHandle) {
        return;
      }
      setCfgError(err instanceof Error ? err.message : "触发热重载失败");
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setReloading(false);
      }
    }
  };

  const activeCooldown = selectedHandle
    ? Math.max(0, (cooldownUntil[selectedHandle] || 0) - nowSec)
    : 0;

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Bot 团队控制面</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {isReadonly
              ? "只读视图 · 模型策略、Skills/MCP 能力与节点心跳"
              : "管理员控制面 · 模型策略 / Effort / 默认项目配置与安全热重载"}
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            void load();
            if (selectedHandle) void loadConfig(selectedHandle);
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading || cfgLoading ? "animate-spin" : ""}`} />
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
        {data?.bots.map((b) => {
          const isSelected = selectedHandle === b.handle;
          return (
            <button
              key={b.handle}
              type="button"
              onClick={() => setSelectedHandle(b.handle)}
              className={`text-left rounded-xl border p-4 space-y-3 transition-colors cursor-pointer ${
                isSelected
                  ? "border-sky-500/60 bg-sky-500/10"
                  : "border-slate-800 bg-slate-900/70 hover:border-slate-700"
              }`}
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
            </button>
          );
        })}
      </div>

      {/* Selected Bot Configuration & Skills/MCP Detail Card */}
      {selectedHandle && (
        <section className="rounded-xl border border-slate-800 bg-slate-900/75 p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                节点配置：{botConfig?.display_name || selectedHandle}
              </h3>
              <span className="text-xs font-mono text-slate-500">({selectedHandle})</span>
              {botConfig && (
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                    botConfig.ipc_online
                      ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {botConfig.ipc_online ? "IPC 在线" : "IPC 离线（只读回退）"}
                </span>
              )}
            </div>

            {!isReadonly && botConfig?.ipc_online && (
              <div className="flex items-center gap-2">
                {!confirmReload ? (
                  <button
                    type="button"
                    disabled={reloading || activeCooldown > 0}
                    onClick={() => setConfirmReload(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20 disabled:opacity-40 text-amber-200 text-xs font-medium cursor-pointer"
                  >
                    <Power className="w-3.5 h-3.5" />
                    {activeCooldown > 0
                      ? `冷却中 (${activeCooldown}s)`
                      : "安全热重载"}
                  </button>
                ) : (
                  <div className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs">
                    <span className="text-amber-200">确认执行前置自检并热重载？</span>
                    <button
                      type="button"
                      disabled={reloading}
                      onClick={() => void handleConfirmReload()}
                      className="px-2 py-0.5 rounded bg-amber-600 hover:bg-amber-500 text-white font-medium cursor-pointer"
                    >
                      {reloading ? "校验中…" : "确认"}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmReload(false)}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer"
                    >
                      取消
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {cfgError && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{cfgError}</span>
            </div>
          )}

          {cfgNotice && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200 flex items-center gap-2">
              <Check className="w-4 h-4 shrink-0" />
              <span>{cfgNotice}</span>
            </div>
          )}

          {cfgLoading && !botConfig ? (
            <div className="py-6 text-center text-xs text-slate-400 inline-flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
              加载节点配置中…
            </div>
          ) : botConfig ? (
            <div className="space-y-5">
              {isReadonly && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 shrink-0" />
                  <span>当前为只读角色（readonly），配置修改与安全热重载已锁定。</span>
                </div>
              )}

              {/* Policy Form */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                <label className="space-y-1 text-xs">
                  <span className="text-slate-400 block">模型策略 (model_mode)</span>
                  <select
                    value={modelMode}
                    disabled={isReadonly || !botConfig.ipc_online || saving}
                    onChange={(e) => {
                      setModelMode(e.target.value as "default" | "follow" | "custom");
                      setIsDirty(true);
                      isDirtyRef.current = true;
                    }}
                    className="w-full h-8 rounded-lg bg-slate-950 border border-slate-800 px-2.5 text-xs text-slate-200 disabled:opacity-50"
                  >
                    <option value="default">default（环境默认）</option>
                    <option value="follow">follow（跟随 DM）</option>
                    <option value="custom">custom（自定义模型）</option>
                  </select>
                </label>

                <label className="space-y-1 text-xs">
                  <span className="text-slate-400 block">自定义模型</span>
                  <select
                    value={customModel}
                    disabled={
                      isReadonly ||
                      !botConfig.ipc_online ||
                      modelMode !== "custom" ||
                      saving
                    }
                    onChange={(e) => {
                      setCustomModel(e.target.value);
                      setIsDirty(true);
                      isDirtyRef.current = true;
                    }}
                    className="w-full h-8 rounded-lg bg-slate-950 border border-slate-800 px-2.5 text-xs text-slate-200 disabled:opacity-50"
                  >
                    <option value="">请选择模型…</option>
                    {botConfig.models.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.label || m.id}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="space-y-1 text-xs">
                  <span className="text-slate-400 block">默认思考强度 (Effort)</span>
                  <select
                    value={defaultEffort}
                    disabled={isReadonly || !botConfig.ipc_online || saving}
                    onChange={(e) => {
                      setDefaultEffort(e.target.value);
                      setIsDirty(true);
                      isDirtyRef.current = true;
                    }}
                    className="w-full h-8 rounded-lg bg-slate-950 border border-slate-800 px-2.5 text-xs text-slate-200 disabled:opacity-50"
                  >
                    <option value="">默认</option>
                    {(botConfig.efforts || ["low", "medium", "high", "xhigh", "max"]).map(
                      (ef) => (
                        <option key={ef} value={ef}>
                          {ef}
                        </option>
                      ),
                    )}
                  </select>
                </label>

                <label className="space-y-1 text-xs">
                  <span className="text-slate-400 block">默认项目</span>
                  <select
                    value={defaultProject}
                    disabled={isReadonly || !botConfig.ipc_online || saving}
                    onChange={(e) => {
                      setDefaultProject(e.target.value);
                      setIsDirty(true);
                      isDirtyRef.current = true;
                    }}
                    className="w-full h-8 rounded-lg bg-slate-950 border border-slate-800 px-2.5 text-xs text-slate-200 disabled:opacity-50"
                  >
                    <option value="">未指定（默认工作区）</option>
                    {botConfig.projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name || p.id}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              {!isReadonly && botConfig.ipc_online && (
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[11px] text-slate-400 font-mono truncate">
                      生效模型：{botConfig.effective_model || "default"}
                    </span>
                    {isDirty && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-[10px] text-amber-200 shrink-0">
                        草稿未保存
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    disabled={saving || (modelMode === "custom" && !customModel)}
                    onClick={() => void handleSaveConfig()}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium cursor-pointer"
                  >
                    {saving ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Save className="w-3.5 h-3.5" />
                    )}
                    保存配置
                  </button>
                </div>
              )}

              {/* Sanitized MCP Servers & Skills Inventory */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800/80">
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                    <Server className="w-3.5 h-3.5 text-sky-400" />
                    <span>MCP 服务 ({botConfig.mcp_servers.length})</span>
                  </div>
                  {botConfig.mcp_servers.length === 0 ? (
                    <div className="text-xs text-slate-500">暂无已配置 MCP 服务</div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {botConfig.mcp_servers.map((m) => (
                        <span
                          key={m.name}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono ${
                            m.enabled
                              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                              : "border-slate-700 bg-slate-900 text-slate-400"
                          }`}
                        >
                          <span>{m.name}</span>
                          <span className="text-[10px] text-slate-400">
                            {m.transport}
                          </span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                    <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                    <span>已加载 Skills ({botConfig.skills.length})</span>
                  </div>
                  {botConfig.skills.length === 0 ? (
                    <div className="text-xs text-slate-500">暂无可见 Skills 元数据</div>
                  ) : (
                    <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                      {botConfig.skills.map((sk) => (
                        <div
                          key={`${sk.scope}-${sk.name}`}
                          className="rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-1.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono text-slate-200 truncate">
                              {sk.name}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400 shrink-0">
                              {sk.scope}
                            </span>
                          </div>
                          {sk.description && (
                            <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                              {sk.description}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : null}
        </section>
      )}
    </div>
  );
}
