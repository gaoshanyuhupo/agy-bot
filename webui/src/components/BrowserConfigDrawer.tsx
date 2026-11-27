import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Globe,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import {
  createEgressNode,
  deleteBrowserProfile,
  deleteEgressNode,
  drawEgressNodes,
  fetchEgressJob,
  pruneEgressNodes,
  updateBrowserProfile,
  upsertBrowserProfile,
  verifyEgressNode,
} from "../api";
import type {
  BrowserEngineId,
  BrowserEngineInfo,
  BrowserProfileItem,
  BrowserProfileUpsertPayload,
  EgressJobItem,
  EgressNodeItem,
} from "../types";

interface BrowserConfigDrawerProps {
  open: boolean;
  onClose: () => void;
  canEdit: boolean;
  engines: BrowserEngineInfo[];
  profiles: BrowserProfileItem[];
  egressNodes: EgressNodeItem[];
  egressVaultReady: boolean;
  egressVaultError: string;
  drawSupported: boolean;
  pruneSupported: boolean;
  onRefreshAll: () => Promise<void>;
  onNotify: (msg: string) => void;
}

type DrawerTab = "profiles" | "egress";
type EgressBindMode = "direct" | "pool" | "bare";
type EgressInputMode = "form" | "paste";

const DRAW_COUNTRIES = ["US", "JP", "GB", "DE", "SG", "CA", "NL", "AU", "FR"] as const;

export function BrowserConfigDrawer({
  open,
  onClose,
  canEdit,
  engines,
  profiles,
  egressNodes,
  egressVaultReady,
  egressVaultError,
  drawSupported,
  pruneSupported,
  onRefreshAll,
  onNotify,
}: BrowserConfigDrawerProps) {
  const [tab, setTab] = useState<DrawerTab>("profiles");
  const [profileEngine, setProfileEngine] = useState<BrowserEngineId>("camoufox");
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Profile editor state
  const [editingProfile, setEditingProfile] = useState<BrowserProfileItem | null>(null);
  const [showProfileForm, setShowProfileForm] = useState(false);
  const [profName, setProfName] = useState("");
  const [profOs, setProfOs] = useState("windows");
  const [profLocale, setProfLocale] = useState("en-US");
  const [profTz, setProfTz] = useState("America/Los_Angeles");
  const [profWindow, setProfWindow] = useState("1280x800");
  const [profMobile, setProfMobile] = useState(false);
  const [profAllowGoogle, setProfAllowGoogle] = useState(false);
  const [profAccount, setProfAccount] = useState("");
  const [profConfirmGoogle, setProfConfirmGoogle] = useState(false);
  const [egressBindMode, setEgressBindMode] = useState<EgressBindMode>("direct");
  const [selectedEgressNode, setSelectedEgressNode] = useState("");
  const [bareProxyUrl, setBareProxyUrl] = useState("");
  const [confirmDeleteProfile, setConfirmDeleteProfile] = useState<string | null>(null);

  // Egress manual add state (sensitive password / proxyUrl ALWAYS cleared right after submit)
  const [showEgressAdd, setShowEgressAdd] = useState(false);
  const [egressInputMode, setEgressInputMode] = useState<EgressInputMode>("form");
  const [egSlug, setEgSlug] = useState("");
  const [egScheme, setEgScheme] = useState("socks5h");
  const [egHost, setEgHost] = useState("");
  const [egPort, setEgPort] = useState("1080");
  const [egUsername, setEgUsername] = useState("");
  const [egPassword, setEgPassword] = useState("");
  const [egPasteUrl, setEgPasteUrl] = useState("");
  const [egNote, setEgNote] = useState("");
  const [confirmDeleteNode, setConfirmDeleteNode] = useState<string | null>(null);

  // Async egress jobs state (verify / draw / prune)
  const [drawCountry, setDrawCountry] = useState<string>("US");
  const [activeJobs, setActiveJobs] = useState<Record<string, EgressJobItem>>({});
  const pollTimersRef = useRef<Map<string, number>>(new Map());
  const mountedRef = useRef(true);

  const clearSensitiveEgressInputs = useCallback(() => {
    setEgPassword("");
    setEgPasteUrl("");
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      for (const tid of pollTimersRef.current.values()) {
        window.clearTimeout(tid);
      }
      pollTimersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (!open || !canEdit) {
      clearSensitiveEgressInputs();
      if (!open) {
        setErrorMsg(null);
      }
    }
  }, [open, canEdit, clearSensitiveEgressInputs]);

  const pollEgressJob = useCallback(
    (job: EgressJobItem) => {
      const jid = job.job_id;
      setActiveJobs((prev) => ({ ...prev, [jid]: job }));

      const scheduleNext = () => {
        const tid = window.setTimeout(async () => {
          pollTimersRef.current.delete(jid);
          if (!mountedRef.current) return;
          try {
            const resp = await fetchEgressJob(jid);
            if (!mountedRef.current) return;
            const updated = resp.job;
            setActiveJobs((prev) => ({ ...prev, [jid]: updated }));
            if (updated.status === "queued" || updated.status === "running") {
              scheduleNext();
            } else {
              await onRefreshAll();
              if (updated.status === "done") {
                onNotify(
                  updated.kind === "verify"
                    ? `✅ 节点 ${updated.target} 测活通过`
                    : updated.kind === "draw"
                      ? `✅ 已抽取 ${updated.target} 住宅 IP 并写入出口池`
                      : "✅ 出口池清理任务完成",
                );
              } else {
                onNotify(`⚠️ 任务 ${updated.kind}(${updated.target}) 失败: ${updated.error || "未知错误"}`);
              }
            }
          } catch {
            // Stop polling on transient fetch error
          }
        }, 1200);
        pollTimersRef.current.set(jid, tid);
      };

      if (job.status === "queued" || job.status === "running") {
        scheduleNext();
      } else {
        void onRefreshAll();
      }
    },
    [onNotify, onRefreshAll],
  );

  if (!open) return null;

  const filteredProfiles = profiles.filter((p) => p.engine === profileEngine);
  const extEngineInfo = engines.find((e) => e.id === "external_chromium");
  const extLabel = extEngineInfo?.label || "External Chromium";

  const openCreateProfile = () => {
    setErrorMsg(null);
    setEditingProfile(null);
    setProfName("");
    setProfOs(profileEngine === "camoufox" ? "windows" : "linux");
    setProfLocale("en-US");
    setProfTz("America/Los_Angeles");
    setProfWindow("1280x800");
    setProfMobile(false);
    setProfAllowGoogle(false);
    setProfAccount("");
    setProfConfirmGoogle(false);
    setEgressBindMode("direct");
    setSelectedEgressNode(egressNodes[0]?.ref || "");
    setBareProxyUrl("");
    setShowProfileForm(true);
  };

  const openEditProfile = (item: BrowserProfileItem) => {
    setErrorMsg(null);
    setEditingProfile(item);
    setProfName(item.name);
    setProfOs(item.os || "windows");
    setProfLocale(item.locale || item.lang || "en-US");
    setProfTz(item.tz || "America/Los_Angeles");
    const winStr = Array.isArray(item.window)
      ? `${item.window[0]}x${item.window[1]}`
      : String(item.window || "1280x800");
    setProfWindow(winStr);
    setProfMobile(Boolean(item.mobile));
    setProfAllowGoogle(Boolean(item.allow_google));
    setProfAccount(item.account || "");
    setProfConfirmGoogle(false);
    if (item.proxy_bao_ref) {
      setEgressBindMode("pool");
      setSelectedEgressNode(item.proxy_bao_ref);
      setBareProxyUrl("");
    } else if (item.egress && item.egress !== "direct" && item.egress.includes("://")) {
      setEgressBindMode("bare");
      setBareProxyUrl(item.egress);
      setSelectedEgressNode("");
    } else {
      setEgressBindMode("direct");
      setSelectedEgressNode(egressNodes[0]?.ref || "");
      setBareProxyUrl("");
    }
    setShowProfileForm(true);
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canEdit) return;
    setErrorMsg(null);
    const trimmedName = profName.trim();
    if (!trimmedName) {
      setErrorMsg("请输入 Profile 名称");
      return;
    }
    if (egressBindMode === "bare" && bareProxyUrl.includes("@")) {
      setErrorMsg("禁止在 Profile 中直接填写含 user:pass@ 的裸代理 URL，请先在「出口 IP 池」中安全录入");
      return;
    }
    if (editingProfile && editingProfile.allow_google && !profConfirmGoogle) {
      setErrorMsg("修改专用 Google Profile 必须勾选显式二次确认框");
      return;
    }

    const payload: BrowserProfileUpsertPayload = {
      engine: profileEngine,
      name: trimmedName,
      overwrite: Boolean(editingProfile),
      window: profWindow.trim() || "1280x800",
    };

    if (profileEngine === "camoufox") {
      payload.os = profOs;
      payload.locale = profLocale.trim() || "en-US";
      payload.mobile = profMobile;
    } else {
      payload.tz = profTz.trim() || "America/Los_Angeles";
      payload.lang = profLocale.trim() || "en-US";
    }

    if (editingProfile) {
      if (editingProfile.allow_google) {
        payload.confirm_google_profile_change = true;
      }
    } else if (profAllowGoogle) {
      payload.allow_google = true;
      payload.persistent = true;
      if (profAccount.trim()) {
        payload.account = profAccount.trim();
      }
    } else if (profAccount.trim()) {
      payload.account = profAccount.trim();
    }

    if (egressBindMode === "pool" && selectedEgressNode.trim()) {
      payload.proxy_bao_ref = selectedEgressNode.trim();
    } else if (egressBindMode === "bare" && bareProxyUrl.trim()) {
      payload.proxy = bareProxyUrl.trim();
    } else {
      payload.proxy = null;
      payload.proxy_bao_ref = null;
    }

    setBusy(true);
    try {
      if (editingProfile) {
        await updateBrowserProfile(profileEngine, editingProfile.name, payload);
        onNotify(`✅ 已更新 ${profileEngine} Profile: ${editingProfile.name}`);
      } else {
        await upsertBrowserProfile(payload);
        onNotify(`✅ 已创建 ${profileEngine} Profile: ${trimmedName}`);
      }
      setShowProfileForm(false);
      setEditingProfile(null);
      await onRefreshAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "保存 Profile 失败");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteProfile = async (item: BrowserProfileItem) => {
    if (!canEdit) return;
    setBusy(true);
    setErrorMsg(null);
    try {
      await deleteBrowserProfile(item.engine, item.name);
      setConfirmDeleteProfile(null);
      onNotify(`🗑 已删除 Profile: ${item.name}`);
      await onRefreshAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "删除 Profile 失败");
    } finally {
      setBusy(false);
    }
  };

  const handleCreateEgressNode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canEdit) return;
    setErrorMsg(null);
    setBusy(true);
    try {
      const payload =
        egressInputMode === "paste"
          ? {
              slug: egSlug.trim() || undefined,
              proxy_url: egPasteUrl.trim(),
              note: egNote.trim() || undefined,
            }
          : {
              slug: egSlug.trim() || undefined,
              scheme: egScheme,
              host: egHost.trim(),
              port: egPort.trim(),
              username: egUsername || undefined,
              password: egPassword || undefined,
              note: egNote.trim() || undefined,
            };
      // Immediately clear plaintext password & raw URL from React state before/after network roundtrip
      clearSensitiveEgressInputs();
      const resp = await createEgressNode(payload);
      setEgSlug("");
      setEgHost("");
      setEgPort("1080");
      setEgUsername("");
      setEgNote("");
      setShowEgressAdd(false);
      onNotify(`✅ 已安全存入 OpenBao: ${resp.node.name}（明文已清空）`);
      await onRefreshAll();
    } catch (err) {
      clearSensitiveEgressInputs();
      setErrorMsg(err instanceof Error ? err.message : "录入出口节点失败");
    } finally {
      setBusy(false);
    }
  };

  const handleVerifyNode = async (name: string) => {
    if (!canEdit) return;
    setErrorMsg(null);
    try {
      const resp = await verifyEgressNode(name);
      pollEgressJob(resp.job);
      onNotify(`⚡ 已发起测活任务: ${name}`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "触发测活失败");
    }
  };

  const handleDrawNodes = async () => {
    if (!canEdit) return;
    setErrorMsg(null);
    try {
      const resp = await drawEgressNodes({ country: drawCountry, want: 1 });
      pollEgressJob(resp.job);
      onNotify(`🎲 已启动抽取 ${drawCountry} 住宅 IP 任务…`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "触发抽取住宅 IP 失败");
    }
  };

  const handlePruneNodes = async () => {
    if (!canEdit) return;
    setErrorMsg(null);
    try {
      const resp = await pruneEgressNodes({ dry_run: false });
      pollEgressJob(resp.job);
      onNotify("🧹 已启动出口池闲置节点清理任务…");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "触发清理失败");
    }
  };

  const handleDeleteNode = async (name: string) => {
    if (!canEdit) return;
    setBusy(true);
    setErrorMsg(null);
    try {
      await deleteEgressNode(name);
      setConfirmDeleteNode(null);
      onNotify(`🗑 已作废出口节点: ${name}`);
      await onRefreshAll();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "作废出口节点失败");
    } finally {
      setBusy(false);
    }
  };

  const runningJobs = Object.values(activeJobs).filter(
    (j) => j.status === "queued" || j.status === "running",
  );

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
      <div className="w-full sm:max-w-lg md:max-w-2xl h-full bg-slate-900 border-l border-slate-700/80 shadow-2xl flex flex-col text-slate-100 select-text">
        {/* Header */}
        <div className="min-h-12 py-2 px-3 sm:px-4 border-b border-slate-800 flex items-center justify-between gap-2 shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <Layers className="w-4 h-4 text-sky-400 shrink-0" />
            <span className="text-sm font-semibold truncate">双浏览器 Profile 与出口 IP 池配置</span>
            {!canEdit && (
              <span className="px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 text-[10px] border border-amber-500/30 shrink-0">
                只读视图
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => void onRefreshAll()}
              className="h-8 w-8 sm:h-7 sm:w-7 rounded-md inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
              title="刷新配置"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => {
                clearSensitiveEgressInputs();
                onClose();
              }}
              className="h-8 w-8 sm:h-7 sm:w-7 rounded-md inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
              title="关闭"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="px-3 sm:px-4 pt-2.5 pb-2 border-b border-slate-800/80 flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => {
              clearSensitiveEgressInputs();
              setTab("profiles");
              setErrorMsg(null);
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer transition-colors ${
              tab === "profiles"
                ? "bg-sky-600 text-white"
                : "bg-slate-800/70 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Profile 配置 ({profiles.length})
          </button>
          <button
            type="button"
            onClick={() => {
              clearSensitiveEgressInputs();
              setTab("egress");
              setErrorMsg(null);
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer transition-colors ${
              tab === "egress"
                ? "bg-sky-600 text-white"
                : "bg-slate-800/70 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            出口 IP 池 ({egressNodes.length})
          </button>
        </div>

        {/* Error banner */}
        {errorMsg && (
          <div className="mx-4 mt-3 px-3 py-2 rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-200 text-xs flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
            <span className="flex-1 break-words">{errorMsg}</span>
            <button type="button" onClick={() => setErrorMsg(null)} className="text-rose-300 hover:text-white cursor-pointer">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-3 sm:p-4 pb-[max(1.5rem,env(safe-area-inset-bottom))] space-y-4">
          {tab === "profiles" ? (
            <>
              {/* Engine switcher + Create button */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex rounded-lg border border-slate-700/80 bg-slate-950/70 p-0.5">
                  <button
                    type="button"
                    onClick={() => {
                      setProfileEngine("camoufox");
                      setShowProfileForm(false);
                    }}
                    className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer ${
                      profileEngine === "camoufox"
                        ? "bg-sky-600 text-white"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Camoufox
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setProfileEngine("external_chromium");
                      setShowProfileForm(false);
                    }}
                    className={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer inline-flex items-center gap-1.5 ${
                      profileEngine === "external_chromium"
                        ? "bg-sky-600 text-white"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>{extLabel}</span>
                    {!extEngineInfo?.available && (
                      <span className="text-[10px] opacity-70">(未配置)</span>
                    )}
                  </button>
                </div>

                {canEdit && (profileEngine === "camoufox" || extEngineInfo?.available) && (
                  <button
                    type="button"
                    onClick={openCreateProfile}
                    className="h-8 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    新建二级 Profile
                  </button>
                )}
              </div>

              {/* Create/Edit Profile Form */}
              {showProfileForm && canEdit && (
                <form
                  onSubmit={handleSaveProfile}
                  className="rounded-xl border border-sky-500/35 bg-slate-950/80 p-3.5 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-sky-300">
                      {editingProfile
                        ? `编辑 ${profileEngine} Profile: ${editingProfile.name}`
                        : `创建 ${profileEngine} 二级 Profile`}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setShowProfileForm(false);
                        setEditingProfile(null);
                      }}
                      className="text-slate-400 hover:text-slate-200 cursor-pointer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">Profile 名称</label>
                      <input
                        type="text"
                        value={profName}
                        disabled={Boolean(editingProfile)}
                        onChange={(e) => setProfName(e.target.value)}
                        placeholder="如 work-us / google-alt"
                        className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 disabled:opacity-60"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">窗口尺寸 (WxH)</label>
                      <input
                        type="text"
                        value={profWindow}
                        onChange={(e) => setProfWindow(e.target.value)}
                        placeholder="1280x800"
                        className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 font-mono"
                      />
                    </div>

                    {profileEngine === "camoufox" ? (
                      <>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">操作系统指纹</label>
                          <select
                            value={profOs}
                            onChange={(e) => setProfOs(e.target.value)}
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2 text-[16px] sm:text-xs text-slate-100"
                          >
                            <option value="windows">windows</option>
                            <option value="macos">macos</option>
                            <option value="linux">linux</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">Locale</label>
                          <input
                            type="text"
                            value={profLocale}
                            onChange={(e) => setProfLocale(e.target.value)}
                            placeholder="en-US"
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                          />
                        </div>
                      </>
                    ) : (
                      <>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">时区 (TZ)</label>
                          <input
                            type="text"
                            value={profTz}
                            onChange={(e) => setProfTz(e.target.value)}
                            placeholder="America/Los_Angeles"
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">语言 (Lang)</label>
                          <input
                            type="text"
                            value={profLocale}
                            onChange={(e) => setProfLocale(e.target.value)}
                            placeholder="en-US"
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                          />
                        </div>
                      </>
                    )}
                  </div>

                  {/* Dedicated Google toggle (create-only; boundary keys immutable on edit) */}
                  {!editingProfile ? (
                    <div className="flex flex-wrap items-center gap-3 pt-1">
                      <label className="inline-flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={profAllowGoogle}
                          onChange={(e) => setProfAllowGoogle(e.target.checked)}
                          className="rounded border-slate-600"
                        />
                        <span>设为专用 Google Profile（1:1 持久隔离）</span>
                      </label>
                      {profileEngine === "camoufox" && (
                        <label className="inline-flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={profMobile}
                            onChange={(e) => setProfMobile(e.target.checked)}
                            className="rounded border-slate-600"
                          />
                          <span>移动端视口</span>
                        </label>
                      )}
                      {profAllowGoogle && (
                        <input
                          type="text"
                          value={profAccount}
                          onChange={(e) => setProfAccount(e.target.value)}
                          placeholder="绑定账号标签（绝不填密码）"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                        />
                      )}
                    </div>
                  ) : editingProfile.allow_google ? (
                    <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 space-y-1.5">
                      <div className="text-[11px] text-amber-200 font-medium">
                        ⚠️ 正在编辑专用 Google Profile（安全边界键保持锁定不可变）
                      </div>
                      <label className="inline-flex items-center gap-2 text-xs text-amber-100 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={profConfirmGoogle}
                          onChange={(e) => setProfConfirmGoogle(e.target.checked)}
                          className="rounded border-amber-500"
                        />
                        <span>我显式确认修改此专用 Google Profile 的指纹/出口配置</span>
                      </label>
                    </div>
                  ) : null}

                  {/* Egress binding */}
                  <div className="space-y-2 pt-1 border-t border-slate-800">
                    <div className="text-[11px] font-medium text-slate-400">出口网络绑定</div>
                    <div className="flex flex-wrap gap-2">
                      {(
                        [
                          ["direct", "直连 (Direct)"],
                          ["pool", "从出口 IP 池选择"],
                          ["bare", "无账密代理 URL"],
                        ] as const
                      ).map(([mode, lbl]) => (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => setEgressBindMode(mode)}
                          className={`px-2.5 py-1.5 sm:py-1 rounded-md text-[11px] border cursor-pointer ${
                            egressBindMode === mode
                              ? "border-sky-500 bg-sky-500/15 text-sky-200"
                              : "border-slate-700 bg-slate-900 text-slate-400"
                          }`}
                        >
                          {lbl}
                        </button>
                      ))}
                    </div>
                    {egressBindMode === "pool" && (
                      <select
                        value={selectedEgressNode}
                        onChange={(e) => setSelectedEgressNode(e.target.value)}
                        className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2 text-[16px] sm:text-xs text-slate-100"
                      >
                        <option value="">-- 请选择 OpenBao 出口节点 --</option>
                        {egressNodes.map((n) => (
                          <option key={n.name} value={n.ref}>
                            {n.name} ({n.status}{n.country ? ` · ${n.country}` : ""}{n.exit_ip ? ` · ${n.exit_ip}` : ""})
                          </option>
                        ))}
                      </select>
                    )}
                    {egressBindMode === "bare" && (
                      <input
                        type="text"
                        value={bareProxyUrl}
                        onChange={(e) => setBareProxyUrl(e.target.value)}
                        placeholder="socks5h://proxy.example.com:1080（禁止含 user:pass@）"
                        className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 font-mono"
                      />
                    )}
                  </div>

                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        setShowProfileForm(false);
                        setEditingProfile(null);
                      }}
                      className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
                    >
                      取消
                    </button>
                    <button
                      type="submit"
                      disabled={busy}
                      className="px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white disabled:opacity-50 cursor-pointer inline-flex items-center gap-1.5"
                    >
                      {busy && <Loader2 className="w-3 h-3 animate-spin" />}
                      保存 Profile
                    </button>
                  </div>
                </form>
              )}

              {/* Profile list */}
              <div className="space-y-2">
                {filteredProfiles.length === 0 ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center text-xs text-slate-400">
                    {profileEngine === "external_chromium" && !extEngineInfo?.available
                      ? "外部 Chromium 适配器未配置（需设置环境变量 AGY_BROWSER_EXTERNAL_CLI）"
                      : "当前引擎下暂无 Profile"}
                  </div>
                ) : (
                  filteredProfiles.map((p) => {
                    const locked = p.pinned || p.active || !canEdit;
                    return (
                      <div
                        key={`${p.engine}:${p.name}`}
                        className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 flex flex-col gap-2"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-xs font-semibold font-mono text-slate-100">
                                {p.name}
                              </span>
                              {p.pinned && (
                                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/35 text-amber-300 text-[10px]">
                                  <Lock className="w-2.5 h-2.5" />
                                  主默认 · 直连锁定
                                </span>
                              )}
                              {p.allow_google && !p.pinned && (
                                <span className="px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-500/35 text-sky-300 text-[10px]">
                                  Google 专用{p.account ? ` (${p.account})` : ""}
                                </span>
                              )}
                              {p.active && (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 text-[10px]">
                                  运行中
                                </span>
                              )}
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-400 font-mono">
                              <span>出口: {p.egress || "direct"}</span>
                              {p.os && <span>· {p.os}</span>}
                              {(p.locale || p.lang) && <span>· {p.locale || p.lang}</span>}
                              {p.tz && <span>· {p.tz}</span>}
                            </div>
                          </div>

                          {canEdit && (
                            <div className="flex items-center gap-1.5 shrink-0">
                              <button
                                type="button"
                                disabled={locked}
                                onClick={() => openEditProfile(p)}
                                title={
                                  p.pinned
                                    ? "主默认 Profile 不可修改"
                                    : p.active
                                      ? "运行中不可修改，请先停止浏览器"
                                      : "编辑配置"
                                }
                                className="px-2.5 py-1 rounded-md border border-slate-700 text-[11px] text-slate-200 hover:bg-slate-800 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
                              >
                                编辑
                              </button>
                              {confirmDeleteProfile === `${p.engine}:${p.name}` ? (
                                <button
                                  type="button"
                                  disabled={busy}
                                  onClick={() => void handleDeleteProfile(p)}
                                  className="px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-[11px] text-white cursor-pointer"
                                >
                                  确认删除
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  disabled={locked || !p.deletable}
                                  onClick={() => setConfirmDeleteProfile(`${p.engine}:${p.name}`)}
                                  title={
                                    p.pinned
                                      ? "主默认 Profile 禁止删除"
                                      : p.active
                                        ? "运行中禁止删除"
                                        : "删除二级 Profile"
                                  }
                                  className="p-1.5 rounded-md border border-slate-700 text-slate-400 hover:text-rose-400 hover:border-rose-500/40 disabled:opacity-35 disabled:pointer-events-none cursor-pointer"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </>
          ) : (
            <>
              {/* Egress Pool Action Bar */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        egressVaultReady ? "bg-emerald-400" : "bg-amber-400"
                      }`}
                    />
                    <span className="font-medium text-slate-200">
                      OpenBao 出口池 {egressVaultReady ? "已就绪" : "未就绪"}
                    </span>
                    {egressVaultError && (
                      <span className="text-[11px] text-amber-300">({egressVaultError})</span>
                    )}
                  </div>

                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => {
                        clearSensitiveEgressInputs();
                        setErrorMsg(null);
                        setShowEgressAdd((v) => !v);
                      }}
                      className="h-8 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      手工录入 SOCKS5 / HTTP
                    </button>
                  )}
                </div>

                {/* Draw / Prune row (only when backend draw_supported === true) */}
                {canEdit && (drawSupported || pruneSupported) && (
                  <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
                    {drawSupported && (
                      <>
                        <select
                          value={drawCountry}
                          onChange={(e) => setDrawCountry(e.target.value)}
                          className="h-9 sm:h-7 rounded-md bg-slate-900 border border-slate-700 px-2 text-[16px] sm:text-xs text-slate-200"
                        >
                          {DRAW_COUNTRIES.map((cc) => (
                            <option key={cc} value={cc}>
                              {cc}
                            </option>
                          ))}
                        </select>
                        <button
                          type="button"
                          onClick={() => void handleDrawNodes()}
                          className="h-7 px-2.5 rounded-md bg-emerald-600/90 hover:bg-emerald-500 text-white text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          现场抽新住宅 IP
                        </button>
                      </>
                    )}
                    {pruneSupported && (
                      <button
                        type="button"
                        onClick={() => void handlePruneNodes()}
                        className="h-7 px-2.5 rounded-md border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        清理闲置节点
                      </button>
                    )}
                  </div>
                )}

                {runningJobs.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {runningJobs.map((j) => (
                      <span
                        key={j.job_id}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-sky-500/15 border border-sky-500/35 text-sky-200 text-[11px]"
                      >
                        <Loader2 className="w-3 h-3 animate-spin" />
                        {j.kind}: {j.target} ({j.status})
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Manual SOCKS5 / HTTP(S) Add Form */}
              {showEgressAdd && canEdit && (
                <form
                  onSubmit={handleCreateEgressNode}
                  autoComplete="off"
                  className="rounded-xl border border-sky-500/35 bg-slate-950/85 p-3.5 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-xs font-semibold text-sky-300">
                        安全录入出口代理（直写 OpenBao，提交即清空明文）
                      </span>
                    </div>
                    <div className="inline-flex rounded-md border border-slate-700 bg-slate-900 p-0.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => {
                          clearSensitiveEgressInputs();
                          setEgressInputMode("form");
                        }}
                        className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                          egressInputMode === "form" ? "bg-sky-600 text-white" : "text-slate-400"
                        }`}
                      >
                        表单录入
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          clearSensitiveEgressInputs();
                          setEgressInputMode("paste");
                        }}
                        className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                          egressInputMode === "paste" ? "bg-sky-600 text-white" : "text-slate-400"
                        }`}
                      >
                        单行粘贴
                      </button>
                    </div>
                  </div>

                  {egressInputMode === "paste" ? (
                    <div className="space-y-2.5">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">
                          代理 URL（已密码遮罩，支持 socks5h://user:pass@host:port）
                        </label>
                        <input
                          type="password"
                          autoComplete="new-password"
                          value={egPasteUrl}
                          onChange={(e) => setEgPasteUrl(e.target.value)}
                          placeholder="socks5h://user:pass@proxy.example.com:1080"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 font-mono"
                        />
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">节点标识 Slug（可选）</label>
                          <input
                            type="text"
                            value={egSlug}
                            onChange={(e) => setEgSlug(e.target.value)}
                            placeholder="自动加 custom- 前缀"
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] text-slate-400 mb-1">备注（可选）</label>
                          <input
                            type="text"
                            value={egNote}
                            onChange={(e) => setEgNote(e.target.value)}
                            placeholder="如 US 住宅出口"
                            className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                          />
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">节点标识 Slug（可选）</label>
                        <input
                          type="text"
                          value={egSlug}
                          onChange={(e) => setEgSlug(e.target.value)}
                          placeholder="如 us-home1"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">协议 Scheme</label>
                        <select
                          value={egScheme}
                          onChange={(e) => setEgScheme(e.target.value)}
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2 text-[16px] sm:text-xs text-slate-100"
                        >
                          <option value="socks5h">socks5h (推荐)</option>
                          <option value="socks5">socks5</option>
                          <option value="http">http</option>
                          <option value="https">https</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">主机 Host</label>
                        <input
                          type="text"
                          value={egHost}
                          onChange={(e) => setEgHost(e.target.value)}
                          placeholder="proxy.example.com"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">端口 Port</label>
                        <input
                          type="text"
                          value={egPort}
                          onChange={(e) => setEgPort(e.target.value)}
                          placeholder="1080"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100 font-mono"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">用户名（可选）</label>
                        <input
                          type="text"
                          autoComplete="off"
                          value={egUsername}
                          onChange={(e) => setEgUsername(e.target.value)}
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 mb-1">密码（可选，永不回显）</label>
                        <input
                          type="password"
                          autoComplete="new-password"
                          value={egPassword}
                          onChange={(e) => setEgPassword(e.target.value)}
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                        />
                      </div>
                      <div className="sm:col-span-2">
                        <label className="block text-[11px] text-slate-400 mb-1">备注（可选）</label>
                        <input
                          type="text"
                          value={egNote}
                          onChange={(e) => setEgNote(e.target.value)}
                          placeholder="如 美西住宅出口"
                          className="w-full h-10 sm:h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 text-[16px] sm:text-xs text-slate-100"
                        />
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        clearSensitiveEgressInputs();
                        setShowEgressAdd(false);
                      }}
                      className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
                    >
                      取消
                    </button>
                    <button
                      type="submit"
                      disabled={busy}
                      className="px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white disabled:opacity-50 cursor-pointer inline-flex items-center gap-1.5"
                    >
                      {busy && <Loader2 className="w-3 h-3 animate-spin" />}
                      安全存入 OpenBao
                    </button>
                  </div>
                </form>
              )}

              {/* Egress Nodes List */}
              <div className="space-y-2">
                {egressNodes.length === 0 ? (
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center text-xs text-slate-400">
                    暂无出口代理节点，可点击上方「手工录入 SOCKS5 / HTTP」添加
                  </div>
                ) : (
                  egressNodes.map((n) => {
                    const isClean = n.status === "clean";
                    const isDead = n.status.startsWith("dead");
                    const isVerifying = Object.values(activeJobs).some(
                      (j) =>
                        j.kind === "verify" &&
                        j.target === n.name &&
                        (j.status === "queued" || j.status === "running"),
                    );
                    return (
                      <div
                        key={n.name}
                        className="rounded-xl border border-slate-800 bg-slate-950/70 p-3 flex flex-col gap-2"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0 space-y-1">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-xs font-semibold font-mono text-slate-100">
                                {n.name}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                                {n.provider}
                              </span>
                              <span
                                className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] border ${
                                  isClean
                                    ? "bg-emerald-500/15 border-emerald-500/35 text-emerald-300"
                                    : isDead
                                      ? "bg-rose-500/15 border-rose-500/35 text-rose-300"
                                      : "bg-amber-500/15 border-amber-500/35 text-amber-300"
                                }`}
                              >
                                {isClean ? (
                                  <CheckCircle2 className="w-2.5 h-2.5" />
                                ) : (
                                  <Activity className="w-2.5 h-2.5" />
                                )}
                                {n.status}
                              </span>
                              {n.has_auth && (
                                <span
                                  title="凭据已加密托管于 OpenBao"
                                  className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-sky-500/10 border border-sky-500/30 text-sky-300 text-[10px]"
                                >
                                  <KeyRound className="w-2.5 h-2.5" />
                                  已认证
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 break-all">
                              {n.server || n.ref}
                            </div>
                            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                              {n.exit_ip && <span className="font-mono text-slate-300">IP: {n.exit_ip}</span>}
                              {(n.country || n.city) && (
                                <span>
                                  {[n.country, n.city].filter(Boolean).join(" / ")}
                                </span>
                              )}
                              {n.isp && <span>· {n.isp}</span>}
                              {n.latency_ms && <span>· {n.latency_ms}ms</span>}
                              {n.mbps && <span>· {n.mbps} Mbps</span>}
                              {n.verified_at && (
                                <span className="text-slate-500">· 验证: {n.verified_at.slice(0, 19).replace("T", " ")}</span>
                              )}
                            </div>
                          </div>

                          {canEdit && (
                            <div className="flex items-center gap-1.5 shrink-0">
                              <button
                                type="button"
                                disabled={isVerifying}
                                onClick={() => void handleVerifyNode(n.name)}
                                className="px-2.5 py-1 rounded-md border border-slate-700 hover:bg-slate-800 text-[11px] text-sky-300 inline-flex items-center gap-1 disabled:opacity-50 cursor-pointer"
                              >
                                {isVerifying ? (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                ) : (
                                  <Zap className="w-3 h-3" />
                                )}
                                测活
                              </button>
                              {n.deletable &&
                                (confirmDeleteNode === n.name ? (
                                  <button
                                    type="button"
                                    disabled={busy}
                                    onClick={() => void handleDeleteNode(n.name)}
                                    className="px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-[11px] text-white cursor-pointer"
                                  >
                                    确认作废
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => setConfirmDeleteNode(n.name)}
                                    title="作废 custom-* 节点"
                                    className="p-1.5 rounded-md border border-slate-700 text-slate-400 hover:text-rose-400 hover:border-rose-500/40 cursor-pointer"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                ))}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
