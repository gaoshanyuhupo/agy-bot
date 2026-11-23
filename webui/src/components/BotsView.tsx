import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Brain,
  Check,
  FileText,
  Loader2,
  Lock,
  Plus,
  Power,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Shield,
  Sliders,
  Sparkles,
  Trash2,
} from "lucide-react";
import {
  StudioApiError,
  deleteBotSkill,
  fetchBotConfig,
  fetchBotProfile,
  fetchBotSkill,
  fetchBots,
  reloadBot,
  saveBotSkill,
  updateBotConfig,
  updateBotProfile,
} from "../api";
import type {
  BotConfigResponse,
  BotProfileDocName,
  BotProfileResponse,
  BotsResponse,
  StudioSession,
} from "../types";

interface BotsViewProps {
  session?: StudioSession;
  eventVersion?: number;
  onSessionRevoked?: (reason: string) => void;
}

type DetailTab = "config" | "persona" | "skills" | "memory";

const DOC_TABS: { key: BotProfileDocName; label: string; hint: string }[] = [
  { key: "SOUL.md", label: "SOUL.md（人格）", hint: "定义该 Bot 的独立角色定位、语气风格与核心价值观" },
  { key: "RULES.md", label: "RULES.md（规则）", hint: "定义该 Bot 的专属执行规范、边界红线与交付要求" },
  { key: "MEMORY.md", label: "MEMORY.md（策展记忆）", hint: "由人工或归户流程维护的长期事实笔记（按 Bot 隔离）" },
];

const MAX_DOC_BYTES_DEFAULT = 24 * 1024;
const SKILL_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text || "").length;
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
  const [activeTab, setActiveTab] = useState<DetailTab>("config");

  // Basic config state
  const [botConfig, setBotConfig] = useState<BotConfigResponse | null>(null);
  const [cfgLoading, setCfgLoading] = useState(false);
  const [cfgError, setCfgError] = useState<string | null>(null);
  const [cfgNotice, setCfgNotice] = useState<string | null>(null);

  const [modelMode, setModelMode] = useState<"default" | "follow" | "custom">("default");
  const [customModel, setCustomModel] = useState<string>("");
  const [defaultEffort, setDefaultEffort] = useState<string>("");
  const [defaultProject, setDefaultProject] = useState<string>("");
  const [isDirty, setIsDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  // Per-Bot Profile / Persona / Skills / Memory state
  const [botProfile, setBotProfile] = useState<BotProfileResponse | null>(null);
  const [profLoading, setProfLoading] = useState(false);
  const [profError, setProfError] = useState<string | null>(null);
  const [profNotice, setProfNotice] = useState<string | null>(null);
  const [profConflictRev, setProfConflictRev] = useState<number | null>(null);

  const [activeDoc, setActiveDoc] = useState<BotProfileDocName>("SOUL.md");
  const [docDrafts, setDocDrafts] = useState<Record<BotProfileDocName, string>>({
    "SOUL.md": "",
    "RULES.md": "",
    "MEMORY.md": "",
  });
  const [profDirty, setProfDirty] = useState(false);
  const [profSaving, setProfSaving] = useState(false);

  // Skills policy & own skill editor state
  const [policyMode, setPolicyMode] = useState<"allowlist" | "all">("allowlist");
  const [enabledCatalogSkills, setEnabledCatalogSkills] = useState<string[]>([]);
  const [policyDirty, setPolicyDirty] = useState(false);
  const [policySaving, setPolicySaving] = useState(false);

  const [skillEditorOpen, setSkillEditorOpen] = useState(false);
  const [skillEditorIsNew, setSkillEditorIsNew] = useState(false);
  const [skillSlugDraft, setSkillSlugDraft] = useState("");
  const [skillContentDraft, setSkillContentDraft] = useState("");
  const [skillLoading, setSkillLoading] = useState(false);
  const [skillSaving, setSkillSaving] = useState(false);
  const [skillDirty, setSkillDirty] = useState(false);

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
  const profDirtyRef = useRef(profDirty);
  profDirtyRef.current = profDirty;
  const docDraftsRef = useRef(docDrafts);
  docDraftsRef.current = docDrafts;
  const policyDirtyRef = useRef(policyDirty);
  policyDirtyRef.current = policyDirty;
  const skillDirtyRef = useRef(skillDirty);
  skillDirtyRef.current = skillDirty;

  const listReqSeqRef = useRef(0);
  const cfgReqSeqRef = useRef(0);
  const profReqSeqRef = useRef(0);
  const skillReqSeqRef = useRef(0);
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

  const syncFormFromProfile = useCallback((prof: BotProfileResponse, forceDocs = false) => {
    if (forceDocs || !profDirtyRef.current) {
      const nextDrafts: Record<BotProfileDocName, string> = {
        "SOUL.md": prof.docs["SOUL.md"] || "",
        "RULES.md": prof.docs["RULES.md"] || "",
        "MEMORY.md": prof.docs["MEMORY.md"] || "",
      };
      setDocDrafts(nextDrafts);
      docDraftsRef.current = nextDrafts;
      setProfDirty(false);
      profDirtyRef.current = false;
    }
    if (forceDocs || !policyDirtyRef.current) {
      setPolicyMode(prof.skills_policy?.mode === "all" ? "all" : "allowlist");
      setEnabledCatalogSkills([...(prof.skills_policy?.enabled_catalog_skills || [])]);
      setPolicyDirty(false);
      policyDirtyRef.current = false;
    }
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

  const loadProfile = useCallback(
    async (handle: string, opts?: { background?: boolean; forceResetDraft?: boolean }) => {
      const isBg = Boolean(opts?.background);
      const forceReset = Boolean(opts?.forceResetDraft);
      const reqSeq = ++profReqSeqRef.current;
      if (!isBg) {
        setProfLoading(true);
        setProfError(null);
        setProfNotice(null);
        setProfConflictRev(null);
      }
      try {
        const res = await fetchBotProfile(handle);
        if (
          !mountedRef.current ||
          profReqSeqRef.current !== reqSeq ||
          selectedHandleRef.current !== handle
        ) {
          return;
        }
        setBotProfile(res);
        // Never overwrite unsaved draft on background SSE refresh
        if (forceReset || !isBg) {
          syncFormFromProfile(res, forceReset);
        } else {
          syncFormFromProfile(res, false);
        }
      } catch (err) {
        if (
          !mountedRef.current ||
          profReqSeqRef.current !== reqSeq ||
          selectedHandleRef.current !== handle
        ) {
          return;
        }
        if (!handleAuthErr(err) && !isBg) {
          setProfError(err instanceof Error ? err.message : "加载 Bot Profile 失败");
        }
      } finally {
        if (
          mountedRef.current &&
          profReqSeqRef.current === reqSeq &&
          selectedHandleRef.current === handle &&
          !isBg
        ) {
          setProfLoading(false);
        }
      }
    },
    [handleAuthErr, syncFormFromProfile],
  );

  useEffect(() => {
    const handleChanged = prevHandleRef.current !== selectedHandle;
    prevHandleRef.current = selectedHandle;
    if (!selectedHandle) {
      cfgReqSeqRef.current += 1;
      profReqSeqRef.current += 1;
      skillReqSeqRef.current += 1;
      setBotConfig(null);
      setBotProfile(null);
      setIsDirty(false);
      isDirtyRef.current = false;
      setProfDirty(false);
      profDirtyRef.current = false;
      setPolicyDirty(false);
      policyDirtyRef.current = false;
      setSkillEditorOpen(false);
      setSkillDirty(false);
      skillDirtyRef.current = false;
      setSaving(false);
      setReloading(false);
      setConfirmReload(false);
      return;
    }
    if (handleChanged) {
      setIsDirty(false);
      isDirtyRef.current = false;
      setProfDirty(false);
      profDirtyRef.current = false;
      setPolicyDirty(false);
      policyDirtyRef.current = false;
      setSkillEditorOpen(false);
      setSkillDirty(false);
      skillDirtyRef.current = false;
      setProfConflictRev(null);
      setSaving(false);
      setReloading(false);
      setConfirmReload(false);
      void loadConfig(selectedHandle, { background: false });
      void loadProfile(selectedHandle, { background: false, forceResetDraft: true });
    } else {
      void loadConfig(selectedHandle, { background: true });
      void loadProfile(selectedHandle, { background: true, forceResetDraft: false });
    }
  }, [selectedHandle, loadConfig, loadProfile, eventVersion]);

  const configIpcOnline = Boolean(botConfig?.ipc_online ?? botProfile?.ipc_online);
  const profileIpcOnline = botProfile
    ? Boolean(botProfile.ipc_online)
    : Boolean(botConfig?.ipc_online);
  const ipcOnline = activeTab === "config" ? configIpcOnline : profileIpcOnline;
  const canEdit = !isReadonly && configIpcOnline;
  const canEditProfile = !isReadonly && profileIpcOnline;
  const maxDocBytes = botProfile?.max_doc_bytes || MAX_DOC_BYTES_DEFAULT;
  const currentDocText = docDrafts[activeDoc] || "";
  const currentDocBytes = useMemo(() => utf8ByteLength(currentDocText), [currentDocText]);
  const currentDocOverLimit = currentDocBytes > maxDocBytes;
  const skillContentBytes = useMemo(() => utf8ByteLength(skillContentDraft), [skillContentDraft]);
  const skillOverLimit = skillContentBytes > maxDocBytes;

  const teamSkillsByOwner = useMemo(() => {
    const groups: Record<string, typeof botProfile extends null ? never : NonNullable<typeof botProfile>["team_skills"]> = {};
    for (const item of botProfile?.team_skills || []) {
      const owner = item.owner || "unknown";
      if (!groups[owner]) groups[owner] = [];
      groups[owner].push(item);
    }
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [botProfile]);

  const handleSaveConfig = async () => {
    const reqHandle = selectedHandle;
    if (!reqHandle || !botConfig || !canEdit) return;
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
      if (selectedHandleRef.current !== reqHandle) return;
      cfgReqSeqRef.current += 1;
      setBotConfig(updated);
      syncFormFromConfig(updated);
      setCfgNotice("配置已通过 Bridge Single-Writer 保存并刷新心跳。");
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (!handleAuthErr(err)) {
        setCfgError(err instanceof Error ? err.message : "保存配置失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setSaving(false);
      }
    }
  };

  const handleSaveProfileDoc = async () => {
    const reqHandle = selectedHandle;
    const targetDoc = activeDoc;
    if (!reqHandle || !botProfile || !canEditProfile || currentDocOverLimit) return;
    setProfSaving(true);
    setProfError(null);
    setProfNotice(null);
    setProfConflictRev(null);
    try {
      const savedContent = docDraftsRef.current[targetDoc] || "";
      const updated = await updateBotProfile(reqHandle, {
        expected_rev: botProfile.rev,
        doc: targetDoc,
        content: savedContent,
      });
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      profReqSeqRef.current += 1;
      setBotProfile(updated);
      const nextDrafts: Record<BotProfileDocName, string> = {
        ...docDraftsRef.current,
        [targetDoc]: updated.docs[targetDoc] ?? savedContent,
      };
      setDocDrafts(nextDrafts);
      docDraftsRef.current = nextDrafts;
      const anyDocStillDirty = DOC_TABS.some(
        (dt) => (nextDrafts[dt.key] || "") !== (updated.docs[dt.key] || ""),
      );
      setProfDirty(anyDocStillDirty);
      profDirtyRef.current = anyDocStillDirty;
      setProfNotice(`${targetDoc} 已保存（rev=${updated.rev}），空闲会话已失效，下一轮热生效。`);
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (handleAuthErr(err)) return;
      if (err instanceof StudioApiError && err.status === 409) {
        const curRev =
          typeof err.data?.current_rev === "number" ? err.data.current_rev : null;
        setProfConflictRev(curRev);
        setProfError(
          `版本冲突 (409 Conflict)：远端已更新${curRev !== null ? `至 rev=${curRev}` : ""}。您的本地草稿已保留，未被覆盖。`,
        );
      } else {
        setProfError(err instanceof Error ? err.message : "保存文档失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setProfSaving(false);
      }
    }
  };

  const handleSaveSkillsPolicy = async () => {
    const reqHandle = selectedHandle;
    if (!reqHandle || !botProfile || !canEditProfile) return;
    setPolicySaving(true);
    setProfError(null);
    setProfNotice(null);
    setProfConflictRev(null);
    try {
      const updated = await updateBotProfile(reqHandle, {
        expected_rev: botProfile.rev,
        skills_policy: {
          mode: policyMode,
          enabled_catalog_skills: enabledCatalogSkills,
        },
      });
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      profReqSeqRef.current += 1;
      setBotProfile(updated);
      setPolicyMode(updated.skills_policy.mode);
      setEnabledCatalogSkills([...updated.skills_policy.enabled_catalog_skills]);
      setPolicyDirty(false);
      policyDirtyRef.current = false;
      setProfNotice(`目录 Skills 授权策略已更新（rev=${updated.rev}）。`);
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (handleAuthErr(err)) return;
      if (err instanceof StudioApiError && err.status === 409) {
        const curRev =
          typeof err.data?.current_rev === "number" ? err.data.current_rev : null;
        setProfConflictRev(curRev);
        setProfError(`版本冲突 (409 Conflict)：策略未覆盖，请刷新后重试。`);
      } else {
        setProfError(err instanceof Error ? err.message : "保存 Skills 策略失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setPolicySaving(false);
      }
    }
  };

  const handleOpenEditSkill = async (slug: string) => {
    const reqHandle = selectedHandle;
    if (!reqHandle) return;
    const reqSeq = ++skillReqSeqRef.current;
    setSkillEditorOpen(true);
    setSkillEditorIsNew(false);
    setSkillSlugDraft(slug);
    setSkillLoading(true);
    setProfError(null);
    setProfNotice(null);
    try {
      const detail = await fetchBotSkill(reqHandle, slug);
      if (
        !mountedRef.current ||
        skillReqSeqRef.current !== reqSeq ||
        selectedHandleRef.current !== reqHandle
      ) {
        return;
      }
      setSkillContentDraft(detail.content);
      setSkillDirty(false);
      skillDirtyRef.current = false;
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (!handleAuthErr(err)) {
        setProfError(err instanceof Error ? err.message : "读取 Skill 内容失败");
      }
      setSkillEditorOpen(false);
    } finally {
      if (mountedRef.current && skillReqSeqRef.current === reqSeq) {
        setSkillLoading(false);
      }
    }
  };

  const handleOpenNewSkill = () => {
    if (!canEditProfile) return;
    setSkillEditorOpen(true);
    setSkillEditorIsNew(true);
    setSkillSlugDraft("");
    setSkillContentDraft(
      "---\nname: my-custom-skill\ndescription: Brief description of when to use this skill\n---\n\n# My Custom Skill\n\n- Step 1\n",
    );
    setSkillDirty(true);
    skillDirtyRef.current = true;
    setProfError(null);
    setProfNotice(null);
  };

  const handleSaveSkill = async () => {
    const reqHandle = selectedHandle;
    const slug = skillSlugDraft.trim().toLowerCase();
    if (!reqHandle || !botProfile || !canEditProfile || !SKILL_SLUG_RE.test(slug) || skillOverLimit) {
      return;
    }
    setSkillSaving(true);
    setProfError(null);
    setProfNotice(null);
    setProfConflictRev(null);
    try {
      const res = await saveBotSkill(reqHandle, slug, {
        expected_rev: botProfile.rev,
        content: skillContentDraft,
      });
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      setSkillDirty(false);
      skillDirtyRef.current = false;
      setSkillEditorIsNew(false);
      setProfNotice(`自有 Skill \`${slug}\` 已保存（rev=${res.rev}）。`);
      await loadProfile(reqHandle, { background: false, forceResetDraft: false });
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (handleAuthErr(err)) return;
      if (err instanceof StudioApiError && err.status === 409) {
        const curRev =
          typeof err.data?.current_rev === "number" ? err.data.current_rev : null;
        setProfConflictRev(curRev);
        setProfError(`版本冲突 (409 Conflict)：Skill 草稿已保留，请先刷新 rev 后重试。`);
      } else {
        setProfError(err instanceof Error ? err.message : "保存 Skill 失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setSkillSaving(false);
      }
    }
  };

  const handleDeleteSkill = async (slug: string) => {
    const reqHandle = selectedHandle;
    if (!reqHandle || !botProfile || !canEditProfile) return;
    setSkillSaving(true);
    setProfError(null);
    setProfNotice(null);
    setProfConflictRev(null);
    try {
      const res = await deleteBotSkill(reqHandle, slug, botProfile.rev);
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (skillSlugDraft === slug) {
        setSkillEditorOpen(false);
        setSkillDirty(false);
        skillDirtyRef.current = false;
      }
      setProfNotice(`自有 Skill \`${slug}\` 已删除（rev=${res.rev}）。`);
      await loadProfile(reqHandle, { background: false, forceResetDraft: false });
    } catch (err) {
      if (!mountedRef.current || selectedHandleRef.current !== reqHandle) return;
      if (handleAuthErr(err)) return;
      if (err instanceof StudioApiError && err.status === 409) {
        const curRev =
          typeof err.data?.current_rev === "number" ? err.data.current_rev : null;
        setProfConflictRev(curRev);
        setProfError("版本冲突 (409 Conflict)：删除被拒绝，请先刷新最新版本。");
      } else {
        setProfError(err instanceof Error ? err.message : "删除 Skill 失败");
      }
    } finally {
      if (mountedRef.current && selectedHandleRef.current === reqHandle) {
        setSkillSaving(false);
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
      if (selectedHandleRef.current !== reqHandle) return;
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
      if (selectedHandleRef.current !== reqHandle) return;
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
              ? "只读视图 · 独立人格/规则/记忆、Skills 策略与节点心跳"
              : "管理员控制面 · 模型策略、独立 Soul/Rules/Memory 编辑、Skills 隔离与安全热重载"}
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            void load();
            if (selectedHandle) {
              void loadConfig(selectedHandle);
              void loadProfile(selectedHandle, { background: false, forceResetDraft: false });
            }
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
        >
          <RefreshCw
            className={`w-3.5 h-3.5 ${loading || cfgLoading || profLoading ? "animate-spin" : ""}`}
          />
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
                  <dd className="text-slate-200 font-mono truncate">{b.effective_model}</dd>
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

      {/* Selected Bot Detail Card with 4 Sub-Tabs */}
      {selectedHandle && (
        <section className="rounded-xl border border-slate-800 bg-slate-900/75 p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <Sliders className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                节点管理：{botConfig?.display_name || selectedHandle}
              </h3>
              <span className="text-xs font-mono text-slate-500">({selectedHandle})</span>
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                  ipcOnline
                    ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {ipcOnline ? "IPC 在线" : "IPC 离线（只读回退）"}
              </span>
              {botProfile && (
                <span className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-300">
                  rev={botProfile.rev}
                </span>
              )}
            </div>

            {canEdit && (
              <div className="flex items-center gap-2">
                {!confirmReload ? (
                  <button
                    type="button"
                    disabled={reloading || activeCooldown > 0}
                    onClick={() => setConfirmReload(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20 disabled:opacity-40 text-amber-200 text-xs font-medium cursor-pointer"
                  >
                    <Power className="w-3.5 h-3.5" />
                    {activeCooldown > 0 ? `冷却中 (${activeCooldown}s)` : "安全热重载"}
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

          {/* Sub-Tabs */}
          <div className="flex flex-wrap gap-1.5 border-b border-slate-800/80 pb-3">
            {(
              [
                { id: "config" as DetailTab, label: "基础配置", icon: Sliders },
                {
                  id: "persona" as DetailTab,
                  label: "人格与规则",
                  icon: FileText,
                  dirty: profDirty,
                },
                {
                  id: "skills" as DetailTab,
                  label: "独立 Skills",
                  icon: Sparkles,
                  dirty: policyDirty || skillDirty,
                },
                { id: "memory" as DetailTab, label: "独立记忆", icon: Brain },
              ] as const
            ).map((tab) => {
              const Icon = tab.icon;
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                    active
                      ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                      : "bg-slate-950/60 text-slate-400 border border-slate-800 hover:text-slate-200"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                  {"dirty" in tab && tab.dirty && (
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                  )}
                </button>
              );
            })}
          </div>

          {(isReadonly || !ipcOnline) && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 shrink-0" />
              <span>
                {isReadonly
                  ? "当前为只读角色（readonly），所有配置、人格/规则与 Skills 编辑控件已锁定。"
                  : "目标 Bot Bridge IPC 离线，当前仅提供只读回退视图，所有写操作已禁用。"}
              </span>
            </div>
          )}

          {/* TAB 1: 基础配置 */}
          {activeTab === "config" && (
            <div className="space-y-5">
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
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                    <label className="space-y-1 text-xs">
                      <span className="text-slate-400 block">模型策略 (model_mode)</span>
                      <select
                        value={modelMode}
                        disabled={!canEdit || saving}
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
                        disabled={!canEdit || modelMode !== "custom" || saving}
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
                        disabled={!canEdit || saving}
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
                        disabled={!canEdit || saving}
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

                  {canEdit && (
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-[11px] text-slate-400 font-mono truncate">
                          生效模型：{botConfig.effective_model || "default"} · 角色：{botConfig.role}
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
                              <span className="text-[10px] text-slate-400">{m.transport}</span>
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                        <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                        <span>当前有效 Skills ({botConfig.skills.length})</span>
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
                </>
              ) : null}
            </div>
          )}

          {/* TAB 2: 人格与规则 (SOUL.md / RULES.md / MEMORY.md) */}
          {activeTab === "persona" && (
            <div className="space-y-4">
              {profError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>{profError}</span>
                  </div>
                  {profConflictRev !== null && (
                    <button
                      type="button"
                      onClick={() =>
                        selectedHandle &&
                        void loadProfile(selectedHandle, {
                          background: false,
                          forceResetDraft: true,
                        })
                      }
                      className="px-2.5 py-1 rounded bg-rose-600/80 hover:bg-rose-500 text-white text-[11px] shrink-0 cursor-pointer"
                    >
                      加载最新版本 (rev={profConflictRev})
                    </button>
                  )}
                </div>
              )}
              {profNotice && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200 flex items-center gap-2">
                  <Check className="w-4 h-4 shrink-0" />
                  <span>{profNotice}</span>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap gap-1.5">
                  {DOC_TABS.map((dt) => (
                    <button
                      key={dt.key}
                      type="button"
                      onClick={() => setActiveDoc(dt.key)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-mono border cursor-pointer ${
                        activeDoc === dt.key
                          ? "border-sky-500/50 bg-sky-500/15 text-sky-200"
                          : "border-slate-800 bg-slate-950/60 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {dt.label}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span
                    className={
                      currentDocOverLimit ? "text-rose-400 font-semibold" : "text-slate-400"
                    }
                  >
                    {currentDocBytes.toLocaleString()} / {maxDocBytes.toLocaleString()} B
                  </span>
                  {profDirty && (
                    <span className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-200">
                      未保存草稿
                    </span>
                  )}
                </div>
              </div>

              <p className="text-[11px] text-slate-400">
                {DOC_TABS.find((d) => d.key === activeDoc)?.hint}
              </p>

              <textarea
                value={currentDocText}
                disabled={!canEditProfile || profSaving}
                onChange={(e) => {
                  const val = e.target.value;
                  setDocDrafts((prev) => {
                    const next = { ...prev, [activeDoc]: val };
                    docDraftsRef.current = next;
                    return next;
                  });
                  setProfDirty(true);
                  profDirtyRef.current = true;
                }}
                rows={14}
                placeholder={`在此编辑 ${activeDoc}（Markdown，上限 24 KiB UTF-8）…`}
                className="w-full rounded-xl bg-slate-950 border border-slate-800 focus:border-sky-500/60 focus:outline-none p-3 font-mono text-xs text-slate-100 leading-relaxed disabled:opacity-60"
              />

              <div className="flex items-center justify-between gap-2">
                <div className="text-[11px] text-slate-500 font-mono">
                  版本 rev={botProfile?.rev ?? 0} · 经由 Bridge Single-Writer 原子落盘（0600）
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={!canEditProfile || !profDirty || profSaving}
                    onClick={() => {
                      if (botProfile) {
                        const resetDrafts: Record<BotProfileDocName, string> = {
                          "SOUL.md": botProfile.docs["SOUL.md"] || "",
                          "RULES.md": botProfile.docs["RULES.md"] || "",
                          "MEMORY.md": botProfile.docs["MEMORY.md"] || "",
                        };
                        setDocDrafts(resetDrafts);
                        docDraftsRef.current = resetDrafts;
                        setProfDirty(false);
                        profDirtyRef.current = false;
                        setProfConflictRev(null);
                        setProfError(null);
                      }
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-xs text-slate-300 cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    重置草稿
                  </button>
                  <button
                    type="button"
                    disabled={!canEditProfile || profSaving || currentDocOverLimit}
                    onClick={() => void handleSaveProfileDoc()}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium cursor-pointer"
                  >
                    {profSaving ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Save className="w-3.5 h-3.5" />
                    )}
                    保存 {activeDoc}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: 独立 Skills */}
          {activeTab === "skills" && !botProfile && (
            <div className="space-y-3">
              {profError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{profError}</span>
                </div>
              )}
              {profLoading ? (
                <div className="py-6 text-center text-xs text-slate-400 inline-flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                  加载 Bot Skills 配置中…
                </div>
              ) : !profError ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  暂无该 Bot 的 Skills 配置数据，请点击右上角「刷新」重试。
                </div>
              ) : null}
            </div>
          )}
          {activeTab === "skills" && botProfile && (
            <div className="space-y-5">
              {profError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{profError}</span>
                </div>
              )}
              {profNotice && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-200 flex items-center gap-2">
                  <Check className="w-4 h-4 shrink-0" />
                  <span>{profNotice}</span>
                </div>
              )}

              {/* Own Bot Skills */}
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                    <span>Bot 自有 Skills ({botProfile.own_skills.length})</span>
                  </div>
                  <button
                    type="button"
                    disabled={!canEditProfile || skillSaving}
                    onClick={handleOpenNewSkill}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-40 text-white text-xs font-medium cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    新建 Skill
                  </button>
                </div>

                {botProfile.own_skills.length === 0 ? (
                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs text-slate-500">
                    该 Bot 尚无自有 Skill，点击右上角「新建 Skill」创建独立技能。
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {botProfile.own_skills.map((sk) => (
                      <div
                        key={sk.slug}
                        className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 flex items-start justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-xs font-mono text-slate-100 truncate">
                            {sk.slug}
                          </div>
                          <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                            {sk.description || sk.name}
                          </p>
                          <div className="text-[10px] font-mono text-slate-500 mt-1">
                            {sk.size_bytes.toLocaleString()} B
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            type="button"
                            disabled={!profileIpcOnline || skillLoading}
                            onClick={() => void handleOpenEditSkill(sk.slug)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-[11px] text-slate-200 cursor-pointer"
                          >
                            {canEditProfile ? "编辑" : "查看"}
                          </button>
                          <button
                            type="button"
                            disabled={!canEditProfile || skillSaving}
                            onClick={() => void handleDeleteSkill(sk.slug)}
                            className="p-1 rounded bg-rose-500/10 hover:bg-rose-500/20 disabled:opacity-40 text-rose-300 cursor-pointer"
                            title="删除自有 Skill"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {skillEditorOpen && (
                  <div className="rounded-xl border border-violet-500/30 bg-slate-950/90 p-4 space-y-3">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-semibold text-violet-200">
                        {skillEditorIsNew ? "新建 Bot 自有 Skill" : `编辑 Skill: ${skillSlugDraft}`}
                      </div>
                      <span
                        className={`text-[11px] font-mono ${
                          skillOverLimit ? "text-rose-400" : "text-slate-400"
                        }`}
                      >
                        {skillContentBytes.toLocaleString()} / {maxDocBytes.toLocaleString()} B
                      </span>
                    </div>

                    {skillEditorIsNew && (
                      <label className="block space-y-1 text-xs">
                        <span className="text-slate-400">
                          Skill Slug（仅允许小写字母、数字、`-`、`_`）
                        </span>
                        <input
                          type="text"
                          value={skillSlugDraft}
                          disabled={!canEditProfile || skillSaving}
                          onChange={(e) => {
                            setSkillSlugDraft(e.target.value);
                            setSkillDirty(true);
                            skillDirtyRef.current = true;
                          }}
                          placeholder="e.g. my-bot-checklist"
                          className="w-full h-8 rounded-lg bg-slate-900 border border-slate-700 px-2.5 font-mono text-xs text-slate-100"
                        />
                      </label>
                    )}

                    {skillLoading ? (
                      <div className="py-6 text-center text-xs text-slate-400">
                        加载 SKILL.md 中…
                      </div>
                    ) : (
                      <textarea
                        value={skillContentDraft}
                        disabled={!canEditProfile || skillSaving}
                        onChange={(e) => {
                          setSkillContentDraft(e.target.value);
                          setSkillDirty(true);
                          skillDirtyRef.current = true;
                        }}
                        rows={10}
                        className="w-full rounded-lg bg-slate-900 border border-slate-800 p-3 font-mono text-xs text-slate-100 disabled:opacity-60"
                      />
                    )}

                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setSkillEditorOpen(false);
                          setSkillDirty(false);
                          skillDirtyRef.current = false;
                        }}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 cursor-pointer"
                      >
                        关闭
                      </button>
                      <button
                        type="button"
                        disabled={
                          !canEditProfile ||
                          skillSaving ||
                          skillOverLimit ||
                          !SKILL_SLUG_RE.test(skillSlugDraft.trim().toLowerCase())
                        }
                        onClick={() => void handleSaveSkill()}
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-40 text-white text-xs font-medium cursor-pointer"
                      >
                        {skillSaving ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Save className="w-3.5 h-3.5" />
                        )}
                        保存 SKILL.md
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Catalog Skills Authorization */}
              <div className="space-y-3 pt-4 border-t border-slate-800/80">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-sky-400" />
                    <span>共享目录 Skills 授权策略</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <select
                      value={policyMode}
                      disabled={!canEditProfile || policySaving || botProfile.role === "coordinator"}
                      onChange={(e) => {
                        setPolicyMode(e.target.value as "allowlist" | "all");
                        setPolicyDirty(true);
                        policyDirtyRef.current = true;
                      }}
                      className="h-7 rounded-lg bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 disabled:opacity-50"
                    >
                      <option value="allowlist">allowlist（仅勾选白名单）</option>
                      <option value="all">all（全部共享目录）</option>
                    </select>
                    <button
                      type="button"
                      disabled={!canEditProfile || !policyDirty || policySaving}
                      onClick={() => void handleSaveSkillsPolicy()}
                      className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium cursor-pointer"
                    >
                      {policySaving ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <Save className="w-3 h-3" />
                      )}
                      保存策略
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {botProfile.catalog_skills.map((cat) => {
                    const checked =
                      botProfile.role === "coordinator" ||
                      policyMode === "all" ||
                      enabledCatalogSkills.includes(cat.slug);
                    return (
                      <label
                        key={cat.slug}
                        className="rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-2 flex items-start gap-2 text-xs cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={
                            !canEditProfile ||
                            policySaving ||
                            policyMode === "all" ||
                            botProfile.role === "coordinator"
                          }
                          onChange={(e) => {
                            const next = e.target.checked
                              ? Array.from(new Set([...enabledCatalogSkills, cat.slug])).sort()
                              : enabledCatalogSkills.filter((s) => s !== cat.slug);
                            setEnabledCatalogSkills(next);
                            setPolicyDirty(true);
                            policyDirtyRef.current = true;
                          }}
                          className="mt-0.5 rounded border-slate-700"
                        />
                        <div className="min-w-0">
                          <div className="font-mono text-slate-200 truncate">{cat.slug}</div>
                          {cat.description && (
                            <p className="text-[11px] text-slate-400 line-clamp-2">
                              {cat.description}
                            </p>
                          )}
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Coordinator Full-Team Aggregated Skills Read-Only View */}
              {botProfile.role === "coordinator" && (
                <div className="space-y-3 pt-4 border-t border-slate-800/80">
                  <div className="text-xs font-semibold text-sky-300 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>
                      总指挥全员 Skills 聚合只读视图 ({botProfile.team_skills.length})
                    </span>
                  </div>
                  {teamSkillsByOwner.length === 0 ? (
                    <div className="text-xs text-slate-500">暂无其他成员的自有 Skills</div>
                  ) : (
                    <div className="space-y-2.5">
                      {teamSkillsByOwner.map(([owner, skills]) => (
                        <div
                          key={owner}
                          className="rounded-lg border border-sky-500/20 bg-sky-500/5 p-3 space-y-2"
                        >
                          <div className="text-xs font-mono text-sky-200">
                            @{owner}（{skills.length}）
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {skills.map((sk) => (
                              <div
                                key={`${owner}-${sk.slug}`}
                                className="rounded border border-slate-800 bg-slate-950/70 px-2.5 py-1.5"
                              >
                                <div className="text-xs font-mono text-slate-200">{sk.slug}</div>
                                <p className="text-[11px] text-slate-400 line-clamp-2">
                                  {sk.description || sk.name}
                                </p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: 独立记忆 */}
          {activeTab === "memory" && !botProfile && (
            <div className="space-y-3">
              {profError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{profError}</span>
                </div>
              )}
              {profLoading ? (
                <div className="py-6 text-center text-xs text-slate-400 inline-flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
                  加载 Bot 记忆统计中…
                </div>
              ) : !profError ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  暂无该 Bot 的独立记忆统计数据，请点击右上角「刷新」重试。
                </div>
              ) : null}
            </div>
          )}
          {activeTab === "memory" && botProfile && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                  <div className="text-[11px] text-slate-400">记忆项目</div>
                  <div className="text-xs font-mono text-sky-300 mt-1 truncate">
                    {botProfile.memory_stats.memory_project}
                  </div>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                  <div className="text-[11px] text-slate-400">记忆视野</div>
                  <div className="text-xs font-mono text-emerald-300 mt-1">
                    {botProfile.memory_stats.memory_scope === "coordinator_all"
                      ? "coordinator_all（全员聚合）"
                      : "isolated（严格隔离）"}
                  </div>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                  <div className="text-[11px] text-slate-400">Observations / Summaries</div>
                  <div className="text-sm font-mono text-slate-100 mt-1">
                    {botProfile.memory_stats.observations_count} /{" "}
                    {botProfile.memory_stats.summaries_count}
                  </div>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                  <div className="text-[11px] text-slate-400">独立 Instincts</div>
                  <div className="text-sm font-mono text-violet-300 mt-1">
                    {botProfile.memory_stats.instincts_count}
                  </div>
                </div>
              </div>

              {botProfile.memory_stats.active_instincts_preview && (
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-slate-300">
                    本 Bot 活跃 Instincts 摘要
                  </div>
                  <pre className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] font-mono text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {botProfile.memory_stats.active_instincts_preview}
                  </pre>
                </div>
              )}

              {botProfile.role === "coordinator" &&
                botProfile.memory_stats.team_memory &&
                botProfile.memory_stats.team_memory.length > 0 && (
                  <div className="space-y-2 pt-3 border-t border-slate-800/80">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-sky-300">
                        总指挥全员记忆聚合视图（总计 Observations:{" "}
                        {botProfile.memory_stats.total_observations ?? 0} · Summaries:{" "}
                        {botProfile.memory_stats.total_summaries ?? 0} · Instincts:{" "}
                        {botProfile.memory_stats.total_instincts ?? 0}）
                      </span>
                    </div>
                    <div className="overflow-x-auto rounded-lg border border-slate-800">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950/90 text-slate-400">
                          <tr>
                            <th className="px-3 py-2 font-medium">项目 / Bot</th>
                            <th className="px-3 py-2 font-medium text-right">Observations</th>
                            <th className="px-3 py-2 font-medium text-right">Summaries</th>
                            <th className="px-3 py-2 font-medium text-right">Instincts</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {botProfile.memory_stats.team_memory.map((row) => (
                            <tr key={row.project} className="bg-slate-900/40">
                              <td className="px-3 py-2 font-mono text-slate-200">
                                {row.project}
                                {row.handle ? (
                                  <span className="ml-1.5 text-[10px] text-slate-500">
                                    (@{row.handle})
                                  </span>
                                ) : null}
                              </td>
                              <td className="px-3 py-2 text-right font-mono text-slate-300">
                                {row.observations_count}
                              </td>
                              <td className="px-3 py-2 text-right font-mono text-slate-300">
                                {row.summaries_count}
                              </td>
                              <td className="px-3 py-2 text-right font-mono text-violet-300">
                                {row.instincts_count}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
