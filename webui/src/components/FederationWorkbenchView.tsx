import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  Archive,
  Bell,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  EyeOff,
  Folder,
  FolderPlus,
  History,
  Inbox,
  Layers,
  Lock,
  MessageSquare,
  MoreHorizontal,
  Network,
  PanelLeft,
  PanelRightClose,
  PanelRightOpen,
  Pencil,
  Pin,
  Plus,
  Radio,
  RefreshCw,
  Send,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Square,
  Tag,
  Terminal,
  Trash2,
  Users,
  X,
} from "lucide-react";
import {
  StudioApiError,
  cancelFederationWorkbenchJob,
  dispatchFederationWorkbenchJob,
  fetchFederationChatroomMessages,
  fetchFederationWorkbench,
  fetchFederationWorkbenchState,
  fetchFederationWorkbenchTimeline,
  sendFederationChatroomMessage,
  updateFederationWorkbenchState,
} from "../api";
import { SafeMarkdown } from "./SafeMarkdown";
import type {
  FederationChatroomMessageItem,
  FederationChatroomMessagesResponse,
  FederationChatroomParticipant,
  FederationHubConfig,
  FederationLeaderEventSummary,
  FederationPullInboxItem,
  FederationRuntimeStatus,
  FederationTimelineJobItem,
  FederationTimelineSource,
  FederationWorkbenchAgentItem,
  FederationWorkbenchConversation,
  FederationWorkbenchProject,
  FederationWorkbenchState,
  FederationWorkbenchUiPrefs,
  NavTab,
  StudioSession,
} from "../types";

interface FederationWorkbenchViewProps {
  session: StudioSession;
  federationEventVer?: number;
  jobsEventVer?: number;
  onNavigate?: (tab: NavTab) => void;
  onSessionRevoked?: (reason: string) => void;
}

type MobilePane = "projects" | "chat" | "telemetry";
type ActivePaneMode = "chatroom" | "conversation";

const POLL_ACTIVE_INTERVAL_MS = 4000;
const POLL_IDLE_INTERVAL_MS = 30000;
const CHATROOM_SSE_DEBOUNCE_MS = 300;

const DEFAULT_PROJECT_ID = "default";
const EXTERNAL_HISTORY_PROJECT_ID = "__external_history__";
const EXTERNAL_HISTORY_CONV_ID = "__external_history_view__";
const MAX_VISIBLE_CONVS_PER_PROJECT = 6;
const MAX_CUSTOM_PROJECTS = 64;
const MAX_CONVERSATIONS = 512;

const FORBIDDEN_PROTO_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SAFE_PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_CONV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const HEARTBEAT_ACTION_LABELS: Record<string, string> = {
  peek: "peek",
  inbox: "inbox",
  claim: "claim",
  result: "result",
  events_ack: "events_ack",
  mcp: "mcp",
};

const CTRL_CHARS_RE = /[\x00-\x1f\x7f]+/g;

function isSafeRecordKey(key: string): boolean {
  const trimmed = key.trim();
  if (!trimmed || FORBIDDEN_PROTO_KEYS.has(trimmed) || FORBIDDEN_PROTO_KEYS.has(trimmed.toLowerCase())) {
    return false;
  }
  return !trimmed.includes("..") && !trimmed.includes("/") && !trimmed.includes("\\");
}

function normalizeSingleLineText(raw: string, maxLen: number): string {
  return raw.replace(CTRL_CHARS_RE, " ").trim().slice(0, maxLen).trim();
}

function emptyUiPrefs(): FederationWorkbenchUiPrefs {
  return {
    sidebarCollapsed: false,
    showArchived: false,
    onlyPinned: false,
    onlyUnread: false,
    telemetryOpen: true,
    selectedAgentId: "",
    selectedProjectId: DEFAULT_PROJECT_ID,
    selectedConversationId: "",
  };
}

function emptyFedWorkbenchState(): FederationWorkbenchState {
  return {
    customProjects: [],
    conversations: [],
    pinnedConversationIds: [],
    archivedConversationIds: [],
    hiddenConversationIds: [],
    collapsedProjectIds: [],
    hiddenProjectIds: [],
    renamedProjects: {},
    renamedConversations: {},
    readAtByConversation: {},
    uiPrefs: emptyUiPrefs(),
  };
}

function sanitizeIdList(raw: unknown, re: RegExp, maxLen: number, allowBuiltins = false): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const s = item.trim();
    if (!s || !isSafeRecordKey(s)) continue;
    const isBuiltin = allowBuiltins && (s === DEFAULT_PROJECT_ID || s === EXTERNAL_HISTORY_PROJECT_ID);
    if (!isBuiltin && !re.test(s)) continue;
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
      if (out.length >= maxLen) break;
    }
  }
  return out;
}

function sanitizeStringRecord(
  raw: unknown,
  keyRe: RegExp,
  maxEntries: number,
  maxValLen: number,
  allowBuiltins = false,
): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!isSafeRecordKey(k) || typeof v !== "string") continue;
    const ck = k.trim();
    const isBuiltin =
      allowBuiltins && (ck === DEFAULT_PROJECT_ID || ck === EXTERNAL_HISTORY_PROJECT_ID);
    if (!isBuiltin && !keyRe.test(ck)) continue;
    const cv = normalizeSingleLineText(v, maxValLen);
    if (!cv) continue;
    out[ck] = cv;
    count += 1;
    if (count >= maxEntries) break;
  }
  return out;
}

function sanitizeNumberRecord(
  raw: unknown,
  keyRe: RegExp,
  maxEntries: number,
): Record<string, number> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, number> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!isSafeRecordKey(k) || typeof v !== "number" || !Number.isFinite(v) || v < 0) continue;
    const ck = k.trim();
    if (!keyRe.test(ck)) continue;
    out[ck] = v;
    count += 1;
    if (count >= maxEntries) break;
  }
  return out;
}

function sanitizeFedWorkbenchState(raw: unknown): FederationWorkbenchState {
  const base = emptyFedWorkbenchState();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return base;
  const obj = raw as Record<string, unknown>;

  if (Array.isArray(obj.customProjects)) {
    const seen = new Set<string>();
    const list: FederationWorkbenchProject[] = [];
    for (const item of obj.customProjects) {
      if (!item || typeof item !== "object" || Array.isArray(item)) continue;
      const rec = item as Record<string, unknown>;
      const id = typeof rec.id === "string" ? rec.id.trim() : "";
      const name = typeof rec.name === "string" ? normalizeSingleLineText(rec.name, 64) : "";
      if (
        !id ||
        !name ||
        !isSafeRecordKey(id) ||
        !SAFE_PROJECT_ID_RE.test(id) ||
        id === DEFAULT_PROJECT_ID ||
        id === EXTERNAL_HISTORY_PROJECT_ID ||
        seen.has(id.toLowerCase())
      ) {
        continue;
      }
      seen.add(id.toLowerCase());
      const proj: FederationWorkbenchProject = { id, name };
      if (typeof rec.description === "string") {
        const cleanDesc = normalizeSingleLineText(rec.description, 240);
        if (cleanDesc) {
          proj.description = cleanDesc;
        }
      }
      if (typeof rec.createdAt === "number" && Number.isFinite(rec.createdAt) && rec.createdAt > 0) {
        proj.createdAt = rec.createdAt;
      }
      list.push(proj);
      if (list.length >= MAX_CUSTOM_PROJECTS) break;
    }
    base.customProjects = list;
  }

  if (Array.isArray(obj.conversations)) {
    const seen = new Set<string>();
    const list: FederationWorkbenchConversation[] = [];
    for (const item of obj.conversations) {
      if (!item || typeof item !== "object" || Array.isArray(item)) continue;
      const rec = item as Record<string, unknown>;
      const id = typeof rec.id === "string" ? rec.id.trim() : "";
      const agentId = typeof rec.agentId === "string" ? rec.agentId.trim() : "";
      const projectId = typeof rec.projectId === "string" ? rec.projectId.trim() : "";
      const title = typeof rec.title === "string" ? normalizeSingleLineText(rec.title, 120) : "";
      if (
        !id ||
        !agentId ||
        !projectId ||
        !title ||
        !isSafeRecordKey(id) ||
        !isSafeRecordKey(agentId) ||
        !isSafeRecordKey(projectId) ||
        !SAFE_CONV_ID_RE.test(id) ||
        !SAFE_PROJECT_ID_RE.test(agentId) ||
        (projectId !== DEFAULT_PROJECT_ID && !SAFE_PROJECT_ID_RE.test(projectId)) ||
        seen.has(id)
      ) {
        continue;
      }
      seen.add(id);
      const conv: FederationWorkbenchConversation = { id, agentId, projectId, title };
      if (typeof rec.createdAt === "number" && Number.isFinite(rec.createdAt) && rec.createdAt > 0) {
        conv.createdAt = rec.createdAt;
      }
      if (typeof rec.updatedAt === "number" && Number.isFinite(rec.updatedAt) && rec.updatedAt > 0) {
        conv.updatedAt = rec.updatedAt;
      }
      list.push(conv);
      if (list.length >= MAX_CONVERSATIONS) break;
    }
    base.conversations = list;
  }

  base.pinnedConversationIds = sanitizeIdList(obj.pinnedConversationIds, SAFE_CONV_ID_RE, 256);
  base.archivedConversationIds = sanitizeIdList(obj.archivedConversationIds, SAFE_CONV_ID_RE, 512);
  base.hiddenConversationIds = sanitizeIdList(obj.hiddenConversationIds, SAFE_CONV_ID_RE, 512);
  base.collapsedProjectIds = sanitizeIdList(obj.collapsedProjectIds, SAFE_PROJECT_ID_RE, 128, true);
  base.hiddenProjectIds = sanitizeIdList(obj.hiddenProjectIds, SAFE_PROJECT_ID_RE, 128, true);
  base.renamedProjects = sanitizeStringRecord(obj.renamedProjects, SAFE_PROJECT_ID_RE, 128, 64, true);
  base.renamedConversations = sanitizeStringRecord(obj.renamedConversations, SAFE_CONV_ID_RE, 512, 120);
  base.readAtByConversation = sanitizeNumberRecord(obj.readAtByConversation, SAFE_CONV_ID_RE, 512);

  if (obj.uiPrefs && typeof obj.uiPrefs === "object" && !Array.isArray(obj.uiPrefs)) {
    const up = obj.uiPrefs as Record<string, unknown>;
    base.uiPrefs = {
      sidebarCollapsed: typeof up.sidebarCollapsed === "boolean" ? up.sidebarCollapsed : false,
      showArchived: typeof up.showArchived === "boolean" ? up.showArchived : false,
      onlyPinned: typeof up.onlyPinned === "boolean" ? up.onlyPinned : false,
      onlyUnread: typeof up.onlyUnread === "boolean" ? up.onlyUnread : false,
      telemetryOpen: typeof up.telemetryOpen === "boolean" ? up.telemetryOpen : true,
      selectedAgentId:
        typeof up.selectedAgentId === "string" &&
        isSafeRecordKey(up.selectedAgentId) &&
        SAFE_PROJECT_ID_RE.test(up.selectedAgentId.trim())
          ? up.selectedAgentId.trim()
          : "",
      selectedProjectId:
        typeof up.selectedProjectId === "string" &&
        isSafeRecordKey(up.selectedProjectId) &&
        (up.selectedProjectId.trim() === DEFAULT_PROJECT_ID ||
          up.selectedProjectId.trim() === EXTERNAL_HISTORY_PROJECT_ID ||
          SAFE_PROJECT_ID_RE.test(up.selectedProjectId.trim()))
          ? up.selectedProjectId.trim()
          : DEFAULT_PROJECT_ID,
      selectedConversationId:
        typeof up.selectedConversationId === "string" &&
        isSafeRecordKey(up.selectedConversationId) &&
        SAFE_CONV_ID_RE.test(up.selectedConversationId.trim())
          ? up.selectedConversationId.trim()
          : "",
    };
  }

  return base;
}

function mergeFedWorkbenchStates(
  remote: FederationWorkbenchState,
  local: FederationWorkbenchState,
): FederationWorkbenchState {
  const projMap = new Map<string, FederationWorkbenchProject>();
  for (const p of remote.customProjects) projMap.set(p.id, p);
  for (const p of local.customProjects) projMap.set(p.id, p);

  const convMap = new Map<string, FederationWorkbenchConversation>();
  for (const c of remote.conversations) convMap.set(c.id, c);
  for (const c of local.conversations) {
    const prev = convMap.get(c.id);
    if (!prev || (c.updatedAt || 0) >= (prev.updatedAt || 0)) {
      convMap.set(c.id, c);
    }
  }

  const readAt: Record<string, number> = { ...remote.readAtByConversation };
  for (const [k, v] of Object.entries(local.readAtByConversation)) {
    if (!isSafeRecordKey(k)) continue;
    const prevReadAt = Object.prototype.hasOwnProperty.call(readAt, k) ? readAt[k] : 0;
    readAt[k] = Math.max(prevReadAt, v);
  }

  return sanitizeFedWorkbenchState({
    customProjects: Array.from(projMap.values()).slice(0, MAX_CUSTOM_PROJECTS),
    conversations: Array.from(convMap.values()).slice(0, MAX_CONVERSATIONS),
    pinnedConversationIds: Array.from(
      new Set([...local.pinnedConversationIds, ...remote.pinnedConversationIds]),
    ),
    archivedConversationIds: Array.from(
      new Set([...local.archivedConversationIds, ...remote.archivedConversationIds]),
    ),
    hiddenConversationIds: Array.from(
      new Set([...local.hiddenConversationIds, ...remote.hiddenConversationIds]),
    ),
    collapsedProjectIds: local.collapsedProjectIds,
    hiddenProjectIds: Array.from(new Set([...local.hiddenProjectIds, ...remote.hiddenProjectIds])),
    renamedProjects: { ...remote.renamedProjects, ...local.renamedProjects },
    renamedConversations: { ...remote.renamedConversations, ...local.renamedConversations },
    readAtByConversation: readAt,
    uiPrefs: { ...remote.uiPrefs, ...local.uiPrefs },
  });
}

function makeProjectId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  const rand = Math.random().toString(36).slice(2, 7);
  return slug ? `proj-${slug}-${rand}` : `proj-${Date.now().toString(36)}-${rand}`;
}

function makeConversationId(): string {
  const rand = Math.random().toString(36).slice(2, 8);
  return `conv-${Date.now().toString(36)}-${rand}`;
}

function formatHeartbeatLabel(
  lastHeartbeatAt?: number | null,
  lastHeartbeatAction?: string | null,
): string {
  if (
    typeof lastHeartbeatAt !== "number" ||
    !Number.isFinite(lastHeartbeatAt) ||
    lastHeartbeatAt <= 0
  ) {
    return "";
  }
  const deltaSec = Math.max(0, Math.floor(Date.now() / 1000 - lastHeartbeatAt));
  let agoText: string;
  if (deltaSec < 60) {
    agoText = `${deltaSec}s 前`;
  } else if (deltaSec < 3600) {
    agoText = `${Math.floor(deltaSec / 60)}m 前`;
  } else if (deltaSec < 86400) {
    agoText = `${Math.floor(deltaSec / 3600)}h 前`;
  } else {
    agoText = `${Math.floor(deltaSec / 86400)}d 前`;
  }
  const rawAct =
    typeof lastHeartbeatAction === "string" ? lastHeartbeatAction.trim().toLowerCase() : "";
  const safeAct = Object.prototype.hasOwnProperty.call(HEARTBEAT_ACTION_LABELS, rawAct)
    ? HEARTBEAT_ACTION_LABELS[rawAct]
    : "";
  return safeAct ? `心跳 ${agoText} · ${safeAct}` : `心跳 ${agoText}`;
}

function formatCompactAge(ts?: number | null): string {
  if (!ts || !Number.isFinite(ts) || ts <= 0) return "";
  const delta = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (delta < 60) return "刚刚";
  if (delta < 3600) return `${Math.floor(delta / 60)}m`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h`;
  return `${Math.floor(delta / 86400)}d`;
}

function formatTs(ts?: number | null): string {
  if (!ts || !Number.isFinite(ts)) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

function formatElapsed(sec?: number | null): string {
  if (sec == null || !Number.isFinite(sec)) return "";
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${s}s`;
}

function runtimeStatusMeta(status: FederationRuntimeStatus): {
  label: string;
  dot: string;
  badge: string;
  glyph: string;
} {
  switch (status) {
    case "online":
      return {
        label: "在线",
        dot: "bg-emerald-400",
        badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        glyph: "●",
      };
    case "stale":
      return {
        label: "静默",
        dot: "bg-amber-400",
        badge: "bg-amber-500/15 text-amber-300 border-amber-500/30",
        glyph: "◐",
      };
    case "disabled":
      return {
        label: "已停用",
        dot: "bg-slate-500",
        badge: "bg-slate-800 text-slate-400 border-slate-700",
        glyph: "○",
      };
    case "revoked":
      return {
        label: "已吊销",
        dot: "bg-rose-500",
        badge: "bg-rose-500/15 text-rose-300 border-rose-500/30",
        glyph: "○",
      };
    default:
      return {
        label: "离线",
        dot: "bg-slate-500",
        badge: "bg-slate-800/80 text-slate-300 border-slate-700",
        glyph: "○",
      };
  }
}

function sourceBadgeMeta(source: FederationTimelineSource): { label: string; cls: string } {
  switch (source) {
    case "studio":
      return { label: "Studio", cls: "bg-sky-500/15 text-sky-300 border-sky-500/30" };
    case "telegram":
      return { label: "Telegram", cls: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30" };
    case "bus":
      return { label: "Bus", cls: "bg-violet-500/15 text-violet-300 border-violet-500/30" };
    default:
      return { label: "Pull", cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" };
  }
}

function jobStatusBadge(status: string): { label: string; cls: string } {
  switch (status) {
    case "done":
      return { label: "已完成", cls: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" };
    case "running":
      return { label: "执行中", cls: "bg-sky-500/15 text-sky-300 border-sky-500/30" };
    case "claimed":
      return { label: "已认领", cls: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" };
    case "queued":
      return { label: "排队中", cls: "bg-amber-500/15 text-amber-300 border-amber-500/30" };
    case "cancelled":
      return { label: "已取消", cls: "bg-slate-700/60 text-slate-300 border-slate-600" };
    case "error":
      return { label: "错误", cls: "bg-rose-500/15 text-rose-300 border-rose-500/30" };
    default:
      return { label: status || "未知", cls: "bg-slate-800 text-slate-300 border-slate-700" };
  }
}

interface SidebarConversationView {
  id: string;
  agentId: string;
  projectId: string;
  title: string;
  updatedAt: number;
  turnCount: number;
  hasActive: boolean;
  isPinned: boolean;
  isArchived: boolean;
  isUnread: boolean;
  isVirtual?: boolean;
}

export function FederationWorkbenchView({
  session,
  federationEventVer = 0,
  jobsEventVer = 0,
  onNavigate,
  onSessionRevoked,
}: FederationWorkbenchViewProps) {
  const [agents, setAgents] = useState<FederationWorkbenchAgentItem[]>([]);
  const [hubConfig, setHubConfig] = useState<FederationHubConfig | null>(null);
  const [serverCanEdit, setServerCanEdit] = useState(session.role === "admin");
  const [wbState, setWbState] = useState<FederationWorkbenchState>(() => emptyFedWorkbenchState());

  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [selectedProjectId, setSelectedProjectId] = useState<string>(DEFAULT_PROJECT_ID);
  const [selectedConversationId, setSelectedConversationId] = useState<string>("");
  const [activePaneMode, setActivePaneMode] = useState<ActivePaneMode>("conversation");

  // Standalone Federation Chatroom (TG Group Bidirectional Mirror) State
  const [chatroomData, setChatroomData] = useState<FederationChatroomMessagesResponse | null>(null);
  const [chatroomLoading, setChatroomLoading] = useState(false);
  const [chatroomSending, setChatroomSending] = useState(false);
  const [chatroomInput, setChatroomInput] = useState("");
  const [chatroomIncludeContext, setChatroomIncludeContext] = useState(true);
  const [chatroomReadSeq, setChatroomReadSeq] = useState<number | null>(null);

  const [timeline, setTimeline] = useState<FederationTimelineJobItem[]>([]);
  const [pullInbox, setPullInbox] = useState<FederationPullInboxItem[]>([]);
  const [leaderEvents, setLeaderEvents] = useState<FederationLeaderEventSummary[]>([]);
  const [hasActiveJobs, setHasActiveJobs] = useState(false);

  const [loadingList, setLoadingList] = useState(true);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [sending, setSending] = useState(false);
  const [cancellingJobId, setCancellingJobId] = useState<string | null>(null);

  const [promptInput, setPromptInput] = useState("");
  const [labelInput, setLabelInput] = useState("");
  const [showLabelInput, setShowLabelInput] = useState(false);
  const [includeContext, setIncludeContext] = useState(true);

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [showTelemetry, setShowTelemetry] = useState(true);
  const [mobilePane, setMobilePane] = useState<MobilePane>("chat");
  const [expandedProjectLists, setExpandedProjectLists] = useState<Record<string, boolean>>({});

  // Popovers & Modals
  const [filterOpen, setFilterOpen] = useState(false);
  const [openProjectMenuId, setOpenProjectMenuId] = useState<string | null>(null);
  const [openConvMenuId, setOpenConvMenuId] = useState<string | null>(null);
  const [newProjectModalOpen, setNewProjectModalOpen] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectDesc, setNewProjectDesc] = useState("");
  const [renameTarget, setRenameTarget] = useState<{
    kind: "project" | "conversation";
    id: string;
    currentName: string;
  } | null>(null);
  const [renameDraft, setRenameDraft] = useState("");

  // Monotonic refs & sync queue refs
  const mountedRef = useRef(true);
  const reqGenRef = useRef(0);
  const listGenRef = useRef(0);
  const chatroomGenRef = useRef(0);
  const chatroomSseDebounceRef = useRef<number | null>(null);
  const activePaneModeRef = useRef<ActivePaneMode>(activePaneMode);
  activePaneModeRef.current = activePaneMode;
  const selectedAgentIdRef = useRef("");
  selectedAgentIdRef.current = selectedAgentId;
  const selectedConversationIdRef = useRef("");
  selectedConversationIdRef.current = selectedConversationId;

  const stateServerVerRef = useRef(0);
  const stateFetchSeqRef = useRef(0);
  const stateSyncInFlightRef = useRef(false);
  const statePendingRef = useRef<FederationWorkbenchState | null>(null);
  const stateRef = useRef<FederationWorkbenchState>(wbState);
  stateRef.current = wbState;

  const isComposingRef = useRef(false);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const chatroomEndRef = useRef<HTMLDivElement | null>(null);

  const canEdit = session.role === "admin" && serverCanEdit;

  const selectedAgent = useMemo(
    () => agents.find((a) => a.agent_id === selectedAgentId) || null,
    [agents, selectedAgentId],
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (chatroomSseDebounceRef.current !== null) {
        window.clearTimeout(chatroomSseDebounceRef.current);
        chatroomSseDebounceRef.current = null;
      }
    };
  }, []);

  // Close menus on outside click
  useEffect(() => {
    const closeAll = () => {
      setOpenProjectMenuId(null);
      setOpenConvMenuId(null);
      setFilterOpen(false);
    };
    window.addEventListener("click", closeAll);
    return () => window.removeEventListener("click", closeAll);
  }, []);

  const handleApiError = useCallback(
    (err: unknown, fallback: string) => {
      if (err instanceof StudioApiError) {
        if (
          err.status === 401 ||
          (err.status === 403 && err.source === "studio_auth" && err.message.includes("会话"))
        ) {
          onSessionRevoked?.(err.message);
        }
        setError(err.message || fallback);
        return;
      }
      setError(err instanceof Error ? err.message : fallback);
    },
    [onSessionRevoked],
  );

  // ------------------------------------------------------------------ Server State Sync Queue (WorkspaceView pattern)
  const applyRemoteState = useCallback((remote: FederationWorkbenchState, initialHydrate = false) => {
    const clean = sanitizeFedWorkbenchState(remote);
    setWbState(clean);
    if (initialHydrate) {
      setSidebarOpen(!clean.uiPrefs.sidebarCollapsed);
      setShowTelemetry(clean.uiPrefs.telemetryOpen);
      if (clean.uiPrefs.selectedProjectId) {
        setSelectedProjectId(clean.uiPrefs.selectedProjectId);
      }
      const currentAid = selectedAgentIdRef.current;
      const prefAid = clean.uiPrefs.selectedAgentId;
      const finalAid = currentAid || prefAid;
      if (!currentAid && prefAid) {
        setSelectedAgentId(prefAid);
      }
      const prefConvId = clean.uiPrefs.selectedConversationId;
      if (prefConvId) {
        const prefConv = clean.conversations.find((c) => c.id === prefConvId);
        const convMatchesAgent =
          !finalAid ||
          (prefConv ? prefConv.agentId === finalAid : !prefAid || prefAid === finalAid);
        if (convMatchesAgent) {
          setSelectedConversationId(prefConvId);
        }
      }
    }
  }, []);

  const flushStateSyncQueue = useCallback(async () => {
    if (!canEdit || stateSyncInFlightRef.current) return;
    stateSyncInFlightRef.current = true;
    try {
      while (mountedRef.current && statePendingRef.current) {
        const nextState = statePendingRef.current;
        statePendingRef.current = null;
        try {
          const saved = await updateFederationWorkbenchState({
            expected_version: stateServerVerRef.current,
            state: nextState,
          });
          if (!mountedRef.current) return;
          stateServerVerRef.current = saved.version;
          if (!statePendingRef.current) {
            applyRemoteState(saved.state, false);
          }
        } catch (err) {
          if (!mountedRef.current) return;
          if (err instanceof StudioApiError && err.status === 409) {
            let latestVer =
              typeof err.data?.version === "number" && Number.isFinite(err.data.version)
                ? err.data.version
                : stateServerVerRef.current;
            let latestState = err.data?.state ? sanitizeFedWorkbenchState(err.data.state) : null;
            if (!latestState) {
              try {
                const fetched = await fetchFederationWorkbenchState();
                latestVer = fetched.version;
                latestState = sanitizeFedWorkbenchState(fetched.state);
              } catch {
                break;
              }
            }
            if (!mountedRef.current) return;
            stateServerVerRef.current = latestVer;
            const localToMerge = statePendingRef.current || nextState;
            statePendingRef.current = null;
            const merged = mergeFedWorkbenchStates(latestState, localToMerge);
            applyRemoteState(merged, false);
            try {
              const retried = await updateFederationWorkbenchState({
                expected_version: latestVer,
                state: merged,
              });
              if (!mountedRef.current) return;
              stateServerVerRef.current = retried.version;
              if (!statePendingRef.current) {
                applyRemoteState(retried.state, false);
              }
            } catch (retryErr) {
              if (
                retryErr instanceof StudioApiError &&
                (retryErr.status === 401 || retryErr.status === 403) &&
                retryErr.source === "studio_auth"
              ) {
                onSessionRevoked?.(retryErr.message || "会话已失效，请重新登录");
                return;
              }
              break;
            }
          } else {
            if (
              err instanceof StudioApiError &&
              (err.status === 401 || err.status === 403) &&
              err.source === "studio_auth"
            ) {
              onSessionRevoked?.(err.message || "会话已失效，请重新登录");
              return;
            }
            break;
          }
        }
      }
    } finally {
      stateSyncInFlightRef.current = false;
    }
  }, [applyRemoteState, canEdit, onSessionRevoked]);

  const updateStateAndSync = useCallback(
    (updater: (prev: FederationWorkbenchState) => FederationWorkbenchState) => {
      setWbState((prev) => {
        const next = sanitizeFedWorkbenchState(updater(prev));
        if (canEdit) {
          statePendingRef.current = next;
          void flushStateSyncQueue();
        }
        return next;
      });
    },
    [canEdit, flushStateSyncQueue],
  );

  const loadWorkbenchState = useCallback(
    async (initialHydrate: boolean) => {
      const seq = ++stateFetchSeqRef.current;
      try {
        const res = await fetchFederationWorkbenchState();
        if (!mountedRef.current || stateFetchSeqRef.current !== seq) return;
        setServerCanEdit(Boolean(res.can_edit));
        const isNewer = res.version >= stateServerVerRef.current;
        stateServerVerRef.current = Math.max(stateServerVerRef.current, res.version);
        if (isNewer && !stateSyncInFlightRef.current && !statePendingRef.current) {
          applyRemoteState(res.state, initialHydrate);
        }
      } catch (err) {
        if (!mountedRef.current || stateFetchSeqRef.current !== seq) return;
        if (
          err instanceof StudioApiError &&
          (err.status === 401 || err.status === 403) &&
          err.source === "studio_auth"
        ) {
          onSessionRevoked?.(err.message || "会话已失效，请重新登录");
        }
      }
    },
    [applyRemoteState, onSessionRevoked],
  );

  // ------------------------------------------------------------------ Roster & Timeline Loaders
  const loadWorkbench = useCallback(
    async (silent = false) => {
      const gen = ++listGenRef.current;
      if (!silent) {
        setLoadingList(true);
      }
      try {
        const res = await fetchFederationWorkbench();
        if (!mountedRef.current || gen !== listGenRef.current) return;
        const nextAgents = res.agents || [];
        setAgents(nextAgents);
        setHubConfig(res.hub_config || null);
        setServerCanEdit(Boolean(res.can_edit));
        const prevAid = selectedAgentIdRef.current;
        let resolvedAid = "";
        if (prevAid && nextAgents.some((a) => a.agent_id === prevAid)) {
          resolvedAid = prevAid;
        } else {
          const prefAid = stateRef.current.uiPrefs.selectedAgentId;
          if (prefAid && nextAgents.some((a) => a.agent_id === prefAid)) {
            resolvedAid = prefAid;
          } else {
            resolvedAid = nextAgents[0]?.agent_id || "";
          }
        }
        setSelectedAgentId(resolvedAid);
        if (resolvedAid !== prevAid) {
          const curConvId = selectedConversationIdRef.current;
          if (curConvId && curConvId !== EXTERNAL_HISTORY_CONV_ID) {
            const curConv = stateRef.current.conversations.find((c) => c.id === curConvId);
            const belongsToResolved = curConv
              ? curConv.agentId === resolvedAid
              : Boolean(resolvedAid && stateRef.current.uiPrefs.selectedAgentId === resolvedAid);
            if (!belongsToResolved) {
              setSelectedConversationId("");
            }
          }
        }
      } catch (err) {
        if (!mountedRef.current || gen !== listGenRef.current) return;
        handleApiError(err, "加载联邦工作台节点失败");
      } finally {
        if (mountedRef.current && gen === listGenRef.current) {
          setLoadingList(false);
        }
      }
    },
    [handleApiError],
  );

  const loadTimeline = useCallback(
    async (agentId: string, silent = false) => {
      const gen = ++reqGenRef.current;
      if (!agentId) {
        setTimeline([]);
        setPullInbox([]);
        setLeaderEvents([]);
        setHasActiveJobs(false);
        setLoadingTimeline(false);
        return;
      }
      if (!silent) {
        setLoadingTimeline(true);
      }
      try {
        const res = await fetchFederationWorkbenchTimeline(agentId, { limit: 200 });
        if (!mountedRef.current || gen !== reqGenRef.current) return;
        setTimeline(res.timeline || []);
        setPullInbox(res.pull_inbox || []);
        setLeaderEvents(res.leader_events || []);
        setHasActiveJobs(Boolean(res.has_active_jobs));
        setServerCanEdit(Boolean(res.can_edit));
        if (res.agent) {
          setAgents((prev) =>
            prev.map((a) => (a.agent_id === res.agent.agent_id ? { ...a, ...res.agent } : a)),
          );
        }
      } catch (err) {
        if (!mountedRef.current || gen !== reqGenRef.current) return;
        handleApiError(err, "加载联邦节点时间线失败");
      } finally {
        if (mountedRef.current && gen === reqGenRef.current) {
          setLoadingTimeline(false);
        }
      }
    },
    [handleApiError],
  );

  const loadChatroom = useCallback(
    async (silent = false) => {
      const gen = ++chatroomGenRef.current;
      if (!silent) {
        setChatroomLoading(true);
      }
      try {
        const res = await fetchFederationChatroomMessages({ limit: 120 });
        if (!mountedRef.current || gen !== chatroomGenRef.current) return;
        setChatroomData(res);
        setServerCanEdit(Boolean(res.can_edit));
        setChatroomReadSeq((prev) => {
          if (activePaneModeRef.current === "chatroom") {
            return res.last_seq;
          }
          if (prev === null) {
            return res.last_seq;
          }
          return prev;
        });
      } catch (err) {
        if (!mountedRef.current || gen !== chatroomGenRef.current) return;
        if (!silent || activePaneModeRef.current === "chatroom") {
          handleApiError(err, "加载联邦聊天室失败");
        }
      } finally {
        if (mountedRef.current && gen === chatroomGenRef.current) {
          setChatroomLoading(false);
        }
      }
    },
    [handleApiError],
  );

  // Initial & SSE-triggered refresh
  useEffect(() => {
    void loadWorkbenchState(federationEventVer === 0);
  }, [loadWorkbenchState, federationEventVer]);

  useEffect(() => {
    void loadWorkbench(federationEventVer > 0 || jobsEventVer > 0);
  }, [loadWorkbench, federationEventVer, jobsEventVer]);

  // Initial chatroom load
  useEffect(() => {
    void loadChatroom(false);
  }, [loadChatroom]);

  // Debounced SSE refresh for Federation Chatroom (300ms, strictly cleaned up on unmount/re-trigger)
  useEffect(() => {
    if (federationEventVer === 0) return;
    if (chatroomSseDebounceRef.current !== null) {
      window.clearTimeout(chatroomSseDebounceRef.current);
    }
    chatroomSseDebounceRef.current = window.setTimeout(() => {
      chatroomSseDebounceRef.current = null;
      void loadChatroom(true);
    }, CHATROOM_SSE_DEBOUNCE_MS);
    return () => {
      if (chatroomSseDebounceRef.current !== null) {
        window.clearTimeout(chatroomSseDebounceRef.current);
        chatroomSseDebounceRef.current = null;
      }
    };
  }, [federationEventVer, loadChatroom]);

  useEffect(() => {
    if (!selectedAgentId) {
      reqGenRef.current += 1;
      setTimeline([]);
      setPullInbox([]);
      setLeaderEvents([]);
      setHasActiveJobs(false);
      return;
    }
    void loadTimeline(selectedAgentId, false);
  }, [selectedAgentId, loadTimeline]);

  useEffect(() => {
    if (!selectedAgentId || (federationEventVer === 0 && jobsEventVer === 0)) return;
    void loadTimeline(selectedAgentId, true);
  }, [selectedAgentId, federationEventVer, jobsEventVer, loadTimeline]);

  const anyActiveInRoster = useMemo(
    () =>
      hasActiveJobs ||
      agents.some(
        (a) =>
          (a.pull_queue_counts?.queued || 0) +
            (a.pull_queue_counts?.claimed || 0) +
            (a.bus_job_counts?.queued || 0) +
            (a.bus_job_counts?.running || 0) >
          0,
      ),
    [hasActiveJobs, agents],
  );

  // Single mutually-exclusive polling loop: 4s while active jobs exist, 30s while idle.
  useEffect(() => {
    const intervalMs = anyActiveInRoster ? POLL_ACTIVE_INTERVAL_MS : POLL_IDLE_INTERVAL_MS;
    const timer = window.setInterval(() => {
      void loadWorkbench(true);
      void loadChatroom(true);
      if (anyActiveInRoster && selectedAgentId) {
        void loadTimeline(selectedAgentId, true);
      }
    }, intervalMs);
    return () => {
      window.clearInterval(timer);
    };
  }, [anyActiveInRoster, selectedAgentId, loadWorkbench, loadTimeline, loadChatroom]);

  // ------------------------------------------------------------------ Derived Tree Data (Projects -> Conversations)
  const pinnedSet = useMemo(() => new Set(wbState.pinnedConversationIds), [wbState.pinnedConversationIds]);
  const archivedSet = useMemo(() => new Set(wbState.archivedConversationIds), [wbState.archivedConversationIds]);
  const hiddenConvSet = useMemo(() => new Set(wbState.hiddenConversationIds), [wbState.hiddenConversationIds]);
  const collapsedProjSet = useMemo(() => new Set(wbState.collapsedProjectIds), [wbState.collapsedProjectIds]);
  const hiddenProjSet = useMemo(() => new Set(wbState.hiddenProjectIds), [wbState.hiddenProjectIds]);

  const jobsByConversation = useMemo(() => {
    const map = new Map<string, FederationTimelineJobItem[]>();
    const externalJobs: FederationTimelineJobItem[] = [];
    for (const item of timeline) {
      const cid = (item.conversation_id || "").trim();
      if (!cid) {
        externalJobs.push(item);
      } else {
        const list = map.get(cid) || [];
        list.push(item);
        map.set(cid, list);
      }
    }
    return { map, externalJobs };
  }, [timeline]);

  const allConversationsForAgent = useMemo((): SidebarConversationView[] => {
    if (!selectedAgentId) return [];
    const byId = new Map<string, SidebarConversationView>();

    // 1. Saved conversations in synced state for this agent
    for (const c of wbState.conversations) {
      if (c.agentId !== selectedAgentId) continue;
      if (hiddenConvSet.has(c.id)) continue;
      const jobs = jobsByConversation.map.get(c.id) || [];
      const latestJobTs = jobs.reduce((acc, j) => Math.max(acc, j.finished_at || j.created_at || 0), 0);
      const updatedAt = Math.max(c.updatedAt || 0, c.createdAt || 0, latestJobTs);
      const readAt = Object.prototype.hasOwnProperty.call(wbState.readAtByConversation, c.id)
        ? wbState.readAtByConversation[c.id]
        : 0;
      const isUnread = latestJobTs > 0 && latestJobTs > readAt && c.id !== selectedConversationId;
      const customTitle = Object.prototype.hasOwnProperty.call(wbState.renamedConversations, c.id)
        ? wbState.renamedConversations[c.id]
        : c.title;
      byId.set(c.id, {
        id: c.id,
        agentId: c.agentId,
        projectId: c.projectId || DEFAULT_PROJECT_ID,
        title: customTitle || c.title || "未命名对话",
        updatedAt,
        turnCount: jobs.length,
        hasActive: jobs.some((j) => j.is_active),
        isPinned: pinnedSet.has(c.id),
        isArchived: archivedSet.has(c.id),
        isUnread,
      });
    }

    // 2. Virtual conversations discovered from timeline items not yet in state.conversations
    for (const [cid, jobs] of jobsByConversation.map.entries()) {
      if (byId.has(cid) || hiddenConvSet.has(cid)) continue;
      const first = jobs[0];
      const latestJobTs = jobs.reduce((acc, j) => Math.max(acc, j.finished_at || j.created_at || 0), 0);
      const readAt = Object.prototype.hasOwnProperty.call(wbState.readAtByConversation, cid)
        ? wbState.readAtByConversation[cid]
        : 0;
      const isUnread = latestJobTs > 0 && latestJobTs > readAt && cid !== selectedConversationId;
      const titleFallback =
        first?.conversation_title ||
        (first?.display_prompt || first?.prompt || "").slice(0, 36) ||
        cid;
      const customTitle = Object.prototype.hasOwnProperty.call(wbState.renamedConversations, cid)
        ? wbState.renamedConversations[cid]
        : titleFallback;
      byId.set(cid, {
        id: cid,
        agentId: selectedAgentId,
        projectId: first?.project_id || DEFAULT_PROJECT_ID,
        title: customTitle,
        updatedAt: latestJobTs,
        turnCount: jobs.length,
        hasActive: jobs.some((j) => j.is_active),
        isPinned: pinnedSet.has(cid),
        isArchived: archivedSet.has(cid),
        isUnread,
        isVirtual: true,
      });
    }

    const list = Array.from(byId.values()).filter((c) => {
      if (!wbState.uiPrefs.showArchived && c.isArchived) return false;
      if (wbState.uiPrefs.onlyPinned && !c.isPinned) return false;
      if (wbState.uiPrefs.onlyUnread && !c.isUnread) return false;
      return true;
    });

    list.sort((a, b) => {
      if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
      if (a.hasActive !== b.hasActive) return a.hasActive ? -1 : 1;
      return b.updatedAt - a.updatedAt;
    });
    return list;
  }, [
    selectedAgentId,
    selectedConversationId,
    wbState.conversations,
    wbState.renamedConversations,
    wbState.readAtByConversation,
    wbState.uiPrefs.showArchived,
    wbState.uiPrefs.onlyPinned,
    wbState.uiPrefs.onlyUnread,
    hiddenConvSet,
    pinnedSet,
    archivedSet,
    jobsByConversation.map,
  ]);

  const projectGroups = useMemo(() => {
    const groups: {
      id: string;
      name: string;
      description?: string;
      isCustom: boolean;
      isExternalHistory?: boolean;
      conversations: SidebarConversationView[];
    }[] = [];

    const resolveProjName = (id: string, fallback: string) =>
      Object.prototype.hasOwnProperty.call(wbState.renamedProjects, id)
        ? wbState.renamedProjects[id]
        : fallback;

    const knownProjIds = new Set<string>([DEFAULT_PROJECT_ID]);
    for (const cp of wbState.customProjects) knownProjIds.add(cp.id);

    // 1. Built-in Default Project
    if (!hiddenProjSet.has(DEFAULT_PROJECT_ID)) {
      groups.push({
        id: DEFAULT_PROJECT_ID,
        name: resolveProjName(DEFAULT_PROJECT_ID, "默认项目"),
        isCustom: false,
        conversations: allConversationsForAgent.filter(
          (c) => c.projectId === DEFAULT_PROJECT_ID || !knownProjIds.has(c.projectId),
        ),
      });
    }

    // 2. Custom Logical Projects
    for (const cp of wbState.customProjects) {
      if (hiddenProjSet.has(cp.id)) continue;
      groups.push({
        id: cp.id,
        name: resolveProjName(cp.id, cp.name),
        description: cp.description,
        isCustom: true,
        conversations: allConversationsForAgent.filter((c) => c.projectId === cp.id),
      });
    }

    // 3. Automatic External History Section (Telegram / Bus / legacy jobs without conversation_id)
    if (!hiddenProjSet.has(EXTERNAL_HISTORY_PROJECT_ID)) {
      const extJobs = jobsByConversation.externalJobs;
      const extLatest = extJobs.reduce((acc, j) => Math.max(acc, j.finished_at || j.created_at || 0), 0);
      const extConv: SidebarConversationView[] =
        extJobs.length > 0
          ? [
              {
                id: EXTERNAL_HISTORY_CONV_ID,
                agentId: selectedAgentId,
                projectId: EXTERNAL_HISTORY_PROJECT_ID,
                title: `外部历史任务 (${extJobs.length})`,
                updatedAt: extLatest,
                turnCount: extJobs.length,
                hasActive: extJobs.some((j) => j.is_active),
                isPinned: false,
                isArchived: false,
                isUnread: false,
                isVirtual: true,
              },
            ]
          : [];
      groups.push({
        id: EXTERNAL_HISTORY_PROJECT_ID,
        name: resolveProjName(EXTERNAL_HISTORY_PROJECT_ID, "外部历史"),
        description: "Telegram / Bot Bus 与未归属历史派单",
        isCustom: false,
        isExternalHistory: true,
        conversations: extConv,
      });
    }

    return groups;
  }, [
    wbState.customProjects,
    wbState.renamedProjects,
    hiddenProjSet,
    allConversationsForAgent,
    jobsByConversation.externalJobs,
    selectedAgentId,
  ]);

  const activeConversationObj = useMemo(() => {
    if (!selectedConversationId || selectedConversationId === EXTERNAL_HISTORY_CONV_ID) return null;
    return allConversationsForAgent.find((c) => c.id === selectedConversationId) || null;
  }, [allConversationsForAgent, selectedConversationId]);

  const isExternalHistoryView = selectedConversationId === EXTERNAL_HISTORY_CONV_ID;

  const visibleMessages = useMemo(() => {
    if (!selectedAgentId) return [];
    if (isExternalHistoryView) {
      return jobsByConversation.externalJobs;
    }
    if (!selectedConversationId) {
      return [];
    }
    return jobsByConversation.map.get(selectedConversationId) || [];
  }, [
    selectedAgentId,
    isExternalHistoryView,
    selectedConversationId,
    jobsByConversation.externalJobs,
    jobsByConversation.map,
  ]);

  // Mark active conversation read when messages arrive
  useEffect(() => {
    if (!canEdit || !selectedConversationId || isExternalHistoryView) return;
    if (visibleMessages.length === 0) return;
    const latestTs = visibleMessages.reduce(
      (acc, j) => Math.max(acc, j.finished_at || j.created_at || 0),
      0,
    );
    const prevRead = Object.prototype.hasOwnProperty.call(
      stateRef.current.readAtByConversation,
      selectedConversationId,
    )
      ? stateRef.current.readAtByConversation[selectedConversationId]
      : 0;
    if (latestTs > prevRead) {
      updateStateAndSync((prev) => ({
        ...prev,
        readAtByConversation: {
          ...prev.readAtByConversation,
          [selectedConversationId]: Math.ceil(latestTs),
        },
      }));
    }
  }, [canEdit, selectedConversationId, isExternalHistoryView, visibleMessages, updateStateAndSync]);

  // ------------------------------------------------------------------ Actions
  const chatroomMessages = useMemo(
    () => chatroomData?.messages || [],
    [chatroomData?.messages],
  );
  const chatroomParticipants = useMemo(
    () => chatroomData?.participants || [],
    [chatroomData?.participants],
  );
  const chatroomUnreadCount = useMemo(() => {
    if (activePaneMode === "chatroom" || !chatroomData?.bound || chatroomReadSeq === null) {
      return 0;
    }
    return chatroomMessages.filter((m) => m.seq > chatroomReadSeq).length;
  }, [activePaneMode, chatroomData?.bound, chatroomReadSeq, chatroomMessages]);

  const handleOpenChatroom = () => {
    setError(null);
    setNotice(null);
    setActivePaneMode("chatroom");
    setMobilePane("chat");
    if (chatroomData) {
      setChatroomReadSeq(chatroomData.last_seq);
    }
    void loadChatroom(true);
  };

  const handleInsertChatroomMention = (participant: FederationChatroomParticipant) => {
    if (!canEdit || !chatroomData?.bound || !participant.can_mention) return;
    const tag = `@${participant.handle} `;
    setChatroomInput((prev) => {
      if (!prev) return tag;
      return prev.endsWith(" ") || prev.endsWith("\n") ? `${prev}${tag}` : `${prev} ${tag}`;
    });
  };

  const handleSendChatroomMessage = async () => {
    if (!canEdit || !chatroomData?.bound || chatroomSending) return;
    const trimmed = chatroomInput.trim();
    if (!trimmed) return;
    setChatroomSending(true);
    setError(null);
    setNotice(null);
    try {
      const res = await sendFederationChatroomMessage({
        content: trimmed,
        include_context: chatroomIncludeContext,
      });
      if (!mountedRef.current) return;
      setChatroomInput("");
      const routedParts: string[] = [];
      if (res.routed_local.length > 0) {
        routedParts.push(`本地: ${res.routed_local.map((h) => `@${h}`).join(", ")}`);
      }
      if (res.routed_external.length > 0) {
        routedParts.push(`外部联邦: ${res.routed_external.map((h) => `@${h}`).join(", ")}`);
      }
      setNotice(
        routedParts.length > 0
          ? `已同步至联邦聊天室 TG 群（${routedParts.join(" · ")}）`
          : "已同步至联邦聊天室 TG 群",
      );
      await loadChatroom(true);
      window.setTimeout(() => {
        chatroomEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 60);
    } catch (err) {
      if (!mountedRef.current) return;
      handleApiError(err, "发送联邦聊天室消息失败");
    } finally {
      if (mountedRef.current) {
        setChatroomSending(false);
      }
    }
  };

  const handleSelectAgent = (agentId: string) => {
    if (agentId === selectedAgentId && activePaneMode === "conversation") return;
    setError(null);
    setNotice(null);
    setActivePaneMode("conversation");
    setSelectedAgentId(agentId);
    // Keep conversation if it belongs to the new agent, else switch to draft new conversation
    const existingForNew = wbState.conversations.find(
      (c) => c.agentId === agentId && !hiddenConvSet.has(c.id) && !archivedSet.has(c.id),
    );
    const nextConvId = existingForNew ? existingForNew.id : "";
    const nextProjId = existingForNew ? existingForNew.projectId : DEFAULT_PROJECT_ID;
    setSelectedConversationId(nextConvId);
    setSelectedProjectId(nextProjId);
    if (canEdit) {
      updateStateAndSync((prev) => ({
        ...prev,
        uiPrefs: {
          ...prev.uiPrefs,
          selectedAgentId: agentId,
          selectedProjectId: nextProjId,
          selectedConversationId: nextConvId,
        },
      }));
    }
  };

  const handleSelectConversation = (convId: string, projectId: string) => {
    setError(null);
    setNotice(null);
    setActivePaneMode("conversation");
    setSelectedConversationId(convId);
    setSelectedProjectId(projectId);
    setMobilePane("chat");
    if (canEdit && convId !== EXTERNAL_HISTORY_CONV_ID) {
      const jobs = jobsByConversation.map.get(convId) || [];
      const latestTs = jobs.reduce((acc, j) => Math.max(acc, j.finished_at || j.created_at || 0), 0);
      updateStateAndSync((prev) => {
        const prevRead = Object.prototype.hasOwnProperty.call(prev.readAtByConversation, convId)
          ? prev.readAtByConversation[convId]
          : 0;
        return {
          ...prev,
          readAtByConversation:
            latestTs > prevRead
              ? { ...prev.readAtByConversation, [convId]: Math.ceil(latestTs) }
              : prev.readAtByConversation,
          uiPrefs: {
            ...prev.uiPrefs,
            selectedProjectId: projectId,
            selectedConversationId: convId,
          },
        };
      });
    }
  };

  const handleStartNewConversation = (projectId?: string) => {
    const targetProj =
      projectId && projectId !== EXTERNAL_HISTORY_PROJECT_ID
        ? projectId
        : selectedProjectId !== EXTERNAL_HISTORY_PROJECT_ID
          ? selectedProjectId
          : DEFAULT_PROJECT_ID;
    setError(null);
    setNotice(null);
    setActivePaneMode("conversation");
    setSelectedProjectId(targetProj);
    setSelectedConversationId("");
    setMobilePane("chat");
    if (canEdit) {
      updateStateAndSync((prev) => ({
        ...prev,
        collapsedProjectIds: prev.collapsedProjectIds.filter((id) => id !== targetProj),
        uiPrefs: {
          ...prev.uiPrefs,
          selectedProjectId: targetProj,
          selectedConversationId: "",
        },
      }));
    }
  };

  const handleToggleSidebar = () => {
    setSidebarOpen((prev) => {
      const next = !prev;
      if (canEdit) {
        updateStateAndSync((st) => ({
          ...st,
          uiPrefs: { ...st.uiPrefs, sidebarCollapsed: !next },
        }));
      }
      return next;
    });
  };

  const handleToggleTelemetry = () => {
    setShowTelemetry((prev) => {
      const next = !prev;
      if (canEdit) {
        updateStateAndSync((st) => ({
          ...st,
          uiPrefs: { ...st.uiPrefs, telemetryOpen: next },
        }));
      }
      return next;
    });
  };

  const handleToggleProjectCollapse = (projId: string) => {
    updateStateAndSync((prev) => {
      const exists = prev.collapsedProjectIds.includes(projId);
      return {
        ...prev,
        collapsedProjectIds: exists
          ? prev.collapsedProjectIds.filter((id) => id !== projId)
          : [...prev.collapsedProjectIds, projId],
      };
    });
  };

  const handleCreateProject = () => {
    if (!canEdit) return;
    const name = normalizeSingleLineText(newProjectName, 64);
    const desc = normalizeSingleLineText(newProjectDesc, 240);
    if (!name) return;
    const id = makeProjectId(name);
    const proj: FederationWorkbenchProject = {
      id,
      name,
      ...(desc ? { description: desc } : {}),
      createdAt: Math.floor(Date.now() / 1000),
    };
    updateStateAndSync((prev) => ({
      ...prev,
      customProjects: [proj, ...prev.customProjects].slice(0, MAX_CUSTOM_PROJECTS),
      hiddenProjectIds: prev.hiddenProjectIds.filter((pid) => pid !== id),
      collapsedProjectIds: prev.collapsedProjectIds.filter((pid) => pid !== id),
      uiPrefs: { ...prev.uiPrefs, selectedProjectId: id },
    }));
    setSelectedProjectId(id);
    setSelectedConversationId("");
    setNewProjectName("");
    setNewProjectDesc("");
    setNewProjectModalOpen(false);
    setNotice(`已创建逻辑项目「${name}」`);
  };

  const handleSubmitRename = () => {
    if (!canEdit || !renameTarget) return;
    const nextName = normalizeSingleLineText(
      renameDraft,
      renameTarget.kind === "project" ? 64 : 120,
    );
    if (!nextName) return;
    if (renameTarget.kind === "project") {
      updateStateAndSync((prev) => ({
        ...prev,
        renamedProjects: { ...prev.renamedProjects, [renameTarget.id]: nextName },
      }));
    } else {
      updateStateAndSync((prev) => ({
        ...prev,
        renamedConversations: { ...prev.renamedConversations, [renameTarget.id]: nextName },
        conversations: prev.conversations.map((c) =>
          c.id === renameTarget.id ? { ...c, title: nextName } : c,
        ),
      }));
    }
    setRenameTarget(null);
    setRenameDraft("");
  };

  const handleHideProject = (projId: string) => {
    if (!canEdit) return;
    updateStateAndSync((prev) => ({
      ...prev,
      hiddenProjectIds: Array.from(new Set([...prev.hiddenProjectIds, projId])),
    }));
    if (selectedProjectId === projId) {
      setSelectedProjectId(DEFAULT_PROJECT_ID);
      setSelectedConversationId("");
    }
  };

  const handleRemoveCustomProject = (projId: string) => {
    if (!canEdit) return;
    updateStateAndSync((prev) => {
      const nextRenames = { ...prev.renamedProjects };
      delete nextRenames[projId];
      return {
        ...prev,
        customProjects: prev.customProjects.filter((p) => p.id !== projId),
        renamedProjects: nextRenames,
        hiddenProjectIds: prev.hiddenProjectIds.filter((id) => id !== projId),
        collapsedProjectIds: prev.collapsedProjectIds.filter((id) => id !== projId),
        conversations: prev.conversations.map((c) =>
          c.projectId === projId ? { ...c, projectId: DEFAULT_PROJECT_ID } : c,
        ),
      };
    });
    if (selectedProjectId === projId) {
      setSelectedProjectId(DEFAULT_PROJECT_ID);
    }
  };

  const handleTogglePinConv = (convId: string) => {
    if (!canEdit) return;
    updateStateAndSync((prev) => {
      const exists = prev.pinnedConversationIds.includes(convId);
      return {
        ...prev,
        pinnedConversationIds: exists
          ? prev.pinnedConversationIds.filter((id) => id !== convId)
          : [convId, ...prev.pinnedConversationIds],
      };
    });
  };

  const handleToggleArchiveConv = (convId: string) => {
    if (!canEdit) return;
    updateStateAndSync((prev) => {
      const exists = prev.archivedConversationIds.includes(convId);
      return {
        ...prev,
        archivedConversationIds: exists
          ? prev.archivedConversationIds.filter((id) => id !== convId)
          : [convId, ...prev.archivedConversationIds],
      };
    });
  };

  const handleHideConv = (convId: string) => {
    if (!canEdit) return;
    updateStateAndSync((prev) => ({
      ...prev,
      hiddenConversationIds: Array.from(new Set([convId, ...prev.hiddenConversationIds])),
      pinnedConversationIds: prev.pinnedConversationIds.filter((id) => id !== convId),
      archivedConversationIds: prev.archivedConversationIds.filter((id) => id !== convId),
    }));
    if (selectedConversationId === convId) {
      setSelectedConversationId("");
    }
  };

  const handleToggleFilterPref = (key: "showArchived" | "onlyPinned" | "onlyUnread") => {
    if (canEdit) {
      updateStateAndSync((prev) => ({
        ...prev,
        uiPrefs: { ...prev.uiPrefs, [key]: !prev.uiPrefs[key] },
      }));
    } else {
      setWbState((prev) => ({
        ...prev,
        uiPrefs: { ...prev.uiPrefs, [key]: !prev.uiPrefs[key] },
      }));
    }
  };

  const handleRestoreHiddenProjects = () => {
    if (!canEdit) return;
    updateStateAndSync((prev) => ({ ...prev, hiddenProjectIds: [] }));
  };

  const handleDispatch = async () => {
    if (!canEdit || !selectedAgent || !selectedAgent.can_dispatch) return;
    const trimmed = promptInput.trim();
    if (!trimmed) return;

    // Lock target `(agentId, projectId, conversationId)` BEFORE any async await to prevent cross-talk
    const targetAgentId = selectedAgent.agent_id;
    const targetProjectId =
      selectedProjectId && selectedProjectId !== EXTERNAL_HISTORY_PROJECT_ID
        ? selectedProjectId
        : DEFAULT_PROJECT_ID;
    const isNewConv = !selectedConversationId || selectedConversationId === EXTERNAL_HISTORY_CONV_ID;
    const targetConversationId = isNewConv ? makeConversationId() : selectedConversationId;
    const nowUnix = Math.floor(Date.now() / 1000);
    const existingConv = stateRef.current.conversations.find((c) => c.id === targetConversationId);
    const existingTitle = Object.prototype.hasOwnProperty.call(
      stateRef.current.renamedConversations,
      targetConversationId,
    )
      ? stateRef.current.renamedConversations[targetConversationId]
      : existingConv?.title || "";
    const targetConversationTitle =
      normalizeSingleLineText(existingTitle, 120) ||
      normalizeSingleLineText(trimmed.split(/\r?\n/)[0] || "", 40) ||
      "新对话";
    const targetLabel = normalizeSingleLineText(labelInput, 120) || undefined;
    const useContext = includeContext && !isNewConv;

    // Immediately register / bump conversation in state so UI switches cleanly to locked target
    setSelectedProjectId(targetProjectId);
    setSelectedConversationId(targetConversationId);
    updateStateAndSync((prev) => {
      const idx = prev.conversations.findIndex((c) => c.id === targetConversationId);
      const nextConvs = [...prev.conversations];
      if (idx >= 0) {
        nextConvs[idx] = { ...nextConvs[idx], updatedAt: nowUnix };
      } else {
        nextConvs.unshift({
          id: targetConversationId,
          agentId: targetAgentId,
          projectId: targetProjectId,
          title: targetConversationTitle,
          createdAt: nowUnix,
          updatedAt: nowUnix,
        });
      }
      return {
        ...prev,
        conversations: nextConvs.slice(0, MAX_CONVERSATIONS),
        hiddenConversationIds: prev.hiddenConversationIds.filter(
          (id) => id !== targetConversationId,
        ),
        readAtByConversation: {
          ...prev.readAtByConversation,
          [targetConversationId]: nowUnix,
        },
        uiPrefs: {
          ...prev.uiPrefs,
          selectedAgentId: targetAgentId,
          selectedProjectId: targetProjectId,
          selectedConversationId: targetConversationId,
        },
      };
    });

    setSending(true);
    setError(null);
    setNotice(null);
    try {
      const res = await dispatchFederationWorkbenchJob(targetAgentId, {
        prompt: trimmed,
        label: targetLabel,
        project_id: targetProjectId,
        conversation_id: targetConversationId,
        conversation_title: targetConversationTitle,
        include_context: useContext,
      });
      if (!mountedRef.current) return;
      setPromptInput("");
      setLabelInput("");
      setNotice(
        res.dispatch_mode === "pull"
          ? `已入队 Pull 任务 ${res.job.job_id}（外部节点将自动拉取）`
          : `已派发任务 ${res.job.job_id} 至 ${targetAgentId}`,
      );
      const activeAidNow = selectedAgentIdRef.current;
      await Promise.all([
        loadWorkbench(true),
        activeAidNow ? loadTimeline(activeAidNow, true) : Promise.resolve(),
      ]);
      window.setTimeout(() => {
        timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 60);
    } catch (err) {
      if (!mountedRef.current) return;
      handleApiError(err, "派发任务失败");
    } finally {
      if (mountedRef.current) {
        setSending(false);
      }
    }
  };

  const handleCancelJob = async (jobId: string) => {
    if (!canEdit || !selectedAgent) return;
    const targetAid = selectedAgent.agent_id;
    setCancellingJobId(jobId);
    setError(null);
    setNotice(null);
    try {
      const res = await cancelFederationWorkbenchJob(targetAid, jobId, "cancelled_by_studio");
      if (!mountedRef.current) return;
      if (res.already_terminal) {
        setNotice(`任务 ${jobId} 已处于终态 (${res.status})，未修改结果`);
      } else {
        setNotice(`已取消任务 ${jobId}`);
      }
      const activeAidNow = selectedAgentIdRef.current;
      await Promise.all([
        loadWorkbench(true),
        activeAidNow ? loadTimeline(activeAidNow, true) : Promise.resolve(),
      ]);
    } catch (err) {
      if (!mountedRef.current) return;
      handleApiError(err, "取消任务失败");
    } finally {
      if (mountedRef.current) {
        setCancellingJobId(null);
      }
    }
  };

  const selectedHbLabel = selectedAgent
    ? formatHeartbeatLabel(selectedAgent.last_heartbeat_at, selectedAgent.last_heartbeat_action)
    : "";

  const activeFilterCount =
    (wbState.uiPrefs.showArchived ? 1 : 0) +
    (wbState.uiPrefs.onlyPinned ? 1 : 0) +
    (wbState.uiPrefs.onlyUnread ? 1 : 0);

  const currentProjectName = useMemo(() => {
    if (isExternalHistoryView) {
      return Object.prototype.hasOwnProperty.call(
        wbState.renamedProjects,
        EXTERNAL_HISTORY_PROJECT_ID,
      )
        ? wbState.renamedProjects[EXTERNAL_HISTORY_PROJECT_ID]
        : "外部历史";
    }
    const pid = activeConversationObj?.projectId || selectedProjectId || DEFAULT_PROJECT_ID;
    if (Object.prototype.hasOwnProperty.call(wbState.renamedProjects, pid)) {
      return wbState.renamedProjects[pid];
    }
    if (pid === DEFAULT_PROJECT_ID) return "默认项目";
    const cp = wbState.customProjects.find((p) => p.id === pid);
    return cp?.name || "默认项目";
  }, [
    isExternalHistoryView,
    activeConversationObj?.projectId,
    selectedProjectId,
    wbState.renamedProjects,
    wbState.customProjects,
  ]);

  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden bg-slate-950">
      {/* Top Navigation Bar (Aligned with WorkspaceView) */}
      <header className="shrink-0 min-h-11 px-2.5 md:px-3.5 py-1.5 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <button
            type="button"
            onClick={handleToggleSidebar}
            title={sidebarOpen ? "收起项目与对话侧栏" : "展开项目与对话侧栏"}
            className="hidden md:inline-flex h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 items-center justify-center text-slate-300 cursor-pointer shrink-0"
          >
            <PanelLeft className="w-3.5 h-3.5" />
          </button>

          <div className="inline-flex items-center gap-1.5 shrink-0">
            <Radio className="w-4 h-4 text-sky-400 shrink-0" />
            <span className="text-xs font-semibold text-slate-100 hidden sm:inline">
              联邦工作台
            </span>
          </div>

          {/* External Agent Selector */}
          <select
            value={selectedAgentId}
            onChange={(e) => handleSelectAgent(e.target.value)}
            disabled={loadingList && agents.length === 0}
            aria-label="选择外部联邦节点"
            className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 max-w-[220px] truncate"
          >
            {agents.length === 0 ? (
              <option value="">暂无外部节点</option>
            ) : (
              agents.map((ag) => {
                const st = runtimeStatusMeta(ag.runtime_status);
                return (
                  <option key={ag.agent_id} value={ag.agent_id} className="bg-slate-950">
                    {st.glyph} {ag.display_name || ag.agent_id} ({ag.adapter_type})
                  </option>
                );
              })
            )}
          </select>

          {selectedAgent && (
            <div className="hidden lg:flex items-center gap-1.5 min-w-0">
              <span
                className={`px-1.5 py-0.5 rounded border text-[10px] font-medium shrink-0 ${
                  runtimeStatusMeta(selectedAgent.runtime_status).badge
                }`}
              >
                {runtimeStatusMeta(selectedAgent.runtime_status).label}
              </span>
              {selectedHbLabel && (
                <span
                  className={`text-[10px] font-mono truncate ${
                    selectedAgent.runtime_status === "online"
                      ? "text-emerald-300/90"
                      : selectedAgent.runtime_status === "stale"
                        ? "text-amber-300/90"
                        : "text-slate-400"
                  }`}
                  title={formatTs(selectedAgent.last_heartbeat_at)}
                >
                  {selectedHbLabel}
                </span>
              )}
            </div>
          )}

          {anyActiveInRoster && (
            <span className="hidden xl:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-sky-500/15 text-sky-300 border border-sky-500/30 shrink-0">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
              轮询中
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {/* Mobile 3-Pane Switcher */}
          <div className="flex md:hidden items-center rounded-lg border border-slate-800 bg-slate-950/80 p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setMobilePane("projects")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "projects" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              项目
            </button>
            <button
              type="button"
              onClick={() => setMobilePane("chat")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "chat" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              对话
            </button>
            <button
              type="button"
              onClick={() => setMobilePane("telemetry")}
              className={`px-2 py-1 rounded-md cursor-pointer ${
                mobilePane === "telemetry" ? "bg-sky-500/20 text-sky-300" : "text-slate-400"
              }`}
            >
              遥测
            </button>
          </div>

          {canEdit && selectedAgent && (
            <button
              type="button"
              onClick={() => handleStartNewConversation()}
              className="inline-flex items-center gap-1 h-7 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2 text-xs text-slate-200 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 text-sky-400" />
              <span className="hidden sm:inline">新对话</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => {
              void loadWorkbench(false);
              void loadWorkbenchState(false);
              void loadChatroom(false);
              if (selectedAgentId) void loadTimeline(selectedAgentId, false);
            }}
            disabled={loadingList || loadingTimeline || chatroomLoading}
            title="刷新节点状态、联邦聊天室与时间线"
            className="inline-flex items-center gap-1 h-7 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2 text-xs text-slate-200 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${loadingList || loadingTimeline || chatroomLoading ? "animate-spin" : ""}`}
            />
            <span className="hidden sm:inline">刷新</span>
          </button>

          <button
            type="button"
            onClick={handleToggleTelemetry}
            title={showTelemetry ? "收起遥测抽屉" : "展开遥测抽屉"}
            className="hidden lg:inline-flex items-center gap-1 h-7 rounded-md border border-slate-700 bg-slate-900 hover:bg-slate-800 px-2 text-xs text-slate-300 cursor-pointer"
          >
            {showTelemetry ? (
              <PanelRightClose className="w-3.5 h-3.5" />
            ) : (
              <PanelRightOpen className="w-3.5 h-3.5" />
            )}
            <span>遥测</span>
          </button>

          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate("federation")}
              className="inline-flex items-center gap-1 h-7 rounded-md border border-sky-500/35 bg-sky-500/15 hover:bg-sky-500/25 px-2 text-xs font-medium text-sky-200 cursor-pointer"
            >
              <Network className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">外部联邦设置</span>
            </button>
          )}
        </div>
      </header>

      {/* Main 3-Pane Body */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* Left Collapsible Sidebar: Pinned Federation Chatroom + Projects -> Conversations Tree */}
        <aside
          className={`${
            mobilePane === "projects"
              ? "flex w-full"
              : sidebarOpen
                ? "hidden md:flex md:w-64 lg:w-72"
                : "hidden"
          } shrink-0 flex-col border-r border-slate-800/90 bg-slate-900/45 min-h-0`}
        >
          {/* Top Pinned Entry: Standalone Federation Chatroom (Symmetrical to Workspace Lobby) */}
          <div className="shrink-0 p-2 border-b border-slate-800/80">
            <button
              type="button"
              onClick={handleOpenChatroom}
              className={`w-full rounded-xl border px-2.5 py-2 text-left transition-colors cursor-pointer flex items-center justify-between gap-2 ${
                activePaneMode === "chatroom"
                  ? "bg-sky-500/15 border-sky-500/45 text-sky-100 shadow-xs"
                  : "bg-slate-950/65 border-slate-800/90 text-slate-200 hover:bg-slate-800/60"
              }`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className={`h-7 w-7 rounded-lg flex items-center justify-center shrink-0 border ${
                    activePaneMode === "chatroom"
                      ? "bg-sky-500/20 border-sky-400/40 text-sky-300"
                      : "bg-slate-900 border-slate-700/80 text-indigo-300"
                  }`}
                >
                  <Users className="w-3.5 h-3.5" />
                </span>
                <div className="min-w-0">
                  <div className="text-xs font-semibold truncate">
                    {chatroomData?.title || "联邦聊天室"}
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                    <span
                      className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                        chatroomData?.bound
                          ? chatroomData.mirror_status === "connected"
                            ? "bg-emerald-400"
                            : "bg-amber-400"
                          : "bg-slate-500"
                      }`}
                    />
                    <span className="truncate">
                      {chatroomData?.bound
                        ? chatroomData.mirror_status === "connected"
                          ? "TG 群双向镜像"
                          : "总指挥离线"
                        : "未绑定 TG 群"}
                    </span>
                  </div>
                </div>
              </div>
              {chatroomUnreadCount > 0 ? (
                <span className="px-1.5 py-0.5 rounded-full bg-sky-500 text-white font-mono text-[10px] font-semibold shrink-0">
                  {chatroomUnreadCount > 99 ? "99+" : chatroomUnreadCount}
                </span>
              ) : (
                <span className="text-[10px] font-mono text-slate-500 shrink-0">
                  {chatroomMessages.length > 0 ? chatroomMessages.length : ""}
                </span>
              )}
            </button>
          </div>

          {/* Sidebar Header */}
          <div className="shrink-0 px-3 py-2 border-b border-slate-800/80 flex items-center justify-between gap-2 relative">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="text-xs font-semibold text-slate-200">项目</span>
              {!canEdit && (
                <span className="px-1.5 py-0.2 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                  只读
                </span>
              )}
            </div>

            <div className="flex items-center gap-1">
              {/* Filter Popover Trigger */}
              <div className="relative" onClick={(e) => e.stopPropagation()}>
                <button
                  type="button"
                  onClick={() => setFilterOpen((v) => !v)}
                  title="筛选对话"
                  className={`h-6 px-1.5 rounded-md border text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors ${
                    filterOpen || activeFilterCount > 0
                      ? "bg-sky-500/15 border-sky-500/40 text-sky-300"
                      : "bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <SlidersHorizontal className="w-3 h-3" />
                  {activeFilterCount > 0 && (
                    <span className="font-mono text-[10px]">{activeFilterCount}</span>
                  )}
                </button>

                {filterOpen && (
                  <div className="absolute right-0 top-7 z-40 w-48 rounded-xl border border-slate-700/90 bg-slate-900/95 shadow-xl py-1 text-xs">
                    <button
                      type="button"
                      onClick={() => handleToggleFilterPref("showArchived")}
                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800/80 flex items-center justify-between cursor-pointer"
                    >
                      <span className="inline-flex items-center gap-2">
                        <Archive className="w-3.5 h-3.5 text-slate-400" />
                        显示已归档
                      </span>
                      {wbState.uiPrefs.showArchived && (
                        <Check className="w-3.5 h-3.5 text-sky-400" />
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleToggleFilterPref("onlyPinned")}
                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800/80 flex items-center justify-between cursor-pointer"
                    >
                      <span className="inline-flex items-center gap-2">
                        <Pin className="w-3.5 h-3.5 text-slate-400" />
                        仅看置顶
                      </span>
                      {wbState.uiPrefs.onlyPinned && (
                        <Check className="w-3.5 h-3.5 text-sky-400" />
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleToggleFilterPref("onlyUnread")}
                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800/80 flex items-center justify-between cursor-pointer"
                    >
                      <span className="inline-flex items-center gap-2">
                        <Sparkles className="w-3.5 h-3.5 text-slate-400" />
                        仅看未读
                      </span>
                      {wbState.uiPrefs.onlyUnread && (
                        <Check className="w-3.5 h-3.5 text-sky-400" />
                      )}
                    </button>
                    {canEdit && wbState.hiddenProjectIds.length > 0 && (
                      <>
                        <div className="my-1 border-t border-slate-800" />
                        <button
                          type="button"
                          onClick={() => {
                            handleRestoreHiddenProjects();
                            setFilterOpen(false);
                          }}
                          className="w-full px-3 py-1.5 text-left text-sky-300 hover:bg-slate-800/80 cursor-pointer"
                        >
                          恢复隐藏项目 ({wbState.hiddenProjectIds.length})
                        </button>
                      </>
                    )}
                  </div>
                )}
              </div>

              {canEdit && (
                <button
                  type="button"
                  onClick={() => setNewProjectModalOpen(true)}
                  title="新增逻辑项目"
                  className="h-6 px-1.5 rounded-md border border-slate-800 bg-slate-950/60 hover:bg-slate-800 text-slate-300 hover:text-sky-300 inline-flex items-center gap-1 text-[11px] cursor-pointer"
                >
                  <FolderPlus className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Tree Scroll Area */}
          <div className="flex-1 min-h-0 overflow-y-auto p-2 space-y-2">
            {loadingList && agents.length === 0 ? (
              <div className="p-4 text-center text-xs text-slate-500">加载外部节点中…</div>
            ) : agents.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-800 p-4 text-center space-y-2.5">
                <div className="text-xs text-slate-400">尚未注册外部联邦 Agent</div>
                {onNavigate && (
                  <button
                    type="button"
                    onClick={() => onNavigate("federation")}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
                  >
                    <Network className="w-3.5 h-3.5" />
                    前往外部联邦设置注册
                  </button>
                )}
              </div>
            ) : (
              projectGroups.map((group) => {
                const isCollapsed = collapsedProjSet.has(group.id);
                const listExpanded = Boolean(
                  Object.prototype.hasOwnProperty.call(expandedProjectLists, group.id) &&
                    expandedProjectLists[group.id],
                );
                const hasOverflow = group.conversations.length > MAX_VISIBLE_CONVS_PER_PROJECT;
                const shownConvs = listExpanded
                  ? group.conversations
                  : group.conversations.slice(0, MAX_VISIBLE_CONVS_PER_PROJECT);
                const hiddenCount = group.conversations.length - shownConvs.length;
                const projMenuOpen = openProjectMenuId === group.id;

                return (
                  <div key={group.id} className="space-y-0.5">
                    {/* Project Group Row */}
                    <div className="group/proj relative flex items-center gap-1 px-1.5 py-1 rounded-lg hover:bg-slate-800/55 transition-colors">
                      <button
                        type="button"
                        onClick={() => handleToggleProjectCollapse(group.id)}
                        className="flex-1 min-w-0 flex items-center gap-1.5 text-left cursor-pointer"
                      >
                        {isCollapsed ? (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        )}
                        {group.isExternalHistory ? (
                          <History className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        ) : (
                          <Folder className="w-3.5 h-3.5 text-sky-400/90 shrink-0" />
                        )}
                        <span
                          className="text-xs font-medium text-slate-200 truncate"
                          title={group.description || group.name}
                        >
                          {group.name}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500 shrink-0">
                          {group.conversations.length}
                        </span>
                      </button>

                      {/* Project Hover Actions */}
                      <div
                        className={`shrink-0 items-center gap-0.5 ${
                          projMenuOpen ? "flex" : "hidden sm:group-hover/proj:flex"
                        }`}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {canEdit && !group.isExternalHistory && (
                          <button
                            type="button"
                            onClick={() => handleStartNewConversation(group.id)}
                            title="在此项目新建对话"
                            className="h-5 w-5 rounded hover:bg-slate-700/70 text-slate-400 hover:text-sky-300 inline-flex items-center justify-center cursor-pointer"
                          >
                            <Plus className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {canEdit && (
                          <button
                            type="button"
                            onClick={() =>
                              setOpenProjectMenuId(projMenuOpen ? null : group.id)
                            }
                            title="项目操作"
                            className="h-5 w-5 rounded hover:bg-slate-700/70 text-slate-400 hover:text-slate-100 inline-flex items-center justify-center cursor-pointer"
                          >
                            <MoreHorizontal className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      {projMenuOpen && canEdit && (
                        <div
                          onClick={(e) => e.stopPropagation()}
                          className="absolute right-1 top-7 z-40 w-40 rounded-xl border border-slate-700 bg-slate-900/95 shadow-xl py-1 text-xs"
                        >
                          {!group.isExternalHistory && (
                            <button
                              type="button"
                              onClick={() => {
                                setOpenProjectMenuId(null);
                                handleStartNewConversation(group.id);
                              }}
                              className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                            >
                              <Plus className="w-3.5 h-3.5 text-sky-400" />
                              新建对话
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => {
                              setOpenProjectMenuId(null);
                              setRenameTarget({
                                kind: "project",
                                id: group.id,
                                currentName: group.name,
                              });
                              setRenameDraft(group.name);
                            }}
                            className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                          >
                            <Pencil className="w-3.5 h-3.5 text-slate-400" />
                            重命名
                          </button>
                          {group.id !== DEFAULT_PROJECT_ID && (
                            <button
                              type="button"
                              onClick={() => {
                                setOpenProjectMenuId(null);
                                handleHideProject(group.id);
                              }}
                              className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                            >
                              <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                              隐藏项目
                            </button>
                          )}
                          {group.isCustom && (
                            <button
                              type="button"
                              onClick={() => {
                                setOpenProjectMenuId(null);
                                handleRemoveCustomProject(group.id);
                              }}
                              className="w-full px-3 py-1.5 text-left text-rose-300 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              移除自定义项目
                            </button>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Conversations under Project */}
                    {!isCollapsed && (
                      <div className="pl-3 space-y-0.5">
                        {shownConvs.length === 0 ? (
                          <div className="pl-5 pr-2 py-1 text-[11px] text-slate-600">
                            {group.isExternalHistory ? "暂无外部历史任务" : "暂无对话"}
                          </div>
                        ) : (
                          shownConvs.map((conv) => {
                            const isSelected =
                              activePaneMode === "conversation" &&
                              conv.id === selectedConversationId;
                            const convMenuOpen = openConvMenuId === conv.id;
                            const isExtItem = conv.id === EXTERNAL_HISTORY_CONV_ID;
                            return (
                              <div
                                key={conv.id}
                                className={`group/conv relative flex items-center gap-1 rounded-lg px-2 py-1.5 transition-colors ${
                                  isSelected
                                    ? "bg-sky-500/15 text-sky-100 border border-sky-500/35"
                                    : "text-slate-300 hover:bg-slate-800/55 border border-transparent"
                                }`}
                              >
                                <button
                                  type="button"
                                  onClick={() => handleSelectConversation(conv.id, group.id)}
                                  className="flex-1 min-w-0 flex items-center gap-1.5 text-left cursor-pointer"
                                >
                                  {conv.hasActive ? (
                                    <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse shrink-0" />
                                  ) : conv.isUnread ? (
                                    <span
                                      title="有未读回复"
                                      className="w-1.5 h-1.5 rounded-full bg-sky-400 shrink-0"
                                    />
                                  ) : conv.isPinned ? (
                                    <Pin className="w-3 h-3 text-cyan-400 shrink-0" />
                                  ) : (
                                    <MessageSquare className="w-3 h-3 text-slate-500 shrink-0" />
                                  )}
                                  <span
                                    className={`text-xs truncate flex-1 ${
                                      conv.isArchived ? "text-slate-500 line-through" : ""
                                    }`}
                                    title={conv.title}
                                  >
                                    {conv.title}
                                  </span>
                                </button>

                                {/* Compact Age (hidden on hover when actions show) */}
                                <span
                                  className={`text-[10px] font-mono text-slate-500 shrink-0 ${
                                    !isExtItem && canEdit
                                      ? convMenuOpen
                                        ? "hidden"
                                        : "sm:group-hover/conv:hidden"
                                      : ""
                                  }`}
                                >
                                  {formatCompactAge(conv.updatedAt)}
                                </span>

                                {/* Hover Quick Actions for Conversations */}
                                {!isExtItem && canEdit && (
                                  <div
                                    className={`shrink-0 items-center gap-0.5 ${
                                      convMenuOpen ? "flex" : "hidden sm:group-hover/conv:flex"
                                    }`}
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    <button
                                      type="button"
                                      onClick={() => handleTogglePinConv(conv.id)}
                                      title={conv.isPinned ? "取消置顶" : "置顶"}
                                      className={`h-5 w-5 rounded hover:bg-slate-700/70 inline-flex items-center justify-center cursor-pointer ${
                                        conv.isPinned ? "text-cyan-400" : "text-slate-400 hover:text-slate-100"
                                      }`}
                                    >
                                      <Pin className="w-3 h-3" />
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        setOpenConvMenuId(convMenuOpen ? null : conv.id)
                                      }
                                      title="对话操作"
                                      className="h-5 w-5 rounded hover:bg-slate-700/70 text-slate-400 hover:text-slate-100 inline-flex items-center justify-center cursor-pointer"
                                    >
                                      <MoreHorizontal className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                )}

                                {convMenuOpen && !isExtItem && canEdit && (
                                  <div
                                    onClick={(e) => e.stopPropagation()}
                                    className="absolute right-1 top-8 z-40 w-36 rounded-xl border border-slate-700 bg-slate-900/95 shadow-xl py-1 text-xs"
                                  >
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setOpenConvMenuId(null);
                                        handleTogglePinConv(conv.id);
                                      }}
                                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                                    >
                                      <Pin className="w-3.5 h-3.5 text-slate-400" />
                                      {conv.isPinned ? "取消置顶" : "置顶"}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setOpenConvMenuId(null);
                                        setRenameTarget({
                                          kind: "conversation",
                                          id: conv.id,
                                          currentName: conv.title,
                                        });
                                        setRenameDraft(conv.title);
                                      }}
                                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                                    >
                                      <Pencil className="w-3.5 h-3.5 text-slate-400" />
                                      重命名
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setOpenConvMenuId(null);
                                        handleToggleArchiveConv(conv.id);
                                      }}
                                      className="w-full px-3 py-1.5 text-left text-slate-200 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                                    >
                                      <Archive className="w-3.5 h-3.5 text-slate-400" />
                                      {conv.isArchived ? "取消归档" : "归档"}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setOpenConvMenuId(null);
                                        handleHideConv(conv.id);
                                      }}
                                      className="w-full px-3 py-1.5 text-left text-rose-300 hover:bg-slate-800 flex items-center gap-2 cursor-pointer"
                                    >
                                      <EyeOff className="w-3.5 h-3.5" />
                                      隐藏对话
                                    </button>
                                  </div>
                                )}
                              </div>
                            );
                          })
                        )}

                        {hasOverflow && (
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedProjectLists((prev) => ({
                                ...prev,
                                [group.id]: !listExpanded,
                              }))
                            }
                            className="w-full flex items-center gap-1.5 pl-5 pr-2 py-1 rounded-lg text-[11px] text-slate-500 hover:text-slate-300 hover:bg-slate-800/40 cursor-pointer"
                          >
                            {listExpanded ? (
                              <>
                                <ChevronUp className="w-3 h-3 shrink-0" />
                                <span>收起</span>
                              </>
                            ) : (
                              <>
                                <ChevronDown className="w-3 h-3 shrink-0" />
                                <span>展开其余 {hiddenCount} 条</span>
                              </>
                            )}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </aside>

        {/* Center Pane: Standalone Federation Chatroom OR Bubble Multi-Turn Conversation Stage */}
        <section
          className={`${
            mobilePane === "chat" ? "flex" : "hidden"
          } md:flex flex-1 min-w-0 min-h-0 flex-col bg-slate-950`}
        >
          {activePaneMode === "chatroom" ? (
            <>
              {/* Federation Chatroom Sub-Header */}
              <div className="shrink-0 px-4 py-2 border-b border-slate-800/80 bg-slate-900/40 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Users className="w-4 h-4 text-sky-400 shrink-0" />
                  <span className="text-xs font-semibold text-slate-100 truncate">
                    {chatroomData?.title || "联邦聊天室"}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded border text-[10px] font-medium shrink-0 ${
                      chatroomData?.bound
                        ? chatroomData.mirror_status === "connected"
                          ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                          : "bg-amber-500/15 text-amber-300 border-amber-500/30"
                        : "bg-slate-800 text-slate-400 border-slate-700"
                    }`}
                  >
                    {chatroomData?.bound
                      ? chatroomData.mirror_status === "connected"
                        ? "TG 群双向实时镜像"
                        : "总指挥 IPC 离线"
                      : "未绑定群聊"}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-slate-400 shrink-0">
                  <span className="font-mono">{chatroomMessages.length} 条消息</span>
                  <span className="hidden sm:inline">·</span>
                  <span className="hidden sm:inline">{chatroomParticipants.length} 位成员</span>
                </div>
              </div>

              {/* Clickable @handle Participant Pills */}
              {chatroomParticipants.length > 0 && (
                <div className="shrink-0 px-4 py-1.5 border-b border-slate-800/60 bg-slate-900/20 flex items-center gap-1.5 overflow-x-auto">
                  <span className="text-[10px] text-slate-500 shrink-0">点击 @ 路由：</span>
                  {chatroomParticipants.map((p) => {
                    const isExt = p.kind === "external_agent";
                    return (
                      <button
                        key={`${p.kind}:${p.handle}`}
                        type="button"
                        disabled={!canEdit || !chatroomData?.bound || !p.can_mention}
                        onClick={() => handleInsertChatroomMention(p)}
                        title={`${p.display_name} (${isExt ? "外部联邦节点" : p.role === "coordinator" ? "本机总指挥" : "本机 Bot"} · ${p.runtime_status})`}
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] shrink-0 transition-colors ${
                          isExt
                            ? "border-violet-500/35 bg-violet-500/10 text-violet-200 hover:bg-violet-500/20"
                            : "border-sky-500/35 bg-sky-500/10 text-sky-200 hover:bg-sky-500/20"
                        } disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            p.online ? "bg-emerald-400" : "bg-slate-500"
                          }`}
                        />
                        <span className="font-mono">@{p.handle}</span>
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Readonly / Error / Notice Banners */}
              <div className="shrink-0 px-4 pt-2 space-y-1.5">
                {!canEdit && (
                  <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-200 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                    当前账号为只读权限（readonly），仅可查看脱敏后的联邦聊天室消息，发言功能已禁用。
                  </div>
                )}
                {error && (
                  <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-200 flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      {error}
                    </span>
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
                  <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-200 flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 shrink-0" />
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
              </div>

              {/* Chatroom Message Stream */}
              <div className="flex-1 min-h-0 overflow-y-auto px-4 py-4 space-y-3">
                {chatroomLoading && !chatroomData ? (
                  <div className="py-12 text-center text-xs text-slate-500">加载联邦聊天室记录中…</div>
                ) : !chatroomData?.bound ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-3">
                    <div className="h-11 w-11 rounded-2xl border border-slate-700 bg-slate-900 flex items-center justify-center text-slate-400">
                      <Users className="w-5 h-5" />
                    </div>
                    <div className="space-y-1.5 max-w-md">
                      <div className="text-sm font-semibold text-slate-100">
                        尚未绑定独立「联邦聊天室」Telegram 群
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        为保证与主团队群硬隔离，联邦聊天室仅读取独立绑定配置（不会回退到主团队群）。请在服务端配置环境变量{" "}
                        <code className="px-1 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-[11px]">
                          AGY_STUDIO_FEDERATION_MIRROR_CHAT_ID
                        </code>{" "}
                        或在{" "}
                        <code className="px-1 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-[11px]">
                          team_config.json
                        </code>{" "}
                        中添加{" "}
                        <code className="px-1 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-[11px]">
                          federation_mirror
                        </code>{" "}
                        字段。
                      </p>
                    </div>
                  </div>
                ) : chatroomMessages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-2.5">
                    <div className="h-10 w-10 rounded-2xl border border-sky-500/30 bg-sky-500/10 flex items-center justify-center text-sky-400">
                      <MessageSquare className="w-5 h-5" />
                    </div>
                    <div className="text-sm font-semibold text-slate-100">联邦聊天室暂无历史消息</div>
                    <p className="text-xs text-slate-400 max-w-md">
                      直接发送消息将由本机总指挥接单并同步至 Telegram 联邦群；使用{" "}
                      <code className="font-mono text-violet-300">@外部节点</code>{" "}
                      将仅镜像人类消息并直派外部节点、自动脱敏回贴最终结果。
                    </p>
                  </div>
                ) : (
                  chatroomMessages.map((msg: FederationChatroomMessageItem) => {
                    const isHuman = msg.sender_kind === "human" || msg.sender_type === "human";
                    const isExternal = msg.sender_kind === "external_agent";
                    return (
                      <div
                        key={`${msg.msg_id}-${msg.seq}`}
                        className={`flex ${isHuman ? "justify-end" : "justify-start"}`}
                      >
                        <div
                          className={`max-w-[92%] md:max-w-[82%] rounded-2xl px-3.5 py-2.5 border space-y-1.5 ${
                            isHuman
                              ? "bg-sky-600/20 border-sky-500/35 text-slate-100"
                              : isExternal
                                ? "bg-violet-950/35 border-violet-500/35 text-slate-100"
                                : "bg-slate-900/85 border-slate-800/90 text-slate-100"
                          }`}
                        >
                          <div
                            className={`flex flex-wrap items-center gap-1.5 text-[10px] ${
                              isHuman ? "justify-end" : "justify-start"
                            }`}
                          >
                            {!isHuman && (
                              <Bot
                                className={`w-3 h-3 shrink-0 ${
                                  isExternal ? "text-violet-300" : "text-emerald-300"
                                }`}
                              />
                            )}
                            <span className="font-semibold text-slate-200">{msg.sender}</span>
                            {isHuman ? (
                              <span className="px-1.5 py-0.2 rounded border border-sky-500/35 bg-sky-500/15 text-sky-200">
                                {msg.source === "web" ? "主人 · Web" : "主人 · TG"}
                              </span>
                            ) : isExternal ? (
                              <span className="px-1.5 py-0.2 rounded border border-violet-500/35 bg-violet-500/15 text-violet-200">
                                外部联邦节点
                              </span>
                            ) : (
                              <span className="px-1.5 py-0.2 rounded border border-emerald-500/35 bg-emerald-500/15 text-emerald-200">
                                {msg.sender_role === "coordinator" ? "本机总指挥" : "本机 Bot"}
                              </span>
                            )}
                            <span className="text-slate-400 font-mono">#{msg.seq}</span>
                            <span className="text-slate-400">{formatTs(msg.ts)}</span>
                          </div>
                          {isHuman ? (
                            <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                              {msg.content}
                            </div>
                          ) : (
                            <SafeMarkdown content={msg.content || ""} className="text-sm" />
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
                <div ref={chatroomEndRef} />
              </div>

              {/* Bottom Rounded Chatroom Composer */}
              <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5">
                <div className="rounded-2xl border border-slate-800 bg-slate-950/95 focus-within:border-sky-500/70 transition-colors p-2 space-y-1.5">
                  <textarea
                    rows={2}
                    value={chatroomInput}
                    disabled={!canEdit || !chatroomData?.bound || chatroomSending}
                    onCompositionStart={() => {
                      isComposingRef.current = true;
                    }}
                    onCompositionEnd={() => {
                      isComposingRef.current = false;
                    }}
                    onChange={(e) => setChatroomInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (isComposingRef.current || e.nativeEvent.isComposing) return;
                      if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
                        e.preventDefault();
                        void handleSendChatroomMessage();
                      }
                    }}
                    placeholder={
                      !canEdit
                        ? "只读权限已禁用联邦聊天室发言"
                        : !chatroomData?.bound
                          ? "请先绑定独立联邦聊天室 TG 群后再发言"
                          : "在联邦聊天室发言（默认路由总指挥；输入 @节点名 可直派本机 Bot 或外部联邦节点，Enter 发送）…"
                    }
                    className="w-full resize-none bg-transparent px-1.5 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:opacity-50"
                  />
                  <div className="pt-1.5 border-t border-slate-800/75 flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {canEdit ? (
                        <button
                          type="button"
                          disabled={!chatroomData?.bound}
                          onClick={() => setChatroomIncludeContext((v) => !v)}
                          title="点名外部联邦节点时自动附带近期已脱敏的群聊上下文"
                          className={`h-7 px-2 rounded-lg border text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors disabled:opacity-40 ${
                            chatroomIncludeContext
                              ? "bg-indigo-500/15 border-indigo-500/40 text-indigo-200"
                              : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          <Layers className="w-3 h-3" />
                          <span>外部节点附带群聊上下文</span>
                        </button>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-amber-300/90">
                          <Lock className="w-3 h-3" />
                          只读模式
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      disabled={
                        !canEdit ||
                        !chatroomData?.bound ||
                        chatroomSending ||
                        !chatroomInput.trim()
                      }
                      onClick={() => void handleSendChatroomMessage()}
                      className="inline-flex items-center gap-1.5 h-8 rounded-xl bg-sky-600 hover:bg-sky-500 px-3.5 text-xs font-medium text-white cursor-pointer disabled:opacity-40 shrink-0"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>{chatroomSending ? "发送中…" : "发送并同步群"}</span>
                    </button>
                  </div>
                </div>
              </footer>
            </>
          ) : (
            <>
          {/* Conversation Sub-Header */}
          {selectedAgent ? (
            <div className="shrink-0 px-4 py-2 border-b border-slate-800/80 bg-slate-900/35 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="px-1.5 py-0.5 rounded bg-slate-800/90 border border-slate-700/80 text-[10px] text-slate-300 shrink-0">
                  {currentProjectName}
                </span>
                <span className="text-slate-600 text-xs">/</span>
                <span className="text-xs font-semibold text-slate-100 truncate">
                  {isExternalHistoryView
                    ? "外部历史任务（Telegram / Bus / 未归属）"
                    : activeConversationObj?.title || "新对话"}
                </span>
                <span className="hidden sm:inline text-[11px] font-mono text-slate-500">
                  · {selectedAgent.agent_id}
                </span>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-400 shrink-0">
                <span className="font-mono">
                  {visibleMessages.length} 轮
                </span>
                <span className="hidden sm:inline">·</span>
                <span className="hidden sm:inline">
                  通道: {selectedAgent.dispatch_mode === "pull" ? "PullQueue" : selectedAgent.dispatch_mode}
                </span>
              </div>
            </div>
          ) : (
            <div className="shrink-0 px-4 py-2 border-b border-slate-800/80 bg-slate-900/35 text-xs text-slate-400">
              请在顶部选择一个外部联邦节点开始多轮对话
            </div>
          )}

          {/* Readonly / Error / Notice Banners */}
          <div className="shrink-0 px-4 pt-2 space-y-1.5">
            {!canEdit && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                当前账号为只读权限（readonly），仅可查看脱敏后的项目与多轮对话，派单与状态修改已禁用。
              </div>
            )}
            {error && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-200 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {error}
                </span>
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
              <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-200 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
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
          </div>

          {/* Bubble Multi-Turn Message Stream */}
          <div className="flex-1 min-h-0 overflow-y-auto px-4 py-4 space-y-4">
            {!selectedAgent ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-2">
                <Radio className="w-8 h-8 text-slate-700" />
                <div className="text-sm font-medium text-slate-300">暂无选中的外部联邦节点</div>
                <div className="text-xs text-slate-500">
                  注册外部节点后即可按项目与对话组织多轮协作任务。
                </div>
              </div>
            ) : loadingTimeline && visibleMessages.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500">加载多轮对话记录中…</div>
            ) : visibleMessages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 space-y-3">
                <div className="h-11 w-11 rounded-2xl border border-sky-500/30 bg-sky-500/10 flex items-center justify-center text-sky-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div className="space-y-1 max-w-md">
                  <div className="text-sm font-semibold text-slate-100">
                    向「{selectedAgent.display_name || selectedAgent.agent_id}」发起新对话
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    所属项目：<span className="text-slate-200">{currentProjectName}</span> ·
                    支持同对话内自动附带最近已完成轮次上下文（最多 6 轮、自动脱敏），并在跨设备间同步项目与对话树。
                  </p>
                  {selectedHbLabel && (
                    <div className="text-[11px] font-mono text-emerald-300/90 pt-1">
                      {selectedHbLabel}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              visibleMessages.map((item) => {
                const srcMeta = sourceBadgeMeta(item.source);
                const stBadge = jobStatusBadge(item.status);
                const elapsedLabel = formatElapsed(item.elapsed_s);
                const userText = item.display_prompt || item.prompt || "(空指令)";
                const ctxTurns = typeof item.context_turns === "number" ? item.context_turns : 0;

                return (
                  <div key={item.job_id} className="space-y-2.5">
                    {/* Right-aligned User Bubble */}
                    <div className="flex justify-end">
                      <div className="max-w-[92%] md:max-w-[82%] rounded-2xl px-3.5 py-2.5 border bg-sky-600/20 border-sky-500/35 text-slate-100 space-y-1.5">
                        <div className="flex flex-wrap items-center justify-end gap-1.5 text-[10px]">
                          {item.label && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded bg-sky-500/20 border border-sky-400/30 text-sky-200">
                              <Tag className="w-2.5 h-2.5" />
                              {item.label}
                            </span>
                          )}
                          {ctxTurns > 0 && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded bg-indigo-500/20 border border-indigo-400/30 text-indigo-200">
                              <Layers className="w-2.5 h-2.5" />
                              含 {ctxTurns} 轮上下文
                            </span>
                          )}
                          <span className={`px-1.5 py-0.2 rounded border ${srcMeta.cls}`}>
                            {srcMeta.label}
                          </span>
                          <span className="text-slate-400">{formatTs(item.created_at)}</span>
                        </div>
                        <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                          {userText}
                        </div>
                      </div>
                    </div>

                    {/* Left-aligned External Agent Reply Bubble */}
                    <div className="flex justify-start">
                      <div className="max-w-[92%] md:max-w-[85%] rounded-2xl px-3.5 py-2.5 border bg-slate-900/80 border-slate-800/90 text-slate-100 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-medium text-slate-200">
                              {selectedAgent.display_name || selectedAgent.agent_id}
                            </span>
                            <span className={`px-1.5 py-0.2 rounded border text-[10px] font-medium ${stBadge.cls}`}>
                              {stBadge.label}
                            </span>
                            {item.bridged && (
                              <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                                桥接去重
                              </span>
                            )}
                            <code className="text-[10px] font-mono text-slate-500">
                              {item.job_id}
                            </code>
                          </div>

                          <div className="flex items-center gap-2">
                            {elapsedLabel && (
                              <span className="inline-flex items-center gap-1 font-mono text-[10px] text-slate-400">
                                <Clock className="w-3 h-3" />
                                {elapsedLabel}
                              </span>
                            )}
                            {canEdit && item.can_cancel && (
                              <button
                                type="button"
                                disabled={cancellingJobId === item.job_id}
                                onClick={() => void handleCancelJob(item.job_id)}
                                className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/15 hover:bg-rose-500/25 px-2 py-0.5 text-[10px] font-medium text-rose-200 cursor-pointer disabled:opacity-50"
                              >
                                <Square className="w-2.5 h-2.5" />
                                {cancellingJobId === item.job_id ? "取消中…" : "取消任务"}
                              </button>
                            )}
                          </div>
                        </div>

                        {item.result_text ? (
                          <SafeMarkdown content={item.result_text} className="text-sm" />
                        ) : item.error || item.cancel_reason ? (
                          <div className="rounded-lg border border-rose-500/30 bg-rose-950/30 px-3 py-2 text-xs text-rose-200 whitespace-pre-wrap break-words">
                            {item.error || item.cancel_reason}
                          </div>
                        ) : item.is_active ? (
                          <div className="flex items-center gap-2 text-xs text-sky-300/90 py-0.5">
                            <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
                            <span>
                              {item.status === "queued"
                                ? "已入队，等待外部节点拉取/接单…"
                                : item.status === "claimed"
                                  ? "外部 Pull Worker 已认领，执行中…"
                                  : "外部节点正在执行中…"}
                            </span>
                          </div>
                        ) : (
                          <div className="text-xs text-slate-500">（无输出正文）</div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
            <div ref={timelineEndRef} />
          </div>

          {/* Bottom Modern Rounded Composer */}
          {selectedAgent && (
            <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5">
              {!selectedAgent.can_dispatch && canEdit ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-slate-400">
                  当前节点不可直接派单：{selectedAgent.dispatch_disabled_reason || "不满足派单条件"}
                </div>
              ) : (
                <div className="rounded-2xl border border-slate-800 bg-slate-950/95 focus-within:border-sky-500/70 transition-colors p-2 space-y-1.5">
                  {showLabelInput && canEdit && (
                    <div className="flex items-center gap-1.5 px-1">
                      <Tag className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <input
                        type="text"
                        value={labelInput}
                        onChange={(e) => setLabelInput(e.target.value)}
                        placeholder="可选任务标签（例如：健康巡检 / 报表生成）"
                        maxLength={120}
                        disabled={sending || !canEdit}
                        className="flex-1 bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none border-b border-slate-800 pb-1"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          setLabelInput("");
                          setShowLabelInput(false);
                        }}
                        className="text-slate-500 hover:text-slate-300 cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}

                  <textarea
                    rows={2}
                    value={promptInput}
                    disabled={!canEdit || sending}
                    onCompositionStart={() => {
                      isComposingRef.current = true;
                    }}
                    onCompositionEnd={() => {
                      isComposingRef.current = false;
                    }}
                    onChange={(e) => setPromptInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (isComposingRef.current || e.nativeEvent.isComposing) return;
                      if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
                        e.preventDefault();
                        void handleDispatch();
                      }
                    }}
                    placeholder={
                      !canEdit
                        ? "只读权限已禁用派单输入"
                        : `向「${selectedAgent.display_name || selectedAgent.agent_id}」发送消息（Enter 发送 · Shift+Enter 换行）…`
                    }
                    className="w-full resize-none bg-transparent px-1.5 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:opacity-50"
                  />

                  <div className="pt-1.5 border-t border-slate-800/75 flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {canEdit ? (
                        <>
                          <button
                            type="button"
                            onClick={() => setIncludeContext((v) => !v)}
                            title="开启后将自动附带同一对话内最近 6 轮已完成且脱敏的上下文摘要"
                            className={`h-7 px-2 rounded-lg border text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors ${
                              includeContext
                                ? "bg-indigo-500/15 border-indigo-500/40 text-indigo-200"
                                : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            <Layers className="w-3 h-3" />
                            <span>附带上下文</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => setShowLabelInput((v) => !v)}
                            className={`h-7 px-2 rounded-lg border text-[11px] inline-flex items-center gap-1 cursor-pointer transition-colors ${
                              showLabelInput || labelInput
                                ? "bg-sky-500/15 border-sky-500/40 text-sky-200"
                                : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            <Tag className="w-3 h-3" />
                            <span>标签</span>
                          </button>
                        </>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-amber-300/90">
                          <Lock className="w-3 h-3" />
                          只读模式
                        </span>
                      )}

                      <span className="text-[10px] font-mono text-slate-500 hidden sm:inline">
                        {selectedAgent.dispatch_mode === "pull" ? "PullQueue 直写" : "BotBus 推送"}
                      </span>
                    </div>

                    <button
                      type="button"
                      disabled={!canEdit || sending || !promptInput.trim()}
                      onClick={() => void handleDispatch()}
                      className="inline-flex items-center gap-1.5 h-8 rounded-xl bg-sky-600 hover:bg-sky-500 px-3.5 text-xs font-medium text-white cursor-pointer disabled:opacity-40 shrink-0"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>{sending ? "派发中…" : "发送"}</span>
                    </button>
                  </div>
                </div>
              )}
            </footer>
          )}
            </>
          )}
        </section>

        {/* Right Collapsible Telemetry Drawer */}
        <aside
          className={`${
            mobilePane === "telemetry"
              ? "flex w-full"
              : showTelemetry
                ? "hidden lg:flex lg:w-80"
                : "hidden"
          } shrink-0 flex-col border-l border-slate-800/90 bg-slate-900/40 min-h-0 overflow-y-auto`}
        >
          {/* Pull Inbox Section */}
          <div className="p-3 border-b border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Inbox className="w-3.5 h-3.5 text-cyan-400" />
                Pull Inbox 待拉取/在途 ({pullInbox.length})
              </span>
            </div>
            {pullInbox.length === 0 ? (
              <div className="text-[11px] text-slate-500 py-2">当前无待处理 Pull 队列任务</div>
            ) : (
              <div className="space-y-1.5">
                {pullInbox.map((pq) => (
                  <div
                    key={pq.job_id}
                    className="rounded-lg border border-slate-800 bg-slate-950/70 p-2 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-1 text-[10px]">
                      <code className="font-mono text-sky-300 truncate">{pq.job_id}</code>
                      <span
                        className={`px-1.5 py-0.2 rounded border ${jobStatusBadge(pq.status).cls}`}
                      >
                        {jobStatusBadge(pq.status).label}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-300 line-clamp-2 break-words">
                      {pq.prompt_preview || pq.label || "-"}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>{formatTs(pq.created_at)}</span>
                      {canEdit && pq.can_cancel && (
                        <button
                          type="button"
                          disabled={cancellingJobId === pq.job_id}
                          onClick={() => void handleCancelJob(pq.job_id)}
                          className="text-rose-300 hover:text-rose-200 cursor-pointer"
                        >
                          取消
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Leader Events Telemetry Section */}
          <div className="p-3 border-b border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Bell className="w-3.5 h-3.5 text-indigo-400" />
                Leader Events 摘要 ({leaderEvents.length})
              </span>
            </div>
            {leaderEvents.length === 0 ? (
              <div className="text-[11px] text-slate-500 py-2">暂无待消费的 leader_events</div>
            ) : (
              <div className="space-y-1.5">
                {leaderEvents.map((ev) => (
                  <div
                    key={ev.event_id}
                    className="rounded-lg border border-slate-800 bg-slate-950/70 p-2 space-y-1 text-[11px]"
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-mono text-indigo-300 text-[10px] truncate">
                        {ev.type} · {ev.event_id}
                      </span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {ev.status}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 flex flex-wrap gap-2">
                      <span>关联任务: {ev.jobs_count}</span>
                      {ev.team_id && <span>团队: {ev.team_id}</span>}
                      {ev.tainted && <span className="text-amber-300">tainted</span>}
                    </div>
                    {ev.job_ids.length > 0 && (
                      <div className="text-[10px] font-mono text-slate-500 truncate">
                        {ev.job_ids.join(", ")}
                      </div>
                    )}
                    <div className="text-[10px] text-slate-500">{formatTs(ev.created_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Hub Endpoint Info */}
          <div className="p-3 space-y-1.5 text-[11px]">
            <div className="text-xs font-semibold text-slate-300">Hub 接入信息</div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 space-y-1 font-mono text-[10px]">
              <div className="text-slate-400">
                公网 URL:{" "}
                <span className="text-emerald-300 break-all">
                  {hubConfig?.public_url || "未配置（回退本地回环）"}
                </span>
              </div>
              <div className="text-slate-400">
                MCP URL:{" "}
                <span className="text-sky-300 break-all">{hubConfig?.mcp_url || "-"}</span>
              </div>
              <div className="text-slate-500">
                回环探活: {hubConfig?.loopback_mcp_url || "-"}
              </div>
            </div>
          </div>
        </aside>
      </div>

      {/* Modal: Create Logical Project (Strictly ZERO Host Path Input) */}
      {newProjectModalOpen && canEdit && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4"
          onClick={() => setNewProjectModalOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-4 space-y-3 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <FolderPlus className="w-4 h-4 text-sky-400" />
                新增联邦逻辑项目
              </h2>
              <button
                type="button"
                onClick={() => setNewProjectModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              用于按主题分组外部节点的多轮对话（纯逻辑分组，不绑定宿主机目录路径）。
            </p>
            <div className="space-y-2.5">
              <div>
                <label className="block text-xs text-slate-300 mb-1">项目名称 *</label>
                <input
                  type="text"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                  maxLength={64}
                  placeholder="例如：边缘巡检 / 季度报表"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">备注说明（可选）</label>
                <input
                  type="text"
                  value={newProjectDesc}
                  onChange={(e) => setNewProjectDesc(e.target.value)}
                  maxLength={240}
                  placeholder="简短描述该项目下的外部协作目标"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setNewProjectModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={!normalizeSingleLineText(newProjectName, 64)}
                onClick={handleCreateProject}
                className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white cursor-pointer disabled:opacity-40"
              >
                创建项目
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Rename Project or Conversation */}
      {renameTarget && canEdit && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4"
          onClick={() => setRenameTarget(null)}
        >
          <div
            className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-4 space-y-3 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100">
                {renameTarget.kind === "project" ? "重命名项目" : "重命名对话"}
              </h2>
              <button
                type="button"
                onClick={() => setRenameTarget(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <input
              type="text"
              value={renameDraft}
              onChange={(e) => setRenameDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  handleSubmitRename();
                }
              }}
              maxLength={renameTarget.kind === "project" ? 64 : 120}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setRenameTarget(null)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={
                  !normalizeSingleLineText(
                    renameDraft,
                    renameTarget.kind === "project" ? 64 : 120,
                  )
                }
                onClick={handleSubmitRename}
                className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white cursor-pointer disabled:opacity-40"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
