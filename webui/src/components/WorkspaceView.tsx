import {
  type ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
  AtSign,
  Bell,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Columns2,
  Columns3,
  Copy,
  FileCode,
  Folder,
  FolderPlus,
  GitBranch,
  Globe,
  Grid2x2,
  ListFilter,
  ListPlus,
  Loader2,
  Lock,
  MessageSquare,
  MoreVertical,
  PanelLeft,
  Pencil,
  Pin,
  Plus,
  RefreshCw,
  Send,
  Square,
  Trash2,
  Users,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import {
  StudioApiError,
  abortChatTurn,
  fetchActiveSessionTurn,
  fetchBotConfig,
  fetchBots,
  fetchModels,
  fetchSessionMessages,
  fetchSessions,
  fetchWorkbenchState,
  sendChatTurn,
  updateBotConfig,
  updateWorkbenchState,
} from "../api";
import {
  MAX_CLIENT_CHAT_STREAMS,
  releaseStreamSlot as releaseStreamSlotById,
  useStreamBudget,
} from "../streamBudget";
import type {
  BotRosterItem,
  BrowserOwner,
  ChatAttachmentItem,
  ChatMessageItem,
  ChatToolCall,
  ExecutionMode,
  ModelOption,
  ModelsResponse,
  PaneKind,
  RoomLiveEvent,
  SessionSummaryItem,
  SessionUpdatedEvent,
  SessionWorktreeInfo,
  StudioSession,
  WorkbenchCustomProjectItem,
  WorkbenchLayoutPrefs,
  WorkbenchPaneConfig,
  WorkbenchSidebarState,
} from "../types";
import { AttentionPanel } from "./AttentionPanel";
import { BrowserView } from "./BrowserView";
import {
  ComposerAttachmentTray,
  DragDropOverlay,
  FILE_INPUT_ACCEPT,
  ImageLightboxModal,
  MessageAttachmentsDisplay,
  SUPPORTED_FORMATS_TOOLTIP,
  WorkspaceFilePickerPopover,
  useAttachmentComposer,
} from "./ComposerAttachments";
import { FilesDiffPanel } from "./FilesDiffPanel";
import { JobsView } from "./JobsView";
import { RoomPanel, type RoomMetaSummary } from "./RoomPanel";
import { SafeMarkdown } from "./SafeMarkdown";

const WORKBENCH_STORAGE_KEY = "agy_studio_workbench_v1";
const TEAM_TARGET_ID = "__team__";

const DEFAULT_VISIBLE_SESSIONS_PER_PROJECT = 5;
const TEMP_PROJECT_NAME_RE = /^tmp[a-z0-9_]{6,}$/i;
const TEMP_PROJECT_GROUP_ID = "__tmp_projects__";
const UNASSIGNED_PROJECT_GROUP_ID = "__unassigned__";
const RESERVED_PROJECT_IDS = new Set<string>([
  TEMP_PROJECT_GROUP_ID,
  UNASSIGNED_PROJECT_GROUP_ID,
  "__other__",
]);
const MAX_CUSTOM_PROJECTS = 64;
const MAX_PROJECT_RENAMES = 128;
const MAX_HIDDEN_PROJECT_IDS = 128;
const MAX_HIDDEN_SESSION_CIDS = 500;
const MAX_PINNED_SESSION_CIDS = 200;
const MAX_ARCHIVED_SESSION_CIDS = 500;
const MAX_UNREAD_SESSION_CIDS = 500;
const MAX_SESSION_RENAMES = 500;
const MAX_PROJECT_NAME_LEN = 64;
const MAX_SESSION_TITLE_LEN = 120;
const FORBIDDEN_RECORD_KEYS = new Set<string>(["__proto__", "prototype", "constructor"]);
const NATIVE_PROVIDER_ID = "native";
const ALL_PROVIDERS_ID = "__all__";
const MODEL_PROVIDER_PREFIX_RE = /^\[([^\]]+)\]\s*(.+)$/;
const INTERNAL_NOISE_LINE_RE =
  /^\s*\[(?:AGY_MEMORY_READONLY|ACB_COORDINATOR_ROLE|ACB_FAST_GROUP_CHAT|ACB_TEAM_DELEGATION|ACB_SCHEDULED_TASK|群聊近期上下文|TG\b)/i;
const LEADING_WRAPPER_TAG_RE =
  /^\s*\[(?:AGY_MEMORY_READONLY[^\]]*|ACB_COORDINATOR_ROLE[^\]]*|ACB_FAST_GROUP_CHAT[^\]]*|ACB_TEAM_DELEGATION[^\]]*|ACB_SCHEDULED_TASK[^\]]*|TG[^\]]*)\]\s*/i;
const WRAPPER_META_ONLY_RE =
  /^(?:(?:bot|role|job|from|to|label|chat_id|topic_id)=[^\s]+\s*)+$/i;

interface ParsedModelOption {
  id: string;
  rawLabel: string;
  provider: string;
  displayName: string;
}

type CustomProjectItem = WorkbenchCustomProjectItem;

interface StoredWorkbenchPrefs extends WorkbenchLayoutPrefs, WorkbenchSidebarState {}

interface ProjectSessionGroup {
  id: string;
  name: string;
  rawName: string;
  kind: "formal" | "temp" | "unassigned";
  projectId: string | null;
  sessions: SessionSummaryItem[];
  latestUpdatedAt: string;
  hasActiveSession: boolean;
  isSelectedProject: boolean;
  isCustom?: boolean;
  isLocalOnly?: boolean;
}

type DeleteConfirmTarget =
  | {
      kind: "project";
      groupId: string;
      projectId: string | null;
      name: string;
      sessionCount: number;
      sessionCids: string[];
      isCustom: boolean;
      groupKind: "formal" | "temp" | "unassigned";
    }
  | {
      kind: "session";
      cid: string;
      title: string;
      projectName: string;
    };

type RenameModalTarget =
  | {
      kind: "project";
      groupId: string;
      currentName: string;
      originalName: string;
    }
  | {
      kind: "session";
      cid: string;
      currentTitle: string;
      originalTitle: string;
    };

type SidebarOpenMenu =
  | { kind: "filter"; top: number; left: number }
  | { kind: "project"; groupId: string; top: number; left: number }
  | { kind: "session"; cid: string; groupId: string; top: number; left: number };

export interface PendingOpenSessionPayload {
  id: number;
  session: SessionSummaryItem;
}

export interface SplitOpenResult {
  ok: boolean;
  message?: string;
}

function formatCompactRelativeTime(raw?: string | null): string {
  if (!raw) return "";
  const trimmed = String(raw).trim();
  if (!trimmed) return "";

  let tsMs = Number.NaN;
  if (/^\d{10,13}$/.test(trimmed)) {
    const n = Number(trimmed);
    tsMs = trimmed.length <= 10 ? n * 1000 : n;
  } else {
    const normalized =
      /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(trimmed) && !trimmed.includes("T")
        ? trimmed.replace(" ", "T")
        : trimmed;
    tsMs = Date.parse(normalized);
  }
  if (!Number.isFinite(tsMs)) return "";

  const diffSec = Math.floor((Date.now() - tsMs) / 1000);
  if (!Number.isFinite(diffSec)) return "";
  if (diffSec < 60) return "now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h`;
  if (diffSec < 86400 * 30) return `${Math.floor(diffSec / 86400)}d`;
  if (diffSec < 86400 * 365) return `${Math.floor(diffSec / (86400 * 30))}mo`;
  return `${Math.floor(diffSec / (86400 * 365))}y`;
}

function computeFloatingMenuPosition(
  anchorRect: DOMRect,
  menuWidth: number,
  estimatedHeight: number,
  align: "right-edge" | "under-trigger" = "under-trigger",
): { top: number; left: number } {
  const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
  const vh = typeof window !== "undefined" ? window.innerHeight : 800;
  const pad = 8;

  const preferredLeft =
    align === "right-edge" ? anchorRect.right - menuWidth : anchorRect.left - 8;
  const left = Math.max(pad, Math.min(preferredLeft, vw - menuWidth - pad));

  let top = anchorRect.bottom + 6;
  if (top + estimatedHeight > vh - pad) {
    const aboveTop = anchorRect.top - estimatedHeight - 6;
    top = aboveTop >= pad ? aboveTop : Math.max(pad, vh - estimatedHeight - pad);
  }
  return { top, left };
}

function isTempProjectName(name: string): boolean {
  return TEMP_PROJECT_NAME_RE.test((name || "").trim());
}

function parseModelOption(m: ModelOption): ParsedModelOption {
  const rawLabel = (m.label || m.id || "").trim();
  const match = MODEL_PROVIDER_PREFIX_RE.exec(rawLabel);
  if (match) {
    const provider = match[1].trim();
    const displayName = match[2].trim();
    if (provider && displayName) {
      return { id: m.id, rawLabel, provider, displayName };
    }
  }
  return {
    id: m.id,
    rawLabel: rawLabel || m.id,
    provider: NATIVE_PROVIDER_ID,
    displayName: rawLabel || m.id,
  };
}

function formatProviderLabel(provider: string): string {
  return provider === NATIVE_PROVIDER_ID ? "AGY 原生" : provider;
}

function formatSessionDisplayTitle(item: SessionSummaryItem): string {
  const rawTitle = (item.title || "").trim();
  const rawPreview = (item.preview || "").trim();
  if (rawTitle && !INTERNAL_NOISE_LINE_RE.test(rawTitle)) {
    return rawTitle;
  }

  const sourceText = rawPreview || rawTitle;
  if (sourceText) {
    const lines = sourceText.split(/\r?\n/);
    for (const rawLine of lines) {
      let line = rawLine.trim();
      if (!line) continue;
      if (/^\[群聊近期上下文/.test(line)) continue;
      let guard = 0;
      while (LEADING_WRAPPER_TAG_RE.test(line) && guard < 4) {
        line = line.replace(LEADING_WRAPPER_TAG_RE, "").trim();
        guard += 1;
      }
      if (!line) continue;
      if (/^\[(?:ACB_|AGY_MEMORY_READONLY|群聊近期上下文)/i.test(line)) continue;
      if (WRAPPER_META_ONLY_RE.test(line)) continue;
      if (/^bot=@?\S+/i.test(line)) {
        const afterMeta = line.replace(/^(?:(?:bot|role|job|from|to)=[^\s]+\s*)+/i, "").trim();
        if (!afterMeta) continue;
        line = afterMeta;
      }
      return line.slice(0, 80);
    }
  }

  const firstLine = (rawTitle || rawPreview).trim();
  if (/^\[群聊近期上下文/.test(firstLine)) return "群聊上下文会话";
  if (/^\[ACB_FAST_GROUP_CHAT/i.test(firstLine)) return "群聊快捷会话";
  if (/^\[ACB_COORDINATOR_ROLE/i.test(firstLine)) return "协调器会话";
  if (/^\[AGY_MEMORY_READONLY/i.test(firstLine)) return "只读上下文会话";
  return rawTitle || item.cid.slice(0, 10);
}

const VALID_PANE_KINDS: ReadonlySet<PaneKind> = new Set<PaneKind>([
  "chat",
  "room",
  "jobs_attention",
  "files",
  "browser",
]);

const DEFAULT_PANES: WorkbenchPaneConfig[] = [
  { id: "pane-1", kind: "chat" },
  { id: "pane-2", kind: "chat" },
  { id: "pane-3", kind: "jobs_attention" },
  { id: "pane-4", kind: "files" },
];

const DEFAULT_LAYOUT: StoredWorkbenchPrefs = {
  paneCount: 1,
  layoutMode: "1",
  panes: DEFAULT_PANES,
  customProjects: [],
  projectRenames: {},
  hiddenProjectIds: [],
  hiddenSessionCids: [],
  pinnedSessionCids: [],
  archivedSessionCids: [],
  unreadSessionCids: [],
  sessionRenames: {},
  showArchived: false,
};

function sanitizeShortSlug(raw: unknown, maxLen = 64): string | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.trim();
  if (!s || s.length > maxLen) return undefined;
  if (!/^[A-Za-z0-9._-]+$/.test(s)) return undefined;
  return s;
}

function sanitizeSessionCid(raw: unknown, maxLen = 128): string | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.trim();
  if (!s || s.length > maxLen) return undefined;
  if (!/^[A-Za-z0-9._:-]+$/.test(s)) return undefined;
  return s;
}

function sanitizeCustomProjects(raw: unknown): CustomProjectItem[] {
  if (!Array.isArray(raw)) return [];
  const out: CustomProjectItem[] = [];
  const seenIds = new Set<string>();
  for (const item of raw) {
    if (out.length >= MAX_CUSTOM_PROJECTS) break;
    if (!item || typeof item !== "object") continue;
    const obj = item as Record<string, unknown>;
    const id = sanitizeShortSlug(obj.id, 64);
    if (!id || RESERVED_PROJECT_IDS.has(id) || seenIds.has(id.toLowerCase())) continue;
    if (typeof obj.name !== "string") continue;
    const name = obj.name.trim().slice(0, MAX_PROJECT_NAME_LEN);
    if (!name) continue;
    seenIds.add(id.toLowerCase());
    const createdAt =
      typeof obj.createdAt === "number" && Number.isFinite(obj.createdAt) && obj.createdAt > 0
        ? obj.createdAt
        : undefined;
    out.push({ id, name, ...(createdAt ? { createdAt } : {}) });
  }
  return out;
}

function sanitizeSlugList(raw: unknown, maxItems: number, maxLen = 64): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (out.length >= maxItems) break;
    const cleaned = sanitizeShortSlug(item, maxLen);
    if (!cleaned || seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
  }
  return out;
}

function sanitizeSessionCidList(raw: unknown, maxItems: number): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (out.length >= maxItems) break;
    const cleaned = sanitizeSessionCid(item, 128);
    if (!cleaned || seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
  }
  return out;
}

function sanitizeProjectRenames(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (count >= MAX_PROJECT_RENAMES) break;
    if (FORBIDDEN_RECORD_KEYS.has(k)) continue;
    const cleanKey = sanitizeShortSlug(k, 64);
    if (!cleanKey || typeof v !== "string") continue;
    const cleanVal = v.trim().slice(0, MAX_PROJECT_NAME_LEN);
    if (!cleanVal) continue;
    out[cleanKey] = cleanVal;
    count += 1;
  }
  return out;
}

function sanitizeSessionRenames(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (count >= MAX_SESSION_RENAMES) break;
    if (FORBIDDEN_RECORD_KEYS.has(k)) continue;
    const cleanKey = sanitizeSessionCid(k, 128);
    if (!cleanKey || typeof v !== "string") continue;
    const cleanVal = v.trim().slice(0, MAX_SESSION_TITLE_LEN);
    if (!cleanVal) continue;
    out[cleanKey] = cleanVal;
    count += 1;
  }
  return out;
}

function buildAsciiKebabSlug(name: string): string | undefined {
  const ascii = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/g, "");
  return sanitizeShortSlug(ascii, 64);
}

function generateRandomProjectSlug(takenLowerIds: ReadonlySet<string>): string {
  for (let i = 0; i < 12; i += 1) {
    const rand = Math.random().toString(36).slice(2, 8).padEnd(6, "0");
    const candidate = sanitizeShortSlug(`proj-${rand}`, 64);
    if (candidate && !takenLowerIds.has(candidate.toLowerCase())) {
      return candidate;
    }
  }
  return `proj-${Date.now().toString(36)}`;
}

function loadWorkbenchPrefs(): StoredWorkbenchPrefs {
  try {
    const raw = window.localStorage.getItem(WORKBENCH_STORAGE_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") return DEFAULT_LAYOUT;

    const rawCount = parsed.paneCount;
    const paneCount: 1 | 2 | 3 | 4 =
      rawCount === 2 || rawCount === 3 || rawCount === 4 ? rawCount : 1;
    const layoutMode: "1" | "2" | "3" | "4" = String(paneCount) as "1" | "2" | "3" | "4";

    const rawPanes = Array.isArray(parsed.panes) ? parsed.panes : [];
    const panes: WorkbenchPaneConfig[] = [];
    for (let i = 0; i < 4; i += 1) {
      const item = rawPanes[i] as Record<string, unknown> | undefined;
      const fallback = DEFAULT_PANES[i];
      if (!item || typeof item !== "object") {
        panes.push({ ...fallback });
        continue;
      }
      const rawKind = item.kind;
      const wasLegacyRoom = rawKind === "room";
      const kind: PaneKind = wasLegacyRoom
        ? "chat"
        : typeof rawKind === "string" && VALID_PANE_KINDS.has(rawKind as PaneKind)
          ? (rawKind as PaneKind)
          : fallback.kind;
      const id = `pane-${i + 1}`;
      panes.push({
        id,
        kind,
        bot: sanitizeShortSlug(item.bot, 64) || (wasLegacyRoom ? TEAM_TARGET_ID : undefined),
        project: sanitizeShortSlug(item.project, 64),
        roomId: sanitizeShortSlug(item.roomId, 32) || (kind === "room" ? "lobby" : undefined),
      });
    }
    const customProjects = sanitizeCustomProjects(parsed.customProjects);
    const projectRenames = sanitizeProjectRenames(parsed.projectRenames);
    const hiddenProjectIds = sanitizeSlugList(parsed.hiddenProjectIds, MAX_HIDDEN_PROJECT_IDS, 64);
    const hiddenSessionCids = sanitizeSessionCidList(
      parsed.hiddenSessionCids,
      MAX_HIDDEN_SESSION_CIDS,
    );
    const pinnedSessionCids = sanitizeSessionCidList(
      parsed.pinnedSessionCids,
      MAX_PINNED_SESSION_CIDS,
    );
    const archivedSessionCids = sanitizeSessionCidList(
      parsed.archivedSessionCids,
      MAX_ARCHIVED_SESSION_CIDS,
    );
    const unreadSessionCids = sanitizeSessionCidList(
      parsed.unreadSessionCids,
      MAX_UNREAD_SESSION_CIDS,
    );
    const sessionRenames = sanitizeSessionRenames(parsed.sessionRenames);
    const showArchived = Boolean(parsed.showArchived === true);
    return {
      paneCount,
      layoutMode,
      panes,
      customProjects,
      projectRenames,
      hiddenProjectIds,
      hiddenSessionCids,
      pinnedSessionCids,
      archivedSessionCids,
      unreadSessionCids,
      sessionRenames,
      showArchived,
    };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

function saveWorkbenchPrefs(prefs: StoredWorkbenchPrefs): void {
  try {
    // Strictly persist ONLY non-sensitive layout/workbench metadata (never prompts, messages, tokens, or paths)
    const cleanCustomProjects = sanitizeCustomProjects(prefs.customProjects);
    const cleanProjectRenames = sanitizeProjectRenames(prefs.projectRenames);
    const cleanHiddenProjectIds = sanitizeSlugList(
      prefs.hiddenProjectIds,
      MAX_HIDDEN_PROJECT_IDS,
      64,
    );
    const cleanHiddenSessionCids = sanitizeSessionCidList(
      prefs.hiddenSessionCids,
      MAX_HIDDEN_SESSION_CIDS,
    );
    const cleanPinnedSessionCids = sanitizeSessionCidList(
      prefs.pinnedSessionCids,
      MAX_PINNED_SESSION_CIDS,
    );
    const cleanArchivedSessionCids = sanitizeSessionCidList(
      prefs.archivedSessionCids,
      MAX_ARCHIVED_SESSION_CIDS,
    );
    const cleanUnreadSessionCids = sanitizeSessionCidList(
      prefs.unreadSessionCids,
      MAX_UNREAD_SESSION_CIDS,
    );
    const cleanSessionRenames = sanitizeSessionRenames(prefs.sessionRenames);
    const cleanShowArchived = Boolean(prefs.showArchived);

    const clean: Record<string, unknown> = {
      paneCount: prefs.paneCount,
      layoutMode: prefs.layoutMode,
      panes: prefs.panes.slice(0, 4).map((p, idx) => ({
        id: `pane-${idx + 1}`,
        kind: VALID_PANE_KINDS.has(p.kind) ? p.kind : "chat",
        ...(sanitizeShortSlug(p.bot, 64) ? { bot: sanitizeShortSlug(p.bot, 64) } : {}),
        ...(sanitizeShortSlug(p.project, 64) ? { project: sanitizeShortSlug(p.project, 64) } : {}),
        ...(sanitizeShortSlug(p.roomId, 32) ? { roomId: sanitizeShortSlug(p.roomId, 32) } : {}),
      })),
      ...(cleanCustomProjects.length > 0 ? { customProjects: cleanCustomProjects } : {}),
      ...(Object.keys(cleanProjectRenames).length > 0
        ? { projectRenames: cleanProjectRenames }
        : {}),
      ...(cleanHiddenProjectIds.length > 0 ? { hiddenProjectIds: cleanHiddenProjectIds } : {}),
      ...(cleanHiddenSessionCids.length > 0 ? { hiddenSessionCids: cleanHiddenSessionCids } : {}),
      ...(cleanPinnedSessionCids.length > 0 ? { pinnedSessionCids: cleanPinnedSessionCids } : {}),
      ...(cleanArchivedSessionCids.length > 0
        ? { archivedSessionCids: cleanArchivedSessionCids }
        : {}),
      ...(cleanUnreadSessionCids.length > 0 ? { unreadSessionCids: cleanUnreadSessionCids } : {}),
      ...(Object.keys(cleanSessionRenames).length > 0
        ? { sessionRenames: cleanSessionRenames }
        : {}),
      ...(cleanShowArchived ? { showArchived: true } : {}),
    };
    const serialized = JSON.stringify(clean);
    window.localStorage.setItem(WORKBENCH_STORAGE_KEY, serialized);
  } catch {
    // Ignore storage failures
  }
}

function extractSidebarState(prefs: StoredWorkbenchPrefs): WorkbenchSidebarState {
  return {
    customProjects: sanitizeCustomProjects(prefs.customProjects),
    projectRenames: sanitizeProjectRenames(prefs.projectRenames),
    hiddenProjectIds: sanitizeSlugList(prefs.hiddenProjectIds, MAX_HIDDEN_PROJECT_IDS, 64),
    hiddenSessionCids: sanitizeSessionCidList(prefs.hiddenSessionCids, MAX_HIDDEN_SESSION_CIDS),
    pinnedSessionCids: sanitizeSessionCidList(prefs.pinnedSessionCids, MAX_PINNED_SESSION_CIDS),
    archivedSessionCids: sanitizeSessionCidList(
      prefs.archivedSessionCids,
      MAX_ARCHIVED_SESSION_CIDS,
    ),
    unreadSessionCids: sanitizeSessionCidList(prefs.unreadSessionCids, MAX_UNREAD_SESSION_CIDS),
    sessionRenames: sanitizeSessionRenames(prefs.sessionRenames),
    showArchived: Boolean(prefs.showArchived),
  };
}

function sanitizeSidebarState(raw: unknown): WorkbenchSidebarState {
  const obj = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  return {
    customProjects: sanitizeCustomProjects(obj.customProjects),
    projectRenames: sanitizeProjectRenames(obj.projectRenames),
    hiddenProjectIds: sanitizeSlugList(obj.hiddenProjectIds, MAX_HIDDEN_PROJECT_IDS, 64),
    hiddenSessionCids: sanitizeSessionCidList(obj.hiddenSessionCids, MAX_HIDDEN_SESSION_CIDS),
    pinnedSessionCids: sanitizeSessionCidList(obj.pinnedSessionCids, MAX_PINNED_SESSION_CIDS),
    archivedSessionCids: sanitizeSessionCidList(
      obj.archivedSessionCids,
      MAX_ARCHIVED_SESSION_CIDS,
    ),
    unreadSessionCids: sanitizeSessionCidList(obj.unreadSessionCids, MAX_UNREAD_SESSION_CIDS),
    sessionRenames: sanitizeSessionRenames(obj.sessionRenames),
    showArchived: Boolean(obj.showArchived === true),
  };
}

function hasNonEmptySidebarState(state: WorkbenchSidebarState): boolean {
  return (
    state.customProjects.length > 0 ||
    Object.keys(state.projectRenames).length > 0 ||
    state.hiddenProjectIds.length > 0 ||
    state.hiddenSessionCids.length > 0 ||
    state.pinnedSessionCids.length > 0 ||
    state.archivedSessionCids.length > 0 ||
    state.unreadSessionCids.length > 0 ||
    Object.keys(state.sessionRenames).length > 0 ||
    state.showArchived
  );
}

function mergeSidebarStates(
  remote: WorkbenchSidebarState,
  local: WorkbenchSidebarState,
): WorkbenchSidebarState {
  return {
    customProjects: sanitizeCustomProjects([...local.customProjects, ...remote.customProjects]),
    projectRenames: sanitizeProjectRenames({ ...remote.projectRenames, ...local.projectRenames }),
    hiddenProjectIds: sanitizeSlugList(
      [...local.hiddenProjectIds, ...remote.hiddenProjectIds],
      MAX_HIDDEN_PROJECT_IDS,
      64,
    ),
    hiddenSessionCids: sanitizeSessionCidList(
      [...local.hiddenSessionCids, ...remote.hiddenSessionCids],
      MAX_HIDDEN_SESSION_CIDS,
    ),
    pinnedSessionCids: sanitizeSessionCidList(
      [...local.pinnedSessionCids, ...remote.pinnedSessionCids],
      MAX_PINNED_SESSION_CIDS,
    ),
    archivedSessionCids: sanitizeSessionCidList(
      [...local.archivedSessionCids, ...remote.archivedSessionCids],
      MAX_ARCHIVED_SESSION_CIDS,
    ),
    unreadSessionCids: sanitizeSessionCidList(
      [...local.unreadSessionCids, ...remote.unreadSessionCids],
      MAX_UNREAD_SESSION_CIDS,
    ),
    sessionRenames: sanitizeSessionRenames({ ...remote.sessionRenames, ...local.sessionRenames }),
    showArchived: Boolean(local.showArchived),
  };
}

function persistSidebarStateStandalone(nextState: WorkbenchSidebarState): void {
  const current = loadWorkbenchPrefs();
  saveWorkbenchPrefs({
    ...current,
    customProjects: nextState.customProjects,
    projectRenames: nextState.projectRenames,
    hiddenProjectIds: nextState.hiddenProjectIds,
    hiddenSessionCids: nextState.hiddenSessionCids,
    pinnedSessionCids: nextState.pinnedSessionCids,
    archivedSessionCids: nextState.archivedSessionCids,
    unreadSessionCids: nextState.unreadSessionCids,
    sessionRenames: nextState.sessionRenames,
    showArchived: nextState.showArchived,
  });
}

export interface PendingQuotePayload {
  id: number;
  text: string;
}

export interface ChatPaneProps {
  paneId: string;
  session: StudioSession;
  initialBot?: string;
  initialProject?: string;
  initialCid?: string | null;
  defaultSidebarOpen?: boolean;
  compactHeader?: boolean;
  sessionSyncEvent?: SessionUpdatedEvent | null;
  roomEvent?: RoomLiveEvent | null;
  roomEvents?: RoomLiveEvent[];
  botsEventVer?: number;
  gatewaysEventVer?: number;
  pendingQuote?: PendingQuotePayload | null;
  onQuoteConsumed?: (quoteId: number) => void;
  pendingOpenSession?: PendingOpenSessionPayload | null;
  onOpenSessionConsumed?: (reqId: number) => void;
  onSplitOpenSession?: (item: SessionSummaryItem) => SplitOpenResult;
  onBotChange?: (bot: string) => void;
  onProjectChange?: (projectId: string) => void;
  onActiveCidChange?: (cid: string | null) => void;
  onActiveWorktreeChange?: (worktreeId: string | null) => void;
  onFocusPane?: (paneId: string) => void;
  extraHeaderActions?: ReactNode;
  customProjects?: CustomProjectItem[];
  projectRenames?: Record<string, string>;
  hiddenProjectIds?: string[];
  hiddenSessionCids?: string[];
  pinnedSessionCids?: string[];
  archivedSessionCids?: string[];
  unreadSessionCids?: string[];
  sessionRenames?: Record<string, string>;
  showArchived?: boolean;
  onAddCustomProject?: (project: CustomProjectItem) => void;
  onRenameProject?: (groupId: string, nextName: string | null) => void;
  onRemoveCustomProject?: (projectId: string, sessionCids: string[]) => void;
  onHideProject?: (projectId: string) => void;
  onHideSessions?: (cids: string[]) => void;
  onTogglePinSession?: (cid: string) => void;
  onToggleArchiveSession?: (cid: string) => void;
  onSetSessionUnread?: (cid: string, unread: boolean) => void;
  onRenameSession?: (cid: string, nextTitle: string | null) => void;
  onSetShowArchived?: (show: boolean) => void;
  onSessionRevoked: (reason: string) => void;
}

export function ChatPane({
  paneId,
  session,
  initialBot,
  initialProject,
  initialCid,
  defaultSidebarOpen = true,
  compactHeader = false,
  sessionSyncEvent,
  roomEvent,
  roomEvents,
  botsEventVer = 0,
  gatewaysEventVer = 0,
  pendingQuote,
  onQuoteConsumed,
  pendingOpenSession,
  onOpenSessionConsumed,
  onSplitOpenSession,
  onBotChange,
  onProjectChange,
  onActiveCidChange,
  onActiveWorktreeChange,
  onFocusPane,
  extraHeaderActions,
  customProjects: controlledCustomProjects,
  projectRenames: controlledProjectRenames,
  hiddenProjectIds: controlledHiddenProjectIds,
  hiddenSessionCids: controlledHiddenSessionCids,
  pinnedSessionCids: controlledPinnedSessionCids,
  archivedSessionCids: controlledArchivedSessionCids,
  unreadSessionCids: controlledUnreadSessionCids,
  sessionRenames: controlledSessionRenames,
  showArchived: controlledShowArchived,
  onAddCustomProject,
  onRenameProject,
  onRemoveCustomProject,
  onHideProject,
  onHideSessions,
  onTogglePinSession,
  onToggleArchiveSession,
  onSetSessionUnread,
  onRenameSession,
  onSetShowArchived,
  onSessionRevoked,
}: ChatPaneProps) {
  const isReadonly = session.role !== "admin";
  const { acquire: acquireStreamSlot, release: releaseStreamSlot } = useStreamBudget(paneId);

  const [fallbackSidebarState, setFallbackSidebarState] = useState<WorkbenchSidebarState>(() => {
    const prefs = loadWorkbenchPrefs();
    return {
      customProjects: prefs.customProjects,
      projectRenames: prefs.projectRenames,
      hiddenProjectIds: prefs.hiddenProjectIds,
      hiddenSessionCids: prefs.hiddenSessionCids,
      pinnedSessionCids: prefs.pinnedSessionCids,
      archivedSessionCids: prefs.archivedSessionCids,
      unreadSessionCids: prefs.unreadSessionCids,
      sessionRenames: prefs.sessionRenames,
      showArchived: prefs.showArchived,
    };
  });

  const customProjects = controlledCustomProjects ?? fallbackSidebarState.customProjects;
  const projectRenames = controlledProjectRenames ?? fallbackSidebarState.projectRenames;
  const hiddenProjectIds = controlledHiddenProjectIds ?? fallbackSidebarState.hiddenProjectIds;
  const hiddenSessionCids = controlledHiddenSessionCids ?? fallbackSidebarState.hiddenSessionCids;
  const pinnedSessionCids = controlledPinnedSessionCids ?? fallbackSidebarState.pinnedSessionCids;
  const archivedSessionCids =
    controlledArchivedSessionCids ?? fallbackSidebarState.archivedSessionCids;
  const unreadSessionCids = controlledUnreadSessionCids ?? fallbackSidebarState.unreadSessionCids;
  const sessionRenames = controlledSessionRenames ?? fallbackSidebarState.sessionRenames;
  const showArchived = controlledShowArchived ?? fallbackSidebarState.showArchived;

  const [filterPinnedOnly, setFilterPinnedOnly] = useState(false);
  const [filterUnreadOnly, setFilterUnreadOnly] = useState(false);
  const [openMenu, setOpenMenu] = useState<SidebarOpenMenu | null>(null);
  const [sidebarToast, setSidebarToast] = useState<string | null>(null);
  const [, setRelativeTimeTick] = useState(0);

  const [createProjectModalOpen, setCreateProjectModalOpen] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [newProjectSlug, setNewProjectSlug] = useState("");
  const [createProjectError, setCreateProjectError] = useState<string | null>(null);
  const [renameTarget, setRenameTarget] = useState<RenameModalTarget | null>(null);
  const [renameInputValue, setRenameInputValue] = useState("");
  const [renameError, setRenameError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DeleteConfirmTarget | null>(null);

  const createProjectNameInputRef = useRef<HTMLInputElement | null>(null);
  const renameInputRef = useRef<HTMLInputElement | null>(null);
  const deleteCancelBtnRef = useRef<HTMLButtonElement | null>(null);
  const floatingMenuRef = useRef<HTMLDivElement | null>(null);
  const sidebarToastTimerRef = useRef<number | null>(null);
  const consumedOpenSessionIdRef = useRef<number>(0);
  const initialCidHydratedRef = useRef<boolean>(false);

  const hiddenProjectIdSet = useMemo(() => new Set(hiddenProjectIds), [hiddenProjectIds]);
  const hiddenSessionCidSet = useMemo(() => new Set(hiddenSessionCids), [hiddenSessionCids]);
  const pinnedSessionCidSet = useMemo(() => new Set(pinnedSessionCids), [pinnedSessionCids]);
  const archivedSessionCidSet = useMemo(() => new Set(archivedSessionCids), [archivedSessionCids]);
  const unreadSessionCidSet = useMemo(() => new Set(unreadSessionCids), [unreadSessionCids]);
  const hiddenProjectIdSetRef = useRef(hiddenProjectIdSet);
  hiddenProjectIdSetRef.current = hiddenProjectIdSet;
  const customProjectsRef = useRef(customProjects);
  customProjectsRef.current = customProjects;

  const [sidebarOpen, setSidebarOpen] = useState(defaultSidebarOpen);
  const [sessions, setSessions] = useState<SessionSummaryItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);

  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [selectedBot, setSelectedBot] = useState<string>(initialBot || "");
  const [meta, setMeta] = useState<ModelsResponse | null>(null);
  const [selectedProject, setSelectedProject] = useState<string>(initialProject || "");
  const [selectedProvider, setSelectedProvider] = useState<string>(ALL_PROVIDERS_ID);
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [selectedEffort, setSelectedEffort] = useState<string>("");
  const [botConfigCanEdit, setBotConfigCanEdit] = useState<boolean>(false);
  const [savingBotConfig, setSavingBotConfig] = useState<boolean>(false);
  const [projectExpandOverrides, setProjectExpandOverrides] = useState<Record<string, boolean>>({});
  const [expandedSessionLists, setExpandedSessionLists] = useState<Record<string, boolean>>({});

  const isTeamMode = selectedBot === TEAM_TARGET_ID;
  const isTeamModeRef = useRef<boolean>(isTeamMode);
  isTeamModeRef.current = isTeamMode;
  const selectedBotRef = useRef<string>(selectedBot);
  selectedBotRef.current = selectedBot;
  const [teamRefreshSignal, setTeamRefreshSignal] = useState(0);
  const [teamRoomMeta, setTeamRoomMeta] = useState<RoomMetaSummary>({
    isMirrorMode: false,
    defaultBotHandle: "",
    loading: false,
    topic: "",
    onlineBotCount: 0,
  });
  const handleTeamRoomMetaChange = useCallback((nextMeta: RoomMetaSummary) => {
    setTeamRoomMeta((prev) =>
      prev.isMirrorMode === nextMeta.isMirrorMode &&
      prev.defaultBotHandle === nextMeta.defaultBotHandle &&
      prev.loading === nextMeta.loading &&
      prev.topic === nextMeta.topic &&
      prev.onlineBotCount === nextMeta.onlineBotCount
        ? prev
        : nextMeta,
    );
  }, []);
  const orderedBots = useMemo(
    () => [...bots].sort((a, b) => Number(b.online) - Number(a.online)),
    [bots],
  );
  const onlineCoordinator = useMemo(
    () =>
      bots.find((b) => b.online && b.role === "coordinator") ||
      bots.find((b) => b.role === "coordinator") ||
      null,
    [bots],
  );
  const orderedBotsRef = useRef(orderedBots);
  orderedBotsRef.current = orderedBots;
  const onlineCoordinatorRef = useRef(onlineCoordinator);
  onlineCoordinatorRef.current = onlineCoordinator;
  const preferSingleBotOnRosterLoadRef = useRef<boolean>(false);

  const resolveSingleBotTarget = useCallback((preferredBot?: string | null): string => {
    const candidate = (preferredBot || "").trim();
    if (candidate && candidate !== TEAM_TARGET_ID) {
      return candidate;
    }
    const coord = onlineCoordinatorRef.current?.handle;
    if (coord && coord !== TEAM_TARGET_ID) {
      return coord;
    }
    const firstOnline = orderedBotsRef.current.find(
      (b) => b.online && b.handle && b.handle !== TEAM_TARGET_ID,
    )?.handle;
    if (firstOnline) return firstOnline;
    const firstAny = orderedBotsRef.current.find(
      (b) => b.handle && b.handle !== TEAM_TARGET_ID,
    )?.handle;
    return firstAny || "";
  }, []);
  const effectiveBot = useMemo(() => {
    if (isTeamMode) {
      return (
        onlineCoordinator?.handle ||
        bots.find((b) => b.online)?.handle ||
        bots[0]?.handle ||
        ""
      );
    }
    return selectedBot;
  }, [isTeamMode, onlineCoordinator, bots, selectedBot]);
  const selectedBotObj = useMemo(
    () => (isTeamMode ? null : bots.find((b) => b.handle === selectedBot) || null),
    [isTeamMode, bots, selectedBot],
  );
  const effectiveBotObj = useMemo(
    () => bots.find((b) => b.handle === effectiveBot) || null,
    [bots, effectiveBot],
  );
  const selectedBotDisplayName = selectedBotObj?.display_name || (isTeamMode ? "" : selectedBot);
  const effectiveBotDisplayName = effectiveBotObj?.display_name || effectiveBot;

  const [activeCid, setActiveCid] = useState<string | null>(null);
  const [worktreeEnabled, setWorktreeEnabled] = useState<boolean>(false);
  const [activeWorktree, setActiveWorktree] = useState<SessionWorktreeInfo | null>(null);
  const onActiveWorktreeChangeRef = useRef(onActiveWorktreeChange);
  onActiveWorktreeChangeRef.current = onActiveWorktreeChange;
  const syncActiveWorktree = useCallback((wt: SessionWorktreeInfo | null | undefined) => {
    const clean = wt && wt.active && wt.worktree_id ? wt : null;
    setActiveWorktree(clean);
    onActiveWorktreeChangeRef.current?.(clean?.worktree_id || null);
  }, []);
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hasMoreHistory, setHasMoreHistory] = useState(false);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [expandedThinking, setExpandedThinking] = useState<Record<string, boolean>>({});

  const [draft, setDraft] = useState("");
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [interrupting, setInterrupting] = useState(false);
  const [pendingQueue, setPendingQueue] = useState<
    {
      id: string;
      prompt: string;
      displayText: string;
      attachments: ChatAttachmentItem[];
      attachmentIds: string[];
      contextFiles: string[];
      createdAt: number;
    }[]
  >([]);
  const [streamDegraded, setStreamDegraded] = useState(false);
  const [remoteSyncSource, setRemoteSyncSource] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [resyncNeeded, setResyncNeeded] = useState(false);

  const mountedRef = useRef(true);
  const esRef = useRef<EventSource | null>(null);
  const timelineEndRef = useRef<HTMLDivElement | null>(null);
  const activeAssistantIdRef = useRef<string | null>(null);
  const genRef = useRef<number>(0);
  const activeCidRef = useRef<string | null>(null);
  const effectiveBotRef = useRef<string>(effectiveBot);
  effectiveBotRef.current = effectiveBot;
  const selectedModelRef = useRef<string>(selectedModel);
  selectedModelRef.current = selectedModel;
  const selectedEffortRef = useRef<string>(selectedEffort);
  selectedEffortRef.current = selectedEffort;
  const selectedProviderRef = useRef<string>(selectedProvider);
  selectedProviderRef.current = selectedProvider;
  const userChoseAllProvidersRef = useRef<boolean>(false);
  const prevLoadedBotRef = useRef<string>("");
  const botConfigPatchSeqRef = useRef<number>(0);
  const lastAutoExpandedCidRef = useRef<string | null>(null);
  const streamingRef = useRef<boolean>(false);
  const interruptingRef = useRef<boolean>(false);
  const pendingQueueRef = useRef(pendingQueue);
  pendingQueueRef.current = pendingQueue;
  const drainNextQueuedTurnRef = useRef<() => void>(() => {});
  const streamingSourceRef = useRef<"local" | "remote" | null>(null);
  const activeTurnIdRef = useRef<string | null>(null);
  const attachInFlightRef = useRef<string | null>(null);
  const lastSyncVerRef = useRef<number>(0);
  const historyLoadSeqRef = useRef<number>(0);
  const sessionsSeqRef = useRef<number>(0);
  const modelsSeqRef = useRef<number>(0);
  const botsSeqRef = useRef<number>(0);
  const consumedQuoteIdRef = useRef<number>(0);
  const degradePollRef = useRef<number | null>(null);
  const onBotChangeRef = useRef(onBotChange);
  onBotChangeRef.current = onBotChange;
  const onProjectChangeRef = useRef(onProjectChange);
  onProjectChangeRef.current = onProjectChange;
  const onQuoteConsumedRef = useRef(onQuoteConsumed);
  onQuoteConsumedRef.current = onQuoteConsumed;

  const setActiveCidSynced = useCallback(
    (cid: string | null) => {
      activeCidRef.current = cid;
      setActiveCid(cid);
      onActiveCidChange?.(cid);
    },
    [onActiveCidChange],
  );

  useEffect(() => {
    if (initialProject !== undefined && initialProject !== selectedProject && !streamingRef.current) {
      setSelectedProject(initialProject);
    }
  }, [initialProject, selectedProject]);

  const handleTeamQuoteConsumed = useCallback((quoteId: number) => {
    consumedQuoteIdRef.current = Math.max(consumedQuoteIdRef.current, quoteId);
    onQuoteConsumedRef.current?.(quoteId);
  }, []);

  useEffect(() => {
    if (isTeamMode || isReadonly || !pendingQuote || pendingQuote.id === consumedQuoteIdRef.current) {
      return;
    }
    consumedQuoteIdRef.current = pendingQuote.id;
    const snippet = pendingQuote.text;
    if (snippet) {
      setDraft((prev) => (prev.trim() ? `${prev}\n\n${snippet}` : snippet));
    }
    onQuoteConsumedRef.current?.(pendingQuote.id);
  }, [isTeamMode, isReadonly, pendingQuote]);

  const stopDegradePoll = useCallback(() => {
    if (degradePollRef.current !== null) {
      window.clearInterval(degradePollRef.current);
      degradePollRef.current = null;
    }
  }, []);

  const closeEventSource = useCallback(() => {
    stopDegradePoll();
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    releaseStreamSlot();
  }, [stopDegradePoll, releaseStreamSlot]);

  const closeEventSourceRef = useRef(closeEventSource);
  closeEventSourceRef.current = closeEventSource;

  const resetStreamState = useCallback(() => {
    closeEventSource();
    streamingRef.current = false;
    streamingSourceRef.current = null;
    activeTurnIdRef.current = null;
    if (mountedRef.current) {
      setStreaming(false);
      setStreamDegraded(false);
      setActiveTurnId(null);
      setRemoteSyncSource(null);
    }
  }, [closeEventSource]);

  const clearPendingQueue = useCallback(() => {
    pendingQueueRef.current = [];
    setPendingQueue([]);
  }, []);

  useEffect(() => {
    if (!isTeamMode) return;
    genRef.current += 1;
    attachInFlightRef.current = null;
    clearPendingQueue();
    resetStreamState();
  }, [isTeamMode, clearPendingQueue, resetStreamState]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      closeEventSourceRef.current();
    };
  }, []);

  useEffect(() => {
    const activePaneId = paneId;
    return () => {
      stopDegradePoll();
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      releaseStreamSlotById(activePaneId);
    };
  }, [paneId, stopDegradePoll]);

  const handleApiAuthError = useCallback(
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

  useEffect(() => {
    const seq = ++botsSeqRef.current;
    void fetchBots()
      .then((res) => {
        if (!mountedRef.current || botsSeqRef.current !== seq) return;
        const roster = res.bots || [];
        setBots(roster);
        setSelectedBot((cur) => {
          if (cur && !(preferSingleBotOnRosterLoadRef.current && cur === TEAM_TARGET_ID)) {
            return cur;
          }
          const onlineCoord = roster.find((b) => b.online && b.role === "coordinator");
          const fallbackSingle =
            onlineCoord?.handle ||
            roster.find((b) => b.role === "coordinator")?.handle ||
            roster.find((b) => b.online)?.handle ||
            roster[0]?.handle ||
            "";
          const pick = preferSingleBotOnRosterLoadRef.current
            ? fallbackSingle
            : onlineCoord
              ? TEAM_TARGET_ID
              : fallbackSingle;
          preferSingleBotOnRosterLoadRef.current = false;
          if (pick) onBotChangeRef.current?.(pick);
          return pick;
        });
      })
      .catch((err) => {
        if (mountedRef.current && botsSeqRef.current === seq) {
          handleApiAuthError(err);
        }
      });
  }, [botsEventVer, gatewaysEventVer, handleApiAuthError]);

  useEffect(() => {
    const seq = ++modelsSeqRef.current;
    const reqBot = effectiveBot && effectiveBot !== TEAM_TARGET_ID ? effectiveBot : "";
    const botSwitched = prevLoadedBotRef.current !== reqBot;
    if (botSwitched) {
      prevLoadedBotRef.current = reqBot;
      userChoseAllProvidersRef.current = false;
      botConfigPatchSeqRef.current += 1;
      setSavingBotConfig(false);
    }

    const modelsPromise = fetchModels(reqBot || undefined);
    const configPromise = reqBot ? fetchBotConfig(reqBot) : Promise.resolve(null);

    void Promise.allSettled([modelsPromise, configPromise]).then(([modelsSettled, cfgSettled]) => {
      if (!mountedRef.current || modelsSeqRef.current !== seq || effectiveBotRef.current !== reqBot) {
        return;
      }

      if (modelsSettled.status === "rejected" && cfgSettled.status === "rejected") {
        handleApiAuthError(modelsSettled.reason);
        handleApiAuthError(cfgSettled.reason);
        setBotConfigCanEdit(false);
        return;
      }
      if (modelsSettled.status === "rejected") {
        handleApiAuthError(modelsSettled.reason);
      }
      if (cfgSettled.status === "rejected") {
        handleApiAuthError(cfgSettled.reason);
      }

      const modelsRes = modelsSettled.status === "fulfilled" ? modelsSettled.value : null;
      const cfgRes = cfgSettled.status === "fulfilled" ? cfgSettled.value : null;

      const mergedModels =
        cfgRes && cfgRes.models.length > 0 ? cfgRes.models : modelsRes?.models || [];
      const mergedEfforts =
        cfgRes && cfgRes.efforts.length > 0
          ? cfgRes.efforts
          : modelsRes?.efforts || ["low", "medium", "high", "xhigh", "max"];
      const mergedProjects =
        modelsRes && modelsRes.projects.length > 0 ? modelsRes.projects : cfgRes?.projects || [];

      const rawServerModel =
        (cfgRes?.effective_model && cfgRes.effective_model !== "default"
          ? cfgRes.effective_model
          : "") ||
        (modelsRes?.effective_model && modelsRes.effective_model !== "default"
          ? modelsRes.effective_model
          : "") ||
        (modelsRes?.active_model && modelsRes.active_model !== "default"
          ? modelsRes.active_model
          : "");
      const serverEffort = (cfgRes?.default_effort ?? modelsRes?.default_effort ?? "")
        .trim()
        .toLowerCase();
      const serverDefaultProject =
        modelsRes?.default_project || cfgRes?.default_project || "";
      const ipcOnline = Boolean(cfgRes ? cfgRes.ipc_online : modelsRes?.ipc_online);

      setMeta({
        ok: true,
        bot: cfgRes?.handle || modelsRes?.bot || reqBot,
        active_model: rawServerModel,
        effective_model: rawServerModel,
        model_mode: cfgRes?.model_mode || modelsRes?.model_mode,
        default_effort: serverEffort,
        default_project: serverDefaultProject,
        efforts: mergedEfforts,
        models: mergedModels,
        projects: mergedProjects,
        ipc_online: ipcOnline,
      });

      setBotConfigCanEdit(!isReadonly && Boolean(reqBot) && (cfgRes ? cfgRes.can_edit : ipcOnline));

      // Authoritative passive echo from server (C8): ALWAYS sync top bar to target Bot's server
      // effective_model & default_effort without triggering any reverse PATCH writeback loop.
      setSelectedModel(rawServerModel);
      setSelectedEffort(serverEffort);

      const parsed = mergedModels.map(parseModelOption);
      if (!userChoseAllProvidersRef.current) {
        const matched = parsed.find((m) => m.id === rawServerModel);
        setSelectedProvider(matched ? matched.provider : ALL_PROVIDERS_ID);
      }

      setSelectedProject((cur) => {
        const hiddenSet = hiddenProjectIdSetRef.current;
        if (cur && !hiddenSet.has(cur)) return cur;
        const visibleBackendProjects = mergedProjects.filter(
          (p) =>
            p.id &&
            !hiddenSet.has(p.id) &&
            !isTempProjectName((p.name || p.id).trim()) &&
            !isTempProjectName(p.id),
        );
        const candidate =
          (serverDefaultProject && !hiddenSet.has(serverDefaultProject)
            ? serverDefaultProject
            : "") ||
          visibleBackendProjects[0]?.id ||
          customProjectsRef.current[0]?.id ||
          "";
        if (candidate !== cur) {
          onProjectChangeRef.current?.(candidate);
        }
        return candidate;
      });
    });
  }, [effectiveBot, botsEventVer, gatewaysEventVer, isReadonly, handleApiAuthError]);

  const parsedModels = useMemo<ParsedModelOption[]>(
    () => (meta?.models || []).map(parseModelOption),
    [meta?.models],
  );

  const providerOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const m of parsedModels) {
      counts.set(m.provider, (counts.get(m.provider) || 0) + 1);
    }
    const list: { id: string; label: string; count: number }[] = [];
    if (counts.has(NATIVE_PROVIDER_ID)) {
      list.push({
        id: NATIVE_PROVIDER_ID,
        label: formatProviderLabel(NATIVE_PROVIDER_ID),
        count: counts.get(NATIVE_PROVIDER_ID) || 0,
      });
    }
    for (const [id, count] of counts.entries()) {
      if (id === NATIVE_PROVIDER_ID) continue;
      list.push({ id, label: formatProviderLabel(id), count });
    }
    return list;
  }, [parsedModels]);

  const effectiveProvider = useMemo(() => {
    if (selectedProvider === ALL_PROVIDERS_ID) return ALL_PROVIDERS_ID;
    if (providerOptions.some((p) => p.id === selectedProvider)) return selectedProvider;
    return ALL_PROVIDERS_ID;
  }, [selectedProvider, providerOptions]);

  const filteredModels = useMemo(() => {
    if (effectiveProvider === ALL_PROVIDERS_ID) return parsedModels;
    return parsedModels.filter((m) => m.provider === effectiveProvider);
  }, [parsedModels, effectiveProvider]);

  const persistBotConfigPatch = useCallback(
    (
      targetBot: string,
      patch: { model_mode?: "default" | "follow" | "custom"; model?: string; default_effort?: string },
      rollback: { model: string; effort: string; provider: string },
    ) => {
      if (isReadonly || !targetBot || isTeamModeRef.current) return;
      const patchSeq = ++botConfigPatchSeqRef.current;
      // Supersede any older in-flight GET so stale config snapshots cannot overwrite this user change
      modelsSeqRef.current += 1;
      setSavingBotConfig(true);
      setErrorBanner(null);

      void updateBotConfig(targetBot, patch)
        .then((res) => {
          if (
            !mountedRef.current ||
            botConfigPatchSeqRef.current !== patchSeq ||
            effectiveBotRef.current !== targetBot
          ) {
            return;
          }
          const canonicalModel =
            res.effective_model && res.effective_model !== "default" ? res.effective_model : "";
          const canonicalEffort = (res.default_effort || "").trim().toLowerCase();
          setSelectedModel(canonicalModel);
          setSelectedEffort(canonicalEffort);
          setBotConfigCanEdit(Boolean(res.can_edit));
          setMeta((prev) =>
            prev
              ? {
                  ...prev,
                  active_model: canonicalModel,
                  effective_model: canonicalModel,
                  model_mode: res.model_mode,
                  default_effort: canonicalEffort,
                  efforts: res.efforts.length > 0 ? res.efforts : prev.efforts,
                  models: res.models.length > 0 ? res.models : prev.models,
                  ipc_online: res.ipc_online,
                }
              : prev,
          );
          if (!userChoseAllProvidersRef.current) {
            const parsed = (res.models || []).map(parseModelOption);
            const matched = parsed.find((m) => m.id === canonicalModel);
            setSelectedProvider(matched ? matched.provider : ALL_PROVIDERS_ID);
          }
          setStatusNotice("已同步写入 TG 默认模型/思考强度配置");
        })
        .catch((err) => {
          if (
            !mountedRef.current ||
            botConfigPatchSeqRef.current !== patchSeq ||
            effectiveBotRef.current !== targetBot
          ) {
            return;
          }
          setSelectedModel(rollback.model);
          setSelectedEffort(rollback.effort);
          setSelectedProvider(rollback.provider);
          if (!handleApiAuthError(err)) {
            setErrorBanner(err instanceof Error ? err.message : "同步 Bot 默认配置失败");
          }
        })
        .finally(() => {
          if (mountedRef.current && botConfigPatchSeqRef.current === patchSeq) {
            setSavingBotConfig(false);
          }
        });
    },
    [handleApiAuthError, isReadonly],
  );

  const handleModelChange = useCallback(
    (nextModel: string) => {
      if (isReadonly) return;
      const targetBot = effectiveBotRef.current;
      if (!targetBot || targetBot === TEAM_TARGET_ID) return;
      const rollback = {
        model: selectedModelRef.current,
        effort: selectedEffortRef.current,
        provider: selectedProviderRef.current,
      };
      setSelectedModel(nextModel);
      const patch = nextModel
        ? { model_mode: "custom" as const, model: nextModel }
        : { model_mode: "default" as const };
      persistBotConfigPatch(targetBot, patch, rollback);
    },
    [isReadonly, persistBotConfigPatch],
  );

  const handleEffortChange = useCallback(
    (nextEffort: string) => {
      if (isReadonly) return;
      const targetBot = effectiveBotRef.current;
      if (!targetBot || targetBot === TEAM_TARGET_ID) return;
      const rollback = {
        model: selectedModelRef.current,
        effort: selectedEffortRef.current,
        provider: selectedProviderRef.current,
      };
      setSelectedEffort(nextEffort);
      persistBotConfigPatch(targetBot, { default_effort: nextEffort }, rollback);
    },
    [isReadonly, persistBotConfigPatch],
  );

  const handleProviderChange = (nextProvider: string) => {
    if (isReadonly) return;
    userChoseAllProvidersRef.current = nextProvider === ALL_PROVIDERS_ID;
    const prevProvider = selectedProviderRef.current;
    setSelectedProvider(nextProvider);
    if (nextProvider === ALL_PROVIDERS_ID) return;
    const candidates = parsedModels.filter((m) => m.provider === nextProvider);
    if (candidates.length === 0) return;
    if (!candidates.some((m) => m.id === selectedModel)) {
      const targetBot = effectiveBotRef.current;
      if (!targetBot || targetBot === TEAM_TARGET_ID) return;
      const rollback = {
        model: selectedModelRef.current,
        effort: selectedEffortRef.current,
        provider: prevProvider,
      };
      const nextModel = candidates[0].id;
      setSelectedModel(nextModel);
      persistBotConfigPatch(targetBot, { model_mode: "custom", model: nextModel }, rollback);
    }
  };

  const loadSessions = useCallback(async () => {
    const seq = ++sessionsSeqRef.current;
    setSessionsLoading(true);
    try {
      const res = await fetchSessions({
        limit: 100,
      });
      if (!mountedRef.current || sessionsSeqRef.current !== seq) return;
      setSessions(res.sessions || []);
    } catch (err) {
      if (!mountedRef.current || sessionsSeqRef.current !== seq) return;
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "加载会话列表失败");
      }
    } finally {
      if (mountedRef.current && sessionsSeqRef.current === seq) {
        setSessionsLoading(false);
      }
    }
  }, [handleApiAuthError]);

  useEffect(() => {
    void loadSessions();
  }, [loadSessions]);

  const backendProjectIdSet = useMemo(() => {
    const ids = new Set<string>();
    for (const p of meta?.projects || []) {
      if (p.id) ids.add(p.id);
    }
    return ids;
  }, [meta?.projects]);

  const resolvedBackendProject = useMemo(() => {
    const isLocalOnly = Boolean(
      selectedProject &&
        customProjects.some((p) => p.id === selectedProject) &&
        !backendProjectIdSet.has(selectedProject),
    );
    if (isLocalOnly) {
      return meta?.default_project || meta?.projects?.[0]?.id || undefined;
    }
    return selectedProject || meta?.default_project || meta?.projects?.[0]?.id || undefined;
  }, [selectedProject, customProjects, backendProjectIdSet, meta?.default_project, meta?.projects]);

  const composerAtts = useAttachmentComposer({
    disabled: isReadonly || interrupting,
    onAuthError: handleApiAuthError,
  });
  const composerFileInputRef = useRef<HTMLInputElement | null>(null);
  const composerTextareaRef = useRef<HTMLTextAreaElement | null>(null);
  const [lightboxImage, setLightboxImage] = useState<{ src: string; name: string } | null>(null);
  const [filePickerMode, setFilePickerMode] = useState<null | "inline" | "button">(null);
  const [filePickerQuery, setFilePickerQuery] = useState("");
  const [filePickerTriggerStart, setFilePickerTriggerStart] = useState<number>(-1);
  const [filePickerActiveIdx, setFilePickerActiveIdx] = useState(0);
  const filePickerVisibleRef = useRef<string[]>([]);

  const prevBackendProjectRef = useRef<string | undefined>(resolvedBackendProject);
  useEffect(() => {
    if (
      prevBackendProjectRef.current &&
      resolvedBackendProject &&
      prevBackendProjectRef.current !== resolvedBackendProject
    ) {
      composerAtts.contextFiles.forEach((p) => composerAtts.removeContextFile(p));
      setFilePickerMode(null);
    }
    prevBackendProjectRef.current = resolvedBackendProject;
  }, [resolvedBackendProject, composerAtts.contextFiles, composerAtts.removeContextFile]);

  const syncInlineAtTrigger = useCallback(
    (value: string, caretPos: number) => {
      if (isReadonly || interrupting || !resolvedBackendProject) {
        if (filePickerMode === "inline") setFilePickerMode(null);
        return;
      }
      const before = value.slice(0, caretPos);
      const match = /(?:^|[\s([{"'])@([^\s@]*)$/.exec(before);
      if (match) {
        const q = match[1] || "";
        const atIdx = before.length - q.length - 1;
        setFilePickerMode("inline");
        setFilePickerQuery(q);
        setFilePickerTriggerStart(atIdx);
        setFilePickerActiveIdx(0);
      } else if (filePickerMode === "inline") {
        setFilePickerMode(null);
        setFilePickerQuery("");
        setFilePickerTriggerStart(-1);
      }
    },
    [filePickerMode, interrupting, isReadonly, resolvedBackendProject],
  );

  const handleSelectWorkspaceFile = useCallback(
    (relPath: string) => {
      composerAtts.addContextFile(relPath);
      if (filePickerMode === "inline" && filePickerTriggerStart >= 0) {
        const ta = composerTextareaRef.current;
        const caret = ta ? ta.selectionStart : draft.length;
        const start = Math.min(filePickerTriggerStart, draft.length);
        const end = Math.max(start, Math.min(caret, draft.length));
        const nextDraft = (draft.slice(0, start) + draft.slice(end)).replace(/\s{2,}$/, " ");
        setDraft(nextDraft);
        window.setTimeout(() => {
          const el = composerTextareaRef.current;
          if (el) {
            el.focus();
            const pos = Math.min(start, nextDraft.length);
            el.setSelectionRange(pos, pos);
          }
        }, 10);
      } else {
        window.setTimeout(() => composerTextareaRef.current?.focus(), 10);
      }
      setFilePickerMode(null);
      setFilePickerQuery("");
      setFilePickerTriggerStart(-1);
      setFilePickerActiveIdx(0);
    },
    [composerAtts, draft, filePickerMode, filePickerTriggerStart],
  );

  const archivedVisibleCount = useMemo(() => {
    let count = 0;
    for (const item of sessions) {
      if (hiddenSessionCidSet.has(item.cid)) continue;
      if (!archivedSessionCidSet.has(item.cid)) continue;
      const pid = (item.project_id || "").trim();
      if (pid && hiddenProjectIdSet.has(pid) && !customProjects.some((cp) => cp.id === pid)) {
        continue;
      }
      count += 1;
    }
    return count;
  }, [sessions, hiddenSessionCidSet, archivedSessionCidSet, hiddenProjectIdSet, customProjects]);

  const hasNarrowFilter = filterPinnedOnly || filterUnreadOnly;
  const hasAnyFilterActive = showArchived || hasNarrowFilter;

  const projectGroups = useMemo<ProjectSessionGroup[]>(() => {
    const formalBuckets = new Map<
      string,
      { rawName: string; sessions: SessionSummaryItem[]; isCustom: boolean; isLocalOnly: boolean }
    >();
    const tempProjectIds = new Set<string>();

    for (const p of meta?.projects || []) {
      if (!p.id) continue;
      const pname = (p.name || p.id).trim();
      if (isTempProjectName(pname) || isTempProjectName(p.id)) {
        tempProjectIds.add(p.id);
        continue;
      }
      if (hiddenProjectIdSet.has(p.id)) {
        continue;
      }
      if (!formalBuckets.has(p.id)) {
        formalBuckets.set(p.id, {
          rawName: pname,
          sessions: [],
          isCustom: false,
          isLocalOnly: false,
        });
      }
    }

    for (const cp of customProjects) {
      if (!cp.id || formalBuckets.has(cp.id)) continue;
      formalBuckets.set(cp.id, {
        rawName: cp.name,
        sessions: [],
        isCustom: true,
        isLocalOnly: !backendProjectIdSet.has(cp.id),
      });
    }

    const tempSessions: SessionSummaryItem[] = [];
    const unassignedSessions: SessionSummaryItem[] = [];

    for (const item of sessions) {
      if (hiddenSessionCidSet.has(item.cid)) continue;
      if (!showArchived && archivedSessionCidSet.has(item.cid)) continue;
      if (filterPinnedOnly && !pinnedSessionCidSet.has(item.cid)) continue;
      if (filterUnreadOnly && !unreadSessionCidSet.has(item.cid)) continue;

      const pid = (item.project_id || "").trim();
      if (pid && hiddenProjectIdSet.has(pid) && !formalBuckets.has(pid)) {
        continue;
      }
      if (pid && formalBuckets.has(pid)) {
        formalBuckets.get(pid)!.sessions.push(item);
      } else if (pid && (tempProjectIds.has(pid) || isTempProjectName(pid))) {
        tempSessions.push(item);
      } else {
        unassignedSessions.push(item);
      }
    }

    const sortSessions = (arr: SessionSummaryItem[]) =>
      [...arr].sort((a, b) => {
        const aPinned = pinnedSessionCidSet.has(a.cid) ? 0 : 1;
        const bPinned = pinnedSessionCidSet.has(b.cid) ? 0 : 1;
        if (aPinned !== bPinned) return aPinned - bPinned;
        return (b.updated_at || "").localeCompare(a.updated_at || "");
      });

    const groups: ProjectSessionGroup[] = [];
    for (const [pid, bucket] of formalBuckets.entries()) {
      const sorted = sortSessions(bucket.sessions);
      if (hasNarrowFilter && sorted.length === 0) continue;
      const displayName = projectRenames[pid] || bucket.rawName;
      groups.push({
        id: pid,
        name: displayName,
        rawName: bucket.rawName,
        kind: "formal",
        projectId: pid,
        sessions: sorted,
        latestUpdatedAt: sorted[0]?.updated_at || "",
        hasActiveSession: Boolean(!isTeamMode && activeCid && sorted.some((s) => s.cid === activeCid)),
        isSelectedProject: selectedProject === pid,
        isCustom: bucket.isCustom,
        isLocalOnly: bucket.isLocalOnly,
      });
    }

    groups.sort((a, b) => {
      if (a.latestUpdatedAt !== b.latestUpdatedAt) {
        return b.latestUpdatedAt.localeCompare(a.latestUpdatedAt);
      }
      return a.name.localeCompare(b.name);
    });

    if (tempSessions.length > 0) {
      const sortedTemp = sortSessions(tempSessions);
      const rawTempName = "其他 / 临时项目";
      groups.push({
        id: TEMP_PROJECT_GROUP_ID,
        name: projectRenames[TEMP_PROJECT_GROUP_ID] || rawTempName,
        rawName: rawTempName,
        kind: "temp",
        projectId: null,
        sessions: sortedTemp,
        latestUpdatedAt: sortedTemp[0]?.updated_at || "",
        hasActiveSession: Boolean(
          !isTeamMode && activeCid && sortedTemp.some((s) => s.cid === activeCid),
        ),
        isSelectedProject: false,
      });
    }

    if (unassignedSessions.length > 0) {
      const sortedUnassigned = sortSessions(unassignedSessions);
      const rawUnassignedName = "未归类对话";
      groups.push({
        id: UNASSIGNED_PROJECT_GROUP_ID,
        name: projectRenames[UNASSIGNED_PROJECT_GROUP_ID] || rawUnassignedName,
        rawName: rawUnassignedName,
        kind: "unassigned",
        projectId: null,
        sessions: sortedUnassigned,
        latestUpdatedAt: sortedUnassigned[0]?.updated_at || "",
        hasActiveSession: Boolean(
          !isTeamMode && activeCid && sortedUnassigned.some((s) => s.cid === activeCid),
        ),
        isSelectedProject: false,
      });
    }

    return groups;
  }, [
    meta?.projects,
    backendProjectIdSet,
    customProjects,
    projectRenames,
    hiddenProjectIdSet,
    hiddenSessionCidSet,
    pinnedSessionCidSet,
    archivedSessionCidSet,
    unreadSessionCidSet,
    showArchived,
    filterPinnedOnly,
    filterUnreadOnly,
    hasNarrowFilter,
    sessions,
    activeCid,
    selectedProject,
    isTeamMode,
  ]);

  const defaultExpandedProjectIds = useMemo(() => {
    const expanded = new Set<string>();
    let formalWithSessionsCount = 0;
    for (const g of projectGroups) {
      if (g.hasActiveSession || hasNarrowFilter) {
        expanded.add(g.id);
      }
      if (g.kind === "formal") {
        if (g.isSelectedProject) {
          expanded.add(g.id);
        }
        if (g.sessions.length > 0 && formalWithSessionsCount < 2) {
          expanded.add(g.id);
          formalWithSessionsCount += 1;
        }
      }
    }
    return expanded;
  }, [projectGroups, hasNarrowFilter]);

  useEffect(() => {
    if (isTeamMode || !activeCid || lastAutoExpandedCidRef.current === activeCid) return;
    for (const g of projectGroups) {
      const idx = g.sessions.findIndex((s) => s.cid === activeCid);
      if (idx >= 0) {
        lastAutoExpandedCidRef.current = activeCid;
        setProjectExpandOverrides((prev) =>
          prev[g.id] === false ? { ...prev, [g.id]: true } : prev,
        );
        if (idx >= DEFAULT_VISIBLE_SESSIONS_PER_PROJECT) {
          setExpandedSessionLists((prev) => (prev[g.id] ? prev : { ...prev, [g.id]: true }));
        }
        break;
      }
    }
  }, [isTeamMode, activeCid, projectGroups]);

  const isGroupExpanded = useCallback(
    (groupId: string): boolean => {
      const override = projectExpandOverrides[groupId];
      if (override !== undefined) return override;
      return defaultExpandedProjectIds.has(groupId);
    },
    [projectExpandOverrides, defaultExpandedProjectIds],
  );

  const showSidebarToast = useCallback((msg: string) => {
    if (sidebarToastTimerRef.current !== null) {
      window.clearTimeout(sidebarToastTimerRef.current);
      sidebarToastTimerRef.current = null;
    }
    setSidebarToast(msg);
    sidebarToastTimerRef.current = window.setTimeout(() => {
      sidebarToastTimerRef.current = null;
      if (mountedRef.current) {
        setSidebarToast(null);
      }
    }, 2400);
  }, []);

  useEffect(() => {
    return () => {
      if (sidebarToastTimerRef.current !== null) {
        window.clearTimeout(sidebarToastTimerRef.current);
        sidebarToastTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (mountedRef.current) {
        setRelativeTimeTick((v) => (v + 1) % 100000);
      }
    }, 60000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!createProjectModalOpen) return;
    const raf = window.requestAnimationFrame(() => {
      createProjectNameInputRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(raf);
  }, [createProjectModalOpen]);

  useEffect(() => {
    if (!renameTarget) return;
    const raf = window.requestAnimationFrame(() => {
      renameInputRef.current?.focus();
      renameInputRef.current?.select();
    });
    return () => window.cancelAnimationFrame(raf);
  }, [renameTarget]);

  useEffect(() => {
    if (!deleteTarget) return;
    const raf = window.requestAnimationFrame(() => {
      deleteCancelBtnRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(raf);
  }, [deleteTarget]);

  useEffect(() => {
    if (!createProjectModalOpen && !renameTarget && !deleteTarget && !openMenu) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        if (deleteTarget) {
          setDeleteTarget(null);
        } else if (renameTarget) {
          setRenameTarget(null);
        } else if (createProjectModalOpen) {
          setCreateProjectModalOpen(false);
        } else if (openMenu) {
          setOpenMenu(null);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [createProjectModalOpen, renameTarget, deleteTarget, openMenu]);

  useEffect(() => {
    if (!openMenu) return;
    const onMouseDown = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (floatingMenuRef.current && target && floatingMenuRef.current.contains(target)) {
        return;
      }
      if (target?.closest("[data-sidebar-menu-trigger='true']")) {
        return;
      }
      setOpenMenu(null);
    };
    const onResize = () => setOpenMenu(null);
    document.addEventListener("mousedown", onMouseDown);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("resize", onResize);
    };
  }, [openMenu]);

  useLayoutEffect(() => {
    if (!openMenu || !floatingMenuRef.current) return;
    const rect = floatingMenuRef.current.getBoundingClientRect();
    const pad = 8;
    let nextTop = openMenu.top;
    let nextLeft = openMenu.left;
    if (rect.bottom > window.innerHeight - pad) {
      nextTop = Math.max(pad, window.innerHeight - rect.height - pad);
    }
    if (rect.right > window.innerWidth - pad) {
      nextLeft = Math.max(pad, window.innerWidth - rect.width - pad);
    }
    if (nextTop !== openMenu.top || nextLeft !== openMenu.left) {
      setOpenMenu((cur) => (cur ? { ...cur, top: nextTop, left: nextLeft } : null));
    }
  }, [openMenu]);

  const applyAddCustomProject = useCallback(
    (project: CustomProjectItem) => {
      if (onAddCustomProject) {
        onAddCustomProject(project);
        return;
      }
      setFallbackSidebarState((prev) => {
        const nextCustom = sanitizeCustomProjects([project, ...prev.customProjects]);
        const next: WorkbenchSidebarState = { ...prev, customProjects: nextCustom };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onAddCustomProject],
  );

  const applyRenameProject = useCallback(
    (groupId: string, nextName: string | null) => {
      if (onRenameProject) {
        onRenameProject(groupId, nextName);
        return;
      }
      setFallbackSidebarState((prev) => {
        const nextMap = { ...prev.projectRenames };
        if (!nextName) {
          delete nextMap[groupId];
        } else {
          nextMap[groupId] = nextName;
        }
        const next: WorkbenchSidebarState = {
          ...prev,
          projectRenames: sanitizeProjectRenames(nextMap),
        };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onRenameProject],
  );

  const applyRemoveCustomProject = useCallback(
    (projectId: string, sessionCids: string[]) => {
      if (onRemoveCustomProject) {
        onRemoveCustomProject(projectId, sessionCids);
        return;
      }
      setFallbackSidebarState((prev) => {
        const removedSet = new Set(sessionCids);
        const nextCustom = prev.customProjects.filter((p) => p.id !== projectId);
        const nextProjectRenames = { ...prev.projectRenames };
        delete nextProjectRenames[projectId];
        const nextSessionRenames = { ...prev.sessionRenames };
        for (const cid of sessionCids) delete nextSessionRenames[cid];
        const nextHiddenCids = sanitizeSessionCidList(
          [...sessionCids, ...prev.hiddenSessionCids],
          MAX_HIDDEN_SESSION_CIDS,
        );
        const next: WorkbenchSidebarState = {
          ...prev,
          customProjects: nextCustom,
          projectRenames: sanitizeProjectRenames(nextProjectRenames),
          hiddenSessionCids: nextHiddenCids,
          pinnedSessionCids: prev.pinnedSessionCids.filter((c) => !removedSet.has(c)),
          archivedSessionCids: prev.archivedSessionCids.filter((c) => !removedSet.has(c)),
          unreadSessionCids: prev.unreadSessionCids.filter((c) => !removedSet.has(c)),
          sessionRenames: sanitizeSessionRenames(nextSessionRenames),
        };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onRemoveCustomProject],
  );

  const applyHideProject = useCallback(
    (projectId: string) => {
      if (onHideProject) {
        onHideProject(projectId);
        return;
      }
      setFallbackSidebarState((prev) => {
        const nextHiddenProjects = sanitizeSlugList(
          [projectId, ...prev.hiddenProjectIds],
          MAX_HIDDEN_PROJECT_IDS,
          64,
        );
        const nextProjectRenames = { ...prev.projectRenames };
        delete nextProjectRenames[projectId];
        const next: WorkbenchSidebarState = {
          ...prev,
          hiddenProjectIds: nextHiddenProjects,
          projectRenames: sanitizeProjectRenames(nextProjectRenames),
        };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onHideProject],
  );

  const applyHideSessions = useCallback(
    (cids: string[]) => {
      if (cids.length === 0) return;
      if (onHideSessions) {
        onHideSessions(cids);
        return;
      }
      setFallbackSidebarState((prev) => {
        const removedSet = new Set(cids);
        const nextHiddenCids = sanitizeSessionCidList(
          [...cids, ...prev.hiddenSessionCids],
          MAX_HIDDEN_SESSION_CIDS,
        );
        const nextSessionRenames = { ...prev.sessionRenames };
        for (const cid of cids) delete nextSessionRenames[cid];
        const next: WorkbenchSidebarState = {
          ...prev,
          hiddenSessionCids: nextHiddenCids,
          pinnedSessionCids: prev.pinnedSessionCids.filter((c) => !removedSet.has(c)),
          archivedSessionCids: prev.archivedSessionCids.filter((c) => !removedSet.has(c)),
          unreadSessionCids: prev.unreadSessionCids.filter((c) => !removedSet.has(c)),
          sessionRenames: sanitizeSessionRenames(nextSessionRenames),
        };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onHideSessions],
  );

  const applyTogglePinSession = useCallback(
    (cid: string) => {
      if (onTogglePinSession) {
        onTogglePinSession(cid);
        return;
      }
      setFallbackSidebarState((prev) => {
        const exists = prev.pinnedSessionCids.includes(cid);
        const nextPinned = exists
          ? prev.pinnedSessionCids.filter((c) => c !== cid)
          : sanitizeSessionCidList([cid, ...prev.pinnedSessionCids], MAX_PINNED_SESSION_CIDS);
        const next: WorkbenchSidebarState = { ...prev, pinnedSessionCids: nextPinned };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onTogglePinSession],
  );

  const applyToggleArchiveSession = useCallback(
    (cid: string) => {
      if (onToggleArchiveSession) {
        onToggleArchiveSession(cid);
        return;
      }
      setFallbackSidebarState((prev) => {
        const exists = prev.archivedSessionCids.includes(cid);
        const nextArchived = exists
          ? prev.archivedSessionCids.filter((c) => c !== cid)
          : sanitizeSessionCidList([cid, ...prev.archivedSessionCids], MAX_ARCHIVED_SESSION_CIDS);
        const next: WorkbenchSidebarState = { ...prev, archivedSessionCids: nextArchived };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onToggleArchiveSession],
  );

  const applySetSessionUnread = useCallback(
    (cid: string, unread: boolean) => {
      if (onSetSessionUnread) {
        onSetSessionUnread(cid, unread);
        return;
      }
      setFallbackSidebarState((prev) => {
        const exists = prev.unreadSessionCids.includes(cid);
        if (unread === exists) return prev;
        const nextUnread = unread
          ? sanitizeSessionCidList([cid, ...prev.unreadSessionCids], MAX_UNREAD_SESSION_CIDS)
          : prev.unreadSessionCids.filter((c) => c !== cid);
        const next: WorkbenchSidebarState = { ...prev, unreadSessionCids: nextUnread };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onSetSessionUnread],
  );

  const applyRenameSession = useCallback(
    (cid: string, nextTitle: string | null) => {
      if (onRenameSession) {
        onRenameSession(cid, nextTitle);
        return;
      }
      setFallbackSidebarState((prev) => {
        const nextMap = { ...prev.sessionRenames };
        if (!nextTitle) {
          delete nextMap[cid];
        } else {
          nextMap[cid] = nextTitle;
        }
        const next: WorkbenchSidebarState = {
          ...prev,
          sessionRenames: sanitizeSessionRenames(nextMap),
        };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onRenameSession],
  );

  const applySetShowArchived = useCallback(
    (show: boolean) => {
      if (onSetShowArchived) {
        onSetShowArchived(show);
        return;
      }
      setFallbackSidebarState((prev) => {
        const next: WorkbenchSidebarState = { ...prev, showArchived: show };
        persistSidebarStateStandalone(next);
        return next;
      });
    },
    [onSetShowArchived],
  );

  const handleOpenCreateProjectModal = () => {
    if (isReadonly) return;
    setOpenMenu(null);
    setNewProjectName("");
    setNewProjectSlug("");
    setCreateProjectError(null);
    setCreateProjectModalOpen(true);
  };

  const handleCloseCreateProjectModal = () => {
    setCreateProjectModalOpen(false);
    setCreateProjectError(null);
  };

  const handleOpenRenameModal = (target: RenameModalTarget) => {
    if (isReadonly) return;
    setOpenMenu(null);
    setRenameTarget(target);
    setRenameInputValue(target.kind === "project" ? target.currentName : target.currentTitle);
    setRenameError(null);
  };

  const handleCloseRenameModal = () => {
    setRenameTarget(null);
    setRenameError(null);
  };

  const handleSubmitRename = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!renameTarget || isReadonly) return;
    const trimmed = renameInputValue.trim();
    if (!trimmed) {
      setRenameError(renameTarget.kind === "project" ? "请输入项目名称" : "请输入对话标题");
      return;
    }
    const maxLen =
      renameTarget.kind === "project" ? MAX_PROJECT_NAME_LEN : MAX_SESSION_TITLE_LEN;
    if (trimmed.length > maxLen) {
      setRenameError(`最长支持 ${maxLen} 个字符`);
      return;
    }
    if (renameTarget.kind === "project") {
      const nextVal = trimmed === renameTarget.originalName ? null : trimmed;
      applyRenameProject(renameTarget.groupId, nextVal);
    } else {
      const nextVal = trimmed === renameTarget.originalTitle ? null : trimmed;
      applyRenameSession(renameTarget.cid, nextVal);
    }
    setRenameTarget(null);
    setRenameError(null);
  };

  const handleCopySessionInfo = async (item: SessionSummaryItem, displayTitle: string) => {
    const payload = `${displayTitle}\n${item.cid}`;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(payload);
      } else {
        const ta = document.createElement("textarea");
        ta.value = payload;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      showSidebarToast("已复制对话标题与 ID");
    } catch {
      showSidebarToast("复制失败，请检查剪贴板权限");
    }
  };

  const loadSessionHistory = useCallback(
    async (
      cid: string,
      beforeCursor?: number | null,
      opts?: { expectedGen?: number; silent?: boolean },
    ) => {
      const reqGen = opts?.expectedGen ?? genRef.current;
      let loadSeq = 0;
      if (!opts?.silent) {
        historyLoadSeqRef.current += 1;
        loadSeq = historyLoadSeqRef.current;
        setHistoryLoading(true);
        setErrorBanner(null);
        setResyncNeeded(false);
      }
      try {
        const res = await fetchSessionMessages(cid, {
          limit: 40,
          before: beforeCursor ?? undefined,
        });
        if (!mountedRef.current) return;
        if (genRef.current !== reqGen || activeCidRef.current !== cid || (!beforeCursor && streamingRef.current)) {
          return;
        }
        setHasMoreHistory(Boolean(res.has_more));
        setNextBefore(res.next_before ?? null);
        if (beforeCursor) {
          setMessages((prev) => [...(res.messages || []), ...prev]);
        } else {
          setMessages(res.messages || []);
          window.setTimeout(() => {
            if (
              mountedRef.current &&
              genRef.current === reqGen &&
              activeCidRef.current === cid &&
              !streamingRef.current
            ) {
              timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
            }
          }, 40);
        }
      } catch (err) {
        if (!mountedRef.current || genRef.current !== reqGen || activeCidRef.current !== cid) {
          return;
        }
        if (!handleApiAuthError(err) && !opts?.silent) {
          setErrorBanner(err instanceof Error ? err.message : "加载历史消息失败");
        }
      } finally {
        if (mountedRef.current && !opts?.silent && historyLoadSeqRef.current === loadSeq) {
          setHistoryLoading(false);
        }
      }
    },
    [handleApiAuthError],
  );

  const updateAssistantBubble = useCallback(
    (updater: (msg: ChatMessageItem) => ChatMessageItem) => {
      const targetId = activeAssistantIdRef.current;
      if (!targetId || !mountedRef.current) return;
      setMessages((prev) => prev.map((m) => (m.id === targetId ? updater(m) : m)));
    },
    [],
  );

  const attachStream = useCallback(
    (turnId: string, botHandle: string, streamGen: number, mode: "local" | "remote") => {
      closeEventSource();
      if (isTeamModeRef.current) return;
      const safeBotHandle = botHandle === TEAM_TARGET_ID ? "" : botHandle;

      if (!acquireStreamSlot()) {
        setStreamDegraded(true);
        setStatusNotice("并发流已达上限（3/3），自动降级为全局事件与历史同步…");
        degradePollRef.current = window.setInterval(() => {
          if (!mountedRef.current || isTeamModeRef.current || genRef.current !== streamGen) {
            stopDegradePoll();
            return;
          }
          const cidNow = activeCidRef.current;
          if (!cidNow) return;
          void fetchActiveSessionTurn(cidNow, safeBotHandle || undefined)
            .then((st) => {
              if (!mountedRef.current || isTeamModeRef.current || genRef.current !== streamGen) {
                return;
              }
              if (!st.active) {
                resetStreamState();
                setStatusNotice(null);
                void loadSessions();
                void loadSessionHistory(cidNow, null, { expectedGen: streamGen, silent: true });
              }
            })
            .catch(() => {
              // Ignore transient poll errors
            });
        }, 2500);
        return;
      }

      setStreamDegraded(false);
      const qs = new URLSearchParams({ turn_id: turnId });
      if (safeBotHandle) qs.set("bot", safeBotHandle);
      const es = new EventSource(`/api/chat/stream?${qs.toString()}`);
      esRef.current = es;

      const isStale = () =>
        !mountedRef.current ||
        isTeamModeRef.current ||
        genRef.current !== streamGen ||
        esRef.current !== es;

      const parseData = (ev: MessageEvent): Record<string, unknown> => {
        try {
          return JSON.parse(String(ev.data || "{}")) as Record<string, unknown>;
        } catch {
          return {};
        }
      };

      const finishAndAlign = (cidHint?: string | null, shouldDrainQueue = false) => {
        resetStreamState();
        if (!mountedRef.current) return;
        setStatusNotice(null);
        void loadSessions();
        const alignCid = cidHint || activeCidRef.current;
        if (mode === "remote" && alignCid && genRef.current === streamGen) {
          void loadSessionHistory(alignCid, null, { expectedGen: streamGen, silent: true });
        }
        if (shouldDrainQueue && pendingQueueRef.current.length > 0) {
          window.setTimeout(() => {
            drainNextQueuedTurnRef.current();
          }, 80);
        }
      };

      es.addEventListener("turn_start", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCidSynced(d.conversation_id);
        }
        if (d.worktree && typeof d.worktree === "object") {
          syncActiveWorktree(d.worktree as SessionWorktreeInfo);
        }
        setStatusNotice(mode === "remote" ? "TG 实时同步中…" : "正在思考与执行…");
      });

      es.addEventListener("init", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.conversation_id === "string" && d.conversation_id) {
          setActiveCidSynced(d.conversation_id);
        }
      });

      es.addEventListener("status", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        if (typeof d.message === "string" && d.message) {
          setStatusNotice(d.message);
        }
      });

      es.addEventListener("thinking", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        updateAssistantBubble((m) => ({
          ...m,
          thinking: (m.thinking || "") + delta,
        }));
      });

      es.addEventListener("tool_use", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const tname = typeof d.tool_name === "string" ? d.tool_name : "tool";
        setStatusNotice(mode === "remote" ? `TG 同步 · 执行工具：${tname}` : `执行工具：${tname}`);
        updateAssistantBubble((m) => {
          const prevTools: ChatToolCall[] = [...(m.tool_calls || [])];
          prevTools.push({ name: tname, active: true });
          return { ...m, tool_calls: prevTools };
        });
      });

      es.addEventListener("tool_result", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const tname = typeof d.tool_name === "string" ? d.tool_name : "tool";
        const dur = typeof d.duration_seconds === "number" ? d.duration_seconds : null;
        updateAssistantBubble((m) => {
          const nextTools = (m.tool_calls || []).map((tc) =>
            tc.name === tname && tc.active ? { ...tc, active: false, duration_seconds: dur } : tc,
          );
          return { ...m, tool_calls: nextTools };
        });
      });

      es.addEventListener("text_delta", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const delta = typeof d.delta === "string" ? d.delta : "";
        if (!delta) return;
        if (mode !== "remote") {
          setStatusNotice(null);
        }
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || "") + delta,
        }));
        timelineEndRef.current?.scrollIntoView({ behavior: "auto" });
      });

      es.addEventListener("done", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const resolvedCid =
          typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
        if (resolvedCid) {
          setActiveCidSynced(resolvedCid);
        }
        if (d.worktree && typeof d.worktree === "object") {
          syncActiveWorktree(d.worktree as SessionWorktreeInfo);
        }
        const finalResp = typeof d.response === "string" ? d.response : "";
        updateAssistantBubble((m) => ({
          ...m,
          content: m.content.trim() ? m.content : finalResp || "(无文本输出)",
          status: typeof d.status === "string" ? d.status : "DONE",
        }));
        finishAndAlign(resolvedCid, true);
      });

      es.addEventListener("aborted", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const partial = typeof d.partial_text === "string" ? d.partial_text : "";
        const resolvedCid =
          typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
        updateAssistantBubble((m) => ({
          ...m,
          content: (m.content || partial) + "\n\n*[已停止生成]*",
          status: "ABORTED",
        }));
        finishAndAlign(resolvedCid);
      });

      es.addEventListener("error", (ev) => {
        if (isStale()) return;
        const mev = ev as MessageEvent;
        if (typeof mev.data === "string" && mev.data) {
          const d = parseData(mev);
          const msg = typeof d.error === "string" ? d.error : "对话执行出错";
          const resolvedCid =
            typeof d.conversation_id === "string" && d.conversation_id ? d.conversation_id : null;
          setErrorBanner(msg);
          updateAssistantBubble((m) => ({
            ...m,
            content: m.content || `⚠️ ${msg}`,
            status: "ERROR",
          }));
          finishAndAlign(resolvedCid);
        } else if (mode === "remote") {
          finishAndAlign(activeCidRef.current);
        }
      });

      es.addEventListener("resync_required", () => {
        if (isStale()) return;
        resetStreamState();
        const curCid = activeCidRef.current;
        if (curCid) {
          setStatusNotice(null);
          void loadSessionHistory(curCid, null, { expectedGen: streamGen, silent: true });
        } else {
          setResyncNeeded(true);
          setStatusNotice("事件流超出缓冲窗口，请重新同步历史记录。");
        }
      });

      es.addEventListener("auth_error", (ev) => {
        if (isStale()) return;
        const d = parseData(ev as MessageEvent);
        const reason = typeof d.error === "string" ? d.error : "会话鉴权已失效";
        resetStreamState();
        onSessionRevoked(reason);
      });
    },
    [
      acquireStreamSlot,
      closeEventSource,
      loadSessionHistory,
      loadSessions,
      onSessionRevoked,
      resetStreamState,
      setActiveCidSynced,
      stopDegradePoll,
      updateAssistantBubble,
    ],
  );

  const probeAndAttachActiveTurn = useCallback(
    async (cid: string, botHint?: string) => {
      if (isReadonly || !cid || streamingRef.current) return;
      if (isTeamModeRef.current) return;
      if (attachInFlightRef.current === cid) return;
      const reqGen = genRef.current;
      let expectedGen = reqGen;
      attachInFlightRef.current = cid;
      const safeBotHint =
        botHint && botHint !== TEAM_TARGET_ID
          ? botHint
          : effectiveBot && effectiveBot !== TEAM_TARGET_ID
            ? effectiveBot
            : undefined;
      try {
        const res = await fetchActiveSessionTurn(cid, safeBotHint);
        if (
          !mountedRef.current ||
          isTeamModeRef.current ||
          genRef.current !== reqGen ||
          activeCidRef.current !== cid ||
          streamingRef.current
        ) {
          return;
        }
        if (!res.active || !res.turn_id) {
          return;
        }
        if (activeTurnIdRef.current === res.turn_id) {
          return;
        }
        genRef.current += 1;
        const attachGen = genRef.current;
        expectedGen = attachGen;
        const src = res.source || "tg";
        const assistantMsgId = `remote-a-${res.turn_id}`;
        const userMsgId = `remote-u-${res.turn_id}`;
        activeAssistantIdRef.current = assistantMsgId;
        activeTurnIdRef.current = res.turn_id;
        streamingRef.current = true;
        streamingSourceRef.current = "remote";
        setActiveTurnId(res.turn_id);
        setStreaming(true);
        setRemoteSyncSource(src);
        setStatusNotice(src === "tg" ? "TG 实时同步中…" : "多端实时同步中…");

        const promptPreview = (res.prompt_preview || "").trim();
        setMessages((prev) => {
          const filtered = prev.filter((m) => m.id !== assistantMsgId && m.id !== userMsgId);
          const lastMsg = filtered[filtered.length - 1];
          const needUserBubble =
            Boolean(promptPreview) &&
            !(
              lastMsg &&
              lastMsg.role === "user" &&
              lastMsg.content.trim().startsWith(promptPreview.slice(0, 60))
            );
          const next: ChatMessageItem[] = [...filtered];
          if (needUserBubble) {
            next.push({ id: userMsgId, role: "user", content: promptPreview });
          }
          next.push({
            id: assistantMsgId,
            role: "assistant",
            content: "",
            thinking: "",
            tool_calls: [],
          });
          return next;
        });

        attachStream(res.turn_id, res.bot || safeBotHint || effectiveBot, attachGen, "remote");
      } catch (err) {
        if (!mountedRef.current || genRef.current !== expectedGen) return;
        handleApiAuthError(err);
      } finally {
        if (attachInFlightRef.current === cid) {
          attachInFlightRef.current = null;
        }
      }
    },
    [attachStream, handleApiAuthError, isReadonly, effectiveBot],
  );

  // React to global `session_updated` / `resync_required` SSE signals from App
  useEffect(() => {
    if (!sessionSyncEvent || sessionSyncEvent.ver === lastSyncVerRef.current) {
      return;
    }
    lastSyncVerRef.current = sessionSyncEvent.ver;
    void loadSessions();

    if (isTeamModeRef.current) return;

    const curCid = activeCidRef.current;
    if (!curCid) return;

    if (sessionSyncEvent.type === "resync_required") {
      if (!streamingRef.current) {
        const curGen = genRef.current;
        void loadSessionHistory(curCid, null, { expectedGen: curGen, silent: true }).then(() => {
          if (
            mountedRef.current &&
            !isReadonly &&
            !isTeamModeRef.current &&
            genRef.current === curGen &&
            activeCidRef.current === curCid &&
            !streamingRef.current
          ) {
            void probeAndAttachActiveTurn(curCid, effectiveBotRef.current || undefined);
          }
        });
      }
      return;
    }

    if (sessionSyncEvent.cid !== curCid) return;

    if (sessionSyncEvent.status === "running") {
      if (!isReadonly && !streamingRef.current) {
        void probeAndAttachActiveTurn(
          curCid,
          sessionSyncEvent.bot || effectiveBotRef.current || undefined,
        );
      }
    } else if (
      sessionSyncEvent.status === "done" ||
      sessionSyncEvent.status === "aborted" ||
      sessionSyncEvent.status === "error"
    ) {
      if (!streamingRef.current || streamingSourceRef.current === "remote" || streamDegraded) {
        if (streamingSourceRef.current === "remote" || streamDegraded) {
          resetStreamState();
          setStatusNotice(null);
        }
        void loadSessionHistory(curCid, null, { expectedGen: genRef.current, silent: true });
        if (sessionSyncEvent.status === "done" && pendingQueueRef.current.length > 0) {
          window.setTimeout(() => {
            drainNextQueuedTurnRef.current();
          }, 120);
        }
      }
    }
  }, [
    isReadonly,
    loadSessionHistory,
    loadSessions,
    probeAndAttachActiveTurn,
    resetStreamState,
    sessionSyncEvent,
    streamDegraded,
  ]);

  const openSessionByItem = useCallback(
    (item: SessionSummaryItem, opts?: { force?: boolean }) => {
      if (!opts?.force && streamingRef.current && streamingSourceRef.current === "local") return;
      setOpenMenu(null);
      if (unreadSessionCidSet.has(item.cid)) {
        applySetSessionUnread(item.cid, false);
      }
      onFocusPane?.(paneId);
      if (isTeamModeRef.current || !selectedBotRef.current) {
        const nextBot = resolveSingleBotTarget(item.bot);
        isTeamModeRef.current = false;
        selectedBotRef.current = nextBot;
        if (!nextBot) {
          preferSingleBotOnRosterLoadRef.current = true;
        }
        setSelectedBot(nextBot);
        if (nextBot) {
          onBotChangeRef.current?.(nextBot);
        }
      }
      genRef.current += 1;
      const nextGen = genRef.current;
      attachInFlightRef.current = null;
      clearPendingQueue();
      resetStreamState();
      setActiveCidSynced(item.cid);
      syncActiveWorktree(item.worktree || null);
      if (item.project_id) {
        setSelectedProject(item.project_id);
        onProjectChangeRef.current?.(item.project_id);
      }
      setStatusNotice(null);
      setErrorBanner(null);
      const safeProbeBot =
        item.bot && item.bot !== TEAM_TARGET_ID ? item.bot : undefined;
      void loadSessionHistory(item.cid, null, { expectedGen: nextGen }).then(() => {
        if (
          mountedRef.current &&
          !isReadonly &&
          !isTeamModeRef.current &&
          genRef.current === nextGen &&
          activeCidRef.current === item.cid &&
          !streamingRef.current
        ) {
          void probeAndAttachActiveTurn(item.cid, safeProbeBot);
        }
      });
    },
    [
      applySetSessionUnread,
      clearPendingQueue,
      isReadonly,
      loadSessionHistory,
      onFocusPane,
      paneId,
      probeAndAttachActiveTurn,
      resetStreamState,
      resolveSingleBotTarget,
      setActiveCidSynced,
      unreadSessionCidSet,
    ],
  );

  const handleSelectSession = (item: SessionSummaryItem) => {
    openSessionByItem(item);
  };

  useEffect(() => {
    if (!pendingOpenSession || pendingOpenSession.id === consumedOpenSessionIdRef.current) return;
    consumedOpenSessionIdRef.current = pendingOpenSession.id;
    initialCidHydratedRef.current = true;
    openSessionByItem(pendingOpenSession.session, { force: true });
    onOpenSessionConsumed?.(pendingOpenSession.id);
  }, [pendingOpenSession, openSessionByItem, onOpenSessionConsumed]);

  useEffect(() => {
    if (initialCidHydratedRef.current || !initialCid || pendingOpenSession || isTeamMode) return;
    initialCidHydratedRef.current = true;
    genRef.current += 1;
    const nextGen = genRef.current;
    setActiveCidSynced(initialCid);
    void loadSessionHistory(initialCid, null, { expectedGen: nextGen }).then(() => {
      if (
        mountedRef.current &&
        !isReadonly &&
        !isTeamModeRef.current &&
        genRef.current === nextGen &&
        activeCidRef.current === initialCid &&
        !streamingRef.current
      ) {
        void probeAndAttachActiveTurn(initialCid, undefined);
      }
    });
  }, [
    initialCid,
    pendingOpenSession,
    isTeamMode,
    isReadonly,
    setActiveCidSynced,
    loadSessionHistory,
    probeAndAttachActiveTurn,
  ]);

  const handleNewChat = (targetProjectId?: string, targetGroupId?: string) => {
    if (streamingRef.current && streamingSourceRef.current === "local") return;
    onFocusPane?.(paneId);
    if (isTeamModeRef.current || !selectedBotRef.current) {
      const nextBot = resolveSingleBotTarget();
      isTeamModeRef.current = false;
      selectedBotRef.current = nextBot;
      if (!nextBot) {
        preferSingleBotOnRosterLoadRef.current = true;
      }
      setSelectedBot(nextBot);
      if (nextBot) {
        onBotChangeRef.current?.(nextBot);
      }
    }
    genRef.current += 1;
    attachInFlightRef.current = null;
    clearPendingQueue();
    resetStreamState();
    if (targetProjectId) {
      setSelectedProject(targetProjectId);
      onProjectChangeRef.current?.(targetProjectId);
    }
    if (targetGroupId) {
      setProjectExpandOverrides((prev) => ({ ...prev, [targetGroupId]: true }));
    }
    setActiveCidSynced(null);
    syncActiveWorktree(null);
    setMessages([]);
    setHasMoreHistory(false);
    setNextBefore(null);
    setStatusNotice(null);
    setErrorBanner(null);
    setResyncNeeded(false);
  };

  const resetChatToEmptyDraft = (nextProjectId?: string) => {
    genRef.current += 1;
    attachInFlightRef.current = null;
    clearPendingQueue();
    resetStreamState();
    if (nextProjectId !== undefined) {
      setSelectedProject(nextProjectId);
      onProjectChangeRef.current?.(nextProjectId);
    }
    setActiveCidSynced(null);
    syncActiveWorktree(null);
    setMessages([]);
    setHasMoreHistory(false);
    setNextBefore(null);
    setStatusNotice(null);
    setErrorBanner(null);
    setResyncNeeded(false);
  };

  const handleSubmitCreateProject = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isReadonly) return;

    const trimmedName = newProjectName.trim();
    if (!trimmedName) {
      setCreateProjectError("请输入项目名称");
      return;
    }
    if (trimmedName.length > MAX_PROJECT_NAME_LEN) {
      setCreateProjectError(`项目名称最长 ${MAX_PROJECT_NAME_LEN} 个字符`);
      return;
    }
    if (customProjects.length >= MAX_CUSTOM_PROJECTS) {
      setCreateProjectError(`自定义项目数量已达上限（${MAX_CUSTOM_PROJECTS} 个），请先删除不需要的项目`);
      return;
    }

    const visibleLowerNames = new Set(projectGroups.map((g) => g.name.trim().toLowerCase()));
    if (visibleLowerNames.has(trimmedName.toLowerCase())) {
      setCreateProjectError(`项目名称「${trimmedName}」已存在，请使用其他名称`);
      return;
    }

    const visibleLowerIds = new Set(
      projectGroups.map((g) => (g.projectId || g.id).trim().toLowerCase()),
    );
    const takenLowerIds = new Set<string>([
      ...visibleLowerIds,
      ...customProjects.map((p) => p.id.toLowerCase()),
    ]);

    const rawSlug = newProjectSlug.trim();
    let resolvedId: string;
    if (rawSlug) {
      const cleaned = sanitizeShortSlug(rawSlug, 64);
      if (!cleaned || RESERVED_PROJECT_IDS.has(cleaned)) {
        setCreateProjectError("项目标识仅支持英文字母、数字、点、下划线和连字符（最长 64 字符）");
        return;
      }
      if (takenLowerIds.has(cleaned.toLowerCase())) {
        setCreateProjectError(`项目标识「${cleaned}」已存在，请更换其他标识`);
        return;
      }
      resolvedId = cleaned;
    } else {
      const asciiSlug = buildAsciiKebabSlug(trimmedName);
      if (asciiSlug && !RESERVED_PROJECT_IDS.has(asciiSlug)) {
        if (takenLowerIds.has(asciiSlug.toLowerCase())) {
          setCreateProjectError(
            `自动生成的项目标识「${asciiSlug}」与现有项目冲突，请手动指定项目标识`,
          );
          return;
        }
        resolvedId = asciiSlug;
      } else {
        resolvedId = generateRandomProjectSlug(takenLowerIds);
      }
    }

    applyAddCustomProject({
      id: resolvedId,
      name: trimmedName,
      createdAt: Date.now(),
    });
    setProjectExpandOverrides((prev) => ({ ...prev, [resolvedId]: true }));
    if (!(streamingRef.current && streamingSourceRef.current === "local")) {
      if (isTeamModeRef.current) {
        setSelectedProject(resolvedId);
        onProjectChangeRef.current?.(resolvedId);
      } else {
        resetChatToEmptyDraft(resolvedId);
      }
    }
    setCreateProjectModalOpen(false);
    setCreateProjectError(null);
  };

  const handleConfirmDelete = () => {
    if (!deleteTarget || isReadonly) return;

    if (deleteTarget.kind === "project") {
      const target = deleteTarget;
      const relatedSessionCids = new Set<string>(target.sessionCids);
      if (target.projectId) {
        for (const s of sessions) {
          if ((s.project_id || "").trim() === target.projectId) {
            relatedSessionCids.add(s.cid);
          }
        }
      }
      const relatedCidList = Array.from(relatedSessionCids);

      if (target.isCustom && target.projectId) {
        applyRemoveCustomProject(target.projectId, relatedCidList);
      } else if (target.groupKind === "formal" && target.projectId) {
        applyHideProject(target.projectId);
      } else {
        applyHideSessions(relatedCidList);
      }

      setProjectExpandOverrides((prev) => {
        if (!(target.groupId in prev)) return prev;
        const next = { ...prev };
        delete next[target.groupId];
        return next;
      });
      setExpandedSessionLists((prev) => {
        if (!(target.groupId in prev)) return prev;
        const next = { ...prev };
        delete next[target.groupId];
        return next;
      });

      const activeInDeleted = Boolean(
        activeCidRef.current && relatedSessionCids.has(activeCidRef.current),
      );
      const selectedIsDeleted = Boolean(target.projectId && selectedProject === target.projectId);
      if (activeInDeleted || selectedIsDeleted) {
        const remainingFormal = projectGroups.find(
          (g) => g.id !== target.groupId && Boolean(g.projectId),
        );
        const fallbackProjectId = selectedIsDeleted
          ? remainingFormal?.projectId || ""
          : undefined;
        resetChatToEmptyDraft(fallbackProjectId);
      }
    } else {
      const target = deleteTarget;
      applyHideSessions([target.cid]);
      if (activeCidRef.current === target.cid) {
        resetChatToEmptyDraft();
      }
    }

    setDeleteTarget(null);
  };

  const dispatchChatTurn = async (
    payload: {
      prompt: string;
      displayText: string;
      attachments: ChatAttachmentItem[];
      attachmentIds: string[];
      contextFiles: string[];
    },
    mode: ExecutionMode = "queue",
  ) => {
    if (isReadonly || isTeamModeRef.current || interruptingRef.current) {
      return;
    }
    const isInterrupt = mode === "interrupt";
    const wasBusy = streamingRef.current;

    if (!isInterrupt && wasBusy) {
      return;
    }

    onFocusPane?.(paneId);
    setFilePickerMode(null);
    setErrorBanner(null);
    setResyncNeeded(false);

    if (isInterrupt) {
      interruptingRef.current = true;
      setInterrupting(true);
      if (wasBusy) {
        closeEventSource();
        const prevAssistantId = activeAssistantIdRef.current;
        if (prevAssistantId) {
          setMessages((prev) =>
            prev.reduce<ChatMessageItem[]>((acc, m) => {
              if (m.id !== prevAssistantId) {
                acc.push(m);
                return acc;
              }
              const hasOutput =
                Boolean(m.content && m.content.trim()) ||
                Boolean(m.thinking && m.thinking.trim()) ||
                Boolean(m.tool_calls && m.tool_calls.length > 0);
              if (!hasOutput) {
                return acc;
              }
              acc.push({
                ...m,
                content: m.content
                  ? `${m.content}\n\n*[已被「⚡ 马上执行」中断]*`
                  : "*[已被「⚡ 马上执行」中断]*",
                status: "ABORTED",
              });
              return acc;
            }, []),
          );
        }
      }
    }

    genRef.current += 1;
    const sendGen = genRef.current;
    attachInFlightRef.current = null;

    const userMsgId = `u-${Date.now()}`;
    const assistantMsgId = `a-${Date.now() + 1}`;
    activeAssistantIdRef.current = assistantMsgId;
    activeTurnIdRef.current = null;
    setActiveTurnId(null);
    streamingRef.current = true;
    streamingSourceRef.current = "local";

    setMessages((prev) => [
      ...prev,
      {
        id: userMsgId,
        role: "user",
        content: payload.displayText,
        attachments: payload.attachments.length > 0 ? payload.attachments : undefined,
        context_files: payload.contextFiles.length > 0 ? payload.contextFiles : undefined,
        execution_mode: isInterrupt ? "interrupt" : undefined,
        interrupted_prev: isInterrupt && wasBusy ? true : undefined,
      },
      { id: assistantMsgId, role: "assistant", content: "", thinking: "", tool_calls: [] },
    ]);
    setStreaming(true);
    setRemoteSyncSource(null);
    setStatusNotice(
      isInterrupt
        ? wasBusy
          ? "⚡ 已中断上一轮并马上执行…"
          : "⚡ 正在优先执行…"
        : "正在提交至 Bridge 队列…",
    );

    const backendProjectParam = resolvedBackendProject;
    const safeBotParam =
      effectiveBot && effectiveBot !== TEAM_TARGET_ID ? effectiveBot : undefined;
    try {
      const res = await sendChatTurn({
        bot: safeBotParam,
        prompt: payload.prompt,
        cid: activeCidRef.current || undefined,
        project: backendProjectParam,
        model: selectedModel || undefined,
        effort: selectedEffort || undefined,
        sync_tg: !isReadonly,
        worktree: !isReadonly && !activeCidRef.current && worktreeEnabled ? true : undefined,
        attachments: payload.attachmentIds.length > 0 ? payload.attachmentIds : undefined,
        context_files: payload.contextFiles.length > 0 ? payload.contextFiles : undefined,
        execution_mode: mode,
      });
      if (!mountedRef.current || genRef.current !== sendGen || isTeamModeRef.current) {
        resetStreamState();
        return;
      }
      if (isInterrupt && res.interrupted_turn_id && !wasBusy) {
        setMessages((prev) =>
          prev.map((m) => (m.id === userMsgId ? { ...m, interrupted_prev: true } : m)),
        );
      }
      activeTurnIdRef.current = res.turn_id;
      setActiveTurnId(res.turn_id);
      if (res.cid) setActiveCidSynced(res.cid);
      if (res.worktree) {
        if (res.worktree.active) {
          syncActiveWorktree(res.worktree);
        } else if (res.worktree.reason) {
          syncActiveWorktree(null);
          setStatusNotice(`Worktree 已安全降级（${res.worktree.reason}），使用主工作区继续执行…`);
        }
      }
      attachStream(res.turn_id, res.bot || safeBotParam || "", sendGen, "local");
    } catch (err) {
      if (!mountedRef.current || genRef.current !== sendGen) {
        return;
      }
      resetStreamState();
      setStatusNotice(null);
      if (handleApiAuthError(err)) return;
      const errMsg =
        err instanceof StudioApiError && err.status === 409
          ? "当前会话正被占用（409 session_busy），请稍后再试、加入排队或点击「⚡ 马上执行」。"
          : err instanceof Error
            ? err.message
            : "发送消息失败";
      setErrorBanner(errMsg);
      setMessages((prev) => prev.filter((m) => m.id !== assistantMsgId));
    } finally {
      interruptingRef.current = false;
      if (mountedRef.current) {
        setInterrupting(false);
      }
    }
  };

  drainNextQueuedTurnRef.current = () => {
    if (
      !mountedRef.current ||
      isReadonly ||
      isTeamModeRef.current ||
      streamingRef.current ||
      interruptingRef.current
    ) {
      return;
    }
    const list = pendingQueueRef.current;
    if (list.length === 0) return;
    const [nextItem, ...rest] = list;
    pendingQueueRef.current = rest;
    setPendingQueue(rest);
    void dispatchChatTurn(nextItem, "queue");
  };

  const handleSend = async (mode: ExecutionMode = "queue") => {
    const text = draft.trim();
    const attIds = composerAtts.readyAttachmentIds;
    const attItems = composerAtts.readyAttachments;
    const ctxFiles = [...composerAtts.contextFiles];
    const hasContent = Boolean(text) || attIds.length > 0 || ctxFiles.length > 0;
    if (
      !hasContent ||
      composerAtts.isUploading ||
      interruptingRef.current ||
      isReadonly ||
      isTeamModeRef.current
    ) {
      return;
    }

    const optimisticDisplayText =
      text ||
      (attItems.length > 0 && ctxFiles.length > 0
        ? "请查看并分析我附加的文件与引用的工作区文件"
        : attItems.length > 0
          ? attItems.some((a) => a.kind === "image")
            ? "请查看并分析我附加的图片/文件"
            : "请查看并分析我附加的文件"
          : "请查看并分析我引用的工作区文件");

    const item = {
      id: `q-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      prompt: text,
      displayText: optimisticDisplayText,
      attachments: [...attItems],
      attachmentIds: [...attIds],
      contextFiles: ctxFiles,
      createdAt: Date.now(),
    };

    setFilePickerMode(null);
    setDraft("");
    composerAtts.clearAll();

    if (mode === "queue" && streamingRef.current) {
      onFocusPane?.(paneId);
      setPendingQueue((prev) => {
        const next = [...prev, item];
        pendingQueueRef.current = next;
        return next;
      });
      return;
    }

    await dispatchChatTurn(item, mode);
  };

  const handleRunQueuedNow = (itemId: string) => {
    if (isReadonly || interruptingRef.current) return;
    const target = pendingQueueRef.current.find((q) => q.id === itemId);
    if (!target) return;
    const rest = pendingQueueRef.current.filter((q) => q.id !== itemId);
    pendingQueueRef.current = rest;
    setPendingQueue(rest);
    void dispatchChatTurn(target, "interrupt");
  };

  const handleRemoveQueuedItem = (itemId: string) => {
    setPendingQueue((prev) => {
      const next = prev.filter((q) => q.id !== itemId);
      pendingQueueRef.current = next;
      return next;
    });
  };

  const handleAbort = async () => {
    if (!activeTurnId) return;
    const safeBotParam =
      effectiveBot && effectiveBot !== TEAM_TARGET_ID ? effectiveBot : undefined;
    setStatusNotice("正在请求停止当前轮次…");
    try {
      await abortChatTurn(activeTurnId, safeBotParam);
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleApiAuthError(err)) {
        setErrorBanner(err instanceof Error ? err.message : "停止任务失败");
      }
    }
  };

  const isLocalStreaming = streaming && !remoteSyncSource;

  return (
    <div
      className="flex-1 min-h-0 min-w-0 flex overflow-hidden bg-slate-950"
      onMouseDown={() => onFocusPane?.(paneId)}
    >
      {/* Left Collapsible Project + Sessions Tree Sidebar */}
      {sidebarOpen && (
        <aside
          className={`${
            compactHeader ? "w-52" : "w-64 lg:w-72"
          } shrink-0 border-r border-slate-800/90 bg-slate-900/50 flex flex-col min-h-0 relative`}
        >
          <div className="shrink-0 h-10 px-3 border-b border-slate-800/90 bg-slate-900/75 flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-400">项目</span>
            <div className="flex items-center gap-0.5">
              <button
                type="button"
                data-sidebar-menu-trigger="true"
                onClick={(e) => {
                  e.stopPropagation();
                  if (openMenu?.kind === "filter") {
                    setOpenMenu(null);
                    return;
                  }
                  const rect = e.currentTarget.getBoundingClientRect();
                  const pos = computeFloatingMenuPosition(rect, 212, 168, "right-edge");
                  setOpenMenu({ kind: "filter", ...pos });
                }}
                title="筛选对话"
                aria-label="筛选对话"
                aria-expanded={openMenu?.kind === "filter"}
                className={`relative h-7 w-7 shrink-0 rounded-md inline-flex items-center justify-center transition-colors cursor-pointer ${
                  hasAnyFilterActive || openMenu?.kind === "filter"
                    ? "bg-slate-800/80 text-cyan-300"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/70"
                }`}
              >
                <ListFilter className="w-3.5 h-3.5" />
                {hasAnyFilterActive && (
                  <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-cyan-400" />
                )}
              </button>

              {!isReadonly && (
                <button
                  type="button"
                  onClick={handleOpenCreateProjectModal}
                  title="新增项目"
                  aria-label="新增项目"
                  className="h-7 w-7 shrink-0 rounded-md hover:bg-slate-800/70 text-slate-400 hover:text-slate-200 inline-flex items-center justify-center transition-colors cursor-pointer"
                >
                  <FolderPlus className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div
            onScroll={() => {
              if (openMenu) setOpenMenu(null);
            }}
            className="flex-1 min-h-0 overflow-y-auto px-1.5 py-2 space-y-1"
          >
            {projectGroups.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-slate-500 space-y-2">
                <div>
                  {sessionsLoading
                    ? "加载项目与会话中…"
                    : hasNarrowFilter
                      ? "当前筛选条件下暂无对话"
                      : "暂无项目或可恢复会话"}
                </div>
                {hasNarrowFilter && (
                  <button
                    type="button"
                    onClick={() => {
                      setFilterPinnedOnly(false);
                      setFilterUnreadOnly(false);
                    }}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                  >
                    清除筛选条件
                  </button>
                )}
              </div>
            ) : (
              projectGroups.map((group) => {
                const expanded = isGroupExpanded(group.id);
                const totalCount = group.sessions.length;
                const hasOverflow = totalCount > DEFAULT_VISIBLE_SESSIONS_PER_PROJECT;
                const listExpanded = Boolean(expandedSessionLists[group.id]);
                const visibleSessions =
                  !hasOverflow || listExpanded
                    ? group.sessions
                    : group.sessions.slice(0, DEFAULT_VISIBLE_SESSIONS_PER_PROJECT);
                const hiddenCount = totalCount - DEFAULT_VISIBLE_SESSIONS_PER_PROJECT;
                const projMenuOpen = openMenu?.kind === "project" && openMenu.groupId === group.id;
                const canShowNewChatBtn =
                  !isReadonly && group.kind !== "temp" && Boolean(group.projectId);
                const canShowProjectMenu = !isReadonly || hasOverflow;

                return (
                  <div key={group.id} className="space-y-0.5">
                    <div
                      className={`group/proj flex items-center gap-1 rounded-lg px-2 py-1.5 transition-colors ${
                        projMenuOpen
                          ? "bg-slate-800/55 text-slate-200"
                          : "hover:bg-slate-800/45 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setOpenMenu(null);
                          setProjectExpandOverrides((prev) => ({
                            ...prev,
                            [group.id]: !expanded,
                          }));
                          if (
                            group.projectId &&
                            !(streamingRef.current && streamingSourceRef.current === "local")
                          ) {
                            setSelectedProject(group.projectId);
                            onProjectChangeRef.current?.(group.projectId);
                          }
                        }}
                        className="flex-1 min-w-0 flex items-center gap-2 text-left cursor-pointer"
                        title={group.name}
                      >
                        <Folder
                          className={`w-3.5 h-3.5 shrink-0 transition-colors ${
                            group.isSelectedProject || group.hasActiveSession
                              ? "text-slate-300"
                              : "text-slate-500 group-hover/proj:text-slate-400"
                          }`}
                        />
                        <span
                          className={`text-xs font-medium truncate ${
                            group.isSelectedProject || group.hasActiveSession
                              ? "text-slate-200"
                              : group.kind === "formal"
                                ? "text-slate-400 group-hover/proj:text-slate-200"
                                : "text-slate-500 group-hover/proj:text-slate-300"
                          }`}
                        >
                          {group.name}
                        </span>
                      </button>

                      {!expanded && totalCount > 0 && !projMenuOpen && (
                        <span className="shrink-0 text-[10px] text-slate-600 tabular-nums pr-0.5 sm:group-hover/proj:hidden">
                          {totalCount}
                        </span>
                      )}

                      {(canShowProjectMenu || canShowNewChatBtn) && (
                        <div
                          className={`shrink-0 items-center gap-0.5 ${
                            projMenuOpen
                              ? "flex"
                              : "flex sm:hidden sm:group-hover/proj:flex max-sm:opacity-75"
                          }`}
                        >
                          {canShowProjectMenu && (
                            <button
                              type="button"
                              data-sidebar-menu-trigger="true"
                              onClick={(e) => {
                                e.stopPropagation();
                                if (projMenuOpen) {
                                  setOpenMenu(null);
                                  return;
                                }
                                const rect = e.currentTarget.getBoundingClientRect();
                                const pos = computeFloatingMenuPosition(
                                  rect,
                                  176,
                                  180,
                                  "under-trigger",
                                );
                                setOpenMenu({ kind: "project", groupId: group.id, ...pos });
                              }}
                              title="项目操作"
                              aria-label={`${group.name} 更多操作`}
                              aria-expanded={projMenuOpen}
                              className={`h-6 w-6 shrink-0 rounded-md inline-flex items-center justify-center transition-colors cursor-pointer ${
                                projMenuOpen
                                  ? "bg-slate-700/70 text-slate-100"
                                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-700/60"
                              }`}
                            >
                              <MoreVertical className="w-3.5 h-3.5" />
                            </button>
                          )}

                          {canShowNewChatBtn && (
                            <button
                              type="button"
                              disabled={isLocalStreaming}
                              onClick={(e) => {
                                e.stopPropagation();
                                setOpenMenu(null);
                                handleNewChat(group.projectId || undefined, group.id);
                              }}
                              title={`在此项目新建对话（${group.name}）`}
                              aria-label={`在 ${group.name} 新建对话`}
                              className="h-6 w-6 shrink-0 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-700/60 disabled:opacity-35 inline-flex items-center justify-center transition-colors cursor-pointer"
                            >
                              <Plus className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      )}
                    </div>

                    {expanded && (
                      <div className="space-y-0.5">
                        {visibleSessions.length === 0 ? (
                          <div className="pl-6 pr-2 py-1 text-[11px] text-slate-600">暂无对话</div>
                        ) : (
                          visibleSessions.map((item) => {
                            const selected = !isTeamMode && activeCid === item.cid;
                            const originalTitle = formatSessionDisplayTitle(item);
                            const displayTitle = sessionRenames[item.cid] || originalTitle;
                            const isPinned = pinnedSessionCidSet.has(item.cid);
                            const isUnread = unreadSessionCidSet.has(item.cid);
                            const isArchived = archivedSessionCidSet.has(item.cid);
                            const sessMenuOpen =
                              openMenu?.kind === "session" && openMenu.cid === item.cid;
                            const relTime = formatCompactRelativeTime(item.updated_at);

                            return (
                              <div
                                key={item.cid}
                                className={`group/sess flex items-center gap-1.5 pl-6 pr-2 py-1.5 rounded-lg border transition-colors ${
                                  selected
                                    ? "bg-slate-800/75 border-slate-700/80 text-slate-100"
                                    : sessMenuOpen
                                      ? "bg-slate-800/55 border-transparent text-slate-100"
                                      : "border-transparent hover:bg-slate-800/45 text-slate-300"
                                } ${isArchived ? "opacity-65" : ""}`}
                              >
                                <button
                                  type="button"
                                  onClick={() => handleSelectSession(item)}
                                  title={`${displayTitle}${relTime ? ` · ${relTime}` : ""}`}
                                  className="flex-1 min-w-0 flex items-center gap-1.5 text-left cursor-pointer"
                                >
                                  {isPinned && (
                                    <Pin className="w-3 h-3 shrink-0 text-cyan-400" />
                                  )}
                                  {isUnread && (
                                    <span
                                      title="未读"
                                      className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0"
                                    />
                                  )}
                                  {isArchived && (
                                    <Archive
                                      className="w-3 h-3 shrink-0 text-slate-500"
                                      aria-label="已归档"
                                    />
                                  )}
                                  <span
                                    className={`truncate flex-1 min-w-0 text-xs leading-5 ${
                                      selected || isUnread ? "font-medium text-slate-100" : ""
                                    }`}
                                  >
                                    {displayTitle}
                                  </span>
                                </button>

                                {/* Idle right slot: 2x2 busy dots OR compact relative time */}
                                <div
                                  className={`shrink-0 items-center gap-1.5 ${
                                    sessMenuOpen ? "hidden" : "flex sm:group-hover/sess:hidden"
                                  }`}
                                >
                                  <button
                                    type="button"
                                    tabIndex={-1}
                                    onClick={() => handleSelectSession(item)}
                                    className="inline-flex items-center cursor-pointer"
                                    aria-hidden="true"
                                  >
                                    {item.busy ? (
                                      <span
                                        title="对话执行中"
                                        className="grid grid-cols-2 gap-0.5 shrink-0 p-0.5"
                                      >
                                        <span className="w-1 h-1 rounded-full bg-slate-400 animate-pulse" />
                                        <span className="w-1 h-1 rounded-full bg-slate-400 animate-pulse [animation-delay:150ms]" />
                                        <span className="w-1 h-1 rounded-full bg-slate-400 animate-pulse [animation-delay:300ms]" />
                                        <span className="w-1 h-1 rounded-full bg-slate-400 animate-pulse [animation-delay:450ms]" />
                                      </span>
                                    ) : relTime ? (
                                      <span className="text-[11px] text-slate-500 tabular-nums">
                                        {relTime}
                                      </span>
                                    ) : null}
                                  </button>

                                  <button
                                    type="button"
                                    data-sidebar-menu-trigger="true"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      const rect = e.currentTarget.getBoundingClientRect();
                                      const pos = computeFloatingMenuPosition(
                                        rect,
                                        176,
                                        268,
                                        "under-trigger",
                                      );
                                      setOpenMenu({
                                        kind: "session",
                                        cid: item.cid,
                                        groupId: group.id,
                                        ...pos,
                                      });
                                    }}
                                    title="更多操作"
                                    aria-label="对话更多操作"
                                    className="sm:hidden h-6 w-6 shrink-0 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-700/60 inline-flex items-center justify-center transition-colors cursor-pointer"
                                  >
                                    <MoreVertical className="w-3.5 h-3.5" />
                                  </button>
                                </div>

                                {/* Hover / menu-open right slot: Archive, Pin, MoreVertical */}
                                <div
                                  className={`shrink-0 items-center gap-0.5 ${
                                    sessMenuOpen ? "flex" : "hidden sm:group-hover/sess:flex"
                                  }`}
                                >
                                  {!isReadonly && (
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setOpenMenu(null);
                                        applyToggleArchiveSession(item.cid);
                                      }}
                                      title={isArchived ? "取消归档" : "归档"}
                                      aria-label={isArchived ? "取消归档" : "归档"}
                                      className={`h-6 w-6 shrink-0 rounded-md inline-flex items-center justify-center transition-colors cursor-pointer ${
                                        isArchived
                                          ? "text-cyan-400 hover:bg-slate-700/60"
                                          : "text-slate-400 hover:text-slate-100 hover:bg-slate-700/60"
                                      }`}
                                    >
                                      <Archive className="w-3.5 h-3.5" />
                                    </button>
                                  )}

                                  {!isReadonly && (
                                    <button
                                      type="button"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setOpenMenu(null);
                                        applyTogglePinSession(item.cid);
                                      }}
                                      title={isPinned ? "取消置顶" : "置顶"}
                                      aria-label={isPinned ? "取消置顶" : "置顶"}
                                      className={`h-6 w-6 shrink-0 rounded-md inline-flex items-center justify-center transition-colors cursor-pointer ${
                                        isPinned
                                          ? "text-cyan-400 hover:bg-slate-700/60"
                                          : "text-slate-400 hover:text-slate-100 hover:bg-slate-700/60"
                                      }`}
                                    >
                                      <Pin className="w-3.5 h-3.5" />
                                    </button>
                                  )}

                                  <button
                                    type="button"
                                    data-sidebar-menu-trigger="true"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      if (sessMenuOpen) {
                                        setOpenMenu(null);
                                        return;
                                      }
                                      const rect = e.currentTarget.getBoundingClientRect();
                                      const pos = computeFloatingMenuPosition(
                                        rect,
                                        176,
                                        268,
                                        "under-trigger",
                                      );
                                      setOpenMenu({
                                        kind: "session",
                                        cid: item.cid,
                                        groupId: group.id,
                                        ...pos,
                                      });
                                    }}
                                    title="更多操作"
                                    aria-label="对话更多操作"
                                    aria-expanded={sessMenuOpen}
                                    className={`h-6 w-6 shrink-0 rounded-md inline-flex items-center justify-center transition-colors cursor-pointer ${
                                      sessMenuOpen
                                        ? "bg-slate-700/70 text-slate-100"
                                        : "text-slate-400 hover:text-slate-100 hover:bg-slate-700/60"
                                    }`}
                                  >
                                    <MoreVertical className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              </div>
                            );
                          })
                        )}

                        {hasOverflow && (
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedSessionLists((prev) => ({
                                ...prev,
                                [group.id]: !listExpanded,
                              }))
                            }
                            className="w-full flex items-center gap-1.5 pl-6 pr-2 py-1 rounded-lg text-[11px] text-slate-500 hover:text-slate-300 hover:bg-slate-800/40 transition-colors cursor-pointer"
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

          {sidebarToast && (
            <div
              role="status"
              aria-live="polite"
              className="pointer-events-none absolute left-2 right-2 bottom-2 z-40 rounded-lg border border-slate-700/80 bg-slate-900/95 px-2.5 py-1.5 text-[11px] text-slate-200 shadow-lg flex items-center gap-1.5"
            >
              <Check className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
              <span className="truncate">{sidebarToast}</span>
            </div>
          )}
        </aside>
      )}

      {/* Main Conversation Stage */}
      <section className="flex-1 min-w-0 min-h-0 flex flex-col">
        <header className="shrink-0 min-h-10 px-2.5 py-1.5 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setSidebarOpen((v) => !v)}
            title={sidebarOpen ? "收起项目与会话树" : "展开项目与会话树"}
            className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer shrink-0"
          >
            <PanelLeft className="w-3.5 h-3.5" />
          </button>

          <div className="flex items-center gap-1.5 flex-wrap flex-1 min-w-0">
            <select
              value={selectedBot}
              onChange={(e) => {
                const next = e.target.value;
                const wasTeam = isTeamModeRef.current;
                if (next === TEAM_TARGET_ID) {
                  isTeamModeRef.current = true;
                  genRef.current += 1;
                  attachInFlightRef.current = null;
                  resetStreamState();
                } else {
                  isTeamModeRef.current = false;
                  if (wasTeam && activeCidRef.current) {
                    const resumeCid = activeCidRef.current;
                    genRef.current += 1;
                    const nextGen = genRef.current;
                    void loadSessionHistory(resumeCid, null, {
                      expectedGen: nextGen,
                      silent: true,
                    }).then(() => {
                      if (
                        mountedRef.current &&
                        !isReadonly &&
                        !isTeamModeRef.current &&
                        genRef.current === nextGen &&
                        activeCidRef.current === resumeCid &&
                        !streamingRef.current
                      ) {
                        void probeAndAttachActiveTurn(resumeCid, undefined);
                      }
                    });
                  }
                }
                setSelectedBot(next);
                onBotChange?.(next);
              }}
              disabled={isLocalStreaming}
              aria-label="选择工作台模式（Team 或单个 Bot）"
              title={
                isTeamMode
                  ? teamRoomMeta.isMirrorMode
                    ? `TG 工作群实时镜像（${
                        teamRoomMeta.defaultBotHandle
                          ? `默认 @${teamRoomMeta.defaultBotHandle} 总指挥接单`
                          : "默认总指挥接单"
                      }）`
                    : "Web 大厅（未绑定 TG 群）"
                  : `单 Bot 直连模式：${selectedBotDisplayName || selectedBot || "默认 Bot"}`
              }
              className={`h-7 rounded-md bg-slate-950 border px-2 text-xs focus:outline-none focus:border-sky-500 max-w-44 disabled:opacity-50 ${
                isTeamMode
                  ? "border-sky-500/50 text-sky-200 font-medium"
                  : "border-slate-800 text-slate-200"
              }`}
            >
              <option value={TEAM_TARGET_ID} className="bg-slate-950 text-sky-200">
                ✦ Team
              </option>
              {selectedBot &&
                !isTeamMode &&
                !orderedBots.some((b) => b.handle === selectedBot) && (
                  <option value={selectedBot} className="bg-slate-950 text-slate-200">
                    {selectedBot}
                  </option>
                )}
              {orderedBots.map((b) => (
                <option key={b.handle} value={b.handle} className="bg-slate-950 text-slate-200">
                  {b.online ? "● " : "○ "}
                  {b.display_name || b.handle}
                </option>
              ))}
            </select>

            {!isTeamMode && activeWorktree?.active && activeWorktree.worktree_id && (
              <span
                title={`当前会话已绑定隔离 Worktree：${activeWorktree.branch || activeWorktree.worktree_id}`}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-[10px] font-mono text-emerald-300 shrink-0 max-w-44 truncate"
              >
                <GitBranch className="w-3 h-3 shrink-0" />
                <span className="truncate">{activeWorktree.worktree_id}</span>
              </span>
            )}
            {isTeamMode ? (
              <div className="flex items-center gap-1.5 flex-wrap min-w-0">
                {teamRoomMeta.isMirrorMode ? (
                  <>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-[10px] font-medium text-emerald-300 shrink-0">
                      TG 工作群镜像
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-[10px] font-medium text-sky-300 truncate max-w-48">
                      {teamRoomMeta.defaultBotHandle
                        ? `默认 @${teamRoomMeta.defaultBotHandle} 总指挥接单`
                        : "默认总指挥接单"}
                    </span>
                  </>
                ) : (
                  <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/80 text-[10px] font-medium text-slate-300 shrink-0">
                    Web 大厅（未绑定 TG 群）
                  </span>
                )}
              </div>
            ) : (
              !compactHeader && (
                <>
                  <div className="inline-flex items-center h-7 rounded-md bg-slate-950 border border-slate-800 focus-within:border-sky-500 overflow-hidden max-w-48">
                    <span className="px-1.5 h-full inline-flex items-center text-[10px] font-medium text-slate-400 bg-slate-900/75 border-r border-slate-800/90 shrink-0">
                      供应商
                    </span>
                    <select
                      value={effectiveProvider}
                      onChange={(e) => handleProviderChange(e.target.value)}
                      disabled={isReadonly || streaming || parsedModels.length === 0 || !botConfigCanEdit || savingBotConfig}
                      aria-label="选择模型供应商"
                      title={isReadonly ? "只读权限禁止修改默认模型" : "模型供应商（切换将同步至 TG 默认模型）"}
                      className="h-full bg-transparent px-1.5 text-xs text-slate-200 focus:outline-none min-w-0 max-w-36 disabled:opacity-50"
                    >
                      <option value={ALL_PROVIDERS_ID} className="bg-slate-950 text-slate-200">
                        全部供应商
                      </option>
                      {providerOptions.map((prov) => (
                        <option
                          key={prov.id}
                          value={prov.id}
                          className="bg-slate-950 text-slate-200"
                        >
                          {prov.label} ({prov.count})
                        </option>
                      ))}
                    </select>
                  </div>

                  <select
                    value={selectedModel}
                    onChange={(e) => handleModelChange(e.target.value)}
                    disabled={isReadonly || streaming || !botConfigCanEdit || savingBotConfig}
                    aria-label="选择模型"
                    title={isReadonly ? "只读权限禁止修改默认模型" : "切换将同步写入 TG 默认模型"}
                    className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-48 disabled:opacity-50"
                  >
                    {(effectiveProvider === ALL_PROVIDERS_ID || !selectedModel) && (
                      <option value="">Bot 默认模型</option>
                    )}
                    {selectedModel && !filteredModels.some((m) => m.id === selectedModel) && (
                      <option value={selectedModel}>{selectedModel}</option>
                    )}
                    {filteredModels.map((m) => (
                      <option key={m.id} value={m.id}>
                        {effectiveProvider === ALL_PROVIDERS_ID ? m.rawLabel : m.displayName}
                      </option>
                    ))}
                  </select>

                  <select
                    value={selectedEffort}
                    onChange={(e) => handleEffortChange(e.target.value)}
                    disabled={isReadonly || streaming || !botConfigCanEdit || savingBotConfig}
                    aria-label="思考强度"
                    title={isReadonly ? "只读权限禁止修改思考强度" : "切换将同步写入 TG 默认思考强度"}
                    className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 disabled:opacity-50"
                  >
                    <option value="">默认强度</option>
                    {(meta?.efforts || ["low", "medium", "high", "xhigh", "max"]).map((ef) => (
                      <option key={ef} value={ef}>
                        {ef}
                      </option>
                    ))}
                  </select>
                </>
              )
            )}
          </div>

          {isTeamMode && (
            <button
              type="button"
              onClick={() => setTeamRefreshSignal((v) => v + 1)}
              title="刷新群聊镜像"
              aria-label="刷新群聊镜像"
              className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer shrink-0"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${teamRoomMeta.loading ? "animate-spin" : ""}`}
              />
            </button>
          )}

          {extraHeaderActions}
        </header>

        {isTeamMode ? (
          <RoomPanel
            lockedRoomId="lobby"
            hideHeader
            session={session}
            projectId={resolvedBackendProject}
            roomEvent={roomEvent}
            roomEvents={roomEvents}
            refreshSignal={teamRefreshSignal}
            pendingQuote={pendingQuote}
            onQuoteConsumed={handleTeamQuoteConsumed}
            onFocusInput={() => onFocusPane?.(paneId)}
            onRoomMetaChange={handleTeamRoomMetaChange}
            onSessionRevoked={onSessionRevoked}
          />
        ) : (
          <div className="relative flex-1 min-h-0 flex flex-col overflow-hidden" {...composerAtts.dragHandlers}>
            <DragDropOverlay visible={composerAtts.isDragging} />
            {isReadonly && (
              <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 shrink-0" />
                <span>只读权限（readonly）：可浏览会话历史，发送与中止操作已禁用。</span>
              </div>
            )}

            {streamDegraded && (
              <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-[11px] text-amber-200">
                并发 SSE 预算已满（3/3），本栏自动降级为全局事件与终态历史同步。
              </div>
            )}

            {errorBanner && (
              <div className="shrink-0 px-3 py-1.5 border-b border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {errorBanner}
                </span>
                <button
                  type="button"
                  onClick={() => setErrorBanner(null)}
                  className="text-rose-300 hover:text-rose-100 underline cursor-pointer shrink-0"
                >
                  关闭
                </button>
              </div>
            )}

            {resyncNeeded && activeCid && (
              <div className="shrink-0 px-3 py-1.5 border-b border-sky-500/30 bg-sky-500/10 text-xs text-sky-200 flex items-center justify-between gap-2">
                <span>实时事件流超出缓冲窗口，可重新加载最新持久化历史。</span>
                <button
                  type="button"
                  onClick={() => void loadSessionHistory(activeCid)}
                  className="px-2 py-0.5 rounded bg-sky-600 hover:bg-sky-500 text-white cursor-pointer"
                >
                  重新同步
                </button>
              </div>
            )}

            <div className="flex-1 min-h-0 overflow-y-auto px-3.5 py-3 space-y-3">
              {hasMoreHistory && activeCid && (
                <div className="flex justify-center">
                  <button
                    type="button"
                    disabled={historyLoading}
                    onClick={() => void loadSessionHistory(activeCid, nextBefore)}
                    className="px-3 py-1 rounded-full border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 cursor-pointer disabled:opacity-50"
                  >
                    {historyLoading ? "加载中…" : "加载更早消息"}
                  </button>
                </div>
              )}

              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center py-8 px-4">
                  <div className="h-10 w-10 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center text-sky-400 mb-2.5">
                    <Bot className="w-5 h-5" />
                  </div>
                  <h2 className="text-sm font-semibold text-slate-100">
                    {selectedBotDisplayName || effectiveBotDisplayName || "默认 Bot"} · 单 Bot 工作台
                  </h2>
                  <p className="text-xs text-slate-400 mt-1 max-w-sm">
                    直连该 Bot 一对一对话，可随时从顶栏切换回 Team 群聊镜像模式。
                  </p>
                </div>
              ) : (
                messages.map((msg) => {
                  const isUser = msg.role === "user";
                  const thinkOpen = Boolean(expandedThinking[msg.id]);
                  return (
                    <div key={msg.id} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                      <div
                        className={`max-w-[92%] md:max-w-[85%] rounded-2xl px-3.5 py-2.5 border ${
                          isUser
                            ? "bg-sky-600/20 border-sky-500/35 text-slate-100"
                            : "bg-slate-900/80 border-slate-800/90 text-slate-100"
                        }`}
                      >
                        {!isUser && (
                          <div className="flex items-center gap-1.5 mb-1.5 text-[11px] text-slate-400">
                            <Bot className="w-3.5 h-3.5 text-sky-400" />
                            <span>{selectedBotDisplayName || effectiveBot || "Assistant"}</span>
                            {msg.truncated && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px]">
                                已截断 (32 KiB)
                              </span>
                            )}
                          </div>
                        )}

                        {!isUser && msg.thinking && msg.thinking.trim() && (
                          <div className="mb-2 rounded-lg border border-slate-800 bg-slate-950/60">
                            <button
                              type="button"
                              onClick={() =>
                                setExpandedThinking((prev) => ({
                                  ...prev,
                                  [msg.id]: !prev[msg.id],
                                }))
                              }
                              className="w-full flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                            >
                              {thinkOpen ? (
                                <ChevronDown className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5" />
                              )}
                              <span>思考过程</span>
                            </button>
                            {thinkOpen && (
                              <div className="px-3 pb-2 text-xs text-slate-400 whitespace-pre-wrap break-words border-t border-slate-800/80 pt-2">
                                {msg.thinking}
                              </div>
                            )}
                          </div>
                        )}

                        {!isUser && msg.tool_calls && msg.tool_calls.length > 0 && (
                          <div className="mb-2 flex flex-wrap gap-1.5">
                            {msg.tool_calls.map((tc, idx) => (
                              <span
                                key={`${msg.id}-tc-${idx}`}
                                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                                  tc.active
                                    ? "border-sky-500/40 bg-sky-500/15 text-sky-300"
                                    : "border-slate-700/80 bg-slate-950/70 text-slate-300"
                                }`}
                              >
                                {tc.active ? (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                ) : (
                                  <Wrench className="w-3 h-3 text-slate-400" />
                                )}
                                <span>{tc.name}</span>
                                {typeof tc.duration_seconds === "number" && (
                                  <span className="text-slate-500">
                                    {tc.duration_seconds.toFixed(1)}s
                                  </span>
                                )}
                              </span>
                            ))}
                          </div>
                        )}

                        {isUser ? (
                          <div>
                            {msg.execution_mode === "interrupt" && (
                              <div className="mb-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-amber-500/15 border border-amber-500/35 text-[10px] font-medium text-amber-300">
                                <Zap className="w-2.5 h-2.5 fill-current" />
                                <span>
                                  {msg.interrupted_prev ? "已中断上一轮并马上执行" : "优先插队执行"}
                                </span>
                              </div>
                            )}
                            <MessageAttachmentsDisplay
                              attachments={msg.attachments}
                              contextFiles={msg.context_files}
                              onPreviewImage={(src, name) => setLightboxImage({ src, name })}
                            />
                            {msg.content && (
                              <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                                {msg.content}
                              </div>
                            )}
                          </div>
                        ) : msg.content ? (
                          <SafeMarkdown content={msg.content} />
                        ) : (
                          <div className="inline-flex items-center gap-2 text-xs text-slate-400">
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-400" />
                            <span>{statusNotice || "正在生成…"}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
              <div ref={timelineEndRef} />
            </div>

            <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5 space-y-2">
              {streaming && (remoteSyncSource || statusNotice) && (
                <div
                  className={`flex items-center gap-2 text-[11px] ${
                    statusNotice?.startsWith("⚡") ? "text-amber-300" : "text-sky-300"
                  }`}
                >
                  <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                  {remoteSyncSource === "tg" && (
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 text-[10px] font-medium shrink-0">
                      TG 实时同步中
                    </span>
                  )}
                  <span className="truncate">{statusNotice || "正在实时同步…"}</span>
                </div>
              )}

              {!isReadonly && pendingQueue.length > 0 && (
                <div className="rounded-xl border border-slate-800/90 bg-slate-950/90 px-2.5 py-1.5 space-y-1">
                  <div className="flex items-center justify-between gap-2 text-[10px] text-slate-400">
                    <span className="inline-flex items-center gap-1.5 font-medium text-sky-300">
                      <ListPlus className="w-3 h-3" />
                      <span>待执行队列 ({pendingQueue.length})</span>
                      <span className="text-slate-500 font-normal hidden sm:inline">
                        当前轮结束后自动按序执行
                      </span>
                    </span>
                    {pendingQueue.length > 1 && (
                      <button
                        type="button"
                        onClick={clearPendingQueue}
                        className="text-slate-400 hover:text-rose-300 cursor-pointer"
                      >
                        清空
                      </button>
                    )}
                  </div>
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {pendingQueue.map((qItem, qIdx) => (
                      <div
                        key={qItem.id}
                        className="flex items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-900/75 px-2 py-1 text-xs"
                      >
                        <span className="font-mono text-[10px] text-slate-500 shrink-0">
                          #{qIdx + 1}
                        </span>
                        <span
                          className="flex-1 min-w-0 truncate text-slate-200"
                          title={qItem.displayText}
                        >
                          {qItem.displayText}
                        </span>
                        {(qItem.attachments.length > 0 || qItem.contextFiles.length > 0) && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400 shrink-0">
                            {qItem.attachments.length + qItem.contextFiles.length} 附件
                          </span>
                        )}
                        <button
                          type="button"
                          disabled={interrupting}
                          onClick={() => handleRunQueuedNow(qItem.id)}
                          title="中断当前轮次并立即执行此条指令"
                          className="h-6 px-2 rounded-md bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-300 text-[11px] font-medium inline-flex items-center gap-1 shrink-0 cursor-pointer disabled:opacity-40"
                        >
                          <Zap className="w-3 h-3 fill-current" />
                          <span>马上执行</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveQueuedItem(qItem.id)}
                          title="移出队列"
                          aria-label="取消该排队消息"
                          className="h-6 w-6 rounded-md hover:bg-slate-800 text-slate-400 hover:text-rose-300 inline-flex items-center justify-center shrink-0 cursor-pointer"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="relative rounded-2xl border border-slate-800 bg-slate-950/95 focus-within:border-sky-500/70 transition-colors p-2">
                {!isReadonly && (
                  <WorkspaceFilePickerPopover
                    open={filePickerMode !== null}
                    projectId={resolvedBackendProject}
                    query={filePickerQuery}
                    showSearchInput={filePickerMode === "button"}
                    selectedFiles={composerAtts.contextFiles}
                    activeIndex={filePickerActiveIdx}
                    onActiveIndexChange={setFilePickerActiveIdx}
                    onQueryChange={setFilePickerQuery}
                    onSelect={handleSelectWorkspaceFile}
                    onClose={() => {
                      setFilePickerMode(null);
                      setFilePickerQuery("");
                      setFilePickerTriggerStart(-1);
                    }}
                    onVisibleFilesChange={(files) => {
                      filePickerVisibleRef.current = files;
                      if (filePickerActiveIdx >= files.length && files.length > 0) {
                        setFilePickerActiveIdx(0);
                      }
                    }}
                  />
                )}

                <ComposerAttachmentTray
                  attachments={composerAtts.pendingAttachments}
                  contextFiles={composerAtts.contextFiles}
                  uploadError={composerAtts.uploadError}
                  onDismissError={() => composerAtts.setUploadError(null)}
                  onRemoveAttachment={composerAtts.removeAttachment}
                  onRemoveContextFile={composerAtts.removeContextFile}
                  onPreviewImage={(src, name) => setLightboxImage({ src, name })}
                />

                <textarea
                  ref={composerTextareaRef}
                  rows={2}
                  value={draft}
                  disabled={isReadonly || interrupting}
                  onFocus={() => onFocusPane?.(paneId)}
                  onPaste={composerAtts.handlePaste}
                  onChange={(e) => {
                    const val = e.target.value;
                    setDraft(val);
                    syncInlineAtTrigger(val, e.target.selectionStart ?? val.length);
                  }}
                  onKeyDown={(e) => {
                    if (filePickerMode === "inline") {
                      const list = filePickerVisibleRef.current;
                      if (e.key === "ArrowDown") {
                        e.preventDefault();
                        if (list.length > 0) {
                          setFilePickerActiveIdx((idx) => (idx + 1) % list.length);
                        }
                        return;
                      }
                      if (e.key === "ArrowUp") {
                        e.preventDefault();
                        if (list.length > 0) {
                          setFilePickerActiveIdx((idx) => (idx - 1 + list.length) % list.length);
                        }
                        return;
                      }
                      if ((e.key === "Enter" || e.key === "Tab") && list.length > 0) {
                        e.preventDefault();
                        const hit = list[filePickerActiveIdx] || list[0];
                        if (hit) handleSelectWorkspaceFile(hit);
                        return;
                      }
                      if (e.key === "Escape") {
                        e.preventDefault();
                        setFilePickerMode(null);
                        setFilePickerQuery("");
                        setFilePickerTriggerStart(-1);
                        return;
                      }
                    }
                    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "Enter") {
                      e.preventDefault();
                      void handleSend("interrupt");
                      return;
                    }
                    if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
                      e.preventDefault();
                      void handleSend("queue");
                    }
                  }}
                  placeholder={
                    isReadonly
                      ? "只读角色已禁用输入"
                      : streaming
                        ? "Bot 正在回复，可继续输入下一条指令（Enter 加入排队 · Ctrl/Cmd+Shift+Enter ⚡马上执行）…"
                        : `向「${selectedBotDisplayName || selectedBot || "默认 Bot"}」发送指令、拖拽/粘贴图片或输入 @ 引用文件…`
                  }
                  className="w-full resize-none bg-transparent px-1.5 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:opacity-50"
                />

                <div className="mt-1.5 pt-1.5 border-t border-slate-800/75 flex items-center justify-between gap-2 flex-wrap sm:flex-nowrap">
                  <div className="flex items-center gap-1 min-w-0">
                    {!isReadonly && (
                      <>
                        <input
                          ref={composerFileInputRef}
                          type="file"
                          multiple
                          accept={FILE_INPUT_ACCEPT}
                          className="hidden"
                          onChange={(e) => {
                            if (e.target.files && e.target.files.length > 0) {
                              composerAtts.addFiles(e.target.files);
                            }
                            e.target.value = "";
                          }}
                        />
                        <button
                          type="button"
                          disabled={interrupting}
                          title={SUPPORTED_FORMATS_TOOLTIP}
                          aria-label="添加图片或文件"
                          onClick={() => composerFileInputRef.current?.click()}
                          className="h-7 px-2 rounded-lg border border-slate-800 bg-slate-900/90 hover:bg-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 text-xs inline-flex items-center gap-1 cursor-pointer disabled:opacity-40"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          <span className="hidden sm:inline">文件/图片</span>
                        </button>
                        <button
                          type="button"
                          disabled={interrupting || !resolvedBackendProject}
                          title={
                            resolvedBackendProject
                              ? `引用项目「${resolvedBackendProject}」中的工作区文件（或直接输入 @）`
                              : "请先选择一个允许的项目"
                          }
                          aria-label="引用工作区文件"
                          onClick={() => {
                            if (filePickerMode === "button") {
                              setFilePickerMode(null);
                            } else {
                              setFilePickerQuery("");
                              setFilePickerActiveIdx(0);
                              setFilePickerMode("button");
                            }
                          }}
                          className={`h-7 px-2 rounded-lg border text-xs inline-flex items-center gap-1 cursor-pointer disabled:opacity-40 ${
                            filePickerMode !== null
                              ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                              : "border-slate-800 bg-slate-900/90 hover:bg-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100"
                          }`}
                        >
                          <AtSign className="w-3.5 h-3.5" />
                          <span className="hidden sm:inline">文件</span>
                        </button>
                        {!activeCid && (
                          <button
                            type="button"
                            disabled={interrupting || !resolvedBackendProject}
                            onClick={() => setWorktreeEnabled((v) => !v)}
                            title={
                              worktreeEnabled
                                ? "已开启独立 Git Worktree 隔离（首轮自动创建 agy-studio/<id> 分支）"
                                : "为新会话启用独立 Git Worktree 隔离（不污染主工作区）"
                            }
                            aria-pressed={worktreeEnabled}
                            className={`h-7 px-2 rounded-lg border text-xs inline-flex items-center gap-1 cursor-pointer disabled:opacity-40 ${
                              worktreeEnabled
                                ? "border-emerald-500/55 bg-emerald-500/15 text-emerald-200"
                                : "border-slate-800 bg-slate-900/90 hover:bg-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100"
                            }`}
                          >
                            <GitBranch className="w-3.5 h-3.5" />
                            <span className="hidden sm:inline">Worktree</span>
                          </button>
                        )}
                        <span
                          title={SUPPORTED_FORMATS_TOOLTIP}
                          className="hidden xl:inline text-[10px] text-slate-500 truncate ml-1 select-none"
                        >
                          {streaming
                            ? "Enter 加入排队 · Ctrl/Cmd+Shift+Enter ⚡马上执行"
                            : "支持图片 / PDF / 音视频 / 代码 · 拖拽或 Ctrl+V 贴图"}
                        </span>
                      </>
                    )}
                  </div>

                  {!isReadonly && (
                    <div className="flex items-center gap-1.5 shrink-0 ml-auto">
                      {composerAtts.isUploading && (
                        <span className="text-[11px] text-sky-300 inline-flex items-center gap-1">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          上传中
                        </span>
                      )}
                      {streaming ? (
                        <>
                          {isLocalStreaming && (
                            <button
                              type="button"
                              onClick={() => void handleAbort()}
                              title="仅停止当前正在生成的轮次"
                              className="h-8 px-2.5 rounded-xl bg-rose-600/90 hover:bg-rose-500 text-white text-xs font-medium inline-flex items-center gap-1 shrink-0 cursor-pointer"
                            >
                              <Square className="w-3 h-3 fill-current" />
                              <span className="hidden sm:inline">停止</span>
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={
                              interrupting ||
                              composerAtts.isUploading ||
                              (!draft.trim() &&
                                composerAtts.readyAttachmentIds.length === 0 &&
                                composerAtts.contextFiles.length === 0)
                            }
                            onClick={() => void handleSend("queue")}
                            title="加入待执行队列，当前轮结束后自动发送（Enter）"
                            className="h-8 px-2.5 sm:px-3 rounded-xl border border-sky-500/45 bg-sky-600/20 hover:bg-sky-600/30 disabled:opacity-40 text-sky-200 text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                          >
                            <ListPlus className="w-3.5 h-3.5" />
                            <span>加入排队</span>
                          </button>
                          <button
                            type="button"
                            disabled={
                              interrupting ||
                              composerAtts.isUploading ||
                              (!draft.trim() &&
                                composerAtts.readyAttachmentIds.length === 0 &&
                                composerAtts.contextFiles.length === 0)
                            }
                            onClick={() => void handleSend("interrupt")}
                            title="中断当前轮次并在同一对话上下文立即执行（Ctrl/Cmd+Shift+Enter）"
                            className="h-8 px-2.5 sm:px-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-slate-950 text-xs font-semibold inline-flex items-center gap-1 shrink-0 cursor-pointer shadow-sm"
                          >
                            {interrupting ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Zap className="w-3.5 h-3.5 fill-current" />
                            )}
                            <span>马上执行</span>
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          disabled={
                            interrupting ||
                            composerAtts.isUploading ||
                            (!draft.trim() &&
                              composerAtts.readyAttachmentIds.length === 0 &&
                              composerAtts.contextFiles.length === 0)
                          }
                          onClick={() => void handleSend("queue")}
                          className="h-8 px-3 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                        >
                          <Send className="w-3.5 h-3.5" />
                          发送
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </footer>
            <ImageLightboxModal
              image={lightboxImage}
              onClose={() => setLightboxImage(null)}
            />
          </div>
        )}
      </section>

      {/* Floating Popover Menus (Filter / Project / Session) - fixed positioned to prevent sidebar clipping */}
      {openMenu && (() => {
        if (openMenu.kind === "filter") {
          return (
            <div
              ref={floatingMenuRef}
              role="menu"
              style={{ top: openMenu.top, left: openMenu.left }}
              className="fixed z-50 w-52 rounded-xl border border-slate-700/80 bg-slate-900 py-1.5 shadow-2xl"
            >
              <div className="px-3 py-1 text-[10px] font-medium uppercase tracking-wider text-slate-500">
                筛选对话
              </div>
              <button
                type="button"
                role="menuitemcheckbox"
                aria-checked={showArchived}
                onClick={() => applySetShowArchived(!showArchived)}
                className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center justify-between gap-2 transition-colors cursor-pointer"
              >
                <span className="inline-flex items-center gap-2 min-w-0">
                  <Archive className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span className="truncate">显示已归档对话</span>
                </span>
                <span className="inline-flex items-center gap-1.5 shrink-0">
                  <span className="text-[10px] font-mono text-slate-500 tabular-nums">
                    {archivedVisibleCount}
                  </span>
                  <span
                    className={`w-3.5 h-3.5 rounded inline-flex items-center justify-center border ${
                      showArchived
                        ? "border-cyan-400 bg-cyan-500/20 text-cyan-300"
                        : "border-slate-700 bg-slate-950/60"
                    }`}
                  >
                    {showArchived && <Check className="w-2.5 h-2.5" />}
                  </span>
                </span>
              </button>

              <div className="border-t border-slate-800 my-1" />

              <button
                type="button"
                role="menuitemcheckbox"
                aria-checked={filterPinnedOnly}
                onClick={() => setFilterPinnedOnly((v) => !v)}
                className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center justify-between gap-2 transition-colors cursor-pointer"
              >
                <span className="inline-flex items-center gap-2 min-w-0">
                  <Pin className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span className="truncate">仅看置顶</span>
                </span>
                <span
                  className={`w-3.5 h-3.5 rounded inline-flex items-center justify-center border shrink-0 ${
                    filterPinnedOnly
                      ? "border-cyan-400 bg-cyan-500/20 text-cyan-300"
                      : "border-slate-700 bg-slate-950/60"
                  }`}
                >
                  {filterPinnedOnly && <Check className="w-2.5 h-2.5" />}
                </span>
              </button>

              <button
                type="button"
                role="menuitemcheckbox"
                aria-checked={filterUnreadOnly}
                onClick={() => setFilterUnreadOnly((v) => !v)}
                className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center justify-between gap-2 transition-colors cursor-pointer"
              >
                <span className="inline-flex items-center gap-2 min-w-0">
                  <MessageSquare className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span className="truncate">仅看未读</span>
                </span>
                <span
                  className={`w-3.5 h-3.5 rounded inline-flex items-center justify-center border shrink-0 ${
                    filterUnreadOnly
                      ? "border-cyan-400 bg-cyan-500/20 text-cyan-300"
                      : "border-slate-700 bg-slate-950/60"
                  }`}
                >
                  {filterUnreadOnly && <Check className="w-2.5 h-2.5" />}
                </span>
              </button>

              {hasAnyFilterActive && (
                <>
                  <div className="border-t border-slate-800 my-1" />
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      applySetShowArchived(false);
                      setFilterPinnedOnly(false);
                      setFilterUnreadOnly(false);
                      setOpenMenu(null);
                    }}
                    className="w-full px-3 py-1.5 text-left text-[11px] text-cyan-400 hover:bg-slate-800/80 transition-colors cursor-pointer"
                  >
                    重置全部筛选
                  </button>
                </>
              )}
            </div>
          );
        }

        if (openMenu.kind === "project") {
          const group = projectGroups.find((g) => g.id === openMenu.groupId);
          if (!group) return null;
          const hasOverflow = group.sessions.length > DEFAULT_VISIBLE_SESSIONS_PER_PROJECT;
          const listExpanded = Boolean(expandedSessionLists[group.id]);
          const canNewChat = !isReadonly && group.kind !== "temp" && Boolean(group.projectId);

          return (
            <div
              ref={floatingMenuRef}
              role="menu"
              style={{ top: openMenu.top, left: openMenu.left }}
              className="fixed z-50 w-44 rounded-xl border border-slate-700/80 bg-slate-900 py-1 shadow-2xl"
            >
              {!isReadonly && (
                <button
                  type="button"
                  role="menuitem"
                  onClick={() =>
                    handleOpenRenameModal({
                      kind: "project",
                      groupId: group.id,
                      currentName: group.name,
                      originalName: group.rawName,
                    })
                  }
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Pencil className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span>重命名</span>
                </button>
              )}

              {canNewChat && (
                <button
                  type="button"
                  role="menuitem"
                  disabled={isLocalStreaming}
                  onClick={() => {
                    setOpenMenu(null);
                    handleNewChat(group.projectId || undefined, group.id);
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 disabled:opacity-40 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span>新建对话</span>
                </button>
              )}

              {hasOverflow && (
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setOpenMenu(null);
                    setProjectExpandOverrides((prev) => ({ ...prev, [group.id]: true }));
                    setExpandedSessionLists((prev) => ({
                      ...prev,
                      [group.id]: !listExpanded,
                    }));
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  {listExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  )}
                  <span>{listExpanded ? "收起折叠" : "展开全部"}</span>
                </button>
              )}

              {!isReadonly && (
                <>
                  <div className="border-t border-slate-800 my-1" />
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setOpenMenu(null);
                      setDeleteTarget({
                        kind: "project",
                        groupId: group.id,
                        projectId: group.projectId,
                        name: group.name,
                        sessionCount: group.sessions.length,
                        sessionCids: group.sessions.map((s) => s.cid),
                        isCustom: Boolean(group.isCustom),
                        groupKind: group.kind,
                      });
                    }}
                    className="w-full px-3 py-1.5 text-left text-xs text-rose-400 hover:bg-rose-500/15 flex items-center gap-2.5 transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5 shrink-0" />
                    <span>删除项目</span>
                  </button>
                </>
              )}
            </div>
          );
        }

        const group = projectGroups.find((g) => g.id === openMenu.groupId);
        const item =
          group?.sessions.find((s) => s.cid === openMenu.cid) ||
          sessions.find((s) => s.cid === openMenu.cid);
        if (!item) return null;
        const originalTitle = formatSessionDisplayTitle(item);
        const displayTitle = sessionRenames[item.cid] || originalTitle;
        const isPinned = pinnedSessionCidSet.has(item.cid);
        const isUnread = unreadSessionCidSet.has(item.cid);
        const isArchived = archivedSessionCidSet.has(item.cid);

        return (
          <div
            ref={floatingMenuRef}
            role="menu"
            style={{ top: openMenu.top, left: openMenu.left }}
            className="fixed z-50 w-44 rounded-xl border border-slate-700/80 bg-slate-900 py-1 shadow-2xl"
          >
            {!isReadonly && (
              <>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() =>
                    handleOpenRenameModal({
                      kind: "session",
                      cid: item.cid,
                      currentTitle: displayTitle,
                      originalTitle,
                    })
                  }
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Pencil className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span>重命名</span>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setOpenMenu(null);
                    applyTogglePinSession(item.cid);
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Pin
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isPinned ? "text-cyan-400" : "text-slate-400"
                    }`}
                  />
                  <span>{isPinned ? "取消置顶" : "置顶"}</span>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setOpenMenu(null);
                    applySetSessionUnread(item.cid, !isUnread);
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <MessageSquare
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isUnread ? "text-cyan-400" : "text-slate-400"
                    }`}
                  />
                  <span>{isUnread ? "标为已读" : "标为未读"}</span>
                </button>

                <div className="border-t border-slate-800 my-1" />
              </>
            )}

            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setOpenMenu(null);
                void handleCopySessionInfo(item, displayTitle);
              }}
              className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5 shrink-0 text-slate-400" />
              <span>复制</span>
            </button>

            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setOpenMenu(null);
                if (!onSplitOpenSession) {
                  showSidebarToast("当前视图暂不支持分屏打开");
                  return;
                }
                const res = onSplitOpenSession(item);
                if (res.message) {
                  showSidebarToast(res.message);
                }
              }}
              className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
            >
              <Columns2 className="w-3.5 h-3.5 shrink-0 text-slate-400" />
              <span>分屏打开</span>
            </button>

            {!isReadonly && (
              <>
                <div className="border-t border-slate-800 my-1" />

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setOpenMenu(null);
                    applyToggleArchiveSession(item.cid);
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-slate-800/80 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Archive
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isArchived ? "text-cyan-400" : "text-slate-400"
                    }`}
                  />
                  <span>{isArchived ? "取消归档" : "归档"}</span>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setOpenMenu(null);
                    setDeleteTarget({
                      kind: "session",
                      cid: item.cid,
                      title: displayTitle,
                      projectName: group?.name || "未归类对话",
                    });
                  }}
                  className="w-full px-3 py-1.5 text-left text-xs text-rose-400 hover:bg-rose-500/15 flex items-center gap-2.5 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5 shrink-0" />
                  <span>删除</span>
                </button>
              </>
            )}
          </div>
        );
      })()}

      {renameTarget && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={`rename-modal-title-${paneId}`}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              handleCloseRenameModal();
            }
          }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800/90 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="h-7 w-7 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-400 inline-flex items-center justify-center shrink-0">
                  <Pencil className="w-4 h-4" />
                </span>
                <h3
                  id={`rename-modal-title-${paneId}`}
                  className="text-sm font-semibold text-slate-100 truncate"
                >
                  {renameTarget.kind === "project" ? "重命名项目" : "重命名对话"}
                </h3>
              </div>
              <button
                type="button"
                onClick={handleCloseRenameModal}
                aria-label="关闭弹窗"
                className="h-7 w-7 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 inline-flex items-center justify-center transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmitRename} className="p-4 space-y-3.5">
              <div>
                <label
                  htmlFor={`rename-input-${paneId}`}
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  {renameTarget.kind === "project" ? "项目显示名称" : "对话显示标题"}
                </label>
                <input
                  ref={renameInputRef}
                  id={`rename-input-${paneId}`}
                  type="text"
                  maxLength={
                    renameTarget.kind === "project"
                      ? MAX_PROJECT_NAME_LEN
                      : MAX_SESSION_TITLE_LEN
                  }
                  value={renameInputValue}
                  onChange={(e) => {
                    setRenameInputValue(e.target.value);
                    if (renameError) setRenameError(null);
                  }}
                  placeholder={
                    renameTarget.kind === "project"
                      ? renameTarget.originalName
                      : renameTarget.originalTitle
                  }
                  className="w-full h-9 rounded-lg bg-slate-950 border border-slate-800 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                />
                {(renameTarget.kind === "project"
                  ? renameTarget.currentName !== renameTarget.originalName
                  : renameTarget.currentTitle !== renameTarget.originalTitle) && (
                  <div className="mt-1.5 flex items-center justify-between gap-2 text-[11px] text-slate-500">
                    <span className="truncate">
                      原名称：
                      {renameTarget.kind === "project"
                        ? renameTarget.originalName
                        : renameTarget.originalTitle}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        if (renameTarget.kind === "project") {
                          applyRenameProject(renameTarget.groupId, null);
                        } else {
                          applyRenameSession(renameTarget.cid, null);
                        }
                        handleCloseRenameModal();
                      }}
                      className="shrink-0 text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                    >
                      恢复默认
                    </button>
                  </div>
                )}
              </div>

              {renameError && (
                <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-xs text-rose-200 flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
                  <span>{renameError}</span>
                </div>
              )}

              <div className="pt-1 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={handleCloseRenameModal}
                  className="h-8 px-3 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
                >
                  取消
                </button>
                <button
                  type="submit"
                  className="h-8 px-3.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white transition-colors cursor-pointer"
                >
                  保存
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {createProjectModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={`create-project-title-${paneId}`}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              handleCloseCreateProjectModal();
            }
          }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800/90 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="h-7 w-7 rounded-lg bg-sky-500/15 border border-sky-500/30 text-sky-400 inline-flex items-center justify-center shrink-0">
                  <Plus className="w-4 h-4" />
                </span>
                <h3
                  id={`create-project-title-${paneId}`}
                  className="text-sm font-semibold text-slate-100 truncate"
                >
                  新增项目
                </h3>
              </div>
              <button
                type="button"
                onClick={handleCloseCreateProjectModal}
                aria-label="关闭弹窗"
                className="h-7 w-7 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 inline-flex items-center justify-center transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSubmitCreateProject} className="p-4 space-y-3.5">
              <div>
                <label
                  htmlFor={`new-project-name-${paneId}`}
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  项目名称 <span className="text-rose-400">*</span>
                </label>
                <input
                  ref={createProjectNameInputRef}
                  id={`new-project-name-${paneId}`}
                  type="text"
                  maxLength={MAX_PROJECT_NAME_LEN}
                  value={newProjectName}
                  onChange={(e) => {
                    setNewProjectName(e.target.value);
                    if (createProjectError) setCreateProjectError(null);
                  }}
                  placeholder="例如：数据看板 / my-web-app"
                  className="w-full h-9 rounded-lg bg-slate-950 border border-slate-800 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label
                  htmlFor={`new-project-slug-${paneId}`}
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  项目标识 <span className="text-slate-500 font-normal">（可选）</span>
                </label>
                <input
                  id={`new-project-slug-${paneId}`}
                  type="text"
                  maxLength={64}
                  value={newProjectSlug}
                  onChange={(e) => {
                    setNewProjectSlug(e.target.value);
                    if (createProjectError) setCreateProjectError(null);
                  }}
                  placeholder={
                    buildAsciiKebabSlug(newProjectName.trim())
                      ? `留空自动生成：${buildAsciiKebabSlug(newProjectName.trim())}`
                      : "留空自动生成（如 proj-xxxxxx）"
                  }
                  className="w-full h-9 rounded-lg bg-slate-950 border border-slate-800 px-3 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                />
                <p className="mt-1 text-[11px] text-slate-500">
                  仅支持英文、数字、点、下划线和连字符；留空将按名称自动生成合法 slug。
                </p>
              </div>

              {createProjectError && (
                <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-xs text-rose-200 flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
                  <span>{createProjectError}</span>
                </div>
              )}

              <div className="pt-1 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={handleCloseCreateProjectModal}
                  className="h-8 px-3 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
                >
                  取消
                </button>
                <button
                  type="submit"
                  className="h-8 px-3.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white transition-colors cursor-pointer"
                >
                  创建项目
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deleteTarget && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={`delete-confirm-title-${paneId}`}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setDeleteTarget(null);
            }
          }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800/90 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="h-7 w-7 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-400 inline-flex items-center justify-center shrink-0">
                  <Trash2 className="w-4 h-4" />
                </span>
                <h3
                  id={`delete-confirm-title-${paneId}`}
                  className="text-sm font-semibold text-slate-100 truncate"
                >
                  {deleteTarget.kind === "project" ? "删除项目" : "删除对话"}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                aria-label="关闭弹窗"
                className="h-7 w-7 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 inline-flex items-center justify-center transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-2.5">
              {deleteTarget.kind === "project" ? (
                <>
                  <p className="text-sm text-slate-100 break-words">
                    确定要删除项目「<span className="font-semibold text-white">{deleteTarget.name}</span>」吗？
                  </p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    将从工作台列表中移除该项目及其 {deleteTarget.sessionCount} 条对话记录（不会删除本地磁盘代码文件）。
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm text-slate-100 break-words">
                    确定要删除对话「<span className="font-semibold text-white">{deleteTarget.title}</span>」吗？
                  </p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    所属项目：{deleteTarget.projectName}。删除后将从工作台会话列表中移除。
                  </p>
                </>
              )}

              <div className="pt-3 flex items-center justify-end gap-2">
                <button
                  ref={deleteCancelBtnRef}
                  type="button"
                  onClick={() => setDeleteTarget(null)}
                  className="h-8 px-3 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
                >
                  取消
                </button>
                <button
                  type="button"
                  onClick={handleConfirmDelete}
                  className="h-8 px-3.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-medium text-white transition-colors cursor-pointer"
                >
                  确认删除
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export interface WorkspaceViewProps {
  session: StudioSession;
  compactMode: boolean;
  browserOwner: BrowserOwner;
  wsSessionEpoch: number;
  sessionSyncEvent?: SessionUpdatedEvent | null;
  roomEvent?: RoomLiveEvent | null;
  roomEvents?: RoomLiveEvent[];
  botsEventVer?: number;
  gatewaysEventVer?: number;
  workbenchStateEventVer?: number;
  jobsEventVer: number;
  attentionEventVer: number;
  onClaimBrowserOwner: (next: BrowserOwner) => void;
  onToggleBrowserDrawer: () => void;
  onPendingAttentionCount?: (count: number) => void;
  onRoleChanged?: (role: "admin" | "readonly") => void;
  onSessionRevoked: (reason: string) => void;
}

export function WorkspaceView({
  session,
  compactMode,
  browserOwner,
  wsSessionEpoch,
  sessionSyncEvent,
  roomEvent,
  roomEvents,
  botsEventVer = 0,
  gatewaysEventVer = 0,
  workbenchStateEventVer = 0,
  jobsEventVer,
  attentionEventVer,
  onClaimBrowserOwner,
  onToggleBrowserDrawer: _onToggleBrowserDrawer,
  onPendingAttentionCount,
  onRoleChanged,
  onSessionRevoked,
}: WorkspaceViewProps) {
  const isReadonly = session.role !== "admin";
  const { activeCount: activeChatStreams } = useStreamBudget();

  const [isDesktopViewport, setIsDesktopViewport] = useState<boolean>(() =>
    typeof window !== "undefined" ? window.innerWidth >= 768 : true,
  );
  const [layout, setLayout] = useState<StoredWorkbenchPrefs>(() => loadWorkbenchPrefs());
  const [filesDrawerOpen, setFilesDrawerOpen] = useState(false);
  const [paneActiveCids, setPaneActiveCids] = useState<Record<string, string | null>>({});
  const [paneActiveWorktreeIds, setPaneActiveWorktreeIds] = useState<Record<string, string | null>>({});
  const [jobsAttentionSubTab, setJobsAttentionSubTab] = useState<Record<string, "attention" | "jobs">>({});
  const [lastFocusedChatPaneId, setLastFocusedChatPaneId] = useState<string>("pane-1");
  const [quoteMap, setQuoteMap] = useState<Record<string, PendingQuotePayload | null>>({});
  const [openSessionMap, setOpenSessionMap] = useState<
    Record<string, PendingOpenSessionPayload | null>
  >({});
  const [handoffPendingPaneId, setHandoffPendingPaneId] = useState<string | null>(null);

  const quoteCounterRef = useRef(0);
  const openSessionCounterRef = useRef(0);
  const mountedRef = useRef(true);
  const layoutRef = useRef<StoredWorkbenchPrefs>(layout);
  layoutRef.current = layout;

  const workbenchServerVerRef = useRef<number>(0);
  const workbenchFetchSeqRef = useRef<number>(0);
  const workbenchInitialSyncDoneRef = useRef<boolean>(false);
  const workbenchSyncInFlightRef = useRef<boolean>(false);
  const workbenchPendingStateRef = useRef<WorkbenchSidebarState | null>(null);

  const applyServerSidebarState = useCallback((remoteState: WorkbenchSidebarState) => {
    const clean = sanitizeSidebarState(remoteState);
    setLayout((prev) => ({
      ...prev,
      customProjects: clean.customProjects,
      projectRenames: clean.projectRenames,
      hiddenProjectIds: clean.hiddenProjectIds,
      hiddenSessionCids: clean.hiddenSessionCids,
      pinnedSessionCids: clean.pinnedSessionCids,
      archivedSessionCids: clean.archivedSessionCids,
      unreadSessionCids: clean.unreadSessionCids,
      sessionRenames: clean.sessionRenames,
      showArchived: clean.showArchived,
    }));
  }, []);

  const flushSidebarSyncQueue = useCallback(async () => {
    if (isReadonly || workbenchSyncInFlightRef.current) return;
    workbenchSyncInFlightRef.current = true;
    try {
      while (mountedRef.current && workbenchPendingStateRef.current) {
        const nextState = workbenchPendingStateRef.current;
        workbenchPendingStateRef.current = null;
        try {
          const saved = await updateWorkbenchState({
            expected_version: workbenchServerVerRef.current,
            state: nextState,
          });
          if (!mountedRef.current) return;
          workbenchServerVerRef.current = saved.version;
          if (!workbenchPendingStateRef.current) {
            applyServerSidebarState(saved.state);
          }
        } catch (err) {
          if (!mountedRef.current) return;
          if (err instanceof StudioApiError && err.status === 409) {
            let latestVer =
              typeof err.data?.version === "number" && Number.isFinite(err.data.version)
                ? err.data.version
                : workbenchServerVerRef.current;
            let latestState = err.data?.state ? sanitizeSidebarState(err.data.state) : null;
            if (!latestState) {
              try {
                const fetched = await fetchWorkbenchState();
                latestVer = fetched.version;
                latestState = sanitizeSidebarState(fetched.state);
              } catch {
                break;
              }
            }
            if (!mountedRef.current) return;
            workbenchServerVerRef.current = latestVer;
            const localToMerge = workbenchPendingStateRef.current || nextState;
            workbenchPendingStateRef.current = null;
            const merged = mergeSidebarStates(latestState, localToMerge);
            applyServerSidebarState(merged);
            try {
              const retried = await updateWorkbenchState({
                expected_version: latestVer,
                state: merged,
              });
              if (!mountedRef.current) return;
              workbenchServerVerRef.current = retried.version;
              if (!workbenchPendingStateRef.current) {
                applyServerSidebarState(retried.state);
              }
            } catch (retryErr) {
              if (
                retryErr instanceof StudioApiError &&
                (retryErr.status === 401 || retryErr.status === 403) &&
                retryErr.source === "studio_auth"
              ) {
                onSessionRevoked(retryErr.message || "会话已失效，请重新登录");
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
              onSessionRevoked(err.message || "会话已失效，请重新登录");
              return;
            }
            break;
          }
        }
      }
    } finally {
      workbenchSyncInFlightRef.current = false;
    }
  }, [applyServerSidebarState, isReadonly, onSessionRevoked]);

  const updateSidebarAndSync = useCallback(
    (updater: (prev: StoredWorkbenchPrefs) => StoredWorkbenchPrefs) => {
      setLayout((prev) => {
        const next = updater(prev);
        if (next === prev) return prev;
        if (!isReadonly) {
          workbenchPendingStateRef.current = extractSidebarState(next);
          void flushSidebarSyncQueue();
        }
        return next;
      });
    },
    [flushSidebarSyncQueue, isReadonly],
  );

  // Initial server hydration + non-destructive localStorage migration + cross-device SSE refresh (C6)
  useEffect(() => {
    const seq = ++workbenchFetchSeqRef.current;
    void fetchWorkbenchState()
      .then((res) => {
        if (!mountedRef.current || workbenchFetchSeqRef.current !== seq) return;
        const serverState = sanitizeSidebarState(res.state);
        if (res.version > 0) {
          workbenchInitialSyncDoneRef.current = true;
          const isNewer = res.version >= workbenchServerVerRef.current;
          workbenchServerVerRef.current = Math.max(workbenchServerVerRef.current, res.version);
          if (isNewer && !workbenchSyncInFlightRef.current && !workbenchPendingStateRef.current) {
            applyServerSidebarState(serverState);
          }
          return;
        }

        // Server uninitialized (`version === 0`): only admin with non-empty local sidebar migrates once
        workbenchServerVerRef.current = 0;
        if (!workbenchInitialSyncDoneRef.current) {
          workbenchInitialSyncDoneRef.current = true;
          const localSidebar = extractSidebarState(layoutRef.current);
          if (!isReadonly && res.can_edit && hasNonEmptySidebarState(localSidebar)) {
            workbenchPendingStateRef.current = localSidebar;
            void flushSidebarSyncQueue();
          }
        }
      })
      .catch((err) => {
        if (!mountedRef.current || workbenchFetchSeqRef.current !== seq) return;
        if (
          err instanceof StudioApiError &&
          (err.status === 401 || err.status === 403) &&
          err.source === "studio_auth"
        ) {
          onSessionRevoked(err.message || "会话已失效，请重新登录");
        }
      });
  }, [
    workbenchStateEventVer,
    applyServerSidebarState,
    flushSidebarSyncQueue,
    isReadonly,
    onSessionRevoked,
  ]);

  useEffect(() => {
    mountedRef.current = true;
    const onResize = () => {
      setIsDesktopViewport(window.innerWidth >= 768);
    };
    window.addEventListener("resize", onResize);
    return () => {
      mountedRef.current = false;
      window.removeEventListener("resize", onResize);
    };
  }, []);

  useEffect(() => {
    saveWorkbenchPrefs(layout);
  }, [layout]);

  const multiPaneEnabled = !compactMode && isDesktopViewport;
  const effectivePaneCount: 1 | 2 | 3 | 4 = multiPaneEnabled ? layout.paneCount : 1;
  const visiblePanes = layout.panes.slice(0, effectivePaneCount);

  useEffect(() => {
    if (!browserOwner.startsWith("pane:")) return;
    const ownerPaneId = browserOwner.slice("pane:".length);
    const stillVisibleBrowser = visiblePanes.some(
      (p) => p.id === ownerPaneId && p.kind === "browser",
    );
    if (!stillVisibleBrowser) {
      onClaimBrowserOwner("none");
    }
  }, [browserOwner, visiblePanes, onClaimBrowserOwner]);

  useEffect(() => {
    if (effectivePaneCount <= 1 || browserOwner !== "none" || handoffPendingPaneId) {
      return;
    }
    const firstVisibleBrowser = visiblePanes.find((p) => p.kind === "browser");
    if (firstVisibleBrowser) {
      onClaimBrowserOwner(`pane:${firstVisibleBrowser.id}`);
    }
  }, [effectivePaneCount, browserOwner, handoffPendingPaneId, visiblePanes, onClaimBrowserOwner]);

  useEffect(() => {
    if (!handoffPendingPaneId) return;
    const targetId = handoffPendingPaneId;
    const timer = window.setTimeout(() => {
      if (!mountedRef.current) return;
      onClaimBrowserOwner(`pane:${targetId}`);
      setHandoffPendingPaneId(null);
    }, 60);
    return () => window.clearTimeout(timer);
  }, [handoffPendingPaneId, onClaimBrowserOwner]);

  const handleSetPaneCount = (count: 1 | 2 | 3 | 4) => {
    setLayout((prev) => ({
      ...prev,
      paneCount: count,
      layoutMode: String(count) as "1" | "2" | "3" | "4",
    }));
    if (count > 1) {
      setFilesDrawerOpen(false);
    }
  };

  const updatePane = useCallback(
    (paneId: string, patch: Partial<WorkbenchPaneConfig>) => {
      setLayout((prev) => ({
        ...prev,
        panes: prev.panes.map((p) => (p.id === paneId ? { ...p, ...patch } : p)),
      }));
    },
    [],
  );

  const handleAddCustomProject = useCallback(
    (project: CustomProjectItem) => {
      updateSidebarAndSync((prev) => ({
        ...prev,
        customProjects: sanitizeCustomProjects([project, ...prev.customProjects]),
      }));
    },
    [updateSidebarAndSync],
  );

  const handleRenameProject = useCallback(
    (groupId: string, nextName: string | null) => {
      updateSidebarAndSync((prev) => {
        const nextMap = { ...prev.projectRenames };
        if (!nextName) {
          delete nextMap[groupId];
        } else {
          nextMap[groupId] = nextName;
        }
        return {
          ...prev,
          projectRenames: sanitizeProjectRenames(nextMap),
        };
      });
    },
    [updateSidebarAndSync],
  );

  const handleRemoveCustomProject = useCallback(
    (projectId: string, sessionCids: string[]) => {
      updateSidebarAndSync((prev) => {
        const removedSet = new Set(sessionCids);
        const nextProjectRenames = { ...prev.projectRenames };
        delete nextProjectRenames[projectId];
        const nextSessionRenames = { ...prev.sessionRenames };
        for (const cid of sessionCids) delete nextSessionRenames[cid];
        return {
          ...prev,
          customProjects: prev.customProjects.filter((p) => p.id !== projectId),
          projectRenames: sanitizeProjectRenames(nextProjectRenames),
          hiddenSessionCids: sanitizeSessionCidList(
            [...sessionCids, ...prev.hiddenSessionCids],
            MAX_HIDDEN_SESSION_CIDS,
          ),
          pinnedSessionCids: prev.pinnedSessionCids.filter((c) => !removedSet.has(c)),
          archivedSessionCids: prev.archivedSessionCids.filter((c) => !removedSet.has(c)),
          unreadSessionCids: prev.unreadSessionCids.filter((c) => !removedSet.has(c)),
          sessionRenames: sanitizeSessionRenames(nextSessionRenames),
        };
      });
    },
    [updateSidebarAndSync],
  );

  const handleHideProject = useCallback(
    (projectId: string) => {
      updateSidebarAndSync((prev) => {
        const nextProjectRenames = { ...prev.projectRenames };
        delete nextProjectRenames[projectId];
        return {
          ...prev,
          hiddenProjectIds: sanitizeSlugList(
            [projectId, ...prev.hiddenProjectIds],
            MAX_HIDDEN_PROJECT_IDS,
            64,
          ),
          projectRenames: sanitizeProjectRenames(nextProjectRenames),
        };
      });
    },
    [updateSidebarAndSync],
  );

  const handleHideSessions = useCallback(
    (cids: string[]) => {
      if (cids.length === 0) return;
      updateSidebarAndSync((prev) => {
        const removedSet = new Set(cids);
        const nextSessionRenames = { ...prev.sessionRenames };
        for (const cid of cids) delete nextSessionRenames[cid];
        return {
          ...prev,
          hiddenSessionCids: sanitizeSessionCidList(
            [...cids, ...prev.hiddenSessionCids],
            MAX_HIDDEN_SESSION_CIDS,
          ),
          pinnedSessionCids: prev.pinnedSessionCids.filter((c) => !removedSet.has(c)),
          archivedSessionCids: prev.archivedSessionCids.filter((c) => !removedSet.has(c)),
          unreadSessionCids: prev.unreadSessionCids.filter((c) => !removedSet.has(c)),
          sessionRenames: sanitizeSessionRenames(nextSessionRenames),
        };
      });
    },
    [updateSidebarAndSync],
  );

  const handleTogglePinSession = useCallback(
    (cid: string) => {
      updateSidebarAndSync((prev) => {
        const exists = prev.pinnedSessionCids.includes(cid);
        const nextPinned = exists
          ? prev.pinnedSessionCids.filter((c) => c !== cid)
          : sanitizeSessionCidList([cid, ...prev.pinnedSessionCids], MAX_PINNED_SESSION_CIDS);
        return { ...prev, pinnedSessionCids: nextPinned };
      });
    },
    [updateSidebarAndSync],
  );

  const handleToggleArchiveSession = useCallback(
    (cid: string) => {
      updateSidebarAndSync((prev) => {
        const exists = prev.archivedSessionCids.includes(cid);
        const nextArchived = exists
          ? prev.archivedSessionCids.filter((c) => c !== cid)
          : sanitizeSessionCidList([cid, ...prev.archivedSessionCids], MAX_ARCHIVED_SESSION_CIDS);
        return { ...prev, archivedSessionCids: nextArchived };
      });
    },
    [updateSidebarAndSync],
  );

  const handleSetSessionUnread = useCallback(
    (cid: string, unread: boolean) => {
      updateSidebarAndSync((prev) => {
        const exists = prev.unreadSessionCids.includes(cid);
        if (unread === exists) return prev;
        const nextUnread = unread
          ? sanitizeSessionCidList([cid, ...prev.unreadSessionCids], MAX_UNREAD_SESSION_CIDS)
          : prev.unreadSessionCids.filter((c) => c !== cid);
        return { ...prev, unreadSessionCids: nextUnread };
      });
    },
    [updateSidebarAndSync],
  );

  const handleRenameSession = useCallback(
    (cid: string, nextTitle: string | null) => {
      updateSidebarAndSync((prev) => {
        const nextMap = { ...prev.sessionRenames };
        if (!nextTitle) {
          delete nextMap[cid];
        } else {
          nextMap[cid] = nextTitle;
        }
        return {
          ...prev,
          sessionRenames: sanitizeSessionRenames(nextMap),
        };
      });
    },
    [updateSidebarAndSync],
  );

  const handleSetShowArchived = useCallback(
    (show: boolean) => {
      updateSidebarAndSync((prev) =>
        prev.showArchived === show ? prev : { ...prev, showArchived: show },
      );
    },
    [updateSidebarAndSync],
  );

  const handlePaneActiveCidChange = useCallback((paneId: string, cid: string | null) => {
    setPaneActiveCids((prev) => (prev[paneId] === cid ? prev : { ...prev, [paneId]: cid }));
  }, []);

  const handleOpenSessionConsumed = useCallback((paneId: string, reqId: number) => {
    setOpenSessionMap((prev) => {
      const cur = prev[paneId];
      if (!cur || cur.id !== reqId) return prev;
      return { ...prev, [paneId]: null };
    });
  }, []);

  const handleSplitOpenSession = useCallback(
    (sourcePaneId: string, item: SessionSummaryItem): SplitOpenResult => {
      if (!multiPaneEnabled) {
        return { ok: false, message: "当前窗口宽度暂不支持分屏，请扩大窗口后重试" };
      }

      const existingIdx = visiblePanes.findIndex(
        (p) => p.id !== sourcePaneId && p.kind === "chat" && paneActiveCids[p.id] === item.cid,
      );
      if (existingIdx >= 0) {
        const existingPane = visiblePanes[existingIdx];
        setLastFocusedChatPaneId(existingPane.id);
        return { ok: true, message: `该对话已在分栏 #${existingIdx + 1} 中打开` };
      }

      if (layout.paneCount >= 4) {
        return { ok: false, message: "已达最大分屏数（4 栏），请先关闭或切换分栏" };
      }

      const nextCount = (layout.paneCount + 1) as 2 | 3 | 4;
      const targetPane = layout.panes[nextCount - 1];
      if (!targetPane) {
        return { ok: false, message: "分屏面板不可用" };
      }

      if (browserOwner === `pane:${targetPane.id}`) {
        onClaimBrowserOwner("none");
      }

      setLayout((prev) => ({
        ...prev,
        paneCount: nextCount,
        layoutMode: String(nextCount) as "2" | "3" | "4",
        panes: prev.panes.map((p) =>
          p.id === targetPane.id
            ? {
                ...p,
                kind: "chat",
                ...(item.project_id ? { project: item.project_id } : {}),
                bot:
                  item.bot && item.bot !== TEAM_TARGET_ID
                    ? item.bot
                    : p.bot && p.bot !== TEAM_TARGET_ID
                      ? p.bot
                      : undefined,
              }
            : p,
        ),
      }));
      setFilesDrawerOpen(false);
      const reqId = ++openSessionCounterRef.current;
      setOpenSessionMap((prev) => ({
        ...prev,
        [targetPane.id]: { id: reqId, session: item },
      }));
      setLastFocusedChatPaneId(targetPane.id);
      return { ok: true };
    },
    [browserOwner, layout.paneCount, layout.panes, multiPaneEnabled, onClaimBrowserOwner, paneActiveCids, visiblePanes],
  );

  const handleChangePaneKind = (paneId: string, nextKind: PaneKind) => {
    if (nextKind === "browser") {
      if (browserOwner === "none" || browserOwner === "drawer" || browserOwner === "tab") {
        onClaimBrowserOwner(`pane:${paneId}`);
      }
    } else if (browserOwner === `pane:${paneId}`) {
      onClaimBrowserOwner("none");
    }
    updatePane(paneId, {
      kind: nextKind,
      ...(nextKind === "room" ? { roomId: "lobby" } : {}),
    });
  };

  const handleTransferBrowserToPane = (targetPaneId: string) => {
    setLayout((prev) => ({
      ...prev,
      panes: prev.panes.map((p) =>
        p.id !== targetPaneId && p.kind === "browser" ? { ...p, kind: "chat" } : p,
      ),
    }));
    onClaimBrowserOwner("none");
    setHandoffPendingPaneId(targetPaneId);
  };

  const handleQuoteToActiveChat = useCallback(
    (snippet: string) => {
      if (isReadonly || !snippet) return;
      const visibleChats = visiblePanes.filter((p) => p.kind === "chat");
      const target =
        visibleChats.find((p) => p.id === lastFocusedChatPaneId) || visibleChats[0];
      if (!target) return;
      const nextId = ++quoteCounterRef.current;
      setQuoteMap((prev) => ({
        ...prev,
        [target.id]: { id: nextId, text: snippet },
      }));
    },
    [isReadonly, lastFocusedChatPaneId, visiblePanes],
  );

  const handleQuoteConsumed = useCallback((paneId: string, quoteId: number) => {
    setQuoteMap((prev) => {
      const cur = prev[paneId];
      if (!cur || cur.id !== quoteId) return prev;
      return { ...prev, [paneId]: null };
    });
  }, []);

  const primaryPane = visiblePanes[0];

  const gridClass =
    effectivePaneCount === 1
      ? "grid-cols-1 grid-rows-1"
      : effectivePaneCount === 2
        ? "grid-cols-2 grid-rows-1"
        : effectivePaneCount === 3
          ? "grid-cols-3 grid-rows-1"
          : "grid-cols-2 grid-rows-2";

  return (
    <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden bg-slate-950">
      {multiPaneEnabled && (
        <div className="shrink-0 h-9 px-3 border-b border-slate-800/90 bg-slate-900/90 flex items-center gap-2 text-xs">
          <span className="text-[11px] font-medium text-slate-400">工作台分屏</span>
          <div className="inline-flex items-center rounded-lg border border-slate-800 bg-slate-950 p-0.5 gap-0.5">
            {(
              [
                { count: 1, label: "1 栏", icon: Square },
                { count: 2, label: "2 栏", icon: Columns2 },
                { count: 3, label: "3 栏", icon: Columns3 },
                { count: 4, label: "4 栏", icon: Grid2x2 },
              ] as const
            ).map(({ count, label, icon: Icon }) => {
              const active = layout.paneCount === count;
              return (
                <button
                  key={count}
                  type="button"
                  onClick={() => handleSetPaneCount(count)}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] transition-colors cursor-pointer ${
                    active
                      ? "bg-sky-500/20 text-sky-300 font-medium"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/70"
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  <span>{label}</span>
                </button>
              );
            })}
          </div>

          <span
            title="客户端并发对话流预算（最多 3 条 /api/chat/stream SSE）"
            className="ml-2 px-1.5 py-0.5 rounded border border-slate-800 bg-slate-950 text-[10px] font-mono text-slate-400"
          >
            SSE {activeChatStreams}/{MAX_CLIENT_CHAT_STREAMS}
          </span>

          <div className="ml-auto flex items-center gap-1.5">
            {effectivePaneCount === 1 && primaryPane.kind === "chat" && (
              <button
                type="button"
                onClick={() => setFilesDrawerOpen((v) => !v)}
                className={`inline-flex items-center gap-1 h-6 px-2 rounded-md text-[11px] font-medium border transition-colors cursor-pointer ${
                  filesDrawerOpen
                    ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                    : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
                }`}
              >
                <FileCode className="w-3 h-3" />
                <span>{filesDrawerOpen ? "收起文件" : "文件/Diff"}</span>
              </button>
            )}
          </div>
        </div>
      )}

      {effectivePaneCount === 1 ? (
        <div className="flex-1 min-h-0 min-w-0 flex overflow-hidden">
          <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden">
            <ChatPane
              paneId={primaryPane.id}
              session={session}
              initialBot={primaryPane.bot}
              initialProject={primaryPane.project}
              initialCid={paneActiveCids[primaryPane.id] || null}
              defaultSidebarOpen={!compactMode && isDesktopViewport}
              sessionSyncEvent={sessionSyncEvent}
              roomEvent={roomEvent}
              roomEvents={roomEvents}
              botsEventVer={botsEventVer}
              gatewaysEventVer={gatewaysEventVer}
              pendingQuote={quoteMap[primaryPane.id] || null}
              onQuoteConsumed={(qid) => handleQuoteConsumed(primaryPane.id, qid)}
              pendingOpenSession={openSessionMap[primaryPane.id] || null}
              onOpenSessionConsumed={(reqId) => handleOpenSessionConsumed(primaryPane.id, reqId)}
              onSplitOpenSession={(item) => handleSplitOpenSession(primaryPane.id, item)}
              onBotChange={(bot) => updatePane(primaryPane.id, { bot })}
              onProjectChange={(project) => updatePane(primaryPane.id, { project })}
              onActiveCidChange={(cid) => handlePaneActiveCidChange(primaryPane.id, cid)}
              onActiveWorktreeChange={(wtId) =>
                setPaneActiveWorktreeIds((prev) =>
                  prev[primaryPane.id] === wtId ? prev : { ...prev, [primaryPane.id]: wtId },
                )
              }
              onFocusPane={setLastFocusedChatPaneId}
              customProjects={layout.customProjects}
              projectRenames={layout.projectRenames}
              hiddenProjectIds={layout.hiddenProjectIds}
              hiddenSessionCids={layout.hiddenSessionCids}
              pinnedSessionCids={layout.pinnedSessionCids}
              archivedSessionCids={layout.archivedSessionCids}
              unreadSessionCids={layout.unreadSessionCids}
              sessionRenames={layout.sessionRenames}
              showArchived={layout.showArchived}
              onAddCustomProject={handleAddCustomProject}
              onRenameProject={handleRenameProject}
              onRemoveCustomProject={handleRemoveCustomProject}
              onHideProject={handleHideProject}
              onHideSessions={handleHideSessions}
              onTogglePinSession={handleTogglePinSession}
              onToggleArchiveSession={handleToggleArchiveSession}
              onSetSessionUnread={handleSetSessionUnread}
              onRenameSession={handleRenameSession}
              onSetShowArchived={handleSetShowArchived}
              extraHeaderActions={
                !multiPaneEnabled ? (
                  <button
                    type="button"
                    onClick={() => setFilesDrawerOpen((v) => !v)}
                    className={`inline-flex items-center gap-1 h-7 px-2 rounded-md text-xs font-medium border transition-colors cursor-pointer shrink-0 ${
                      filesDrawerOpen
                        ? "bg-sky-500/20 border-sky-500/40 text-sky-300"
                        : "bg-slate-950/70 border-slate-800 text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>文件</span>
                  </button>
                ) : undefined
              }
              onSessionRevoked={onSessionRevoked}
            />
          </div>

          {filesDrawerOpen && (
            <aside className="w-full md:w-[400px] xl:w-[460px] shrink-0 border-l border-slate-800/90 bg-slate-950 flex flex-col min-h-0">
              <FilesDiffPanel
                session={session}
                selectedProject={
                  primaryPane.project &&
                  !layout.customProjects.some((cp) => cp.id === primaryPane.project)
                    ? primaryPane.project
                    : undefined
                }
                selectedBot={
                  primaryPane.bot && primaryPane.bot !== TEAM_TARGET_ID
                    ? primaryPane.bot
                    : undefined
                }
                activeCid={paneActiveCids[primaryPane.id] || null}
                selectedWorktreeId={paneActiveWorktreeIds[primaryPane.id] || null}
                onWorktreeChange={(wtId) =>
                  setPaneActiveWorktreeIds((prev) =>
                    prev[primaryPane.id] === wtId ? prev : { ...prev, [primaryPane.id]: wtId },
                  )
                }
                onProjectChange={(pid) => updatePane(primaryPane.id, { project: pid })}
                onQuoteToChat={isReadonly ? undefined : handleQuoteToActiveChat}
                onClose={() => setFilesDrawerOpen(false)}
                onSessionRevoked={onSessionRevoked}
              />
            </aside>
          )}
        </div>
      ) : (
        <div className={`flex-1 min-h-0 min-w-0 grid ${gridClass} gap-px bg-slate-800/90 overflow-hidden`}>
          {visiblePanes.map((pane, idx) => {
            const subTab = jobsAttentionSubTab[pane.id] || "attention";
            const ownsBrowser = browserOwner === `pane:${pane.id}`;
            const otherBrowserOwner =
              pane.kind === "browser" && browserOwner !== "none" && !ownsBrowser;

            return (
              <div
                key={pane.id}
                className="min-h-0 min-w-0 flex flex-col bg-slate-950 overflow-hidden"
              >
                <div className="shrink-0 h-8 px-2 border-b border-slate-800/90 bg-slate-900/80 flex items-center gap-1.5 text-[11px]">
                  <span className="font-mono text-[10px] text-slate-500 px-1">#{idx + 1}</span>
                  <select
                    value={pane.kind === "room" ? "chat" : pane.kind}
                    onChange={(e) => handleChangePaneKind(pane.id, e.target.value as PaneKind)}
                    aria-label={`分栏 ${idx + 1} 视图类型`}
                    className="h-6 rounded bg-slate-950 border border-slate-800 px-1.5 text-[11px] text-slate-200 focus:outline-none focus:border-sky-500"
                  >
                    <option value="chat">对话 (Chat)</option>
                    <option value="jobs_attention">审批 / 派工</option>
                    <option value="files">文件审查 (Files/Diff)</option>
                    <option value="browser">实时浏览器 (Browser)</option>
                  </select>

                  {pane.kind === "jobs_attention" && (
                    <div className="ml-auto inline-flex rounded border border-slate-800 bg-slate-950 p-0.5">
                      <button
                        type="button"
                        onClick={() =>
                          setJobsAttentionSubTab((prev) => ({ ...prev, [pane.id]: "attention" }))
                        }
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] cursor-pointer ${
                          subTab === "attention"
                            ? "bg-amber-500/20 text-amber-300"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        <Bell className="w-2.5 h-2.5" />
                        审批
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setJobsAttentionSubTab((prev) => ({ ...prev, [pane.id]: "jobs" }))
                        }
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] cursor-pointer ${
                          subTab === "jobs"
                            ? "bg-sky-500/20 text-sky-300"
                            : "text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        <Activity className="w-2.5 h-2.5" />
                        派工
                      </button>
                    </div>
                  )}

                  {pane.kind === "chat" && lastFocusedChatPaneId === pane.id && (
                    <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-sky-400">
                      <MessageSquare className="w-2.5 h-2.5" />
                      活跃对话
                    </span>
                  )}

                  {pane.kind === "room" && (
                    <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-emerald-400">
                      <Users className="w-2.5 h-2.5" />
                      #{pane.roomId || "lobby"}
                    </span>
                  )}
                </div>

                <div className="flex-1 min-h-0 min-w-0 flex flex-col overflow-hidden">
                  {pane.kind === "chat" && (
                    <ChatPane
                      paneId={pane.id}
                      session={session}
                      initialBot={pane.bot}
                      initialProject={pane.project}
                      initialCid={paneActiveCids[pane.id] || null}
                      defaultSidebarOpen={false}
                      compactHeader
                      sessionSyncEvent={sessionSyncEvent}
                      roomEvent={roomEvent}
                      roomEvents={roomEvents}
                      botsEventVer={botsEventVer}
                      gatewaysEventVer={gatewaysEventVer}
                      pendingQuote={quoteMap[pane.id] || null}
                      onQuoteConsumed={(qid) => handleQuoteConsumed(pane.id, qid)}
                      pendingOpenSession={openSessionMap[pane.id] || null}
                      onOpenSessionConsumed={(reqId) => handleOpenSessionConsumed(pane.id, reqId)}
                      onSplitOpenSession={(item) => handleSplitOpenSession(pane.id, item)}
                      onBotChange={(bot) => updatePane(pane.id, { bot })}
                      onProjectChange={(project) => updatePane(pane.id, { project })}
                      onActiveCidChange={(cid) => handlePaneActiveCidChange(pane.id, cid)}
                      onActiveWorktreeChange={(wtId) =>
                        setPaneActiveWorktreeIds((prev) =>
                          prev[pane.id] === wtId ? prev : { ...prev, [pane.id]: wtId },
                        )
                      }
                      onFocusPane={setLastFocusedChatPaneId}
                      customProjects={layout.customProjects}
                      projectRenames={layout.projectRenames}
                      hiddenProjectIds={layout.hiddenProjectIds}
                      hiddenSessionCids={layout.hiddenSessionCids}
                      pinnedSessionCids={layout.pinnedSessionCids}
                      archivedSessionCids={layout.archivedSessionCids}
                      unreadSessionCids={layout.unreadSessionCids}
                      sessionRenames={layout.sessionRenames}
                      showArchived={layout.showArchived}
                      onAddCustomProject={handleAddCustomProject}
                      onRenameProject={handleRenameProject}
                      onRemoveCustomProject={handleRemoveCustomProject}
                      onHideProject={handleHideProject}
                      onHideSessions={handleHideSessions}
                      onTogglePinSession={handleTogglePinSession}
                      onToggleArchiveSession={handleToggleArchiveSession}
                      onSetSessionUnread={handleSetSessionUnread}
                      onRenameSession={handleRenameSession}
                      onSetShowArchived={handleSetShowArchived}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "room" && (
                    <RoomPanel
                      session={session}
                      initialRoomId={pane.roomId || "lobby"}
                      onRoomChange={(roomId) => updatePane(pane.id, { roomId })}
                      roomEvent={roomEvent}
                      roomEvents={roomEvents}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "jobs_attention" &&
                    (subTab === "attention" ? (
                      <AttentionPanel
                        session={session}
                        eventVersion={attentionEventVer}
                        onOpenBrowser={() => handleChangePaneKind(pane.id, "browser")}
                        onPendingCountChange={onPendingAttentionCount}
                        onSessionRevoked={onSessionRevoked}
                      />
                    ) : (
                      <div className="flex-1 min-h-0 overflow-y-auto">
                        <JobsView
                          session={session}
                          eventVersion={jobsEventVer}
                          onSessionRevoked={onSessionRevoked}
                        />
                      </div>
                    ))}

                  {pane.kind === "files" && (
                    <FilesDiffPanel
                      session={session}
                      selectedProject={
                        pane.project && !layout.customProjects.some((cp) => cp.id === pane.project)
                          ? pane.project
                          : undefined
                      }
                      selectedBot={
                        pane.bot && pane.bot !== TEAM_TARGET_ID ? pane.bot : undefined
                      }
                      activeCid={paneActiveCids[lastFocusedChatPaneId] || null}
                      selectedWorktreeId={paneActiveWorktreeIds[lastFocusedChatPaneId] || null}
                      onWorktreeChange={(wtId) =>
                        setPaneActiveWorktreeIds((prev) =>
                          prev[lastFocusedChatPaneId] === wtId
                            ? prev
                            : { ...prev, [lastFocusedChatPaneId]: wtId },
                        )
                      }
                      onProjectChange={(pid) => updatePane(pane.id, { project: pid })}
                      onQuoteToChat={isReadonly ? undefined : handleQuoteToActiveChat}
                      onSessionRevoked={onSessionRevoked}
                    />
                  )}

                  {pane.kind === "browser" &&
                    (ownsBrowser ? (
                      <BrowserView
                        key={`pane-${pane.id}-${wsSessionEpoch}`}
                        session={session}
                        compact={false}
                        variant="drawer"
                        onCloseDrawer={() => handleChangePaneKind(pane.id, "chat")}
                        onSessionRevoked={onSessionRevoked}
                        onRoleChanged={onRoleChanged}
                      />
                    ) : (
                      <div className="flex-1 min-h-0 flex flex-col items-center justify-center text-center p-6 space-y-3 bg-slate-950">
                        <div className="h-10 w-10 rounded-xl border border-amber-500/35 bg-amber-500/10 flex items-center justify-center text-amber-300">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div className="text-sm font-medium text-slate-100">
                          {handoffPendingPaneId
                            ? "正在移交实时浏览器连接…"
                            : otherBrowserOwner
                              ? "实时浏览器已由另一视图持有"
                              : "实时浏览器尚未在此栏激活"}
                        </div>
                        <p className="text-xs text-slate-400 max-w-xs">
                          同一会话仅允许单实例实时浏览器 WebSocket 连接（防双栏抢占接管）。
                        </p>
                        {!handoffPendingPaneId && (
                          <button
                            type="button"
                            onClick={() => handleTransferBrowserToPane(pane.id)}
                            className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium cursor-pointer"
                          >
                            {otherBrowserOwner ? "将浏览器移至此栏" : "在此栏启用浏览器"}
                          </button>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
