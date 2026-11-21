import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  AtSign,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Hash,
  Layers,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  Users,
  Wrench,
  XCircle,
  Zap,
} from "lucide-react";
import {
  StudioApiError,
  createRoom,
  fetchBots,
  fetchRoomActivity,
  fetchRoomMessages,
  fetchRooms,
  sendRoomMessage,
} from "../api";
import type {
  BotRosterItem,
  ExecutionMode,
  RoomActivityBotItem,
  RoomActivityDispatchInfo,
  RoomActivityJobItem,
  RoomLiveEvent,
  RoomMessageItem,
  RoomSummary,
  StudioSession,
} from "../types";
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
import { SafeMarkdown } from "./SafeMarkdown";

export interface RoomMetaSummary {
  isMirrorMode: boolean;
  defaultBotHandle: string;
  loading: boolean;
  topic: string;
  onlineBotCount: number;
}

export interface RoomPanelProps {
  session: StudioSession;
  initialRoomId?: string;
  lockedRoomId?: string;
  projectId?: string;
  hideHeader?: boolean;
  refreshSignal?: number;
  pendingQuote?: { id: number; text: string } | null;
  onQuoteConsumed?: (id: number) => void;
  onFocusInput?: () => void;
  onRoomMetaChange?: (meta: RoomMetaSummary) => void;
  onRoomChange?: (roomId: string) => void;
  roomEvent?: RoomLiveEvent | null;
  roomEvents?: RoomLiveEvent[];
  onSessionRevoked: (reason: string) => void;
}

function formatTime(ts: number): string {
  if (!ts) return "";
  try {
    return new Date(ts * 1000).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "";
  }
}

function formatDurationClock(secRaw: number | null | undefined): string {
  if (secRaw === null || secRaw === undefined || !Number.isFinite(secRaw)) return "00:00";
  const total = Math.max(0, Math.floor(secRaw));
  const hrs = Math.floor(total / 3600);
  const mins = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const mm = String(mins).padStart(2, "0");
  const ss = String(secs).padStart(2, "0");
  if (hrs > 0) {
    return `${hrs}:${mm}:${ss}`;
  }
  return `${mm}:${ss}`;
}

function inferClientStageTag(msg: RoomMessageItem): string {
  if (msg.stage_tag) return msg.stage_tag;
  if (msg.sender_type !== "bot") return "";
  const sample = (msg.content || "").slice(0, 600);
  if (/(?:收到来自|我开始处理|开始处理|已接单|已收到派单|收到派单|开始执行)/.test(sample)) {
    return "ack";
  }
  if (/(?:执行失败|任务失败|处理失败|已取消|异常中断|执行超时|❌)/.test(sample)) {
    return "error";
  }
  if (/(?:已验收通过|验收通过|已验收|已完成|任务完成|已交付|交付完成|上线预览|最终交付)/.test(sample)) {
    return "delivery";
  }
  if (/(?:已立刻排入|已排入|已派单|已派给|已分派|派单给|排入.{0,16}队列|单号\s*[`「【(（]?\s*job-)/.test(sample)) {
    return "dispatch";
  }
  return "reply";
}

function extractClientJobId(msg: RoomMessageItem): string {
  if (msg.job_id) return msg.job_id;
  if (msg.sender_type !== "bot") return "";
  const m = /\b(job-[a-zA-Z0-9_-]{4,24})\b/.exec((msg.content || "").slice(0, 800));
  return m ? m[1] : "";
}

function getStageBadgeMeta(stageTag: string): { label: string; cls: string } | null {
  switch (stageTag) {
    case "ack":
      return {
        label: "📥 接单回执",
        cls: "bg-cyan-500/15 text-cyan-200 border border-cyan-500/30",
      };
    case "dispatch":
      return {
        label: "📤 总指挥派单",
        cls: "bg-indigo-500/15 text-indigo-200 border border-indigo-500/30",
      };
    case "delivery":
      return {
        label: "✅ 交付完成",
        cls: "bg-emerald-500/15 text-emerald-200 border border-emerald-500/30",
      };
    case "error":
      return {
        label: "⚠️ 执行异常",
        cls: "bg-rose-500/15 text-rose-200 border border-rose-500/30",
      };
    case "reply":
      return {
        label: "💬 群内应答",
        cls: "bg-slate-800/90 text-slate-300 border border-slate-700/80",
      };
    default:
      return null;
  }
}

interface PipelineStepItem {
  id: string;
  icon: string;
  label: string;
  sublabel?: string;
  status: "done" | "active" | "pending" | "error";
}

export function RoomPanel({
  session,
  initialRoomId,
  lockedRoomId,
  projectId,
  hideHeader = false,
  refreshSignal,
  pendingQuote,
  onQuoteConsumed,
  onFocusInput,
  onRoomMetaChange,
  onRoomChange,
  roomEvent,
  roomEvents,
  onSessionRevoked,
}: RoomPanelProps) {
  const isReadonly = session.role !== "admin";
  const normalizedLockedRoomId = (lockedRoomId || "").trim();

  const [rooms, setRooms] = useState<RoomSummary[]>([]);
  const [roomsLoading, setRoomsLoading] = useState(false);
  const [selectedRoomId, setSelectedRoomId] = useState<string>(
    normalizedLockedRoomId || initialRoomId || "lobby",
  );
  const effectiveRoomId = normalizedLockedRoomId || selectedRoomId;
  const [messages, setMessages] = useState<RoomMessageItem[]>([]);
  const [msgsLoading, setMsgsLoading] = useState(false);
  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [typingBots, setTypingBots] = useState<Record<string, number>>({});
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Live Pipeline & Activity state
  const [activeBots, setActiveBots] = useState<RoomActivityBotItem[]>([]);
  const [recentJobs, setRecentJobs] = useState<RoomActivityJobItem[]>([]);
  const [recentDispatch, setRecentDispatch] = useState<RoomActivityDispatchInfo | null>(null);
  const [activityMirrorBound, setActivityMirrorBound] = useState<boolean>(false);
  const [queueExpanded, setQueueExpanded] = useState<boolean>(false);
  const [clockOffsetSec, setClockOffsetSec] = useState<number>(0);
  const [nowSec, setNowSec] = useState<number>(() => Date.now() / 1000);

  // Create room form state
  const [createOpen, setCreateOpen] = useState(false);
  const [newRoomId, setNewRoomId] = useState("");
  const [newRoomTitle, setNewRoomTitle] = useState("");
  const [newRoomTopic, setNewRoomTopic] = useState("");
  const [creating, setCreating] = useState(false);

  const mountedRef = useRef(true);
  const lockedRoomIdRef = useRef<string>(normalizedLockedRoomId);
  lockedRoomIdRef.current = normalizedLockedRoomId;
  const selectedRoomRef = useRef<string>(effectiveRoomId);
  selectedRoomRef.current = effectiveRoomId;
  const onRoomChangeRef = useRef(onRoomChange);
  onRoomChangeRef.current = onRoomChange;
  const onQuoteConsumedRef = useRef(onQuoteConsumed);
  onQuoteConsumedRef.current = onQuoteConsumed;
  const onRoomMetaChangeRef = useRef(onRoomMetaChange);
  onRoomMetaChangeRef.current = onRoomMetaChange;
  const roomsSeqRef = useRef(0);
  const msgsSeqRef = useRef(0);
  const botsSeqRef = useRef(0);
  const activitySeqRef = useRef(0);
  const activityDebounceRef = useRef<number | null>(null);
  const lastRoomEventVerRef = useRef<number>(
    roomEvents && roomEvents.length > 0
      ? roomEvents[roomEvents.length - 1].ver
      : (roomEvent?.ver ?? 0),
  );
  const lastRefreshSignalRef = useRef<number | undefined>(refreshSignal);
  const consumedQuoteIdRef = useRef<number>(0);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (activityDebounceRef.current !== null) {
        window.clearTimeout(activityDebounceRef.current);
        activityDebounceRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (normalizedLockedRoomId && selectedRoomId !== normalizedLockedRoomId) {
      setSelectedRoomId(normalizedLockedRoomId);
    }
  }, [normalizedLockedRoomId, selectedRoomId]);

  useEffect(() => {
    if (isReadonly || !pendingQuote || pendingQuote.id === consumedQuoteIdRef.current) return;
    consumedQuoteIdRef.current = pendingQuote.id;
    const snippet = pendingQuote.text;
    if (snippet) {
      setDraft((prev) => (prev.trim() ? `${prev}\n\n${snippet}` : snippet));
    }
    onQuoteConsumedRef.current?.(pendingQuote.id);
  }, [isReadonly, pendingQuote]);

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

  const composerAtts = useAttachmentComposer({
    disabled: isReadonly || sending,
    onAuthError: handleAuthErr,
  });
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [lightboxImage, setLightboxImage] = useState<{ src: string; name: string } | null>(null);
  const [filePickerOpen, setFilePickerOpen] = useState(false);
  const [filePickerQuery, setFilePickerQuery] = useState("");
  const [filePickerActiveIdx, setFilePickerActiveIdx] = useState(0);

  const loadRooms = useCallback(async () => {
    const seq = ++roomsSeqRef.current;
    setRoomsLoading(true);
    try {
      const res = await fetchRooms();
      if (!mountedRef.current || roomsSeqRef.current !== seq) return;
      const nextRooms = res.rooms || [];
      setRooms(nextRooms);
      if (!lockedRoomIdRef.current) {
        const exists = nextRooms.some((r) => r.room_id === selectedRoomRef.current);
        if (!exists && nextRooms.length > 0) {
          const fallback = nextRooms[0].room_id;
          setSelectedRoomId(fallback);
          onRoomChangeRef.current?.(fallback);
        }
      }
    } catch (err) {
      if (!mountedRef.current || roomsSeqRef.current !== seq) return;
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "加载频道列表失败");
      }
    } finally {
      if (mountedRef.current && roomsSeqRef.current === seq) {
        setRoomsLoading(false);
      }
    }
  }, [handleAuthErr]);

  const loadBots = useCallback(async () => {
    const seq = ++botsSeqRef.current;
    try {
      const res = await fetchBots();
      if (!mountedRef.current || botsSeqRef.current !== seq) return;
      setBots(res.bots || []);
    } catch (err) {
      if (mountedRef.current && botsSeqRef.current === seq) {
        handleAuthErr(err);
      }
    }
  }, [handleAuthErr]);

  const loadActivity = useCallback(
    async (roomId: string) => {
      if (!roomId) return;
      const seq = ++activitySeqRef.current;
      try {
        const res = await fetchRoomActivity(roomId);
        if (
          !mountedRef.current ||
          activitySeqRef.current !== seq ||
          selectedRoomRef.current !== roomId
        ) {
          return;
        }
        const clientNow = Date.now() / 1000;
        if (typeof res.server_ts === "number" && Number.isFinite(res.server_ts) && res.server_ts > 0) {
          setClockOffsetSec(res.server_ts - clientNow);
        }
        setNowSec(clientNow);
        setActiveBots(res.active_bots || []);
        setRecentJobs(res.recent_jobs || []);
        setRecentDispatch(res.recent_dispatch || null);
        setActivityMirrorBound(Boolean(res.mirror_bound));
      } catch (err) {
        if (
          !mountedRef.current ||
          activitySeqRef.current !== seq ||
          selectedRoomRef.current !== roomId
        ) {
          return;
        }
        handleAuthErr(err);
      }
    },
    [handleAuthErr],
  );

  const scheduleActivityRefresh = useCallback(
    (roomId: string, delayMs = 220) => {
      if (activityDebounceRef.current !== null) {
        window.clearTimeout(activityDebounceRef.current);
      }
      activityDebounceRef.current = window.setTimeout(() => {
        activityDebounceRef.current = null;
        if (mountedRef.current && selectedRoomRef.current === roomId) {
          void loadActivity(roomId);
        }
      }, delayMs);
    },
    [loadActivity],
  );

  const loadMessages = useCallback(
    async (roomId: string, opts?: { silent?: boolean }) => {
      if (!roomId) return;
      const seq = ++msgsSeqRef.current;
      if (!opts?.silent) {
        setMsgsLoading(true);
        setErrorMsg(null);
      }
      try {
        const res = await fetchRoomMessages(roomId, { limit: 150 });
        if (!mountedRef.current || msgsSeqRef.current !== seq || selectedRoomRef.current !== roomId) {
          return;
        }
        setMessages(res.messages || []);
        window.setTimeout(() => {
          if (mountedRef.current && selectedRoomRef.current === roomId) {
            endRef.current?.scrollIntoView({ behavior: "auto" });
          }
        }, 30);
      } catch (err) {
        if (!mountedRef.current || msgsSeqRef.current !== seq || selectedRoomRef.current !== roomId) {
          return;
        }
        if (!handleAuthErr(err) && !opts?.silent) {
          setErrorMsg(err instanceof Error ? err.message : "加载群聊消息失败");
        }
      } finally {
        if (mountedRef.current && !opts?.silent && msgsSeqRef.current === seq) {
          setMsgsLoading(false);
        }
      }
    },
    [handleAuthErr],
  );

  useEffect(() => {
    void loadRooms();
    void loadBots();
  }, [loadRooms, loadBots]);

  useEffect(() => {
    setTypingBots({});
    setQueueExpanded(false);
    void loadMessages(effectiveRoomId);
    void loadActivity(effectiveRoomId);
  }, [effectiveRoomId, loadMessages, loadActivity]);

  useEffect(() => {
    if (refreshSignal === undefined || refreshSignal === lastRefreshSignalRef.current) return;
    lastRefreshSignalRef.current = refreshSignal;
    void loadRooms();
    void loadBots();
    void loadMessages(selectedRoomRef.current);
    void loadActivity(selectedRoomRef.current);
  }, [refreshSignal, loadRooms, loadBots, loadMessages, loadActivity]);

  // Process ALL global SSE events (room_message, room_typing, room_activity, job_updated, bots_updated, resync_required)
  useEffect(() => {
    const batch: RoomLiveEvent[] =
      roomEvents && roomEvents.length > 0
        ? roomEvents
        : roomEvent
          ? [roomEvent]
          : [];
    if (batch.length === 0) return;

    const unseen = batch.filter((ev) => ev.ver > lastRoomEventVerRef.current);
    if (unseen.length === 0) return;
    lastRoomEventVerRef.current = unseen[unseen.length - 1].ver;

    const curRoom = selectedRoomRef.current;
    let shouldRefreshActivity = false;
    let shouldRefreshBots = false;

    for (const ev of unseen) {
      if (ev.type === "resync_required") {
        void loadRooms();
        void loadBots();
        void loadMessages(curRoom, { silent: true });
        void loadActivity(curRoom);
        continue;
      }

      if (ev.type === "bots_updated") {
        shouldRefreshBots = true;
        shouldRefreshActivity = true;
        continue;
      }

      if (ev.type === "job_updated") {
        shouldRefreshActivity = true;
        if (ev.job_id && ev.status) {
          const jid = ev.job_id;
          const nextSt = ev.status === "error" ? "failed" : ev.status;
          const evTs = ev.ts || Date.now() / 1000;
          setRecentJobs((prev) => {
            const idx = prev.findIndex((j) => j.job_id === jid);
            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = {
                ...updated[idx],
                status: nextSt,
                ...(ev.label ? { label: ev.label } : {}),
                ...(typeof ev.duration_s === "number" ? { duration_s: ev.duration_s } : {}),
                ...(nextSt === "running" && !updated[idx].started_at ? { started_at: evTs } : {}),
                ...(nextSt === "done" || nextSt === "failed" || nextSt === "cancelled"
                  ? { finished_at: evTs }
                  : {}),
              };
              return updated;
            }
            return [
              {
                job_id: jid,
                group_id: ev.group_id || "",
                bot: ev.bot || "",
                from_bot: ev.from_bot || "",
                label: ev.label || jid,
                status: nextSt,
                progress: ev.stage_label || "",
                created_at: evTs,
                started_at: nextSt === "running" ? evTs : null,
                finished_at:
                  nextSt === "done" || nextSt === "failed" || nextSt === "cancelled" ? evTs : null,
                duration_s: typeof ev.duration_s === "number" ? ev.duration_s : null,
              },
              ...prev,
            ].slice(0, 12);
          });
        }
        continue;
      }

      if (ev.room_id && ev.room_id !== curRoom) {
        continue;
      }

      if (ev.type === "room_typing" && ev.bot) {
        const bHandle = ev.bot;
        const isTyping = Boolean(ev.typing);
        const nowT = Date.now() / 1000 + clockOffsetSec;
        setTypingBots((prev) => {
          if (isTyping && prev[bHandle]) return prev;
          if (!isTyping && !prev[bHandle]) return prev;
          const next = { ...prev };
          if (isTyping) next[bHandle] = nowT;
          else delete next[bHandle];
          return next;
        });
        continue;
      }

      if (ev.type === "room_activity") {
        shouldRefreshActivity = true;
        const phase = (ev.phase || "").toLowerCase();
        const evTs = ev.ts || Date.now() / 1000 + clockOffsetSec;

        if (phase === "dispatched" || phase === "received" || phase === "urgent_dispatched") {
          const targets = (ev.target_bots || []).filter(Boolean);
          const isUrgent = phase === "urgent_dispatched";
          setRecentDispatch({
            phase,
            target_bots: targets.length > 0 ? targets : ev.bot ? [ev.bot] : [],
            dispatched_at: evTs,
            stage_label:
              ev.stage_label ||
              (isUrgent
                ? targets.length > 0
                  ? `⚡ 插队指令已发送至 ${targets.map((b) => `@${b}`).join("、")}，优先调度处理`
                  : "⚡ 插队指令已发送，优先调度处理"
                : targets.length > 0
                  ? `已送达 ${targets.map((b) => `@${b}`).join("、")}，等待接单处理`
                  : "指令已送达，等待调度处理"),
          });
          setNowSec(Date.now() / 1000);
        } else if (
          ev.job_id &&
          (phase === "queued" ||
            phase === "running" ||
            phase === "tool_use" ||
            phase === "done" ||
            phase === "failed" ||
            phase === "cancelled")
        ) {
          const jid = ev.job_id;
          const normStatus =
            phase === "tool_use"
              ? "running"
              : ev.status === "error"
                ? "failed"
                : ev.status || phase;
          setRecentJobs((prev) => {
            const idx = prev.findIndex((j) => j.job_id === jid);
            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = {
                ...updated[idx],
                status: normStatus,
                ...(ev.label ? { label: ev.label } : {}),
                ...(ev.stage_label ? { progress: ev.stage_label } : {}),
                ...(typeof ev.duration_s === "number" ? { duration_s: ev.duration_s } : {}),
                ...(normStatus === "running" && !updated[idx].started_at
                  ? { started_at: evTs }
                  : {}),
                ...(normStatus === "done" || normStatus === "failed" || normStatus === "cancelled"
                  ? { finished_at: evTs }
                  : {}),
              };
              return updated;
            }
            return [
              {
                job_id: jid,
                group_id: ev.group_id || "",
                bot: ev.bot || "",
                from_bot: ev.from_bot || "",
                label: ev.label || jid,
                status: normStatus,
                progress: ev.stage_label || "",
                created_at: evTs,
                started_at: normStatus === "running" ? evTs : null,
                finished_at:
                  normStatus === "done" || normStatus === "failed" || normStatus === "cancelled"
                    ? evTs
                    : null,
                duration_s: typeof ev.duration_s === "number" ? ev.duration_s : null,
              },
              ...prev,
            ].slice(0, 12);
          });
        } else if (ev.bot) {
          const bHandle = ev.bot.toLowerCase();
          if (phase === "thinking" || phase === "running") {
            setActiveBots((prev) => {
              const idx = prev.findIndex((b) => b.handle.toLowerCase() === bHandle);
              const nextItem: RoomActivityBotItem = {
                handle: bHandle,
                display_name: ev.display_name || (idx >= 0 ? prev[idx].display_name : bHandle),
                role: ev.role || (idx >= 0 ? prev[idx].role : "worker"),
                state: phase,
                stage_label:
                  ev.stage_label ||
                  (phase === "thinking" ? "正在思考 / 调度" : "正在处理派单"),
                current_job_id: ev.job_id || (idx >= 0 ? prev[idx].current_job_id : null),
                current_job_label: ev.label || (idx >= 0 ? prev[idx].current_job_label : ""),
                queue_depth: ev.queue_depth ?? (idx >= 0 ? prev[idx].queue_depth : 0),
                started_at: idx >= 0 && prev[idx].started_at ? prev[idx].started_at : evTs,
                elapsed_s: 0,
              };
              if (idx >= 0) {
                const cp = [...prev];
                cp[idx] = nextItem;
                return cp;
              }
              return [nextItem, ...prev];
            });
          } else if (phase === "idle") {
            setActiveBots((prev) => prev.filter((b) => b.handle.toLowerCase() !== bHandle));
            setTypingBots((prev) => {
              if (!prev[bHandle]) return prev;
              const next = { ...prev };
              delete next[bHandle];
              return next;
            });
          }
        }
        continue;
      }

      if (ev.type === "room_message") {
        shouldRefreshActivity = true;
        const incoming = ev.message;
        if (incoming && incoming.room_id === curRoom) {
          if (incoming.sender_type === "bot" && incoming.sender) {
            const sLow = incoming.sender.toLowerCase();
            setTypingBots((prev) => {
              const next = { ...prev };
              let changed = false;
              for (const k of Object.keys(next)) {
                if (k.toLowerCase() === sLow) {
                  delete next[k];
                  changed = true;
                }
              }
              return changed ? next : prev;
            });
            setRecentDispatch((prev) => {
              if (!prev) return null;
              if (prev.target_bots.some((tb) => tb.toLowerCase() === sLow)) {
                return null;
              }
              return prev;
            });
          } else if (incoming.sender_type === "human") {
            setRecentDispatch({
              phase: "received",
              target_bots: incoming.mentions || [],
              dispatched_at: incoming.ts || Date.now() / 1000 + clockOffsetSec,
              stage_label: "收到用户指令，等待调度处理",
            });
          }
          setMessages((prev) => {
            if (
              prev.some(
                (m) =>
                  m.msg_id === incoming.msg_id ||
                  (incoming.seq > 0 && m.seq === incoming.seq),
              )
            ) {
              return prev;
            }
            return [...prev, incoming].slice(-200);
          });
          window.setTimeout(() => {
            if (mountedRef.current && selectedRoomRef.current === incoming.room_id) {
              endRef.current?.scrollIntoView({ behavior: "smooth" });
            }
          }, 30);
        } else {
          void loadMessages(curRoom, { silent: true });
        }
      }
    }

    if (shouldRefreshBots) {
      void loadBots();
    }
    if (shouldRefreshActivity) {
      scheduleActivityRefresh(curRoom, 220);
    }
  }, [
    roomEvent,
    roomEvents,
    clockOffsetSec,
    loadActivity,
    loadBots,
    loadMessages,
    loadRooms,
    scheduleActivityRefresh,
  ]);

  const handleSelectRoom = (rid: string) => {
    if (lockedRoomIdRef.current) return;
    if (rid === effectiveRoomId) return;
    setSelectedRoomId(rid);
    onRoomChange?.(rid);
  };

  const handleCreateRoom = async () => {
    if (isReadonly || creating || hideHeader || lockedRoomIdRef.current) return;
    const rid = newRoomId.trim().toLowerCase();
    if (!rid) {
      setErrorMsg("请输入频道 ID（小写字母/数字/下划线/连字符）");
      return;
    }
    setCreating(true);
    setErrorMsg(null);
    try {
      const res = await createRoom({
        room_id: rid,
        title: newRoomTitle.trim() || rid,
        topic: newRoomTopic.trim(),
      });
      if (!mountedRef.current) return;
      setNewRoomId("");
      setNewRoomTitle("");
      setNewRoomTopic("");
      setCreateOpen(false);
      await loadRooms();
      if (mountedRef.current && res.room?.room_id) {
        setSelectedRoomId(res.room.room_id);
        onRoomChange?.(res.room.room_id);
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "创建频道失败");
      }
    } finally {
      if (mountedRef.current) setCreating(false);
    }
  };

  const onlineBots = bots.filter((b) => b.online);
  const botMetaByHandle = useMemo(() => {
    const m: Record<string, BotRosterItem> = {};
    for (const b of bots) {
      m[b.handle.toLowerCase()] = b;
    }
    return m;
  }, [bots]);
  const activeRoomMeta = rooms.find((r) => r.room_id === effectiveRoomId);
  const isMirrorMode =
    activeRoomMeta?.mode === "tg_mirror" ||
    Boolean(activeRoomMeta?.mirror_bound) ||
    activityMirrorBound;
  const defaultBotHandle =
    activeRoomMeta?.default_bot ||
    onlineBots.find((b) => b.role === "coordinator")?.handle ||
    "";

  const [sendingMode, setSendingMode] = useState<ExecutionMode | null>(null);

  const handleSend = async (mode: ExecutionMode = "queue") => {
    const content = draft.trim();
    const attIds = composerAtts.readyAttachmentIds;
    const ctxFiles = [...composerAtts.contextFiles];
    const hasPayload = Boolean(content) || attIds.length > 0 || ctxFiles.length > 0;
    if (isReadonly || sending || composerAtts.isUploading || !hasPayload) return;
    const targetRoom = selectedRoomRef.current;
    setSending(true);
    setSendingMode(mode);
    setErrorMsg(null);
    setFilePickerOpen(false);
    try {
      const res = await sendRoomMessage(targetRoom, {
        content,
        project: ctxFiles.length > 0 && projectId ? projectId : undefined,
        attachments: attIds.length > 0 ? attIds : undefined,
        context_files: ctxFiles.length > 0 ? ctxFiles : undefined,
        execution_mode: mode,
      });
      if (!mountedRef.current) return;
      setDraft("");
      composerAtts.clearAll();
      if (selectedRoomRef.current === targetRoom) {
        const targets =
          res.dispatched_bots && res.dispatched_bots.length > 0
            ? res.dispatched_bots
            : defaultBotHandle
              ? [defaultBotHandle]
              : [];
        if (targets.length > 0) {
          const nowServer = Date.now() / 1000 + clockOffsetSec;
          const isUrgent = mode === "interrupt";
          setRecentDispatch({
            phase: isUrgent ? "urgent_dispatched" : "dispatched",
            target_bots: targets,
            dispatched_at: nowServer,
            stage_label: isUrgent
              ? `⚡ 插队指令已发送至 ${targets.map((b) => `@${b}`).join("、")}，优先调度处理`
              : `已送达 ${targets.map((b) => `@${b}`).join("、")}，等待接单处理`,
          });
          setNowSec(Date.now() / 1000);
        }
        if (res.message) {
          setMessages((prev) => {
            if (
              prev.some(
                (m) =>
                  m.msg_id === res.message.msg_id ||
                  (res.message.seq > 0 && m.seq === res.message.seq),
              )
            ) {
              return prev;
            }
            return [...prev, res.message].slice(-200);
          });
          window.setTimeout(() => {
            if (mountedRef.current && selectedRoomRef.current === targetRoom) {
              endRef.current?.scrollIntoView({ behavior: "smooth" });
            }
          }, 30);
        }
        scheduleActivityRefresh(targetRoom, 250);
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "发送消息失败");
      }
    } finally {
      if (mountedRef.current) {
        setSending(false);
        setSendingMode(null);
      }
    }
  };

  const roomMetaLoading = roomsLoading || msgsLoading;
  const roomMetaTopic = activeRoomMeta?.topic || "";
  const onlineBotCount = onlineBots.length;

  useEffect(() => {
    onRoomMetaChangeRef.current?.({
      isMirrorMode,
      defaultBotHandle,
      loading: roomMetaLoading,
      topic: roomMetaTopic,
      onlineBotCount,
    });
  }, [isMirrorMode, defaultBotHandle, roomMetaLoading, roomMetaTopic, onlineBotCount]);

  // Derived real-time pipeline collections
  const serverNowSec = nowSec + clockOffsetSec;
  const runningJobs = useMemo(
    () => recentJobs.filter((j) => j.status === "running"),
    [recentJobs],
  );
  const queuedJobs = useMemo(
    () => recentJobs.filter((j) => j.status === "queued"),
    [recentJobs],
  );
  const completedJobs = useMemo(
    () =>
      recentJobs.filter(
        (j) => j.status === "done" || j.status === "failed" || j.status === "cancelled",
      ),
    [recentJobs],
  );

  // Merge activeBots with typingBots & runningJobs so every active bot appears cleanly once
  const mergedActiveBots = useMemo<RoomActivityBotItem[]>(() => {
    const byHandle = new Map<string, RoomActivityBotItem>();
    for (const b of activeBots) {
      const h = b.handle.toLowerCase();
      byHandle.set(h, b);
    }
    for (const rj of runningJobs) {
      const h = (rj.bot || "").toLowerCase();
      if (!h) continue;
      const existing = byHandle.get(h);
      const meta = botMetaByHandle[h];
      byHandle.set(h, {
        handle: h,
        display_name: existing?.display_name || meta?.display_name || h,
        role: existing?.role || meta?.role || "worker",
        state: "running",
        stage_label: rj.progress || existing?.stage_label || "正在处理派单",
        current_job_id: rj.job_id,
        current_job_label: rj.label || existing?.current_job_label || "",
        queue_depth: existing?.queue_depth ?? meta?.queue_depth ?? 0,
        started_at: rj.started_at || existing?.started_at || rj.created_at || null,
        elapsed_s: existing?.elapsed_s ?? rj.duration_s ?? 0,
      });
    }
    for (const [rawHandle, startedTs] of Object.entries(typingBots)) {
      const h = rawHandle.toLowerCase();
      if (!byHandle.has(h)) {
        const meta = botMetaByHandle[h];
        const role = meta?.role || "worker";
        byHandle.set(h, {
          handle: h,
          display_name: meta?.display_name || h,
          role,
          state: "thinking",
          stage_label: role === "coordinator" ? "正在思考 / 调度" : "正在思考 / 生成回复",
          current_job_id: null,
          current_job_label: "",
          queue_depth: meta?.queue_depth ?? 0,
          started_at: startedTs,
          elapsed_s: 0,
        });
      }
    }
    const order: Record<string, number> = { thinking: 0, running: 1, queued: 2, idle: 3 };
    return Array.from(byHandle.values())
      .filter((b) => b.state !== "idle")
      .sort((a, b) => (order[a.state] ?? 9) - (order[b.state] ?? 9));
  }, [activeBots, runningJobs, typingBots, botMetaByHandle]);

  const isRecentDispatchActive = useMemo(() => {
    if (!recentDispatch) return false;
    const age = serverNowSec - recentDispatch.dispatched_at;
    return age >= -5 && age <= 60;
  }, [recentDispatch, serverNowSec]);

  const hasLivePipelineActivity =
    runningJobs.length > 0 ||
    queuedJobs.length > 0 ||
    mergedActiveBots.length > 0 ||
    isRecentDispatchActive;

  // Tick 1-second timer ONLY while live activity exists
  useEffect(() => {
    if (!hasLivePipelineActivity) return;
    setNowSec(Date.now() / 1000);
    const id = window.setInterval(() => {
      if (mountedRef.current) {
        setNowSec(Date.now() / 1000);
      }
    }, 1000);
    return () => window.clearInterval(id);
  }, [hasLivePipelineActivity]);

  // Build 5-stage horizontal pipeline timeline when active
  const pipelineSteps = useMemo<PipelineStepItem[]>(() => {
    const coordBot = mergedActiveBots.find((b) => b.role === "coordinator");
    const activeWorkerBots = mergedActiveBots.filter(
      (b) => b.role !== "coordinator" && (b.state === "running" || b.state === "thinking"),
    );
    const primaryRunJob = runningJobs[0] || null;
    const primaryQueuedJob = queuedJobs[0] || null;
    const latestDoneJob = completedJobs[0] || null;
    const latestMsg = messages[messages.length - 1];
    const recentHumanMsg = [...messages].reverse().find((m) => m.sender_type === "human");
    const hasActiveJob = Boolean(primaryRunJob || primaryQueuedJob);

    // Step 1: Received / Dispatched
    const step1Status: PipelineStepItem["status"] =
      hasActiveJob || mergedActiveBots.length > 0 || recentHumanMsg
        ? "done"
        : isRecentDispatchActive
          ? "active"
          : "pending";
    const step1Sub = isRecentDispatchActive && recentDispatch?.target_bots?.length
      ? recentDispatch.target_bots.map((b) => `@${b}`).join(" ")
      : recentHumanMsg?.source === "tg"
        ? "来自 TG 群"
        : recentHumanMsg?.source === "web"
          ? "来自 WebUI"
          : undefined;

    // Step 2: Coordinator thinking / scheduling
    const coordHandle = coordBot?.handle || defaultBotHandle || "总指挥";
    const coordElapsed =
      coordBot && coordBot.started_at
        ? formatDurationClock(serverNowSec - coordBot.started_at)
        : isRecentDispatchActive && recentDispatch?.dispatched_at
          ? formatDurationClock(serverNowSec - recentDispatch.dispatched_at)
          : undefined;
    const step2Status: PipelineStepItem["status"] = coordBot
      ? "active"
      : hasActiveJob || (latestMsg?.sender_type === "bot" && !isRecentDispatchActive)
        ? "done"
        : isRecentDispatchActive
          ? "active"
          : "pending";

    // Step 3: Dispatched job(s)
    const activeTotalJobs = runningJobs.length + queuedJobs.length;
    const step3Status: PipelineStepItem["status"] = hasActiveJob
      ? "done"
      : latestDoneJob && serverNowSec - (latestDoneJob.finished_at || 0) < 90
        ? "done"
        : "pending";
    const step3Label = primaryRunJob
      ? `已派单 ${primaryRunJob.job_id}`
      : primaryQueuedJob
        ? `已排单 ${primaryQueuedJob.job_id}`
        : "等待派单";
    const step3Sub =
      activeTotalJobs > 1
        ? `${runningJobs.length} 执行 · ${queuedJobs.length} 排队`
        : primaryRunJob
          ? `@${primaryRunJob.bot}`
          : primaryQueuedJob
            ? `@${primaryQueuedJob.bot}`
            : undefined;

    // Step 4: Worker running / tool execution
    const primaryWorker = activeWorkerBots[0] || null;
    const workerStart =
      primaryRunJob?.started_at || primaryWorker?.started_at || null;
    const workerClock = workerStart ? formatDurationClock(serverNowSec - workerStart) : undefined;
    const step4Status: PipelineStepItem["status"] =
      primaryRunJob || primaryWorker
        ? "active"
        : primaryQueuedJob
          ? "pending"
          : latestDoneJob && serverNowSec - (latestDoneJob.finished_at || 0) < 90
            ? latestDoneJob.status === "failed"
              ? "error"
              : "done"
            : "pending";
    const step4Label = primaryRunJob
      ? `@${primaryRunJob.bot} 处理中${workerClock ? ` (${workerClock})` : ""}`
      : primaryWorker
        ? `@${primaryWorker.handle} 处理中${workerClock ? ` (${workerClock})` : ""}`
        : primaryQueuedJob
          ? `@${primaryQueuedJob.bot} 排队等待`
          : "Worker 执行";
    const step4Sub =
      primaryRunJob?.progress ||
      primaryWorker?.stage_label ||
      (primaryQueuedJob ? `队列中 (${queuedJobs.length})` : undefined);

    // Step 5: Delivery
    const recentlyDelivered =
      !hasActiveJob &&
      !coordBot &&
      Boolean(
        latestDoneJob &&
          latestDoneJob.finished_at &&
          serverNowSec - latestDoneJob.finished_at < 90,
      );
    const step5Status: PipelineStepItem["status"] = recentlyDelivered
      ? latestDoneJob?.status === "failed"
        ? "error"
        : "done"
      : "pending";

    const isUrgentDispatch =
      isRecentDispatchActive && recentDispatch?.phase === "urgent_dispatched";
    return [
      {
        id: "received",
        icon: isUrgentDispatch ? "⚡" : "📨",
        label: isUrgentDispatch ? "⚡ 插队指令已发送" : "指令已送达",
        sublabel: step1Sub,
        status: isUrgentDispatch ? "active" : step1Status,
      },
      {
        id: "coord",
        icon: "🧠",
        label: coordBot
          ? `@${coordHandle} ${coordBot.stage_label || "调度/思考中"}${coordElapsed ? ` (${coordElapsed})` : ""}`
          : isRecentDispatchActive && !hasActiveJob
            ? `@${coordHandle} 接单思考中${coordElapsed ? ` (${coordElapsed})` : ""}`
            : `@${coordHandle} 调度`,
        status: step2Status,
      },
      {
        id: "dispatch",
        icon: "📤",
        label: step3Label,
        sublabel: step3Sub,
        status: step3Status,
      },
      {
        id: "worker",
        icon: "⚙️",
        label: step4Label,
        sublabel: step4Sub,
        status: step4Status,
      },
      {
        id: "delivery",
        icon: step5Status === "error" ? "⚠️" : "✅",
        label: step5Status === "error" ? "异常结束" : "交付验收",
        sublabel:
          recentlyDelivered && latestDoneJob?.duration_s != null
            ? `耗时 ${formatDurationClock(latestDoneJob.duration_s)}`
            : undefined,
        status: step5Status,
      },
    ];
  }, [
    mergedActiveBots,
    runningJobs,
    queuedJobs,
    completedJobs,
    messages,
    isRecentDispatchActive,
    recentDispatch,
    defaultBotHandle,
    serverNowSec,
  ]);

  // Live in-progress bubbles at the bottom of the timeline
  const liveBubbles = useMemo(() => {
    const items: {
      key: string;
      handle: string;
      displayName: string;
      role: string;
      state: string;
      stageLabel: string;
      jobId: string | null;
      jobLabel: string;
      elapsedStr: string;
    }[] = [];

    for (const b of mergedActiveBots) {
      if (b.state === "queued") continue;
      const elapsed = b.started_at ? Math.max(0, serverNowSec - b.started_at) : b.elapsed_s || 0;
      items.push({
        key: `live-bot-${b.handle}`,
        handle: b.handle,
        displayName: b.display_name || b.handle,
        role: b.role,
        state: b.state,
        stageLabel: b.stage_label || (b.state === "thinking" ? "正在思考 / 调度" : "正在处理派单"),
        jobId: b.current_job_id,
        jobLabel: b.current_job_label || "",
        elapsedStr: formatDurationClock(elapsed),
      });
    }

    if (items.length === 0 && isRecentDispatchActive && recentDispatch) {
      const targets =
        recentDispatch.target_bots.length > 0
          ? recentDispatch.target_bots
          : defaultBotHandle
            ? [defaultBotHandle]
            : [];
      const primary = targets[0] || "coordinator";
      const meta = botMetaByHandle[primary.toLowerCase()];
      const elapsed = Math.max(0, serverNowSec - recentDispatch.dispatched_at);
      items.push({
        key: `live-dispatch-${primary}`,
        handle: primary,
        displayName: meta?.display_name || primary,
        role: meta?.role || "coordinator",
        state: "thinking",
        stageLabel: recentDispatch.stage_label || `已送达 @${primary}，等待接单处理`,
        jobId: null,
        jobLabel: "",
        elapsedStr: formatDurationClock(elapsed),
      });
    }

    return items;
  }, [mergedActiveBots, isRecentDispatchActive, recentDispatch, defaultBotHandle, botMetaByHandle, serverNowSec]);

  const activeTypingHandles = Object.keys(typingBots);
  const isUrgentDispatchActive =
    isRecentDispatchActive && recentDispatch?.phase === "urgent_dispatched";
  const hasBusyBotOrDispatch =
    hasLivePipelineActivity ||
    onlineBots.some((b) => b.busy) ||
    activeTypingHandles.length > 0;
  const latestCompletedJob = completedJobs[0] || null;

  const formatRoleBadge = (roleRaw?: string): { label: string; cls: string } | null => {
    const r = (roleRaw || "").toLowerCase();
    if (r === "coordinator") {
      return { label: "总指挥", cls: "bg-sky-500/20 text-sky-300 border border-sky-500/30" };
    }
    if (r === "worker") {
      return {
        label: "Worker",
        cls: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/25",
      };
    }
    if (r === "peer") {
      return {
        label: "协作",
        cls: "bg-indigo-500/15 text-indigo-300 border border-indigo-500/25",
      };
    }
    return null;
  };

  const renderJobStatusBadge = (status: string) => {
    switch (status) {
      case "running":
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-500/35 text-sky-300 text-[10px] font-medium shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
            执行中
          </span>
        );
      case "queued":
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/35 text-amber-300 text-[10px] font-medium shrink-0">
            <Clock className="w-2.5 h-2.5" />
            排队中
          </span>
        );
      case "done":
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-medium shrink-0">
            <CheckCircle2 className="w-2.5 h-2.5" />
            已完成
          </span>
        );
      case "failed":
      case "error":
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[10px] font-medium shrink-0">
            <XCircle className="w-2.5 h-2.5" />
            失败
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 text-[10px] shrink-0">
            已取消
          </span>
        );
    }
  };

  return (
    <div
      className="relative flex-1 min-h-0 min-w-0 flex flex-col bg-slate-950 overflow-hidden"
      {...composerAtts.dragHandlers}
    >
      <DragDropOverlay visible={composerAtts.isDragging} />

      {/* Header Bar */}
      {!hideHeader && (
        <header className="shrink-0 px-3 py-2 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-100">
            <Users className="w-4 h-4 text-sky-400" />
            <span>多 Bot 群聊室</span>
          </div>

          <select
            value={effectiveRoomId}
            onChange={(e) => handleSelectRoom(e.target.value)}
            disabled={Boolean(normalizedLockedRoomId)}
            aria-label="选择群聊频道"
            className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-44 disabled:opacity-60"
          >
            {rooms.length === 0 && <option value={effectiveRoomId}># {effectiveRoomId}</option>}
            {rooms.map((r) => (
              <option key={r.room_id} value={r.room_id}>
                # {r.title || r.room_id}
              </option>
            ))}
          </select>

          {isMirrorMode && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-[10px] font-medium text-emerald-300">
                TG 工作群镜像
              </span>
              <span className="px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-[10px] font-medium text-sky-300">
                {defaultBotHandle ? `默认 @${defaultBotHandle} 总指挥接单` : "默认总指挥接单"}
              </span>
            </div>
          )}

          {activeRoomMeta?.topic && (
            <span className="text-[11px] text-slate-400 truncate max-w-xs hidden sm:inline">
              {activeRoomMeta.topic}
            </span>
          )}

          <div className="ml-auto flex items-center gap-1.5">
            {!isReadonly && !normalizedLockedRoomId && (
              <button
                type="button"
                onClick={() => setCreateOpen((v) => !v)}
                className="h-7 px-2 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 text-xs text-slate-200 inline-flex items-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                新建频道
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                void loadRooms();
                void loadBots();
                void loadMessages(effectiveRoomId);
                void loadActivity(effectiveRoomId);
              }}
              title="刷新群聊室"
              className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${roomsLoading || msgsLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </header>
      )}

      {/* Inline Create Room Panel */}
      {!hideHeader && !normalizedLockedRoomId && createOpen && !isReadonly && (
        <div className="shrink-0 px-3 py-2 border-b border-slate-800 bg-slate-900/90 flex flex-wrap items-center gap-2 text-xs">
          <input
            type="text"
            value={newRoomId}
            onChange={(e) => setNewRoomId(e.target.value)}
            placeholder="频道 ID（如 dev-room）"
            className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-100 w-36 focus:outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={newRoomTitle}
            onChange={(e) => setNewRoomTitle(e.target.value)}
            placeholder="标题（可选）"
            className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-100 w-32 focus:outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={newRoomTopic}
            onChange={(e) => setNewRoomTopic(e.target.value)}
            placeholder="主题说明（可选）"
            className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-100 flex-1 min-w-36 focus:outline-none focus:border-sky-500"
          />
          <button
            type="button"
            disabled={creating}
            onClick={() => void handleCreateRoom()}
            className="h-7 px-3 rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white font-medium cursor-pointer"
          >
            {creating ? "创建中…" : "创建"}
          </button>
        </div>
      )}

      {isReadonly && (
        <div className="shrink-0 px-3 py-1.5 border-b border-amber-500/30 bg-amber-500/10 text-xs text-amber-200 flex items-center gap-2">
          <Lock className="w-3.5 h-3.5 shrink-0" />
          <span>只读权限（readonly）：可实时查看团队协作进度与历史，发言与新建频道已禁用。</span>
        </div>
      )}

      {errorMsg && (
        <div className="shrink-0 px-3 py-1.5 border-b border-rose-500/30 bg-rose-500/10 text-xs text-rose-200 flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            {errorMsg}
          </span>
          <button
            type="button"
            onClick={() => setErrorMsg(null)}
            className="underline cursor-pointer shrink-0"
          >
            关闭
          </button>
        </div>
      )}

      {/* ① Compact Live Pipeline Panel (auto-expands when active, collapses to slim pill when idle) */}
      <div
        className={`shrink-0 border-b transition-colors ${
          hasLivePipelineActivity
            ? "border-sky-500/25 bg-slate-900/90"
            : "border-slate-800/80 bg-slate-900/45"
        }`}
      >
        {hasLivePipelineActivity ? (
          <div className="px-3 py-2 space-y-2">
            {/* Pipeline header row */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-sky-200">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                </span>
                实时处理链路
              </span>

              {isUrgentDispatchActive && (
                <span className="px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-400/50 text-[10px] font-semibold text-amber-200 inline-flex items-center gap-1 animate-pulse">
                  <Zap className="w-2.5 h-2.5 fill-current" />
                  <span>插队指令已发送</span>
                </span>
              )}
              {runningJobs.length > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-sky-500/15 border border-sky-500/30 text-[10px] font-medium text-sky-300 tabular-nums">
                  {runningJobs.length} 执行中
                </span>
              )}
              {queuedJobs.length > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-amber-500/15 border border-amber-500/30 text-[10px] font-medium text-amber-300 tabular-nums">
                  {queuedJobs.length} 排队中
                </span>
              )}
              {runningJobs.length === 0 && queuedJobs.length === 0 && mergedActiveBots.length > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-[10px] font-medium text-emerald-300">
                  {mergedActiveBots.length} Bot 处理中
                </span>
              )}

              {recentJobs.length > 0 && (
                <button
                  type="button"
                  onClick={() => setQueueExpanded((v) => !v)}
                  className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-slate-700/80 bg-slate-950/70 hover:bg-slate-800 text-[10px] text-slate-300 cursor-pointer"
                >
                  <Layers className="w-3 h-3 text-sky-400" />
                  <span>
                    {queueExpanded
                      ? "收起队列"
                      : queuedJobs.length > 0
                        ? `查看多单队列 (${runningJobs.length + queuedJobs.length})`
                        : `派单流水 (${recentJobs.length})`}
                  </span>
                  {queueExpanded ? (
                    <ChevronUp className="w-3 h-3" />
                  ) : (
                    <ChevronDown className="w-3 h-3" />
                  )}
                </button>
              )}
            </div>

            {/* Horizontal scrollable 5-stage live stepper */}
            <div className="flex items-center gap-1 overflow-x-auto pb-0.5 no-scrollbar">
              {pipelineSteps.map((step, idx) => {
                const pillCls =
                  step.status === "active"
                    ? "border-sky-500/45 bg-sky-500/15 text-sky-100 shadow-[0_0_12px_-4px_rgba(56,189,248,0.5)]"
                    : step.status === "done"
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                      : step.status === "error"
                        ? "border-rose-500/35 bg-rose-500/10 text-rose-200"
                        : "border-slate-800 bg-slate-950/60 text-slate-500";
                return (
                  <div key={step.id} className="flex items-center gap-1 shrink-0">
                    <div
                      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[11px] leading-tight ${pillCls}`}
                    >
                      <span className="text-xs leading-none">{step.icon}</span>
                      <div className="flex flex-col min-w-0">
                        <span className="font-medium whitespace-nowrap tabular-nums">
                          {step.label}
                        </span>
                        {step.sublabel && (
                          <span className="text-[10px] opacity-80 whitespace-nowrap truncate max-w-44">
                            {step.sublabel}
                          </span>
                        )}
                      </div>
                      {step.status === "active" && (
                        <Loader2 className="w-3 h-3 animate-spin text-sky-300 shrink-0" />
                      )}
                    </div>
                    {idx < pipelineSteps.length - 1 && (
                      <span className="text-slate-600 text-[10px] select-none">→</span>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Expandable queue & recent jobs drawer */}
            {queueExpanded && recentJobs.length > 0 && (
              <div className="pt-1.5 border-t border-slate-800/80 space-y-1 max-h-48 overflow-y-auto">
                {recentJobs.slice(0, 8).map((job, idx) => {
                  const isRunning = job.status === "running";
                  const isQueued = job.status === "queued";
                  const queueRank = isQueued
                    ? queuedJobs.findIndex((qj) => qj.job_id === job.job_id) + 1
                    : 0;
                  const liveDur = isRunning
                    ? formatDurationClock(
                        job.started_at ? serverNowSec - job.started_at : job.duration_s,
                      )
                    : isQueued
                      ? `等待 ${formatDurationClock(serverNowSec - job.created_at)}`
                      : job.duration_s != null
                        ? formatDurationClock(job.duration_s)
                        : "";
                  return (
                    <div
                      key={`${job.job_id}-${idx}`}
                      className={`rounded-lg border px-2.5 py-1.5 text-[11px] flex items-center gap-2 ${
                        isRunning
                          ? "border-sky-500/35 bg-sky-500/10"
                          : isQueued
                            ? "border-amber-500/25 bg-amber-500/5"
                            : "border-slate-800/80 bg-slate-950/60 opacity-80"
                      }`}
                    >
                      {renderJobStatusBadge(job.status)}
                      {isQueued && queueRank > 0 && (
                        <span className="text-[10px] font-mono text-amber-300/90 shrink-0">
                          #{queueRank}
                        </span>
                      )}
                      <span className="font-mono text-[10px] text-slate-400 shrink-0">
                        {job.job_id}
                      </span>
                      <span className="font-mono text-[10px] text-sky-300 shrink-0">
                        @{job.bot}
                      </span>
                      <span className="text-slate-200 truncate flex-1 min-w-0" title={job.label}>
                        {job.label || "未命名派单"}
                      </span>
                      {isRunning && job.progress && (
                        <span className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-900/90 border border-slate-700/80 text-[10px] text-cyan-200 shrink-0 max-w-44 truncate">
                          <Wrench className="w-2.5 h-2.5 shrink-0" />
                          <span className="truncate">{job.progress}</span>
                        </span>
                      )}
                      {liveDur && (
                        <span className="font-mono text-[10px] text-slate-400 tabular-nums shrink-0">
                          {liveDur}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        ) : (
          /* Idle slim status capsule */
          <div className="px-3 py-1.5">
            <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
              <span className="inline-flex items-center gap-1.5 text-slate-300">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/80" />
                <span>团队空闲</span>
              </span>
              <span className="text-slate-600">·</span>
              <span className="tabular-nums">{onlineBotCount} Bot 在线</span>
              {latestCompletedJob && (
                <>
                  <span className="text-slate-600 hidden sm:inline">·</span>
                  <span className="hidden sm:inline-flex items-center gap-1 text-slate-400 truncate max-w-sm">
                    <Activity className="w-3 h-3 text-emerald-400/80 shrink-0" />
                    <span className="truncate">
                      最近{latestCompletedJob.status === "failed" ? "异常" : "交付"}：
                      <span className="font-mono text-slate-300 ml-1">
                        {latestCompletedJob.job_id}
                      </span>
                      {latestCompletedJob.label ? ` · ${latestCompletedJob.label}` : ""}
                    </span>
                    {latestCompletedJob.duration_s != null && (
                      <span className="font-mono text-[10px] text-slate-500 shrink-0">
                        ({formatDurationClock(latestCompletedJob.duration_s)})
                      </span>
                    )}
                  </span>
                </>
              )}
              {recentJobs.length > 0 && (
                <button
                  type="button"
                  onClick={() => setQueueExpanded((v) => !v)}
                  className="ml-auto inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-slate-800 bg-slate-950/60 hover:bg-slate-800 text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <span>{queueExpanded ? "收起近期派单" : `近期派单 (${recentJobs.length})`}</span>
                  {queueExpanded ? (
                    <ChevronUp className="w-3 h-3" />
                  ) : (
                    <ChevronDown className="w-3 h-3" />
                  )}
                </button>
              )}
            </div>

            {queueExpanded && recentJobs.length > 0 && (
              <div className="mt-2 pt-1.5 border-t border-slate-800/70 space-y-1 max-h-40 overflow-y-auto">
                {recentJobs.slice(0, 6).map((job, idx) => (
                  <div
                    key={`idle-${job.job_id}-${idx}`}
                    className="rounded-lg border border-slate-800/75 bg-slate-950/55 px-2.5 py-1 text-[11px] flex items-center gap-2"
                  >
                    {renderJobStatusBadge(job.status)}
                    <span className="font-mono text-[10px] text-slate-400 shrink-0">
                      {job.job_id}
                    </span>
                    <span className="font-mono text-[10px] text-sky-300/90 shrink-0">
                      @{job.bot}
                    </span>
                    <span className="text-slate-300 truncate flex-1 min-w-0" title={job.label}>
                      {job.label || "未命名派单"}
                    </span>
                    {job.duration_s != null && (
                      <span className="font-mono text-[10px] text-slate-500 tabular-nums shrink-0">
                        {formatDurationClock(job.duration_s)}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ② Messages Timeline with Stage Badges & Live In-Progress Bubbles */}
      <div className="flex-1 min-h-0 overflow-y-auto px-3.5 py-3 space-y-2.5">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-8 px-4">
            <Hash className="w-8 h-8 text-slate-600 mb-2" />
            <div className="text-sm font-medium text-slate-200">
              欢迎来到 #{activeRoomMeta?.title || effectiveRoomId}
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              {isMirrorMode
                ? "已实时镜像当前 Telegram 工作群：直接输入消息即由总指挥接单并派活，全链路处理环节实时同步。"
                : "在下方输入 @ 机器人名 即可点名在线 Bot 协作讨论（已内置防死循环接力护栏）。"}
            </p>
          </div>
        ) : (
          messages.map((m) => {
            if (m.sender_type === "system") {
              return (
                <div
                  key={m.msg_id}
                  className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 flex items-start gap-2"
                >
                  <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-amber-300" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold">系统护栏</span>
                      {m.blocked_reason && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/20 font-mono text-[10px]">
                          {m.blocked_reason}
                        </span>
                      )}
                      <span className="text-[10px] text-amber-300/70 ml-auto font-mono">
                        {formatTime(m.ts)}
                      </span>
                    </div>
                    <div className="mt-0.5 break-words">{m.content}</div>
                  </div>
                </div>
              );
            }

            const isHuman = m.sender_type === "human";
            const senderBotMeta = !isHuman ? botMetaByHandle[m.sender.toLowerCase()] : undefined;
            const roleBadge = !isHuman
              ? formatRoleBadge(m.sender_role || senderBotMeta?.role)
              : null;
            const stageTag = !isHuman ? inferClientStageTag(m) : "";
            const stageBadge = !isHuman ? getStageBadgeMeta(stageTag) : null;
            const msgJobId = !isHuman ? extractClientJobId(m) : "";

            const botBubbleAccent =
              stageTag === "ack"
                ? "bg-slate-900/85 border-cyan-500/30"
                : stageTag === "dispatch"
                  ? "bg-slate-900/85 border-indigo-500/30"
                  : stageTag === "delivery"
                    ? "bg-slate-900/85 border-emerald-500/30"
                    : stageTag === "error"
                      ? "bg-slate-900/85 border-rose-500/35"
                      : "bg-slate-900/85 border-slate-800";

            return (
              <div
                key={m.msg_id}
                className={`flex ${isHuman ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[92%] md:max-w-[84%] rounded-2xl px-3.5 py-2.5 border text-slate-100 ${
                    isHuman
                      ? "bg-sky-600/20 border-sky-500/35"
                      : botBubbleAccent
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1 text-[11px] text-slate-400 flex-wrap">
                    {!isHuman && <Bot className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                    <span className="font-medium text-slate-200">{m.sender}</span>
                    {roleBadge && (
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-medium ${roleBadge.cls}`}>
                        {roleBadge.label}
                      </span>
                    )}
                    {isHuman && isMirrorMode && (
                      <span className="px-1.5 py-0.2 rounded bg-sky-500/15 border border-sky-500/30 text-[10px] text-sky-200">
                        📨 指令
                      </span>
                    )}
                    {stageBadge && (
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-medium ${stageBadge.cls}`}>
                        {stageBadge.label}
                      </span>
                    )}
                    {msgJobId && (
                      <span className="px-1.5 py-0.2 rounded bg-slate-950/80 border border-slate-700/80 font-mono text-[10px] text-slate-300">
                        {msgJobId}
                      </span>
                    )}
                    {isMirrorMode && m.source && (
                      <span className="px-1 py-0.2 rounded bg-slate-800/90 font-mono text-[10px] text-slate-400 uppercase">
                        {m.source === "web" ? "Web" : "TG"}
                      </span>
                    )}
                    {m.hop > 0 && (
                      <span className="px-1 py-0.5 rounded bg-slate-800 font-mono text-[10px] text-slate-300">
                        hop {m.hop}
                      </span>
                    )}
                    <span className="ml-auto text-[10px] text-slate-500 font-mono">
                      #{m.seq} · {formatTime(m.ts)}
                    </span>
                  </div>
                  {isHuman ? (
                    <div>
                      <MessageAttachmentsDisplay
                        attachments={m.attachments}
                        contextFiles={m.context_files}
                        onPreviewImage={(src, name) => setLightboxImage({ src, name })}
                      />
                      {m.content && (
                        <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                          {m.content}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div>
                      <MessageAttachmentsDisplay
                        attachments={m.attachments}
                        contextFiles={m.context_files}
                        onPreviewImage={(src, name) => setLightboxImage({ src, name })}
                      />
                      <SafeMarkdown content={m.content} />
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}

        {/* Dynamic Live In-Progress Bot Bubbles */}
        {liveBubbles.map((item) => {
          const roleBadge = formatRoleBadge(item.role);
          const isThinking = item.state === "thinking";
          return (
            <div key={item.key} className="flex justify-start">
              <div className="max-w-[92%] md:max-w-[82%] rounded-2xl px-3.5 py-2.5 border border-dashed border-sky-500/45 bg-sky-500/[0.07] text-slate-100 space-y-1.5">
                <div className="flex items-center gap-1.5 text-[11px] flex-wrap">
                  <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin shrink-0" />
                  <span className="font-medium text-sky-100">@{item.handle}</span>
                  {item.displayName && item.displayName !== item.handle && (
                    <span className="text-slate-400">({item.displayName})</span>
                  )}
                  {roleBadge && (
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-medium ${roleBadge.cls}`}>
                      {roleBadge.label}
                    </span>
                  )}
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded bg-sky-500/20 border border-sky-500/35 text-[10px] text-sky-200 font-medium">
                    <span className="w-1.5 h-1.5 rounded-full bg-sky-300 animate-pulse" />
                    {isThinking ? "思考 / 调度中" : "执行处理中"}
                  </span>
                  {item.jobId && (
                    <span className="px-1.5 py-0.2 rounded bg-slate-950/80 border border-slate-700/80 font-mono text-[10px] text-slate-300">
                      {item.jobId}
                    </span>
                  )}
                  <span className="ml-auto font-mono text-[10px] text-sky-300 tabular-nums">
                    已耗时 {item.elapsedStr}
                  </span>
                </div>

                <div className="text-xs text-slate-200 leading-relaxed break-words">
                  {item.jobLabel ? (
                    <span>
                      正在处理【<span className="text-slate-100 font-medium">{item.jobLabel}</span>】
                    </span>
                  ) : (
                    <span>{item.stageLabel}</span>
                  )}
                </div>

                {item.jobLabel && item.stageLabel && (
                  <div className="flex items-center gap-1.5 text-[11px] text-cyan-200/90">
                    <Wrench className="w-3 h-3 shrink-0 text-cyan-300" />
                    <span className="truncate">{item.stageLabel}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {/* Compact Queued Tasks Card at bottom of timeline */}
        {queuedJobs.length > 0 && (
          <div className="flex justify-start">
            <div className="max-w-[92%] md:max-w-[82%] rounded-xl border border-dashed border-amber-500/35 bg-amber-500/[0.06] px-3 py-2 text-xs text-amber-100 space-y-1">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-amber-200">
                <Clock className="w-3.5 h-3.5 shrink-0 text-amber-300" />
                <span>排队等待执行（{queuedJobs.length} 单）</span>
              </div>
              <div className="space-y-1">
                {queuedJobs.slice(0, 3).map((qj, idx) => (
                  <div
                    key={`q-bubble-${qj.job_id}`}
                    className="flex items-center gap-1.5 text-[11px] text-amber-100/90 flex-wrap"
                  >
                    <span className="font-mono text-[10px] text-amber-300">#{idx + 1}</span>
                    <span className="font-mono text-[10px] text-sky-300">@{qj.bot}</span>
                    <span className="font-mono text-[10px] text-slate-400">{qj.job_id}</span>
                    <span className="truncate max-w-xs sm:max-w-md">
                      {qj.label ? `【${qj.label}】` : "等待前序任务完成"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div ref={endRef} />
      </div>

      {/* Typing + Quick Bot Mention Chips + Composer */}
      <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5 space-y-2">
        {activeTypingHandles.length > 0 && liveBubbles.length === 0 && (
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-300">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>{activeTypingHandles.map((b) => `@${b}`).join("、")} 正在回复…</span>
          </div>
        )}

        {!isReadonly && onlineBots.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-[10px] text-slate-500 mr-0.5">
              {isMirrorMode ? "指定点名：" : "点名："}
            </span>
            {onlineBots.slice(0, 8).map((b) => {
              const isBusyNow =
                b.busy ||
                mergedActiveBots.some((ab) => ab.handle.toLowerCase() === b.handle.toLowerCase());
              return (
                <button
                  key={b.handle}
                  type="button"
                  onClick={() =>
                    setDraft((prev) =>
                      prev.includes(`@${b.handle}`)
                        ? prev
                        : `${prev}${prev && !prev.endsWith(" ") ? " " : ""}@${b.handle} `,
                    )
                  }
                  className="px-2 py-0.5 rounded-full border border-slate-800 bg-slate-950 hover:bg-slate-800 text-[11px] text-sky-300 font-mono inline-flex items-center gap-1 cursor-pointer"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      isBusyNow ? "bg-amber-400 animate-pulse" : "bg-emerald-400"
                    }`}
                  />
                  <span>@{b.handle}</span>
                  {b.role === "coordinator" && (
                    <span className="font-sans text-[9px] px-1 rounded bg-sky-500/20 text-sky-200">
                      总指挥
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}

        <div className="relative rounded-2xl border border-slate-800 bg-slate-950/95 focus-within:border-sky-500/70 transition-colors p-2">
          {!isReadonly && projectId && (
            <WorkspaceFilePickerPopover
              open={filePickerOpen}
              projectId={projectId}
              query={filePickerQuery}
              showSearchInput
              selectedFiles={composerAtts.contextFiles}
              activeIndex={filePickerActiveIdx}
              onActiveIndexChange={setFilePickerActiveIdx}
              onQueryChange={setFilePickerQuery}
              onSelect={(relPath) => {
                composerAtts.addContextFile(relPath);
                setFilePickerOpen(false);
                setFilePickerQuery("");
              }}
              onClose={() => {
                setFilePickerOpen(false);
                setFilePickerQuery("");
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
            rows={2}
            value={draft}
            disabled={isReadonly || sending}
            onFocus={() => onFocusInput?.()}
            onPaste={composerAtts.handlePaste}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (
                (e.ctrlKey || e.metaKey) &&
                e.shiftKey &&
                e.key === "Enter" &&
                !isReadonly &&
                hasBusyBotOrDispatch
              ) {
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
                ? "只读权限已禁用群聊发言"
                : isMirrorMode
                  ? defaultBotHandle
                    ? `直接发送指令、拖拽/粘贴图片（默认 @${defaultBotHandle} 总指挥接单派活，也可 @ 指定 Bot）…`
                    : "直接发送指令、拖拽/粘贴图片（默认总指挥接单派活，也可 @ 指定 Bot）…"
                  : "输入消息、拖拽/粘贴图片并用 @ 点名在线 Bot…（Enter 发送）"
            }
            className="w-full resize-none bg-transparent px-1.5 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:opacity-50"
          />

          <div className="mt-1.5 pt-1.5 border-t border-slate-800/75 flex items-center justify-between gap-2 flex-wrap sm:flex-nowrap">
            <div className="flex items-center gap-1 min-w-0">
              {!isReadonly && (
                <>
                  <input
                    ref={fileInputRef}
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
                    disabled={sending}
                    title={SUPPORTED_FORMATS_TOOLTIP}
                    aria-label="添加图片或文件"
                    onClick={() => fileInputRef.current?.click()}
                    className="h-7 px-2 rounded-lg border border-slate-800 bg-slate-900/90 hover:bg-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 text-xs inline-flex items-center gap-1 cursor-pointer disabled:opacity-40"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">文件/图片</span>
                  </button>
                  {projectId && (
                    <button
                      type="button"
                      disabled={sending}
                      title={`引用项目「${projectId}」中的工作区文件`}
                      aria-label="引用工作区文件"
                      onClick={() => {
                        setFilePickerQuery("");
                        setFilePickerActiveIdx(0);
                        setFilePickerOpen((v) => !v);
                      }}
                      className={`h-7 px-2 rounded-lg border text-xs inline-flex items-center gap-1 cursor-pointer disabled:opacity-40 ${
                        filePickerOpen
                          ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                          : "border-slate-800 bg-slate-900/90 hover:bg-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100"
                      }`}
                    >
                      <AtSign className="w-3.5 h-3.5" />
                      <span className="hidden sm:inline">文件</span>
                    </button>
                  )}
                  <span
                    title={SUPPORTED_FORMATS_TOOLTIP}
                    className="hidden xl:inline text-[10px] text-slate-500 truncate ml-1 select-none"
                  >
                    {hasBusyBotOrDispatch
                      ? "Bot 忙碌中 · 支持 ⚡插队发送（Ctrl/Cmd+Shift+Enter）"
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
                {hasBusyBotOrDispatch && (
                  <button
                    type="button"
                    disabled={
                      sending ||
                      composerAtts.isUploading ||
                      (!draft.trim() &&
                        composerAtts.readyAttachmentIds.length === 0 &&
                        composerAtts.contextFiles.length === 0)
                    }
                    onClick={() => void handleSend("interrupt")}
                    title="优先插队发送至目标 Bot（Ctrl/Cmd+Shift+Enter）"
                    className="h-8 px-2.5 sm:px-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-slate-950 text-xs font-semibold inline-flex items-center gap-1 shrink-0 cursor-pointer shadow-sm"
                  >
                    {sending && sendingMode === "interrupt" ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Zap className="w-3.5 h-3.5 fill-current" />
                    )}
                    <span>插队发送</span>
                  </button>
                )}
                <button
                  type="button"
                  disabled={
                    sending ||
                    composerAtts.isUploading ||
                    (!draft.trim() &&
                      composerAtts.readyAttachmentIds.length === 0 &&
                      composerAtts.contextFiles.length === 0)
                  }
                  onClick={() => void handleSend("queue")}
                  className="h-8 px-3 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                >
                  {sending && sendingMode !== "interrupt" ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Send className="w-3.5 h-3.5" />
                  )}
                  发送
                </button>
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
  );
}
