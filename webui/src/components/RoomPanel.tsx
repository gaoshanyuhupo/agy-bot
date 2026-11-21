import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Hash,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Send,
  ShieldAlert,
  Users,
} from "lucide-react";
import {
  StudioApiError,
  createRoom,
  fetchBots,
  fetchRoomMessages,
  fetchRooms,
  sendRoomMessage,
} from "../api";
import type {
  BotRosterItem,
  RoomLiveEvent,
  RoomMessageItem,
  RoomSummary,
  StudioSession,
} from "../types";
import { SafeMarkdown } from "./SafeMarkdown";

export interface RoomPanelProps {
  session: StudioSession;
  initialRoomId?: string;
  onRoomChange?: (roomId: string) => void;
  roomEvent?: RoomLiveEvent | null;
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

export function RoomPanel({
  session,
  initialRoomId,
  onRoomChange,
  roomEvent,
  onSessionRevoked,
}: RoomPanelProps) {
  const isReadonly = session.role !== "admin";

  const [rooms, setRooms] = useState<RoomSummary[]>([]);
  const [roomsLoading, setRoomsLoading] = useState(false);
  const [selectedRoomId, setSelectedRoomId] = useState<string>(initialRoomId || "lobby");
  const [messages, setMessages] = useState<RoomMessageItem[]>([]);
  const [msgsLoading, setMsgsLoading] = useState(false);
  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [typingBots, setTypingBots] = useState<Record<string, boolean>>({});
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Create room form state
  const [createOpen, setCreateOpen] = useState(false);
  const [newRoomId, setNewRoomId] = useState("");
  const [newRoomTitle, setNewRoomTitle] = useState("");
  const [newRoomTopic, setNewRoomTopic] = useState("");
  const [creating, setCreating] = useState(false);

  const mountedRef = useRef(true);
  const selectedRoomRef = useRef<string>(selectedRoomId);
  selectedRoomRef.current = selectedRoomId;
  const onRoomChangeRef = useRef(onRoomChange);
  onRoomChangeRef.current = onRoomChange;
  const roomsSeqRef = useRef(0);
  const msgsSeqRef = useRef(0);
  const botsSeqRef = useRef(0);
  const lastRoomEventVerRef = useRef(0);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

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

  const loadRooms = useCallback(async () => {
    const seq = ++roomsSeqRef.current;
    setRoomsLoading(true);
    try {
      const res = await fetchRooms();
      if (!mountedRef.current || roomsSeqRef.current !== seq) return;
      setRooms(res.rooms || []);
      const exists = (res.rooms || []).some((r) => r.room_id === selectedRoomRef.current);
      if (!exists && res.rooms && res.rooms.length > 0) {
        const fallback = res.rooms[0].room_id;
        setSelectedRoomId(fallback);
        onRoomChangeRef.current?.(fallback);
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
  }, [loadRooms]);

  useEffect(() => {
    const seq = ++botsSeqRef.current;
    void fetchBots()
      .then((res) => {
        if (!mountedRef.current || botsSeqRef.current !== seq) return;
        setBots(res.bots || []);
      })
      .catch((err) => {
        if (mountedRef.current && botsSeqRef.current === seq) {
          handleAuthErr(err);
        }
      });
  }, [handleAuthErr]);

  useEffect(() => {
    setTypingBots({});
    void loadMessages(selectedRoomId);
  }, [selectedRoomId, loadMessages]);

  // React to global SSE room_message / room_typing / resync_required
  useEffect(() => {
    if (!roomEvent || roomEvent.ver === lastRoomEventVerRef.current) return;
    lastRoomEventVerRef.current = roomEvent.ver;

    if (roomEvent.type === "resync_required") {
      void loadRooms();
      void loadMessages(selectedRoomRef.current, { silent: true });
      return;
    }

    if (roomEvent.room_id && roomEvent.room_id !== selectedRoomRef.current) {
      return;
    }

    if (roomEvent.type === "room_typing" && roomEvent.bot) {
      const bHandle = roomEvent.bot;
      const isTyping = Boolean(roomEvent.typing);
      setTypingBots((prev) => {
        if (Boolean(prev[bHandle]) === isTyping) return prev;
        const next = { ...prev };
        if (isTyping) next[bHandle] = true;
        else delete next[bHandle];
        return next;
      });
      return;
    }

    if (roomEvent.type === "room_message") {
      const incoming = roomEvent.message;
      if (incoming && incoming.room_id === selectedRoomRef.current) {
        setMessages((prev) => {
          if (prev.some((m) => m.msg_id === incoming.msg_id || m.seq === incoming.seq)) {
            return prev;
          }
          return [...prev, incoming].slice(-200);
        });
        window.setTimeout(() => {
          if (mountedRef.current) endRef.current?.scrollIntoView({ behavior: "smooth" });
        }, 30);
      } else {
        void loadMessages(selectedRoomRef.current, { silent: true });
      }
    }
  }, [roomEvent, loadMessages, loadRooms]);

  const handleSelectRoom = (rid: string) => {
    if (rid === selectedRoomId) return;
    setSelectedRoomId(rid);
    onRoomChange?.(rid);
  };

  const handleCreateRoom = async () => {
    if (isReadonly || creating) return;
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

  const handleSend = async () => {
    const content = draft.trim();
    if (isReadonly || sending || !content) return;
    const targetRoom = selectedRoomRef.current;
    setSending(true);
    setErrorMsg(null);
    try {
      const res = await sendRoomMessage(targetRoom, { content });
      if (!mountedRef.current) return;
      setDraft("");
      if (res.message && selectedRoomRef.current === targetRoom) {
        setMessages((prev) => {
          if (prev.some((m) => m.msg_id === res.message.msg_id || m.seq === res.message.seq)) {
            return prev;
          }
          return [...prev, res.message].slice(-200);
        });
      }
    } catch (err) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(err)) {
        setErrorMsg(err instanceof Error ? err.message : "发送消息失败");
      }
    } finally {
      if (mountedRef.current) setSending(false);
    }
  };

  const onlineBots = bots.filter((b) => b.online);
  const activeTyping = Object.keys(typingBots).filter((k) => typingBots[k]);
  const activeRoomMeta = rooms.find((r) => r.room_id === selectedRoomId);

  return (
    <div className="flex-1 min-h-0 min-w-0 flex flex-col bg-slate-950 overflow-hidden">
      {/* Header Bar */}
      <header className="shrink-0 px-3 py-2 border-b border-slate-800/90 bg-slate-900/75 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-100">
          <Users className="w-4 h-4 text-sky-400" />
          <span>多 Bot 群聊室</span>
        </div>

        <select
          value={selectedRoomId}
          onChange={(e) => handleSelectRoom(e.target.value)}
          aria-label="选择群聊频道"
          className="h-7 rounded-md bg-slate-950 border border-slate-800 px-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 max-w-44"
        >
          {rooms.length === 0 && <option value="lobby"># lobby</option>}
          {rooms.map((r) => (
            <option key={r.room_id} value={r.room_id}>
              # {r.title || r.room_id}
            </option>
          ))}
        </select>

        {activeRoomMeta?.topic && (
          <span className="text-[11px] text-slate-400 truncate max-w-xs hidden sm:inline">
            {activeRoomMeta.topic}
          </span>
        )}

        <div className="ml-auto flex items-center gap-1.5">
          {!isReadonly && (
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
              void loadMessages(selectedRoomId);
            }}
            title="刷新群聊室"
            className="h-7 w-7 rounded-md border border-slate-800 bg-slate-950/70 hover:bg-slate-800 inline-flex items-center justify-center text-slate-300 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${roomsLoading || msgsLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {/* Inline Create Room Panel */}
      {createOpen && !isReadonly && (
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
          <span>只读权限（readonly）：可浏览 Web 群聊室历史，发言与新建频道已禁用。</span>
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

      {/* Messages Timeline */}
      <div className="flex-1 min-h-0 overflow-y-auto px-3.5 py-3 space-y-2.5">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-8 px-4">
            <Hash className="w-8 h-8 text-slate-600 mb-2" />
            <div className="text-sm font-medium text-slate-200">
              欢迎来到 #{activeRoomMeta?.title || selectedRoomId}
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              在下方输入 <code className="text-sky-300">@ 机器人名</code> 即可点名在线 Bot 协作讨论（已内置防死循环接力护栏，与 Telegram 群聊完全隔离）。
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
            return (
              <div
                key={m.msg_id}
                className={`flex ${isHuman ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[92%] md:max-w-[84%] rounded-2xl px-3.5 py-2.5 border ${
                    isHuman
                      ? "bg-sky-600/20 border-sky-500/35 text-slate-100"
                      : "bg-slate-900/85 border-slate-800 text-slate-100"
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1 text-[11px] text-slate-400 flex-wrap">
                    {!isHuman && <Bot className="w-3.5 h-3.5 text-emerald-400" />}
                    <span className="font-medium text-slate-200">{m.sender}</span>
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
                    <div className="text-sm whitespace-pre-wrap break-words leading-relaxed">
                      {m.content}
                    </div>
                  ) : (
                    <SafeMarkdown content={m.content} />
                  )}
                </div>
              </div>
            );
          })
        )}
        <div ref={endRef} />
      </div>

      {/* Typing + Quick Bot Mention Chips + Composer */}
      <footer className="shrink-0 border-t border-slate-800/90 bg-slate-900/70 p-2.5 space-y-2">
        {activeTyping.length > 0 && (
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-300">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>{activeTyping.map((b) => `@${b}`).join("、")} 正在回复…</span>
          </div>
        )}

        {!isReadonly && onlineBots.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-[10px] text-slate-500 mr-0.5">点名：</span>
            {onlineBots.slice(0, 8).map((b) => (
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
                className="px-2 py-0.5 rounded-full border border-slate-800 bg-slate-950 hover:bg-slate-800 text-[11px] text-sky-300 font-mono cursor-pointer"
              >
                @{b.handle}
              </button>
            ))}
          </div>
        )}

        <div className="flex items-end gap-2">
          <textarea
            rows={2}
            value={draft}
            disabled={isReadonly || sending}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void handleSend();
              }
            }}
            placeholder={
              isReadonly
                ? "只读权限已禁用群聊发言"
                : "输入消息并用 @ 点名在线 Bot…（Enter 发送）"
            }
            className="flex-1 resize-none rounded-xl bg-slate-950 border border-slate-800 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 disabled:opacity-50"
          />
          <button
            type="button"
            disabled={isReadonly || sending || !draft.trim()}
            onClick={() => void handleSend()}
            className="h-10 px-3 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white text-xs font-medium inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
          >
            {sending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
            发送
          </button>
        </div>
      </footer>
    </div>
  );
}
