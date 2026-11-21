import type {
  ActiveSessionTurnResponse,
  AttentionDecideResponse,
  AttentionResponse,
  AuthMode,
  BotConfigPatchPayload,
  BotConfigResponse,
  BotReloadResponse,
  BotsResponse,
  BrowserStatusResponse,
  ChatAbortResponse,
  ChatSendPayload,
  ChatSendResponse,
  CostsResponse,
  EventStreamStatus,
  FileContentResponse,
  FileDiffResponse,
  FileTreeResponse,
  JobCancelResponse,
  JobDetailResponse,
  JobDispatchPayload,
  JobDispatchResponse,
  JobRetryResponse,
  JobsResponse,
  ModelsResponse,
  OverviewResponse,
  ProjectsResponse,
  RoomCreateResponse,
  RoomMessagesResponse,
  RoomSendResponse,
  RoomsResponse,
  ScheduleCreatePayload,
  ScheduleDeleteResponse,
  ScheduleMutationResponse,
  SchedulePatchPayload,
  ScheduleRunResponse,
  SchedulesResponse,
  SessionMessagesResponse,
  SessionsResponse,
  StudioEventEnvelope,
  StudioEventType,
  StudioSession,
  UndoActionResponse,
  UndoCheckpointsResponse,
} from "./types";

let csrfTokenMemory = "";

export function setCsrfToken(token: string): void {
  csrfTokenMemory = token || "";
}

export function getCsrfToken(): string {
  return csrfTokenMemory;
}

export class StudioApiError extends Error {
  status: number;
  source: string;
  authMode?: AuthMode;
  retryAfter?: number;
  code?: string;
  conflicts?: string[];
  constructor(
    message: string,
    status: number,
    source = "studio_auth",
    authMode?: AuthMode,
    retryAfter?: number,
    code?: string,
    conflicts?: string[],
  ) {
    super(message);
    this.status = status;
    this.source = source;
    this.authMode = authMode;
    this.retryAfter = retryAfter;
    this.code = code;
    this.conflicts = conflicts;
  }
}

async function requestJson<T>(
  path: string,
  init: RequestInit = {},
  includeCsrf = false,
): Promise<T> {
  const headers = new Headers(init.headers || {});
  const method = (init.method || "GET").toUpperCase();
  const isMutating = method === "POST" || method === "PATCH" || method === "PUT" || method === "DELETE";
  if ((init.body || isMutating) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (includeCsrf && csrfTokenMemory) {
    headers.set("X-Studio-CSRF", csrfTokenMemory);
  }
  const resp = await fetch(path, {
    ...init,
    body: init.body !== undefined ? init.body : isMutating ? "{}" : undefined,
    credentials: "same-origin",
    headers,
  });
  let payload: Record<string, unknown> = {};
  try {
    payload = (await resp.json()) as Record<string, unknown>;
  } catch {
    payload = {};
  }
  if (!resp.ok || payload.ok === false) {
    const msg =
      typeof payload.error === "string" && payload.error
        ? payload.error
        : `HTTP ${resp.status}`;
    const src = typeof payload.source === "string" ? payload.source : "studio_auth";
    const mode: AuthMode | undefined =
      payload.auth_mode === "password" || payload.auth_mode === "legacy"
        ? payload.auth_mode
        : undefined;
    const retryAfter =
      typeof payload.retry_after === "number" && Number.isFinite(payload.retry_after)
        ? payload.retry_after
        : undefined;
    const code = typeof payload.code === "string" && payload.code ? payload.code : undefined;
    const conflicts = Array.isArray(payload.conflicts)
      ? payload.conflicts.filter((c): c is string => typeof c === "string")
      : undefined;
    throw new StudioApiError(msg, resp.status, src, mode, retryAfter, code, conflicts);
  }
  return payload as unknown as T;
}

export function fetchMe(): Promise<StudioSession> {
  return requestJson<StudioSession>("/api/auth/me");
}

export function authLogin(username: string, password: string): Promise<StudioSession> {
  return requestJson<StudioSession>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function authChangePassword(
  curPwd: string,
  nextPwd: string,
): Promise<StudioSession> {
  return requestJson<StudioSession>(
    "/api/auth/change-password",
    {
      method: "POST",
      body: JSON.stringify({
        current_password: curPwd,
        new_password: nextPwd,
      }),
    },
    true,
  );
}

export function authTelegram(initData: string): Promise<StudioSession> {
  return requestJson<StudioSession>("/api/auth/telegram", {
    method: "POST",
    body: JSON.stringify({ initData }),
  });
}

export function authRedeemMagic(token: string): Promise<StudioSession> {
  return requestJson<StudioSession>("/api/auth/redeem", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

export function authLogout(): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>(
    "/api/auth/logout",
    { method: "POST" },
    true,
  );
}

export function fetchOverview(): Promise<OverviewResponse> {
  return requestJson<OverviewResponse>("/api/overview");
}

export function fetchBots(): Promise<BotsResponse> {
  return requestJson<BotsResponse>("/api/bots");
}

export function fetchJobs(params?: {
  limit?: number;
  status?: string;
}): Promise<JobsResponse> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.status) q.set("status", params.status);
  const qs = q.toString();
  return requestJson<JobsResponse>(`/api/jobs${qs ? `?${qs}` : ""}`);
}

export function fetchJobDetail(jobId: string): Promise<JobDetailResponse> {
  return requestJson<JobDetailResponse>(`/api/jobs/${encodeURIComponent(jobId)}`);
}

export function dispatchJobs(payload: JobDispatchPayload): Promise<JobDispatchResponse> {
  return requestJson<JobDispatchResponse>(
    "/api/jobs/dispatch",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function cancelJob(jobId: string): Promise<JobCancelResponse> {
  return requestJson<JobCancelResponse>(
    `/api/jobs/${encodeURIComponent(jobId)}/cancel`,
    {
      method: "POST",
      body: "{}",
    },
    true,
  );
}

export function retryJob(jobId: string): Promise<JobRetryResponse> {
  return requestJson<JobRetryResponse>(
    `/api/jobs/${encodeURIComponent(jobId)}/retry`,
    {
      method: "POST",
      body: "{}",
    },
    true,
  );
}

export function fetchSchedules(): Promise<SchedulesResponse> {
  return requestJson<SchedulesResponse>("/api/schedules");
}

export function createSchedule(
  payload: ScheduleCreatePayload,
): Promise<ScheduleMutationResponse> {
  return requestJson<ScheduleMutationResponse>(
    "/api/schedules",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function updateSchedule(
  scheduleId: string,
  payload: SchedulePatchPayload,
): Promise<ScheduleMutationResponse> {
  return requestJson<ScheduleMutationResponse>(
    `/api/schedules/${encodeURIComponent(scheduleId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function deleteSchedule(scheduleId: string): Promise<ScheduleDeleteResponse> {
  return requestJson<ScheduleDeleteResponse>(
    `/api/schedules/${encodeURIComponent(scheduleId)}`,
    {
      method: "DELETE",
      body: "{}",
    },
    true,
  );
}

export function runScheduleNow(
  scheduleId: string,
  bot?: string,
): Promise<ScheduleRunResponse> {
  return requestJson<ScheduleRunResponse>(
    `/api/schedules/${encodeURIComponent(scheduleId)}/run`,
    {
      method: "POST",
      body: JSON.stringify(bot ? { bot } : {}),
    },
    true,
  );
}

export class StudioEventClient {
  private es: EventSource | null = null;
  private stopped = false;
  private lastSeq = 0;
  private reconnectTimer: number | null = null;
  private reconnectDelayMs = 1500;
  private readonly onEvent: (ev: StudioEventEnvelope) => void;
  private readonly onStatus: (status: EventStreamStatus) => void;
  private readonly onAuthError: (reason: string, code?: string) => void;

  constructor(opts: {
    onEvent: (ev: StudioEventEnvelope) => void;
    onStatus: (status: EventStreamStatus) => void;
    onAuthError: (reason: string, code?: string) => void;
  }) {
    this.onEvent = opts.onEvent;
    this.onStatus = opts.onStatus;
    this.onAuthError = opts.onAuthError;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.es) {
      this.es.close();
      this.es = null;
    }
    this.onStatus("disconnected");
  }

  private connect(): void {
    if (this.stopped) return;
    if (this.es) {
      this.es.close();
      this.es = null;
    }
    this.onStatus(this.lastSeq > 0 ? "reconnecting" : "connecting");
    const url = this.lastSeq > 0 ? `/api/events?after_seq=${this.lastSeq}` : "/api/events";
    const es = new EventSource(url);
    this.es = es;

    const parseEvent = (raw: MessageEvent): Record<string, unknown> => {
      try {
        return JSON.parse(String(raw.data || "{}")) as Record<string, unknown>;
      } catch {
        return {};
      }
    };

    const bindType = (evType: StudioEventType) => {
      es.addEventListener(evType, (rawEv) => {
        if (this.stopped || this.es !== es) return;
        const msgEv = rawEv as MessageEvent;
        const data = parseEvent(msgEv);
        const seqNum = msgEv.lastEventId ? Number.parseInt(msgEv.lastEventId, 10) : NaN;
        if (Number.isFinite(seqNum) && seqNum > this.lastSeq) {
          this.lastSeq = seqNum;
        }
        if (evType === "auth_error") {
          const reason =
            typeof data.error === "string" && data.error ? data.error : "访问权限已被撤销";
          const code = typeof data.code === "string" ? data.code : undefined;
          this.stop();
          this.onAuthError(reason, code);
          return;
        }
        if (evType === "connected") {
          this.reconnectDelayMs = 1500;
          this.onStatus("connected");
        }
        this.onEvent({
          type: evType,
          seq: Number.isFinite(seqNum) ? seqNum : undefined,
          data,
        });
      });
    };

    bindType("connected");
    bindType("job_updated");
    bindType("schedule_updated");
    bindType("bots_updated");
    bindType("session_updated");
    bindType("room_message");
    bindType("room_typing");
    bindType("attention_updated");
    bindType("resync_required");
    bindType("auth_error");

    es.onopen = () => {
      if (this.stopped || this.es !== es) return;
      this.reconnectDelayMs = 1500;
      this.onStatus("connected");
    };

    es.onerror = () => {
      if (this.stopped || this.es !== es) return;
      es.close();
      this.es = null;
      this.onStatus("reconnecting");

      // Probe session state so 401/403 stops reconnect immediately (zero infinite loop)
      void fetchMe()
        .then((me) => {
          if (this.stopped) return;
          if (me.must_change_password) {
            this.stop();
            this.onAuthError("password_change_required", "password_change_required");
            return;
          }
          const delay = this.reconnectDelayMs;
          this.reconnectDelayMs = Math.min(15000, Math.round(this.reconnectDelayMs * 1.6));
          this.reconnectTimer = window.setTimeout(() => {
            this.reconnectTimer = null;
            this.connect();
          }, delay);
        })
        .catch((err) => {
          if (this.stopped) return;
          if (err instanceof StudioApiError && (err.status === 401 || err.status === 403)) {
            this.stop();
            this.onAuthError(err.message || "会话已失效，请重新登录");
            return;
          }
          const delay = this.reconnectDelayMs;
          this.reconnectDelayMs = Math.min(15000, Math.round(this.reconnectDelayMs * 1.6));
          this.reconnectTimer = window.setTimeout(() => {
            this.reconnectTimer = null;
            this.connect();
          }, delay);
        });
    };
  }
}

export function fetchCosts(scope: "all" | "agent" | "sched" = "all"): Promise<CostsResponse> {
  return requestJson<CostsResponse>(`/api/costs?scope=${encodeURIComponent(scope)}`);
}

export function fetchBrowserStatus(): Promise<BrowserStatusResponse> {
  return requestJson<BrowserStatusResponse>("/api/browser/status");
}

export function fetchSessions(params?: {
  limit?: number;
  bot?: string;
  source?: string;
  q?: string;
}): Promise<SessionsResponse> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.bot) q.set("bot", params.bot);
  if (params?.source && params.source !== "all") q.set("source", params.source);
  if (params?.q && params.q.trim()) q.set("q", params.q.trim());
  const qs = q.toString();
  return requestJson<SessionsResponse>(`/api/sessions${qs ? `?${qs}` : ""}`);
}

export function fetchSessionMessages(
  cid: string,
  params?: { limit?: number; before?: number | null },
): Promise<SessionMessagesResponse> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.before != null && params.before > 0) q.set("before", String(params.before));
  const qs = q.toString();
  return requestJson<SessionMessagesResponse>(
    `/api/sessions/${encodeURIComponent(cid)}/messages${qs ? `?${qs}` : ""}`,
  );
}

export function fetchActiveSessionTurn(
  cid: string,
  bot?: string,
): Promise<ActiveSessionTurnResponse> {
  const qs = bot ? `?bot=${encodeURIComponent(bot)}` : "";
  return requestJson<ActiveSessionTurnResponse>(
    `/api/sessions/${encodeURIComponent(cid)}/active-turn${qs}`,
  );
}

export function fetchModels(bot?: string): Promise<ModelsResponse> {
  const qs = bot ? `?bot=${encodeURIComponent(bot)}` : "";
  return requestJson<ModelsResponse>(`/api/models${qs}`);
}

export function sendChatTurn(payload: ChatSendPayload): Promise<ChatSendResponse> {
  return requestJson<ChatSendResponse>(
    "/api/chat/send",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function abortChatTurn(turnId: string, bot?: string): Promise<ChatAbortResponse> {
  return requestJson<ChatAbortResponse>(
    "/api/chat/abort",
    {
      method: "POST",
      body: JSON.stringify({ turn_id: turnId, bot: bot || undefined }),
    },
    true,
  );
}

// Phase B M1: Workspace Files, Git Diff & Undo/Redo
export function fetchProjects(): Promise<ProjectsResponse> {
  return requestJson<ProjectsResponse>("/api/projects");
}

export function fetchFileTree(params: {
  project_id: string;
  dir?: string;
  depth?: number;
}): Promise<FileTreeResponse> {
  const q = new URLSearchParams({ project_id: params.project_id });
  if (params.dir) q.set("dir", params.dir);
  if (params.depth) q.set("depth", String(params.depth));
  return requestJson<FileTreeResponse>(`/api/files/tree?${q.toString()}`);
}

export function fetchFileContent(
  projectId: string,
  path: string,
): Promise<FileContentResponse> {
  const q = new URLSearchParams({ project_id: projectId, path });
  return requestJson<FileContentResponse>(`/api/files/content?${q.toString()}`);
}

export function fetchFileDiff(params: {
  project_id: string;
  scope?: "all" | "staged" | "unstaged";
  path?: string;
}): Promise<FileDiffResponse> {
  const q = new URLSearchParams({
    project_id: params.project_id,
    scope: params.scope || "all",
  });
  if (params.path) q.set("path", params.path);
  return requestJson<FileDiffResponse>(`/api/files/diff?${q.toString()}`);
}

export function fetchUndoCheckpoints(params?: {
  bot?: string;
  cid?: string | null;
  project_id?: string;
}): Promise<UndoCheckpointsResponse> {
  const q = new URLSearchParams();
  if (params?.bot) q.set("bot", params.bot);
  if (params?.cid) q.set("cid", params.cid);
  if (params?.project_id) q.set("project_id", params.project_id);
  const qs = q.toString();
  return requestJson<UndoCheckpointsResponse>(`/api/undo/checkpoints${qs ? `?${qs}` : ""}`);
}

export function applyUndoCheckpoint(payload: {
  entry_id: string;
  bot?: string;
  cid?: string | null;
  project_id?: string;
  force?: boolean;
}): Promise<UndoActionResponse> {
  return requestJson<UndoActionResponse>(
    "/api/undo/apply",
    {
      method: "POST",
      body: JSON.stringify({
        entry_id: payload.entry_id,
        bot: payload.bot || undefined,
        cid: payload.cid || undefined,
        project_id: payload.project_id || undefined,
        force: Boolean(payload.force),
      }),
    },
    true,
  );
}

export function redoUndoCheckpoint(payload: {
  entry_id: string;
  bot?: string;
  cid?: string | null;
  project_id?: string;
  force?: boolean;
}): Promise<UndoActionResponse> {
  return requestJson<UndoActionResponse>(
    "/api/undo/redo",
    {
      method: "POST",
      body: JSON.stringify({
        entry_id: payload.entry_id,
        bot: payload.bot || undefined,
        cid: payload.cid || undefined,
        project_id: payload.project_id || undefined,
        force: Boolean(payload.force),
      }),
    },
    true,
  );
}

// Phase B M1: Bot Team Control Plane
export function fetchBotConfig(handle: string): Promise<BotConfigResponse> {
  return requestJson<BotConfigResponse>(`/api/bots/${encodeURIComponent(handle)}/config`);
}

export function updateBotConfig(
  handle: string,
  payload: BotConfigPatchPayload,
): Promise<BotConfigResponse> {
  return requestJson<BotConfigResponse>(
    `/api/bots/${encodeURIComponent(handle)}/config`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function reloadBot(handle: string): Promise<BotReloadResponse> {
  return requestJson<BotReloadResponse>(
    `/api/bots/${encodeURIComponent(handle)}/reload`,
    {
      method: "POST",
      body: "{}",
    },
    true,
  );
}

// Phase B M2: Web Multi-Bot Chat Rooms
export function fetchRooms(): Promise<RoomsResponse> {
  return requestJson<RoomsResponse>("/api/rooms");
}

export function createRoom(payload: {
  room_id: string;
  title?: string;
  topic?: string;
}): Promise<RoomCreateResponse> {
  return requestJson<RoomCreateResponse>(
    "/api/rooms",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function fetchRoomMessages(
  roomId: string,
  params?: { after_seq?: number; limit?: number },
): Promise<RoomMessagesResponse> {
  const q = new URLSearchParams();
  if (params?.after_seq && params.after_seq > 0) q.set("after_seq", String(params.after_seq));
  if (params?.limit) q.set("limit", String(params.limit));
  const qs = q.toString();
  return requestJson<RoomMessagesResponse>(
    `/api/rooms/${encodeURIComponent(roomId)}/messages${qs ? `?${qs}` : ""}`,
  );
}

export function sendRoomMessage(
  roomId: string,
  payload: { content: string; project?: string },
): Promise<RoomSendResponse> {
  return requestJson<RoomSendResponse>(
    `/api/rooms/${encodeURIComponent(roomId)}/messages`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

// Phase B M2: Unified Attention Queue
export function fetchAttention(status?: "all" | "pending" | "resolved"): Promise<AttentionResponse> {
  const qs = status && status !== "all" ? `?status=${encodeURIComponent(status)}` : "";
  return requestJson<AttentionResponse>(`/api/attention${qs}`);
}

export function decideAttentionItem(
  itemId: string,
  payload: { decision: "approved" | "rejected"; note?: string },
): Promise<AttentionDecideResponse> {
  return requestJson<AttentionDecideResponse>(
    `/api/attention/${encodeURIComponent(itemId)}/decide`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    true,
  );
}

export function formatTokens(n: number): string {
  if (!n || n <= 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function formatUsd(n: number): string {
  if (!n || n <= 0) return "$0.00";
  if (n < 0.01) return `$${n.toFixed(4)}`;
  if (n < 1) return `$${n.toFixed(3)}`;
  return `$${n.toFixed(2)}`;
}
