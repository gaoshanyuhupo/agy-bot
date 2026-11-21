export type UserRole = "admin" | "readonly";
export type AuthMode = "password" | "legacy";

export interface StudioSession {
  ok: boolean;
  authenticated: boolean;
  auth_mode?: AuthMode;
  bot: string;
  user_id: number;
  role: UserRole;
  auth_track: "password" | "telegram" | "magic_link";
  username?: string;
  must_change_password?: boolean;
  csrf_token: string;
  user?: {
    id: number;
    first_name?: string;
    last_name?: string;
    username?: string;
  };
}

export interface ApiErrorPayload {
  ok: false;
  source?: "studio_auth" | "upstream" | "studio_api";
  error: string;
  auth_mode?: AuthMode;
  retry_after?: number;
}

export interface BotRosterItem {
  handle: string;
  display_name: string;
  role: "coordinator" | "worker" | "peer" | string;
  online: boolean;
  busy: boolean;
  current_job: string | null;
  queue_depth: number;
  specialty: string;
  model_mode: string;
  effective_model: string;
  active_model: string;
  default_project: string;
  last_seen: number;
}

export interface BotsResponse {
  ok: boolean;
  readonly: boolean;
  total: number;
  online: number;
  busy: number;
  bots: BotRosterItem[];
}

export interface JobItem {
  job_id: string;
  group_id: string;
  label: string;
  from_bot: string;
  target_bot: string;
  status: "queued" | "running" | "done" | "error" | "cancelled" | string;
  project: string;
  model: string;
  effort: string;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  duration_sec: number | null;
  has_summary?: boolean;
  has_error?: boolean;
  error_code?: string;
}

export interface JobsResponse {
  ok: boolean;
  readonly: boolean;
  total: number;
  counts: Record<string, number>;
  jobs: JobItem[];
}

export interface JobDetail extends JobItem {
  cancel_requested?: boolean;
  progress?: string;
  prompt: string;
  result: string;
  error: string;
  truncated?: boolean;
  truncated_fields?: string[];
}

export interface JobDetailResponse {
  ok: boolean;
  job: JobDetail;
}

export interface JobDispatchAssignment {
  bot: string;
  prompt: string;
  label?: string;
  project?: string;
  model?: string;
  effort?: string;
}

export type JobDispatchPayload =
  | JobDispatchAssignment
  | { assignments: JobDispatchAssignment[] };

export interface JobDispatchResponse {
  ok: boolean;
  group_id: string;
  jobs: JobItem[];
}

export interface JobCancelResponse {
  ok: boolean;
  job_id: string;
  already_terminal: boolean;
  cancelled?: boolean;
  status: string;
  via_ipc?: boolean;
}

export interface JobRetryResponse {
  ok: boolean;
  retried_from: string;
  job_id: string;
  job: JobItem;
}

export interface ScheduleItem {
  id: string;
  name: string;
  enabled: boolean;
  read_only_cli?: boolean;
  schedule_type: string;
  schedule_expr: string;
  task_type: string;
  model: string;
  project: string;
  bot?: string;
  silent_if_empty?: boolean;
  prompt?: string;
  next_run_at: string | null;
  next_run_local: string | null;
  countdown: string;
  last_run_at: string | null;
  last_run_local: string | null;
  last_status: string;
  run_count: number;
  has_last_error?: boolean;
  last_error_code?: string;
}

export interface SchedulesResponse {
  ok: boolean;
  readonly: boolean;
  tz_label: string;
  total: number;
  active: number;
  paused: number;
  schedules: ScheduleItem[];
}

export interface ScheduleCreatePayload {
  name: string;
  schedule_expr: string;
  task_type: "prompt" | "reminder";
  prompt: string;
  project?: string;
  model?: string;
  enabled?: boolean;
  silent_if_empty?: boolean;
  bot?: string;
}

export interface SchedulePatchPayload {
  name?: string;
  schedule_expr?: string;
  task_type?: "prompt" | "reminder";
  prompt?: string;
  project?: string;
  model?: string;
  enabled?: boolean;
  silent_if_empty?: boolean;
}

export interface ScheduleMutationResponse {
  ok: boolean;
  schedule: ScheduleItem;
}

export interface ScheduleDeleteResponse {
  ok: boolean;
  deleted: boolean;
  id: string;
}

export interface ScheduleRunResponse {
  ok: boolean;
  queued: boolean;
  schedule_id: string;
  bot: string;
}

export type StudioEventType =
  | "connected"
  | "job_updated"
  | "schedule_updated"
  | "bots_updated"
  | "session_updated"
  | "resync_required"
  | "auth_error";

export interface SessionUpdatedEvent {
  ver: number;
  type: "session_updated" | "resync_required";
  cid?: string;
  bot?: string;
  source?: string;
  status?: string;
  busy?: boolean;
  updated_at?: number;
}

export interface StudioEventEnvelope {
  type: StudioEventType;
  seq?: number;
  data: Record<string, unknown>;
}

export type EventStreamStatus = "connecting" | "connected" | "reconnecting" | "disconnected";

export interface CostAgg {
  input_tokens: number;
  cache_read_tokens: number;
  output_tokens: number;
  total_tokens: number;
  calls: number;
  cache_hit_pct: number;
  cost_usd: number;
  nocache_usd: number;
  saved_usd: number;
  save_pct: number;
}

export interface DailyCostRow extends CostAgg {
  date: string;
  label: string;
}

export interface ModelCostRow extends CostAgg {
  family: string;
  label: string;
}

export interface QuotaGroup {
  name: string;
  buckets: {
    name: string;
    window: string;
    remaining_pct: number;
    reset_countdown: string;
  }[];
}

export interface CostsResponse {
  ok: boolean;
  readonly: boolean;
  scope: "all" | "agent" | "sched";
  tz_label: string;
  week_window: {
    start_local: string;
    end_local: string;
    remaining: string;
  };
  today: CostAgg;
  week: CostAgg;
  month: CostAgg;
  d7: CostAgg;
  d30: CostAgg;
  daily_14d: DailyCostRow[];
  by_model_week: ModelCostRow[];
  by_model_month: ModelCostRow[];
  quota_groups: QuotaGroup[];
}

export interface BrowserStatusResponse {
  ok: boolean;
  readonly: boolean;
  reachable: boolean;
  running: boolean;
  session_restricted?: boolean;
  engine_mode: string;
  profile?: string | null;
  pinned?: boolean;
  egress?: string;
  os?: string;
  takeover?: boolean;
  ai_busy?: boolean;
  url?: string;
  title?: string;
  vw?: number;
  vh?: number;
  quality_preset?: string;
  viewers?: number;
  tabs_count?: number;
  source?: string;
  error?: string;
}

export interface OverviewResponse {
  ok: boolean;
  readonly: boolean;
  generated_at: number;
  viewer: {
    bot: string;
    user_id: number;
    role: UserRole;
    auth_track: string;
  };
  summary: {
    bots_total: number;
    bots_online: number;
    bots_busy: number;
    jobs_total: number;
    jobs_running: number;
    jobs_queued: number;
    jobs_error: number;
    schedules_total: number;
    schedules_active: number;
    today_cost_usd: number;
    today_tokens: number;
    today_cache_hit_pct: number;
    week_cost_usd: number;
    week_saved_usd: number;
    month_cost_usd: number;
  };
  browser: BrowserStatusResponse;
  recent_jobs: JobItem[];
}

export interface BrowserTabInfo {
  index: number;
  title: string;
  url: string;
  active?: boolean;
}

export interface LiveBrowserState {
  running: boolean;
  session_restricted?: boolean;
  restricted_reason?: string;
  engine_mode: string;
  session_gen: number;
  takeover_gen: number;
  profile: string | null;
  pinned: boolean;
  egress: string;
  os: string;
  takeover: boolean;
  takeover_reason: string;
  ai_status: string;
  ai_busy: boolean;
  url: string;
  title: string;
  vw: number;
  vh: number;
  tabs: BrowserTabInfo[];
  cursor?: {
    x?: number;
    y?: number;
    actor?: string;
    kind?: string;
    ts?: number;
  };
  quality_preset: "smooth" | "balanced" | "hd" | string;
  viewers: number;
}

export type NavTab =
  | "workspace"
  | "overview"
  | "browser"
  | "bots"
  | "jobs"
  | "schedules"
  | "costs";

export interface SessionSummaryItem {
  cid: string;
  title: string;
  preview: string;
  updated_at: string;
  project_id: string;
  source: string;
  bot: string;
  busy: boolean;
}

export interface SessionsResponse {
  ok: boolean;
  total: number;
  sessions: SessionSummaryItem[];
}

export interface ChatToolCall {
  name: string;
  duration_seconds?: number | null;
  active?: boolean;
}

export interface ChatMessageItem {
  id: string;
  role: "user" | "assistant";
  content: string;
  thinking?: string;
  tool_calls?: ChatToolCall[];
  status?: string;
  truncated?: boolean;
  created_at?: string;
  byte_offset?: number;
}

export interface SessionMessagesResponse {
  ok: boolean;
  cid: string;
  messages: ChatMessageItem[];
  has_more: boolean;
  next_before: number | null;
  total_returned: number;
}

export interface ModelOption {
  id: string;
  label: string;
}

export interface ProjectOption {
  id: string;
  name: string;
}

export interface ModelsResponse {
  ok: boolean;
  bot: string;
  active_model: string;
  default_project: string;
  efforts: string[];
  models: ModelOption[];
  projects: ProjectOption[];
  ipc_online: boolean;
}

export interface ChatSendPayload {
  bot?: string;
  prompt: string;
  cid?: string | null;
  project?: string | null;
  model?: string | null;
  effort?: string | null;
  sync_tg?: boolean;
}

export interface ActiveSessionTurnResponse {
  ok: boolean;
  active: boolean;
  cid: string;
  bot?: string;
  turn_id?: string;
  source?: "tg" | "web" | string;
  status?: string;
  prompt_preview?: string;
}

export interface ChatSendResponse {
  ok: boolean;
  turn_id: string;
  bot: string;
  cid: string | null;
  status: string;
}

export interface ChatAbortResponse {
  ok: boolean;
  turn_id: string;
  aborted: boolean;
  bot: string;
}

declare global {
  interface Window {
    Telegram?: {
      WebApp?: {
        initData?: string;
        platform?: string;
        ready?: () => void;
        expand?: () => void;
      };
    };
  }
}
