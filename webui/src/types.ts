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
  default_effort?: string;
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
  | "room_message"
  | "room_typing"
  | "room_activity"
  | "attention_updated"
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
  | "attention"
  | "files"
  | "overview"
  | "browser"
  | "bots"
  | "models"
  | "openbao"
  | "security-card"
  | "jobs"
  | "schedules"
  | "costs";

export type OpenBaoSource = "host_auto" | "custom" | "unconfigured";
export type OpenBaoAuthMode = "host_card" | "token" | "approle";

export interface OpenBaoConfigResponse {
  ok: boolean;
  enabled: boolean;
  source: OpenBaoSource;
  addr: string;
  kv_mount: string;
  gateway_path_prefix: string;
  auth_mode: OpenBaoAuthMode;
  auth_label: string;
  credential_configured: boolean;
  credential_hint: string;
  fallback_mode: "local_0600" | string;
  security_card_status: "reserved" | string;
  can_edit: boolean;
  host_auto_available?: boolean;
  bao_cli_available?: boolean;
  updated_at?: number | null;
}

export interface OpenBaoConfigUpdatePayload {
  enabled?: boolean;
  addr?: string;
  kv_mount?: string;
  gateway_path_prefix?: string;
  auth_mode?: OpenBaoAuthMode;
  auth_label?: string;
  token?: string;
  role_id?: string;
  secret_id?: string;
  clear_credentials?: boolean;
  reset_to_host_auto?: boolean;
}

export interface OpenBaoTestPayload {
  addr?: string;
  auth_mode?: OpenBaoAuthMode;
}

export interface OpenBaoTestResponse {
  ok: boolean;
  reachable: boolean;
  initialized: boolean | null;
  sealed: boolean | null;
  latency_ms: number;
  auth_verified?: boolean | null;
  message: string;
}

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

export type AttachmentKind =
  | "image"
  | "pdf"
  | "document"
  | "code"
  | "audio"
  | "video"
  | "archive";

export interface ChatAttachmentItem {
  id: string;
  name: string;
  kind: AttachmentKind | string;
  mime?: string;
  size?: number;
  size_label?: string;
  preview_url: string;
}

export interface UploadAttachmentResponse {
  ok: boolean;
  attachment: ChatAttachmentItem;
}

export interface ChatToolCall {
  name: string;
  duration_seconds?: number | null;
  active?: boolean;
}

export type ExecutionMode = "queue" | "interrupt";

export interface ChatMessageItem {
  id: string;
  role: "user" | "assistant";
  content: string;
  attachments?: ChatAttachmentItem[];
  context_files?: string[];
  thinking?: string;
  tool_calls?: ChatToolCall[];
  status?: string;
  truncated?: boolean;
  created_at?: string;
  byte_offset?: number;
  execution_mode?: ExecutionMode;
  interrupted_prev?: boolean;
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
  attachments?: string[];
  context_files?: string[];
  execution_mode?: ExecutionMode;
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
  display_prompt?: string;
  attachments?: ChatAttachmentItem[];
  context_files?: string[];
  execution_mode?: ExecutionMode;
  interrupted_turn_id?: string | null;
}

export interface ChatAbortResponse {
  ok: boolean;
  turn_id: string;
  aborted: boolean;
  bot: string;
}

// Phase B M1: Workspace Files, Git Diff & Undo/Redo
export interface WorkspaceProjectItem {
  id: string;
  name: string;
  is_git: boolean;
}

export interface ProjectsResponse {
  ok: boolean;
  projects: WorkspaceProjectItem[];
}

export interface FileTreeNode {
  name: string;
  path: string;
  type: "dir" | "file";
  size: number | null;
  has_children?: boolean;
  children?: FileTreeNode[];
}

export interface FileTreeResponse {
  ok: boolean;
  project_id: string;
  dir: string;
  truncated: boolean;
  total: number;
  entries: FileTreeNode[];
}

export interface FileContentResponse {
  ok: boolean;
  project_id: string;
  path: string;
  is_binary: boolean;
  size: number;
  language: string;
  content: string;
  lines: number;
  truncated: boolean;
}

export interface GitDiffFileEntry {
  path: string;
  status: string;
  staged: string;
}

export interface FileDiffResponse {
  ok: boolean;
  project_id: string;
  is_git: boolean;
  scope: "all" | "staged" | "unstaged";
  path: string;
  files: GitDiffFileEntry[];
  diff: string;
  truncated: boolean;
}

export interface UndoCheckpointChange {
  path: string;
  action: string;
}

export interface UndoCheckpointItem {
  entry_id: string;
  ts: number;
  cid: string;
  project_id: string;
  prompt: string;
  truncated: boolean;
  changes_count: number;
  changes: UndoCheckpointChange[];
  is_top: boolean;
}

export interface UndoCheckpointsResponse {
  ok: boolean;
  ipc_online: boolean;
  bot: string;
  undo_stack: UndoCheckpointItem[];
  redo_stack: UndoCheckpointItem[];
}

export interface UndoActionResponse {
  ok: boolean;
  action: "undo" | "redo";
  bot: string;
  entry_id: string;
  cid: string;
  project_id: string;
  applied: UndoCheckpointChange[];
  remaining_undo: number;
  remaining_redo: number;
}

// Phase B M1: Bot Team Control Plane
export interface BotSkillItem {
  name: string;
  scope: string;
  description: string;
}

export interface BotMcpServerItem {
  name: string;
  transport: string;
  enabled: boolean;
}

export interface BotConfigResponse {
  ok: boolean;
  ipc_online: boolean;
  can_edit: boolean;
  handle: string;
  display_name: string;
  role: string;
  specialty: string;
  model_mode: "default" | "follow" | "custom";
  configured_model: string;
  effective_model: string;
  dm_model: string;
  env_default_model: string;
  default_effort: string;
  default_project: string;
  efforts: string[];
  models: ModelOption[];
  projects: ProjectOption[];
  skills: BotSkillItem[];
  mcp_servers: BotMcpServerItem[];
  busy: boolean;
  queue_depth: number;
}

export interface BotConfigPatchPayload {
  model_mode?: "default" | "follow" | "custom";
  model?: string;
  default_effort?: string;
  default_project?: string;
}

export interface BotReloadResponse {
  ok: boolean;
  bot: string;
  scheduled: boolean;
  self_check: string;
  cooldown_sec?: number;
}

// Phase B M2: Web Multi-Bot Chat Rooms, Unified Attention Queue & Multi-Pane Workbench
export interface RoomSummary {
  room_id: string;
  title: string;
  topic: string;
  mode?: "tg_mirror" | "web_room";
  mirror_bound?: boolean;
  default_bot?: string;
  created_at: number;
  updated_at: number;
  last_seq: number;
  message_count: number;
}

export interface RoomsResponse {
  ok: boolean;
  total: number;
  max_rooms: number;
  rooms: RoomSummary[];
}

export type RoomMessageStageTag = "ack" | "dispatch" | "delivery" | "error" | "reply";

export interface RoomMessageItem {
  seq: number;
  msg_id: string;
  room_id: string;
  ts: number;
  sender_type: "human" | "bot" | "system";
  sender: string;
  sender_role?: string;
  source?: "tg" | "web" | string;
  stage_tag?: RoomMessageStageTag | string;
  job_id?: string;
  content: string;
  attachments?: ChatAttachmentItem[];
  context_files?: string[];
  truncated?: boolean;
  mentions: string[];
  chain_id: string;
  hop: number;
  status: string;
  blocked_reason: string;
}

export interface RoomActivityBotItem {
  handle: string;
  display_name: string;
  role: string;
  state: "thinking" | "running" | "queued" | "idle" | string;
  stage_label: string;
  current_job_id: string | null;
  current_job_label?: string;
  queue_depth?: number;
  started_at: number | null;
  elapsed_s: number;
}

export interface RoomActivityJobItem {
  job_id: string;
  group_id: string;
  bot: string;
  from_bot: string;
  label: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled" | string;
  progress?: string;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  duration_s: number | null;
}

export interface RoomActivityDispatchInfo {
  phase: string;
  target_bots: string[];
  dispatched_at: number;
  stage_label?: string;
}

export interface RoomActivityResponse {
  ok: boolean;
  room_id: string;
  mode?: "tg_mirror" | "web_room" | string;
  mirror_bound: boolean;
  server_ts?: number;
  active_bots: RoomActivityBotItem[];
  recent_jobs: RoomActivityJobItem[];
  recent_dispatch?: RoomActivityDispatchInfo | null;
}

export interface RoomMessagesResponse {
  ok: boolean;
  room: RoomSummary;
  room_id: string;
  latest_seq: number;
  total: number;
  messages: RoomMessageItem[];
}

export interface RoomCreateResponse {
  ok: boolean;
  room: RoomSummary;
}

export interface RoomSendResponse {
  ok: boolean;
  execution_mode?: ExecutionMode;
  message: RoomMessageItem;
  dispatched_bots: string[];
  blocked_bots: string[];
  blocked_reason: string;
}

export interface RoomLiveEvent {
  ver: number;
  type:
    | "room_message"
    | "room_typing"
    | "room_activity"
    | "job_updated"
    | "bots_updated"
    | "resync_required";
  room_id?: string;
  bot?: string;
  from_bot?: string;
  display_name?: string;
  role?: string;
  typing?: boolean;
  busy?: boolean;
  phase?: string;
  target_bots?: string[];
  job_id?: string;
  group_id?: string;
  status?: string;
  label?: string;
  stage_label?: string;
  duration_s?: number | null;
  queue_depth?: number;
  source?: string;
  ts?: number;
  message?: RoomMessageItem;
}

export type AttentionKind = "plan" | "action" | "undo_force" | "browser_takeover";
export type AttentionRiskLevel = "medium" | "high";
export type AttentionStatus = "pending" | "approved" | "rejected" | "expired";

export interface AttentionItem {
  item_id: string;
  kind: AttentionKind;
  risk_level: AttentionRiskLevel;
  status: AttentionStatus;
  readonly_signal?: boolean;
  title: string;
  summary: string;
  origin?: string;
  page_title?: string;
  takeover_reason?: string;
  bot: string;
  cid: string;
  project_id: string;
  room_id: string;
  created_at: number;
  expires_at: number | null;
  decided_at: number | null;
  decided_by: string | null;
  decision_note?: string;
}

export interface AttentionResponse {
  ok: boolean;
  total: number;
  pending_count: number;
  has_browser_takeover: boolean;
  items: AttentionItem[];
}

export interface AttentionDecideResponse {
  ok: boolean;
  item: AttentionItem;
  decision: "approved" | "rejected";
  notify?: {
    notified: boolean;
    bot?: string;
    reason?: string;
  };
}

export type PaneKind = "chat" | "room" | "jobs_attention" | "files" | "browser";

export interface WorkbenchPaneConfig {
  id: string;
  kind: PaneKind;
  bot?: string;
  project?: string;
  roomId?: string;
}

export interface WorkbenchLayoutPrefs {
  paneCount: 1 | 2 | 3 | 4;
  layoutMode: "1" | "2" | "3" | "4";
  panes: WorkbenchPaneConfig[];
}

export type BrowserOwner = "none" | "tab" | "drawer" | `pane:${string}`;

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
