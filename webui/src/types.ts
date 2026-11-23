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
  | "gateways_updated"
  | "accounts_updated"
  | "workbench_state_updated"
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

export interface AccountCostRow extends CostAgg {
  account_id: string;
  alias: string;
  plan_tier: string;
  plan_label: string;
}

export interface PlanCostRow extends CostAgg {
  plan_tier: string;
  plan_label: string;
  accounts: string[];
  account_count: number;
}

export type PlanTierId = "ultra" | "pro" | "enterprise" | "free" | "unknown" | string;

export interface AccountQuotaBucket {
  id: string;
  name: string;
  window: string;
  remaining_fraction: number;
  remaining_pct: number;
  reset_time: string | null;
}

export interface AccountQuotaGroup {
  name: string;
  buckets: AccountQuotaBucket[];
}

export interface AccountQuotaSummary {
  has_quota: boolean;
  fetched_at_iso: string;
  gemini_5h_pct: number | null;
  gemini_5h_reset_at: string | null;
  gemini_weekly_pct: number | null;
  gemini_weekly_reset_at: string | null;
  claude_gpt_5h_pct: number | null;
  claude_gpt_5h_reset_at: string | null;
  claude_gpt_weekly_pct: number | null;
  claude_gpt_weekly_reset_at: string | null;
  groups: AccountQuotaGroup[];
}

export interface WeeklyResetUtcConfig {
  weekday: number;
  hour: number;
  minute?: number;
}

export interface GoogleAccountItem {
  account_id: string;
  alias: string;
  email_masked: string;
  plan_tier: PlanTierId;
  plan_label: string;
  is_active: boolean;
  is_duplicate: boolean;
  duplicate_of: string | null;
  status: "ready" | "pending_login" | "logged_out" | string;
  auth_method?: string;
  is_host_adopted?: boolean;
  credential_fingerprint?: string;
  paid_tier_id?: string;
  current_tier_id?: string;
  last_checked_at?: string;
  last_error?: string;
  created_at?: string;
  updated_at?: string;
  quota_summary: AccountQuotaSummary;
  weekly_reset_utc?: WeeklyResetUtcConfig | null;
}

export interface PlanPoolMetric {
  accounts_with_data: number;
  total_remaining_fraction: number;
  avg_remaining_pct: number | null;
  max_remaining_pct: number | null;
  exhausted_count: number;
  earliest_reset_at: string | null;
}

export interface PlanTierQuotaSummary {
  plan_tier: PlanTierId;
  plan_label: string;
  unique_accounts: number;
  slot_count: number;
  duplicate_slots: number;
  account_ids: string[];
  pools: {
    gemini_5h: PlanPoolMetric;
    gemini_weekly: PlanPoolMetric;
    claude_gpt_5h: PlanPoolMetric;
    claude_gpt_weekly: PlanPoolMetric;
  };
}

export interface MultiPlanQuotaSummary {
  active_account_id: string | null;
  total_unique_accounts: number;
  total_slots: number;
  duplicate_slot_count: number;
  for_group?: boolean;
  tiers: PlanTierQuotaSummary[];
}

export interface AccountRecommendationBucket {
  model_group: "claude_gpt" | "gemini" | string;
  recommended: GoogleAccountItem | null;
  reason: string;
  candidates: GoogleAccountItem[];
}

export interface GoogleAccountsResponse {
  ok: boolean;
  active_account_id: string | null;
  accounts: GoogleAccountItem[];
  by_plan: MultiPlanQuotaSummary;
  recommendation: {
    claude_gpt: AccountRecommendationBucket;
    gemini: AccountRecommendationBucket;
  };
  can_edit: boolean;
  updated_at: string;
}

export interface GoogleAccountAddPayload {
  account_id: string;
  alias?: string;
}

export interface GoogleAccountPatchPayload {
  alias?: string;
  weekly_reset_utc_weekday?: number;
  weekly_reset_utc_hour?: number;
  weekly_reset_utc_minute?: number;
}

export interface GoogleAccountMutationResponse {
  ok: boolean;
  account?: GoogleAccountItem;
  account_id?: string;
  was_active?: boolean;
  snapshot: GoogleAccountsResponse;
}

export interface GoogleAccountActivateResponse {
  ok: boolean;
  previous_account_id: string | null;
  active_account_id: string;
  switched: boolean;
  account: GoogleAccountItem;
  recycle_results?: {
    handle: string;
    ok: boolean;
    status: number | string;
    recycled?: boolean;
    error?: string;
  }[];
  snapshot: GoogleAccountsResponse;
}

export interface GoogleAccountRefreshAllResponse {
  ok: boolean;
  all_succeeded: boolean;
  refreshed: GoogleAccountItem[];
  errors: Record<string, string>;
  snapshot: GoogleAccountsResponse;
}

export interface GoogleLoginFlowState {
  flow_id: string;
  account_id: string;
  alias: string;
  status: "awaiting_code" | "submitting" | "completed" | "cancelled" | "expired" | "failed" | string;
  created_at: number;
  expires_at: number;
  auth_url?: string;
  error: string;
  account?: GoogleAccountItem | null;
}

export interface GoogleLoginFlowResponse {
  ok: boolean;
  flow: GoogleLoginFlowState;
  snapshot?: GoogleAccountsResponse;
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
  by_account_month?: AccountCostRow[];
  by_plan_month?: PlanCostRow[];
  accounts_quota?: MultiPlanQuotaSummary;
  filter?: {
    account_id: string | null;
    plan_tier: string | null;
  };
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

export type GatewayDialectId =
  | "new_api"
  | "cpa"
  | "openrouter"
  | "deepseek"
  | "zhipu"
  | "ark"
  | "litellm"
  | "openai_2api"
  | "openai_strict";

export type GatewayEffortMode = "body" | "model_paren" | "none";
export type GatewayMaxTokensField = "max_completion_tokens" | "max_tokens" | "omit";
export type GatewayCredentialKind = "api_key" | "api_key_env" | "server_cmd_readonly" | "none";
export type GatewaySecretBackend =
  | "openbao"
  | "local_0600"
  | "env"
  | "host_cmd_readonly"
  | "security_card"
  | "legacy_plaintext"
  | "none";

export interface GatewaySecretRefSummary {
  backend: string;
  kv_mount?: string;
  path?: string;
  slot?: string;
  version?: number | null;
  status?: string;
}

export interface GatewayItem {
  id: string;
  name: string;
  base_url: string;
  dialect: GatewayDialectId;
  enabled: boolean;
  credential_kind: GatewayCredentialKind;
  secret_backend: GatewaySecretBackend;
  has_api_key: boolean;
  api_key_hint: string;
  api_key_env: string;
  read_only_cmd: boolean;
  secret_ref_summary: GatewaySecretRefSummary | null;
  include_models: string[];
  exclude_models: string[];
  models: string[];
  supports_reasoning_effort: boolean;
  effort_mode: GatewayEffortMode;
  flatten_system_content: boolean;
  strip_stream_options: boolean;
  max_tokens_field: GatewayMaxTokensField;
  max_tokens_cap: number | null;
  adaptive_400_fallback: boolean;
  timeout_s: number;
  extra_headers: Record<string, string>;
  updated_at?: number | null;
}

export interface GatewaySecretStoreStatus {
  active_backend: "openbao" | "local_0600" | string;
  openbao_ready: boolean;
  fallback_mode: string;
  security_card_status: string;
  backends: { backend_id: string; priority: number; status: string }[];
}

export interface GatewaysListResponse {
  ok: boolean;
  can_edit: boolean;
  total: number;
  gateways: GatewayItem[];
  secret_store: GatewaySecretStoreStatus;
}

export interface GatewayMutationPayload {
  id?: string;
  name?: string;
  base_url?: string;
  dialect?: GatewayDialectId;
  enabled?: boolean;
  credential_kind?: "api_key" | "api_key_env" | "none";
  api_key?: string;
  api_key_env?: string;
  clear_api_key?: boolean;
  preferred_secret_backend?: "openbao" | "local_0600";
  include_models?: string[];
  exclude_models?: string[];
  models?: string[];
  supports_reasoning_effort?: boolean;
  effort_mode?: GatewayEffortMode;
  flatten_system_content?: boolean;
  strip_stream_options?: boolean;
  max_tokens_field?: GatewayMaxTokensField;
  max_tokens_cap?: number | null;
  adaptive_400_fallback?: boolean;
  timeout_s?: number;
  extra_headers?: Record<string, string>;
}

export interface GatewayMutationResponse {
  ok: boolean;
  gateway: GatewayItem;
  secret_backend: string;
  fallback_used?: boolean;
}

export interface GatewayDeleteResponse {
  ok: boolean;
  deleted: boolean;
  id: string;
  secret_deleted?: boolean;
}

export interface GatewayProbePayload {
  gateway_id?: string;
  base_url?: string;
  dialect?: GatewayDialectId;
  credential_kind?: "api_key" | "api_key_env" | "none";
  api_key?: string;
  api_key_env?: string;
  include_models?: string[];
  exclude_models?: string[];
  models?: string[];
  extra_headers?: Record<string, string>;
}

export interface GatewayProbeResponse {
  ok: boolean;
  reachable: boolean;
  http_status: number | null;
  latency_ms: number;
  endpoint: string;
  truncated?: boolean;
  discovered_models: string[];
  discovered_count: number;
  exposed_models: string[];
  exposed_count: number;
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
  effective_model?: string;
  model_mode?: string;
  default_effort?: string;
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

export type BotProfileDocName = "SOUL.md" | "RULES.md" | "MEMORY.md";

export interface BotSkillsPolicy {
  mode: "allowlist" | "all";
  enabled_catalog_skills: string[];
}

export interface BotProfileSkillItem {
  slug: string;
  name: string;
  scope: string;
  description: string;
  size_bytes: number;
  updated_at: number;
  owner?: string;
  enabled?: boolean;
}

export interface BotTeamMemoryRow {
  handle: string;
  project: string;
  observations_count: number;
  summaries_count: number;
  instincts_count: number;
}

export interface BotMemoryStats {
  memory_project: string;
  memory_scope: "isolated" | "coordinator_all" | string;
  observations_count: number;
  summaries_count: number;
  instincts_count: number;
  active_instincts_preview: string;
  team_memory?: BotTeamMemoryRow[];
  total_observations?: number;
  total_summaries?: number;
  total_instincts?: number;
}

export interface BotProfileResponse {
  ok: boolean;
  ipc_online: boolean;
  can_edit: boolean;
  handle: string;
  role: string;
  rev: number;
  max_doc_bytes: number;
  specialty: string;
  memory_project: string;
  memory_scope: string;
  updated_at: number;
  updated_by: string;
  docs: Record<BotProfileDocName, string>;
  doc_bytes: Record<BotProfileDocName, number>;
  skills_policy: BotSkillsPolicy;
  own_skills: BotProfileSkillItem[];
  catalog_skills: BotProfileSkillItem[];
  team_skills: BotProfileSkillItem[];
  effective_skills: BotProfileSkillItem[];
  memory_stats: BotMemoryStats;
}

export interface BotProfileUpdatePayload {
  expected_rev: number;
  doc?: BotProfileDocName;
  content?: string;
  docs?: Partial<Record<BotProfileDocName, string>>;
  skills_policy?: BotSkillsPolicy;
  specialty?: string;
}

export interface BotSkillDetailResponse {
  ok: boolean;
  handle: string;
  slug: string;
  rev: number;
  name: string;
  description: string;
  content: string;
  size_bytes: number;
  max_doc_bytes: number;
  can_edit: boolean;
}

export interface BotSkillPutPayload {
  expected_rev: number;
  content: string;
}

export interface BotSkillDeleteResponse {
  ok: boolean;
  deleted: boolean;
  handle: string;
  slug: string;
  rev: number;
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

export interface WorkbenchCustomProjectItem {
  id: string;
  name: string;
  createdAt?: number;
}

export interface WorkbenchSidebarState {
  customProjects: WorkbenchCustomProjectItem[];
  projectRenames: Record<string, string>;
  hiddenProjectIds: string[];
  hiddenSessionCids: string[];
  pinnedSessionCids: string[];
  archivedSessionCids: string[];
  unreadSessionCids: string[];
  sessionRenames: Record<string, string>;
  showArchived: boolean;
}

export interface WorkbenchStateResponse {
  ok: boolean;
  version: number;
  updated_at: number | null;
  state: WorkbenchSidebarState;
  can_edit: boolean;
}

export interface WorkbenchStateUpdatePayload {
  expected_version?: number;
  state: WorkbenchSidebarState;
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
