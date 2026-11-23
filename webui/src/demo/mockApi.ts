import type {
  AccountCostRow,
  ActiveSessionTurnResponse,
  AttentionDecideResponse,
  AttentionItem,
  AttentionResponse,
  AuthMode,
  BotConfigPatchPayload,
  BotConfigResponse,
  BotProfileDocName,
  BotProfileResponse,
  BotProfileUpdatePayload,
  BotReloadResponse,
  BotRosterItem,
  BotSkillDeleteResponse,
  BotSkillDetailResponse,
  BotSkillPutPayload,
  BotsResponse,
  BrowserStatusResponse,
  ChatAbortResponse,
  ChatAttachmentItem,
  ChatMessageItem,
  ChatSendPayload,
  ChatSendResponse,
  CostAgg,
  CostsResponse,
  DailyCostRow,
  EventStreamStatus,
  ExecutionMode,
  FileContentResponse,
  FileDiffResponse,
  FileTreeNode,
  FileTreeResponse,
  GatewayDeleteResponse,
  GatewayItem,
  GatewayMutationPayload,
  GatewayMutationResponse,
  GatewayProbePayload,
  GatewayProbeResponse,
  GatewaysListResponse,
  GoogleAccountActivateResponse,
  GoogleAccountAddPayload,
  GoogleAccountItem,
  GoogleAccountMutationResponse,
  GoogleAccountPatchPayload,
  GoogleAccountRefreshAllResponse,
  GoogleAccountsResponse,
  GoogleLoginFlowResponse,
  GoogleLoginFlowState,
  JobCancelResponse,
  JobDetail,
  JobDetailResponse,
  JobDispatchAssignment,
  JobDispatchPayload,
  JobDispatchResponse,
  JobItem,
  JobRetryResponse,
  JobsResponse,
  ModelCostRow,
  ModelOption,
  ModelsResponse,
  MultiPlanQuotaSummary,
  OpenBaoConfigResponse,
  OpenBaoConfigUpdatePayload,
  OpenBaoTestPayload,
  OpenBaoTestResponse,
  OverviewResponse,
  PlanCostRow,
  PlanTierQuotaSummary,
  ProjectOption,
  ProjectsResponse,
  RoomActivityBotItem,
  RoomActivityJobItem,
  RoomActivityResponse,
  RoomCreateResponse,
  RoomMessageItem,
  RoomMessagesResponse,
  RoomSendResponse,
  RoomsResponse,
  RoomSummary,
  ScheduleCreatePayload,
  ScheduleDeleteResponse,
  ScheduleItem,
  ScheduleMutationResponse,
  SchedulePatchPayload,
  ScheduleRunResponse,
  SchedulesResponse,
  SessionMessagesResponse,
  SessionsResponse,
  SessionSummaryItem,
  StudioEventEnvelope,
  StudioSession,
  UndoActionResponse,
  UndoCheckpointItem,
  UndoCheckpointsResponse,
  UploadAttachmentResponse,
  WorkbenchSidebarState,
  WorkbenchStateResponse,
  WorkbenchStateUpdatePayload,
  WorkspaceProjectItem,
} from "../types";
import {
  abortDemoTurn,
  emitDemoEvent,
  getDemoBrowserStatus,
  registerDemoTurn,
  subscribeDemoEvents,
} from "./mockEventBus";

const nowSec = (): number => Math.floor(Date.now() / 1000);
const isoAgo = (secAgo: number): string => new Date((nowSec() - secAgo) * 1000).toISOString();

const DEMO_PREVIEW_SVG =
  "data:image/svg+xml;charset=utf-8," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="260" viewBox="0 0 480 260">' +
      '<rect width="480" height="260" rx="14" fill="#0f172a"/>' +
      '<rect x="16" y="16" width="448" height="34" rx="8" fill="#1e293b"/>' +
      '<circle cx="34" cy="33" r="5" fill="#38bdf8"/>' +
      '<circle cx="52" cy="33" r="5" fill="#34d399"/>' +
      '<text x="72" y="37" fill="#e2e8f0" font-family="sans-serif" font-size="13" font-weight="600">AGY Studio Demo Architecture Preview</text>' +
      '<rect x="16" y="66" width="214" height="176" rx="10" fill="#111827" stroke="#334155"/>' +
      '<rect x="250" y="66" width="214" height="176" rx="10" fill="#111827" stroke="#0ea5e9"/>' +
      '<text x="32" y="96" fill="#38bdf8" font-family="monospace" font-size="12">Multi-Bot Pipeline</text>' +
      '<text x="32" y="122" fill="#cbd5e1" font-family="sans-serif" font-size="11">1. Coordinator Dispatch</text>' +
      '<text x="32" y="146" fill="#cbd5e1" font-family="sans-serif" font-size="11">2. Isolated Worker Dev</text>' +
      '<text x="32" y="170" fill="#34d399" font-family="sans-serif" font-size="11">3. Read-Only QA Gate</text>' +
      '<text x="266" y="96" fill="#34d399" font-family="monospace" font-size="12">Security &amp; Vault</text>' +
      '<text x="266" y="122" fill="#cbd5e1" font-family="sans-serif" font-size="11">OpenBao KV v2 Ready</text>' +
      '<text x="266" y="146" fill="#cbd5e1" font-family="sans-serif" font-size="11">Zero Plaintext Secrets</text>' +
      '<text x="266" y="170" fill="#38bdf8" font-family="sans-serif" font-size="11">Live-Browser HITL</text>' +
      "</svg>",
  );

let csrfTokenMemory = "demo-csrf";

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
  data?: Record<string, unknown>;
  constructor(
    message: string,
    status: number,
    source = "studio_auth",
    authMode?: AuthMode,
    retryAfter?: number,
    code?: string,
    conflicts?: string[],
    data?: Record<string, unknown>,
  ) {
    super(message);
    this.status = status;
    this.source = source;
    this.authMode = authMode;
    this.retryAfter = retryAfter;
    this.code = code;
    this.conflicts = conflicts;
    this.data = data;
  }
}

function delay(ms = 40): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// In-memory Demo State
// ---------------------------------------------------------------------------

let demoSession: StudioSession | null = {
  ok: true,
  authenticated: true,
  auth_mode: "password",
  bot: "@example_main_bot",
  user_id: 1001,
  role: "admin",
  auth_track: "password",
  username: "demo-admin",
  must_change_password: false,
  csrf_token: "demo-csrf",
  user: {
    id: 1001,
    first_name: "Demo",
    last_name: "Admin",
    username: "demo-admin",
  },
};

function requireAuth(): StudioSession {
  if (!demoSession) {
    throw new StudioApiError("未登录或会话已失效，请重新登录", 401, "studio_auth", "password");
  }
  return { ...demoSession };
}

const DEMO_PROJECTS: WorkspaceProjectItem[] = [
  { id: "agy-studio-demo", name: "agy-studio-demo", is_git: true },
  { id: "edge-gateway-kit", name: "edge-gateway-kit", is_git: true },
];

const DEMO_PROJECT_OPTIONS: ProjectOption[] = DEMO_PROJECTS.map((p) => ({
  id: p.id,
  name: p.name,
}));

const DEMO_NATIVE_MODELS: ModelOption[] = [
  { id: "gemini-2.5-pro", label: "Gemini 2.5 Pro" },
  { id: "gemini-2.5-flash", label: "Gemini 2.5 Flash" },
  { id: "claude-sonnet-4", label: "Claude Sonnet 4" },
];

let demoGateways: GatewayItem[] = [
  {
    id: "openrouter-demo",
    name: "OpenRouter 聚合网关",
    base_url: "https://openrouter.example.com/api/v1",
    dialect: "openrouter",
    enabled: true,
    credential_kind: "api_key",
    secret_backend: "openbao",
    has_api_key: true,
    api_key_hint: "vault-managed",
    api_key_env: "",
    read_only_cmd: false,
    secret_ref_summary: {
      backend: "openbao",
      kv_mount: "secret",
      path: "studio/demo/gateways/openrouter-demo",
      version: 3,
      status: "active",
    },
    include_models: ["claude-*", "gpt-*"],
    exclude_models: ["*:free"],
    models: ["claude-sonnet-4", "gpt-4.1", "o4-mini"],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: false,
    strip_stream_options: false,
    max_tokens_field: "max_tokens",
    max_tokens_cap: null,
    adaptive_400_fallback: true,
    timeout_s: 120,
    extra_headers: { "X-Title": "AGY-Studio-Demo" },
    updated_at: nowSec() - 900,
  },
  {
    id: "cpa-demo",
    name: "CPA 推理中转站",
    base_url: "https://cpa.example.com/v1",
    dialect: "cpa",
    enabled: true,
    credential_kind: "api_key",
    secret_backend: "openbao",
    has_api_key: true,
    api_key_hint: "vault-managed",
    api_key_env: "",
    read_only_cmd: false,
    secret_ref_summary: {
      backend: "openbao",
      kv_mount: "secret",
      path: "studio/demo/gateways/cpa-demo",
      version: 2,
      status: "active",
    },
    include_models: [],
    exclude_models: [],
    models: ["gemini-2.5-pro", "claude-opus-4"],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: false,
    strip_stream_options: false,
    max_tokens_field: "max_completion_tokens",
    max_tokens_cap: null,
    adaptive_400_fallback: true,
    timeout_s: 150,
    extra_headers: {},
    updated_at: nowSec() - 1800,
  },
  {
    id: "deepseek-demo",
    name: "DeepSeek 官方兼容端点",
    base_url: "https://deepseek.example.com/v1",
    dialect: "deepseek",
    enabled: true,
    credential_kind: "api_key_env",
    secret_backend: "env",
    has_api_key: true,
    api_key_hint: "已安全托管",
    api_key_env: "DEEPSEEK_DEMO_KEY",
    read_only_cmd: false,
    secret_ref_summary: {
      backend: "env",
      status: "active",
    },
    include_models: ["deepseek-*"],
    exclude_models: [],
    models: ["deepseek-reasoner", "deepseek-chat"],
    supports_reasoning_effort: false,
    effort_mode: "none",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 8192,
    adaptive_400_fallback: true,
    timeout_s: 90,
    extra_headers: {},
    updated_at: nowSec() - 3600,
  },
];

function buildAllModelOptions(): ModelOption[] {
  const gwModels: ModelOption[] = [];
  for (const gw of demoGateways) {
    if (!gw.enabled) continue;
    for (const m of gw.models) {
      gwModels.push({
        id: `gw:${gw.id}:${m}`,
        label: `[${gw.name}] ${m}`,
      });
    }
  }
  return [...DEMO_NATIVE_MODELS, ...gwModels];
}

let demoBots: BotRosterItem[] = [
  {
    handle: "@example_main_bot",
    display_name: "主控协调器",
    role: "coordinator",
    online: true,
    busy: false,
    current_job: null,
    queue_depth: 0,
    specialty: "多 Agent 编排 · 任务拆解 · Dev-QA 门控收敛",
    model_mode: "custom",
    effective_model: "gw:openrouter-demo:claude-sonnet-4",
    active_model: "gw:openrouter-demo:claude-sonnet-4",
    default_effort: "high",
    default_project: "agy-studio-demo",
    last_seen: nowSec() - 4,
  },
  {
    handle: "@your_bot_1",
    display_name: "核心开发 Bot",
    role: "worker",
    online: true,
    busy: true,
    current_job: "job-demo-03",
    queue_depth: 1,
    specialty: "全栈功能实现 · Git Diff 审阅 · 单元测试与零停机同步",
    model_mode: "custom",
    effective_model: "gw:cpa-demo:gemini-2.5-pro",
    active_model: "gw:cpa-demo:gemini-2.5-pro",
    default_effort: "high",
    default_project: "agy-studio-demo",
    last_seen: nowSec() - 2,
  },
  {
    handle: "@your_bot_2",
    display_name: "独立只读 QA",
    role: "worker",
    online: true,
    busy: false,
    current_job: null,
    queue_depth: 0,
    specialty: "Shift-Left 预检契约 · 脱敏审计 · 无头浏览器回归",
    model_mode: "default",
    effective_model: "gemini-2.5-pro",
    active_model: "gemini-2.5-pro",
    default_effort: "medium",
    default_project: "agy-studio-demo",
    last_seen: nowSec() - 7,
  },
];

const demoBotExtras: Record<
  string,
  {
    skills: { name: string; scope: string; description: string }[];
    mcp_servers: { name: string; transport: string; enabled: boolean }[];
  }
> = {
  "@example_main_bot": {
    skills: [
      { name: "dev-qa-contract", scope: "project", description: "Dev-QA 分级门控与反例契约" },
      { name: "live-browser", scope: "project", description: "实时浏览器镜像与人工接管" },
      { name: "mem-search", scope: "global", description: "跨会话持久记忆三步检索" },
    ],
    mcp_servers: [
      { name: "acb-team", transport: "stdio", enabled: true },
      { name: "claude-mem", transport: "stdio", enabled: true },
    ],
  },
  "@your_bot_1": {
    skills: [
      { name: "dev-qa-contract", scope: "project", description: "Dev-QA 分级门控与反例契约" },
      { name: "live-browser", scope: "project", description: "实时浏览器镜像与人工接管" },
    ],
    mcp_servers: [{ name: "acb-team", transport: "stdio", enabled: true }],
  },
  "@your_bot_2": {
    skills: [
      { name: "dev-qa-contract", scope: "project", description: "只读 QA 独立验收流水线" },
    ],
    mcp_servers: [{ name: "acb-team", transport: "stdio", enabled: true }],
  },
};

let demoOpenBao: OpenBaoConfigResponse = {
  ok: true,
  enabled: true,
  source: "host_auto",
  addr: "https://vault.example.com",
  kv_mount: "secret",
  gateway_path_prefix: "studio/demo/gateways",
  auth_mode: "host_card",
  auth_label: "demo-slot",
  credential_configured: true,
  credential_hint: "已安全托管于演示 OpenBao 槽位（前端永不回显明文凭据）",
  fallback_mode: "local_0600",
  security_card_status: "reserved",
  can_edit: true,
  host_auto_available: true,
  bao_cli_available: true,
  updated_at: nowSec() - 1200,
};

let demoAttentionItems: AttentionItem[] = [
  {
    item_id: "att-demo-01",
    kind: "action",
    risk_level: "high",
    status: "pending",
    title: "生产网关密钥轮换写入 OpenBao",
    summary:
      "开发节点请求将外部模型网关 `openrouter-demo` 的新凭据写入 `studio/demo/gateways/openrouter-demo`（仅写入密文槽位，不落盘配置文件）。请管理员复核并批准。",
    bot: "your_bot_1",
    cid: "conv-demo-01",
    project_id: "agy-studio-demo",
    room_id: "lobby",
    created_at: nowSec() - 420,
    expires_at: nowSec() + 1800,
    decided_at: null,
    decided_by: null,
  },
  {
    item_id: "att-demo-02",
    kind: "plan",
    risk_level: "medium",
    status: "pending",
    title: "多 Bot 并行回归测试执行计划确认",
    summary:
      "协调器拟将本次版本验证拆分为 2 路并行子任务：\n1. @your_bot_1 执行离线 `tsc --noEmit` 与单测矩阵\n2. @your_bot_2 执行只读脱敏门控与 360px/1440px 浏览器巡检",
    bot: "example_main_bot",
    cid: "conv-demo-01",
    project_id: "agy-studio-demo",
    room_id: "lobby",
    created_at: nowSec() - 180,
    expires_at: nowSec() + 2400,
    decided_at: null,
    decided_by: null,
  },
  {
    item_id: "att-demo-03",
    kind: "undo_force",
    risk_level: "medium",
    status: "approved",
    title: "回滚 gateway_adapter 超时默认值",
    summary: "已确认将 `timeout_s` 从 180s 恢复为 120s，并通过全部适配器单元测试。",
    bot: "your_bot_1",
    cid: "conv-demo-02",
    project_id: "edge-gateway-kit",
    room_id: "lobby",
    created_at: nowSec() - 3200,
    expires_at: null,
    decided_at: nowSec() - 2900,
    decided_by: "demo-admin",
    decision_note: "已核对 diff 与回归测试",
  },
];

let demoJobs: JobDetail[] = [
  {
    job_id: "job-demo-01",
    group_id: "grp-demo-01",
    label: "Shift-Left QA 预检契约与安全红线审计",
    from_bot: "@example_main_bot",
    target_bot: "@your_bot_2",
    status: "done",
    project: "agy-studio-demo",
    model: "gemini-2.5-pro",
    effort: "high",
    created_at: nowSec() - 2400,
    started_at: nowSec() - 2390,
    finished_at: nowSec() - 2240,
    duration_sec: 150,
    has_summary: true,
    has_error: false,
    progress: "已完成 8 项反例契约核验",
    prompt: "只读审查 AGY Studio 外部网关 SSRF 防护、CSP 策略与静态脱敏规则，输出 8 条必过契约。",
    result:
      "### QA 预检结论：`PASS`\n- 脱敏扫描：`0 hits`（`core-public` + `public-release`）\n- SSRF 校验：已锁定预解析 IP 连接器，阻断零 TTL DNS Rebinding\n- 前端单测与离线构建全部通过",
    error: "",
  },
  {
    job_id: "job-demo-02",
    group_id: "grp-demo-01",
    label: "外部模型方言适配与流式 SSE 健壮性修复",
    from_bot: "@example_main_bot",
    target_bot: "@your_bot_1",
    status: "done",
    project: "edge-gateway-kit",
    model: "gw:cpa-demo:gemini-2.5-pro",
    effort: "high",
    created_at: nowSec() - 1800,
    started_at: nowSec() - 1785,
    finished_at: nowSec() - 1520,
    duration_sec: 265,
    has_summary: true,
    has_error: false,
    progress: "18/18 测试通过",
    prompt: "补齐 OpenRouter / CPA / DeepSeek 方言的 SSE 终态保护与非有限浮点 token 防护。",
    result:
      "已完成 `bridge/gateway_adapter.py` 修改：\n- 读取线程外层包裹 `try/except/finally` 确保 `done_ev.set()` 必触发\n- 使用 `math.isfinite` 过滤上游异常浮点计数\n- 单元测试 `test_gateway_adapter.py` 全绿",
    error: "",
  },
  {
    job_id: "job-demo-03",
    group_id: "grp-demo-02",
    label: "实时浏览器 Canvas 触控拖拽与自适应码率联调",
    from_bot: "@example_main_bot",
    target_bot: "@your_bot_1",
    status: "running",
    project: "agy-studio-demo",
    model: "gw:cpa-demo:gemini-2.5-pro",
    effort: "medium",
    created_at: nowSec() - 320,
    started_at: nowSec() - 300,
    finished_at: null,
    duration_sec: null,
    has_summary: false,
    has_error: false,
    progress: "正在验证移动端 360px 视口 pointercancel 安全释放…",
    prompt: "完善 Live-Browser 桌面抽屉与全屏模式的指针捕获清理逻辑，防止切换标签后按键卡死。",
    result: "",
    error: "",
  },
  {
    job_id: "job-demo-04",
    group_id: "grp-demo-00",
    label: "模拟超时网关重试演练",
    from_bot: "@example_main_bot",
    target_bot: "@your_bot_2",
    status: "error",
    project: "edge-gateway-kit",
    model: "gw:deepseek-demo:deepseek-reasoner",
    effort: "low",
    created_at: nowSec() - 5400,
    started_at: nowSec() - 5390,
    finished_at: nowSec() - 5310,
    duration_sec: 80,
    has_summary: false,
    has_error: true,
    error_code: "UPSTREAM_TIMEOUT",
    progress: "探测端点超时（演练样例）",
    prompt: "执行混沌超时注入测试，确认熔断与自动降级日志正确落盘。",
    result: "",
    error: "Simulated upstream timeout after 80s; circuit breaker opened cleanly and fell back to native model.",
  },
];

let demoSchedules: ScheduleItem[] = [
  {
    id: "sched-demo-01",
    name: "每日仓库脱敏与安全门控巡检",
    enabled: true,
    read_only_cli: false,
    schedule_type: "cron",
    schedule_expr: "0 9 * * *",
    task_type: "prompt",
    model: "gemini-2.5-pro",
    project: "agy-studio-demo",
    bot: "@your_bot_2",
    silent_if_empty: true,
    prompt: "运行 verify_gate.py --scope security --tier prod，若存在告警则推送摘要至协作大厅。",
    next_run_at: isoAgo(-14400),
    next_run_local: "明日 09:00",
    countdown: "4h 00m",
    last_run_at: isoAgo(72000),
    last_run_local: "今日 09:00",
    last_status: "ok",
    run_count: 14,
  },
  {
    id: "sched-demo-02",
    name: "每小时外部模型网关健康心跳",
    enabled: true,
    read_only_cli: false,
    schedule_type: "cron",
    schedule_expr: "@hourly",
    task_type: "prompt",
    model: "gemini-2.5-flash",
    project: "edge-gateway-kit",
    bot: "@example_main_bot",
    silent_if_empty: true,
    prompt: "依次探测已启用的外部模型网关延迟与可用模型列表，仅在异常时告警。",
    next_run_at: isoAgo(-1800),
    next_run_local: "整点 +30m",
    countdown: "30m",
    last_run_at: isoAgo(1800),
    last_run_local: "30 分钟前",
    last_status: "ok",
    run_count: 86,
  },
  {
    id: "sched-demo-03",
    name: "每周缓存命中率与费用账单汇总",
    enabled: false,
    read_only_cli: false,
    schedule_type: "cron",
    schedule_expr: "0 9 * * 1",
    task_type: "reminder",
    model: "gemini-2.5-flash",
    project: "agy-studio-demo",
    bot: "@example_main_bot",
    silent_if_empty: false,
    prompt: "汇总过去 7 天各模型家族的 Token 消耗、Prefix Cache 命中率与节省费用报告。",
    next_run_at: null,
    next_run_local: "已暂停",
    countdown: "已暂停",
    last_run_at: isoAgo(345600),
    last_run_local: "4 天前",
    last_status: "ok",
    run_count: 5,
  },
];

let demoRooms: RoomSummary[] = [
  {
    room_id: "lobby",
    title: "团队协作大厅",
    topic: "AGY Studio 多 Bot 协同研发 · TG 双向镜像演示",
    mode: "tg_mirror",
    mirror_bound: true,
    default_bot: "@example_main_bot",
    created_at: nowSec() - 86400,
    updated_at: nowSec() - 60,
    last_seq: 5,
    message_count: 5,
  },
  {
    room_id: "release-qa",
    title: "发版与 QA 门控室",
    topic: "Prod-Release 门控签核 · 只读 QA 审查记录",
    mode: "web_room",
    mirror_bound: false,
    default_bot: "@your_bot_2",
    created_at: nowSec() - 43200,
    updated_at: nowSec() - 600,
    last_seq: 2,
    message_count: 2,
  },
];

const demoRoomMessages: Record<string, RoomMessageItem[]> = {
  lobby: [
    {
      seq: 1,
      msg_id: "rm-demo-01",
      room_id: "lobby",
      ts: nowSec() - 1200,
      sender_type: "human",
      sender: "demo-admin",
      source: "web",
      content: "请 @example_main_bot 统筹本轮 AGY Studio 外部模型与实时浏览器回归，先做 Shift-Left QA 预检。",
      mentions: ["@example_main_bot"],
      chain_id: "chain-demo-01",
      hop: 0,
      status: "done",
      blocked_reason: "",
    },
    {
      seq: 2,
      msg_id: "rm-demo-02",
      room_id: "lobby",
      ts: nowSec() - 1140,
      sender_type: "bot",
      sender: "@example_main_bot",
      sender_role: "coordinator",
      source: "web",
      stage_tag: "dispatch",
      job_id: "job-demo-01",
      content:
        "收到，已按 **Prod-Release** 门控拆解任务并已派单给 @your_bot_2（单号 `job-demo-01`）执行只读预检契约审计，同时排入 @your_bot_1 等待契约签出后推进开发。",
      mentions: ["@your_bot_2", "@your_bot_1"],
      chain_id: "chain-demo-01",
      hop: 1,
      status: "done",
      blocked_reason: "",
    },
    {
      seq: 3,
      msg_id: "rm-demo-03",
      room_id: "lobby",
      ts: nowSec() - 1080,
      sender_type: "bot",
      sender: "@your_bot_2",
      sender_role: "worker",
      source: "web",
      stage_tag: "ack",
      job_id: "job-demo-01",
      content: "收到来自 @example_main_bot 的派单（`job-demo-01`），我开始在只读沙箱执行脱敏审计、SSRF 核验与反例清单整理。",
      mentions: ["@example_main_bot"],
      chain_id: "chain-demo-01",
      hop: 2,
      status: "done",
      blocked_reason: "",
    },
    {
      seq: 4,
      msg_id: "rm-demo-04",
      room_id: "lobby",
      ts: nowSec() - 780,
      sender_type: "bot",
      sender: "@your_bot_2",
      sender_role: "worker",
      source: "web",
      stage_tag: "delivery",
      job_id: "job-demo-01",
      content:
        "已完成只读预检（`job-demo-01`）：\n- 脱敏扫描 `core-public` **0 hits**\n- 外部模型网关跨源探测剥离凭据校验 **PASS**\n- 实时浏览器 WebSocket 断连清理 **PASS**\n\n已交付契约给 @your_bot_1 开始实现。",
      attachments: [
        {
          id: "att-img-demo-01",
          name: "studio-architecture-preview.svg",
          kind: "image",
          mime: "image/svg+xml",
          size: 1420,
          size_label: "1.4 KB",
          preview_url: DEMO_PREVIEW_SVG,
        },
      ],
      mentions: ["@your_bot_1"],
      chain_id: "chain-demo-01",
      hop: 3,
      status: "done",
      blocked_reason: "",
    },
    {
      seq: 5,
      msg_id: "rm-demo-05",
      room_id: "lobby",
      ts: nowSec() - 120,
      sender_type: "bot",
      sender: "@your_bot_1",
      sender_role: "worker",
      source: "web",
      stage_tag: "delivery",
      job_id: "job-demo-02",
      content:
        "已交付 `job-demo-02`：外部模型方言适配与流式 SSE 健壮性修复全部完成，18/18 单元测试通过；可在左侧 **文件审查** 查看实时 Git Diff 与 Undo 检查点，或点击 **实时浏览器** 体验人工接管。",
      context_files: ["bridge/gateway_adapter.py", "studio/server.py"],
      mentions: ["@example_main_bot"],
      chain_id: "chain-demo-01",
      hop: 4,
      status: "done",
      blocked_reason: "",
    },
  ],
  "release-qa": [
    {
      seq: 1,
      msg_id: "rm-qa-01",
      room_id: "release-qa",
      ts: nowSec() - 1600,
      sender_type: "bot",
      sender: "@your_bot_2",
      sender_role: "worker",
      source: "web",
      stage_tag: "reply",
      content: "发版门控室已就绪：所有进入公仓的代码均需满足 `security_audit.py` 0 hits 与全量单测绿灯。",
      mentions: [],
      chain_id: "chain-qa-01",
      hop: 0,
      status: "done",
      blocked_reason: "",
    },
    {
      seq: 2,
      msg_id: "rm-qa-02",
      room_id: "release-qa",
      ts: nowSec() - 600,
      sender_type: "bot",
      sender: "@example_main_bot",
      sender_role: "coordinator",
      source: "web",
      stage_tag: "delivery",
      content: "上一轮 CI 矩阵 6/6 全绿，审批中心仍有 2 项待管理员人工签核。",
      mentions: [],
      chain_id: "chain-qa-01",
      hop: 1,
      status: "done",
      blocked_reason: "",
    },
  ],
};

let demoSessions: SessionSummaryItem[] = [
  {
    cid: "conv-demo-01",
    title: "AGY Studio 架构与多 Bot 协作巡检",
    preview: "已完成外部模型、OpenBao 托管与实时浏览器抽屉的全链路核验…",
    updated_at: isoAgo(120),
    project_id: "agy-studio-demo",
    source: "web",
    bot: "@example_main_bot",
    busy: false,
  },
  {
    cid: "conv-demo-02",
    title: "OpenRouter / CPA 方言适配与 SSE 容错",
    preview: "已补齐 math.isfinite 保护与 finally 终态信号 emission…",
    updated_at: isoAgo(1500),
    project_id: "edge-gateway-kit",
    source: "web",
    bot: "@your_bot_1",
    busy: false,
  },
  {
    cid: "conv-demo-03",
    title: "脱敏规则与 360px 移动端视口复测",
    preview: "11 个导航模块 + 底部 5 项栏 + 更多抽屉均无横向溢出…",
    updated_at: isoAgo(3600),
    project_id: "agy-studio-demo",
    source: "tg",
    bot: "@your_bot_2",
    busy: false,
  },
];

const demoSessionMessages: Record<string, ChatMessageItem[]> = {
  "conv-demo-01": [
    {
      id: "msg-demo-01",
      role: "user",
      content: "帮我检查当前 AGY Studio 的多 Bot 协作状态、OpenBao 托管健康度，并生成一份简明报告。",
      context_files: ["studio/server.py", "bridge/gateway_adapter.py"],
      attachments: [
        {
          id: "att-doc-demo-01",
          name: "release-checklist.md",
          kind: "document",
          mime: "text/markdown",
          size: 2048,
          size_label: "2.0 KB",
          preview_url: "",
        },
      ],
      created_at: isoAgo(240),
    },
    {
      id: "msg-demo-02",
      role: "assistant",
      thinking:
        "先聚合在线 Bot 节点、OpenBao 密码库健康状态与最近派工单，再核对审批中心是否有待处理高危动作。",
      tool_calls: [
        { name: "fetch_bots_roster", duration_seconds: 0.2, active: false },
        { name: "check_openbao_health", duration_seconds: 0.3, active: false },
        { name: "read_file", duration_seconds: 0.1, active: false },
      ],
      content:
        "### AGY Studio 系统巡检摘要\n\n" +
        "1. **Bot 团队在线率**：`3 / 3` 节点在线（`@example_main_bot` 主控协调器、`@your_bot_1` 核心开发、`@your_bot_2` 独立只读 QA）。\n" +
        "2. **OpenBao 密钥托管**：已连接演示地址 `https://vault.example.com`，KV v2 挂载点 `secret`，状态 **已解封 · 可写**。\n" +
        "3. **待处理审批**：审批中心有 **2 条** 待确认事项（含高危密钥轮换审批）。\n\n" +
        "> 💡 你可以在下方输入框直接发送任意问题体验流式思考 + 工具调用回复，或点击左侧 **「实时浏览器」** 体验桌面端右侧滑出式 Canvas 镜像与人工接管。",
      status: "DONE",
      created_at: isoAgo(180),
    },
  ],
  "conv-demo-02": [
    {
      id: "msg-demo-21",
      role: "user",
      content: "确认外部模型网关的 SSE 流式异常处理是否已加上终态保障？",
      created_at: isoAgo(1600),
    },
    {
      id: "msg-demo-22",
      role: "assistant",
      thinking: "检查 bridge/gateway_adapter.py 中流式读取线程的异常捕获与退出信号。",
      tool_calls: [{ name: "read_file", duration_seconds: 0.2, active: false }],
      content:
        "已确认完成修复：\n\n```python\ntry:\n    for raw_line in resp.iter_lines(decode_unicode=True):\n        ...\nfinally:\n    done_ev.set()\n```\n\n同时对上游返回非有限浮点 token 计数加入了 `math.isfinite` 校验。",
      status: "DONE",
      created_at: isoAgo(1500),
    },
  ],
  "conv-demo-03": [
    {
      id: "msg-demo-31",
      role: "user",
      content: "汇报本次脱敏与移动端响应式回归结果。",
      created_at: isoAgo(3700),
    },
    {
      id: "msg-demo-32",
      role: "assistant",
      content:
        "回归全部通过：\n- `security_audit.py --mode core-public`: **0 hits**\n- 移动端 `360px` / `390px` 底部 5 项栏与 `MobileMoreSheet` 零溢出、零报错。",
      status: "DONE",
      created_at: isoAgo(3600),
    },
  ],
};

// Virtual repository files & diffs
const DEMO_FILE_TREES: Record<string, FileTreeNode[]> = {
  "agy-studio-demo": [
    {
      name: "studio",
      path: "studio",
      type: "dir",
      size: null,
      has_children: true,
      children: [
        { name: "server.py", path: "studio/server.py", type: "file", size: 4820 },
        { name: "event_hub.py", path: "studio/event_hub.py", type: "file", size: 2140 },
      ],
    },
    {
      name: "bridge",
      path: "bridge",
      type: "dir",
      size: null,
      has_children: true,
      children: [
        { name: "gateway_adapter.py", path: "bridge/gateway_adapter.py", type: "file", size: 3910 },
      ],
    },
    { name: "README.md", path: "README.md", type: "file", size: 1280 },
    { name: "pyproject.toml", path: "pyproject.toml", type: "file", size: 640 },
  ],
  "edge-gateway-kit": [
    {
      name: "bridge",
      path: "bridge",
      type: "dir",
      size: null,
      has_children: true,
      children: [
        { name: "gateway_adapter.py", path: "bridge/gateway_adapter.py", type: "file", size: 3910 },
      ],
    },
    { name: "README.md", path: "README.md", type: "file", size: 960 },
  ],
};

const DEMO_FILE_CONTENTS: Record<string, { language: string; content: string }> = {
  "studio/server.py": {
    language: "python",
    content: [
      '"""AGY Studio HTTP/WS Control Plane (Sanitized Demo Excerpt)."""',
      "",
      "from aiohttp import web",
      "",
      "async def handle_health(_request: web.Request) -> web.Response:",
      '    return web.json_response({"ok": True, "mode": "demo", "rbac": "enforced"})',
      "",
      "async def handle_openbao_test(request: web.Request) -> web.Response:",
      '    # Strict canonical origin & SSRF validation before probing Vault',
      '    return web.json_response({"ok": True, "reachable": True, "sealed": False})',
    ].join("\n"),
  },
  "studio/event_hub.py": {
    language: "python",
    content: [
      '"""In-memory bounded SSE EventHub for Studio clients."""',
      "",
      "class EventHub:",
      "    def __init__(self, max_backlog: int = 200) -> None:",
      "        self.max_backlog = max_backlog",
      "        self.seq = 0",
      "",
      "    def publish(self, event_type: str, payload: dict) -> int:",
      "        self.seq += 1",
      "        return self.seq",
    ].join("\n"),
  },
  "bridge/gateway_adapter.py": {
    language: "python",
    content: [
      '"""OpenAI-Compatible External Model Gateway Adapter (Demo Excerpt)."""',
      "",
      "import math",
      "",
      "def safe_int_usage(value: object) -> int:",
      "    if isinstance(value, bool):",
      "        return 0",
      "    if isinstance(value, (int, float)) and math.isfinite(value):",
      "        return max(0, int(value))",
      "    return 0",
    ].join("\n"),
  },
  "README.md": {
    language: "markdown",
    content: [
      "# AGY Studio Demo Workspace",
      "",
      "- 多 Bot 团队协作与实时事件流",
      "- OpenBao 分级密钥托管与外部模型网关方言适配",
      "- Live-Browser Canvas 镜像与人工接管（HITL）",
      "- 文件树浏览、Git Diff 审查与 Undo / Redo 检查点",
    ].join("\n"),
  },
  "pyproject.toml": {
    language: "toml",
    content: [
      "[project]",
      'name = "agy-studio-demo"',
      'version = "2.0.0"',
      'requires-python = ">=3.11"',
    ].join("\n"),
  },
};

const DEMO_DIFF_BLOCKS: Record<string, { status: string; staged: string; diff: string }> = {
  "studio/server.py": {
    status: "M",
    staged: "unstaged",
    diff: [
      "diff --git a/studio/server.py b/studio/server.py",
      "--- a/studio/server.py",
      "+++ b/studio/server.py",
      "@@ -12,6 +12,10 @@ async def handle_gateway_probe(request):",
      "-    target_url = body.get('base_url')",
      "+    target_url = validate_canonical_origin(body.get('base_url'), stored_gw)",
      "+    if not same_origin and stored_gw.read_only_cmd:",
      "+        return web.json_response({'ok': False, 'error': 'cross-origin blocked'}, status=403)",
      "     return await run_bounded_probe(target_url)",
    ].join("\n"),
  },
  "bridge/gateway_adapter.py": {
    status: "M",
    staged: "staged",
    diff: [
      "diff --git a/bridge/gateway_adapter.py b/bridge/gateway_adapter.py",
      "--- a/bridge/gateway_adapter.py",
      "+++ b/bridge/gateway_adapter.py",
      "@@ -84,4 +84,9 @@ def safe_int_usage(value):",
      "-    return int(value or 0)",
      "+    if isinstance(value, bool):",
      "+        return 0",
      "+    if isinstance(value, (int, float)) and math.isfinite(value):",
      "+        return max(0, int(value))",
      "+    return 0",
    ].join("\n"),
  },
};

let demoUndoStack: UndoCheckpointItem[] = [
  {
    entry_id: "ckpt-demo-02",
    ts: nowSec() - 480,
    cid: "conv-demo-01",
    project_id: "agy-studio-demo",
    prompt: "为外部模型探测接口增加同源校验与跨源凭据剥离",
    truncated: false,
    changes_count: 2,
    changes: [
      { path: "studio/server.py", action: "modified" },
      { path: "bridge/gateway_adapter.py", action: "modified" },
    ],
    is_top: true,
  },
  {
    entry_id: "ckpt-demo-01",
    ts: nowSec() - 1900,
    cid: "conv-demo-01",
    project_id: "agy-studio-demo",
    prompt: "初始化 OpenBao 演示配置与安全卡预留视图",
    truncated: false,
    changes_count: 1,
    changes: [{ path: "studio/event_hub.py", action: "modified" }],
    is_top: false,
  },
];

let demoRedoStack: UndoCheckpointItem[] = [
  {
    entry_id: "ckpt-demo-03",
    ts: nowSec() - 120,
    cid: "conv-demo-01",
    project_id: "agy-studio-demo",
    prompt: "调整 README 示例说明文案",
    truncated: false,
    changes_count: 1,
    changes: [{ path: "README.md", action: "modified" }],
    is_top: true,
  },
];

function refreshCheckpointTopFlags(): void {
  demoUndoStack = demoUndoStack.map((item, idx) => ({ ...item, is_top: idx === 0 }));
  demoRedoStack = demoRedoStack.map((item, idx) => ({ ...item, is_top: idx === 0 }));
}

let demoWorkbenchVersion = 1;
let demoWorkbenchState: WorkbenchSidebarState = {
  customProjects: [],
  projectRenames: {},
  hiddenProjectIds: [],
  hiddenSessionCids: [],
  pinnedSessionCids: ["conv-demo-01"],
  archivedSessionCids: [],
  unreadSessionCids: [],
  sessionRenames: {},
  showArchived: false,
};

let nextIdCounter = 20;
function nextDemoId(prefix: string): string {
  nextIdCounter += 1;
  return `${prefix}-demo-${nextIdCounter}`;
}

function pendingAttentionCountNow(): number {
  return demoAttentionItems.filter((it) => it.status === "pending").length;
}

// ---------------------------------------------------------------------------
// Exported API Functions (1:1 signature match with `webui/src/api.ts`)
// ---------------------------------------------------------------------------

export async function fetchMe(): Promise<StudioSession> {
  await delay(25);
  return requireAuth();
}

export async function authLogin(username: string, _password: string): Promise<StudioSession> {
  await delay(80);
  const clean = username.trim() || "demo-admin";
  demoSession = {
    ok: true,
    authenticated: true,
    auth_mode: "password",
    bot: "@example_main_bot",
    user_id: 1001,
    role: "admin",
    auth_track: "password",
    username: clean,
    must_change_password: false,
    csrf_token: "demo-csrf",
    user: {
      id: 1001,
      first_name: clean,
      username: clean,
    },
  };
  setCsrfToken(demoSession.csrf_token);
  return { ...demoSession };
}

export async function authChangePassword(
  _curPwd: string,
  _nextPwd: string,
): Promise<StudioSession> {
  await delay(60);
  const cur = requireAuth();
  demoSession = {
    ...cur,
    must_change_password: false,
    csrf_token: "demo-csrf",
  };
  return { ...demoSession };
}

export async function authTelegram(_initData: string): Promise<StudioSession> {
  await delay(40);
  return requireAuth();
}

export async function authRedeemMagic(_token: string): Promise<StudioSession> {
  await delay(40);
  return requireAuth();
}

export async function authLogout(): Promise<{ ok: boolean }> {
  await delay(40);
  demoSession = null;
  setCsrfToken("");
  return { ok: true };
}

export async function fetchOverview(): Promise<OverviewResponse> {
  await delay(35);
  const me = requireAuth();
  const botsOnline = demoBots.filter((b) => b.online).length;
  const botsBusy = demoBots.filter((b) => b.busy).length;
  const jobsRunning = demoJobs.filter((j) => j.status === "running").length;
  const jobsQueued = demoJobs.filter((j) => j.status === "queued").length;
  const jobsError = demoJobs.filter((j) => j.status === "error").length;
  const schedulesActive = demoSchedules.filter((s) => s.enabled).length;

  return {
    ok: true,
    readonly: false,
    generated_at: nowSec(),
    viewer: {
      bot: me.bot,
      user_id: me.user_id,
      role: me.role,
      auth_track: me.auth_track,
    },
    summary: {
      bots_total: demoBots.length,
      bots_online: botsOnline,
      bots_busy: botsBusy,
      jobs_total: demoJobs.length,
      jobs_running: jobsRunning,
      jobs_queued: jobsQueued,
      jobs_error: jobsError,
      schedules_total: demoSchedules.length,
      schedules_active: schedulesActive,
      today_cost_usd: 1.84,
      today_tokens: 1420 * 1000,
      today_cache_hit_pct: 78.4,
      week_cost_usd: 11.62,
      week_saved_usd: 26.45,
      month_cost_usd: 38.9,
    },
    browser: getDemoBrowserStatus(),
    recent_jobs: demoJobs.slice(0, 6).map((j) => ({ ...j })),
  };
}

export async function fetchBots(): Promise<BotsResponse> {
  await delay(30);
  requireAuth();
  return {
    ok: true,
    readonly: false,
    total: demoBots.length,
    online: demoBots.filter((b) => b.online).length,
    busy: demoBots.filter((b) => b.busy).length,
    bots: demoBots.map((b) => ({ ...b })),
  };
}

export async function fetchJobs(params?: {
  limit?: number;
  status?: string;
}): Promise<JobsResponse> {
  await delay(35);
  requireAuth();
  const counts: Record<string, number> = {
    running: 0,
    queued: 0,
    done: 0,
    error: 0,
    cancelled: 0,
  };
  for (const j of demoJobs) {
    counts[j.status] = (counts[j.status] || 0) + 1;
  }
  let filtered = demoJobs;
  if (params?.status) {
    filtered = filtered.filter((j) => j.status === params.status);
  }
  const lim = params?.limit && params.limit > 0 ? params.limit : 50;
  return {
    ok: true,
    readonly: false,
    total: filtered.length,
    counts,
    jobs: filtered.slice(0, lim).map((j) => ({ ...j })),
  };
}

export async function fetchJobDetail(jobId: string): Promise<JobDetailResponse> {
  await delay(30);
  requireAuth();
  const found = demoJobs.find((j) => j.job_id === jobId);
  if (!found) {
    throw new StudioApiError(`未找到派工单 ${jobId}`, 404, "studio_api");
  }
  return { ok: true, job: { ...found } };
}

export async function dispatchJobs(payload: JobDispatchPayload): Promise<JobDispatchResponse> {
  await delay(70);
  requireAuth();
  const groupId = nextDemoId("grp");
  const list: JobDispatchAssignment[] =
    "assignments" in payload ? payload.assignments : [payload];
  const created: JobItem[] = [];
  for (const item of list) {
    const jid = nextDemoId("job");
    const ts = nowSec();
    const detail: JobDetail = {
      job_id: jid,
      group_id: groupId,
      label: item.label || item.prompt.slice(0, 32),
      from_bot: "@example_main_bot",
      target_bot: item.bot,
      status: "running",
      project: item.project || "agy-studio-demo",
      model: item.model || "gemini-2.5-pro",
      effort: item.effort || "medium",
      created_at: ts,
      started_at: ts,
      finished_at: null,
      duration_sec: null,
      has_summary: false,
      has_error: false,
      progress: "已派发至演示队列执行中…",
      prompt: item.prompt,
      result: "",
      error: "",
    };
    demoJobs = [detail, ...demoJobs];
    created.push({ ...detail });
    emitDemoEvent("job_updated", {
      job_id: jid,
      bot: item.bot,
      status: "running",
      label: detail.label,
      ts,
    });
    window.setTimeout(() => {
      const target = demoJobs.find((j) => j.job_id === jid);
      if (target && target.status === "running") {
        target.status = "done";
        target.finished_at = nowSec();
        target.duration_sec = Math.max(1, target.finished_at - (target.started_at || target.created_at));
        target.has_summary = true;
        target.progress = "演示执行已完成";
        target.result = `已完成演示任务 **${target.label}**，所有门控检查通过。`;
        emitDemoEvent("job_updated", {
          job_id: jid,
          bot: target.target_bot,
          status: "done",
          label: target.label,
          duration_s: target.duration_sec,
          ts: nowSec(),
        });
      }
    }, 1200);
  }
  return { ok: true, group_id: groupId, jobs: created };
}

export async function cancelJob(jobId: string): Promise<JobCancelResponse> {
  await delay(50);
  requireAuth();
  const target = demoJobs.find((j) => j.job_id === jobId);
  if (!target) {
    throw new StudioApiError(`未找到派工单 ${jobId}`, 404, "studio_api");
  }
  const terminal = target.status === "done" || target.status === "error" || target.status === "cancelled";
  if (!terminal) {
    target.status = "cancelled";
    target.finished_at = nowSec();
    target.progress = "已由管理员取消";
    emitDemoEvent("job_updated", {
      job_id: jobId,
      bot: target.target_bot,
      status: "cancelled",
      label: target.label,
      ts: nowSec(),
    });
  }
  return {
    ok: true,
    job_id: jobId,
    already_terminal: terminal,
    cancelled: !terminal,
    status: target.status,
    via_ipc: true,
  };
}

export async function retryJob(jobId: string): Promise<JobRetryResponse> {
  await delay(60);
  requireAuth();
  const orig = demoJobs.find((j) => j.job_id === jobId);
  if (!orig) {
    throw new StudioApiError(`未找到派工单 ${jobId}`, 404, "studio_api");
  }
  const newId = nextDemoId("job");
  const ts = nowSec();
  const cloned: JobDetail = {
    ...orig,
    job_id: newId,
    status: "done",
    created_at: ts,
    started_at: ts,
    finished_at: ts + 2,
    duration_sec: 2,
    has_error: false,
    has_summary: true,
    error: "",
    progress: "重试执行完成",
    result: `已成功重试原任务 \`${jobId}\`，所有检查项恢复正常。`,
  };
  demoJobs = [cloned, ...demoJobs];
  emitDemoEvent("job_updated", {
    job_id: newId,
    bot: cloned.target_bot,
    status: "done",
    label: cloned.label,
    duration_s: 2,
    ts,
  });
  return { ok: true, retried_from: jobId, job_id: newId, job: { ...cloned } };
}

export async function fetchSchedules(): Promise<SchedulesResponse> {
  await delay(30);
  requireAuth();
  const active = demoSchedules.filter((s) => s.enabled).length;
  return {
    ok: true,
    readonly: false,
    tz_label: "UTC+8",
    total: demoSchedules.length,
    active,
    paused: demoSchedules.length - active,
    schedules: demoSchedules.map((s) => ({ ...s })),
  };
}

export async function createSchedule(
  payload: ScheduleCreatePayload,
): Promise<ScheduleMutationResponse> {
  await delay(50);
  requireAuth();
  const enabled = payload.enabled ?? true;
  const item: ScheduleItem = {
    id: nextDemoId("sched"),
    name: payload.name,
    enabled,
    read_only_cli: false,
    schedule_type: "cron",
    schedule_expr: payload.schedule_expr,
    task_type: payload.task_type,
    model: payload.model || "gemini-2.5-pro",
    project: payload.project || "agy-studio-demo",
    bot: payload.bot || "@example_main_bot",
    silent_if_empty: payload.silent_if_empty ?? true,
    prompt: payload.prompt,
    next_run_at: enabled ? isoAgo(-3600) : null,
    next_run_local: enabled ? "1 小时后" : "已暂停",
    countdown: enabled ? "1h 00m" : "已暂停",
    last_run_at: null,
    last_run_local: null,
    last_status: "pending",
    run_count: 0,
  };
  demoSchedules = [item, ...demoSchedules];
  emitDemoEvent("schedule_updated", { id: item.id, ts: nowSec() });
  return { ok: true, schedule: { ...item } };
}

export async function updateSchedule(
  scheduleId: string,
  payload: SchedulePatchPayload,
): Promise<ScheduleMutationResponse> {
  await delay(50);
  requireAuth();
  const idx = demoSchedules.findIndex((s) => s.id === scheduleId);
  if (idx < 0) {
    throw new StudioApiError(`未找到定时任务 ${scheduleId}`, 404, "studio_api");
  }
  const cur = demoSchedules[idx];
  const nextEnabled = payload.enabled !== undefined ? payload.enabled : cur.enabled;
  const updated: ScheduleItem = {
    ...cur,
    name: payload.name !== undefined ? payload.name : cur.name,
    schedule_expr: payload.schedule_expr !== undefined ? payload.schedule_expr : cur.schedule_expr,
    task_type: payload.task_type !== undefined ? payload.task_type : cur.task_type,
    prompt: payload.prompt !== undefined ? payload.prompt : cur.prompt,
    project: payload.project !== undefined ? payload.project : cur.project,
    model: payload.model !== undefined ? payload.model : cur.model,
    silent_if_empty:
      payload.silent_if_empty !== undefined ? payload.silent_if_empty : cur.silent_if_empty,
    enabled: nextEnabled,
    next_run_at: nextEnabled ? isoAgo(-3600) : null,
    next_run_local: nextEnabled ? "1 小时后" : "已暂停",
    countdown: nextEnabled ? "1h 00m" : "已暂停",
  };
  demoSchedules[idx] = updated;
  emitDemoEvent("schedule_updated", { id: scheduleId, ts: nowSec() });
  return { ok: true, schedule: { ...updated } };
}

export async function deleteSchedule(scheduleId: string): Promise<ScheduleDeleteResponse> {
  await delay(40);
  requireAuth();
  demoSchedules = demoSchedules.filter((s) => s.id !== scheduleId);
  emitDemoEvent("schedule_updated", { id: scheduleId, ts: nowSec() });
  return { ok: true, deleted: true, id: scheduleId };
}

export async function runScheduleNow(
  scheduleId: string,
  bot?: string,
): Promise<ScheduleRunResponse> {
  await delay(60);
  requireAuth();
  const target = demoSchedules.find((s) => s.id === scheduleId);
  if (!target) {
    throw new StudioApiError(`未找到定时任务 ${scheduleId}`, 404, "studio_api");
  }
  target.run_count += 1;
  target.last_run_at = isoAgo(0);
  target.last_run_local = "刚刚";
  target.last_status = "ok";
  emitDemoEvent("schedule_updated", { id: scheduleId, ts: nowSec() });
  return {
    ok: true,
    queued: true,
    schedule_id: scheduleId,
    bot: bot || target.bot || "@example_main_bot",
  };
}

export class StudioEventClient {
  private unsub: (() => void) | null = null;
  private startTimer: number | null = null;
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
    this.stop();
    this.onStatus("connecting");
    this.unsub = subscribeDemoEvents((ev) => {
      if (ev.type === "auth_error") {
        this.onAuthError(
          typeof ev.data.error === "string" ? ev.data.error : "访问权限已变更",
          typeof ev.data.code === "string" ? ev.data.code : undefined,
        );
        return;
      }
      this.onEvent(ev);
    });
    this.startTimer = window.setTimeout(() => {
      this.startTimer = null;
      this.onStatus("connected");
      this.onEvent({ type: "connected", seq: 1, data: { mode: "demo" } });
      this.onEvent({
        type: "attention_updated",
        seq: 2,
        data: { pending_count: pendingAttentionCountNow() },
      });
    }, 30);
  }

  stop(): void {
    if (this.startTimer !== null) {
      window.clearTimeout(this.startTimer);
      this.startTimer = null;
    }
    if (this.unsub) {
      this.unsub();
      this.unsub = null;
    }
    this.onStatus("disconnected");
  }
}

function makeCostAgg(
  scale: number,
  inputK: number,
  cacheK: number,
  outputK: number,
  calls: number,
  costUsd: number,
  savedUsd: number,
): CostAgg {
  const input_tokens = Math.round(inputK * 1000 * scale);
  const cache_read_tokens = Math.round(cacheK * 1000 * scale);
  const output_tokens = Math.round(outputK * 1000 * scale);
  const total_tokens = input_tokens + cache_read_tokens + output_tokens;
  const totalIn = Math.max(1, input_tokens + cache_read_tokens);
  const cache_hit_pct = Number(((cache_read_tokens / totalIn) * 100).toFixed(1));
  const c = Number((costUsd * scale).toFixed(2));
  const s = Number((savedUsd * scale).toFixed(2));
  const nc = Number((c + s).toFixed(2));
  const save_pct = nc > 0 ? Number(((s / nc) * 100).toFixed(1)) : 0;
  return {
    input_tokens,
    cache_read_tokens,
    output_tokens,
    total_tokens,
    calls: Math.max(1, Math.round(calls * scale)),
    cache_hit_pct,
    cost_usd: c,
    nocache_usd: nc,
    saved_usd: s,
    save_pct,
  };
}

const DEMO_PLAN_LABELS: Record<string, string> = {
  ultra: "Google AI Ultra",
  pro: "Google AI Pro",
  enterprise: "Enterprise",
  free: "Free",
  unknown: "Unknown",
};

const DEMO_PLAN_PRIORITY: Record<string, number> = {
  ultra: 4,
  pro: 3,
  enterprise: 2,
  free: 1,
  unknown: 0,
};

const isoAhead = (secAhead: number): string =>
  new Date((nowSec() + secAhead) * 1000).toISOString();

let demoActiveGoogleAccountId: string | null = "ultra_main";
let demoGoogleAccounts: GoogleAccountItem[] = [
  {
    account_id: "ultra_main",
    alias: "Ultra 主力号",
    email_masked: "u***a@example.com",
    plan_tier: "ultra",
    plan_label: "Google AI Ultra",
    is_active: true,
    is_duplicate: false,
    duplicate_of: null,
    status: "ready",
    auth_method: "oauth-personal",
    is_host_adopted: true,
    credential_fingerprint: "demo_fp_ultra_01",
    last_checked_at: isoAgo(120),
    last_error: "",
    weekly_reset_utc: { weekday: 4, hour: 23, minute: 0 },
    quota_summary: {
      has_quota: true,
      fetched_at_iso: isoAgo(120),
      gemini_5h_pct: 92,
      gemini_5h_reset_at: isoAhead(3 * 3600 + 25 * 60),
      gemini_weekly_pct: 78,
      gemini_weekly_reset_at: isoAhead(4 * 86400 + 6 * 3600),
      claude_gpt_5h_pct: 64,
      claude_gpt_5h_reset_at: isoAhead(2 * 3600 + 18 * 60),
      claude_gpt_weekly_pct: 58,
      claude_gpt_weekly_reset_at: isoAhead(4 * 86400 + 6 * 3600),
      groups: [],
    },
  },
  {
    account_id: "pro_work",
    alias: "Pro 协作号",
    email_masked: "p***k@example.com",
    plan_tier: "pro",
    plan_label: "Google AI Pro",
    is_active: false,
    is_duplicate: false,
    duplicate_of: null,
    status: "ready",
    auth_method: "oauth-personal",
    is_host_adopted: false,
    credential_fingerprint: "demo_fp_pro_02",
    last_checked_at: isoAgo(300),
    last_error: "",
    weekly_reset_utc: { weekday: 1, hour: 8, minute: 0 },
    quota_summary: {
      has_quota: true,
      fetched_at_iso: isoAgo(300),
      gemini_5h_pct: 86,
      gemini_5h_reset_at: isoAhead(4 * 3600 + 10 * 60),
      gemini_weekly_pct: 84,
      gemini_weekly_reset_at: isoAhead(2 * 86400 + 14 * 3600),
      claude_gpt_5h_pct: 95,
      claude_gpt_5h_reset_at: isoAhead(4 * 3600 + 10 * 60),
      claude_gpt_weekly_pct: 88,
      claude_gpt_weekly_reset_at: isoAhead(2 * 86400 + 14 * 3600),
      groups: [],
    },
  },
  {
    account_id: "free_lab",
    alias: "Free 实验号",
    email_masked: "f***e@example.com",
    plan_tier: "free",
    plan_label: "Free",
    is_active: false,
    is_duplicate: false,
    duplicate_of: null,
    status: "ready",
    auth_method: "oauth-personal",
    is_host_adopted: false,
    credential_fingerprint: "demo_fp_free_03",
    last_checked_at: isoAgo(600),
    last_error: "",
    weekly_reset_utc: null,
    quota_summary: {
      has_quota: true,
      fetched_at_iso: isoAgo(600),
      gemini_5h_pct: 70,
      gemini_5h_reset_at: isoAhead(1 * 3600 + 45 * 60),
      gemini_weekly_pct: 62,
      gemini_weekly_reset_at: isoAhead(5 * 86400 + 2 * 3600),
      claude_gpt_5h_pct: 40,
      claude_gpt_5h_reset_at: isoAhead(1 * 3600 + 45 * 60),
      claude_gpt_weekly_pct: 35,
      claude_gpt_weekly_reset_at: isoAhead(5 * 86400 + 2 * 3600),
      groups: [],
    },
  },
];

const demoLoginFlows = new Map<string, GoogleLoginFlowState>();

function buildDemoPlanSummary(): MultiPlanQuotaSummary {
  const tierMap = new Map<string, PlanTierQuotaSummary>();
  const seenFp = new Set<string>();
  let totalUnique = 0;
  let dupSlots = 0;

  for (const acct of demoGoogleAccounts) {
    const tierKey = acct.plan_tier || "unknown";
    let t = tierMap.get(tierKey);
    if (!t) {
      const emptyPool = () => ({
        accounts_with_data: 0,
        total_remaining_fraction: 0,
        avg_remaining_pct: null as number | null,
        max_remaining_pct: null as number | null,
        exhausted_count: 0,
        earliest_reset_at: null as string | null,
      });
      t = {
        plan_tier: tierKey,
        plan_label: acct.plan_label || DEMO_PLAN_LABELS[tierKey] || "Unknown",
        unique_accounts: 0,
        slot_count: 0,
        duplicate_slots: 0,
        account_ids: [],
        pools: {
          gemini_5h: emptyPool(),
          gemini_weekly: emptyPool(),
          claude_gpt_5h: emptyPool(),
          claude_gpt_weekly: emptyPool(),
        },
      };
      tierMap.set(tierKey, t);
    }
    t.slot_count += 1;
    t.account_ids.push(acct.account_id);
    const dedupKey = acct.credential_fingerprint ? `fp:${acct.credential_fingerprint}` : `slot:${acct.account_id}`;
    if (seenFp.has(dedupKey)) {
      t.duplicate_slots += 1;
      dupSlots += 1;
      continue;
    }
    seenFp.add(dedupKey);
    t.unique_accounts += 1;
    totalUnique += 1;

    const qs = acct.quota_summary;
    const poolPairs: [keyof PlanTierQuotaSummary["pools"], number | null, string | null][] = [
      ["gemini_5h", qs.gemini_5h_pct, qs.gemini_5h_reset_at],
      ["gemini_weekly", qs.gemini_weekly_pct, qs.gemini_weekly_reset_at],
      ["claude_gpt_5h", qs.claude_gpt_5h_pct, qs.claude_gpt_5h_reset_at],
      ["claude_gpt_weekly", qs.claude_gpt_weekly_pct, qs.claude_gpt_weekly_reset_at],
    ];
    for (const [pk, pct, rst] of poolPairs) {
      if (pct === null) continue;
      const pool = t.pools[pk];
      pool.accounts_with_data += 1;
      pool.total_remaining_fraction = Number((pool.total_remaining_fraction + pct / 100).toFixed(4));
      pool.max_remaining_pct = pool.max_remaining_pct === null ? pct : Math.max(pool.max_remaining_pct, pct);
      if (pct <= 5) pool.exhausted_count += 1;
      if (rst && (!pool.earliest_reset_at || rst < pool.earliest_reset_at)) {
        pool.earliest_reset_at = rst;
      }
    }
  }

  for (const t of tierMap.values()) {
    for (const pool of Object.values(t.pools)) {
      if (pool.accounts_with_data > 0) {
        pool.avg_remaining_pct = Number(
          ((pool.total_remaining_fraction / pool.accounts_with_data) * 100).toFixed(1),
        );
      }
    }
  }

  const tiers = Array.from(tierMap.values()).sort(
    (a, b) => (DEMO_PLAN_PRIORITY[b.plan_tier] || 0) - (DEMO_PLAN_PRIORITY[a.plan_tier] || 0),
  );
  return {
    active_account_id: demoActiveGoogleAccountId,
    total_unique_accounts: totalUnique,
    total_slots: demoGoogleAccounts.length,
    duplicate_slot_count: dupSlots,
    tiers,
  };
}

function buildDemoGoogleAccountsSnapshot(): GoogleAccountsResponse {
  const accounts = demoGoogleAccounts.map((a) => ({
    ...a,
    is_active: a.account_id === demoActiveGoogleAccountId,
    quota_summary: { ...a.quota_summary },
    weekly_reset_utc: a.weekly_reset_utc ? { ...a.weekly_reset_utc } : null,
  }));
  const by_plan = buildDemoPlanSummary();

  const pickBest = (group: "claude_gpt" | "gemini") => {
    const ready = accounts
      .filter((a) => a.status === "ready")
      .map((a) => {
        const vals =
          group === "gemini"
            ? [a.quota_summary.gemini_5h_pct, a.quota_summary.gemini_weekly_pct]
            : [a.quota_summary.claude_gpt_5h_pct, a.quota_summary.claude_gpt_weekly_pct];
        const nums = vals.filter((v): v is number => v !== null);
        const eff = nums.length > 0 ? Math.min(...nums) : -1;
        return { a, eff };
      })
      .filter((x) => x.eff > 5)
      .sort((x, y) => y.eff - x.eff);
    const top = ready[0] || null;
    return {
      model_group: group,
      recommended: top ? top.a : null,
      reason: top
        ? `Selected ${top.a.account_id} (${top.a.plan_label}, min remaining ${top.eff.toFixed(1)}%)`
        : `No non-exhausted account available for ${group}`,
      candidates: ready.map((x) => x.a),
    };
  };

  return {
    ok: true,
    active_account_id: demoActiveGoogleAccountId,
    accounts,
    by_plan,
    recommendation: {
      claude_gpt: pickBest("claude_gpt"),
      gemini: pickBest("gemini"),
    },
    can_edit: true,
    updated_at: new Date().toISOString(),
  };
}

export async function fetchGoogleAccounts(): Promise<GoogleAccountsResponse> {
  await delay(30);
  requireAuth();
  return buildDemoGoogleAccountsSnapshot();
}

export async function addGoogleAccount(
  payload: GoogleAccountAddPayload,
): Promise<GoogleAccountMutationResponse> {
  await delay(40);
  requireAuth();
  const aid = (payload.account_id || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(aid)) {
    throw new StudioApiError("account_id 格式非法", 400, "studio_api");
  }
  if (demoGoogleAccounts.some((a) => a.account_id === aid)) {
    throw new StudioApiError(`Account '${aid}' already exists`, 409, "studio_api");
  }
  const item: GoogleAccountItem = {
    account_id: aid,
    alias: payload.alias?.trim() || aid,
    email_masked: "",
    plan_tier: "unknown",
    plan_label: "Unknown",
    is_active: false,
    is_duplicate: false,
    duplicate_of: null,
    status: "pending_login",
    auth_method: "oauth-personal",
    is_host_adopted: false,
    last_checked_at: "",
    last_error: "",
    weekly_reset_utc: null,
    quota_summary: {
      has_quota: false,
      fetched_at_iso: "",
      gemini_5h_pct: null,
      gemini_5h_reset_at: null,
      gemini_weekly_pct: null,
      gemini_weekly_reset_at: null,
      claude_gpt_5h_pct: null,
      claude_gpt_5h_reset_at: null,
      claude_gpt_weekly_pct: null,
      claude_gpt_weekly_reset_at: null,
      groups: [],
    },
  };
  demoGoogleAccounts = [...demoGoogleAccounts, item];
  emitDemoEvent("accounts_updated", { action: "add", account_id: aid, ts: nowSec() });
  return { ok: true, account: item, snapshot: buildDemoGoogleAccountsSnapshot() };
}

export async function updateGoogleAccount(
  accountId: string,
  payload: GoogleAccountPatchPayload,
): Promise<GoogleAccountMutationResponse> {
  await delay(35);
  requireAuth();
  const target = demoGoogleAccounts.find((a) => a.account_id === accountId);
  if (!target) {
    throw new StudioApiError(`账号 '${accountId}' 不存在`, 404, "studio_api");
  }
  if (payload.alias && payload.alias.trim()) {
    target.alias = payload.alias.trim();
  }
  if (
    payload.weekly_reset_utc_weekday !== undefined ||
    payload.weekly_reset_utc_hour !== undefined
  ) {
    target.weekly_reset_utc = {
      weekday: payload.weekly_reset_utc_weekday ?? target.weekly_reset_utc?.weekday ?? 4,
      hour: payload.weekly_reset_utc_hour ?? target.weekly_reset_utc?.hour ?? 23,
      minute: payload.weekly_reset_utc_minute ?? 0,
    };
  }
  emitDemoEvent("accounts_updated", { action: "update", account_id: accountId, ts: nowSec() });
  return { ok: true, account: { ...target }, snapshot: buildDemoGoogleAccountsSnapshot() };
}

export async function deleteGoogleAccount(
  accountId: string,
): Promise<GoogleAccountMutationResponse> {
  await delay(40);
  requireAuth();
  const wasActive = demoActiveGoogleAccountId === accountId;
  demoGoogleAccounts = demoGoogleAccounts.filter((a) => a.account_id !== accountId);
  if (wasActive) {
    demoActiveGoogleAccountId = demoGoogleAccounts[0]?.account_id || null;
  }
  emitDemoEvent("accounts_updated", { action: "delete", account_id: accountId, ts: nowSec() });
  return {
    ok: true,
    account_id: accountId,
    was_active: wasActive,
    snapshot: buildDemoGoogleAccountsSnapshot(),
  };
}

export async function startGoogleAccountLogin(
  accountId: string,
  payload?: { alias?: string; timeout_sec?: number },
): Promise<GoogleLoginFlowResponse> {
  await delay(45);
  requireAuth();
  const now = nowSec();
  const fid = `gflow_demo_${now.toString(36)}`;
  const stateToken = `demo_state_${now.toString(36)}`;
  const existing = demoGoogleAccounts.find((a) => a.account_id === accountId);
  const flow: GoogleLoginFlowState = {
    flow_id: fid,
    account_id: accountId,
    alias: payload?.alias || existing?.alias || accountId,
    status: "awaiting_code",
    created_at: now,
    expires_at: now + 300,
    auth_url: `https://accounts.google.com/o/oauth2/auth?client_id=demo&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback&response_type=code&state=${stateToken}`,
    error: "",
  };
  demoLoginFlows.set(fid, flow);
  return { ok: true, flow: { ...flow } };
}

export async function fetchGoogleLoginFlow(flowId: string): Promise<GoogleLoginFlowResponse> {
  await delay(20);
  requireAuth();
  const flow = demoLoginFlows.get(flowId);
  if (!flow) {
    throw new StudioApiError("未找到对应的 OAuth 登录流", 404, "studio_api");
  }
  const { auth_url: _omit, ...safeFlow } = flow;
  void _omit;
  return { ok: true, flow: safeFlow };
}

export async function submitGoogleLoginCode(
  flowId: string,
  codeOrUrl: string,
): Promise<GoogleLoginFlowResponse> {
  await delay(65);
  requireAuth();
  const flow = demoLoginFlows.get(flowId);
  if (!flow) {
    throw new StudioApiError("未找到对应的 OAuth 登录流", 404, "studio_api");
  }
  if (!codeOrUrl.trim()) {
    throw new StudioApiError("请提供授权码或回调 URL", 400, "studio_api");
  }
  let target = demoGoogleAccounts.find((a) => a.account_id === flow.account_id);
  if (!target) {
    target = {
      account_id: flow.account_id,
      alias: flow.alias,
      email_masked: `${flow.account_id[0] || "u"}***@example.com`,
      plan_tier: "pro",
      plan_label: "Google AI Pro",
      is_active: false,
      is_duplicate: false,
      duplicate_of: null,
      status: "ready",
      credential_fingerprint: `demo_fp_${flow.account_id}`,
      last_checked_at: new Date().toISOString(),
      last_error: "",
      weekly_reset_utc: null,
      quota_summary: {
        has_quota: true,
        fetched_at_iso: new Date().toISOString(),
        gemini_5h_pct: 98,
        gemini_5h_reset_at: isoAhead(5 * 3600),
        gemini_weekly_pct: 96,
        gemini_weekly_reset_at: isoAhead(6 * 86400),
        claude_gpt_5h_pct: 95,
        claude_gpt_5h_reset_at: isoAhead(5 * 3600),
        claude_gpt_weekly_pct: 94,
        claude_gpt_weekly_reset_at: isoAhead(6 * 86400),
        groups: [],
      },
    };
    demoGoogleAccounts = [...demoGoogleAccounts, target];
  } else {
    target.status = "ready";
    target.email_masked = target.email_masked || `${target.account_id[0] || "u"}***@example.com`;
    if (target.plan_tier === "unknown") {
      target.plan_tier = "pro";
      target.plan_label = "Google AI Pro";
    }
    target.last_checked_at = new Date().toISOString();
    target.quota_summary = {
      ...target.quota_summary,
      has_quota: true,
      fetched_at_iso: new Date().toISOString(),
      gemini_5h_pct: target.quota_summary.gemini_5h_pct ?? 96,
      gemini_weekly_pct: target.quota_summary.gemini_weekly_pct ?? 92,
      claude_gpt_5h_pct: target.quota_summary.claude_gpt_5h_pct ?? 94,
      claude_gpt_weekly_pct: target.quota_summary.claude_gpt_weekly_pct ?? 90,
    };
  }
  flow.status = "completed";
  flow.account = { ...target };
  flow.auth_url = undefined;
  emitDemoEvent("accounts_updated", { action: "login_completed", account_id: target.account_id, ts: nowSec() });
  return {
    ok: true,
    flow: { ...flow },
    snapshot: buildDemoGoogleAccountsSnapshot(),
  };
}

export async function cancelGoogleLoginFlow(flowId: string): Promise<GoogleLoginFlowResponse> {
  await delay(20);
  requireAuth();
  const flow = demoLoginFlows.get(flowId);
  if (!flow) {
    throw new StudioApiError("未找到对应的 OAuth 登录流", 404, "studio_api");
  }
  flow.status = "cancelled";
  flow.auth_url = undefined;
  return { ok: true, flow: { ...flow } };
}

export async function logoutGoogleAccount(
  accountId: string,
): Promise<GoogleAccountMutationResponse> {
  await delay(35);
  requireAuth();
  const target = demoGoogleAccounts.find((a) => a.account_id === accountId);
  if (!target) {
    throw new StudioApiError(`账号 '${accountId}' 不存在`, 404, "studio_api");
  }
  const wasActive = demoActiveGoogleAccountId === accountId;
  if (wasActive) demoActiveGoogleAccountId = null;
  target.status = "logged_out";
  target.is_active = false;
  target.quota_summary = {
    ...target.quota_summary,
    has_quota: false,
    gemini_5h_pct: null,
    gemini_weekly_pct: null,
    claude_gpt_5h_pct: null,
    claude_gpt_weekly_pct: null,
  };
  emitDemoEvent("accounts_updated", { action: "logout", account_id: accountId, ts: nowSec() });
  return {
    ok: true,
    account: { ...target },
    was_active: wasActive,
    snapshot: buildDemoGoogleAccountsSnapshot(),
  };
}

export async function activateGoogleAccount(
  accountId: string,
): Promise<GoogleAccountActivateResponse> {
  await delay(45);
  requireAuth();
  const target = demoGoogleAccounts.find((a) => a.account_id === accountId);
  if (!target) {
    throw new StudioApiError(`账号 '${accountId}' 不存在`, 404, "studio_api");
  }
  const prev = demoActiveGoogleAccountId;
  demoActiveGoogleAccountId = accountId;
  emitDemoEvent("accounts_updated", {
    action: "activate",
    account_id: accountId,
    active_account_id: accountId,
    ts: nowSec(),
  });
  const snap = buildDemoGoogleAccountsSnapshot();
  return {
    ok: true,
    previous_account_id: prev,
    active_account_id: accountId,
    switched: prev !== accountId,
    account: snap.accounts.find((a) => a.account_id === accountId) || target,
    recycle_results: [{ handle: "example_main_bot", ok: true, status: 200, recycled: true }],
    snapshot: snap,
  };
}

export async function refreshGoogleAccountQuota(
  accountId: string,
): Promise<GoogleAccountMutationResponse> {
  await delay(50);
  requireAuth();
  const target = demoGoogleAccounts.find((a) => a.account_id === accountId);
  if (!target) {
    throw new StudioApiError(`账号 '${accountId}' 不存在`, 404, "studio_api");
  }
  target.last_checked_at = new Date().toISOString();
  target.quota_summary.fetched_at_iso = target.last_checked_at;
  emitDemoEvent("accounts_updated", { action: "refresh", account_id: accountId, ts: nowSec() });
  return { ok: true, account: { ...target }, snapshot: buildDemoGoogleAccountsSnapshot() };
}

export async function refreshAllGoogleAccountsQuota(): Promise<GoogleAccountRefreshAllResponse> {
  await delay(70);
  requireAuth();
  const nowIso = new Date().toISOString();
  for (const a of demoGoogleAccounts) {
    if (a.status === "ready") {
      a.last_checked_at = nowIso;
      a.quota_summary.fetched_at_iso = nowIso;
    }
  }
  emitDemoEvent("accounts_updated", { action: "refresh_all", ts: nowSec() });
  const snap = buildDemoGoogleAccountsSnapshot();
  return {
    ok: true,
    all_succeeded: true,
    refreshed: snap.accounts.filter((a) => a.status === "ready"),
    errors: {},
    snapshot: snap,
  };
}

export async function fetchCosts(
  scope: "all" | "agent" | "sched" = "all",
  filters?: { account_id?: string | null; plan_tier?: string | null },
): Promise<CostsResponse> {
  await delay(35);
  requireAuth();
  const baseScale = scope === "all" ? 1 : scope === "agent" ? 0.78 : 0.22;

  const accountWeights: { account_id: string; alias: string; plan_tier: string; weight: number }[] = [
    { account_id: "ultra_main", alias: "Ultra 主力号", plan_tier: "ultra", weight: 0.58 },
    { account_id: "pro_work", alias: "Pro 协作号", plan_tier: "pro", weight: 0.31 },
    { account_id: "free_lab", alias: "Free 实验号", plan_tier: "free", weight: 0.11 },
  ];

  const cleanAid = filters?.account_id && filters.account_id !== "all" ? filters.account_id : null;
  const cleanTier = filters?.plan_tier && filters.plan_tier !== "all" ? filters.plan_tier : null;

  const matchedAccounts = accountWeights.filter((a) => {
    if (cleanAid && a.account_id !== cleanAid) return false;
    if (cleanTier && a.plan_tier !== cleanTier) return false;
    return true;
  });
  const filterWeight = matchedAccounts.reduce((acc, item) => acc + item.weight, 0);
  const scale = baseScale * filterWeight;

  const dayWeights = [0.65, 0.9, 1.25, 0.82, 1.4, 1.15, 0.72, 1.1, 1.55, 1.32, 0.94, 1.48, 1.22, 1.0];
  const daily_14d: DailyCostRow[] = dayWeights.map((w, idx) => {
    const dt = new Date(Date.now() - (13 - idx) * 86400 * 1000);
    const mm = String(dt.getMonth() + 1).padStart(2, "0");
    const dd = String(dt.getDate()).padStart(2, "0");
    const yyyy = dt.getFullYear();
    const agg = makeCostAgg(scale * w, 260, 980, 95, 28, 1.65, 3.8);
    // Keep 3-char prefix so `CostsView.tsx`'s `d.label.slice(3)` renders `MM-DD`
    const prefix = `D${String(idx + 1).padStart(2, "0")}`;
    return {
      ...agg,
      date: `${yyyy}-${mm}-${dd}`,
      label: `${prefix}${mm}-${dd}`,
    };
  });

  const by_model_month: ModelCostRow[] =
    scale <= 0
      ? []
      : [
          {
            family: "claude-sonnet-4",
            label: "Claude Sonnet 4 (OpenRouter)",
            ...makeCostAgg(scale, 1840, 7420, 620, 290, 18.4, 42.1),
          },
          {
            family: "gemini-2.5-pro",
            label: "Gemini 2.5 Pro (AGY / CPA)",
            ...makeCostAgg(scale, 1520, 6380, 480, 240, 13.8, 31.6),
          },
          {
            family: "deepseek-reasoner",
            label: "DeepSeek Reasoner",
            ...makeCostAgg(scale, 960, 2850, 390, 145, 6.7, 11.4),
          },
        ];

  const by_model_week: ModelCostRow[] = by_model_month.map((m) => ({
    ...m,
    ...makeCostAgg(0.3 * scale, 520, 2100, 180, 76, m.cost_usd, m.saved_usd),
  }));

  const by_account_month: AccountCostRow[] = matchedAccounts.map((a) => ({
    account_id: a.account_id,
    alias: a.alias,
    plan_tier: a.plan_tier,
    plan_label: DEMO_PLAN_LABELS[a.plan_tier] || "Unknown",
    ...makeCostAgg(baseScale * a.weight, 4320, 16650, 1490, 675, 38.9, 85.1),
  }));

  const planAggMap = new Map<string, { weight: number; accounts: string[] }>();
  for (const a of matchedAccounts) {
    const cur = planAggMap.get(a.plan_tier) || { weight: 0, accounts: [] };
    cur.weight += a.weight;
    cur.accounts.push(a.account_id);
    planAggMap.set(a.plan_tier, cur);
  }
  const by_plan_month: PlanCostRow[] = Array.from(planAggMap.entries()).map(([tier, info]) => ({
    plan_tier: tier,
    plan_label: DEMO_PLAN_LABELS[tier] || "Unknown",
    accounts: info.accounts,
    account_count: info.accounts.length,
    ...makeCostAgg(baseScale * info.weight, 4320, 16650, 1490, 675, 38.9, 85.1),
  }));

  return {
    ok: true,
    readonly: false,
    scope,
    tz_label: "UTC+8",
    week_window: {
      start_local: "周一 00:00",
      end_local: "周日 23:59",
      remaining: "余 3 天 14 小时",
    },
    today: makeCostAgg(scale, 290, 1040, 90, 34, 1.84, 4.12),
    week: makeCostAgg(scale, 1820, 6540, 540, 212, 11.62, 26.45),
    month: makeCostAgg(scale, 4320, 16650, 1490, 675, 38.9, 85.1),
    d7: makeCostAgg(scale, 1950, 7120, 610, 238, 12.85, 28.9),
    d30: makeCostAgg(scale, 4680, 17800, 1580, 718, 41.2, 91.3),
    daily_14d,
    by_model_week,
    by_model_month,
    by_account_month,
    by_plan_month,
    accounts_quota: buildDemoPlanSummary(),
    filter: {
      account_id: cleanAid,
      plan_tier: cleanTier,
    },
    quota_groups: [
      {
        name: "AGY 主配额池（演示）",
        buckets: [
          { name: "5 小时滚动窗口", window: "5h", remaining_pct: 84, reset_countdown: "2h 18m 后重置" },
          { name: "7 天周配额窗口", window: "7d", remaining_pct: 71, reset_countdown: "3d 14h 后重置" },
        ],
      },
      {
        name: "外部模型中转网关额度",
        buckets: [
          { name: "OpenRouter 月度预算", window: "30d", remaining_pct: 76, reset_countdown: "12d 后重置" },
          { name: "CPA 并发推理槽位", window: "1h", remaining_pct: 92, reset_countdown: "38m 后重置" },
        ],
      },
    ],
  };
}

export async function fetchBrowserStatus(): Promise<BrowserStatusResponse> {
  await delay(25);
  requireAuth();
  return getDemoBrowserStatus();
}

export async function fetchSessions(params?: {
  limit?: number;
  bot?: string;
  source?: string;
  q?: string;
}): Promise<SessionsResponse> {
  await delay(30);
  requireAuth();
  let items = [...demoSessions];
  if (params?.bot) {
    items = items.filter((s) => s.bot === params.bot);
  }
  if (params?.source && params.source !== "all") {
    items = items.filter((s) => s.source === params.source);
  }
  if (params?.q && params.q.trim()) {
    const q = params.q.trim().toLowerCase();
    items = items.filter(
      (s) => s.title.toLowerCase().includes(q) || s.preview.toLowerCase().includes(q),
    );
  }
  const lim = params?.limit && params.limit > 0 ? params.limit : 100;
  return {
    ok: true,
    total: items.length,
    sessions: items.slice(0, lim).map((s) => ({ ...s })),
  };
}

export async function fetchSessionMessages(
  cid: string,
  _params?: { limit?: number; before?: number | null },
): Promise<SessionMessagesResponse> {
  await delay(25);
  requireAuth();
  const list = demoSessionMessages[cid] || [];
  return {
    ok: true,
    cid,
    messages: list.map((m) => ({ ...m })),
    has_more: false,
    next_before: null,
    total_returned: list.length,
  };
}

export async function fetchActiveSessionTurn(
  cid: string,
  bot?: string,
): Promise<ActiveSessionTurnResponse> {
  await delay(20);
  requireAuth();
  return {
    ok: true,
    active: false,
    cid,
    bot: bot || "@example_main_bot",
  };
}

export async function fetchModels(bot?: string): Promise<ModelsResponse> {
  await delay(25);
  requireAuth();
  const target = demoBots.find((b) => b.handle === bot) || demoBots[0];
  return {
    ok: true,
    bot: target.handle,
    active_model: target.active_model,
    effective_model: target.effective_model,
    model_mode: target.model_mode,
    default_effort: target.default_effort || "high",
    default_project: target.default_project,
    efforts: ["low", "medium", "high"],
    models: buildAllModelOptions(),
    projects: DEMO_PROJECT_OPTIONS.map((p) => ({ ...p })),
    ipc_online: true,
  };
}

const uploadedAttachmentMap = new Map<string, ChatAttachmentItem>();

export async function uploadChatAttachment(file: File): Promise<UploadAttachmentResponse> {
  await delay(60);
  requireAuth();
  const id = nextDemoId("att");
  const isImage = file.type.startsWith("image/") && file.type !== "image/svg+xml";
  const previewUrl = isImage ? DEMO_PREVIEW_SVG : "";
  const kind = isImage
    ? "image"
    : file.name.toLowerCase().endsWith(".pdf")
      ? "pdf"
      : /\.(py|ts|tsx|js|json|sh|sql)$/.test(file.name.toLowerCase())
        ? "code"
        : "document";
  const item: ChatAttachmentItem = {
    id,
    name: file.name || "demo-attachment.txt",
    kind,
    mime: file.type || "application/octet-stream",
    size: file.size || 512,
    size_label: file.size >= 1024 ? `${(file.size / 1024).toFixed(1)} KB` : `${file.size || 512} B`,
    preview_url: previewUrl,
  };
  uploadedAttachmentMap.set(id, item);
  return { ok: true, attachment: item };
}

export async function sendChatTurn(payload: ChatSendPayload): Promise<ChatSendResponse> {
  await delay(40);
  requireAuth();
  const bot = payload.bot || "@example_main_bot";
  const project = payload.project || "agy-studio-demo";
  const isNewSession = !payload.cid;
  const cid = payload.cid || nextDemoId("conv");
  const turnId = nextDemoId("turn");
  const atts: ChatAttachmentItem[] = (payload.attachments || [])
    .map((id) => uploadedAttachmentMap.get(id))
    .filter((x): x is ChatAttachmentItem => Boolean(x));

  const userMsg: ChatMessageItem = {
    id: nextDemoId("msg"),
    role: "user",
    content: payload.prompt,
    attachments: atts.length > 0 ? atts : undefined,
    context_files: payload.context_files?.length ? [...payload.context_files] : undefined,
    created_at: isoAgo(0),
    execution_mode: payload.execution_mode,
  };
  if (!demoSessionMessages[cid]) {
    demoSessionMessages[cid] = [];
  }
  demoSessionMessages[cid].push(userMsg);

  const existingSession = demoSessions.find((s) => s.cid === cid);
  if (existingSession) {
    existingSession.updated_at = isoAgo(0);
    existingSession.preview = payload.prompt.slice(0, 64);
  } else {
    demoSessions = [
      {
        cid,
        title: payload.prompt.slice(0, 36) || "新演示会话",
        preview: payload.prompt.slice(0, 64),
        updated_at: isoAgo(0),
        project_id: project,
        source: "web",
        bot,
        busy: false,
      },
      ...demoSessions,
    ];
  }

  registerDemoTurn({
    turnId,
    cid,
    isNewSession,
    bot,
    prompt: payload.prompt,
    project,
    model: payload.model || "gw:openrouter-demo:claude-sonnet-4",
    attachments: atts,
    contextFiles: payload.context_files ? [...payload.context_files] : [],
    aborted: false,
    abortListeners: new Set(),
    onComplete: (assistantMsg, resolvedCid) => {
      if (!demoSessionMessages[resolvedCid]) {
        demoSessionMessages[resolvedCid] = [];
      }
      demoSessionMessages[resolvedCid].push(assistantMsg);
      const sess = demoSessions.find((s) => s.cid === resolvedCid);
      if (sess) {
        sess.updated_at = isoAgo(0);
        sess.preview = assistantMsg.content.replace(/\s+/g, " ").slice(0, 72);
      }
      emitDemoEvent("session_updated", {
        cid: resolvedCid,
        bot,
        source: "web",
        status: "done",
        busy: false,
        updated_at: nowSec(),
      });
    },
  });

  return {
    ok: true,
    turn_id: turnId,
    bot,
    cid: payload.cid || null,
    status: "running",
    display_prompt: payload.prompt,
    attachments: atts.length > 0 ? atts : undefined,
    context_files: payload.context_files,
    execution_mode: payload.execution_mode || "queue",
    interrupted_turn_id: null,
  };
}

export async function abortChatTurn(turnId: string, bot?: string): Promise<ChatAbortResponse> {
  await delay(25);
  requireAuth();
  const aborted = abortDemoTurn(turnId);
  return {
    ok: true,
    turn_id: turnId,
    aborted,
    bot: bot || "@example_main_bot",
  };
}

export async function fetchProjects(): Promise<ProjectsResponse> {
  await delay(25);
  requireAuth();
  return { ok: true, projects: DEMO_PROJECTS.map((p) => ({ ...p })) };
}

export async function fetchFileTree(params: {
  project_id: string;
  dir?: string;
  depth?: number;
}): Promise<FileTreeResponse> {
  await delay(25);
  requireAuth();
  const rootEntries = DEMO_FILE_TREES[params.project_id] || DEMO_FILE_TREES["agy-studio-demo"];
  if (params.dir) {
    const dirNode = rootEntries.find((n) => n.type === "dir" && n.path === params.dir);
    const children = dirNode?.children || [];
    return {
      ok: true,
      project_id: params.project_id,
      dir: params.dir,
      truncated: false,
      total: children.length,
      entries: children.map((c) => ({ ...c })),
    };
  }
  return {
    ok: true,
    project_id: params.project_id,
    dir: "",
    truncated: false,
    total: rootEntries.length,
    entries: rootEntries.map((n) => ({
      ...n,
      children: n.children ? n.children.map((c) => ({ ...c })) : undefined,
    })),
  };
}

export async function fetchFileContent(
  projectId: string,
  path: string,
): Promise<FileContentResponse> {
  await delay(25);
  requireAuth();
  const file = DEMO_FILE_CONTENTS[path] || {
    language: "text",
    content: `# ${path}\n\n演示环境虚拟文件内容（${projectId}）。`,
  };
  const lines = file.content.split("\n").length;
  return {
    ok: true,
    project_id: projectId,
    path,
    is_binary: false,
    size: file.content.length,
    language: file.language,
    content: file.content,
    lines,
    truncated: false,
  };
}

export async function fetchFileDiff(params: {
  project_id: string;
  scope?: "all" | "staged" | "unstaged";
  path?: string;
}): Promise<FileDiffResponse> {
  await delay(30);
  requireAuth();
  const scope = params.scope || "all";
  const allEntries = Object.entries(DEMO_DIFF_BLOCKS).filter(([p, info]) => {
    if (params.path && p !== params.path) return false;
    if (scope !== "all" && info.staged !== scope) return false;
    return true;
  });
  return {
    ok: true,
    project_id: params.project_id,
    is_git: true,
    scope,
    path: params.path || "",
    files: allEntries.map(([p, info]) => ({
      path: p,
      status: info.status,
      staged: info.staged,
    })),
    diff: allEntries.map(([, info]) => info.diff).join("\n\n"),
    truncated: false,
  };
}

export async function fetchUndoCheckpoints(params?: {
  bot?: string;
  cid?: string | null;
  project_id?: string;
}): Promise<UndoCheckpointsResponse> {
  await delay(25);
  requireAuth();
  refreshCheckpointTopFlags();
  return {
    ok: true,
    ipc_online: true,
    bot: params?.bot || "@example_main_bot",
    undo_stack: demoUndoStack.map((u) => ({ ...u, changes: [...u.changes] })),
    redo_stack: demoRedoStack.map((r) => ({ ...r, changes: [...r.changes] })),
  };
}

export async function applyUndoCheckpoint(payload: {
  entry_id: string;
  bot?: string;
  cid?: string | null;
  project_id?: string;
  force?: boolean;
}): Promise<UndoActionResponse> {
  await delay(50);
  requireAuth();
  const idx = demoUndoStack.findIndex((u) => u.entry_id === payload.entry_id);
  if (idx < 0) {
    throw new StudioApiError(`未找到检查点 ${payload.entry_id}`, 404, "studio_api");
  }
  const [item] = demoUndoStack.splice(idx, 1);
  demoRedoStack.unshift(item);
  refreshCheckpointTopFlags();
  return {
    ok: true,
    action: "undo",
    bot: payload.bot || "@example_main_bot",
    entry_id: item.entry_id,
    cid: item.cid,
    project_id: item.project_id,
    applied: [...item.changes],
    remaining_undo: demoUndoStack.length,
    remaining_redo: demoRedoStack.length,
  };
}

export async function redoUndoCheckpoint(payload: {
  entry_id: string;
  bot?: string;
  cid?: string | null;
  project_id?: string;
  force?: boolean;
}): Promise<UndoActionResponse> {
  await delay(50);
  requireAuth();
  const idx = demoRedoStack.findIndex((r) => r.entry_id === payload.entry_id);
  if (idx < 0) {
    throw new StudioApiError(`未找到重做检查点 ${payload.entry_id}`, 404, "studio_api");
  }
  const [item] = demoRedoStack.splice(idx, 1);
  demoUndoStack.unshift(item);
  refreshCheckpointTopFlags();
  return {
    ok: true,
    action: "redo",
    bot: payload.bot || "@example_main_bot",
    entry_id: item.entry_id,
    cid: item.cid,
    project_id: item.project_id,
    applied: [...item.changes],
    remaining_undo: demoUndoStack.length,
    remaining_redo: demoRedoStack.length,
  };
}

export async function fetchBotConfig(handle: string): Promise<BotConfigResponse> {
  await delay(30);
  requireAuth();
  const bot = demoBots.find((b) => b.handle === handle) || demoBots[0];
  const extras = demoBotExtras[bot.handle] || { skills: [], mcp_servers: [] };
  const mode: "default" | "follow" | "custom" =
    bot.model_mode === "follow" || bot.model_mode === "custom" ? bot.model_mode : "default";
  return {
    ok: true,
    ipc_online: true,
    can_edit: true,
    handle: bot.handle,
    display_name: bot.display_name,
    role: bot.role,
    specialty: bot.specialty,
    model_mode: mode,
    configured_model: bot.active_model,
    effective_model: bot.effective_model,
    dm_model: "gemini-2.5-pro",
    env_default_model: "gemini-2.5-pro",
    default_effort: bot.default_effort || "high",
    default_project: bot.default_project,
    efforts: ["low", "medium", "high"],
    models: buildAllModelOptions(),
    projects: DEMO_PROJECT_OPTIONS.map((p) => ({ ...p })),
    skills: extras.skills,
    mcp_servers: extras.mcp_servers,
    busy: bot.busy,
    queue_depth: bot.queue_depth,
  };
}

export async function updateBotConfig(
  handle: string,
  payload: BotConfigPatchPayload,
): Promise<BotConfigResponse> {
  await delay(50);
  requireAuth();
  const bot = demoBots.find((b) => b.handle === handle);
  if (!bot) {
    throw new StudioApiError(`未找到 Bot ${handle}`, 404, "studio_api");
  }
  if (payload.model_mode) {
    bot.model_mode = payload.model_mode;
  }
  if (payload.model_mode === "custom" && payload.model) {
    bot.active_model = payload.model;
    bot.effective_model = payload.model;
  } else if (payload.model_mode === "default" || payload.model_mode === "follow") {
    bot.active_model = "gemini-2.5-pro";
    bot.effective_model = "gemini-2.5-pro";
  }
  if (payload.default_effort) {
    bot.default_effort = payload.default_effort;
  }
  if (payload.default_project) {
    bot.default_project = payload.default_project;
  }
  bot.last_seen = nowSec();
  emitDemoEvent("bots_updated", { handle, ts: nowSec() });
  return fetchBotConfig(handle);
}

export async function reloadBot(handle: string): Promise<BotReloadResponse> {
  await delay(60);
  requireAuth();
  emitDemoEvent("bots_updated", { handle, ts: nowSec() });
  return {
    ok: true,
    bot: handle,
    scheduled: true,
    self_check: "ok (demo zero-downtime sentinel)",
    cooldown_sec: 15,
  };
}

const demoBotProfiles: Record<
  string,
  {
    rev: number;
    docs: Record<BotProfileDocName, string>;
    skills_policy: { mode: "allowlist" | "all"; enabled_catalog_skills: string[] };
    own_skills: Record<string, string>;
  }
> = {};

function ensureDemoBotProfile(handle: string) {
  const clean = handle.replace(/^@/, "").toLowerCase();
  if (!demoBotProfiles[clean]) {
    const bot = demoBots.find((b) => b.handle.replace(/^@/, "").toLowerCase() === clean);
    const isCoord = bot?.role === "coordinator";
    demoBotProfiles[clean] = {
      rev: 1,
      docs: {
        "SOUL.md": `# ${bot?.display_name || clean}\n\n演示 Bot 独立人格配置。`,
        "RULES.md": "- 优先执行只读检查与单元测试。\n- 保持输出简洁结构化。",
        "MEMORY.md": "- 演示长期记忆笔记（独立隔离）。",
      },
      skills_policy: {
        mode: isCoord ? "all" : "allowlist",
        enabled_catalog_skills: ["dev-qa-contract"],
      },
      own_skills: {
        "demo-own-workflow":
          "---\nname: demo-own-workflow\ndescription: Demo bot private workflow skill\n---\n\n# Demo Own Workflow\n",
      },
    };
  }
  return demoBotProfiles[clean];
}

export async function fetchBotProfile(handle: string): Promise<BotProfileResponse> {
  await delay(30);
  const sess = requireAuth();
  const bot = demoBots.find((b) => b.handle === handle) || demoBots[0];
  const clean = bot.handle.replace(/^@/, "").toLowerCase();
  const st = ensureDemoBotProfile(clean);
  const isCoord = bot.role === "coordinator";
  const enc = new TextEncoder();
  const ownSkills = Object.entries(st.own_skills).map(([slug, content]) => ({
    slug,
    name: slug,
    scope: "bot",
    owner: clean,
    description: "Bot 自有独立 Skill",
    size_bytes: enc.encode(content).length,
    updated_at: nowSec(),
  }));
  const catalogSkills = ["dev-qa-contract", "live-browser", "mem-search"].map((slug) => ({
    slug,
    name: slug,
    scope: "catalog",
    description: `共享目录技能 (${slug})`,
    size_bytes: 512,
    updated_at: nowSec(),
    enabled:
      isCoord ||
      st.skills_policy.mode === "all" ||
      st.skills_policy.enabled_catalog_skills.includes(slug),
  }));
  const teamSkills = isCoord
    ? demoBots
        .filter((b) => b.handle !== bot.handle)
        .map((b) => {
          const oh = b.handle.replace(/^@/, "").toLowerCase();
          return {
            slug: "demo-own-workflow",
            name: "demo-own-workflow",
            scope: "team_bot",
            owner: oh,
            description: `${b.display_name} 专属技能`,
            size_bytes: 120,
            updated_at: nowSec(),
          };
        })
    : [];
  return {
    ok: true,
    ipc_online: true,
    can_edit: sess.role === "admin",
    handle: clean,
    role: bot.role,
    rev: st.rev,
    max_doc_bytes: 24 * 1024,
    specialty: bot.specialty,
    memory_project: `bot-${clean}`,
    memory_scope: isCoord ? "coordinator_all" : "isolated",
    updated_at: nowSec(),
    updated_by: sess.username || "demo-admin",
    docs: { ...st.docs },
    doc_bytes: {
      "SOUL.md": enc.encode(st.docs["SOUL.md"]).length,
      "RULES.md": enc.encode(st.docs["RULES.md"]).length,
      "MEMORY.md": enc.encode(st.docs["MEMORY.md"]).length,
    },
    skills_policy: {
      mode: st.skills_policy.mode,
      enabled_catalog_skills: [...st.skills_policy.enabled_catalog_skills],
    },
    own_skills: ownSkills,
    catalog_skills: catalogSkills,
    team_skills: teamSkills,
    effective_skills: [...ownSkills, ...teamSkills, ...catalogSkills.filter((c) => c.enabled)],
    memory_stats: {
      memory_project: `bot-${clean}`,
      memory_scope: isCoord ? "coordinator_all" : "isolated",
      observations_count: 12,
      summaries_count: 3,
      instincts_count: 2,
      active_instincts_preview: "- **[workflow]** Always run verify_gate before release.",
      ...(isCoord
        ? {
            team_memory: demoBots.map((b) => {
              const h = b.handle.replace(/^@/, "").toLowerCase();
              return {
                handle: h,
                project: `bot-${h}`,
                observations_count: 12,
                summaries_count: 3,
                instincts_count: 2,
              };
            }),
            total_observations: demoBots.length * 12,
            total_summaries: demoBots.length * 3,
            total_instincts: demoBots.length * 2,
          }
        : {}),
    },
  };
}

export async function updateBotProfile(
  handle: string,
  payload: BotProfileUpdatePayload,
): Promise<BotProfileResponse> {
  await delay(40);
  const sess = requireAuth();
  if (sess.role !== "admin") {
    throw new StudioApiError("只读权限禁止修改 Profile", 403, "studio_api");
  }
  const clean = handle.replace(/^@/, "").toLowerCase();
  const st = ensureDemoBotProfile(clean);
  if (payload.expected_rev !== st.rev) {
    throw new StudioApiError("版本冲突", 409, "upstream", undefined, undefined, "rev_conflict", undefined, {
      current_rev: st.rev,
    });
  }
  if (payload.doc && payload.content !== undefined) {
    st.docs[payload.doc] = payload.content;
  }
  if (payload.docs) {
    for (const [k, v] of Object.entries(payload.docs)) {
      if (v !== undefined) st.docs[k as BotProfileDocName] = v;
    }
  }
  if (payload.skills_policy) {
    st.skills_policy = {
      mode: payload.skills_policy.mode,
      enabled_catalog_skills: [...payload.skills_policy.enabled_catalog_skills],
    };
  }
  st.rev += 1;
  emitDemoEvent("bots_updated", { handle, action: "profile_updated", ts: nowSec() });
  return fetchBotProfile(handle);
}

export async function fetchBotSkill(handle: string, slug: string): Promise<BotSkillDetailResponse> {
  await delay(25);
  const sess = requireAuth();
  const clean = handle.replace(/^@/, "").toLowerCase();
  const st = ensureDemoBotProfile(clean);
  const content = st.own_skills[slug];
  if (content === undefined) {
    throw new StudioApiError(`未找到 Skill ${slug}`, 404, "upstream");
  }
  return {
    ok: true,
    handle: clean,
    slug,
    rev: st.rev,
    name: slug,
    description: "Bot 自有 Skill",
    content,
    size_bytes: new TextEncoder().encode(content).length,
    max_doc_bytes: 24 * 1024,
    can_edit: sess.role === "admin",
  };
}

export async function saveBotSkill(
  handle: string,
  slug: string,
  payload: BotSkillPutPayload,
): Promise<BotSkillDetailResponse> {
  await delay(40);
  const sess = requireAuth();
  if (sess.role !== "admin") {
    throw new StudioApiError("只读权限禁止编辑 Skill", 403, "studio_api");
  }
  const clean = handle.replace(/^@/, "").toLowerCase();
  const st = ensureDemoBotProfile(clean);
  if (payload.expected_rev !== st.rev) {
    throw new StudioApiError("版本冲突", 409, "upstream", undefined, undefined, "rev_conflict", undefined, {
      current_rev: st.rev,
    });
  }
  st.own_skills[slug] = payload.content;
  st.rev += 1;
  emitDemoEvent("bots_updated", { handle, action: "skill_updated", slug, ts: nowSec() });
  return fetchBotSkill(handle, slug);
}

export async function deleteBotSkill(
  handle: string,
  slug: string,
  expectedRev: number,
): Promise<BotSkillDeleteResponse> {
  await delay(40);
  const sess = requireAuth();
  if (sess.role !== "admin") {
    throw new StudioApiError("只读权限禁止删除 Skill", 403, "studio_api");
  }
  const clean = handle.replace(/^@/, "").toLowerCase();
  const st = ensureDemoBotProfile(clean);
  if (expectedRev !== st.rev) {
    throw new StudioApiError("版本冲突", 409, "upstream", undefined, undefined, "rev_conflict", undefined, {
      current_rev: st.rev,
    });
  }
  delete st.own_skills[slug];
  st.rev += 1;
  emitDemoEvent("bots_updated", { handle, action: "skill_deleted", slug, ts: nowSec() });
  return { ok: true, deleted: true, handle: clean, slug, rev: st.rev };
}

export async function fetchRooms(): Promise<RoomsResponse> {
  await delay(25);
  requireAuth();
  return {
    ok: true,
    total: demoRooms.length,
    max_rooms: 12,
    rooms: demoRooms.map((r) => ({ ...r })),
  };
}

export async function createRoom(payload: {
  room_id: string;
  title?: string;
  topic?: string;
}): Promise<RoomCreateResponse> {
  await delay(45);
  requireAuth();
  const rid = payload.room_id.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-") || nextDemoId("room");
  if (demoRooms.some((r) => r.room_id === rid)) {
    throw new StudioApiError(`房间 ${rid} 已存在`, 409, "studio_api");
  }
  const ts = nowSec();
  const room: RoomSummary = {
    room_id: rid,
    title: payload.title?.trim() || rid,
    topic: payload.topic?.trim() || "多 Bot 演示协作房间",
    mode: "web_room",
    mirror_bound: false,
    default_bot: "@example_main_bot",
    created_at: ts,
    updated_at: ts,
    last_seq: 0,
    message_count: 0,
  };
  demoRooms = [...demoRooms, room];
  demoRoomMessages[rid] = [];
  return { ok: true, room: { ...room } };
}

export async function fetchRoomMessages(
  roomId: string,
  params?: { after_seq?: number; limit?: number },
): Promise<RoomMessagesResponse> {
  await delay(25);
  requireAuth();
  const room = demoRooms.find((r) => r.room_id === roomId) || demoRooms[0];
  const all = demoRoomMessages[room.room_id] || [];
  const afterSeq = params?.after_seq || 0;
  const filtered = afterSeq > 0 ? all.filter((m) => m.seq > afterSeq) : all;
  const lim = params?.limit && params.limit > 0 ? params.limit : 100;
  const sliced = filtered.slice(-lim);
  return {
    ok: true,
    room: { ...room },
    room_id: room.room_id,
    latest_seq: all.length > 0 ? all[all.length - 1].seq : 0,
    total: all.length,
    messages: sliced.map((m) => ({ ...m })),
  };
}

export async function fetchRoomActivity(roomId: string): Promise<RoomActivityResponse> {
  await delay(25);
  requireAuth();
  const ts = nowSec();
  const active_bots: RoomActivityBotItem[] = demoBots.map((b) => ({
    handle: b.handle,
    display_name: b.display_name,
    role: b.role,
    state: b.busy ? "running" : "idle",
    stage_label: b.busy ? "执行中 · Canvas 回归联调" : "待命就绪",
    current_job_id: b.current_job,
    current_job_label: b.current_job ? "实时浏览器 Canvas 联调" : undefined,
    queue_depth: b.queue_depth,
    started_at: b.busy ? ts - 240 : null,
    elapsed_s: b.busy ? 240 : 0,
  }));
  const recent_jobs: RoomActivityJobItem[] = demoJobs.slice(0, 4).map((j) => ({
    job_id: j.job_id,
    group_id: j.group_id,
    bot: j.target_bot,
    from_bot: j.from_bot,
    label: j.label,
    status: j.status === "error" ? "failed" : j.status,
    progress: j.progress,
    created_at: j.created_at,
    started_at: j.started_at,
    finished_at: j.finished_at,
    duration_s: j.duration_sec,
  }));
  return {
    ok: true,
    room_id: roomId,
    mode: roomId === "lobby" ? "tg_mirror" : "web_room",
    mirror_bound: roomId === "lobby",
    server_ts: ts,
    active_bots,
    recent_jobs,
    recent_dispatch: {
      phase: "done",
      target_bots: ["@your_bot_1", "@your_bot_2"],
      dispatched_at: ts - 180,
      stage_label: "已完成多 Bot 协同交付",
    },
  };
}

export async function sendRoomMessage(
  roomId: string,
  payload: {
    content: string;
    project?: string;
    attachments?: string[];
    context_files?: string[];
    execution_mode?: ExecutionMode;
  },
): Promise<RoomSendResponse> {
  await delay(45);
  const me = requireAuth();
  const room = demoRooms.find((r) => r.room_id === roomId) || demoRooms[0];
  const list = (demoRoomMessages[room.room_id] = demoRoomMessages[room.room_id] || []);
  const seq = (list[list.length - 1]?.seq || 0) + 1;
  const ts = nowSec();
  const atts = (payload.attachments || [])
    .map((id) => uploadedAttachmentMap.get(id))
    .filter((x): x is ChatAttachmentItem => Boolean(x));

  const userMsg: RoomMessageItem = {
    seq,
    msg_id: nextDemoId("rm"),
    room_id: room.room_id,
    ts,
    sender_type: "human",
    sender: me.username || "demo-admin",
    source: "web",
    content: payload.content,
    attachments: atts.length > 0 ? atts : undefined,
    context_files: payload.context_files,
    mentions: ["@example_main_bot"],
    chain_id: nextDemoId("chain"),
    hop: 0,
    status: "done",
    blocked_reason: "",
  };
  list.push(userMsg);
  room.last_seq = seq;
  room.message_count = list.length;
  room.updated_at = ts;

  emitDemoEvent("room_typing", {
    room_id: room.room_id,
    bot: "@example_main_bot",
    typing: true,
    ts,
  });

  window.setTimeout(() => {
    const replySeq = (list[list.length - 1]?.seq || 0) + 1;
    const replyTs = nowSec();
    const replyText =
      `已收到指令：「${payload.content.slice(0, 60)}」。\n\n` +
      `本演示环境已通过内存事件总线完成调度编排：\n` +
      `- 已同步给 \`@your_bot_1\`（开发）与 \`@your_bot_2\`（只读 QA）\n` +
      `- 无任何真实后端调用，所有状态均在浏览器本地安全闭环。`;
    const replyMsg: RoomMessageItem = {
      seq: replySeq,
      msg_id: nextDemoId("rm"),
      room_id: room.room_id,
      ts: replyTs,
      sender_type: "bot",
      sender: "@example_main_bot",
      sender_role: "coordinator",
      source: "web",
      stage_tag: "reply",
      content: replyText,
      mentions: ["@your_bot_1", "@your_bot_2"],
      chain_id: userMsg.chain_id,
      hop: 1,
      status: "done",
      blocked_reason: "",
    };
    list.push(replyMsg);
    room.last_seq = replySeq;
    room.message_count = list.length;
    room.updated_at = replyTs;
    emitDemoEvent("room_typing", {
      room_id: room.room_id,
      bot: "@example_main_bot",
      typing: false,
      ts: replyTs,
    });
    emitDemoEvent("room_message", {
      seq: replyMsg.seq,
      msg_id: replyMsg.msg_id,
      room_id: replyMsg.room_id,
      ts: replyMsg.ts,
      sender_type: replyMsg.sender_type,
      sender: replyMsg.sender,
      sender_role: replyMsg.sender_role,
      source: replyMsg.source,
      stage_tag: replyMsg.stage_tag,
      text: replyMsg.content,
      mentions: replyMsg.mentions,
      chain_id: replyMsg.chain_id,
      hop: replyMsg.hop,
      status: replyMsg.status,
      blocked_reason: "",
    });
  }, 450);

  return {
    ok: true,
    execution_mode: payload.execution_mode || "queue",
    message: { ...userMsg },
    dispatched_bots: ["@example_main_bot"],
    blocked_bots: [],
    blocked_reason: "",
  };
}

export async function fetchAttention(
  status?: "all" | "pending" | "resolved",
): Promise<AttentionResponse> {
  await delay(25);
  requireAuth();
  const pendingCount = pendingAttentionCountNow();
  let items = [...demoAttentionItems];
  if (status === "pending") {
    items = items.filter((it) => it.status === "pending");
  } else if (status === "resolved") {
    items = items.filter((it) => it.status !== "pending");
  }
  return {
    ok: true,
    total: items.length,
    pending_count: pendingCount,
    has_browser_takeover: items.some((it) => it.kind === "browser_takeover" && it.status === "pending"),
    items: items.map((it) => ({ ...it })),
  };
}

export async function decideAttentionItem(
  itemId: string,
  payload: { decision: "approved" | "rejected"; note?: string },
): Promise<AttentionDecideResponse> {
  await delay(50);
  const me = requireAuth();
  const item = demoAttentionItems.find((it) => it.item_id === itemId);
  if (!item) {
    throw new StudioApiError(`未找到审批项 ${itemId}`, 404, "studio_api");
  }
  if (item.status !== "pending") {
    throw new StudioApiError("该审批项已处理或已过期", 409, "studio_api");
  }
  item.status = payload.decision;
  item.decided_at = nowSec();
  item.decided_by = me.username || "demo-admin";
  item.decision_note = payload.note || "";
  emitDemoEvent("attention_updated", {
    item_id: itemId,
    decision: payload.decision,
    pending_count: pendingAttentionCountNow(),
    ts: nowSec(),
  });
  return {
    ok: true,
    item: { ...item },
    decision: payload.decision,
    notify: {
      notified: true,
      bot: item.bot,
    },
  };
}

export async function fetchOpenBaoConfig(): Promise<OpenBaoConfigResponse> {
  await delay(30);
  requireAuth();
  return { ...demoOpenBao };
}

export async function updateOpenBaoConfig(
  payload: OpenBaoConfigUpdatePayload,
): Promise<OpenBaoConfigResponse> {
  await delay(60);
  requireAuth();
  if (payload.reset_to_host_auto) {
    demoOpenBao = {
      ...demoOpenBao,
      enabled: true,
      source: "host_auto",
      addr: "https://vault.example.com",
      kv_mount: "secret",
      gateway_path_prefix: "studio/demo/gateways",
      auth_mode: "host_card",
      auth_label: "demo-slot",
      credential_configured: true,
      updated_at: nowSec(),
    };
    return { ...demoOpenBao };
  }
  demoOpenBao = {
    ...demoOpenBao,
    source: "custom",
    enabled: payload.enabled !== undefined ? payload.enabled : demoOpenBao.enabled,
    addr: payload.addr !== undefined ? payload.addr : demoOpenBao.addr,
    kv_mount: payload.kv_mount !== undefined ? payload.kv_mount : demoOpenBao.kv_mount,
    gateway_path_prefix:
      payload.gateway_path_prefix !== undefined
        ? payload.gateway_path_prefix
        : demoOpenBao.gateway_path_prefix,
    auth_mode: payload.auth_mode !== undefined ? payload.auth_mode : demoOpenBao.auth_mode,
    auth_label: payload.auth_label !== undefined ? payload.auth_label : demoOpenBao.auth_label,
    credential_configured: payload.clear_credentials ? false : true,
    updated_at: nowSec(),
  };
  return { ...demoOpenBao };
}

export async function testOpenBaoConnection(
  payload?: OpenBaoTestPayload,
): Promise<OpenBaoTestResponse> {
  await delay(90);
  requireAuth();
  const targetAddr = payload?.addr || demoOpenBao.addr;
  return {
    ok: true,
    reachable: true,
    initialized: true,
    sealed: false,
    latency_ms: 18,
    auth_verified: true,
    message: `演示集群连通性正常（${targetAddr} · 已解封 · KV v2 可读写）`,
  };
}

export async function fetchGateways(): Promise<GatewaysListResponse> {
  await delay(30);
  requireAuth();
  const openbaoReady = Boolean(demoOpenBao.enabled && demoOpenBao.credential_configured);
  return {
    ok: true,
    can_edit: true,
    total: demoGateways.length,
    gateways: demoGateways.map((g) => ({
      ...g,
      include_models: [...g.include_models],
      exclude_models: [...g.exclude_models],
      models: [...g.models],
      extra_headers: { ...g.extra_headers },
      secret_ref_summary: g.secret_ref_summary ? { ...g.secret_ref_summary } : null,
    })),
    secret_store: {
      active_backend: openbaoReady ? "openbao" : "local_0600",
      openbao_ready: openbaoReady,
      fallback_mode: "local_0600",
      security_card_status: "reserved",
      backends: [
        { backend_id: "openbao", priority: 1, status: openbaoReady ? "ready" : "disabled" },
        { backend_id: "security_card", priority: 2, status: "reserved" },
        { backend_id: "local_0600", priority: 3, status: "ready" },
      ],
    },
  };
}

function buildGatewayItem(id: string, payload: GatewayMutationPayload, prev?: GatewayItem): GatewayItem {
  const credKind = payload.credential_kind || prev?.credential_kind || "api_key";
  const backend =
    credKind === "none"
      ? "none"
      : credKind === "api_key_env"
        ? "env"
        : payload.preferred_secret_backend || (demoOpenBao.enabled ? "openbao" : "local_0600");
  return {
    id,
    name: payload.name || prev?.name || id,
    base_url: payload.base_url || prev?.base_url || "https://api.example.com/v1",
    dialect: payload.dialect || prev?.dialect || "openai_strict",
    enabled: payload.enabled !== undefined ? payload.enabled : (prev?.enabled ?? true),
    credential_kind: credKind,
    secret_backend: backend,
    has_api_key: payload.clear_api_key ? false : credKind !== "none",
    api_key_hint: credKind === "none" ? "" : "vault-managed",
    api_key_env: payload.api_key_env !== undefined ? payload.api_key_env : (prev?.api_key_env || ""),
    read_only_cmd: false,
    secret_ref_summary:
      backend === "openbao"
        ? {
            backend: "openbao",
            kv_mount: demoOpenBao.kv_mount,
            path: `${demoOpenBao.gateway_path_prefix}/${id}`,
            version: (prev?.secret_ref_summary?.version || 0) + 1,
            status: "active",
          }
        : { backend, status: "active" },
    include_models: payload.include_models || prev?.include_models || [],
    exclude_models: payload.exclude_models || prev?.exclude_models || [],
    models: payload.models || prev?.models || ["gpt-4.1", "claude-sonnet-4"],
    supports_reasoning_effort:
      payload.supports_reasoning_effort ?? prev?.supports_reasoning_effort ?? true,
    effort_mode: payload.effort_mode || prev?.effort_mode || "body",
    flatten_system_content: payload.flatten_system_content ?? prev?.flatten_system_content ?? false,
    strip_stream_options: payload.strip_stream_options ?? prev?.strip_stream_options ?? false,
    max_tokens_field: payload.max_tokens_field || prev?.max_tokens_field || "max_tokens",
    max_tokens_cap:
      payload.max_tokens_cap !== undefined ? payload.max_tokens_cap : (prev?.max_tokens_cap ?? null),
    adaptive_400_fallback: payload.adaptive_400_fallback ?? prev?.adaptive_400_fallback ?? true,
    timeout_s: payload.timeout_s ?? prev?.timeout_s ?? 120,
    extra_headers: payload.extra_headers || prev?.extra_headers || {},
    updated_at: nowSec(),
  };
}

export async function createGateway(
  payload: GatewayMutationPayload,
): Promise<GatewayMutationResponse> {
  await delay(60);
  requireAuth();
  const id = (payload.id || nextDemoId("gw")).trim();
  if (demoGateways.some((g) => g.id === id)) {
    throw new StudioApiError(`网关标识 ${id} 已存在`, 409, "studio_api");
  }
  const gw = buildGatewayItem(id, payload);
  demoGateways = [gw, ...demoGateways];
  emitDemoEvent("gateways_updated", { id, ts: nowSec() });
  return { ok: true, gateway: { ...gw }, secret_backend: gw.secret_backend, fallback_used: false };
}

export async function updateGateway(
  gatewayId: string,
  payload: GatewayMutationPayload,
): Promise<GatewayMutationResponse> {
  await delay(55);
  requireAuth();
  const idx = demoGateways.findIndex((g) => g.id === gatewayId);
  if (idx < 0) {
    throw new StudioApiError(`未找到网关 ${gatewayId}`, 404, "studio_api");
  }
  const gw = buildGatewayItem(gatewayId, payload, demoGateways[idx]);
  demoGateways[idx] = gw;
  emitDemoEvent("gateways_updated", { id: gatewayId, ts: nowSec() });
  return { ok: true, gateway: { ...gw }, secret_backend: gw.secret_backend, fallback_used: false };
}

export async function patchGateway(
  gatewayId: string,
  payload: GatewayMutationPayload,
): Promise<GatewayMutationResponse> {
  return updateGateway(gatewayId, payload);
}

export async function deleteGateway(gatewayId: string): Promise<GatewayDeleteResponse> {
  await delay(45);
  requireAuth();
  demoGateways = demoGateways.filter((g) => g.id !== gatewayId);
  emitDemoEvent("gateways_updated", { id: gatewayId, ts: nowSec() });
  return { ok: true, deleted: true, id: gatewayId, secret_deleted: true };
}

function buildProbeResult(
  endpointUrl: string,
  baseModels: string[],
): GatewayProbeResponse {
  const discovered =
    baseModels.length > 0
      ? baseModels
      : ["claude-sonnet-4", "gemini-2.5-pro", "gpt-4.1", "o4-mini"];
  const cleanBase = endpointUrl.replace(/\/+$/, "");
  return {
    ok: true,
    reachable: true,
    http_status: 200,
    latency_ms: 42,
    endpoint: `${cleanBase}/models`,
    truncated: false,
    discovered_models: discovered,
    discovered_count: discovered.length,
    exposed_models: discovered,
    exposed_count: discovered.length,
    message: `演示探测成功：发现 ${discovered.length} 个兼容模型（同源凭据校验通过）`,
  };
}

export async function probeGatewayDraft(
  payload: GatewayProbePayload,
): Promise<GatewayProbeResponse> {
  await delay(90);
  requireAuth();
  return buildProbeResult(
    payload.base_url || "https://openrouter.example.com/api/v1",
    payload.models || ["claude-sonnet-4", "gpt-4.1", "deepseek-reasoner"],
  );
}

export async function probeGatewayById(
  gatewayId: string,
  payload?: GatewayProbePayload,
): Promise<GatewayProbeResponse> {
  await delay(90);
  requireAuth();
  const gw = demoGateways.find((g) => g.id === gatewayId);
  return buildProbeResult(
    payload?.base_url || gw?.base_url || "https://openrouter.example.com/api/v1",
    payload?.models?.length ? payload.models : gw?.models || [],
  );
}

export async function fetchWorkbenchState(): Promise<WorkbenchStateResponse> {
  await delay(20);
  requireAuth();
  return {
    ok: true,
    version: demoWorkbenchVersion,
    updated_at: nowSec(),
    state: {
      ...demoWorkbenchState,
      customProjects: [...demoWorkbenchState.customProjects],
      projectRenames: { ...demoWorkbenchState.projectRenames },
      hiddenProjectIds: [...demoWorkbenchState.hiddenProjectIds],
      hiddenSessionCids: [...demoWorkbenchState.hiddenSessionCids],
      pinnedSessionCids: [...demoWorkbenchState.pinnedSessionCids],
      archivedSessionCids: [...demoWorkbenchState.archivedSessionCids],
      unreadSessionCids: [...demoWorkbenchState.unreadSessionCids],
      sessionRenames: { ...demoWorkbenchState.sessionRenames },
    },
    can_edit: true,
  };
}

export async function updateWorkbenchState(
  payload: WorkbenchStateUpdatePayload,
): Promise<WorkbenchStateResponse> {
  await delay(25);
  requireAuth();
  demoWorkbenchVersion += 1;
  demoWorkbenchState = { ...payload.state };
  emitDemoEvent("workbench_state_updated", { version: demoWorkbenchVersion, ts: nowSec() });
  return fetchWorkbenchState();
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
