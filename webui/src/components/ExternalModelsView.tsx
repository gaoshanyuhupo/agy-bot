import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  Copy,
  CreditCard,
  Edit3,
  Eye,
  Filter,
  Globe,
  Info,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  Network,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Sliders,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { StudioApiError, fetchBots, fetchModels, fetchOpenBaoConfig } from "../api";
import type {
  BotRosterItem,
  ModelOption,
  NavTab,
  OpenBaoConfigResponse,
  StudioSession,
} from "../types";

interface ExternalModelsViewProps {
  session?: StudioSession;
  onNavigate?: (tab: NavTab) => void;
  onSessionRevoked?: (reason: string) => void;
}

type DialectId =
  | "new_api"
  | "cpa"
  | "openrouter"
  | "deepseek"
  | "zhipu"
  | "ark"
  | "litellm"
  | "openai_2api"
  | "openai_strict";

type EffortMode = "body" | "model_paren" | "none";
type MaxTokensField = "max_completion_tokens" | "max_tokens" | "omit";
type CredentialKind = "api_key" | "api_key_env" | "server_cmd_readonly";

interface DialectPreset {
  id: DialectId;
  label: string;
  shortLabel: string;
  tagline: string;
  placeholderUrl: string;
  sampleModels: string[];
  supports_reasoning_effort: boolean;
  effort_mode: EffortMode;
  flatten_system_content: boolean;
  strip_stream_options: boolean;
  max_tokens_field: MaxTokensField;
  max_tokens_cap: number | null;
  adaptive_400_fallback: boolean;
}

interface ExtraHeaderPair {
  key: string;
  value: string;
}

interface GatewayRecord {
  id: string;
  name: string;
  base_url: string;
  dialect: DialectId;
  enabled: boolean;
  source: "live" | "preview";
  credential_kind: CredentialKind;
  api_key_masked: string;
  api_key_env: string;
  include_models: string[];
  exclude_models: string[];
  models: string[];
  discovered_models: string[];
  supports_reasoning_effort: boolean;
  effort_mode: EffortMode;
  flatten_system_content: boolean;
  strip_stream_options: boolean;
  max_tokens_field: MaxTokensField;
  max_tokens_cap: number | null;
  adaptive_400_fallback: boolean;
  timeout_s: number;
  extra_headers: ExtraHeaderPair[];
  updated_at?: number;
}

interface ProbeResult {
  ok: boolean;
  latencyMs: number;
  discoveredCount: number;
  exposedCount: number;
  endpoint: string;
  summary: string;
  checkedAt: string;
}

const PREVIEW_STORAGE_KEY = "agy_studio_external_gateways_preview_v1";
const GW_ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;
const MODEL_PROVIDER_PREFIX_RE = /^\[([^\]]+)\]\s*(.+)$/;
const FORBIDDEN_IDS = new Set(["__proto__", "prototype", "constructor"]);
const SENSITIVE_HEADER_KEYS = new Set([
  "authorization",
  "x-api-key",
  "api-key",
  "proxy-authorization",
  "cookie",
  "x-auth-token",
]);

function isSensitiveHeaderKey(key: string): boolean {
  return SENSITIVE_HEADER_KEYS.has(key.trim().toLowerCase());
}

function sanitizeExtraHeaders(headers: ExtraHeaderPair[]): ExtraHeaderPair[] {
  return headers
    .map((h) => {
      const k = h.key.trim();
      const v = h.value.trim();
      if (!k) return null;
      return {
        key: k,
        value: isSensitiveHeaderKey(k) ? "[REDACTED]" : v,
      };
    })
    .filter((h): h is ExtraHeaderPair => h !== null);
}

// 1:1 mirror of DIALECT_PRESETS in bridge/gateway_adapter.py
const DIALECT_PRESETS: DialectPreset[] = [
  {
    id: "new_api",
    label: "New API / One-API",
    shortLabel: "New API",
    tagline: "最常见中转站，默认拍平 system、裁剪 stream_options 并启用 400 降级",
    placeholderUrl: "https://api.example-newapi.com/v1",
    sampleModels: [
      "claude-sonnet-4-5",
      "gpt-5.1",
      "deepseek-chat",
      "dall-e-3-image-hd",
      "text-embedding-3-large",
    ],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 16384,
    adaptive_400_fallback: true,
  },
  {
    id: "cpa",
    label: "CPA / CLIProxyAPI",
    shortLabel: "CPA",
    tagline: "完整支持 reasoning_effort 与 max_completion_tokens，保留多段 system",
    placeholderUrl: "https://cpa.example.com/v1",
    sampleModels: ["team/gpt-5.4", "team/claude-sonnet-4-6", "team/gemini-2.5-pro"],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: false,
    strip_stream_options: false,
    max_tokens_field: "max_completion_tokens",
    max_tokens_cap: null,
    adaptive_400_fallback: true,
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    shortLabel: "OpenRouter",
    tagline: "聚合全球主流模型，支持 body effort 且不限制 max_tokens_cap",
    placeholderUrl: "https://openrouter.example.com/api/v1",
    sampleModels: [
      "anthropic/claude-sonnet-4",
      "openai/gpt-5",
      "google/gemini-2.5-pro",
      "deepseek/deepseek-r1",
    ],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: false,
    strip_stream_options: false,
    max_tokens_field: "max_tokens",
    max_tokens_cap: null,
    adaptive_400_fallback: true,
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    shortLabel: "DeepSeek",
    tagline: "官方兼容协议，默认 8192 输出上限，自动剥离不兼容扩展字段",
    placeholderUrl: "https://deepseek.example.com/v1",
    sampleModels: ["deepseek-chat", "deepseek-reasoner"],
    supports_reasoning_effort: false,
    effort_mode: "none",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 8192,
    adaptive_400_fallback: true,
  },
  {
    id: "zhipu",
    label: "智谱 GLM",
    shortLabel: "智谱 GLM",
    tagline: "BigModel v4 兼容模式，默认拍平 system 并启用 400 自适应降级",
    placeholderUrl: "https://bigmodel.example.com/api/paas/v4",
    sampleModels: ["glm-4.5", "glm-4-plus", "glm-4-air", "embedding-3"],
    supports_reasoning_effort: false,
    effort_mode: "none",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 16384,
    adaptive_400_fallback: true,
  },
  {
    id: "ark",
    label: "火山方舟 Ark",
    shortLabel: "火山 Ark",
    tagline: "支持推理强度 body 参数，兼容 Doubao 与方舟托管 DeepSeek 端点",
    placeholderUrl: "https://ark.example.com/api/v3",
    sampleModels: ["doubao-1.5-thinking-pro", "deepseek-r1-250528"],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 16384,
    adaptive_400_fallback: true,
  },
  {
    id: "litellm",
    label: "LiteLLM",
    shortLabel: "LiteLLM",
    tagline: "自建 LiteLLM Proxy，直通 max_completion_tokens 与结构化 system",
    placeholderUrl: "http://127.0.0.1:4000/v1",
    sampleModels: ["gpt-5", "claude-sonnet-4", "o3-mini"],
    supports_reasoning_effort: true,
    effort_mode: "body",
    flatten_system_content: false,
    strip_stream_options: false,
    max_tokens_field: "max_completion_tokens",
    max_tokens_cap: null,
    adaptive_400_fallback: true,
  },
  {
    id: "openai_2api",
    label: "2API 中转",
    shortLabel: "2API",
    tagline: "采用 model(effort) 括号模式传递推理强度，适配各类逆向/二开中转",
    placeholderUrl: "https://2api.example.com/v1",
    sampleModels: ["gpt-5", "claude-sonnet-4", "o4-mini"],
    supports_reasoning_effort: true,
    effort_mode: "model_paren",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 16384,
    adaptive_400_fallback: true,
  },
  {
    id: "openai_strict",
    label: "通用 OpenAI 兼容",
    shortLabel: "OpenAI 兼容",
    tagline: "保守兼容预设，仅发送标准 OpenAI 字段，适配任意自建兼容端点",
    placeholderUrl: "https://api.openai.com/v1",
    sampleModels: ["gpt-4.1", "gpt-4o-mini"],
    supports_reasoning_effort: false,
    effort_mode: "none",
    flatten_system_content: true,
    strip_stream_options: true,
    max_tokens_field: "max_tokens",
    max_tokens_cap: 16384,
    adaptive_400_fallback: true,
  },
];

const DIALECT_MAP: Record<DialectId, DialectPreset> = DIALECT_PRESETS.reduce(
  (acc, item) => {
    acc[item.id] = item;
    return acc;
  },
  {} as Record<DialectId, DialectPreset>,
);

function getDialectPreset(id: string): DialectPreset {
  return DIALECT_MAP[id as DialectId] || DIALECT_MAP.openai_strict;
}

function slugifyGatewayId(name: string): string {
  const base = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/-+/g, "-")
    .replace(/[-_]+$/, "")
    .slice(0, 32);
  if (!base || FORBIDDEN_IDS.has(base)) return "";
  return base;
}

function maskApiKey(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (trimmed.includes("••••")) return trimmed;
  if (trimmed.length <= 6) {
    return `${trimmed.slice(0, 2)}••••`;
  }
  const prefix = trimmed.startsWith("sk-") ? "sk-" : trimmed.slice(0, 3);
  const suffix = trimmed.slice(-4);
  return `${prefix}••••${suffix}`;
}

function parsePatternList(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  );
}

// ReDoS-safe iterative fnmatchcase (`*` and `?`) matching bridge/gateway_adapter.py
function globMatchCase(text: string, pattern: string): boolean {
  let ti = 0;
  let pi = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (ti < text.length) {
    if (pi < pattern.length && (pattern[pi] === "?" || pattern[pi] === text[ti])) {
      ti += 1;
      pi += 1;
    } else if (pi < pattern.length && pattern[pi] === "*") {
      starIdx = pi;
      matchIdx = ti;
      pi += 1;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx += 1;
      ti = matchIdx;
    } else {
      return false;
    }
  }
  while (pi < pattern.length && pattern[pi] === "*") {
    pi += 1;
  }
  return pi === pattern.length;
}

function modelMatchesFilters(
  modelId: string,
  includePatterns: string[],
  excludePatterns: string[],
): boolean {
  const mid = modelId.trim();
  if (!mid) return false;
  if (includePatterns.length > 0) {
    if (!includePatterns.some((pat) => globMatchCase(mid, pat))) {
      return false;
    }
  }
  if (excludePatterns.length > 0) {
    if (excludePatterns.some((pat) => globMatchCase(mid, pat))) {
      return false;
    }
  }
  return true;
}

function buildUpstreamModelsUrl(baseUrl: string): string {
  const clean = (baseUrl || "").trim().replace(/\/+$/, "");
  if (!clean) return "(由后端 gateways.json 托管)/v1/models";
  try {
    const parsed = new URL(clean);
    if (parsed.pathname.replace(/^\/+|\/+$/g, "")) {
      return `${clean}/models`;
    }
    return `${clean}/v1/models`;
  } catch {
    return `${clean}/v1/models`;
  }
}

function inferDialectFromProvider(label: string, id: string): DialectId {
  const s = `${label} ${id}`.toLowerCase();
  if (s.includes("cpa") || s.includes("cliproxy")) return "cpa";
  if (s.includes("openrouter")) return "openrouter";
  if (s.includes("deepseek")) return "deepseek";
  if (s.includes("zhipu") || s.includes("glm") || s.includes("bigmodel")) return "zhipu";
  if (s.includes("ark") || s.includes("doubao") || s.includes("volces")) return "ark";
  if (s.includes("litellm")) return "litellm";
  if (s.includes("2api")) return "openai_2api";
  if (s.includes("newapi") || s.includes("new-api") || s.includes("oneapi") || s.includes("one-api")) {
    return "new_api";
  }
  return "openai_strict";
}

function loadPreviewGateways(): GatewayRecord[] {
  try {
    const raw = window.localStorage.getItem(PREVIEW_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const out: GatewayRecord[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue;
      const rec = item as Record<string, unknown>;
      const id = typeof rec.id === "string" ? rec.id.trim().toLowerCase() : "";
      if (!id || !GW_ID_RE.test(id) || FORBIDDEN_IDS.has(id)) continue;
      const dialect = getDialectPreset(typeof rec.dialect === "string" ? rec.dialect : "openai_strict").id;
      const preset = DIALECT_MAP[dialect];
      const credKind: CredentialKind =
        rec.credential_kind === "api_key_env"
          ? "api_key_env"
          : rec.credential_kind === "server_cmd_readonly"
            ? "server_cmd_readonly"
            : "api_key";
      const rawMasked = typeof rec.api_key_masked === "string" ? rec.api_key_masked : "";
      out.push({
        id,
        name: typeof rec.name === "string" && rec.name.trim() ? rec.name.trim() : id,
        base_url: typeof rec.base_url === "string" ? rec.base_url.trim() : "",
        dialect,
        enabled: typeof rec.enabled === "boolean" ? rec.enabled : true,
        source: "preview",
        credential_kind: credKind,
        // Defensive: always ensure stored value is masked even if manually tampered
        api_key_masked: rawMasked ? maskApiKey(rawMasked) : "",
        api_key_env: typeof rec.api_key_env === "string" ? rec.api_key_env.trim() : "",
        include_models: Array.isArray(rec.include_models)
          ? rec.include_models.filter((x): x is string => typeof x === "string" && Boolean(x.trim()))
          : [],
        exclude_models: Array.isArray(rec.exclude_models)
          ? rec.exclude_models.filter((x): x is string => typeof x === "string" && Boolean(x.trim()))
          : [],
        models: Array.isArray(rec.models)
          ? rec.models.filter((x): x is string => typeof x === "string" && Boolean(x.trim()))
          : [],
        discovered_models: Array.isArray(rec.discovered_models)
          ? rec.discovered_models.filter((x): x is string => typeof x === "string" && Boolean(x.trim()))
          : [],
        supports_reasoning_effort:
          typeof rec.supports_reasoning_effort === "boolean"
            ? rec.supports_reasoning_effort
            : preset.supports_reasoning_effort,
        effort_mode:
          rec.effort_mode === "body" || rec.effort_mode === "model_paren" || rec.effort_mode === "none"
            ? rec.effort_mode
            : preset.effort_mode,
        flatten_system_content:
          typeof rec.flatten_system_content === "boolean"
            ? rec.flatten_system_content
            : preset.flatten_system_content,
        strip_stream_options:
          typeof rec.strip_stream_options === "boolean"
            ? rec.strip_stream_options
            : preset.strip_stream_options,
        max_tokens_field:
          rec.max_tokens_field === "max_completion_tokens" ||
          rec.max_tokens_field === "max_tokens" ||
          rec.max_tokens_field === "omit"
            ? rec.max_tokens_field
            : preset.max_tokens_field,
        max_tokens_cap:
          typeof rec.max_tokens_cap === "number" && Number.isFinite(rec.max_tokens_cap) && rec.max_tokens_cap > 0
            ? Math.floor(rec.max_tokens_cap)
            : null,
        adaptive_400_fallback:
          typeof rec.adaptive_400_fallback === "boolean"
            ? rec.adaptive_400_fallback
            : preset.adaptive_400_fallback,
        timeout_s:
          typeof rec.timeout_s === "number" && Number.isFinite(rec.timeout_s) && rec.timeout_s >= 5
            ? rec.timeout_s
            : 300,
        extra_headers: Array.isArray(rec.extra_headers)
          ? sanitizeExtraHeaders(
              rec.extra_headers.filter(
                (h): h is ExtraHeaderPair =>
                  Boolean(h) &&
                  typeof (h as ExtraHeaderPair).key === "string" &&
                  typeof (h as ExtraHeaderPair).value === "string",
              ),
            )
          : [],
        updated_at: typeof rec.updated_at === "number" ? rec.updated_at : undefined,
      });
    }
    return out;
  } catch {
    return [];
  }
}

function savePreviewGateways(list: GatewayRecord[]): void {
  try {
    const safeList = list
      .filter((g) => g.source === "preview")
      .map((g) => ({
        ...g,
        // Never persist plaintext API keys or sensitive header values into localStorage
        api_key_masked: g.api_key_masked ? maskApiKey(g.api_key_masked) : "",
        extra_headers: sanitizeExtraHeaders(g.extra_headers),
      }));
    window.localStorage.setItem(PREVIEW_STORAGE_KEY, JSON.stringify(safeList));
  } catch {
    // Ignore storage quota errors
  }
}

interface ParsedExternalCatalog {
  liveGateways: GatewayRecord[];
  nativeCount: number;
  externalModelCount: number;
  modelOptionsByGateway: Record<string, { slug: string; upstream: string; label: string }[]>;
}

function extractExternalCatalog(models: ModelOption[]): ParsedExternalCatalog {
  const groups = new Map<
    string,
    {
      id: string;
      name: string;
      models: { slug: string; upstream: string; label: string }[];
    }
  >();
  let nativeCount = 0;
  let externalModelCount = 0;

  for (const item of models) {
    const label = (item.label || item.id || "").trim();
    const match = MODEL_PROVIDER_PREFIX_RE.exec(label);
    if (!match) {
      nativeCount += 1;
      continue;
    }
    const providerLabel = match[1].trim();
    const upstreamModel = match[2].trim();
    if (!providerLabel || !upstreamModel) {
      nativeCount += 1;
      continue;
    }
    externalModelCount += 1;

    let gwId = "";
    if (item.id.startsWith("gw:")) {
      const rest = item.id.slice(3);
      const colonIdx = rest.indexOf(":");
      if (colonIdx > 0) {
        gwId = rest.slice(0, colonIdx).trim().toLowerCase();
      }
    }
    if (!gwId || !GW_ID_RE.test(gwId)) {
      gwId = slugifyGatewayId(providerLabel) || "external";
    }

    const existing = groups.get(gwId);
    if (existing) {
      existing.models.push({ slug: item.id, upstream: upstreamModel, label });
    } else {
      groups.set(gwId, {
        id: gwId,
        name: providerLabel,
        models: [{ slug: item.id, upstream: upstreamModel, label }],
      });
    }
  }

  const liveGateways: GatewayRecord[] = [];
  const modelOptionsByGateway: Record<string, { slug: string; upstream: string; label: string }[]> =
    {};

  for (const grp of groups.values()) {
    const dialect = inferDialectFromProvider(grp.name, grp.id);
    const preset = DIALECT_MAP[dialect];
    modelOptionsByGateway[grp.id] = grp.models;
    liveGateways.push({
      id: grp.id,
      name: grp.name,
      base_url: "",
      dialect,
      enabled: true,
      source: "live",
      credential_kind: "server_cmd_readonly",
      api_key_masked: "",
      api_key_env: "",
      include_models: [],
      exclude_models: [],
      models: [],
      discovered_models: grp.models.map((m) => m.upstream),
      supports_reasoning_effort: preset.supports_reasoning_effort,
      effort_mode: preset.effort_mode,
      flatten_system_content: preset.flatten_system_content,
      strip_stream_options: preset.strip_stream_options,
      max_tokens_field: preset.max_tokens_field,
      max_tokens_cap: preset.max_tokens_cap,
      adaptive_400_fallback: preset.adaptive_400_fallback,
      timeout_s: 300,
      extra_headers: [],
    });
  }

  return { liveGateways, nativeCount, externalModelCount, modelOptionsByGateway };
}

interface GatewayEditorState {
  mode: "create" | "edit";
  editingLiveOrigin: boolean;
  name: string;
  id: string;
  idTouched: boolean;
  base_url: string;
  dialect: DialectId;
  enabled: boolean;
  credential_kind: CredentialKind;
  api_key_input: string;
  api_key_masked_existing: string;
  api_key_env: string;
  include_models_text: string;
  exclude_models_text: string;
  static_models_text: string;
  discovered_models: string[];
  supports_reasoning_effort: boolean;
  effort_mode: EffortMode;
  flatten_system_content: boolean;
  strip_stream_options: boolean;
  max_tokens_field: MaxTokensField;
  max_tokens_cap_text: string;
  adaptive_400_fallback: boolean;
  timeout_s_text: string;
  extra_headers: ExtraHeaderPair[];
  advancedOpen: boolean;
}

function makeEditorStateFromPreset(dialect: DialectId = "new_api"): GatewayEditorState {
  const preset = DIALECT_MAP[dialect];
  return {
    mode: "create",
    editingLiveOrigin: false,
    name: "",
    id: "",
    idTouched: false,
    base_url: "",
    dialect,
    enabled: true,
    credential_kind: "api_key",
    api_key_input: "",
    api_key_masked_existing: "",
    api_key_env: "",
    include_models_text: "",
    exclude_models_text: "*-image-*, *-embedding-*",
    static_models_text: "",
    discovered_models: [...preset.sampleModels],
    supports_reasoning_effort: preset.supports_reasoning_effort,
    effort_mode: preset.effort_mode,
    flatten_system_content: preset.flatten_system_content,
    strip_stream_options: preset.strip_stream_options,
    max_tokens_field: preset.max_tokens_field,
    max_tokens_cap_text: preset.max_tokens_cap ? String(preset.max_tokens_cap) : "",
    adaptive_400_fallback: preset.adaptive_400_fallback,
    timeout_s_text: "300",
    extra_headers: [],
    advancedOpen: false,
  };
}

function makeEditorStateFromRecord(gw: GatewayRecord): GatewayEditorState {
  return {
    mode: "edit",
    editingLiveOrigin: gw.source === "live",
    name: gw.name,
    id: gw.id,
    idTouched: true,
    base_url: gw.base_url || getDialectPreset(gw.dialect).placeholderUrl,
    dialect: gw.dialect,
    enabled: gw.enabled,
    credential_kind: gw.credential_kind,
    api_key_input: "",
    api_key_masked_existing: gw.api_key_masked,
    api_key_env: gw.api_key_env,
    include_models_text: gw.include_models.join(", "),
    exclude_models_text: gw.exclude_models.join(", "),
    static_models_text: gw.models.join(", "),
    discovered_models:
      gw.discovered_models.length > 0
        ? [...gw.discovered_models]
        : [...getDialectPreset(gw.dialect).sampleModels],
    supports_reasoning_effort: gw.supports_reasoning_effort,
    effort_mode: gw.effort_mode,
    flatten_system_content: gw.flatten_system_content,
    strip_stream_options: gw.strip_stream_options,
    max_tokens_field: gw.max_tokens_field,
    max_tokens_cap_text: gw.max_tokens_cap ? String(gw.max_tokens_cap) : "",
    adaptive_400_fallback: gw.adaptive_400_fallback,
    timeout_s_text: String(gw.timeout_s || 300),
    extra_headers: gw.extra_headers.map((h) => ({ ...h })),
    advancedOpen: false,
  };
}

export function ExternalModelsView({
  session,
  onNavigate,
  onSessionRevoked,
}: ExternalModelsViewProps) {
  const isReadonly = !session || session.role !== "admin";

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ipcOnline, setIpcOnline] = useState(true);
  const [liveModels, setLiveModels] = useState<ModelOption[]>([]);
  const [bots, setBots] = useState<BotRosterItem[]>([]);
  const [openBaoStatus, setOpenBaoStatus] = useState<OpenBaoConfigResponse | null>(null);
  const [previewGateways, setPreviewGateways] = useState<GatewayRecord[]>(() =>
    loadPreviewGateways(),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Interactive filter sandbox state on inspector (for testing globs against selected gateway)
  const [inspectorIncludeText, setInspectorIncludeText] = useState("");
  const [inspectorExcludeText, setInspectorExcludeText] = useState("");
  const [inspectorModelQuery, setInspectorModelQuery] = useState("");
  const [showJsonSnippet, setShowJsonSnippet] = useState(false);
  const [showArchCard, setShowArchCard] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Probe simulation state
  const [probingId, setProbingId] = useState<string | null>(null);
  const [probeResults, setProbeResults] = useState<Record<string, ProbeResult>>({});

  // Editor modal state
  const [editor, setEditor] = useState<GatewayEditorState | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [editorProbeMsg, setEditorProbeMsg] = useState<string | null>(null);
  const [editorProbing, setEditorProbing] = useState(false);

  // Delete confirmation modal state
  const [deleteTarget, setDeleteTarget] = useState<GatewayRecord | null>(null);
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

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

  const loadLiveCatalog = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [modelsRes, botsRes, openBaoRes] = await Promise.all([
        fetchModels(),
        fetchBots(),
        fetchOpenBaoConfig().catch(() => null),
      ]);
      if (!mountedRef.current) return;
      setLiveModels(modelsRes.models || []);
      setIpcOnline(Boolean(modelsRes.ipc_online));
      setBots(botsRes.bots || []);
      setOpenBaoStatus(openBaoRes);
    } catch (e) {
      if (!mountedRef.current) return;
      if (!handleAuthErr(e)) {
        setError(e instanceof Error ? e.message : "加载实时模型目录失败");
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [handleAuthErr]);

  useEffect(() => {
    void loadLiveCatalog();
  }, [loadLiveCatalog]);

  const parsedCatalog = useMemo(() => extractExternalCatalog(liveModels), [liveModels]);

  // Merge live gateways + preview gateways (preview overrides if same id, keeping live discovered models)
  const allGateways = useMemo<GatewayRecord[]>(() => {
    const map = new Map<string, GatewayRecord>();
    for (const lg of parsedCatalog.liveGateways) {
      map.set(lg.id, lg);
    }
    for (const pg of previewGateways) {
      const liveMatch = map.get(pg.id);
      if (liveMatch) {
        map.set(pg.id, {
          ...pg,
          discovered_models:
            liveMatch.discovered_models.length > 0
              ? liveMatch.discovered_models
              : pg.discovered_models,
        });
      } else {
        map.set(pg.id, pg);
      }
    }
    return Array.from(map.values());
  }, [parsedCatalog.liveGateways, previewGateways]);

  // Ensure a valid selected gateway when list changes
  useEffect(() => {
    if (allGateways.length === 0) {
      setSelectedId(null);
      return;
    }
    setSelectedId((cur) => {
      if (cur && allGateways.some((g) => g.id === cur)) return cur;
      return allGateways[0].id;
    });
  }, [allGateways]);

  const selectedGateway = useMemo(
    () => allGateways.find((g) => g.id === selectedId) || null,
    [allGateways, selectedId],
  );

  // Sync inspector filter sandbox when selected gateway changes
  useEffect(() => {
    if (!selectedGateway) {
      setInspectorIncludeText("");
      setInspectorExcludeText("");
      setInspectorModelQuery("");
      return;
    }
    setInspectorIncludeText(selectedGateway.include_models.join(", "));
    setInspectorExcludeText(selectedGateway.exclude_models.join(", "));
    setInspectorModelQuery("");
  }, [selectedGateway?.id, selectedGateway?.include_models.join(","), selectedGateway?.exclude_models.join(",")]);

  // Map each gateway id -> bots currently using any model from that gateway
  const botBindingsByGateway = useMemo<Record<string, BotRosterItem[]>>(() => {
    const result: Record<string, BotRosterItem[]> = {};
    for (const gw of allGateways) {
      const liveOpts = parsedCatalog.modelOptionsByGateway[gw.id] || [];
      const candidateIds = new Set<string>();
      for (const opt of liveOpts) {
        candidateIds.add(opt.slug);
        candidateIds.add(opt.upstream);
        candidateIds.add(`gw:${gw.id}:${opt.upstream}`);
      }
      for (const m of [...gw.discovered_models, ...gw.models]) {
        candidateIds.add(m);
        candidateIds.add(`gw:${gw.id}:${m}`);
      }
      const matched = bots.filter((b) => {
        const eff = (b.effective_model || "").trim();
        const act = (b.active_model || "").trim();
        return (
          (eff && (candidateIds.has(eff) || eff.startsWith(`gw:${gw.id}:`))) ||
          (act && (candidateIds.has(act) || act.startsWith(`gw:${gw.id}:`)))
        );
      });
      result[gw.id] = matched;
    }
    return result;
  }, [allGateways, bots, parsedCatalog.modelOptionsByGateway]);

  // KPI metrics
  const stats = useMemo(() => {
    const total = allGateways.length;
    const enabled = allGateways.filter((g) => g.enabled).length;
    const liveCount = allGateways.filter((g) => g.source === "live").length;
    const previewCount = allGateways.filter((g) => g.source === "preview").length;
    const activeBotSet = new Set<string>();
    for (const list of Object.values(botBindingsByGateway)) {
      for (const b of list) activeBotSet.add(b.handle);
    }
    let exposedTotal = 0;
    for (const gw of allGateways) {
      if (!gw.enabled) continue;
      const pool = Array.from(new Set([...gw.discovered_models, ...gw.models]));
      exposedTotal += pool.filter((m) =>
        modelMatchesFilters(m, gw.include_models, gw.exclude_models),
      ).length;
    }
    return {
      total,
      enabled,
      liveCount,
      previewCount,
      activeBotsCount: activeBotSet.size,
      exposedTotal,
    };
  }, [allGateways, botBindingsByGateway]);

  const persistPreviewList = useCallback((next: GatewayRecord[]) => {
    setPreviewGateways(next);
    savePreviewGateways(next);
  }, []);

  const handleToggleEnabled = (gw: GatewayRecord) => {
    if (isReadonly) return;
    if (gw.source === "live") {
      setBannerNotice(
        `「${gw.name}」当前由后端 gateways.json 托管；点击「编辑」可创建预演覆盖草稿，接入后端写 API 后将支持在线启停热生效。`,
      );
      return;
    }
    const next = previewGateways.map((item) =>
      item.id === gw.id ? { ...item, enabled: !item.enabled, updated_at: Date.now() } : item,
    );
    persistPreviewList(next);
    setBannerNotice(`已${gw.enabled ? "停用" : "启用"}预演站点「${gw.name}」。`);
  };

  const handleRunProbe = (gw: GatewayRecord) => {
    setProbingId(gw.id);
    window.setTimeout(() => {
      if (!mountedRef.current) return;
      const pool = Array.from(
        new Set([
          ...gw.discovered_models,
          ...gw.models,
          ...(gw.discovered_models.length === 0 && gw.models.length === 0
            ? getDialectPreset(gw.dialect).sampleModels
            : []),
        ]),
      );
      const exposed = pool.filter((m) =>
        modelMatchesFilters(m, gw.include_models, gw.exclude_models),
      );
      const latency = gw.source === "live" ? 118 : 164;
      setProbeResults((prev) => ({
        ...prev,
        [gw.id]: {
          ok: true,
          latencyMs: latency,
          discoveredCount: pool.length,
          exposedCount: exposed.length,
          endpoint: buildUpstreamModelsUrl(gw.base_url),
          summary:
            gw.source === "live"
              ? `已关联实时目录（${pool.length} 个上游模型）；接入 POST /api/gateways/${gw.id}/probe 后将由后端直连探测延迟与鉴权状态。`
              : `预演探测模拟通过（方言 ${gw.dialect}）；接入 POST /api/gateways/${gw.id}/probe 后将真实拉取上游 /v1/models 并缓存目录。`,
          checkedAt: new Date().toLocaleTimeString(),
        },
      }));
      setProbingId(null);
    }, 450);
  };

  const handleCopyText = (key: string, text: string) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      void navigator.clipboard.writeText(text).then(() => {
        setCopiedKey(key);
        window.setTimeout(() => {
          setCopiedKey((cur) => (cur === key ? null : cur));
        }, 1600);
      });
    }
  };

  const openCreateModal = () => {
    if (isReadonly) return;
    setEditorError(null);
    setEditorProbeMsg(null);
    setEditor(makeEditorStateFromPreset("new_api"));
  };

  const openEditModal = (gw: GatewayRecord) => {
    if (isReadonly) return;
    setEditorError(null);
    setEditorProbeMsg(null);
    setEditor(makeEditorStateFromRecord(gw));
  };

  const applyDialectTemplate = (dialectId: DialectId) => {
    const preset = DIALECT_MAP[dialectId];
    setEditor((cur) => {
      if (!cur) return cur;
      return {
        ...cur,
        dialect: dialectId,
        supports_reasoning_effort: preset.supports_reasoning_effort,
        effort_mode: preset.effort_mode,
        flatten_system_content: preset.flatten_system_content,
        strip_stream_options: preset.strip_stream_options,
        max_tokens_field: preset.max_tokens_field,
        max_tokens_cap_text: preset.max_tokens_cap ? String(preset.max_tokens_cap) : "",
        adaptive_400_fallback: preset.adaptive_400_fallback,
        discovered_models:
          cur.mode === "create" ? [...preset.sampleModels] : cur.discovered_models,
      };
    });
  };

  const handleEditorProbe = () => {
    if (!editor) return;
    setEditorError(null);
    const cleanUrl = editor.base_url.trim();
    if (!cleanUrl) {
      setEditorError("请先填写 Base URL 再测试连通性");
      return;
    }
    try {
      const u = new URL(cleanUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        setEditorError("Base URL 必须使用 http:// 或 https:// 协议");
        return;
      }
    } catch {
      setEditorError("Base URL 格式不正确，请检查域名与协议");
      return;
    }
    setEditorProbing(true);
    setEditorProbeMsg(null);
    window.setTimeout(() => {
      if (!mountedRef.current) return;
      const preset = getDialectPreset(editor.dialect);
      const discovered =
        editor.discovered_models.length > 0
          ? editor.discovered_models
          : [...preset.sampleModels];
      const inc = parsePatternList(editor.include_models_text);
      const exc = parsePatternList(editor.exclude_models_text);
      const stat = parsePatternList(editor.static_models_text);
      const union = Array.from(new Set([...discovered, ...stat]));
      const passed = union.filter((m) => modelMatchesFilters(m, inc, exc));
      setEditor((cur) => (cur ? { ...cur, discovered_models: discovered } : cur));
      setEditorProbeMsg(
        `预演探测模拟成功（${buildUpstreamModelsUrl(cleanUrl)} · 152ms）：发现 ${union.length} 个候选模型，过滤后暴露 ${passed.length} 个。接入后端 POST /api/gateways/{id}/probe 后将真实请求上游。`,
      );
      setEditorProbing(false);
    }, 450);
  };

  const handleSaveEditor = () => {
    if (!editor || isReadonly) return;
    setEditorError(null);

    const name = editor.name.trim();
    const id = editor.id.trim().toLowerCase();
    const baseUrl = editor.base_url.trim().replace(/\/+$/, "");

    if (!name) {
      setEditorError("请填写显示名称（例如：New API 主站、DeepSeek 官方）");
      return;
    }
    if (!id || !GW_ID_RE.test(id) || FORBIDDEN_IDS.has(id)) {
      setEditorError("站点 ID 须满足 ^[a-z0-9][a-z0-9_-]{0,31}$，不可包含冒号或斜杠");
      return;
    }
    if (editor.mode === "create" && allGateways.some((g) => g.id === id)) {
      setEditorError(`站点 ID「${id}」已存在，请换用唯一标识`);
      return;
    }
    if (!baseUrl) {
      setEditorError("请填写 Base URL");
      return;
    }
    try {
      const parsed = new URL(baseUrl);
      if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || !parsed.host) {
        setEditorError("Base URL 必须是有效的 http:// 或 https:// 地址");
        return;
      }
    } catch {
      setEditorError("Base URL 格式不合法，请输入完整 http(s):// 地址");
      return;
    }

    let apiKeyMasked = editor.api_key_masked_existing;
    let apiKeyEnv = "";
    if (editor.credential_kind === "api_key") {
      const rawKey = editor.api_key_input.trim();
      if (rawKey) {
        apiKeyMasked = maskApiKey(rawKey);
      } else if (!apiKeyMasked) {
        setEditorError("请输入 API Key，或切换为「环境变量」凭证模式");
        return;
      }
    } else if (editor.credential_kind === "api_key_env") {
      apiKeyEnv = editor.api_key_env.trim();
      if (!apiKeyEnv || !ENV_NAME_RE.test(apiKeyEnv)) {
        setEditorError("环境变量名须为大写字母/数字/下划线（例如 NEW_API_KEY）");
        return;
      }
      apiKeyMasked = "";
    }

    let maxTokensCap: number | null = null;
    if (editor.max_tokens_cap_text.trim()) {
      const n = Number(editor.max_tokens_cap_text.trim());
      if (!Number.isInteger(n) || n <= 0) {
        setEditorError("max_tokens_cap 须为空（不限）或正整数");
        return;
      }
      maxTokensCap = n;
    }

    const timeoutVal = Number(editor.timeout_s_text.trim() || "300");
    if (!Number.isFinite(timeoutVal) || timeoutVal < 5 || timeoutVal > 1800) {
      setEditorError("超时时间 timeout_s 须在 5 ~ 1800 秒之间");
      return;
    }

    const cleanHeaders: ExtraHeaderPair[] = [];
    for (const pair of editor.extra_headers) {
      const k = pair.key.trim();
      const v = pair.value.trim();
      if (!k && !v) continue;
      if (!k || /[\r\n:]/.test(k) || /[\r\n]/.test(v)) {
        setEditorError("自定义请求头名称或值包含非法字符");
        return;
      }
      cleanHeaders.push({ key: k, value: v });
    }

    const record: GatewayRecord = {
      id,
      name,
      base_url: baseUrl,
      dialect: editor.dialect,
      enabled: editor.enabled,
      source: "preview",
      credential_kind: editor.credential_kind,
      api_key_masked: apiKeyMasked,
      api_key_env: apiKeyEnv,
      include_models: parsePatternList(editor.include_models_text),
      exclude_models: parsePatternList(editor.exclude_models_text),
      models: parsePatternList(editor.static_models_text),
      discovered_models:
        editor.discovered_models.length > 0
          ? editor.discovered_models
          : [...getDialectPreset(editor.dialect).sampleModels],
      supports_reasoning_effort: editor.supports_reasoning_effort,
      effort_mode: editor.effort_mode,
      flatten_system_content: editor.flatten_system_content,
      strip_stream_options: editor.strip_stream_options,
      max_tokens_field: editor.max_tokens_field,
      max_tokens_cap: maxTokensCap,
      adaptive_400_fallback: editor.adaptive_400_fallback,
      timeout_s: timeoutVal,
      extra_headers: sanitizeExtraHeaders(cleanHeaders),
      updated_at: Date.now(),
    };

    const existsInPreview = previewGateways.some((g) => g.id === record.id);
    const nextList = existsInPreview
      ? previewGateways.map((g) => (g.id === record.id ? record : g))
      : [...previewGateways, record];

    persistPreviewList(nextList);
    setSelectedId(record.id);
    setEditor(null);
    setBannerNotice(
      `已保存「${record.name}」到预演配置（明文密钥未写入本地存储，仅保留脱敏状态）。接入后端 API 后将原子写入 gateways.json / OpenBao 并热重载。`,
    );
  };

  const handleConfirmDelete = () => {
    if (!deleteTarget || isReadonly) return;
    const target = deleteTarget;
    setDeleteTarget(null);
    if (target.source === "live") {
      setBannerNotice(
        `「${target.name}」属于后端 gateways.json 实时生效站点，预演阶段不可删除；接入 DELETE /api/gateways/${target.id} 后支持受控移除。`,
      );
      return;
    }
    const next = previewGateways.filter((g) => g.id !== target.id);
    persistPreviewList(next);
    setBannerNotice(`已移除预演中转站「${target.name}」。`);
  };

  // Inspector real-time model filter evaluation
  const inspectorEval = useMemo(() => {
    if (!selectedGateway) {
      return { rows: [], exposedCount: 0, filteredOutCount: 0, isDirtySandbox: false };
    }
    const inc = parsePatternList(inspectorIncludeText);
    const exc = parsePatternList(inspectorExcludeText);
    const savedInc = selectedGateway.include_models.join(",");
    const savedExc = selectedGateway.exclude_models.join(",");
    const isDirtySandbox = inc.join(",") !== savedInc || exc.join(",") !== savedExc;

    const liveOpts = parsedCatalog.modelOptionsByGateway[selectedGateway.id] || [];
    const slugMap = new Map<string, string>();
    for (const o of liveOpts) {
      slugMap.set(o.upstream, o.slug);
    }

    const staticSet = new Set(selectedGateway.models);
    const pool = Array.from(
      new Set([...selectedGateway.discovered_models, ...selectedGateway.models]),
    );
    const q = inspectorModelQuery.trim().toLowerCase();

    const rows = pool
      .map((modelId) => {
        const matched = modelMatchesFilters(modelId, inc, exc);
        const isStatic = staticSet.has(modelId) && !selectedGateway.discovered_models.includes(modelId);
        const refSlug = slugMap.get(modelId) || `gw:${selectedGateway.id}:${modelId}`;
        return {
          modelId,
          matched,
          isStatic,
          displayLabel: `[${selectedGateway.name}] ${modelId}`,
          refSlug,
        };
      })
      .filter((row) => !q || row.modelId.toLowerCase().includes(q) || row.displayLabel.toLowerCase().includes(q));

    const exposedCount = rows.filter((r) => r.matched).length;
    const filteredOutCount = rows.length - exposedCount;
    return { rows, exposedCount, filteredOutCount, isDirtySandbox };
  }, [
    selectedGateway,
    inspectorIncludeText,
    inspectorExcludeText,
    inspectorModelQuery,
    parsedCatalog.modelOptionsByGateway,
  ]);

  // Editor live filter preview
  const editorFilterPreview = useMemo(() => {
    if (!editor) return { rows: [], exposedCount: 0, totalCount: 0 };
    const inc = parsePatternList(editor.include_models_text);
    const exc = parsePatternList(editor.exclude_models_text);
    const stat = parsePatternList(editor.static_models_text);
    const union = Array.from(new Set([...editor.discovered_models, ...stat]));
    const siteName = editor.name.trim() || editor.id.trim() || "中转站";
    const rows = union.map((m) => ({
      modelId: m,
      matched: modelMatchesFilters(m, inc, exc),
      displayLabel: `[${siteName}] ${m}`,
    }));
    return {
      rows,
      exposedCount: rows.filter((r) => r.matched).length,
      totalCount: rows.length,
    };
  }, [editor]);

  // Sanitized gateways.json preview snippet for selected gateway
  const jsonSnippet = useMemo(() => {
    if (!selectedGateway) return "";
    const obj: Record<string, unknown> = {
      id: selectedGateway.id,
      name: selectedGateway.name,
      base_url:
        selectedGateway.base_url ||
        getDialectPreset(selectedGateway.dialect).placeholderUrl,
      dialect: selectedGateway.dialect,
      enabled: selectedGateway.enabled,
    };
    if (selectedGateway.credential_kind === "server_cmd_readonly") {
      obj.api_key_cmd = "[REDACTED · 服务端 OpenBao/命令凭证托管]";
    } else if (selectedGateway.credential_kind === "api_key_env") {
      obj.api_key_env = selectedGateway.api_key_env || "GATEWAY_API_KEY";
    } else {
      obj.api_key = selectedGateway.api_key_masked || "[REDACTED]";
    }
    if (selectedGateway.include_models.length > 0) {
      obj.include_models = selectedGateway.include_models;
    }
    if (selectedGateway.exclude_models.length > 0) {
      obj.exclude_models = selectedGateway.exclude_models;
    }
    if (selectedGateway.models.length > 0) {
      obj.models = selectedGateway.models;
    }
    obj.supports_reasoning_effort = selectedGateway.supports_reasoning_effort;
    obj.effort_mode = selectedGateway.effort_mode;
    obj.max_tokens_field = selectedGateway.max_tokens_field;
    if (selectedGateway.max_tokens_cap !== null) {
      obj.max_tokens_cap = selectedGateway.max_tokens_cap;
    }
    obj.flatten_system_content = selectedGateway.flatten_system_content;
    obj.strip_stream_options = selectedGateway.strip_stream_options;
    obj.adaptive_400_fallback = selectedGateway.adaptive_400_fallback;
    if (selectedGateway.timeout_s !== 300) {
      obj.timeout_s = selectedGateway.timeout_s;
    }
    if (selectedGateway.extra_headers.length > 0) {
      obj.extra_headers = Object.fromEntries(
        sanitizeExtraHeaders(selectedGateway.extra_headers).map((h) => [h.key, h.value]),
      );
    }
    return JSON.stringify(obj, null, 2);
  }, [selectedGateway]);

  return (
    <div className="p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-slate-100">外部模型与中转站</h2>
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-300">
              <Sparkles className="w-3 h-3" />
              MVP-Preview 交互预演
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            底层对接 <code className="font-mono text-slate-300">bridge/gateway_adapter.py</code> 多网关适配器（9 种方言预设），支持 WebUI 工作台、Bot 团队与 Telegram <code className="font-mono text-slate-300">/model</code> 共享生效
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void loadLiveCatalog()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新模型目录
          </button>
          {!isReadonly && (
            <button
              type="button"
              onClick={openCreateModal}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              添加中转站
            </button>
          )}
        </div>
      </div>

      {/* Readonly Role Banner */}
      {isReadonly && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 flex items-center gap-2 text-xs text-amber-200">
          <Lock className="w-4 h-4 shrink-0 text-amber-400" />
          <span>
            当前为只读权限（readonly）：仅可查看实时发现的外部中转站、暴露模型目录与 Bot 绑定状态，新增/编辑/启停/删除操作已隐藏。
          </span>
        </div>
      )}

      {/* Secret Hosting Status & Quick Navigation */}
      <div
        className={`rounded-xl border px-3.5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
          openBaoStatus?.enabled && openBaoStatus?.credential_configured
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
            : "border-sky-500/25 bg-sky-500/10 text-sky-100"
        }`}
      >
        <div className="flex items-start gap-2.5 min-w-0">
          {openBaoStatus?.enabled && openBaoStatus?.credential_configured ? (
            <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
          ) : (
            <Info className="w-4 h-4 shrink-0 text-sky-400 mt-0.5" />
          )}
          <div className="space-y-1 leading-relaxed min-w-0">
            <div className="font-medium flex flex-wrap items-center gap-1.5">
              {openBaoStatus?.enabled && openBaoStatus?.credential_configured ? (
                <>
                  <span>
                    🔒 已接入 OpenBao（未来保存将自动转存
                    {!isReadonly && openBaoStatus.gateway_path_prefix
                      ? `至 ${openBaoStatus.gateway_path_prefix}/<id>`
                      : ""}
                    ）
                  </span>
                  {openBaoStatus.source === "host_auto" && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-200 border border-emerald-500/30">
                      已自动载入本机配置
                    </span>
                  )}
                </>
              ) : (
                <span>🛡️ 未配置 OpenBao（将使用本机 0600 兜底 / 后续安全卡存档）</span>
              )}
            </div>
            {!isReadonly && (
              <div className="text-[11px] opacity-85">
                标有「后端生效」的站点来自当前在线 Bridge 的真实{" "}
                <code className="font-mono">/api/models</code> 目录；新增或编辑的站点保存在预演草稿中，
                <strong>明文 API Key 绝不写入浏览器存储</strong>（仅保留脱敏掩码{" "}
                <code className="font-mono">[REDACTED]</code>）。
              </div>
            )}
          </div>
        </div>

        {onNavigate && (
          <div className="flex flex-wrap items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate("openbao")}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700/80 bg-slate-900/80 hover:bg-slate-800 px-2.5 py-1.5 text-[11px] font-medium text-slate-100 cursor-pointer"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              OpenBao 配置
            </button>
            <button
              type="button"
              onClick={() => onNavigate("security-card")}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700/80 bg-slate-900/80 hover:bg-slate-800 px-2.5 py-1.5 text-[11px] font-medium text-slate-100 cursor-pointer"
            >
              <CreditCard className="w-3.5 h-3.5 text-amber-400" />
              安全卡（预留）
            </button>
          </div>
        )}
      </div>

      {/* Transient Feedback Notice */}
      {bannerNotice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs text-emerald-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            <span>{bannerNotice}</span>
          </div>
          <button
            type="button"
            onClick={() => setBannerNotice(null)}
            aria-label="关闭提示"
            className="text-emerald-300/80 hover:text-emerald-100 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Load Error */}
      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2 text-xs text-rose-200">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Top 3 KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>已配置中转站</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-slate-100">{stats.total}</span>
            <span className="text-xs text-slate-400 font-mono">
              {stats.liveCount} 后端生效 · {stats.previewCount} 预演草稿
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>已启用站点</span>
            <Network className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-slate-100">{stats.enabled}</span>
            <span className="text-xs text-slate-400 font-mono">
              / {stats.total} 总计 · {stats.activeBotsCount} 个 Bot 正在调用
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>已发现外部模型</span>
            <Layers className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-slate-100">{stats.exposedTotal}</span>
            <span className="text-xs text-slate-400 font-mono">
              实时 {parsedCatalog.externalModelCount} · 原生 {parsedCatalog.nativeCount}
              {!ipcOnline ? " · IPC离线" : ""}
            </span>
          </div>
        </div>
      </div>

      {/* Main Split Workspace: Left Gateway Cards + Right Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left: Gateway List */}
        <div className="lg:col-span-5 space-y-2.5">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-semibold text-slate-300">
              中转站清单 ({allGateways.length})
            </span>
            <span className="text-[11px] text-slate-500">点击查看模型过滤与协议配置</span>
          </div>

          {loading && allGateways.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-8 flex items-center justify-center gap-2 text-xs text-slate-400">
              <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
              正在同步实时模型目录与 Bot 状态…
            </div>
          ) : allGateways.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-8 text-center space-y-3">
              <Layers className="w-7 h-7 text-slate-600 mx-auto" />
              <div className="space-y-1">
                <div className="text-sm font-medium text-slate-200">暂未发现外部中转站</div>
                <p className="text-xs text-slate-400">
                  当前仅使用 AGY 原生模型（{parsedCatalog.nativeCount} 个）。点击下方按钮选择模板，3 步接入 New API / OpenRouter / DeepSeek / CPA 等中转站。
                </p>
              </div>
              {!isReadonly && (
                <button
                  type="button"
                  onClick={openCreateModal}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3.5 py-2 text-xs font-medium text-white cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  添加第一个中转站
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-2.5">
              {allGateways.map((gw) => {
                const selected = gw.id === selectedId;
                const preset = getDialectPreset(gw.dialect);
                const pool = Array.from(new Set([...gw.discovered_models, ...gw.models]));
                const exposedCount = pool.filter((m) =>
                  modelMatchesFilters(m, gw.include_models, gw.exclude_models),
                ).length;
                const boundBots = botBindingsByGateway[gw.id] || [];

                return (
                  <div
                    key={gw.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedId(gw.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedId(gw.id);
                      }
                    }}
                    className={`rounded-xl border p-3.5 transition-colors cursor-pointer space-y-2.5 ${
                      selected
                        ? "border-sky-500/50 bg-sky-500/10"
                        : "border-slate-800 bg-slate-900/70 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`w-2 h-2 rounded-full shrink-0 ${
                              gw.enabled ? "bg-emerald-400" : "bg-slate-600"
                            }`}
                          />
                          <span className="text-sm font-semibold text-slate-100 truncate">
                            {gw.name}
                          </span>
                          <span className="text-[11px] font-mono text-slate-400 bg-slate-950/80 border border-slate-800 px-1.5 py-0.5 rounded">
                            {gw.id}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${
                              gw.source === "live"
                                ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                                : "bg-amber-500/15 text-amber-300 border-amber-500/30"
                            }`}
                          >
                            {gw.source === "live" ? "后端生效 · gateways.json" : "预演草稿"}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            {preset.shortLabel}
                          </span>
                          {gw.credential_kind === "server_cmd_readonly" ? (
                            <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-800/90 text-slate-300 border border-slate-700/80">
                              <Lock className="w-2.5 h-2.5 text-emerald-400" />
                              服务端命令凭证
                            </span>
                          ) : gw.credential_kind === "api_key_env" ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/90 text-sky-300">
                              <KeyRound className="w-2.5 h-2.5" />
                              env:{gw.api_key_env}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/90 text-slate-300">
                              <KeyRound className="w-2.5 h-2.5 text-amber-400" />
                              {gw.api_key_masked || "已脱敏"}
                            </span>
                          )}
                        </div>
                      </div>

                      {!isReadonly && (
                        <div
                          className="flex items-center gap-1 shrink-0"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            onClick={() => handleToggleEnabled(gw)}
                            title={gw.enabled ? "停用该站点" : "启用该站点"}
                            aria-label={gw.enabled ? `停用 ${gw.name}` : `启用 ${gw.name}`}
                            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors cursor-pointer ${
                              gw.enabled ? "bg-emerald-500/80" : "bg-slate-700"
                            }`}
                          >
                            <span
                              className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                                gw.enabled ? "translate-x-4.5" : "translate-x-1"
                              }`}
                            />
                          </button>
                          <button
                            type="button"
                            onClick={() => openEditModal(gw)}
                            title="编辑配置"
                            aria-label={`编辑 ${gw.name}`}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 cursor-pointer"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteTarget(gw)}
                            title="删除站点"
                            aria-label={`删除 ${gw.name}`}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                      <span className="font-mono truncate max-w-[65%]">
                        {gw.base_url || "由后端 gateways.json 托管端点"}
                      </span>
                      <span className="font-mono text-sky-300 shrink-0">
                        {exposedCount} / {pool.length} 模型
                      </span>
                    </div>

                    {boundBots.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                        <span className="text-[10px] text-slate-500">使用中 Bot：</span>
                        {boundBots.map((b) => (
                          <span
                            key={b.handle}
                            className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/25"
                          >
                            <Bot className="w-2.5 h-2.5" />
                            {b.handle}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Selected Gateway Inspector & Real-Time Filter Preview */}
        <div className="lg:col-span-7 space-y-4">
          {!selectedGateway ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-10 text-center text-xs text-slate-500">
              请在左侧选择一个中转站查看模型过滤与协议适配详情
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">
              {/* Inspector Header */}
              <div className="p-4 border-b border-slate-800 flex flex-wrap items-start justify-between gap-3 bg-slate-950/40">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-semibold text-slate-100">
                      {selectedGateway.name}
                    </h3>
                    <span className="text-xs font-mono text-slate-400">
                      ({selectedGateway.id})
                    </span>
                    <span
                      className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                        selectedGateway.enabled
                          ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {selectedGateway.enabled ? "已启用" : "已停用"}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5 truncate">
                    <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span className="truncate">
                      {selectedGateway.base_url || "后端 gateways.json 托管（未在只读接口暴露上游地址）"}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    disabled={probingId === selectedGateway.id}
                    onClick={() => handleRunProbe(selectedGateway)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/15 hover:bg-sky-500/25 px-3 py-1.5 text-xs font-medium text-sky-200 disabled:opacity-50 cursor-pointer"
                  >
                    {probingId === selectedGateway.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Play className="w-3.5 h-3.5" />
                    )}
                    测试连通 & 拉取模型
                  </button>
                  {!isReadonly && (
                    <button
                      type="button"
                      onClick={() => openEditModal(selectedGateway)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                      {selectedGateway.source === "live" ? "调整预演配置" : "编辑"}
                    </button>
                  )}
                </div>
              </div>

              <div className="p-4 space-y-4">
                {/* Probe Result Feedback */}
                {probeResults[selectedGateway.id] && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 space-y-1 text-xs">
                    <div className="flex items-center justify-between gap-2 text-emerald-200 font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        连通探测结果（预演模拟 · {probeResults[selectedGateway.id].latencyMs}ms）
                      </span>
                      <span className="text-[11px] font-mono text-emerald-300/80">
                        {probeResults[selectedGateway.id].checkedAt}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-300 truncate">
                      GET {probeResults[selectedGateway.id].endpoint} → 发现{" "}
                      {probeResults[selectedGateway.id].discoveredCount} 个，过滤后暴露{" "}
                      {probeResults[selectedGateway.id].exposedCount} 个
                    </div>
                    <p className="text-[11px] text-emerald-200/90">
                      {probeResults[selectedGateway.id].summary}
                    </p>
                  </div>
                )}

                {/* Active Bot Bindings */}
                <div className="rounded-lg border border-slate-800/90 bg-slate-950/50 p-3 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-200 inline-flex items-center gap-1.5">
                      <Bot className="w-3.5 h-3.5 text-sky-400" />
                      当前使用该中转站的 Bot
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      来自实时 /api/bots
                    </span>
                  </div>
                  {(botBindingsByGateway[selectedGateway.id] || []).length === 0 ? (
                    <div className="text-[11px] text-slate-500">
                      暂无 Bot 将默认模型固定到此站点（仍可在工作台或 Telegram <code className="font-mono text-slate-400">/model</code> 中随时按会话选用）。
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {(botBindingsByGateway[selectedGateway.id] || []).map((b) => (
                        <div
                          key={b.handle}
                          className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-[11px]"
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              b.online ? "bg-emerald-400" : "bg-slate-600"
                            }`}
                          />
                          <span className="font-mono text-slate-200">{b.handle}</span>
                          <span className="text-slate-500">·</span>
                          <span className="font-mono text-sky-300">
                            {b.effective_model || b.active_model}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Model Filter & Live Exposure Preview */}
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                      <Filter className="w-3.5 h-3.5 text-sky-400" />
                      模型目录与过滤实时预览
                    </div>
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      <span className="text-emerald-400">
                        暴露 {inspectorEval.exposedCount}
                      </span>
                      <span className="text-slate-600">/</span>
                      <span className="text-slate-400">
                        过滤 {inspectorEval.filteredOutCount}
                      </span>
                    </div>
                  </div>

                  {/* Live Glob Sandbox Inputs */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    <div className="space-y-1">
                      <label className="text-[11px] text-slate-400 flex items-center justify-between">
                        <span>白名单 include_models (glob)</span>
                        <span className="font-mono text-[10px] text-slate-500">空=全部</span>
                      </label>
                      <input
                        type="text"
                        value={inspectorIncludeText}
                        onChange={(e) => setInspectorIncludeText(e.target.value)}
                        placeholder="例：team/*, claude-*, gpt-5*"
                        className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] text-slate-400 flex items-center justify-between">
                        <span>黑名单 exclude_models (glob)</span>
                        <span className="font-mono text-[10px] text-slate-500">优先排除</span>
                      </label>
                      <input
                        type="text"
                        value={inspectorExcludeText}
                        onChange={(e) => setInspectorExcludeText(e.target.value)}
                        placeholder="例：*-image-*, *-embedding-*"
                        className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>

                  {inspectorEval.isDirtySandbox && !isReadonly && (
                    <div className="flex items-center justify-between gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-[11px] text-amber-200">
                      <span>正在实时试算过滤规则（尚未保存到站点配置）</span>
                      <button
                        type="button"
                        onClick={() => {
                          const inc = parsePatternList(inspectorIncludeText);
                          const exc = parsePatternList(inspectorExcludeText);
                          if (selectedGateway.source === "preview") {
                            const next = previewGateways.map((g) =>
                              g.id === selectedGateway.id
                                ? {
                                    ...g,
                                    include_models: inc,
                                    exclude_models: exc,
                                    updated_at: Date.now(),
                                  }
                                : g,
                            );
                            persistPreviewList(next);
                            setBannerNotice(`已应用过滤规则到预演站点「${selectedGateway.name}」。`);
                          } else {
                            openEditModal({
                              ...selectedGateway,
                              include_models: inc,
                              exclude_models: exc,
                            });
                          }
                        }}
                        className="rounded bg-amber-500/20 hover:bg-amber-500/30 px-2 py-0.5 text-amber-100 font-medium cursor-pointer"
                      >
                        {selectedGateway.source === "preview" ? "应用到草稿" : "进入编辑保存"}
                      </button>
                    </div>
                  )}

                  {/* Search inside models */}
                  <input
                    type="text"
                    value={inspectorModelQuery}
                    onChange={(e) => setInspectorModelQuery(e.target.value)}
                    placeholder="搜索模型 ID…"
                    className="w-full rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                  />

                  {/* Model Exposure List */}
                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 max-h-60 overflow-y-auto divide-y divide-slate-800/70">
                    {inspectorEval.rows.length === 0 ? (
                      <div className="p-5 text-center text-xs text-slate-500">
                        暂无匹配的候选模型（可在编辑中补充静态兜底列表 <code className="font-mono">models</code>）
                      </div>
                    ) : (
                      inspectorEval.rows.map((row) => (
                        <div
                          key={row.modelId}
                          className="px-3 py-2 flex items-center justify-between gap-2 text-xs hover:bg-slate-900/60"
                        >
                          <div className="min-w-0 flex items-center gap-2">
                            <span
                              className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                row.matched
                                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/25"
                                  : "bg-slate-800 text-slate-500"
                              }`}
                            >
                              {row.matched ? "暴露" : "过滤"}
                            </span>
                            <span
                              className={`font-mono truncate ${
                                row.matched ? "text-slate-100" : "text-slate-500 line-through"
                              }`}
                              title={row.displayLabel}
                            >
                              {row.displayLabel}
                            </span>
                            {row.isStatic && (
                              <span className="shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300">
                                静态兜底
                              </span>
                            )}
                          </div>
                          <button
                            type="button"
                            onClick={() => handleCopyText(`m:${row.modelId}`, row.refSlug)}
                            title={`复制显式模型引用：${row.refSlug}`}
                            className="shrink-0 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono text-slate-400 hover:text-sky-300 hover:bg-slate-800 cursor-pointer"
                          >
                            {copiedKey === `m:${row.modelId}` ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                已复制
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                复制引用
                              </>
                            )}
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Protocol Adaptation Readout */}
                <div className="rounded-lg border border-slate-800/90 bg-slate-950/40 p-3 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 inline-flex items-center gap-1.5">
                      <Sliders className="w-3.5 h-3.5 text-sky-400" />
                      协议方言与兼容适配参数
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowJsonSnippet((v) => !v)}
                      className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                    >
                      <Code2 className="w-3.5 h-3.5" />
                      {showJsonSnippet ? "隐藏 JSON 片段" : "查看 gateways.json 片段"}
                    </button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">方言预设</div>
                      <div className="font-mono text-slate-200 mt-0.5">
                        {selectedGateway.dialect}
                      </div>
                    </div>
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">推理强度模式</div>
                      <div className="font-mono text-slate-200 mt-0.5">
                        {selectedGateway.supports_reasoning_effort
                          ? selectedGateway.effort_mode
                          : "关闭 (none)"}
                      </div>
                    </div>
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">Token 上限字段</div>
                      <div className="font-mono text-slate-200 mt-0.5 truncate">
                        {selectedGateway.max_tokens_field}
                        {selectedGateway.max_tokens_cap
                          ? ` ≤ ${selectedGateway.max_tokens_cap}`
                          : " (不限)"}
                      </div>
                    </div>
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">System 拍平 / 裁剪</div>
                      <div className="font-mono text-slate-200 mt-0.5">
                        {selectedGateway.flatten_system_content ? "拍平" : "原样"} ·{" "}
                        {selectedGateway.strip_stream_options ? "去 stream_opt" : "保留"}
                      </div>
                    </div>
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">400 自适应降级</div>
                      <div
                        className={`font-mono mt-0.5 ${
                          selectedGateway.adaptive_400_fallback
                            ? "text-emerald-400"
                            : "text-slate-400"
                        }`}
                      >
                        {selectedGateway.adaptive_400_fallback ? "已开启" : "关闭"}
                      </div>
                    </div>
                    <div className="rounded-md bg-slate-900/80 border border-slate-800/80 px-2.5 py-1.5">
                      <div className="text-slate-500">超时 / 自定义头</div>
                      <div className="font-mono text-slate-200 mt-0.5">
                        {selectedGateway.timeout_s}s · {selectedGateway.extra_headers.length} 头
                      </div>
                    </div>
                  </div>

                  {showJsonSnippet && (
                    <div className="relative rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <button
                        type="button"
                        onClick={() => handleCopyText("json", jsonSnippet)}
                        className="absolute top-2 right-2 inline-flex items-center gap-1 rounded border border-slate-800 bg-slate-900 hover:bg-slate-800 px-2 py-1 text-[10px] text-slate-300 cursor-pointer"
                      >
                        {copiedKey === "json" ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            已复制
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            复制脱敏 JSON
                          </>
                        )}
                      </button>
                      <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto pr-20">
                        {jsonSnippet}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Collapsible Architecture & Synergy Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <button
          type="button"
          onClick={() => setShowArchCard((v) => !v)}
          className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-900/90 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Shield className="w-4 h-4 text-sky-400" />
            <span>项目协同闭环：工作台 ↔ gateways.json ↔ Telegram /model ↔ 故障回退 ↔ 用量账单</span>
          </div>
          {showArchCard ? (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
        </button>

        {showArchCard && (
          <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 space-y-3 text-xs text-slate-300">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-2.5">
              {[
                {
                  step: "1. 统一配置源",
                  detail:
                    "通过 gateways.json 集中定义中转站，Bridge 启动内嵌回环适配代理 (127.0.0.1:0/g/<token>/v1)，密钥不透传给子进程。",
                },
                {
                  step: "2. WebUI 工作台",
                  detail:
                    "自动按 [供应商] 分组展示模型下拉，选定后通过 gw:<id>:<model> 精确路由，避免同名模型冲突。",
                },
                {
                  step: "3. Telegram /model",
                  detail:
                    "所有多 Bot 实例共享同一套中转站模型目录，私聊、群聊与 Bot 团队默认模型均可一键切换。",
                },
                {
                  step: "4. 故障回退链",
                  detail:
                    "配合 model_failover 与 400 自适应降级，主站限流或协议报错时自动无感回退至备选中转站或原生模型。",
                },
                {
                  step: "5. 用量账单归集",
                  detail:
                    "用量账本按 gateway:<id> 模型家族归集 Token 与估算费用，便于评估不同中转站性价比。",
                },
              ].map((card) => (
                <div
                  key={card.step}
                  className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-1"
                >
                  <div className="font-semibold text-sky-300 text-[11px]">{card.step}</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{card.detail}</p>
                </div>
              ))}
            </div>
            <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-x-4 gap-y-1">
              <span>下一阶段可扩展方向：</span>
              <span className="text-slate-300">• 全局故障回退链（model_failover）可视化排序</span>
              <span className="text-slate-300">• 按站点维度的可用率 / 延迟 / 账单下钻</span>
              <span className="text-slate-300">• OpenBao 密钥直连引用（免明文落盘）</span>
            </div>
          </div>
        )}
      </div>

      {/* Add / Edit Gateway Modal */}
      {editor && !isReadonly && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-5"
          onClick={() => setEditor(null)}
        >
          <div
            className="w-full max-w-3xl max-h-[90vh] rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between gap-2 bg-slate-950/60">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {editor.mode === "create"
                    ? "添加外部中转站"
                    : editor.editingLiveOrigin
                      ? `调整预演配置 · ${editor.name}`
                      : `编辑中转站 · ${editor.name}`}
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  3 步完成中转站接入；选择方言模板后自动预设兼容参数，一般无需修改高级区
                </p>
              </div>
              <button
                type="button"
                onClick={() => setEditor(null)}
                aria-label="关闭弹窗"
                className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              {editorError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 flex items-center gap-2 text-xs text-rose-200">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{editorError}</span>
                </div>
              )}

              {/* Step 1: 9 Dialect Templates */}
              <section className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200">
                    1. 选择中转站类型 / 方言预设（9 种内置适配器）
                  </span>
                  <span className="text-[11px] font-mono text-sky-400">
                    dialect: {editor.dialect}
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {DIALECT_PRESETS.map((preset) => {
                    const active = editor.dialect === preset.id;
                    return (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => applyDialectTemplate(preset.id)}
                        className={`text-left rounded-xl border p-2.5 transition-colors cursor-pointer ${
                          active
                            ? "border-sky-500/60 bg-sky-500/15 text-sky-100"
                            : "border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-300"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-xs font-semibold truncate">
                            {preset.label}
                          </span>
                          {active && <Check className="w-3.5 h-3.5 text-sky-400 shrink-0" />}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-1 line-clamp-2 leading-snug">
                          {preset.tagline}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </section>

              {/* Step 2: Core Required Fields */}
              <section className="space-y-3 pt-2 border-t border-slate-800/80">
                <div className="text-xs font-semibold text-slate-200">
                  2. 核心连接与凭证信息
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] text-slate-300">
                      显示名称 <span className="text-rose-400">*</span>
                    </label>
                    <input
                      type="text"
                      value={editor.name}
                      onChange={(e) => {
                        const val = e.target.value;
                        setEditor((cur) => {
                          if (!cur) return cur;
                          return {
                            ...cur,
                            name: val,
                            id:
                              cur.mode === "create" && !cur.idTouched
                                ? slugifyGatewayId(val)
                                : cur.id,
                          };
                        });
                      }}
                      placeholder="例：New API 主站 / OpenRouter"
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] text-slate-300 flex items-center justify-between">
                      <span>
                        站点 ID (slug) <span className="text-rose-400">*</span>
                      </span>
                      <span className="font-mono text-[10px] text-slate-500">
                        ^[a-z0-9][a-z0-9_-]&#123;0,31&#125;$
                      </span>
                    </label>
                    <input
                      type="text"
                      disabled={editor.mode === "edit"}
                      value={editor.id}
                      onChange={(e) =>
                        setEditor((cur) =>
                          cur
                            ? {
                                ...cur,
                                id: e.target.value.toLowerCase(),
                                idTouched: true,
                              }
                            : cur,
                        )
                      }
                      placeholder="自动生成，如 new-api"
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 disabled:opacity-60 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-300 flex items-center justify-between">
                    <span>
                      Base URL <span className="text-rose-400">*</span>
                    </span>
                    <span className="text-[10px] text-slate-500">
                      仅支持 http(s)://，未带路径时自动拼接 /v1
                    </span>
                  </label>
                  <input
                    type="url"
                    value={editor.base_url}
                    onChange={(e) =>
                      setEditor((cur) => (cur ? { ...cur, base_url: e.target.value } : cur))
                    }
                    placeholder={getDialectPreset(editor.dialect).placeholderUrl}
                    className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                  />
                </div>

                {/* Credential Source Switch (Strict No-RCE, No Plaintext LocalStorage) */}
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <label className="text-[11px] text-slate-300">凭证来源</label>
                    {editor.credential_kind !== "server_cmd_readonly" && (
                      <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() =>
                            setEditor((cur) =>
                              cur ? { ...cur, credential_kind: "api_key" } : cur,
                            )
                          }
                          className={`px-2.5 py-1 rounded-md cursor-pointer ${
                            editor.credential_kind === "api_key"
                              ? "bg-sky-600 text-white"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          API Key
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setEditor((cur) =>
                              cur ? { ...cur, credential_kind: "api_key_env" } : cur,
                            )
                          }
                          className={`px-2.5 py-1 rounded-md cursor-pointer ${
                            editor.credential_kind === "api_key_env"
                              ? "bg-sky-600 text-white"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          环境变量 (api_key_env)
                        </button>
                      </div>
                    )}
                  </div>

                  {editor.credential_kind === "server_cmd_readonly" ? (
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2.5 flex items-center justify-between gap-2 text-xs text-emerald-200">
                      <span className="inline-flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        服务端命令凭证（只读 · OpenBao/主机托管，前端禁止编辑命令防 RCE）
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          setEditor((cur) =>
                            cur ? { ...cur, credential_kind: "api_key_env" } : cur,
                          )
                        }
                        className="shrink-0 text-[11px] underline text-emerald-300 hover:text-emerald-100 cursor-pointer"
                      >
                        改用环境变量
                      </button>
                    </div>
                  ) : editor.credential_kind === "api_key" ? (
                    <div className="space-y-1.5">
                      <input
                        type="password"
                        autoComplete="off"
                        value={editor.api_key_input}
                        onChange={(e) =>
                          setEditor((cur) =>
                            cur ? { ...cur, api_key_input: e.target.value } : cur,
                          )
                        }
                        placeholder={
                          editor.api_key_masked_existing
                            ? `已脱敏保存（${editor.api_key_masked_existing}），留空保持不变`
                            : "输入 sk-... 密钥（预演态仅保留脱敏掩码）"
                        }
                        className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                      />
                      <p className="text-[11px] text-amber-300/90">
                        安全保护：前端预演绝不将明文 API Key 存入浏览器 localStorage（保存时立即脱敏为 [REDACTED]）；接入后端 API 后将写入受保护配置 / OpenBao。
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-1">
                      <input
                        type="text"
                        value={editor.api_key_env}
                        onChange={(e) =>
                          setEditor((cur) =>
                            cur ? { ...cur, api_key_env: e.target.value.toUpperCase() } : cur,
                          )
                        }
                        placeholder="例：NEW_API_KEY 或 OPENROUTER_API_KEY"
                        className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                      />
                      <p className="text-[11px] text-slate-500">
                        Bridge 运行时从宿主环境或 systemd EnvironmentFile 读取该变量，推荐生产环境使用。
                      </p>
                    </div>
                  )}
                </div>
              </section>

              {/* Step 3: Model Filtering & Live Preview */}
              <section className="space-y-3 pt-2 border-t border-slate-800/80">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-200">
                    3. 模型过滤与静态兜底目录
                  </span>
                  <button
                    type="button"
                    disabled={editorProbing}
                    onClick={handleEditorProbe}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/15 hover:bg-sky-500/25 px-2.5 py-1 text-[11px] font-medium text-sky-200 disabled:opacity-50 cursor-pointer"
                  >
                    {editorProbing ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Play className="w-3 h-3" />
                    )}
                    测试连通 & 拉取模型
                  </button>
                </div>

                {editorProbeMsg && (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-200">
                    {editorProbeMsg}
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] text-slate-300">
                      白名单 include_models（逗号分隔 glob）
                    </label>
                    <input
                      type="text"
                      value={editor.include_models_text}
                      onChange={(e) =>
                        setEditor((cur) =>
                          cur ? { ...cur, include_models_text: e.target.value } : cur,
                        )
                      }
                      placeholder="例：team/*, claude-*, gpt-5*"
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] text-slate-300">
                      黑名单 exclude_models（逗号分隔 glob）
                    </label>
                    <input
                      type="text"
                      value={editor.exclude_models_text}
                      onChange={(e) =>
                        setEditor((cur) =>
                          cur ? { ...cur, exclude_models_text: e.target.value } : cur,
                        )
                      }
                      placeholder="例：*-image-*, *-embedding-*"
                      className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-300">
                    手动静态兜底模型 models（针对未开放 /v1/models 的站点，逗号或换行分隔）
                  </label>
                  <input
                    type="text"
                    value={editor.static_models_text}
                    onChange={(e) =>
                      setEditor((cur) =>
                        cur ? { ...cur, static_models_text: e.target.value } : cur,
                      )
                    }
                    placeholder="例：ep-20250501-xxxxx, custom-claude-sonnet"
                    className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-sky-500"
                  />
                </div>

                {/* Live Filter Preview inside Editor */}
                <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="inline-flex items-center gap-1.5 text-slate-300 font-medium">
                      <Eye className="w-3.5 h-3.5 text-sky-400" />
                      工作台 / Telegram 暴露预览
                    </span>
                    <span className="font-mono text-emerald-400">
                      {editorFilterPreview.exposedCount} / {editorFilterPreview.totalCount} 将暴露
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                    {editorFilterPreview.rows.map((row) => (
                      <span
                        key={row.modelId}
                        className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                          row.matched
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                            : "border-slate-800 bg-slate-900 text-slate-500 line-through"
                        }`}
                      >
                        {row.displayLabel}
                      </span>
                    ))}
                  </div>
                </div>
              </section>

              {/* Collapsible Advanced Dialect Adaptation */}
              <section className="rounded-xl border border-slate-800 bg-slate-950/40 overflow-hidden">
                <button
                  type="button"
                  onClick={() =>
                    setEditor((cur) =>
                      cur ? { ...cur, advancedOpen: !cur.advancedOpen } : cur,
                    )
                  }
                  className="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-medium text-slate-300 hover:bg-slate-900/70 cursor-pointer"
                >
                  <span className="inline-flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-sky-400" />
                    高级协议适配（默认随方言模板自动预设）
                  </span>
                  {editor.advancedOpen ? (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-slate-400" />
                  )}
                </button>

                {editor.advancedOpen && (
                  <div className="p-3.5 border-t border-slate-800 space-y-3.5 text-xs">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="space-y-1">
                        <label className="text-[11px] text-slate-400">effort_mode</label>
                        <select
                          value={editor.effort_mode}
                          onChange={(e) =>
                            setEditor((cur) =>
                              cur
                                ? { ...cur, effort_mode: e.target.value as EffortMode }
                                : cur,
                            )
                          }
                          className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                        >
                          <option value="body">body (标准字段)</option>
                          <option value="model_paren">model_paren (2API 括号)</option>
                          <option value="none">none (不发送)</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <label className="text-[11px] text-slate-400">max_tokens_field</label>
                        <select
                          value={editor.max_tokens_field}
                          onChange={(e) =>
                            setEditor((cur) =>
                              cur
                                ? {
                                    ...cur,
                                    max_tokens_field: e.target.value as MaxTokensField,
                                  }
                                : cur,
                            )
                          }
                          className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                        >
                          <option value="max_tokens">max_tokens</option>
                          <option value="max_completion_tokens">max_completion_tokens</option>
                          <option value="omit">omit (省略不发)</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <label className="text-[11px] text-slate-400">
                          max_tokens_cap（空=不限）
                        </label>
                        <input
                          type="number"
                          min={1}
                          value={editor.max_tokens_cap_text}
                          onChange={(e) =>
                            setEditor((cur) =>
                              cur ? { ...cur, max_tokens_cap_text: e.target.value } : cur,
                            )
                          }
                          placeholder="16384"
                          className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      {(
                        [
                          [
                            "supports_reasoning_effort",
                            "支持推理强度 (supports_reasoning_effort)",
                          ],
                          [
                            "flatten_system_content",
                            "拍平多段 system 消息 (flatten_system_content)",
                          ],
                          [
                            "strip_stream_options",
                            "移除 stream_options (strip_stream_options)",
                          ],
                          [
                            "adaptive_400_fallback",
                            "400 错误自适应降级重试 (adaptive_400_fallback)",
                          ],
                        ] as const
                      ).map(([field, label]) => (
                        <label
                          key={field}
                          className="flex items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-2 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={editor[field]}
                            onChange={(e) =>
                              setEditor((cur) =>
                                cur ? { ...cur, [field]: e.target.checked } : cur,
                              )
                            }
                            className="rounded border-slate-700 bg-slate-950 text-sky-500 focus:ring-sky-500"
                          />
                          <span className="text-[11px] text-slate-200">{label}</span>
                        </label>
                      ))}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-[11px] text-slate-400">
                          请求超时 timeout_s（秒）
                        </label>
                        <input
                          type="number"
                          min={5}
                          max={1800}
                          value={editor.timeout_s_text}
                          onChange={(e) =>
                            setEditor((cur) =>
                              cur ? { ...cur, timeout_s_text: e.target.value } : cur,
                            )
                          }
                          className="w-full rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                        />
                      </div>
                      <label className="flex items-center gap-2 self-end rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={editor.enabled}
                          onChange={(e) =>
                            setEditor((cur) =>
                              cur ? { ...cur, enabled: e.target.checked } : cur,
                            )
                          }
                          className="rounded border-slate-700 bg-slate-950 text-emerald-500"
                        />
                        <span className="text-[11px] text-slate-200">保存后立即启用站点</span>
                      </label>
                    </div>

                    {/* Custom Extra Headers */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] text-slate-400">
                          自定义请求头 (extra_headers，如 HTTP-Referer / X-Title)
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            setEditor((cur) =>
                              cur
                                ? {
                                    ...cur,
                                    extra_headers: [
                                      ...cur.extra_headers,
                                      { key: "", value: "" },
                                    ],
                                  }
                                : cur,
                            )
                          }
                          className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                        >
                          <Plus className="w-3 h-3" />
                          添加请求头
                        </button>
                      </div>
                      {editor.extra_headers.length > 0 && (
                        <div className="space-y-1.5">
                          {editor.extra_headers.map((pair, idx) => (
                            <div key={idx} className="flex items-center gap-2">
                              <input
                                type="text"
                                value={pair.key}
                                onChange={(e) =>
                                  setEditor((cur) => {
                                    if (!cur) return cur;
                                    const next = [...cur.extra_headers];
                                    next[idx] = { ...next[idx], key: e.target.value };
                                    return { ...cur, extra_headers: next };
                                  })
                                }
                                placeholder="Header 名称"
                                className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                              />
                              <input
                                type="text"
                                value={pair.value}
                                onChange={(e) =>
                                  setEditor((cur) => {
                                    if (!cur) return cur;
                                    const next = [...cur.extra_headers];
                                    next[idx] = { ...next[idx], value: e.target.value };
                                    return { ...cur, extra_headers: next };
                                  })
                                }
                                placeholder="Header 值"
                                className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
                              />
                              <button
                                type="button"
                                onClick={() =>
                                  setEditor((cur) => {
                                    if (!cur) return cur;
                                    return {
                                      ...cur,
                                      extra_headers: cur.extra_headers.filter((_, i) => i !== idx),
                                    };
                                  })
                                }
                                aria-label="删除请求头"
                                className="p-1 rounded text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </section>
            </div>

            {/* Modal Footer */}
            <div className="px-5 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setEditor(null)}
                className="rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3.5 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                onClick={handleSaveEditor}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                保存到预演列表
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Controlled Delete Confirmation Modal */}
      {deleteTarget && !isReadonly && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4"
          onClick={() => setDeleteTarget(null)}
        >
          <div
            className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-5 space-y-4 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start gap-3">
              <div className="rounded-xl bg-rose-500/15 p-2 text-rose-400 shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-slate-100">
                  确认移除中转站「{deleteTarget.name}」？
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {deleteTarget.source === "live"
                    ? `站点 ${deleteTarget.id} 当前由后端 gateways.json 托管。预演阶段不会修改服务器文件，正式接入后端 API 后移除将同步刷新模型目录。`
                    : `将从当前预演配置中移除站点 ${deleteTarget.id} 及其过滤规则。`}
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3.5 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                className="rounded-lg bg-rose-600 hover:bg-rose-500 px-3.5 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                {deleteTarget.source === "live" ? "知道了" : "确认移除"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
