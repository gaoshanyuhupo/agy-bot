import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  Copy,
  Edit3,
  FileText,
  KeyRound,
  Lock,
  Network,
  Plus,
  RefreshCw,
  RotateCw,
  Server,
  Shield,
  ShieldAlert,
  Trash2,
  Users,
  X,
} from "lucide-react";
import {
  StudioApiError,
  createFederationAgent,
  createFederationTeam,
  deleteFederationAgent,
  deleteFederationTeam,
  fetchFederationAudit,
  fetchFederationHealth,
  fetchFederationOverview,
  mintFederationAgentToken,
  revokeFederationAgent,
  rotateFederationAgentToken,
  setFederationTeamLeader,
  updateFederationAgent,
  updateFederationTeam,
} from "../api";
import type {
  FederationAgentItem,
  FederationAgentKind,
  FederationAuditEntry,
  FederationOverviewResponse,
  FederationTeamItem,
  StudioSession,
} from "../types";

interface FederationViewProps {
  session: StudioSession;
  eventVersion?: number;
  onSessionRevoked?: (reason: string) => void;
}

interface OneTimeTokenModalState {
  agentId: string;
  tokenId: string;
  tokenValue: string;
  actionLabel: string;
  revokedPrevious?: number;
}

type SubTab = "agents" | "teams" | "audit";

const AGENT_KIND_OPTIONS: {
  value: FederationAgentKind;
  label: string;
  desc: string;
  needsProfile: boolean;
  needsEndpoint: boolean;
}[] = [
  {
    value: "hermes_local",
    label: "Hermes 本机多 Profile",
    desc: "直连本机 hermes -p <profile> 多实例并行",
    needsProfile: true,
    needsEndpoint: false,
  },
  {
    value: "hermes_remote",
    label: "Hermes 独立服务器",
    desc: "远程独立 Hermes 节点（支持 /p/<profile> 多实例路由）",
    needsProfile: false,
    needsEndpoint: true,
  },
  {
    value: "muse_remote",
    label: "Muse 外部 Agent",
    desc: "远程 Muse / OpenAI 兼容推流外部 Agent",
    needsProfile: false,
    needsEndpoint: true,
  },
  {
    value: "http_a2a",
    label: "HTTP / A2A 外部节点",
    desc: "标准 HTTP Push / A2A 双向联邦外部 Agent",
    needsProfile: false,
    needsEndpoint: true,
  },
  {
    value: "pull_worker",
    label: "NAT Pull Worker",
    desc: "无公网入口，内网主动向 Hub 拉取并回传任务",
    needsProfile: false,
    needsEndpoint: false,
  },
  {
    value: "agy_local",
    label: "AGY 本机 Bot",
    desc: "纳入多团队编排的本机 Antigravity Bot",
    needsProfile: false,
    needsEndpoint: false,
  },
  {
    value: "mcp_inbound_only",
    label: "仅入站 MCP Agent",
    desc: "仅通过 MCP / REST 主动接入 Hub 的外部 Agent",
    needsProfile: false,
    needsEndpoint: false,
  },
];

const TRUST_LEVEL_OPTIONS = [
  { value: "remote_trusted", label: "remote_trusted（受信任外部）" },
  { value: "local_worker", label: "local_worker（本机工作节点）" },
  { value: "local_admin", label: "local_admin（本机管理级）" },
  { value: "remote_untrusted", label: "remote_untrusted（受限外部）" },
  { value: "readonly_guest", label: "readonly_guest（只读访客）" },
];

function parseCsvIds(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[,\s]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    ),
  );
}

function formatTs(ts?: number): string {
  if (!ts || !Number.isFinite(ts)) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

export function FederationView({
  session,
  eventVersion = 0,
  onSessionRevoked,
}: FederationViewProps) {
  const isAdmin = session.role === "admin";
  const [subTab, setSubTab] = useState<SubTab>("agents");
  const [overview, setOverview] = useState<FederationOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshingHealth, setRefreshingHealth] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [teamWarnings, setTeamWarnings] = useState<string[]>([]);

  // Ephemeral in-memory only one-time token modal state (NEVER persisted)
  const [oneTimeToken, setOneTimeToken] = useState<OneTimeTokenModalState | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Agent form modal state
  const [agentModalOpen, setAgentModalOpen] = useState(false);
  const [editingAgentId, setEditingAgentId] = useState<string | null>(null);
  const [agentIdInput, setAgentIdInput] = useState("");
  const [displayNameInput, setDisplayNameInput] = useState("");
  const [kindInput, setKindInput] = useState<FederationAgentKind>("hermes_local");
  const [profileInput, setProfileInput] = useState("default");
  const [endpointInput, setEndpointInput] = useState("");
  const [secretRefInput, setSecretRefInput] = useState("");
  const [trustLevelInput, setTrustLevelInput] = useState("remote_trusted");
  const [enabledInput, setEnabledInput] = useState(true);
  const [coordPeerInput, setCoordPeerInput] = useState(false);
  const [hostInvokeInput, setHostInvokeInput] = useState(false);
  const [canDispatchInput, setCanDispatchInput] = useState(false);
  const [canReceiveInput, setCanReceiveInput] = useState(true);
  const [allowedTeamsInput, setAllowedTeamsInput] = useState("");
  const [autoMint, setAutoMint] = useState(true);

  // Team form modal state
  const [teamModalOpen, setTeamModalOpen] = useState(false);
  const [editingTeamId, setEditingTeamId] = useState<string | null>(null);
  const [teamIdInput, setTeamIdInput] = useState("");
  const [teamNameInput, setTeamNameInput] = useState("");
  const [teamLeaderInput, setTeamLeaderInput] = useState("");
  const [teamCoLeadersInput, setTeamCoLeadersInput] = useState("");
  const [teamMembersInput, setTeamMembersInput] = useState("");

  // Audit state (Admin only)
  const [auditEntries, setAuditEntries] = useState<FederationAuditEntry[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditLimit] = useState(50);
  const [auditActorFilter, setAuditActorFilter] = useState("");
  const [auditLoading, setAuditLoading] = useState(false);

  // Zero out one-time token on unmount
  useEffect(() => {
    return () => {
      setOneTimeToken(null);
    };
  }, []);

  const handleSubTabChange = (next: SubTab) => {
    setOneTimeToken(null);
    setSubTab(next);
  };

  const handleApiError = useCallback(
    (err: unknown, fallback: string) => {
      if (err instanceof StudioApiError) {
        if (err.status === 401 || (err.status === 403 && err.source === "studio_auth" && err.message.includes("会话"))) {
          onSessionRevoked?.(err.message);
        }
        setError(err.message || fallback);
        return;
      }
      setError(err instanceof Error ? err.message : fallback);
    },
    [onSessionRevoked],
  );

  const loadOverview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchFederationOverview();
      setOverview(data);
    } catch (err) {
      handleApiError(err, "加载联邦总览失败");
    } finally {
      setLoading(false);
    }
  }, [handleApiError]);

  const loadAudit = useCallback(
    async (offsetVal = auditOffset, actorVal = auditActorFilter) => {
      if (!isAdmin) return;
      setAuditLoading(true);
      try {
        const res = await fetchFederationAudit({
          limit: auditLimit,
          offset: offsetVal,
          actor_id: actorVal.trim() || undefined,
        });
        setAuditEntries(res.entries || []);
        setAuditTotal(res.total || 0);
      } catch (err) {
        handleApiError(err, "加载联邦审计日志失败");
      } finally {
        setAuditLoading(false);
      }
    },
    [auditActorFilter, auditLimit, auditOffset, handleApiError, isAdmin],
  );

  useEffect(() => {
    void loadOverview();
  }, [loadOverview, eventVersion]);

  useEffect(() => {
    if (subTab === "audit" && isAdmin) {
      void loadAudit(auditOffset, auditActorFilter);
    }
  }, [subTab, isAdmin, auditOffset, auditActorFilter, loadAudit]);

  const activeRegisteredAgents = useMemo(
    () => (overview?.agents || []).filter((a) => !a.revoked),
    [overview],
  );

  const handleRefreshHealth = async () => {
    setRefreshingHealth(true);
    try {
      const h = await fetchFederationHealth();
      setOverview((prev) => (prev ? { ...prev, hub_health: h } : prev));
    } catch (err) {
      handleApiError(err, "探测 Hub 健康状态失败");
    } finally {
      setRefreshingHealth(false);
    }
  };

  const openCreateAgentModal = () => {
    setEditingAgentId(null);
    setAgentIdInput("");
    setDisplayNameInput("");
    setKindInput("hermes_local");
    setProfileInput("default");
    setEndpointInput("");
    setSecretRefInput("");
    setTrustLevelInput("remote_trusted");
    setEnabledInput(true);
    setCoordPeerInput(false);
    setHostInvokeInput(false);
    setCanDispatchInput(false);
    setCanReceiveInput(true);
    setAllowedTeamsInput("");
    setAutoMint(true);
    setAgentModalOpen(true);
  };

  const openEditAgentModal = (agent: FederationAgentItem) => {
    setEditingAgentId(agent.agent_id);
    setAgentIdInput(agent.agent_id);
    setDisplayNameInput(agent.display_name || agent.agent_id);
    const derivedKind: FederationAgentKind =
      agent.transport === "pull_worker" || agent.driver === "pull_worker"
        ? "pull_worker"
        : ((agent.kind as FederationAgentKind) || "http_a2a");
    setKindInput(derivedKind);
    setProfileInput(agent.profile || "");
    setEndpointInput(agent.endpoint_url || "");
    setSecretRefInput(agent.secret_ref || "");
    setTrustLevelInput(agent.trust_level || "remote_trusted");
    setEnabledInput(Boolean(agent.enabled));
    setCoordPeerInput(Boolean(agent.capabilities?.coordinator_peer));
    setHostInvokeInput(Boolean(agent.capabilities?.host_server_invoke));
    setCanDispatchInput(Boolean(agent.capabilities?.can_dispatch));
    setCanReceiveInput(Boolean(agent.capabilities?.can_receive ?? true));
    setAllowedTeamsInput((agent.capabilities?.allowed_teams || []).join(", "));
    setAutoMint(false);
    setAgentModalOpen(true);
  };

  const handleSubmitAgent = async () => {
    if (!isAdmin) return;
    setBusyKey("agent-submit");
    setError(null);
    setNotice(null);
    try {
      const capabilities = {
        coordinator_peer: coordPeerInput,
        host_server_invoke: hostInvokeInput,
        can_dispatch: canDispatchInput,
        can_receive: canReceiveInput,
        allowed_teams: parseCsvIds(allowedTeamsInput),
      };
      if (editingAgentId) {
        await updateFederationAgent(editingAgentId, {
          display_name: displayNameInput.trim() || editingAgentId,
          kind: kindInput,
          profile: profileInput.trim(),
          endpoint_url: endpointInput.trim(),
          secret_ref: secretRefInput.trim(),
          trust_level: trustLevelInput,
          enabled: enabledInput,
          capabilities,
        });
        setNotice(`已更新外部 Agent: ${editingAgentId}`);
      } else {
        const res = await createFederationAgent({
          agent_id: agentIdInput.trim().toLowerCase(),
          display_name: displayNameInput.trim() || undefined,
          kind: kindInput,
          profile: profileInput.trim() || undefined,
          endpoint_url: endpointInput.trim() || undefined,
          secret_ref: secretRefInput.trim() || undefined,
          trust_level: trustLevelInput,
          enabled: enabledInput,
          capabilities,
          mint_token: autoMint,
          token_label: "studio-initial",
        });
        setNotice(`已注册外部 Agent: ${res.agent.agent_id}`);
        if (res.token && res.token_id) {
          setOneTimeToken({
            agentId: res.agent.agent_id,
            tokenId: res.token_id,
            tokenValue: res.token,
            actionLabel: "初始签发",
          });
        }
      }
      setAgentModalOpen(false);
      await loadOverview();
    } catch (err) {
      handleApiError(err, "保存 Agent 失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleQuickToggleCapability = async (
    agent: FederationAgentItem,
    capKey: "coordinator_peer" | "host_server_invoke" | "can_dispatch" | "can_receive",
  ) => {
    if (!isAdmin || agent.revoked) return;
    setBusyKey(`cap:${agent.agent_id}:${capKey}`);
    setError(null);
    try {
      const nextCaps = {
        ...agent.capabilities,
        [capKey]: !agent.capabilities[capKey],
      };
      await updateFederationAgent(agent.agent_id, { capabilities: nextCaps });
      setNotice(`已更新 ${agent.agent_id} 权限 ${capKey}=${String(nextCaps[capKey])}`);
      await loadOverview();
    } catch (err) {
      handleApiError(err, "更新 Agent 权限失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleMintToken = async (agentId: string) => {
    if (!isAdmin) return;
    setBusyKey(`mint:${agentId}`);
    setError(null);
    try {
      const res = await mintFederationAgentToken(agentId, "studio-mint");
      setOneTimeToken({
        agentId: res.agent_id,
        tokenId: res.token_id,
        tokenValue: res.token,
        actionLabel: "新增签发",
      });
      await loadOverview();
    } catch (err) {
      handleApiError(err, "签发 Token 失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleRotateToken = async (agentId: string) => {
    if (!isAdmin) return;
    setBusyKey(`rotate:${agentId}`);
    setError(null);
    try {
      const res = await rotateFederationAgentToken(agentId, {
        label: "studio-rotated",
        revoke_existing: true,
      });
      setOneTimeToken({
        agentId: res.agent_id,
        tokenId: res.token_id,
        tokenValue: res.token,
        actionLabel: "轮换并作废旧凭据",
        revokedPrevious: res.revoked_previous,
      });
      await loadOverview();
    } catch (err) {
      handleApiError(err, "轮换 Token 失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleRevokeAgent = async (agentId: string) => {
    if (!isAdmin) return;
    setBusyKey(`revoke:${agentId}`);
    setError(null);
    try {
      await revokeFederationAgent(agentId);
      setNotice(`已触发 Kill-Switch：${agentId} 已即时吊销并作废全部 Token`);
      await loadOverview();
    } catch (err) {
      handleApiError(err, "吊销 Agent 失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleDeleteAgent = async (agentId: string) => {
    if (!isAdmin) return;
    setBusyKey(`delete:${agentId}`);
    setError(null);
    try {
      await deleteFederationAgent(agentId);
      setNotice(`已删除 Agent: ${agentId}`);
      await loadOverview();
    } catch (err) {
      handleApiError(err, "删除 Agent 失败");
    } finally {
      setBusyKey(null);
    }
  };

  const openCreateTeamModal = () => {
    setEditingTeamId(null);
    setTeamIdInput("");
    setTeamNameInput("");
    setTeamLeaderInput(activeRegisteredAgents[0]?.agent_id || "");
    setTeamCoLeadersInput("");
    setTeamMembersInput("");
    setTeamModalOpen(true);
  };

  const openEditTeamModal = (team: FederationTeamItem) => {
    setEditingTeamId(team.team_id);
    setTeamIdInput(team.team_id);
    setTeamNameInput(team.display_name || team.team_id);
    setTeamLeaderInput(team.leader_agent_id || "");
    setTeamCoLeadersInput((team.co_leaders || []).join(", "));
    setTeamMembersInput((team.members || []).join(", "));
    setTeamModalOpen(true);
  };

  const handleSubmitTeam = async () => {
    if (!isAdmin) return;
    setBusyKey("team-submit");
    setError(null);
    setNotice(null);
    setTeamWarnings([]);
    try {
      const coLeaders = parseCsvIds(teamCoLeadersInput);
      const members = parseCsvIds(teamMembersInput);
      const res = editingTeamId
        ? await updateFederationTeam(editingTeamId, {
            display_name: teamNameInput.trim() || editingTeamId,
            leader_agent_id: teamLeaderInput.trim(),
            co_leaders: coLeaders,
            members,
          })
        : await createFederationTeam({
            team_id: teamIdInput.trim().toLowerCase(),
            display_name: teamNameInput.trim() || undefined,
            leader_agent_id: teamLeaderInput.trim() || undefined,
            co_leaders: coLeaders,
            members,
          });
      setTeamModalOpen(false);
      setNotice(
        editingTeamId ? `已更新团队 ${res.team.team_id}` : `已创建团队 ${res.team.team_id}`,
      );
      if (res.warnings && res.warnings.length > 0) {
        setTeamWarnings(res.warnings);
      }
      await loadOverview();
    } catch (err) {
      handleApiError(err, "保存团队失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleQuickLeaderChange = async (team: FederationTeamItem, nextLeaderId: string) => {
    if (!isAdmin || !nextLeaderId || nextLeaderId === team.leader_agent_id) return;
    setBusyKey(`leader:${team.team_id}`);
    setError(null);
    setTeamWarnings([]);
    try {
      const res = await setFederationTeamLeader(team.team_id, {
        leader_agent_id: nextLeaderId,
      });
      setNotice(`团队 ${team.team_id} 负责人已切换为 ${nextLeaderId}`);
      if (res.warnings && res.warnings.length > 0) {
        setTeamWarnings(res.warnings);
      }
      await loadOverview();
    } catch (err) {
      handleApiError(err, "切换团队负责人失败");
    } finally {
      setBusyKey(null);
    }
  };

  const handleDeleteTeam = async (teamId: string) => {
    if (!isAdmin) return;
    setBusyKey(`team-del:${teamId}`);
    setError(null);
    try {
      await deleteFederationTeam(teamId);
      setNotice(`已删除团队 ${teamId}`);
      await loadOverview();
    } catch (err) {
      handleApiError(err, "删除团队失败");
    } finally {
      setBusyKey(null);
    }
  };

  const copyText = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(key);
      window.setTimeout(() => setCopiedField(null), 1800);
    } catch {
      setError("剪贴板复制失败，请手动选中复制");
    }
  };

  const hubHealth = overview?.hub_health;
  const hubMcpUrl = overview?.hub_config?.mcp_url || "http://127.0.0.1:18799/hub/mcp";

  const hermesStdioSnippet = oneTimeToken
    ? JSON.stringify(
        {
          mcpServers: {
            "agy-federation": {
              command: "python3",
              args: [
                "bridge/federation_mcp_stdio.py",
                "--hub-url",
                hubMcpUrl.replace(/\/hub\/mcp$/, ""),
                "--agent-id",
                oneTimeToken.agentId,
              ],
              env: {
                AGY_FEDERATION_TOKEN: oneTimeToken.tokenValue,
              },
            },
          },
        },
        null,
        2,
      )
    : "";

  const hermesStreamHttpSnippet = oneTimeToken
    ? JSON.stringify(
        {
          mcpServers: {
            "agy-federation-http": {
              url: hubMcpUrl,
              headers: {
                Authorization: `Bearer ${oneTimeToken.tokenValue}`,
              },
            },
          },
        },
        null,
        2,
      )
    : "";

  return (
    <div className="max-w-6xl mx-auto p-4 md:p-6 space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-sky-400" />
            外部 Agent 双向联邦控制面
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            管理多实例 Hermes / Muse / A2A / Pull Worker 联邦节点、多团队动态换帅、一次性 Token 与三把防自我提权硬锁。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void handleRefreshHealth()}
            disabled={refreshingHealth}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshingHealth ? "animate-spin" : ""}`} />
            探测 Hub
          </button>
          <button
            type="button"
            onClick={() => void loadOverview()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新全量
          </button>
        </div>
      </div>

      {/* Status & Summary Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400">本地回环 Hub 状态</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                hubHealth?.reachable
                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                  : "bg-amber-500/15 text-amber-300 border border-amber-500/30"
              }`}
            >
              {hubHealth?.reachable ? "HEALTHY" : (hubHealth?.status || "UNKNOWN").toUpperCase()}
            </span>
          </div>
          <div className="mt-2 font-mono text-xs text-slate-200">
            {overview?.hub_config?.loopback_valid
              ? `${overview.hub_config.host}:${overview.hub_config.port}`
              : "未配置合法回环端口"}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            延迟：{hubHealth?.latency_ms != null ? `${hubHealth.latency_ms} ms` : "-"} · 防 SSRF 硬绑定回环
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
          <div className="text-[11px] text-slate-400">联邦 Agent 节点</div>
          <div className="mt-1.5 text-xl font-semibold text-slate-100 font-mono">
            {overview?.counts.agents_enabled ?? 0}
            <span className="text-xs font-normal text-slate-400">
              {" "}
              / {overview?.counts.agents_total ?? 0} 启用
            </span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            已吊销：{overview?.counts.agents_revoked ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
          <div className="text-[11px] text-slate-400">高权能力分布</div>
          <div className="mt-1.5 flex items-center gap-3 text-xs text-slate-200">
            <span>平权总指挥: {overview?.counts.agents_coordinator_peer ?? 0}</span>
            <span>本机调用: {overview?.counts.agents_host_invoke ?? 0}</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400">所有高权仅限人类 Owner 显式授予</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3.5">
          <div className="text-[11px] text-slate-400">多团队编排</div>
          <div className="mt-1.5 text-xl font-semibold text-slate-100 font-mono">
            {overview?.counts.teams_total ?? 0}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">支持任意注册 Agent 担任动态 Leader</div>
        </div>
      </div>

      {/* Three Anti-Self-Escalation Hard Locks Banner */}
      <div className="rounded-xl border border-sky-500/25 bg-sky-950/20 p-4 space-y-2.5">
        <div className="flex items-center gap-2 text-xs font-semibold text-sky-300">
          <Lock className="w-4 h-4" />
          三把防自我提权硬锁（服务端强制执行，不可被任何外部 Agent 绕过）
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          {(overview?.hard_locks || []).map((lock) => (
            <div
              key={lock.id}
              className="rounded-lg border border-slate-800/90 bg-slate-950/60 p-2.5 space-y-1"
            >
              <div className="text-[11px] font-semibold text-slate-100">{lock.title}</div>
              <div className="text-[11px] text-slate-400 leading-relaxed">{lock.detail}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Alerts */}
      {!isAdmin && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          当前账号为只读权限（readonly），仅可查看脱敏后的联邦拓扑，所有写操作与 Token 签发已锁定。
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200 flex items-center justify-between gap-2">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} className="text-rose-300 cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {notice && (
        <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 px-3.5 py-2.5 text-xs text-emerald-200 flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            {notice}
          </span>
          <button type="button" onClick={() => setNotice(null)} className="text-emerald-300 cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
      {teamWarnings.length > 0 && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 space-y-1">
          <div className="font-semibold flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            最小权限安全提示（未执行静默自动提权）
          </div>
          {teamWarnings.map((w, idx) => (
            <div key={idx}>{w}</div>
          ))}
        </div>
      )}

      {/* Sub-navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => handleSubTabChange("agents")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
              subTab === "agents"
                ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            外部 Agent ({overview?.agents.length ?? 0})
          </button>
          <button
            type="button"
            onClick={() => handleSubTabChange("teams")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
              subTab === "teams"
                ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            多团队与负责人 ({overview?.teams.length ?? 0})
          </button>
          {isAdmin && (
            <button
              type="button"
              onClick={() => handleSubTabChange("audit")}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
                subTab === "audit"
                  ? "bg-sky-500/15 text-sky-300 border border-sky-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              Host Bridge 审计日志
            </button>
          )}
        </div>

        {isAdmin && subTab === "agents" && (
          <button
            type="button"
            onClick={openCreateAgentModal}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            注册外部 Agent
          </button>
        )}
        {isAdmin && subTab === "teams" && (
          <button
            type="button"
            onClick={openCreateTeamModal}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-xs font-medium text-white cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            新建联邦团队
          </button>
        )}
      </div>

      {/* Agents Section */}
      {subTab === "agents" && (
        <div className="space-y-3">
          {loading && !overview ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 text-center text-xs text-slate-400">
              正在加载外部 Agent 列表…
            </div>
          ) : (overview?.agents.length || 0) === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-8 text-center space-y-2">
              <div className="text-sm text-slate-300">尚未注册外部联邦 Agent</div>
              <div className="text-xs text-slate-500">
                支持注册本机多 Profile Hermes、独立服务器 Hermes（含 /p/&lt;profile&gt;）、Muse、HTTP/A2A 及 NAT Pull Worker。
              </div>
            </div>
          ) : (
            (overview?.agents || []).map((agent) => {
              const caps = agent.capabilities;
              return (
                <div
                  key={agent.agent_id}
                  className={`rounded-xl border p-4 space-y-3 ${
                    agent.revoked
                      ? "border-rose-500/35 bg-rose-950/15"
                      : "border-slate-800 bg-slate-900/70"
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-sm text-slate-100">
                          {agent.display_name || agent.agent_id}
                        </span>
                        <code className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-sky-300">
                          {agent.agent_id}
                        </code>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {agent.kind} / {agent.driver}
                        </span>
                        {agent.profile && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300">
                            profile:{agent.profile}
                          </span>
                        )}
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                            agent.revoked
                              ? "bg-rose-500/20 text-rose-300"
                              : agent.enabled
                                ? "bg-emerald-500/15 text-emerald-300"
                                : "bg-slate-700 text-slate-300"
                          }`}
                        >
                          {agent.revoked ? "REVOKED" : agent.enabled ? "ENABLED" : "DISABLED"}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                          Tokens: {agent.active_token_count}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-4 gap-y-1">
                        <span>传输: {agent.transport}</span>
                        <span>信任级: {agent.trust_level}</span>
                        {agent.endpoint_url && <span>端点: {agent.endpoint_url}</span>}
                        {agent.secret_ref ? (
                          <span>OpenBao Ref: {agent.secret_ref}</span>
                        ) : agent.has_secret_ref ? (
                          <span>OpenBao Ref: 已配置（仅管理员可见路径）</span>
                        ) : null}
                        {caps.allowed_teams.length > 0 && (
                          <span>限定团队: {caps.allowed_teams.join(", ")}</span>
                        )}
                      </div>
                    </div>

                    {isAdmin && (
                      <div className="flex flex-wrap items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => openEditAgentModal(agent)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 hover:bg-slate-800 px-2.5 py-1 text-[11px] text-slate-200 cursor-pointer"
                        >
                          <Edit3 className="w-3 h-3" />
                          编辑
                        </button>
                        {!agent.revoked && (
                          <>
                            <button
                              type="button"
                              disabled={busyKey === `mint:${agent.agent_id}`}
                              onClick={() => void handleMintToken(agent.agent_id)}
                              className="inline-flex items-center gap-1 rounded-lg border border-sky-500/40 bg-sky-500/10 hover:bg-sky-500/20 px-2.5 py-1 text-[11px] text-sky-200 cursor-pointer disabled:opacity-50"
                            >
                              <KeyRound className="w-3 h-3" />
                              签发 Token
                            </button>
                            <button
                              type="button"
                              disabled={busyKey === `rotate:${agent.agent_id}`}
                              onClick={() => void handleRotateToken(agent.agent_id)}
                              className="inline-flex items-center gap-1 rounded-lg border border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20 px-2.5 py-1 text-[11px] text-amber-200 cursor-pointer disabled:opacity-50"
                            >
                              <RotateCw className="w-3 h-3" />
                              轮换 Token
                            </button>
                            <button
                              type="button"
                              disabled={busyKey === `revoke:${agent.agent_id}`}
                              onClick={() => void handleRevokeAgent(agent.agent_id)}
                              className="inline-flex items-center gap-1 rounded-lg border border-rose-500/50 bg-rose-500/15 hover:bg-rose-500/25 px-2.5 py-1 text-[11px] text-rose-200 cursor-pointer disabled:opacity-50"
                            >
                              <Ban className="w-3 h-3" />
                              一键吊销
                            </button>
                          </>
                        )}
                        <button
                          type="button"
                          disabled={busyKey === `delete:${agent.agent_id}`}
                          onClick={() => void handleDeleteAgent(agent.agent_id)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 hover:border-rose-500/40 hover:text-rose-300 px-2 py-1 text-[11px] text-slate-400 cursor-pointer disabled:opacity-50"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Visual Capability Switches */}
                  <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-800/80">
                    {(
                      [
                        { key: "coordinator_peer", label: "与总指挥平权 (coordinator_peer)" },
                        { key: "host_server_invoke", label: "本机服务器调用 (host_server_invoke)" },
                        { key: "can_dispatch", label: "允许派工 (can_dispatch)" },
                        { key: "can_receive", label: "允许接单 (can_receive)" },
                      ] as const
                    ).map((item) => {
                      const active = Boolean(caps[item.key]);
                      return (
                        <button
                          key={item.key}
                          type="button"
                          disabled={!isAdmin || agent.revoked || busyKey === `cap:${agent.agent_id}:${item.key}`}
                          onClick={() => void handleQuickToggleCapability(agent, item.key)}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] border transition-colors ${
                            active
                              ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                              : "border-slate-800 bg-slate-950/60 text-slate-400"
                          } ${isAdmin && !agent.revoked ? "cursor-pointer hover:border-sky-500/40" : "opacity-75 cursor-default"}`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              active ? "bg-emerald-400" : "bg-slate-600"
                            }`}
                          />
                          {item.label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Teams Section */}
      {subTab === "teams" && (
        <div className="space-y-3">
          {(overview?.teams.length || 0) === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-8 text-center space-y-2">
              <div className="text-sm text-slate-300">尚未创建多团队编排</div>
              <div className="text-xs text-slate-500">
                可创建多个独立团队，并由 Owner 将任意已注册 Agent（Hermes / Muse / A2A / Pull Worker / AGY）指派为动态负责人。
              </div>
            </div>
          ) : (
            (overview?.teams || []).map((team) => (
              <div
                key={team.team_id}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-slate-100">
                        {team.display_name || team.team_id}
                      </span>
                      <code className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-sky-300">
                        {team.team_id}
                      </code>
                    </div>
                    <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-4 gap-y-1">
                      <span>负责人: {team.leader_agent_id || "未指派"}</span>
                      <span>
                        联席负责人: {team.co_leaders.length ? team.co_leaders.join(", ") : "无"}
                      </span>
                      <span>成员 ({team.members.length}): {team.members.join(", ") || "无"}</span>
                    </div>
                  </div>

                  {isAdmin && (
                    <div className="flex flex-wrap items-center gap-2">
                      <label className="text-[11px] text-slate-400 flex items-center gap-1.5">
                        快速换帅:
                        <select
                          aria-label={`切换团队 ${team.team_id} 负责人`}
                          value={team.leader_agent_id || ""}
                          disabled={busyKey === `leader:${team.team_id}`}
                          onChange={(e) => void handleQuickLeaderChange(team, e.target.value)}
                          className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200"
                        >
                          <option value="">-- 选择任意注册 Agent --</option>
                          {activeRegisteredAgents.map((ag) => (
                            <option key={ag.agent_id} value={ag.agent_id}>
                              {ag.agent_id} ({ag.kind})
                            </option>
                          ))}
                        </select>
                      </label>
                      <button
                        type="button"
                        onClick={() => openEditTeamModal(team)}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-700 hover:bg-slate-800 px-2.5 py-1 text-[11px] text-slate-200 cursor-pointer"
                      >
                        <Edit3 className="w-3 h-3" />
                        编辑
                      </button>
                      <button
                        type="button"
                        disabled={busyKey === `team-del:${team.team_id}`}
                        onClick={() => void handleDeleteTeam(team.team_id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-700 hover:border-rose-500/40 hover:text-rose-300 px-2 py-1 text-[11px] text-slate-400 cursor-pointer"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  )}
                </div>

                {(team.leader_can_dispatch === false || (team.warnings && team.warnings.length > 0)) && (
                  <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-200 flex items-start gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    <div>
                      {(team.warnings && team.warnings.length > 0
                        ? team.warnings
                        : ["当前负责人 can_dispatch=false，如需允许其派工请在外部 Agent 卡片中显式开启 can_dispatch。"]
                      ).join(" ")}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Host Bridge Audit Log Section (Admin Only) */}
      {subTab === "audit" && isAdmin && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={auditActorFilter}
              onChange={(e) => {
                setAuditOffset(0);
                setAuditActorFilter(e.target.value);
              }}
              placeholder="按 actor_id 筛选..."
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-200 w-56"
            />
            <button
              type="button"
              onClick={() => void loadAudit(auditOffset, auditActorFilter)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${auditLoading ? "animate-spin" : ""}`} />
              刷新日志
            </button>
            <span className="ml-auto text-[11px] text-slate-400">
              共 {auditTotal} 条（已脱敏，防符号链接只读）
            </span>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-[11px] text-slate-400">
                <tr>
                  <th className="px-3 py-2">时间</th>
                  <th className="px-3 py-2">事件</th>
                  <th className="px-3 py-2">调用方</th>
                  <th className="px-3 py-2">动作</th>
                  <th className="px-3 py-2">结果</th>
                  <th className="px-3 py-2">说明</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {auditEntries.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-slate-500">
                      暂无联邦审计记录
                    </td>
                  </tr>
                ) : (
                  auditEntries.map((entry, idx) => (
                    <tr key={`${entry.ts || 0}-${idx}`} className="hover:bg-slate-800/30">
                      <td className="px-3 py-2 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {formatTs(entry.ts)}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-sky-300">
                        {entry.event || "-"}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate-200">
                        {entry.actor_id || "-"}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] text-slate-300">
                        {entry.action || "-"}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            entry.outcome === "ok" || entry.outcome === "allowed"
                              ? "bg-emerald-500/15 text-emerald-300"
                              : "bg-rose-500/15 text-rose-300"
                          }`}
                        >
                          {entry.outcome || "-"}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-[11px] text-slate-400 max-w-xs truncate">
                        {entry.reason || "-"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              disabled={auditOffset === 0}
              onClick={() => setAuditOffset((o) => Math.max(0, o - auditLimit))}
              className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 disabled:opacity-40 cursor-pointer"
            >
              上一页
            </button>
            <button
              type="button"
              disabled={auditOffset + auditLimit >= auditTotal}
              onClick={() => setAuditOffset((o) => o + auditLimit)}
              className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 disabled:opacity-40 cursor-pointer"
            >
              下一页
            </button>
          </div>
        </div>
      )}

      {/* Agent Create / Edit Modal */}
      {agentModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 p-5 space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100">
                {editingAgentId ? `编辑外部 Agent (${editingAgentId})` : "注册外部联邦 Agent"}
              </h2>
              <button
                type="button"
                onClick={() => setAgentModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <label className="space-y-1">
                <span className="text-slate-400">Agent ID (小写字母/数字/_/-)</span>
                <input
                  type="text"
                  disabled={Boolean(editingAgentId)}
                  value={agentIdInput}
                  onChange={(e) => setAgentIdInput(e.target.value)}
                  placeholder="例如 hermes_ops_1"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100 disabled:opacity-60"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-400">显示名称</span>
                <input
                  type="text"
                  value={displayNameInput}
                  onChange={(e) => setDisplayNameInput(e.target.value)}
                  placeholder="例如 运维 Hermes 节点"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-400">接入类型 (Driver / Transport)</span>
                <select
                  value={kindInput}
                  onChange={(e) => setKindInput(e.target.value as FederationAgentKind)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                >
                  {AGENT_KIND_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label} — {opt.desc}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1">
                <span className="text-slate-400">
                  Hermes Profile {kindInput === "hermes_local" ? "(必填)" : "(远程 /p/<profile> 可选)"}
                </span>
                <input
                  type="text"
                  value={profileInput}
                  onChange={(e) => setProfileInput(e.target.value)}
                  placeholder="default / ops_1"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-400">信任级别 (Trust Level)</span>
                <select
                  value={trustLevelInput}
                  onChange={(e) => setTrustLevelInput(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                >
                  {TRUST_LEVEL_OPTIONS.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-400">远端 Endpoint URL (http/https，严禁内嵌凭据)</span>
                <input
                  type="text"
                  value={endpointInput}
                  onChange={(e) => setEndpointInput(e.target.value)}
                  placeholder="https://hermes-node-a.example.com"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-400">OpenBao secret_ref（仅引用路径，严禁明文密钥）</span>
                <input
                  type="text"
                  value={secretRefInput}
                  onChange={(e) => setSecretRefInput(e.target.value)}
                  placeholder="例如 <mount>/<namespace>/<item>#<field>"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-400">限定团队 allowed_teams (逗号分隔，留空表示不额外裁剪)</span>
                <input
                  type="text"
                  value={allowedTeamsInput}
                  onChange={(e) => setAllowedTeamsInput(e.target.value)}
                  placeholder="team-alpha, team-ops"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800">
              <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={coordPeerInput}
                  onChange={(e) => setCoordPeerInput(e.target.checked)}
                />
                与总指挥平权 (coordinator_peer)
              </label>
              <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={hostInvokeInput}
                  onChange={(e) => setHostInvokeInput(e.target.checked)}
                />
                允许调用本机服务器 (host_server_invoke)
              </label>
              <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={canDispatchInput}
                  onChange={(e) => setCanDispatchInput(e.target.checked)}
                />
                允许派工 (can_dispatch)
              </label>
              <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={canReceiveInput}
                  onChange={(e) => setCanReceiveInput(e.target.checked)}
                />
                允许接单 (can_receive)
              </label>
              <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enabledInput}
                  onChange={(e) => setEnabledInput(e.target.checked)}
                />
                启用节点 (enabled)
              </label>
              {!editingAgentId && (
                <label className="flex items-center gap-2 text-sky-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={autoMint}
                    onChange={(e) => setAutoMint(e.target.checked)}
                  />
                  注册后立即签发一次性 Token
                </label>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setAgentModalOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={busyKey === "agent-submit"}
                onClick={() => void handleSubmitAgent()}
                className="rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-1.5 text-xs font-medium text-white cursor-pointer disabled:opacity-50"
              >
                {editingAgentId ? "保存修改" : "确认注册"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Team Create / Edit Modal */}
      {teamModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-100">
                {editingTeamId ? `编辑团队 (${editingTeamId})` : "新建联邦团队"}
              </h2>
              <button
                type="button"
                onClick={() => setTeamModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <label className="block space-y-1">
                <span className="text-slate-400">团队 ID (team_id)</span>
                <input
                  type="text"
                  disabled={Boolean(editingTeamId)}
                  value={teamIdInput}
                  onChange={(e) => setTeamIdInput(e.target.value)}
                  placeholder="例如 team-ops"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100 disabled:opacity-60"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-slate-400">团队名称</span>
                <input
                  type="text"
                  value={teamNameInput}
                  onChange={(e) => setTeamNameInput(e.target.value)}
                  placeholder="例如 运维自动化团队"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-slate-400">动态负责人 (leader_agent_id — 可选任意注册 Agent)</span>
                <select
                  value={teamLeaderInput}
                  onChange={(e) => setTeamLeaderInput(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                >
                  <option value="">-- 暂不指派 --</option>
                  {activeRegisteredAgents.map((ag) => (
                    <option key={ag.agent_id} value={ag.agent_id}>
                      {ag.agent_id} ({ag.kind} · can_dispatch={String(ag.capabilities.can_dispatch)})
                    </option>
                  ))}
                </select>
              </label>

              <label className="block space-y-1">
                <span className="text-slate-400">联席负责人 co_leaders (逗号分隔 agent_id)</span>
                <input
                  type="text"
                  value={teamCoLeadersInput}
                  onChange={(e) => setTeamCoLeadersInput(e.target.value)}
                  placeholder="hermes_ops_1, muse_lead"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>

              <label className="block space-y-1">
                <span className="text-slate-400">团队成员 members (逗号分隔 agent_id)</span>
                <input
                  type="text"
                  value={teamMembersInput}
                  onChange={(e) => setTeamMembersInput(e.target.value)}
                  placeholder="hermes_ops_1, pull_worker_1"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-slate-100"
                />
              </label>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setTeamModalOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 cursor-pointer"
              >
                取消
              </button>
              <button
                type="button"
                disabled={busyKey === "team-submit"}
                onClick={() => void handleSubmitTeam()}
                className="rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-1.5 text-xs font-medium text-white cursor-pointer disabled:opacity-50"
              >
                保存团队
              </button>
            </div>
          </div>
        </div>
      )}

      {/* One-Time Bearer Token Modal (strictly ephemeral memory state, zero persistence) */}
      {oneTimeToken && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-amber-500/40 bg-slate-900 p-5 space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-amber-200 flex items-center gap-2">
                <Shield className="w-4 h-4 text-amber-400" />
                一次性入站凭据（仅本次展示，关闭后永不可再查）
              </h2>
              <button
                type="button"
                onClick={() => setOneTimeToken(null)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs text-slate-300 space-y-1">
              <div>
                Agent: <code className="text-sky-300">{oneTimeToken.agentId}</code> · 操作：
                {oneTimeToken.actionLabel}
                {typeof oneTimeToken.revokedPrevious === "number"
                  ? `（已立即作废 ${oneTimeToken.revokedPrevious} 个旧凭据）`
                  : ""}
              </div>
              <div className="text-amber-300/90 text-[11px]">
                此凭据仅暂存于当前弹窗内存，关闭弹窗或切换页面后立即清零，服务端仅保留加盐 HMAC-SHA256 哈希。
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Bearer Token ({oneTimeToken.tokenId})</span>
                <button
                  type="button"
                  onClick={() => void copyText("raw", oneTimeToken.tokenValue)}
                  className="inline-flex items-center gap-1 text-sky-300 hover:text-sky-200 cursor-pointer"
                >
                  {copiedField === "raw" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copiedField === "raw" ? "已复制" : "一键复制 Token"}
                </button>
              </div>
              <pre className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] font-mono text-emerald-300 break-all whitespace-pre-wrap">
                {oneTimeToken.tokenValue}
              </pre>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Hermes MCP Stdio 配置片段</span>
                <button
                  type="button"
                  onClick={() => void copyText("stdio", hermesStdioSnippet)}
                  className="inline-flex items-center gap-1 text-sky-300 hover:text-sky-200 cursor-pointer"
                >
                  {copiedField === "stdio" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copiedField === "stdio" ? "已复制" : "复制 Stdio 配置"}
                </button>
              </div>
              <pre className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] font-mono text-slate-200 overflow-x-auto">
                {hermesStdioSnippet}
              </pre>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Hermes MCP Streamable HTTP 配置片段</span>
                <button
                  type="button"
                  onClick={() => void copyText("http", hermesStreamHttpSnippet)}
                  className="inline-flex items-center gap-1 text-sky-300 hover:text-sky-200 cursor-pointer"
                >
                  {copiedField === "http" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copiedField === "http" ? "已复制" : "复制 HTTP 配置"}
                </button>
              </div>
              <pre className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] font-mono text-slate-200 overflow-x-auto">
                {hermesStreamHttpSnippet}
              </pre>
            </div>

            <div className="flex justify-end pt-1">
              <button
                type="button"
                onClick={() => setOneTimeToken(null)}
                className="rounded-lg bg-amber-600 hover:bg-amber-500 px-4 py-1.5 text-xs font-medium text-white cursor-pointer"
              >
                我已妥善保存，立即关闭并清空内存
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
