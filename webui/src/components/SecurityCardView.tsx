import { useEffect, useState } from "react";
import {
  ArrowRight,
  Clock,
  CreditCard,
  FileSearch,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Plus,
  Shield,
  ShieldCheck,
  Sparkles,
  Upload,
} from "lucide-react";
import { fetchOpenBaoConfig } from "../api";
import type { NavTab, OpenBaoConfigResponse } from "../types";

interface SecurityCardViewProps {
  onNavigate?: (tab: NavTab) => void;
}

const CARD_BLUEPRINT_FEATURES = [
  {
    icon: Shield,
    accent: "text-emerald-400",
    title: "分级加密卡片槽位（LV1 / LV2）",
    desc: "借鉴 OpenBao 权限分层理念，在项目内原生提供 LV1 读写卡（外部模型、日常 API Key）与 LV2 只读卡（高敏基础设施凭据），默认最小权限隔离。",
  },
  {
    icon: Lock,
    accent: "text-sky-400",
    title: "主密钥封包加密存储",
    desc: "采用 Envelope Encryption 封包加密将所有密钥密文存入服务端 0600 保险箱，支持独立卡片解锁与内存零持久明文，消除零散明文配置文件风险。",
  },
  {
    icon: Clock,
    accent: "text-amber-400",
    title: "过期轮换与一键吊销",
    desc: "为每张安全卡设置有效期、访问范围与轮换提醒；发现异常或换机时可一键吊销单张卡片，不影响其它正常业务槽位。",
  },
  {
    icon: FileSearch,
    accent: "text-violet-400",
    title: "全链路审计追踪",
    desc: "每次凭据写入、读取、轮换与吊销均记录至 0600 只追加审计日志（含操作者、来源通道与时间戳，永不记录明文密钥值）。",
  },
];

export function SecurityCardView({ onNavigate }: SecurityCardViewProps) {
  const [openBaoStatus, setOpenBaoStatus] = useState<OpenBaoConfigResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    void fetchOpenBaoConfig()
      .then((res) => {
        if (!cancelled) setOpenBaoStatus(res);
      })
      .catch(() => {
        // Graceful fallback on preview
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const openBaoActive = Boolean(openBaoStatus?.enabled && openBaoStatus?.credential_configured);

  return (
    <div className="p-4 sm:p-5 md:p-6 max-w-6xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <CreditCard className="w-5 h-5 text-amber-400 shrink-0" />
              安全卡
            </h2>
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/35 bg-amber-500/15 px-2.5 py-0.5 text-[11px] font-medium text-amber-300">
              <Sparkles className="w-3 h-3" />
              预留功能 · Roadmap
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            面向无 OpenBao 部署环境的项目内置密钥存档方案：无需额外部署密码库服务，也能为「外部模型」与各类工具提供分级加密凭据托管。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate?.("openbao")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            前往 OpenBao 配置
          </button>
          <button
            type="button"
            onClick={() => onNavigate?.("models")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 px-3 py-1.5 text-xs text-slate-200 cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-sky-400" />
            前往外部模型
          </button>
        </div>
      </div>

      {/* Reserved Action Bar (explicit disabled state to prevent mis-clicks) */}
      <div className="rounded-2xl border border-amber-500/25 bg-amber-500/8 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1 min-w-0">
          <div className="text-xs font-semibold text-amber-200 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            安全卡引擎当前处于架构预留阶段
          </div>
          <p className="text-xs text-amber-100/80 leading-relaxed">
            后端 <code className="font-mono text-amber-200">SecretStore</code> 抽象接口已为安全卡预留槽位（状态：<code className="font-mono text-amber-200">reserved</code>）。
            {openBaoActive
              ? " 当前主机已自动接入 OpenBao，密钥将优先由 OpenBao 托管。"
              : " 安全卡正式上线前，未配置 OpenBao 的环境将自动使用服务器 0600 权限文件兜底保存。"}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            disabled
            title="安全卡功能预留中，后续版本开放"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-900/70 px-3.5 py-2 text-xs font-medium text-slate-500 cursor-not-allowed opacity-70"
          >
            <Plus className="w-3.5 h-3.5" />
            创建安全卡（预留）
          </button>
          <button
            type="button"
            disabled
            title="安全卡功能预留中，后续版本开放"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-900/70 px-3.5 py-2 text-xs font-medium text-slate-500 cursor-not-allowed opacity-70"
          >
            <Upload className="w-3.5 h-3.5" />
            导入卡片（预留）
          </button>
        </div>
      </div>

      {/* Three-Tier Hosting Priority Roadmap */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">三层密钥托管优先级路线图</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              统一服务于「外部模型」中转站及其他工具密钥，按环境能力自动降级衔接
            </p>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            SecretStore Priority Chain
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {/* Tier 1: OpenBao */}
          <div
            className={`rounded-xl border p-4 space-y-2.5 ${
              openBaoActive
                ? "border-emerald-500/40 bg-emerald-500/10"
                : "border-slate-800 bg-slate-950/60"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-100">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-300 font-mono text-[11px] inline-flex items-center justify-center">
                  1
                </span>
                OpenBao
              </span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                  openBaoActive
                    ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/35"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {openBaoActive ? "当前已接入" : "配置后优先"}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              已有 OpenBao 密码库时自动探测或手动配置即可接管，WebUI 粘贴的明文 Key 自动转存进 KV 路径。
            </p>
            <button
              type="button"
              onClick={() => onNavigate?.("openbao")}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-300 hover:text-emerald-200 cursor-pointer"
            >
              管理 OpenBao 配置
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {/* Tier 2: Security Card */}
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/8 p-4 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-100">
                <span className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-300 font-mono text-[11px] inline-flex items-center justify-center">
                  2
                </span>
                内置安全卡
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-medium bg-amber-500/20 text-amber-300 border border-amber-500/35">
                预留中
              </span>
            </div>
            <p className="text-xs text-slate-300/90 leading-relaxed">
              为没有部署 OpenBao 的个人与开源用户提供原生加密卡片存档，支持 LV1 读写 / LV2 只读分级与轮换吊销。
            </p>
            <span className="inline-flex items-center gap-1 text-[11px] text-amber-300/80">
              <Sparkles className="w-3 h-3" />
              下一阶段落地
            </span>
          </div>

          {/* Tier 3: Local 0600 */}
          <div
            className={`rounded-xl border p-4 space-y-2.5 ${
              !openBaoActive
                ? "border-sky-500/40 bg-sky-500/10"
                : "border-slate-800 bg-slate-950/60"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-100">
                <span className="w-5 h-5 rounded-full bg-sky-500/20 text-sky-300 font-mono text-[11px] inline-flex items-center justify-center">
                  3
                </span>
                服务器 0600 兜底
              </span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                  !openBaoActive
                    ? "bg-sky-500/20 text-sky-300 border border-sky-500/35"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {!openBaoActive ? "当前兜底" : "备用兜底"}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              零外部依赖的基础保护：服务端采用 0700 目录 + 0600 权限原子落盘，前端永不写入 localStorage。
            </p>
            <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
              <HardDrive className="w-3 h-3" />
              local_0600 已就绪
            </span>
          </div>
        </div>
      </div>

      {/* Planned Card Slots Preview */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/50 p-4 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/15 border border-emerald-500/25 flex items-center justify-center">
                <KeyRound className="w-4 h-4 text-emerald-400" />
              </div>
              <div>
                <div className="text-xs font-semibold text-slate-200">LV1 读写安全卡（槽位预留）</div>
                <div className="text-[11px] text-slate-500 font-mono">scope: lv1/* · read/write</div>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400">
              待启用
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            用于存放「外部模型」中转站 API Key、第三方 SaaS Webhook Token 等日常可由 WebUI 与 Agent 读写轮换的凭据。
          </p>
        </div>

        <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/50 p-4 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/25 flex items-center justify-center">
                <Shield className="w-4 h-4 text-sky-400" />
              </div>
              <div>
                <div className="text-xs font-semibold text-slate-200">LV2 只读安全卡（槽位预留）</div>
                <div className="text-[11px] text-slate-500 font-mono">scope: lv2/* · read-only</div>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400">
              待启用
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            用于存放云厂商 AK、服务器凭据等高敏感资产，运行态仅允许受控只读调用，严禁自动化任务直接覆盖或删除。
          </p>
        </div>
      </div>

      {/* Design Blueprint Grid */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 px-0.5">安全卡能力设计蓝图</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
          {CARD_BLUEPRINT_FEATURES.map((feat) => {
            const Icon = feat.icon;
            return (
              <div
                key={feat.title}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2"
              >
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
                  <Icon className={`w-4 h-4 shrink-0 ${feat.accent}`} />
                  <span>{feat.title}</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{feat.desc}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
