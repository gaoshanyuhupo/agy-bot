import {
  Bell,
  Bot,
  CreditCard,
  DollarSign,
  FileCode,
  KeyRound,
  Layers,
  LayoutDashboard,
  LogOut,
  ShieldCheck,
  X,
} from "lucide-react";
import type { NavTab, StudioSession } from "../types";

interface MobileMoreSheetProps {
  open: boolean;
  activeTab: NavTab;
  session: StudioSession;
  isPasswordTrack: boolean;
  onClose: () => void;
  onNavigate: (tab: NavTab) => void;
  onOpenPasswordModal: () => void;
  onLogout: () => void;
}

const SHEET_ITEMS: {
  id: NavTab;
  label: string;
  desc: string;
  icon: typeof LayoutDashboard;
  badge?: string;
}[] = [
  { id: "attention", label: "审批中心", desc: "统一审批队列与浏览器接管感知", icon: Bell },
  { id: "files", label: "文件审查", desc: "项目文件树、Git Diff 与撤回/重做", icon: FileCode },
  { id: "overview", label: "总览", desc: "多 Bot 状态与系统健康指标", icon: LayoutDashboard },
  { id: "bots", label: "Bot 团队", desc: "在线节点、专长与当前任务", icon: Bot },
  { id: "models", label: "外部模型", desc: "中转站接入、方言适配与模型过滤", icon: Layers },
  { id: "openbao", label: "OpenBao", desc: "中央密码库自动载入、连通性测试与路径配置", icon: ShieldCheck },
  {
    id: "security-card",
    label: "安全卡",
    desc: "无 OpenBao 用户的内置分级加密卡片存档",
    icon: CreditCard,
    badge: "预留",
  },
  { id: "costs", label: "用量账单", desc: "Token 消耗、缓存命中与额度", icon: DollarSign },
];

export function MobileMoreSheet({
  open,
  activeTab,
  session,
  isPasswordTrack,
  onClose,
  onNavigate,
  onOpenPasswordModal,
  onLogout,
}: MobileMoreSheetProps) {
  if (!open) return null;

  const accountLabel = session.username
    ? session.username
    : `${session.bot} · #${session.user_id}`;

  return (
    <div
      className="fixed inset-0 z-50 md:hidden flex flex-col justify-end bg-slate-950/70 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        className="rounded-t-2xl border-t border-slate-800 bg-slate-900 px-4 pt-3 pb-6 space-y-4 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-sm font-semibold text-slate-100 truncate">{accountLabel}</span>
            <span
              className={`shrink-0 px-1.5 py-0.5 rounded font-semibold uppercase text-[10px] ${
                session.role === "admin"
                  ? "bg-emerald-500/15 text-emerald-300"
                  : "bg-amber-500/15 text-amber-300"
              }`}
            >
              {session.role}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭更多菜单"
            className="h-8 w-8 rounded-lg inline-flex items-center justify-center text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-1.5 max-h-[60vh] overflow-y-auto">
          {SHEET_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onNavigate(item.id);
                  onClose();
                }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors cursor-pointer ${
                  active
                    ? "bg-sky-500/15 border border-sky-500/30 text-sky-300"
                    : "border border-slate-800/80 bg-slate-950/50 text-slate-200 hover:bg-slate-800/70"
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium flex items-center gap-1.5">
                    <span>{item.label}</span>
                    {item.badge && (
                      <span className="px-1.5 py-0.2 rounded bg-amber-500/15 text-amber-300 border border-amber-500/25 text-[10px]">
                        {item.badge}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">{item.desc}</div>
                </div>
              </button>
            );
          })}
        </div>

        <div className="pt-2 border-t border-slate-800 grid grid-cols-2 gap-2">
          {isPasswordTrack && (
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenPasswordModal();
              }}
              className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950/60 hover:bg-slate-800 py-2.5 text-xs text-slate-200 cursor-pointer"
            >
              <KeyRound className="w-3.5 h-3.5" />
              修改密码
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              onClose();
              onLogout();
            }}
            className={`inline-flex items-center justify-center gap-1.5 rounded-xl border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 py-2.5 text-xs text-rose-200 cursor-pointer ${
              isPasswordTrack ? "" : "col-span-2"
            }`}
          >
            <LogOut className="w-3.5 h-3.5" />
            退出登录
          </button>
        </div>
      </div>
    </div>
  );
}
