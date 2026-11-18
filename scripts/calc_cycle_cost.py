#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Antigravity CLI - Cycle Token & Cost Calculator (Sanitized / 脱敏独立版)
========================================================================
统计 Antigravity CLI 本周期（或今日/本月/全量）的 Token 消耗、缓存命中率及折算美金金额。

核心特性：
1. 数据源：自动遍历 ~/.gemini/antigravity-cli/brain/*/logs/transcript.jsonl
2. 会话去重：准确识别并去重 fork 继承的父会话步骤签名 (step_index, created_at, in, ca, out)
3. 动态模型识别：解析运行时切换模型（如 Gemini 3.8 Flash, 4 Hydrogen, 4 Carbon, Claude 等）
4. 周期计算：自动对齐周配额刷新锚点（支持自动读取配额重置配置或自定义）
5. 阶梯与缓存计费：严格按照官方计费规则（输入、输出、90%~95% 缓存读取折扣），统计实际开销与节省金额
"""

import argparse
import datetime
import glob
import json
import os
import re

# 默认基础路径（自动适配用户主目录，无需硬编码用户敏感路径）
DEFAULT_BRAIN_ROOT = os.path.expanduser("~/.gemini/antigravity-cli/brain")
DEFAULT_CONFIG_FILE = os.path.expanduser("~/.gemini/antigravity-cli/cache/cost_config.json")

# 模型家族标准正则与标签映射
_MODEL_SETTINGS_RE = re.compile(r"Model Selection` from .+? to (.+?)\. No need")

_MODEL_LABELS = {
    "gemini-3.8-flash": "Gemini 3.8 Flash",
    "gemini-4-hydrogen": "Gemini 4 Hydrogen",
    "gemini-4-carbon": "Gemini 4 Carbon",
    "gemini-4-argon": "Gemini 4 Argon",
    "gemini-pro-orchestrator": "Orchestrator Pro",
    "gemini-3.1-pro": "Gemini 3.1 Pro",
    "claude-opus-5-5": "Claude Opus 5.5",
    "claude-sonnet-5-5": "Claude Sonnet 5.5",
    "gpt-oss-120b": "GPT-OSS 120B",
}

# 官方定价表（美元 / 100万 Tokens）：(未缓存输入单价, 缓存读取单价, 输出单价)
_MODEL_RATES = {
    "gemini-3.8-flash": (0.75, 0.075, 3.75),        # 90% 缓存折扣
    "gemini-4-hydrogen": (1.50, 0.075, 7.50),       # 95% 缓存折扣
    "gemini-4-carbon": (2.00, 0.10, 10.00),         # 95% 缓存折扣
    "gemini-4-argon": (2.00, 0.10, 10.00),          # 95% 缓存折扣
    "gemini-pro-orchestrator": (2.00, 0.10, 10.00), # 95% 缓存折扣
    "gemini-3.1-pro": (2.00, 0.20, 12.00),          # 90% 缓存折扣 (<=200k)
    "claude-opus-5-5": (4.00, 0.20, 20.00),         # 95% 缓存折扣
    "claude-sonnet-5-5": (2.00, 0.10, 10.00),       # 95% 缓存折扣
    "gpt-oss-120b": (0.15, 0.075, 0.60),            # 开源模型池
}

# 默认周限额重置锚点：每周五 23:00 UTC（对应北京时间周六 07:00 UTC+8）
# 格式：(weekday: 0=周一..4=周五..6=周日, hour_utc, minute_utc)
_DEFAULT_WEEKLY_RESET_UTC = (4, 23, 0)


def canonical_model_family(raw_model: str) -> str:
    """标准化模型名称归类到指定模型池"""
    s = (raw_model or "").strip().lower()
    if not s or s == "none":
        return "gemini-3.8-flash"
    if "3.8" in s or "flash" in s:
        return "gemini-3.8-flash"
    if "hydrogen" in s:
        return "gemini-4-hydrogen"
    if "orchestrator" in s:
        return "gemini-pro-orchestrator"
    if "argon" in s:
        return "gemini-4-argon"
    if "carbon" in s:
        return "gemini-4-carbon"
    if "opus" in s:
        return "claude-opus-5-5"
    if "sonnet" in s:
        return "claude-sonnet-5-5"
    if "gpt-oss" in s or "120b" in s:
        return "gpt-oss-120b"
    if "pro" in s:
        return "gemini-3.1-pro"
    return "gemini-3.8-flash"


def get_model_rates(family: str, ymd_utc: str = "") -> tuple:
    """获取指定模型单价 (入, 缓存读, 出) / 1M Tokens"""
    return _MODEL_RATES.get(family, (2.00, 0.10, 10.00))


def load_weekly_reset_anchor(config_path: str = DEFAULT_CONFIG_FILE) -> tuple:
    """从本地配置读取与云端同步的周限额刷新锚点，若不存在则回退至默认"""
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f) or {}
            wd = int(cfg.get("weekly_reset_utc_weekday", _DEFAULT_WEEKLY_RESET_UTC[0])) % 7
            hr = int(cfg.get("weekly_reset_utc_hour", _DEFAULT_WEEKLY_RESET_UTC[1])) % 24
            mn = int(cfg.get("weekly_reset_utc_minute", _DEFAULT_WEEKLY_RESET_UTC[2])) % 60
            return wd, hr, mn
        except Exception:
            pass
    return _DEFAULT_WEEKLY_RESET_UTC


def get_current_cycle_bounds(now_utc: datetime.datetime, config_path: str = DEFAULT_CONFIG_FILE):
    """计算当前周期的 UTC 起止时间 (cycle_start_utc, cycle_end_utc, remaining_timedelta)"""
    wd, hr, mn = load_weekly_reset_anchor(config_path)
    days_ahead = (wd - now_utc.weekday()) % 7
    cand_end = now_utc.replace(hour=hr, minute=mn, second=0, microsecond=0) + datetime.timedelta(days=days_ahead)
    if cand_end <= now_utc:
        cand_end += datetime.timedelta(days=7)
    cycle_end_utc = cand_end
    cycle_start_utc = cycle_end_utc - datetime.timedelta(days=7)
    rem = max(datetime.timedelta(0), cycle_end_utc - now_utc)
    return cycle_start_utc, cycle_end_utc, rem


def format_tokens(n: int) -> str:
    """格式化 Token 为百万 (M) 显示"""
    if n <= 0:
        return "0.00 M"
    m = n / 1_000_000.0
    return f"{m:,.2f} M"


def format_usd(val: float) -> str:
    """格式化美元金额"""
    if val <= 0.0:
        return "$0.00"
    if val < 0.01:
        return f"${val:.4f}"
    return f"${val:,.2f}"


def collect_token_stats(brain_dir: str, start_utc: datetime.datetime = None, end_utc: datetime.datetime = None):
    """
    遍历 transcript.jsonl 并汇总结算统计数据
    """
    pattern = os.path.join(brain_dir, "*", ".system_generated", "logs", "transcript.jsonl")
    transcript_files = glob.glob(pattern)

    totals = {
        "inp": 0,       # 新输入 tokens
        "ca": 0,        # 缓存读取 tokens
        "out": 0,       # 输出 tokens (含 CoT 思考推理 tokens)
        "cost": 0.0,    # 实际折算美金
        "nocache": 0.0, # 无缓存基线美金
        "calls": 0,     # 调用次数
    }
    by_model = {}
    seen_signatures = set()

    for tp in transcript_files:
        cur_family = "gemini-3.8-flash"
        try:
            with open(tp, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    # 动态监测对话内模型切换事件
                    if "Model Selection" in line:
                        content = str(obj.get("content") or "")
                        match = _MODEL_SETTINGS_RE.search(content)
                        if match:
                            cur_family = canonical_model_family(match.group(1))

                    # 仅统计实际生成计费步骤 (PLANNER_RESPONSE 及 /compact 生成的 CHECKPOINT)
                    step_type = obj.get("type")
                    if step_type not in ("PLANNER_RESPONSE", "CHECKPOINT"):
                        continue

                    inp = int(obj.get("input_tokens") or 0)
                    ca = int(obj.get("cache_read_tokens") or 0)
                    out = int(obj.get("output_tokens") or 0)
                    if not (inp or ca or out):
                        continue

                    if obj.get("model"):
                        cur_family = canonical_model_family(obj.get("model"))

                    ts_str = str(obj.get("created_at") or "").strip()
                    if not ts_str:
                        continue
                    try:
                        dt_utc = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
                    except Exception:
                        continue

                    # 周期时间过滤
                    if start_utc and dt_utc < start_utc:
                        continue
                    if end_utc and dt_utc >= end_utc:
                        continue

                    # 跨会话 fork 继承步骤去重
                    step_idx = int(obj.get("step_index") or 0)
                    sig = (step_idx, ts_str, inp, ca, out)
                    if sig in seen_signatures:
                        continue
                    seen_signatures.add(sig)

                    # 金额计算 (按照官方计费)
                    ymd_utc = dt_utc.strftime("%Y-%m-%d")
                    p_in, p_ca, p_out = get_model_rates(cur_family, ymd_utc)
                    step_cost = (inp * p_in + ca * p_ca + out * p_out) / 1_000_000.0
                    step_nocache = ((inp + ca) * p_in + out * p_out) / 1_000_000.0

                    totals["inp"] += inp
                    totals["ca"] += ca
                    totals["out"] += out
                    totals["cost"] += step_cost
                    totals["nocache"] += step_nocache
                    totals["calls"] += 1

                    m_agg = by_model.setdefault(cur_family, {
                        "inp": 0, "ca": 0, "out": 0, "cost": 0.0, "nocache": 0.0, "calls": 0
                    })
                    m_agg["inp"] += inp
                    m_agg["ca"] += ca
                    m_agg["out"] += out
                    m_agg["cost"] += step_cost
                    m_agg["nocache"] += step_nocache
                    m_agg["calls"] += 1
        except Exception:
            continue

    return totals, by_model


def main():
    parser = argparse.ArgumentParser(description="Antigravity CLI 周期 Token 与金额统计脚本 (脱敏版)")
    parser.add_argument("--brain-dir", default=DEFAULT_BRAIN_ROOT, help="Antigravity 会话数据目录 (默认 ~/.gemini/antigravity-cli/brain)")
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="周期配置路径 (默认 ~/.gemini/antigravity-cli/cache/cost_config.json)")
    parser.add_argument("--today", action="store_true", help="仅统计今日消耗 (本地时区 00:00 至今)")
    parser.add_argument("--month", action="store_true", help="仅统计当月消耗 (本月 1 日 00:00 至今)")
    parser.add_argument("--all-time", action="store_true", help="统计所有历史记录")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    args = parser.parse_args()

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    # 本地时区 (默认为系统时区或 UTC+8)
    local_tz = datetime.datetime.now().astimezone().tzinfo or datetime.timezone(datetime.timedelta(hours=8))
    now_local = now_utc.astimezone(local_tz)

    # 确定起止时间
    rem_str = ""
    if args.today:
        period_name = "今日"
        today_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        start_utc = today_start_local.astimezone(datetime.timezone.utc)
        end_utc = None
        period_desc = f"{now_local.strftime('%Y-%m-%d')} (00:00 至今)"
    elif args.month:
        period_name = "本月"
        month_start_local = now_local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start_utc = month_start_local.astimezone(datetime.timezone.utc)
        end_utc = None
        period_desc = f"{now_local.strftime('%Y-%m')} (本月 1 日至今)"
    elif args.all_time:
        period_name = "全部历史"
        start_utc = None
        end_utc = None
        period_desc = "全部历史已记录对话"
    else:
        period_name = "本周配额周期"
        start_utc, end_utc, rem = get_current_cycle_bounds(now_utc, args.config)
        start_local = start_utc.astimezone(local_tz)
        end_local = end_utc.astimezone(local_tz)
        rem_d = rem.days
        rem_h = rem.seconds // 3600
        rem_str = f"距重置剩 {rem_d} 天 {rem_h} 小时" if rem_d > 0 else f"距重置剩 {rem_h} 小时"
        period_desc = f"{start_local.strftime('%m-%d %H:%M')} ~ {end_local.strftime('%m-%d %H:%M')} ({rem_str})"

    totals, by_model = collect_token_stats(args.brain_dir, start_utc, end_utc)

    tot_tokens = totals["inp"] + totals["ca"] + totals["out"]
    tot_prompt = totals["inp"] + totals["ca"]
    cache_pct = (totals["ca"] * 100.0 / tot_prompt) if tot_prompt > 0 else 0.0
    saved_usd = max(0.0, totals["nocache"] - totals["cost"])
    save_pct = (saved_usd * 100.0 / totals["nocache"]) if totals["nocache"] > 0 else 0.0

    if args.json:
        result = {
            "period": period_name,
            "period_desc": period_desc,
            "start_utc": start_utc.isoformat() if start_utc else None,
            "end_utc": end_utc.isoformat() if end_utc else None,
            "tokens": {
                "total": tot_tokens,
                "input_new": totals["inp"],
                "cache_read": totals["ca"],
                "output": totals["out"],
                "cache_rate_percent": round(cache_pct, 2),
            },
            "financial_usd": {
                "actual_cost": round(totals["cost"], 4),
                "baseline_without_cache": round(totals["nocache"], 4),
                "saved_amount": round(saved_usd, 4),
                "saved_percent": round(save_pct, 1),
            },
            "calls_count": totals["calls"],
            "models": {}
        }
        for fam, m in sorted(by_model.items(), key=lambda kv: -kv[1]["cost"]):
            m_in = m["inp"] + m["ca"]
            m_cr = (m["ca"] * 100.0 / m_in) if m_in > 0 else 0.0
            result["models"][fam] = {
                "label": _MODEL_LABELS.get(fam, fam),
                "tokens": m["inp"] + m["ca"] + m["out"],
                "input_new": m["inp"],
                "cache_read": m["ca"],
                "output": m["out"],
                "cache_rate_percent": round(m_cr, 2),
                "cost_usd": round(m["cost"], 4),
                "calls": m["calls"],
            }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    # 终端美化输出
    print("=" * 64)
    print(f"📊 Antigravity 本机用量账单统计 ({period_name})")
    print(f"🕒 统计区间: {period_desc}")
    print("=" * 64)
    print(f"• 消耗总量 : {format_tokens(tot_tokens)} (共 {totals['calls']} 次生成)")
    print(f"  ├─ 新输入 Token : {format_tokens(totals['inp'])}")
    print(f"  ├─ 缓存读取     : {format_tokens(totals['ca'])}")
    print(f"  └─ 输出(含思考) : {format_tokens(totals['out'])}")

    # 可视化缓存条
    filled = min(10, max(0, int(round(cache_pct / 10.0))))
    bar = "▓" * filled + "░" * (10 - filled)
    print(f"• 缓存命中率   : {cache_pct:.1f}% [{bar}]")
    print("-" * 64)
    print(f"• 折算实际金额 : {format_usd(totals['cost'])} USD")
    print(f"• 无缓存原价   : {format_usd(totals['nocache'])} USD")
    print(f"• 缓存节省金额 : {format_usd(saved_usd)} USD (节省 -{save_pct:.0f}%)")
    print("=" * 64)

    if by_model:
        print("🤖 模型消耗构成 (按费用降序):")
        for fam, m in sorted(by_model.items(), key=lambda kv: -kv[1]["cost"]):
            mtot = m["inp"] + m["ca"] + m["out"]
            min_tot = m["inp"] + m["ca"]
            mcr = (m["ca"] * 100.0 / min_tot) if min_tot > 0 else 0.0
            lbl = _MODEL_LABELS.get(fam, fam)
            cost_pct = (m["cost"] * 100.0 / totals["cost"]) if totals["cost"] > 0 else 0.0
            print(f"  • {lbl:<22} : {format_tokens(mtot):>9} | 缓 {mcr:4.1f}% | {format_usd(m['cost']):>8} ({cost_pct:4.1f}%)")
        print("=" * 64)


if __name__ == "__main__":
    main()
