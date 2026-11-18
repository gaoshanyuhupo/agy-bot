#!/usr/bin/env python3
"""Pure token usage, cache rate, Google USD cost ledger, and plan quota rendering helpers."""

from __future__ import annotations

import datetime
import fcntl
import glob
import html as html_mod
import json
import os
import re
import time

try:
    import zoneinfo
except ImportError:
    zoneinfo = None

MODEL_SETTINGS_RE = re.compile(r"Model Selection` from .+? to (.+?)\. No need")
WEEKDAY_CN = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")
DEFAULT_WEEKLY_RESET_UTC = (4, 23, 0)  # Friday 23:00 UTC

MODEL_FAMILY_LABELS = {
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


def get_cost_tz(cost_tz_name: str = "Asia/Shanghai"):
    """Resolve configured timezone (defaults to UTC+8 Asia/Shanghai)."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if zoneinfo is not None and cost_tz_name:
        try:
            tz = zoneinfo.ZoneInfo(cost_tz_name)
            off = tz.utcoffset(now_utc) or datetime.timedelta(0)
            hrs = off.total_seconds() / 3600.0
            if hrs == 0:
                lbl = "UTC"
            elif hrs == int(hrs):
                lbl = f"UTC{int(hrs):+d}"
            else:
                lbl = f"UTC{hrs:+.1f}"
            return tz, lbl
        except Exception:
            pass
    return datetime.timezone(datetime.timedelta(hours=8)), "UTC+8"


def canonical_model_family(raw_model):
    """Map raw model identifiers to canonical billing family slugs."""
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


def google_model_rates_per_m(family, ymd_utc, prompt_tokens=0):
    """Return `(uncached_input_usd, cache_read_usd, output_usd)` per 1M tokens."""
    if family == "gemini-3.8-flash":
        return (0.75, 0.075, 3.75) if ymd_utc <= "2026-12-31" else (1.50, 0.15, 7.50)
    if family == "gemini-4-hydrogen":
        return (1.50, 0.075, 7.50)
    if family in ("gemini-4-carbon", "gemini-4-argon", "gemini-pro-orchestrator"):
        return (2.00, 0.10, 10.00) if ymd_utc <= "2026-11-30" else (4.00, 0.20, 20.00)
    if family == "gemini-3.1-pro":
        return (4.00, 0.40, 18.00) if prompt_tokens > 200_000 else (2.00, 0.20, 12.00)
    if family == "claude-opus-5-5":
        return (4.00, 0.20, 20.00)
    if family == "claude-sonnet-5-5":
        return (2.00, 0.10, 10.00)
    if family == "gpt-oss-120b":
        return (0.15, 0.075, 0.60)
    return (2.00, 0.10, 10.00)


def parse_transcript_cost_steps(tpath, log_fn=None):
    """Parse a conversation's transcript.jsonl into compact billing step tuples."""
    steps = []
    cur_family = "gemini-3.8-flash"
    first_epoch = float("inf")
    has_sched_marker = False
    try:
        with open(tpath, "r", encoding="utf-8") as f:
            for raw in f:
                if not raw.strip():
                    continue
                if not has_sched_marker and "[ACB_SCHEDULED_TASK" in raw:
                    has_sched_marker = True
                try:
                    o = json.loads(raw)
                except Exception:
                    continue
                if "Model Selection" in raw:
                    c = str(o.get("content") or "")
                    m = MODEL_SETTINGS_RE.search(c)
                    if m:
                        cur_family = canonical_model_family(m.group(1))
                if o.get("type") not in ("PLANNER_RESPONSE", "CHECKPOINT"):
                    continue
                inp = int(o.get("input_tokens") or 0)
                ca = int(o.get("cache_read_tokens") or 0)
                out = int(o.get("output_tokens") or 0)
                if not (inp or ca or out):
                    continue
                if o.get("model"):
                    cur_family = canonical_model_family(o.get("model"))
                ts = str(o.get("created_at") or "").strip()
                if not ts:
                    continue
                try:
                    dt_utc = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
                except Exception:
                    continue
                ep = dt_utc.timestamp()
                if ep < first_epoch:
                    first_epoch = ep
                ymd_utc = dt_utc.strftime("%Y-%m-%d")
                hour_utc = dt_utc.strftime("%Y-%m-%dT%H")
                pi, pc, po = google_model_rates_per_m(cur_family, ymd_utc, prompt_tokens=(inp + ca))
                cost_usd = (inp * pi + ca * pc + out * po) / 1_000_000.0
                nocache_usd = ((inp + ca) * pi + out * po) / 1_000_000.0
                sig = (int(o.get("step_index") or 0), ts, inp, ca, out)
                steps.append((hour_utc, cur_family, inp, ca, out, cost_usd, nocache_usd, sig))
    except Exception as e:
        if log_fn:
            log_fn("parse transcript cost failed (%s): %r" % (tpath, e))
    if first_epoch == float("inf"):
        first_epoch = 0.0
    return first_epoch, steps, has_sched_marker


def collect_cost_hourly_buckets(
    *,
    brain_root: str,
    cost_ledger_file: str,
    cost_ledger_lock: str,
    meta_map: dict,
    mem_cache: dict,
    cache_lock,
    log_fn=None,
):
    """Aggregate hourly token/cost buckets across transcripts and persistent ledger."""
    tpaths = glob.glob(os.path.join(brain_root, "*", ".system_generated", "logs", "transcript.jsonl"))

    dirty = False
    live_convs = {}
    with cache_lock:
        for tp in tpaths:
            try:
                st = os.stat(tp)
            except OSError:
                continue
            parts = tp.split(os.sep)
            try:
                b_idx = parts.index("brain")
                cid = parts[b_idx + 1]
            except ValueError:
                continue
            cached = mem_cache.get(cid)
            if cached and len(cached) >= 5 and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                first_ep, steps, has_sched = cached[2], cached[3], cached[4]
            else:
                first_ep, steps, has_sched = parse_transcript_cost_steps(tp, log_fn=log_fn)
                mem_cache[cid] = (st.st_mtime_ns, st.st_size, first_ep, steps, has_sched)
                dirty = True
            live_convs[cid] = (st.st_mtime_ns, st.st_size, first_ep, steps, has_sched)

    seen_sigs = set()
    conv_hours = {}
    for cid, (mtime_ns, size, _first_ep, steps, has_sched) in sorted(
        live_convs.items(), key=lambda kv: (kv[1][2], kv[0])
    ):
        m_info = meta_map.get(cid) or {"project_id": "default-cli-project", "is_observer": False}
        hours_map = {}
        for hour_utc, fam, inp, ca, out, cost_u, nocache_u, sig in steps:
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            fam_map = hours_map.setdefault(hour_utc, {})
            acc = fam_map.get(fam)
            if acc is None:
                fam_map[fam] = [inp, ca, out, 1, cost_u, nocache_u]
            else:
                acc[0] += inp
                acc[1] += ca
                acc[2] += out
                acc[3] += 1
                acc[4] += cost_u
                acc[5] += nocache_u
        conv_hours[cid] = {
            "mtime_ns": mtime_ns,
            "size": size,
            "project_id": m_info["project_id"],
            "is_observer": m_info["is_observer"],
            "is_scheduled": bool(m_info.get("is_scheduled", False) or has_sched),
            "hours": hours_map,
        }

    archived_convs = {}
    try:
        os.makedirs(os.path.dirname(cost_ledger_file), exist_ok=True)
        with open(cost_ledger_lock, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                ledger = {}
                if os.path.isfile(cost_ledger_file):
                    try:
                        with open(cost_ledger_file, "r", encoding="utf-8") as rf:
                            ledger = json.load(rf) or {}
                    except Exception:
                        ledger = {}
                saved_convs = ledger.get("conversations") or {}
                for cid, entry in saved_convs.items():
                    if cid not in conv_hours:
                        if meta_map.get(cid, {}).get("is_scheduled") and not entry.get("is_scheduled"):
                            entry = dict(entry)
                            entry["is_scheduled"] = True
                            dirty = True
                        archived_convs[cid] = entry
                    elif bool(entry.get("is_scheduled", False)) != bool(conv_hours[cid]["is_scheduled"]):
                        dirty = True
                if dirty or not os.path.isfile(cost_ledger_file):
                    merged = dict(archived_convs)
                    merged.update(conv_hours)
                    tmp_path = f"{cost_ledger_file}.{os.getpid()}.tmp"
                    with open(tmp_path, "w", encoding="utf-8") as wf:
                        json.dump({"version": 1, "conversations": merged}, wf, separators=(",", ":"))
                    os.replace(tmp_path, cost_ledger_file)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        if log_fn:
            log_fn("cost ledger sync error: %r" % e)

    all_convs = dict(archived_convs)
    all_convs.update(conv_hours)

    records = []
    for cid, entry in all_convs.items():
        pid = entry.get("project_id") or "default-cli-project"
        is_obs = bool(entry.get("is_observer", False))
        is_sched = bool(entry.get("is_scheduled", False))
        for hour_utc, fam_map in (entry.get("hours") or {}).items():
            try:
                dt_h = datetime.datetime.strptime(hour_utc, "%Y-%m-%dT%H").replace(tzinfo=datetime.timezone.utc)
            except Exception:
                continue
            for fam, vals in fam_map.items():
                records.append((
                    dt_h, cid, pid, is_obs, is_sched, fam,
                    int(vals[0]), int(vals[1]), int(vals[2]), int(vals[3]),
                    float(vals[4]), float(vals[5]),
                ))
    return records


def new_cost_agg():
    return {"inp": 0, "ca": 0, "out": 0, "calls": 0, "cost": 0.0, "nocache": 0.0}


def add_cost_agg(agg, inp, ca, out, calls, cost, nocache):
    agg["inp"] += inp
    agg["ca"] += ca
    agg["out"] += out
    agg["calls"] += calls
    agg["cost"] += cost
    agg["nocache"] += nocache


def fmt_m_tokens(tokens):
    if tokens <= 0:
        return "0 M"
    m = tokens / 1_000_000.0
    if m < 0.01:
        return f"{m:.4f} M"
    if m < 0.1:
        return f"{m:.3f} M"
    return f"{m:,.2f} M"


def fmt_m_num(tokens):
    if tokens <= 0:
        return "0"
    m = tokens / 1_000_000.0
    if m < 0.01:
        return f"{m:.3f}"
    return f"{m:,.2f}"


def fmt_usd(val):
    if val <= 0.0:
        return "$0.00"
    if val < 0.01:
        return f"${val:.4f}"
    if val < 1.0:
        return f"${val:.3f}"
    return f"${val:,.2f}"


def agg_metrics(agg):
    tot_in = agg["inp"] + agg["ca"]
    tot_tok = tot_in + agg["out"]
    cache_pct = (agg["ca"] * 100.0 / tot_in) if tot_in > 0 else 0.0
    saved = max(0.0, agg["nocache"] - agg["cost"])
    save_pct = (saved * 100.0 / agg["nocache"]) if agg["nocache"] > 0 else 0.0
    filled = min(10, max(0, int(round(cache_pct / 10.0))))
    bar = "▓" * filled + "░" * (10 - filled)
    return tot_tok, cache_pct, bar, saved, save_pct


def render_period_block(icon, title, sub_label, agg):
    tot_tok, cache_pct, bar, saved, save_pct = agg_metrics(agg)
    if tot_tok == 0:
        return (
            f"{icon} <b>{title}</b> ({sub_label})\n"
            f"• 消耗：<code>0 M</code> · 缓存率：<code>0.0%</code> · 美金：<code>$0.00</code>"
        )
    save_note = (
        f"无缓存{fmt_usd(agg['nocache'])} · 省{fmt_usd(saved)} / -{save_pct:.0f}%"
        if saved >= 0.005 else f"共 {agg['calls']} 次调用"
    )
    return (
        f"{icon} <b>{title}</b> ({sub_label})\n"
        f"• 消耗：<b><code>{fmt_m_tokens(tot_tok)}</code></b> "
        f"<code>(新{fmt_m_num(agg['inp'])} + 缓{fmt_m_num(agg['ca'])} + 出{fmt_m_num(agg['out'])})</code>\n"
        f"• 缓存率：<b><code>{cache_pct:.1f}%</code></b> <code>[{bar}]</code>\n"
        f"• 折算美金：<b><code>{fmt_usd(agg['cost'])}</code></b> <code>({save_note})</code>"
    )


def make_cost_keyboard(view="overview", scope="all"):
    views = [
        ("overview", "📊 日周月"),
        ("daily", "📅 每日明细"),
        ("models", "🤖 模型单价"),
    ]
    scopes = [
        ("all", "🌐 全部"),
        ("agent", "👤 仅主对话"),
        ("sched", "⏰ 定时"),
        ("project", "📂 当前项目"),
    ]
    row_views = [
        {"text": f"{'✓ ' if v == view else ''}{lbl}", "callback_data": f"cost:{v}:{scope}"}
        for v, lbl in views
    ]
    row_scopes = [
        {"text": f"{'✓ ' if s == scope else ''}{lbl}", "callback_data": f"cost:{view}:{s}"}
        for s, lbl in scopes
    ]
    row_refresh = [
        {"text": "🔄 刷新我的用量", "callback_data": f"cost:{view}:{scope}"},
        {"text": "📊 总套餐配额 (/usage)", "callback_data": "action:usage"},
    ]
    return {"inline_keyboard": [row_views, row_scopes, row_refresh]}


def load_weekly_reset_utc(cost_config_file: str):
    if os.path.isfile(cost_config_file):
        try:
            with open(cost_config_file, "r", encoding="utf-8") as f:
                cfg = json.load(f) or {}
            wd = int(cfg.get("weekly_reset_utc_weekday", DEFAULT_WEEKLY_RESET_UTC[0])) % 7
            hr = int(cfg.get("weekly_reset_utc_hour", DEFAULT_WEEKLY_RESET_UTC[1])) % 24
            mn = int(cfg.get("weekly_reset_utc_minute", DEFAULT_WEEKLY_RESET_UTC[2])) % 60
            return wd, hr, mn
        except Exception:
            pass
    return DEFAULT_WEEKLY_RESET_UTC


def save_weekly_reset_utc(cost_config_file: str, wd, hr, mn):
    os.makedirs(os.path.dirname(cost_config_file), exist_ok=True)
    tmp = f"{cost_config_file}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({
            "weekly_reset_utc_weekday": int(wd) % 7,
            "weekly_reset_utc_hour": int(hr) % 24,
            "weekly_reset_utc_minute": int(mn) % 60,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, f, indent=2)
    os.replace(tmp, cost_config_file)


def get_weekly_quota_bounds(now_utc, local_tz, cost_config_file: str):
    """Return `(cycle_start_utc, cycle_end_utc, cycle_start_local, cycle_end_local, rem_str)`."""
    wd, hr, mn = load_weekly_reset_utc(cost_config_file)
    days_ahead = (wd - now_utc.weekday()) % 7
    cand_end = now_utc.replace(hour=hr, minute=mn, second=0, microsecond=0) + datetime.timedelta(days=days_ahead)
    if cand_end <= now_utc:
        cand_end += datetime.timedelta(days=7)
    cycle_end_utc = cand_end
    cycle_start_utc = cycle_end_utc - datetime.timedelta(days=7)
    rem = max(datetime.timedelta(0), cycle_end_utc - now_utc)
    rem_d = rem.days
    rem_h = rem.seconds // 3600
    rem_m = (rem.seconds % 3600) // 60
    if rem_d > 0:
        rem_str = f"剩{rem_d}天{rem_h}h重置"
    elif rem_h > 0:
        rem_str = f"剩{rem_h}h{rem_m}m重置"
    else:
        rem_str = f"剩{rem_m}m重置"
    return (
        cycle_start_utc,
        cycle_end_utc,
        cycle_start_utc.astimezone(local_tz),
        cycle_end_utc.astimezone(local_tz),
        rem_str,
    )


def calibrate_weekly_reset_from_text(raw_arg: str, cost_config_file: str) -> bool:
    """Parse e.g. '5 days, 11 hours' or '5d 11h' or 'default' and persist new UTC weekly anchor."""
    s = (raw_arg or "").strip().lower()
    if s in ("default", "reset"):
        save_weekly_reset_utc(cost_config_file, *DEFAULT_WEEKLY_RESET_UTC)
        return True
    m_d = re.search(r"(\d+)\s*(?:days?|d|天)", s)
    m_h = re.search(r"(\d+)\s*(?:hours?|hrs?|h|小时)", s)
    m_m = re.search(r"(\d+)\s*(?:minutes?|mins?|m|分)", s)
    if not (m_d or m_h or m_m):
        return False
    days = int(m_d.group(1)) if m_d else 0
    hours = int(m_h.group(1)) if m_h else 0
    mins = int(m_m.group(1)) if m_m else None
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    target = now_utc + datetime.timedelta(days=days, hours=hours, minutes=(mins or 0))
    if mins is None:
        if target.minute >= 30:
            target = (target + datetime.timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        else:
            target = target.replace(minute=0, second=0, microsecond=0)
    else:
        target = target.replace(second=0, microsecond=0)
    save_weekly_reset_utc(cost_config_file, target.weekday(), target.hour, target.minute)
    return True


def render_cost_panel(
    *,
    view: str,
    scope: str,
    cur_proj: str,
    proj_name: str,
    records,
    cost_tz_name: str,
    cost_config_file: str,
):
    """Render `/cost` HTML panel + inline keyboard."""
    if view not in ("overview", "daily", "models"):
        view = "overview"
    if scope not in ("all", "agent", "sched", "project"):
        scope = "all"

    tz, tz_lbl = get_cost_tz(cost_tz_name)
    now_local = datetime.datetime.now(tz)
    now_utc = now_local.astimezone(datetime.timezone.utc)

    if scope == "agent":
        scope_desc = "👤 仅主对话 (不含后台观测/定时)"
    elif scope == "sched":
        scope_desc = "⏰ 定时任务消耗"
    elif scope == "project":
        scope_desc = f"📂 当前项目 ({html_mod.escape(proj_name)})"
    else:
        scope_desc = "🌐 全部消耗 (主对话 + 后台记忆 + 定时)"

    today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start_utc, _week_end_utc, week_start_loc, week_end_loc, week_rem_str = get_weekly_quota_bounds(
        now_utc, tz, cost_config_file
    )
    d7_start = today_start - datetime.timedelta(days=6)
    d14_start = today_start - datetime.timedelta(days=13)
    d30_start = today_start - datetime.timedelta(days=29)
    month_prefix = now_local.strftime("%Y-%m")
    today_ymd = now_local.strftime("%Y-%m-%d")

    agg_today = new_cost_agg()
    agg_week = new_cost_agg()
    agg_d7 = new_cost_agg()
    agg_d30 = new_cost_agg()
    agg_month = new_cost_agg()
    by_day = {}
    by_model_today = {}
    by_model_week = {}
    by_model_month = {}

    for dt_utc_h, _cid, pid, is_obs, is_sched, fam, inp, ca, out, calls, cost_u, nocache_u in records:
        if scope == "agent" and (is_obs or is_sched):
            continue
        if scope == "sched" and not is_sched:
            continue
        if scope == "project" and (is_obs or is_sched or pid != cur_proj):
            continue
        dt_loc = dt_utc_h.astimezone(tz)
        ymd = dt_loc.strftime("%Y-%m-%d")

        if ymd == today_ymd:
            add_cost_agg(agg_today, inp, ca, out, calls, cost_u, nocache_u)
            add_cost_agg(by_model_today.setdefault(fam, new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_utc_h >= week_start_utc:
            add_cost_agg(agg_week, inp, ca, out, calls, cost_u, nocache_u)
            add_cost_agg(by_model_week.setdefault(fam, new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d7_start:
            add_cost_agg(agg_d7, inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d14_start:
            add_cost_agg(by_day.setdefault(ymd, new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d30_start:
            add_cost_agg(agg_d30, inp, ca, out, calls, cost_u, nocache_u)
        if ymd.startswith(month_prefix):
            add_cost_agg(agg_month, inp, ca, out, calls, cost_u, nocache_u)
            add_cost_agg(by_model_month.setdefault(fam, new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)

    header = (
        f"<b>💰 我的用量与缓存账单 (/cost)</b>\n"
        f"<code>口径: {scope_desc} · 本机统计 · {tz_lbl}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
    )
    wk_reset_note = f"{WEEKDAY_CN[week_end_loc.weekday()]} {week_end_loc.strftime('%H:%M')} 重置"
    footer = (
        f"\n\n<i>🕒 刷新于 {now_local.strftime('%H:%M:%S')} · 周周期每{wk_reset_note} · "
        f"按 Google 官方阶梯及缓存计费</i>"
    )

    if view == "overview":
        b_today = render_period_block("📅", "今日", now_local.strftime("%m-%d"), agg_today)
        week_lbl = f"{week_start_loc.strftime('%m-%d %H:%M')}起 · {week_rem_str}"
        b_week = render_period_block("📆", "本周累计", week_lbl, agg_week)
        b_month = render_period_block("🗓", "本月", month_prefix, agg_month)

        def _fmt_overview_models(mdict, title):
            lines = []
            for fam, magg in sorted(mdict.items(), key=lambda kv: -kv[1]["cost"]):
                mtok, mcr, _, _, _ = agg_metrics(magg)
                mlbl = MODEL_FAMILY_LABELS.get(fam, fam)
                lines.append(
                    f"• <code>{html_mod.escape(mlbl)}</code> · "
                    f"<code>{fmt_m_tokens(mtok)}</code> · 缓<code>{mcr:.1f}%</code> · "
                    f"<b><code>{fmt_usd(magg['cost'])}</code></b>"
                )
            if not lines:
                return ""
            return f"\n\n{title}\n" + "\n".join(lines)

        sec_week_models = _fmt_overview_models(by_model_week, f"🤖 <b>本周模型构成</b> ({week_rem_str})")
        sec_month_models = _fmt_overview_models(by_model_month, "🤖 <b>本月模型构成</b>")
        body = f"{b_today}\n\n{b_week}\n\n{b_month}{sec_week_models}{sec_month_models}"

    elif view == "daily":
        day_lines = []
        for offset in range(14):
            d_dt = today_start - datetime.timedelta(days=offset)
            ymd = d_dt.strftime("%Y-%m-%d")
            dagg = by_day.get(ymd)
            if not dagg:
                continue
            dtok, dcr, _, dsaved, _ = agg_metrics(dagg)
            wk = WEEKDAY_CN[d_dt.weekday()]
            day_lines.append(
                f"• <code>{d_dt.strftime('%m-%d')} {wk}</code> · "
                f"<b><code>{fmt_m_tokens(dtok)}</code></b> · "
                f"缓<code>{dcr:.1f}%</code> · "
                f"<b><code>{fmt_usd(dagg['cost'])}</code></b> "
                f"<code>(省{fmt_usd(dsaved)})</code>"
            )
        if not day_lines:
            day_lines.append("• <code>近 14 天暂无 Token 消耗记录</code>")

        wk_tok, wk_cr, _, wk_saved, _ = agg_metrics(agg_week)
        d7_tok, d7_cr, _, d7_saved, _ = agg_metrics(agg_d7)
        d30_tok, d30_cr, _, d30_saved, _ = agg_metrics(agg_d30)
        body = (
            "📅 <b>近 14 天每日明细</b>\n"
            + "\n".join(day_lines)
            + "\n\n📊 <b>配额周期与滚动合计</b>\n"
            + f"• <b>本周配额 ({week_rem_str})：</b><code>{fmt_m_tokens(wk_tok)}</code> · 缓<code>{wk_cr:.1f}%</code> · "
              f"<b><code>{fmt_usd(agg_week['cost'])}</code></b> <code>(省{fmt_usd(wk_saved)})</code>\n"
            + f"• <b>近7天滚动：</b><code>{fmt_m_tokens(d7_tok)}</code> · 缓<code>{d7_cr:.1f}%</code> · "
              f"<b><code>{fmt_usd(agg_d7['cost'])}</code></b> <code>(省{fmt_usd(d7_saved)})</code>\n"
            + f"• <b>近30天滚动：</b><code>{fmt_m_tokens(d30_tok)}</code> · 缓<code>{d30_cr:.1f}%</code> · "
              f"<b><code>{fmt_usd(agg_d30['cost'])}</code></b> <code>(省{fmt_usd(d30_saved)})</code>"
        )

    else:
        def _fmt_model_group(title, mdict):
            if not mdict:
                return f"<b>{title}</b>\n• <code>暂无消耗</code>"
            rows = [f"<b>{title}</b>"]
            for fam, magg in sorted(mdict.items(), key=lambda kv: -kv[1]["cost"]):
                mtok, mcr, _, msaved, _ = agg_metrics(magg)
                mlbl = MODEL_FAMILY_LABELS.get(fam, fam)
                tot_in = magg["inp"] + magg["ca"]
                pi, pc, _ = google_model_rates_per_m(fam, now_utc.strftime("%Y-%m-%d"))
                eff_in = ((magg["inp"] * pi + magg["ca"] * pc) / tot_in) if tot_in > 0 else pi
                rows.append(
                    f"• <b>{html_mod.escape(mlbl)}</b>\n"
                    f"  <code>{fmt_m_tokens(mtok)}</code> · 缓<code>{mcr:.1f}%</code> "
                    f"(等效输入<code>${eff_in:.2f}/M</code>) · "
                    f"<b><code>{fmt_usd(magg['cost'])}</code></b> <code>(省{fmt_usd(msaved)})</code>"
                )
            return "\n".join(rows)

        ymd_now = now_utc.strftime("%Y-%m-%d")
        f_pi, f_pc, f_po = google_model_rates_per_m("gemini-3.8-flash", ymd_now)
        h_pi, h_pc, h_po = google_model_rates_per_m("gemini-4-hydrogen", ymd_now)
        c_pi, c_pc, c_po = google_model_rates_per_m("gemini-4-carbon", ymd_now)
        price_ref = (
            "📌 <b>当前 Google 官方计费单价 (/ 1M tok)</b>\n"
            f"• <code>Flash 3.8 </code>: 入<code>${f_pi:g}</code> · 缓存读<code>${f_pc:g}</code> · 出<code>${f_po:g}</code>\n"
            f"• <code>Hydrogen 4</code>: 入<code>${h_pi:g}</code> · 缓存读<code>${h_pc:g}</code> · 出<code>${h_po:g}</code>\n"
            f"• <code>Carbon/Arg</code>: 入<code>${c_pi:g}</code> · 缓存读<code>${c_pc:g}</code> · 出<code>${c_po:g}</code>"
        )
        body = (
            _fmt_model_group("📅 今日模型分项", by_model_today)
            + "\n\n"
            + _fmt_model_group(f"📆 本周配额模型分项 ({week_rem_str})", by_model_week)
            + "\n\n"
            + _fmt_model_group("🗓 本月模型分项", by_model_month)
            + "\n\n"
            + price_ref
        )

    return header + body + footer, make_cost_keyboard(view=view, scope=scope)


def load_cached_plan_quota(quota_cache_file: str):
    if not os.path.isfile(quota_cache_file):
        return None
    try:
        with open(quota_cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("groups"), list) and data["groups"]:
            return data
    except Exception:
        pass
    return None


def parse_iso_z(ts_str):
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        s = ts_str.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def make_usage_keyboard():
    return {
        "inline_keyboard": [
            [
                {"text": "🔄 刷新总套餐配额", "callback_data": "usage:refresh"},
                {"text": "💰 我的本机用量 (/cost)", "callback_data": "action:cost"},
            ],
            [
                {"text": "🤖 切换模型 (/model)", "callback_data": "action:model"},
            ],
        ]
    }


def fmt_quota_countdown(rst_utc, now_utc):
    if rst_utc is None:
        return "未知"
    rem = max(datetime.timedelta(0), rst_utc - now_utc)
    d = rem.days
    h = rem.seconds // 3600
    m = (rem.seconds % 3600) // 60
    if d > 0:
        return f"剩{d}天{h}h"
    if h > 0:
        return f"剩{h}h{m}m"
    return f"剩{m}m"


def render_usage_panel(snap, is_fallback: bool, err_str: str, cost_tz_name: str = "Asia/Shanghai"):
    """Render `/usage` HTML panel + keyboard from a quota snapshot."""
    tz, tz_lbl = get_cost_tz(cost_tz_name)
    now_local = datetime.datetime.now(tz)
    now_utc = now_local.astimezone(datetime.timezone.utc)

    header = (
        "<b>📊 反重力总套餐配额卡片 (/usage)</b>\n"
        f"<code>口径: ☁️ 官方云端总套餐实时配额 (全端共享) · {tz_lbl}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
    )
    kb = make_usage_keyboard()

    if not snap:
        body = (
            "⚠️ <b>暂无法获取云端总套餐实时配额</b>\n"
            f"<code>{html_mod.escape((err_str or '')[:220] or '未知错误')}</code>\n\n"
            "<i>可点击下方按钮重试，或查看本机统计 <code>/cost</code>。</i>"
        )
        return header + body, kb

    group_blocks = []
    gemini_wk_pct = None
    gemini_5h_pct = None
    claude_wk_pct = None

    for grp in (snap.get("groups") or []):
        raw_gname = (grp.get("name") or "").strip()
        gl = raw_gname.lower()
        if "gemini" in gl:
            g_icon = "💎"
            g_title = "Gemini 模型组"
            g_models = "Carbon 4 · Hydrogen 4 · Argon 4 · Orchestrator · Flash 3.8"
        elif "claude" in gl or "gpt" in gl:
            g_icon = "🧩"
            g_title = "Claude & GPT 模型组"
            g_models = "Claude Opus 5.5 · Claude Sonnet 5.5 · GPT-OSS 120B"
        else:
            g_icon = "🤖"
            g_title = raw_gname or "其他模型组"
            raw_desc = (grp.get("description") or "").replace("Models within this group:", "").strip()
            g_models = raw_desc[:72]

        b_lines = [f"{g_icon} <b>{html_mod.escape(g_title)}</b>"]
        if g_models:
            b_lines.append(f"<code>含 {html_mod.escape(g_models)}</code>")

        for b in (grp.get("buckets") or []):
            win = (b.get("window") or "").lower()
            bname = (b.get("name") or "").strip()
            if win == "weekly" or "weekly" in bname.lower():
                win_lbl = "每周限额"
                is_weekly = True
            elif win == "5h" or "hour" in bname.lower():
                win_lbl = "5小时窗口"
                is_weekly = False
            else:
                win_lbl = bname or "配额"
                is_weekly = False

            rem_frac = max(0.0, min(1.0, float(b.get("remaining_fraction", 0.0))))
            rem_pct = rem_frac * 100.0
            used_pct = max(0.0, 100.0 - rem_pct)

            if "gemini" in gl and is_weekly:
                gemini_wk_pct = rem_pct
            elif "gemini" in gl and not is_weekly:
                gemini_5h_pct = rem_pct
            elif ("claude" in gl or "gpt" in gl) and is_weekly:
                claude_wk_pct = rem_pct

            filled = int(round(rem_frac * 10))
            bar = "▓" * filled + "░" * (10 - filled)

            if rem_pct <= 5.0:
                badge = " 🚨"
            elif rem_pct < 20.0:
                badge = " ⚠️"
            elif rem_pct < 50.0:
                badge = " ⚡"
            else:
                badge = " ✅"

            rst_utc = parse_iso_z(b.get("reset_time"))
            if rst_utc is not None:
                rst_loc = rst_utc.astimezone(tz)
                if rst_loc.date() == now_local.date():
                    rst_str = f"今日 {rst_loc.strftime('%H:%M')}"
                else:
                    rst_str = f"{rst_loc.strftime('%m-%d')} {WEEKDAY_CN[rst_loc.weekday()]} {rst_loc.strftime('%H:%M')}"
                cd_str = fmt_quota_countdown(rst_utc, now_utc)
                rst_info = f"<code>{rst_str}</code> 重置 (<b>{cd_str}</b>)"
            else:
                rst_info = "<code>重置时间未知</code>"

            b_lines.append(
                f"• <b>{html_mod.escape(win_lbl)}：</b>剩余 <b><code>{rem_pct:.1f}%</code></b> "
                f"<code>(已用 {used_pct:.1f}%)</code>{badge}\n"
                f"  <code>[{bar}]</code> · {rst_info}"
            )

        group_blocks.append("\n".join(b_lines))

    if gemini_wk_pct is not None and gemini_wk_pct < 20.0 and (claude_wk_pct or 0.0) >= 50.0:
        tip = (
            f"\n\n💡 <b>配额建议：</b>Gemini 周限额仅剩 <code>{gemini_wk_pct:.1f}%</code>，"
            f"而 Claude/GPT 池尚余 <code>{claude_wk_pct:.1f}%</code>；重度编码/推理可点下方切至 Claude 5.5 分担额度。"
        )
    elif gemini_5h_pct is not None and gemini_5h_pct < 20.0:
        tip = (
            f"\n\n💡 <b>配额建议：</b>Gemini 5小时窗口剩余 <code>{gemini_5h_pct:.1f}%</code>，"
            f"短期密集请求建议稍候窗口刷新或切换 Flash / Claude 模型。"
        )
    else:
        tip = "\n\n<i>💡 同组模型共享周限额与 5h 窗口，按模型 Token 成本权重扣减套餐进度。</i>"

    ft_epoch = float(snap.get("fetched_at_epoch") or time.time())
    ft_loc = datetime.datetime.fromtimestamp(ft_epoch, tz)
    if is_fallback:
        footer = (
            f"\n\n<i>🕒 缓存快照于 {ft_loc.strftime('%m-%d %H:%M:%S')}（后续自动刷新） · "
            f"本机明细请看 /cost</i>"
        )
    else:
        footer = (
            f"\n\n<i>🕒 实时同步于 {ft_loc.strftime('%H:%M:%S')} · "
            f"0 Token 直连官方配额接口 · 本机明细请看 /cost</i>"
        )

    body = "\n\n".join(group_blocks) + tip
    return header + body + footer, kb
