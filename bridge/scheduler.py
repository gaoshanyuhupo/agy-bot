#!/usr/bin/env python3
"""
bridge/scheduler.py — Autonomous Scheduled Tasks Engine for Antigravity CLI Telegram Bridge
Zero-dependency cron evaluator, atomic multi-bot task storage, and Telegram interactive control panel.
"""

import os
import re
import json
import time
import fcntl
import datetime
import html as html_mod

HOME = os.path.expanduser("~")
SCHEDULED_TASKS_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/scheduled_tasks.json")
SCHEDULED_TASKS_LOCK = "/tmp/agy_scheduled_tasks.lock"
MIN_CRON_INTERVAL_SECS = 300  # 5 minutes safety floor for recurring cron tasks

_MONTH_ALIASES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_DOW_ALIASES = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}
_CRON_MACROS = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
}
_REL_UNIT_PAT = r"(?:days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s|天|小时|分钟|分|秒)"
_REL_FULL_RE = re.compile(
    rf"^(?:in\s+)?((?:\d+\s*{_REL_UNIT_PAT}\s*)+)$",
    re.IGNORECASE,
)
_REL_PREFIX_RE = re.compile(
    rf"^((?:in\s+)(?:\d+\s*{_REL_UNIT_PAT}?\s*)+|(?:\d+\s*{_REL_UNIT_PAT}\s*)+)(?:\s+([\s\S]+))?$",
    re.IGNORECASE,
)
_REL_TOKEN_RE = re.compile(rf"(\d+)\s*({_REL_UNIT_PAT})?", re.IGNORECASE)


# ---------------------------------------------------------------- Timezone & Time Helpers
def get_scheduler_tz(tz_name="Asia/Shanghai"):
    """Return (timezone_obj, tz_label)."""
    tz_env = os.environ.get("AGY_TG_COST_TZ", tz_name or "Asia/Shanghai")
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tz_env)
        now = datetime.datetime.now(tz)
        off = now.utcoffset()
        if off is not None:
            hrs = off.total_seconds() / 3600.0
            lbl = "UTC" if hrs == 0 else (f"UTC{int(hrs):+d}" if hrs == int(hrs) else f"UTC{hrs:+.1f}")
            return tz, lbl
    except Exception:
        pass
    return datetime.timezone(datetime.timedelta(hours=8)), "UTC+8"


def parse_iso_utc(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
    except Exception:
        return None


def format_iso_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def format_countdown(target_dt, from_dt=None):
    if target_dt is None:
        return "无计划"
    from_dt = from_dt or datetime.datetime.now(datetime.timezone.utc)
    if target_dt.tzinfo is None:
        target_dt = target_dt.replace(tzinfo=datetime.timezone.utc)
    diff = target_dt - from_dt
    secs = int(diff.total_seconds())
    if secs <= 0:
        return "即将触发"
    days = secs // 86400
    rem = secs % 86400
    hrs = rem // 3600
    mins = (rem % 3600) // 60
    if days > 0:
        return f"剩 {days}天{hrs}h"
    if hrs > 0:
        return f"剩 {hrs}h{mins}m"
    if mins > 0:
        return f"剩 {mins}m"
    return f"剩 {max(1, secs)}s"


# ---------------------------------------------------------------- Cron & Relative Parser
def _parse_cron_atom(tok, min_val, max_val, aliases=None):
    s = tok.strip().lower()
    if aliases and s in aliases:
        val = aliases[s]
    else:
        val = int(s)
    if val < min_val or val > max_val:
        raise ValueError(f"Value {tok} out of range [{min_val}..{max_val}]")
    return val


def parse_cron_field(field_str, min_val, max_val, aliases=None, wrap_max=None):
    field_str = field_str.strip()
    if not field_str:
        raise ValueError("Empty cron field")
    if field_str == "*":
        return set(range(min_val, max_val + 1))

    values = set()
    for raw_part in field_str.split(","):
        p = raw_part.strip()
        if not p:
            raise ValueError(f"Invalid empty list element in '{field_str}'")
        has_step = "/" in p
        step = 1
        if has_step:
            subparts = p.split("/")
            if len(subparts) != 2 or not subparts[1].strip():
                raise ValueError(f"Invalid step syntax: {raw_part}")
            p = subparts[0].strip()
            step = int(subparts[1].strip())
            if step <= 0:
                raise ValueError("Cron step must be positive")

        if p == "*" or p == "":
            values.update(range(min_val, max_val + 1, step))
        elif "-" in p:
            range_parts = p.split("-")
            if len(range_parts) != 2:
                raise ValueError(f"Invalid range syntax: {raw_part}")
            start = _parse_cron_atom(range_parts[0], min_val, max_val, aliases=aliases)
            end = _parse_cron_atom(range_parts[1], min_val, max_val, aliases=aliases)
            if start <= end:
                seq = list(range(start, end + 1))
            else:
                upper = wrap_max if wrap_max is not None else max_val
                seq = list(range(start, upper + 1)) + list(range(min_val, end + 1))
            values.update(seq[::step])
        else:
            val = _parse_cron_atom(p, min_val, max_val, aliases=aliases)
            if has_step:
                upper = wrap_max if wrap_max is not None else max_val
                values.update(range(val, upper + 1, step))
            else:
                values.add(val)

    if not values:
        raise ValueError(f"No valid values in field: {field_str}")
    return values


def parse_cron_expression(cron_expr):
    norm = _CRON_MACROS.get(cron_expr.strip().lower(), cron_expr.strip())
    parts = norm.split()
    if len(parts) != 5:
        raise ValueError(f"Cron 表达式必须包含 5 个字段 (分 时 日 月 周)，当前收到 {len(parts)} 个: {cron_expr}")

    minutes = parse_cron_field(parts[0], 0, 59)
    hours = parse_cron_field(parts[1], 0, 23)
    doms = parse_cron_field(parts[2], 1, 31)
    months = parse_cron_field(parts[3], 1, 12, aliases=_MONTH_ALIASES)
    raw_dows = parse_cron_field(parts[4], 0, 7, aliases=_DOW_ALIASES, wrap_max=6)
    dows = {0 if d == 7 else d for d in raw_dows}

    dom_restricted = parts[2].strip() != "*"
    dow_restricted = parts[4].strip() != "*"

    return minutes, hours, doms, months, dows, dom_restricted, dow_restricted


def next_cron_occurrence(cron_expr, from_dt, tz):
    """Evaluate cron expression in local timezone `tz` and return next occurrence in UTC."""
    minutes, hours, doms, months, dows, dom_res, dow_res = parse_cron_expression(cron_expr)

    local_from = from_dt.astimezone(tz)
    curr = local_from.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    # 4+ years covers Feb 29 leap-year schedules cleanly
    limit = curr + datetime.timedelta(days=366 * 4 + 5)

    while curr < limit:
        if curr.month not in months:
            if curr.month == 12:
                curr = curr.replace(year=curr.year + 1, month=1, day=1, hour=0, minute=0)
            else:
                curr = curr.replace(month=curr.month + 1, day=1, hour=0, minute=0)
            continue

        dow = (curr.weekday() + 1) % 7  # 0=Sun..6=Sat
        if dom_res and dow_res:
            day_match = (curr.day in doms) or (dow in dows)
        elif dom_res:
            day_match = curr.day in doms
        elif dow_res:
            day_match = dow in dows
        else:
            day_match = True

        if not day_match:
            curr = (curr + datetime.timedelta(days=1)).replace(hour=0, minute=0)
            continue

        if curr.hour not in hours:
            curr = (curr + datetime.timedelta(hours=1)).replace(minute=0)
            continue

        if curr.minute not in minutes:
            curr += datetime.timedelta(minutes=1)
            continue

        return curr.astimezone(datetime.timezone.utc)

    return None


def validate_cron_min_interval(cron_expr, tz, min_secs=MIN_CRON_INTERVAL_SECS, from_dt=None):
    """Validate cron syntax and enforce minimum interval floor between consecutive triggers."""
    probe = from_dt or datetime.datetime.now(datetime.timezone.utc)
    first_dt = next_cron_occurrence(cron_expr, probe, tz)
    if not first_dt:
        raise ValueError(f"无效或永不触发的 Cron 日期表达式: {cron_expr}")
    prev_dt = first_dt
    for _ in range(5):
        nxt_dt = next_cron_occurrence(cron_expr, prev_dt, tz)
        if not nxt_dt:
            break
        gap = (nxt_dt - prev_dt).total_seconds()
        if gap < min_secs:
            raise ValueError(
                f"Cron 触发间隔过短 ({int(gap)}秒)，周期性任务最小间隔限制为 {min_secs // 60} 分钟"
            )
        prev_dt = nxt_dt
    return first_dt


def parse_relative_time(rel_str, from_dt_utc=None):
    """Strictly parse relative timer strings like 'in 30m', 'in 1h 30m', 'in 2h', '30m', '45分钟'."""
    s = (rel_str or "").strip()
    if not s or "*" in s or len(s.split()) >= 5:
        return None

    low = s.lower()
    has_in = low.startswith("in ")
    body = s[3:].strip() if has_in else s
    if not body:
        return None

    # Without 'in ', require explicit time units on every segment
    if not has_in and not _REL_FULL_RE.match(s):
        return None

    pos = 0
    total_seconds = 0
    matched_any = False
    for m in _REL_TOKEN_RE.finditer(body):
        if body[pos:m.start()].strip():
            return None
        pos = m.end()
        val = int(m.group(1))
        unit = (m.group(2) or ("m" if has_in else "")).lower()
        if not unit:
            return None
        matched_any = True
        if unit in ("d", "day", "days", "天"):
            total_seconds += val * 86400
        elif unit in ("h", "hr", "hrs", "hour", "hours", "小时"):
            total_seconds += val * 3600
        elif unit in ("m", "min", "mins", "minute", "minutes", "分", "分钟"):
            total_seconds += val * 60
        elif unit in ("s", "sec", "secs", "second", "seconds", "秒"):
            total_seconds += val
        else:
            return None

    if body[pos:].strip() or not matched_any or total_seconds <= 0:
        return None

    base = from_dt_utc or datetime.datetime.now(datetime.timezone.utc)
    return base + datetime.timedelta(seconds=total_seconds)


def split_schedule_and_body(raw_text):
    """Parse optional task flags + schedule expression + prompt/command body.

    Returns (sched_expr, body, opts_dict) or raises ValueError on syntax mismatch.
    Supported leading flags (before schedule):
      --model <slug> | -m <slug>
      --loud | --no-silent | --always-notify
      --silent
      --timeout <seconds>
    Supported schedule formats:
      1. Macros: @hourly, @daily, @midnight, @weekly, @monthly
      2. Relative timers: 'in 30m', 'in 1h 30m', 'in 1h30m', '30m', '2h', '45分钟'
      3. Standard 5-field cron: '0 9 * * *', '*/30 9-18 * * MON-FRI'
    """
    s = (raw_text or "").strip()
    opts = {}

    # Parse leading task-level flags before the schedule expression
    while s.startswith("-"):
        parts = s.split(None, 2)
        flag = parts[0].lower()
        if flag in ("--loud", "--no-silent", "--always-notify"):
            opts["silent_if_empty"] = False
            s = s[len(parts[0]):].strip()
        elif flag == "--silent":
            opts["silent_if_empty"] = True
            s = s[len(parts[0]):].strip()
        elif flag in ("--model", "-m") and len(parts) >= 2:
            opts["model"] = parts[1].strip()
            s = parts[2].strip() if len(parts) >= 3 else ""
        elif flag == "--timeout" and len(parts) >= 2 and parts[1].isdigit():
            opts["timeout_secs"] = int(parts[1])
            s = parts[2].strip() if len(parts) >= 3 else ""
        else:
            break

    if not s:
        raise ValueError("缺少定时时间表达式")

    # 1. Macro (@daily, @hourly, ...)
    first_tok = s.split(None, 1)[0]
    if first_tok.lower() in _CRON_MACROS:
        body = s[len(first_tok):].strip()
        return first_tok.lower(), body, opts

    # 2. Relative timer ('in 30m ...', 'in 1h 30m ...', '30m ...')
    m_rel = _REL_PREFIX_RE.match(s)
    if m_rel:
        cand_sched = m_rel.group(1).strip()
        if parse_relative_time(cand_sched) is not None:
            body = (m_rel.group(2) or "").strip()
            return cand_sched, body, opts

    # 3. Standard 5-field cron ('0 9 * * * ...')
    m_cron = re.match(r"^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)(?:\s+([\s\S]+))?$", s)
    if m_cron:
        cand_cron = m_cron.group(1).strip()
        # Validate 5-field cron immediately
        parse_cron_expression(cand_cron)
        body = (m_cron.group(2) or "").strip()
        return cand_cron, body, opts

    raise ValueError(
        "无法识别时间格式，请使用 5 段式 Cron (如 `0 9 * * *`)、宏 (`@daily`) 或倒计时 (如 `in 30m`)"
    )


# ---------------------------------------------------------------- Storage & Task Manager
class TaskManager:
    def __init__(self, filepath=SCHEDULED_TASKS_FILE, lockpath=SCHEDULED_TASKS_LOCK):
        self.filepath = filepath
        self.lockpath = lockpath
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

    def _load_raw(self):
        if not os.path.isfile(self.filepath):
            return {"version": 1, "tasks": {}}
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
                if "tasks" not in data:
                    data["tasks"] = {}
                return data
        except Exception:
            return {"version": 1, "tasks": {}}

    def _save_raw(self, data):
        tmp = f"{self.filepath}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.filepath)

    @staticmethod
    def _matches_bot(task, bot_instance_id):
        if not bot_instance_id:
            return True
        owner = task.get("bot_instance_id")
        return (not owner) or (owner == bot_instance_id)

    def list_tasks(self, bot_instance_id=None):
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                data = self._load_raw()
                return [
                    t for t in data.get("tasks", {}).values()
                    if self._matches_bot(t, bot_instance_id)
                ]
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def get_task(self, task_id):
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                data = self._load_raw()
                return data.get("tasks", {}).get(task_id)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def create_task(self, name, schedule_expr, task_type, payload,
                    target_chat_id=None, target_thread_id=None, session_mode="isolated",
                    model="gemini-3.8-flash-low", project=None, workdir=None,
                    timeout_secs=None, silent_if_empty=None, custom_id=None,
                    bot_instance_id=None):
        """Validate, create, and atomically persist a new scheduled task."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tz, _ = get_scheduler_tz()

        rel_target = parse_relative_time(schedule_expr, from_dt_utc=now_utc)
        if rel_target:
            sched_type = "once"
            cron_expr = None
            next_run_dt = rel_target
        else:
            sched_type = "cron"
            cron_expr = schedule_expr.strip()
            next_run_dt = validate_cron_min_interval(cron_expr, tz, from_dt=now_utc)

        if silent_if_empty is None:
            if sched_type == "once" or task_type in ("cost_report", "usage_report", "browser"):
                silent_if_empty = False
            else:
                silent_if_empty = True

        if timeout_secs is None:
            timeout_secs = 300 if task_type == "browser" else (240 if task_type == "agent" else 180)

        tid = custom_id or f"task-{int(time.time() * 1000) % 1000000:06x}"

        task = {
            "id": tid,
            "name": (name or "").strip() or f"Task-{tid}",
            "enabled": True,
            "bot_instance_id": bot_instance_id,
            "schedule_type": sched_type,
            "schedule_expr": schedule_expr.strip(),
            "cron_expr": cron_expr,
            "task_type": task_type,  # 'agent', 'script', 'cost_report', 'browser'
            "payload": payload or {},
            "execution": {
                "session_mode": session_mode or "isolated",
                "model": model or "gemini-3.8-flash-low",
                "project": project or "agy-cli-bot",
                "workdir": workdir,
                "timeout_secs": int(timeout_secs),
            },
            "delivery": {
                "target_chat_id": target_chat_id,
                "target_thread_id": target_thread_id,
                "silent_if_empty": bool(silent_if_empty),
                "notify_on_failure": True,
                "header_prefix": "⏰",
            },
            "state": {
                "created_at": format_iso_utc(now_utc),
                "last_run_at": None,
                "last_status": "pending",
                "last_error": None,
                "run_count": 0,
                "next_run_at": format_iso_utc(next_run_dt),
            },
        }

        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                data["tasks"][tid] = task
                self._save_raw(data)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

        return task

    def delete_task(self, task_id):
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                if task_id in data.get("tasks", {}):
                    del data["tasks"][task_id]
                    self._save_raw(data)
                    return True
                return False
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def toggle_task(self, task_id, enable=None):
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tz, _ = get_scheduler_tz()
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                t = data.get("tasks", {}).get(task_id)
                if not t:
                    return None
                if enable is None:
                    t["enabled"] = not t.get("enabled", True)
                else:
                    t["enabled"] = bool(enable)

                if t["enabled"]:
                    if t.get("schedule_type") == "cron" and t.get("cron_expr"):
                        n_dt = next_cron_occurrence(t["cron_expr"], now_utc, tz)
                        t["state"]["next_run_at"] = format_iso_utc(n_dt)
                    elif t.get("schedule_type") == "once":
                        cur_nxt = parse_iso_utc(t.get("state", {}).get("next_run_at"))
                        if not cur_nxt or cur_nxt <= now_utc:
                            n_dt = parse_relative_time(t.get("schedule_expr", ""), from_dt_utc=now_utc)
                            t["state"]["next_run_at"] = format_iso_utc(n_dt)

                self._save_raw(data)
                return t["enabled"]
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def toggle_silent(self, task_id):
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                t = data.get("tasks", {}).get(task_id)
                if not t:
                    return None
                deliv = t.setdefault("delivery", {})
                deliv["silent_if_empty"] = not bool(deliv.get("silent_if_empty", True))
                self._save_raw(data)
                return deliv["silent_if_empty"]
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def get_due_tasks(self, now_utc=None, bot_instance_id=None):
        """Atomically find due tasks belonging to `bot_instance_id`, advance `next_run_at`, and return them."""
        now_utc = now_utc or datetime.datetime.now(datetime.timezone.utc)
        tz, _ = get_scheduler_tz()
        due = []

        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                dirty = False
                for _tid, t in list(data.get("tasks", {}).items()):
                    if not t.get("enabled", True):
                        continue
                    if not self._matches_bot(t, bot_instance_id):
                        continue
                    nxt_str = t.get("state", {}).get("next_run_at")
                    if not nxt_str:
                        continue
                    nxt_dt = parse_iso_utc(nxt_str)
                    if not nxt_dt:
                        continue

                    if nxt_dt <= now_utc:
                        if bot_instance_id and not t.get("bot_instance_id"):
                            t["bot_instance_id"] = bot_instance_id
                        due.append(dict(t))
                        dirty = True
                        if t.get("schedule_type") == "once":
                            t["enabled"] = False
                            t["state"]["next_run_at"] = None
                        else:
                            floor_dt = max(
                                now_utc,
                                nxt_dt + datetime.timedelta(seconds=MIN_CRON_INTERVAL_SECS - 60),
                            )
                            n_dt = next_cron_occurrence(t["cron_expr"], floor_dt, tz)
                            t["state"]["next_run_at"] = format_iso_utc(n_dt)
                if dirty:
                    self._save_raw(data)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

        return due

    def record_completion(self, task_id, status, error=None, last_snippet=None):
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        with open(self.lockpath, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load_raw()
                t = data.get("tasks", {}).get(task_id)
                if not t:
                    return
                st = t.setdefault("state", {})
                st["last_run_at"] = format_iso_utc(now_utc)
                st["last_status"] = "success" if status == "success" else "failed"
                st["last_error"] = str(error) if error else None
                st["run_count"] = int(st.get("run_count") or 0) + 1
                if last_snippet:
                    st["last_output_snippet"] = last_snippet[:300]
                self._save_raw(data)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


# Global task manager instance
task_mgr = TaskManager()


# ---------------------------------------------------------------- Telegram Panel Formatter
def build_schedule_panel(view="list", selected_task_id=None, bot_instance_id=None):
    """Render interactive Telegram HTML message and inline keyboard."""
    tz, tz_lbl = get_scheduler_tz()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_loc = now_utc.astimezone(tz)
    tasks = task_mgr.list_tasks(bot_instance_id=bot_instance_id)

    header = (
        f"<b>⏰ 定时任务调度器</b>\n"
        f"<code>时区: {tz_lbl} · 当前时间: {now_loc.strftime('%m-%d %H:%M:%S')}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
    )

    if view == "detail" and selected_task_id:
        t = task_mgr.get_task(selected_task_id)
        if not t:
            view = "list"
        else:
            st = t.get("state", {})
            ex = t.get("execution", {})
            deliv = t.get("delivery", {})
            status_icon = "🟢 运行中" if t.get("enabled", True) else "🔴 已暂停/已完成"
            nxt_dt = parse_iso_utc(st.get("next_run_at"))
            rem_str = format_countdown(nxt_dt, now_utc)
            nxt_loc_str = nxt_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S") if nxt_dt else "无计划"
            last_dt = parse_iso_utc(st.get("last_run_at"))
            last_loc_str = last_dt.astimezone(tz).strftime("%m-%d %H:%M:%S") if last_dt else "尚未运行"
            ttype = t.get("task_type")
            model_line = (
                f"• <b>执行模型</b>: <code>{ex.get('model', 'default')}</code> (隔离会话)\n"
                if ttype in ("agent", "browser")
                else "• <b>执行通道</b>: <code>原生零 Token 直连</code>\n"
            )
            silent_on = bool(deliv.get("silent_if_empty", True))
            tgt_thread = deliv.get("target_thread_id")
            route_line = f"• <b>投递目标</b>: <code>chat {deliv.get('target_chat_id')} / Topic #{tgt_thread}</code>\n" if tgt_thread else ""

            body = (
                f"📌 <b>任务详情: {html_mod.escape(t.get('name', ''))}</b> (<code>{t['id']}</code>)\n\n"
                f"• <b>状态</b>: {status_icon}\n"
                f"• <b>类型</b>: <code>{ttype}</code>\n"
                f"• <b>计划</b>: <code>{html_mod.escape(t.get('schedule_expr', ''))}</code> ({t.get('schedule_type')})\n"
                f"• <b>下次执行</b>: <code>{nxt_loc_str}</code> (<b>{rem_str}</b>)\n"
                f"{route_line}"
                f"{model_line}"
                f"• <b>静默空结果</b>: <code>{'开启 (无新内容不打扰)' if silent_on else '关闭 (每次必汇报)'}</code>\n"
                f"• <b>累计执行</b>: <code>{st.get('run_count', 0)} 次</code> · 上次: <code>{last_loc_str}</code> (<code>{st.get('last_status', 'pending')}</code>)\n"
            )
            if st.get("last_error"):
                body += f"⚠️ <b>最近错误</b>: <code>{html_mod.escape(st['last_error'][:240])}</code>\n"
            if t.get("payload"):
                payload_str = json.dumps(t["payload"], ensure_ascii=False)
                if len(payload_str) > 160:
                    payload_str = payload_str[:160] + "..."
                body += f"📦 <b>载荷内容</b>: <code>{html_mod.escape(payload_str)}</code>\n"

            toggle_label = "⏸ 暂停任务" if t.get("enabled", True) else "▶ 启用任务"
            silent_label = f"🔕 静默空结果: {'开' if silent_on else '关'}"
            kb = {
                "inline_keyboard": [
                    [
                        {"text": toggle_label, "callback_data": f"sched:toggle:{t['id']}"},
                        {"text": "⚡ 立即触发一次", "callback_data": f"sched:run:{t['id']}"},
                    ],
                    [
                        {"text": silent_label, "callback_data": f"sched:silent:{t['id']}"},
                        {"text": "🗑 删除任务", "callback_data": f"sched:del:{t['id']}"},
                    ],
                    [
                        {"text": "🔙 返回列表", "callback_data": "sched:list:all"},
                    ],
                ]
            }
            return header + body, kb

    # Default: List view
    if not tasks:
        body = (
            "<i>当前暂无生效中的定时任务。</i>\n\n"
            "<b>常用创建语法示例:</b>\n"
            "• <code>/schedule cost 0 9 * * *</code> (每天早9点账单，0 Token)\n"
            "• <code>/schedule add 0 9 * * * 用 mail-ctl 检查未读重要邮件</code>\n"
            "• <code>/schedule browser 30 9 * * * 检查站点登录状态并截图</code>\n"
            "• <code>/schedule script 0 0 * * * python3 /path/to/job.py</code>\n"
            "• <code>/schedule in 30m 提醒我检查线上服务状态</code>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "➕ 早 9 点账单预设", "callback_data": "sched:preset:cost"},
                    {"text": "➕ 每小时巡检预设", "callback_data": "sched:preset:hourly"},
                ],
                [{"text": "🔄 刷新", "callback_data": "sched:list:all"}],
            ]
        }
        return header + body, kb

    active_count = sum(1 for t in tasks if t.get("enabled", True))
    paused_count = len(tasks) - active_count

    rows = []
    kb_task_buttons = []
    for t in sorted(tasks, key=lambda x: (not x.get("enabled", True), x.get("state", {}).get("next_run_at") or "9999")):
        st = t.get("state", {})
        status_pill = "🟢" if t.get("enabled", True) else "🔴"
        nxt_dt = parse_iso_utc(st.get("next_run_at"))
        rem_str = format_countdown(nxt_dt, now_utc)
        type_lbl = {
            "cost_report": "报表",
            "usage_report": "套餐配额",
            "agent": "Agent",
            "script": "脚本",
            "browser": "浏览器",
        }.get(t.get("task_type"), t.get("task_type"))

        row_str = (
            f"{status_pill} <b>{html_mod.escape(t.get('name', ''))}</b> (<code>{t['id']}</code>)\n"
            f"   • 计划: <code>{html_mod.escape(t.get('schedule_expr', ''))}</code> · <code>{type_lbl}</code>\n"
            f"   • 下次: <code>{rem_str}</code> · 运行: <code>{st.get('run_count', 0)}次</code>"
        )
        if st.get("last_status") == "failed":
            row_str += " · ⚠️ <code>异常</code>"
        rows.append(row_str)

        btn_mark = "🟢" if t.get("enabled", True) else "🔴"
        kb_task_buttons.append({
            "text": f"{btn_mark} {t.get('name', '')[:12]}",
            "callback_data": f"sched:view:{t['id']}",
        })

    body = (
        "\n".join(rows) + "\n\n"
        f"📊 <b>统计</b>: 活跃 <code>{active_count}</code> 个 · 暂停 <code>{paused_count}</code> 个 · 总计 <code>{len(tasks)}</code> 个\n"
        f"<i>💡 点击下方按钮管理任务，或发送 <code>/schedule help</code> 查看完整语法</i>"
    )

    btn_grid = [kb_task_buttons[i:i + 2] for i in range(0, len(kb_task_buttons), 2)]
    bottom_row = [
        {"text": "➕ 预设: 早9点账单", "callback_data": "sched:preset:cost"},
        {"text": "🔄 刷新", "callback_data": "sched:list:all"},
    ]
    btn_grid.append(bottom_row)

    return header + body, {"inline_keyboard": btn_grid}
