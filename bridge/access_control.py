#!/usr/bin/env python3
"""RBAC & chat/user authorization helpers for `agy-tg-bridge`."""

from __future__ import annotations

import html as html_mod
from typing import Iterable, Optional, Set, Tuple


def parse_uid_set(raw: Optional[str]) -> Set[int]:
    """Parse comma/whitespace-separated integer Telegram IDs into a set."""
    out: Set[int] = set()
    if not raw:
        return out
    for tok in str(raw).replace(" ", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.add(int(tok))
        except ValueError:
            continue
    return out


def parse_bool_flag(raw: Optional[str], default: bool = False) -> bool:
    """Parse an environment boolean flag (`1`/`true`/`yes` vs `0`/`false`/`no`)."""
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if not s:
        return default
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def extract_user_id(from_user) -> Optional[int]:
    """Safely extract integer user ID from a Telegram User dict."""
    if not isinstance(from_user, dict):
        return None
    raw_id = from_user.get("id")
    if raw_id is None or raw_id == "":
        return None
    try:
        return int(raw_id)
    except (TypeError, ValueError):
        return None


def resolve_user_role(
    chat_id,
    from_user=None,
    *,
    allowed_chats: Iterable[int],
    allowed_users: Iterable[int] = (),
    admin_users: Iterable[int] = (),
    readonly_users: Iterable[int] = (),
    allow_group_readonly: bool = False,
    allow_uid_fallback: bool = False,
) -> str:
    """Resolve RBAC role for a message/callback: `'admin'`, `'readonly'`, or `'denied'`.

    Backward compatibility:
    - When `admin_users`, `readonly_users`, and `allow_group_readonly` are all unset,
      behavior matches legacy `AGY_TG_ALLOWED_CHATS` + `AGY_TG_ALLOWED_USERS` 100%.
    - When `admin_users` is unset, `allowed_users` carries full admin semantics.
    - `readonly` never bypasses `allowed_chats`.
    """
    allowed_chats_set = set(allowed_chats or ())
    if not allowed_chats_set:
        return "denied"

    uid = extract_user_id(from_user)
    chat_ok = (chat_id in allowed_chats_set) or (
        allow_uid_fallback and uid is not None and uid in allowed_chats_set
    )
    if not chat_ok:
        return "denied"

    # Internal chat-only authorization check (no user object supplied)
    if from_user is None:
        return "admin"

    allowed_users_set = set(allowed_users or ())
    admin_users_set = set(admin_users or ())
    readonly_users_set = set(readonly_users or ())
    effective_admins = admin_users_set if admin_users_set else allowed_users_set

    is_group = bool(chat_id is not None and int(chat_id) < 0)

    if effective_admins:
        if uid is not None and uid in effective_admins:
            return "admin"
        if uid is not None and uid in readonly_users_set:
            return "readonly"
        if admin_users_set and allowed_users_set and uid is not None and uid in allowed_users_set:
            return "readonly"
        if allow_group_readonly and is_group:
            return "readonly"
        return "denied"

    if uid is not None and uid in readonly_users_set:
        return "readonly"
    if allow_group_readonly and is_group:
        return "readonly"
    return "admin"


def is_authorized(
    chat_id,
    from_user=None,
    *,
    allowed_chats: Iterable[int],
    allowed_users: Iterable[int] = (),
    admin_users: Iterable[int] = (),
    readonly_users: Iterable[int] = (),
    allow_group_readonly: bool = False,
    allow_uid_fallback: bool = False,
) -> bool:
    """Return True if user/chat holds `'admin'` or `'readonly'` access."""
    role = resolve_user_role(
        chat_id,
        from_user=from_user,
        allowed_chats=allowed_chats,
        allowed_users=allowed_users,
        admin_users=admin_users,
        readonly_users=readonly_users,
        allow_group_readonly=allow_group_readonly,
        allow_uid_fallback=allow_uid_fallback,
    )
    return role in ("admin", "readonly")


_ALWAYS_READONLY_COMMANDS = frozenset({
    "/start",
    "/help",
    "/status",
    "/usage",
    "/quota",
    "/context",
    "/sessions",
    "/files",
})

_VIEW_ONLY_WHEN_EMPTY_COMMANDS = frozenset({
    "/model",
    "/effort",
    "/project",
    "/team",
    "/bots",
    "/browser",
    "/profile",
})

_SCHEDULE_COMMANDS = frozenset({"/schedule", "/cron", "/timer", "/timers"})
_COST_COMMANDS = frozenset({"/cost", "/bill"})

_READONLY_CALLBACK_EXACT = frozenset({
    "action:usage",
    "usage:refresh",
    "action:cost",
    "action:context",
    "action:schedule",
    "action:team",
    "action:project",
    "action:model",
    "action:effort",
    "action:files",
    "action:browser",
    "browser:refresh",
    "browser:card_refresh",
    "sched:list",
    "team:refresh",
})


def is_command_allowed_for_role(role: str, cmd: str, raw_rest: str = "") -> Tuple[bool, str]:
    """Check whether `role` may execute slash command `cmd` with arguments `raw_rest`."""
    if role == "admin":
        return True, ""
    if role != "readonly":
        return False, "unauthorized"

    c = (cmd or "").strip().lower()
    rest = (raw_rest or "").strip()
    sub = rest.split()[0].lower() if rest else ""

    if c in _ALWAYS_READONLY_COMMANDS:
        return True, ""
    if c in _COST_COMMANDS:
        if sub in ("reset", "calibrate"):
            return False, f"{c} {sub}"
        return True, ""
    if c in _VIEW_ONLY_WHEN_EMPTY_COMMANDS:
        if not rest:
            return True, ""
        return False, f"{c} {sub}"
    if c in _SCHEDULE_COMMANDS:
        if not rest or sub in ("list", "show", "panel", "help", "-h", "--help"):
            return True, ""
        return False, f"{c} {sub}"
    if c == "/compact":
        if sub in ("status", "info", "panel"):
            return True, ""
        return False, c
    if c == "/dream":
        if not rest or sub in ("status", "info"):
            return True, ""
        return False, f"{c} {sub}"

    return False, c


def is_callback_allowed_for_role(role: str, callback_data: str) -> Tuple[bool, str]:
    """Check whether `role` may trigger an inline-keyboard callback."""
    if role == "admin":
        return True, ""
    if role != "readonly":
        return False, "unauthorized"

    data = (callback_data or "").strip()
    if data in _READONLY_CALLBACK_EXACT:
        return True, ""
    if data.startswith("cost:") or data.startswith("sched:view:") or data.startswith("mp:"):
        return True, ""
    return False, data


def build_readonly_prompt_prefix(uid: Optional[int] = None) -> str:
    """Build strict system-level sandbox instruction prepended to readonly guest turns."""
    uid_label = str(uid) if uid is not None else "unknown"
    return (
        f"[ACB_READONLY_GUEST user_id={uid_label} role=readonly]\n"
        "当前提问者为群内只读访客（readonly），本次会话处于严格只读沙箱隔离模式：\n"
        "- 严禁创建、修改、删除或写入任何工作区或系统文件。\n"
        "- 严禁执行会修改状态的 shell/git/部署/重启命令，严禁调用团队派工（bot_bus / delegate）或修改定时任务。\n"
        "- 严禁读取或泄露任何密钥、环境变量、.env、token、OpenBao 或敏感凭证内容。\n"
        "- 仅可进行只读代码/文档解释、状态问答与只读分析；若对方请求写入代码、修改配置或读取凭证，请礼貌拒绝并告知仅管理员可操作。"
    )


def format_rbac_denied_message(action_label: str, is_callback: bool = False) -> str:
    """Return a polite user-facing RBAC denial message."""
    if is_callback:
        return "🔒 权限不足：当前账号为只读访客（readonly），仅管理员可执行此操作。"
    safe_action = html_mod.escape(action_label or "该操作")
    return (
        f"🔒 <b>权限不足（只读访客 readonly）</b>\n"
        f"当前账号无权执行 <code>{safe_action}</code>（仅管理员可修改状态或触发写操作）。\n"
        f"<i>可用只读查询：<code>/help</code>、<code>/status</code>、<code>/usage</code>、<code>/cost</code>、<code>/context</code> 及普通问答。</i>"
    )
