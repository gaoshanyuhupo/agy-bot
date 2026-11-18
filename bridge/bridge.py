#!/usr/bin/env python3
"""agy-tg-bridge v3: Ultra-low-latency Real-Time Telegram bridge for Antigravity CLI.

Key Real-Time Architecture:
- Native Telegram Bot API `sendMessageDraft` (Bot API 9.5+) streaming engine:
  * 0ms instant "Thinking…" bubble + native Stop button (`can_stop=True` / `stopped_message_generation`)
  * Event-driven instant (<50ms) live updates on every thought block, tool start, and tool completion
  * ~4.5 fps (0.22s) non-blocking animated token streaming during `agent_response`
  * Automatic fallback to `sendMessage` + `editMessageText` in environments without draft support
- Non-blocking `AgySession` stdout event queue with 60ms `result` lookahead coalescing:
  * Final turns deliver in ONE atomic `sendMessage` (replacing the draft seamlessly with collapsible
    thinking/tools + formatted HTML + usage footer + file buttons, zero post-send edit flash)
  * Intermediate turns (e.g. QR codes, milestones before background waits) flush immediately at +60ms
    and auto-push referenced/generated images via `sendPhoto`
- Persistent warm `--input-format stream-json --output-format stream-json` process pool
"""
import collections
import datetime
import fcntl
import glob
import hashlib
import html as html_mod
import itertools
import json
import os
import queue
import random
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import zlib
try:
    import zoneinfo
except ImportError:
    zoneinfo = None

import requests

try:
    import scheduler
except ImportError:
    from bridge import scheduler

try:
    import bot_bus
except ImportError:
    from bridge import bot_bus

# Load local .env file if present
_env_file = os.environ.get("AGY_TG_ENV_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
if os.path.isfile(_env_file):
    with open(_env_file, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ[_k.strip()] = _v.strip().strip("'\"")

HOME = os.path.expanduser("~")
BOT_TOKEN = os.environ.get("AGY_TG_BOT_TOKEN", "")
ALLOWED = {int(x) for x in os.environ.get("AGY_TG_ALLOWED_CHATS", "").split(",") if x.strip()}
ALLOWED_USERS = {int(x) for x in os.environ.get("AGY_TG_ALLOWED_USERS", "").split(",") if x.strip()}
WORKDIR = os.path.realpath(os.environ.get("AGY_TG_WORKDIR", os.path.join(HOME, "agy-workspace")))
UPLOADDIR = os.path.join(WORKDIR, "uploads")
BRAIN_ROOT = os.path.join(HOME, ".gemini/antigravity-cli/brain")
PROJECTS_DIR = os.path.join(HOME, ".gemini/config/projects")
AGY_BIN = os.environ.get("AGY_TG_AGY_BIN", os.path.join(HOME, ".local/bin/agy"))
PRINT_TIMEOUT = os.environ.get("AGY_TG_PRINT_TIMEOUT", "30m")
STATE_FILE = os.environ.get("AGY_TG_STATE_FILE", os.path.join(HOME, ".agy-tg-bridge-state.json"))
RELOAD_TRIGGER = os.environ.get("AGY_TG_RELOAD_FILE", "/tmp/agy_bridge_reload")
BOT_INSTANCE_ID = hashlib.sha1((os.path.realpath(STATE_FILE) + "|" + BOT_TOKEN[:12]).encode("utf-8")).hexdigest()[:10]
BOT_OUTBOX_DIR = os.path.join("/tmp", f"agy-outbox-{BOT_INSTANCE_ID}")
IMG_CLAIMS_FILE = "/tmp/agy_bridge_img_claims.json"
ACB_UNDO_DIR = os.path.join(HOME, ".gemini/antigravity-cli/cache/acb_undo")
ACB_UNDO_BLOBS_DIR = os.path.join(ACB_UNDO_DIR, "blobs")
os.makedirs(BOT_OUTBOX_DIR, exist_ok=True)
os.makedirs(ACB_UNDO_BLOBS_DIR, exist_ok=True)
IDLE_SESSION_TTL = int(os.environ.get("AGY_TG_IDLE_TTL", "2700"))
MAX_WARM_SESSIONS = int(os.environ.get("AGY_TG_MAX_WARM_SESSIONS", "4"))
ALBUM_DEBOUNCE_SECONDS = float(os.environ.get("AGY_TG_ALBUM_DEBOUNCE", "1.25"))
DEFAULT_AUTO_COMPACT_TOKENS = int(os.environ.get("AGY_TG_AUTO_COMPACT_TOKENS", "140000"))
AGY_HARD_COMPACT_CEILING = 254000
META_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/conversation_metadata.json")
SUMMARIES_DB = os.path.join(HOME, ".gemini/antigravity-cli/conversation_summaries.db")
COST_LEDGER_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/cost_ledger_v2.json")
COST_CONFIG_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/cost_config.json")
QUOTA_CACHE_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/quota_usage.json")
COST_LEDGER_LOCK = "/tmp/agy_cost_ledger.lock"
SCHEDULED_CIDS_FILE = os.path.join(HOME, ".gemini/antigravity-cli/cache/scheduled_cids.json")
COST_TZ_NAME = os.environ.get("AGY_TG_COST_TZ", "Asia/Shanghai")
AGY_REPO_DIR = os.environ.get("AGY_REPO_DIR", os.path.join(HOME, "agy-cli-bot"))
AGY_BROWSER_PROFILE_LABEL = os.environ.get("AGY_BROWSER_PROFILE_LABEL", "persistent-profile").strip()
STT_BASE = os.environ.get("AGY_TG_STT_BASE", "")
STT_KEY = os.environ.get("AGY_TG_STT_KEY", "")
STT_MODEL = os.environ.get("AGY_TG_STT_MODEL", "whisper-1")
ENV_BOT_ROLE = os.environ.get("AGY_TG_BOT_ROLE", "").strip().lower()
ENV_BOT_MODEL = os.environ.get("AGY_TG_BOT_MODEL", "").strip()
ENV_BOT_PROJECT = os.environ.get("AGY_TG_BOT_PROJECT", "").strip()
ENV_BOT_SPECIALTY = os.environ.get("AGY_TG_BOT_SPECIALTY", "").strip()
_raw_bus_chat_mode = os.environ.get("AGY_BUS_CHAT_MODE", "conversational").strip().lower()
BUS_CHAT_MODE = _raw_bus_chat_mode if _raw_bus_chat_mode in ("conversational", "card") else "conversational"
BUS_FAST_CHAT_ENABLED = os.environ.get("AGY_BUS_FAST_CHAT", "1").strip().lower() not in ("0", "false", "no")
_fast_chat_sem = threading.Semaphore(1)
API = "https://api.telegram.org/bot" + BOT_TOKEN

BOT_META = {
    "bot_id": 0,
    "handle": f"bot_{BOT_INSTANCE_ID}",
    "first_name": "Antigravity Bot",
    "resolved": False,
}
_active_bus_job_id = None

EFFORTS = ("low", "medium", "high", "xhigh", "max")
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif")

# Timeouts: (connect_timeout, read_timeout)
FAST_TIMEOUT = (3.5, 6.0)
DEFAULT_TIMEOUT = (8.0, 30.0)

# Force IPv4 for Telegram Bot API by default so flaky IPv6 paths don't stall polling/edits.
if os.environ.get("AGY_TG_FORCE_IPV4", "1").strip().lower() not in ("0", "false", "no"):
    try:
        import socket
        import urllib3.util.connection as _urllib3_cn
        _urllib3_cn.allowed_gai_family = lambda: socket.AF_INET
    except Exception:
        pass

# Persistent HTTP session (thread-safe connection pool)
_http_session_lock = threading.Lock()


def _build_http_session():
    """Create a fresh requests.Session with bounded connection pooling."""
    sess = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


def _reset_http_session(reason=None):
    """Atomically swap `http_session` without closing in-flight worker connections."""
    global http_session
    new_sess = _build_http_session()
    with _http_session_lock:
        http_session = new_sess
    if reason:
        log("Rebuilt http_session connection pool (%s)" % reason)
    return new_sess


http_session = _build_http_session()

_instance_lock_fh = None
_instance_lock_path_held = None


def _instance_lock_path():
    """Return a per-bot isolated lock path so distinct bots never block each other."""
    lock_dir = os.environ.get("AGY_TG_LOCK_DIR") or tempfile.gettempdir()
    key = f"token:{BOT_TOKEN}" if BOT_TOKEN else f"state:{os.path.realpath(STATE_FILE)}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return os.path.join(lock_dir, f"agy-tg-bridge-{digest}.lock")


def _acquire_instance_lock(lock_path=None):
    """Acquire an exclusive non-blocking flock for this bot instance.

    Sets FD_CLOEXEC so `os.execv` hot reload atomically closes the fd at exec time
    and lets the re-exec'd process seamlessly re-acquire the lock.
    """
    global _instance_lock_fh, _instance_lock_path_held
    target = lock_path or _instance_lock_path()
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    if _instance_lock_fh is not None:
        if _instance_lock_path_held == target:
            return _instance_lock_fh
        _release_instance_lock()

    fh = open(target, "a+", encoding="utf-8")
    try:
        os.set_inheritable(fh.fileno(), False)
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        owner_pid = ""
        try:
            fh.seek(0)
            lines = fh.read().strip().splitlines()
            if lines:
                owner_pid = lines[0].strip()
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass
        pid_note = f", pid={owner_pid}" if owner_pid else ""
        msg = (
            f"ERROR: Another bridge instance is already running for this bot "
            f"(lock={target}{pid_note}): {e}"
        )
        print(msg, file=sys.stderr, flush=True)
        raise SystemExit(1)

    try:
        fh.seek(0)
        fh.truncate(0)
        fh.write(f"{os.getpid()}\n{BOT_INSTANCE_ID}\n")
        fh.flush()
    except Exception:
        pass
    _instance_lock_fh = fh
    _instance_lock_path_held = target
    return fh


def _release_instance_lock():
    """Release the held instance flock (used in tests and clean process exit)."""
    global _instance_lock_fh, _instance_lock_path_held
    fh = _instance_lock_fh
    _instance_lock_fh = None
    _instance_lock_path_held = None
    if fh is not None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass

shutting_down = False


class _JobQueue:
    """Thread-safe FIFO job queue supporting per-scope inspection and selective cancellation."""

    def __init__(self):
        self._cond = threading.Condition()
        self._items = collections.deque()

    def put(self, item):
        with self._cond:
            self._items.append(item)
            self._cond.notify()

    def get(self):
        with self._cond:
            while not self._items:
                self._cond.wait()
            return self._items.popleft()

    def qsize(self):
        with self._cond:
            return len(self._items)

    def empty(self):
        with self._cond:
            return not self._items

    def task_done(self):
        pass

    def _item_scope(self, item):
        if isinstance(item, tuple):
            if len(item) >= 3:
                return item[2]
            if len(item) == 2:
                return scope_key_for(item[0], None)
        return None

    def count_scope(self, scope_key):
        with self._cond:
            return sum(1 for it in self._items if self._item_scope(it) == scope_key)

    def cancel_scope(self, scope_key):
        removed = 0
        kept = collections.deque()
        with self._cond:
            while self._items:
                it = self._items.popleft()
                if self._item_scope(it) == scope_key:
                    removed += 1
                else:
                    kept.append(it)
            self._items = kept
        return removed

    def clear_all(self):
        with self._cond:
            removed = len(self._items)
            self._items.clear()
        return removed


job_q = _JobQueue()

# Monotonic non-zero draft_id generator (1 .. 2_000_000_000)
_draft_id_lock = threading.Lock()
_draft_id_seq = itertools.count(int(time.time() * 10) % 1_500_000_000 + 100)


def alloc_draft_pair():
    """Allocate two consecutive non-zero draft IDs: (status_draft_id, text_draft_id)."""
    with _draft_id_lock:
        d1 = (next(_draft_id_seq) % 2_000_000_000) or 1
        d2 = (next(_draft_id_seq) % 2_000_000_000) or 2
        return d1, d2


# Session & turn lifecycle state
session_lock = threading.Lock()
_session_pool = {}          # scope_key -> warm AgySession instance
turn_running = False        # True ONLY while run_agy / run_compact is executing a turn
turn_running_scope = None   # scope_key of currently executing interactive turn
turn_running_chat = None    # chat_id of currently executing interactive turn
session_dirty_scopes = set()  # scope_keys whose warm session must recycle after active turn
cancel_requested = False    # True if user triggered /cancel or native Stop button

state_lock = threading.Lock()
_last_compacted_line = {}  # cid -> transcript line count at last bridge-driven compaction

PRIMARY_CHAT_ID = next((c for c in sorted(ALLOWED) if c > 0), next(iter(sorted(ALLOWED)), None))
PRIMARY_SCOPE_KEY = str(PRIMARY_CHAT_ID) if PRIMARY_CHAT_ID is not None else "default"

_SCOPE_PREF_KEYS = ("mode", "model", "effort", "thinking", "auto_compact", "auto_compact_tokens")


def _normalize_thread_id(tid):
    """Normalize Telegram topic thread_id; General topic (1) or <= 0 maps to None."""
    if tid is None or tid == "":
        return None
    try:
        val = int(tid)
    except (TypeError, ValueError):
        return None
    return val if val > 1 else None


def _extract_thread_id(msg):
    """Extract normalized Forum/DM topic thread_id from a Telegram Message dict."""
    if not isinstance(msg, dict):
        return None
    raw_tid = msg.get("message_thread_id")
    if raw_tid is None:
        return None
    chat = msg.get("chat") or {}
    if msg.get("is_topic_message") or chat.get("is_forum"):
        return _normalize_thread_id(raw_tid)
    return None


def scope_key_for(chat_id, thread_id=None):
    """Canonical persistence/routing key for a chat or Telegram Topic."""
    if chat_id is None:
        return PRIMARY_SCOPE_KEY
    norm_tid = _normalize_thread_id(thread_id)
    if norm_tid is not None:
        return f"{int(chat_id)}:{norm_tid}"
    return f"{int(chat_id)}"


def parse_scope_key(scope_key):
    """Decode `scope_key` back into `(chat_id: int|None, thread_id: int|None)`."""
    if not scope_key or scope_key == "default":
        return PRIMARY_CHAT_ID, None
    s = str(scope_key)
    if ":" in s:
        c_part, t_part = s.split(":", 1)
        try:
            return int(c_part), _normalize_thread_id(t_part)
        except ValueError:
            return PRIMARY_CHAT_ID, None
    try:
        return int(s), None
    except ValueError:
        return PRIMARY_CHAT_ID, None


def _is_authorized(chat_id, from_user=None, allow_uid_fallback=False):
    if not ALLOWED:
        return False
    uid = (from_user or {}).get("id") if isinstance(from_user, dict) else None
    if ALLOWED_USERS and uid is not None and uid not in ALLOWED_USERS:
        return False
    if chat_id in ALLOWED:
        return True
    if allow_uid_fallback and uid is not None and uid in ALLOWED:
        return True
    return False


def _format_scope_badge(chat_id, thread_id=None):
    norm_tid = _normalize_thread_id(thread_id)
    if norm_tid is not None:
        return f"Topic #{norm_tid} (群 {chat_id})" if (chat_id and int(chat_id) < 0) else f"Topic #{norm_tid}"
    if chat_id is not None and int(chat_id) < 0:
        return f"群组主区 ({chat_id})"
    return f"私聊 DM ({chat_id})" if chat_id is not None else "默认会话"


def _default_scope_state(prefs_source=None):
    src = prefs_source if isinstance(prefs_source, dict) else {}
    return {
        "conversation_id": None,
        "project": None,
        "workdir": None,
        "mode": src.get("mode") or "auto",
        "model": src.get("model"),
        "effort": src.get("effort"),
        "thinking": bool(src.get("thinking", True)),
        "auto_compact": bool(src.get("auto_compact", True)),
        "auto_compact_tokens": int(src.get("auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS),
        "auto_compact_v2_migrated": True,
        "in_flight": None,
        "last_turn": None,
        "undo_stack": [],
        "redo_stack": [],
        "pending_undo_notice": None,
    }


state = {
    "conversation_id": None,
    "project": None,
    "workdir": None,
    "mode": "auto",
    "model": None,
    "effort": None,
    "thinking": True,
    "auto_compact": True,
    "auto_compact_tokens": DEFAULT_AUTO_COMPACT_TOKENS,
    "auto_compact_v2_migrated": True,
    "in_flight": None,
    "primary_scope": PRIMARY_SCOPE_KEY,
    "scopes": {PRIMARY_SCOPE_KEY: _default_scope_state()},
}


def _sync_top_level_mirrors_locked():
    """Keep top-level legacy keys synchronized with primary scope & active in-flight marker."""
    scopes = state.setdefault("scopes", {})
    prim_key = state.get("primary_scope") or PRIMARY_SCOPE_KEY
    prim = scopes.get(prim_key)
    if isinstance(prim, dict):
        for k in ("conversation_id", "project", "workdir", "mode", "model", "effort",
                  "thinking", "auto_compact", "auto_compact_tokens"):
            state[k] = prim.get(k)
    active_inf = None
    for sc in scopes.values():
        if isinstance(sc, dict) and isinstance(sc.get("in_flight"), dict):
            active_inf = sc["in_flight"]
            break
    state["in_flight"] = active_inf


def _ensure_scope_locked(scope_key=None):
    skey = scope_key or PRIMARY_SCOPE_KEY
    scopes = state.setdefault("scopes", {})
    sc = scopes.get(skey)
    if not isinstance(sc, dict):
        prim = scopes.get(state.get("primary_scope") or PRIMARY_SCOPE_KEY) or state
        sc = _default_scope_state(prefs_source=prim)
        scopes[skey] = sc
    else:
        defaults = _default_scope_state()
        for k, v in defaults.items():
            sc.setdefault(k, v)
    return sc


def get_scope_state(scope_key=None):
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        return dict(sc)


def get_scope_value(scope_key, key, default=None):
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        return sc.get(key, default)


def update_scope_state(scope_key=None, **updates):
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        sc.update(updates)
        _sync_top_level_mirrors_locked()


def current_workdir(scope_key=None):
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        w = sc.get("workdir")
    if w:
        rw = os.path.realpath(os.path.expanduser(w))
        if os.path.isdir(rw):
            return rw
    return WORKDIR


def current_project(scope_key=None):
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        return sc.get("project") or None


def list_agy_projects():
    """Return list of dicts: {id, name, workdir, repo_url} from ~/.gemini/config/projects/*.json."""
    items = []
    seen_ids = set()
    if os.path.isdir(PROJECTS_DIR):
        for fn in sorted(os.listdir(PROJECTS_DIR)):
            if not fn.endswith(".json"):
                continue
            fp = os.path.join(PROJECTS_DIR, fn)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            pid = (data.get("id") or os.path.splitext(fn)[0]).strip()
            if not pid or pid in seen_ids:
                continue
            seen_ids.add(pid)
            name = (data.get("name") or pid).strip()
            wdir = None
            repo_url = None
            pres = data.get("projectResources") or {}
            res_list = pres.get("resources") if isinstance(pres, dict) else None
            if isinstance(res_list, list):
                for r in res_list:
                    if not isinstance(r, dict):
                        continue
                    furi = r.get("folderUri") or (r.get("gitFolder") or {}).get("folderUri") or ""
                    if furi.startswith("file://") and not wdir:
                        cand = os.path.realpath(furi[len("file://"):])
                        if os.path.isdir(cand):
                            wdir = cand
                    rem = r.get("remoteResource") or {}
                    if isinstance(rem, dict) and rem.get("url") and not repo_url:
                        repo_url = rem.get("url")
            if not wdir:
                if pid == "default-cli-project":
                    wdir = WORKDIR
                else:
                    cand = os.path.join(HOME, name)
                    if os.path.isdir(cand):
                        wdir = os.path.realpath(cand)
            final_wdir = wdir or WORKDIR
            if not repo_url and os.path.isdir(os.path.join(final_wdir, ".git")):
                try:
                    gr = subprocess.run(
                        ["git", "-C", final_wdir, "config", "--get", "remote.origin.url"],
                        capture_output=True, text=True, timeout=2,
                    )
                    if gr.returncode == 0 and gr.stdout.strip():
                        repo_url = gr.stdout.strip()
                except Exception:
                    pass
            items.append({
                "id": pid,
                "name": name,
                "workdir": final_wdir,
                "repo_url": repo_url or "",
            })
    if "default-cli-project" not in seen_ids:
        items.insert(0, {
            "id": "default-cli-project",
            "name": "CLI Project",
            "workdir": WORKDIR,
            "repo_url": "",
        })
    return items
if os.path.exists(STATE_FILE):
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            if isinstance(loaded.get("scopes"), dict) and loaded["scopes"]:
                migrated_scopes = {}
                for sk, sdata in loaded["scopes"].items():
                    if isinstance(sdata, dict):
                        sc = _default_scope_state()
                        for k in sc:
                            if k in sdata:
                                sc[k] = sdata[k]
                        migrated_scopes[str(sk)] = sc
                if migrated_scopes:
                    state["scopes"] = migrated_scopes
                if loaded.get("primary_scope"):
                    state["primary_scope"] = str(loaded["primary_scope"])
            else:
                # Migrate legacy single-scope flat state cleanly into primary scope
                sc = _default_scope_state(prefs_source=loaded)
                for k in sc:
                    if k in loaded:
                        sc[k] = loaded[k]
                if not loaded.get("auto_compact_v2_migrated"):
                    if sc.get("auto_compact_tokens") == 180000:
                        sc["auto_compact_tokens"] = DEFAULT_AUTO_COMPACT_TOKENS
                    sc["auto_compact_v2_migrated"] = True
                state["scopes"] = {PRIMARY_SCOPE_KEY: sc}
            with state_lock:
                _sync_top_level_mirrors_locked()
    except Exception:
        pass


def save_state():
    with state_lock:
        _sync_top_level_mirrors_locked()
        tmp = STATE_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, STATE_FILE)
        except Exception:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def sig_handler(signum, frame):
    global shutting_down
    log("Received signal %d, initiating graceful shutdown..." % signum)
    shutting_down = True


def _tg_json(resp):
    """Safely parse a Telegram HTTP response as a dict without raising on HTML/5xx bodies."""
    if resp is None:
        return {}
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _tg_ok(resp):
    return bool(_tg_json(resp).get("ok"))


def _tg_retry_after(resp):
    if resp is None or getattr(resp, "status_code", None) != 429:
        return None
    try:
        return max(1, int(_tg_json(resp).get("parameters", {}).get("retry_after", 2)))
    except Exception:
        return 2


POLL_BACKOFF_BASE = 2.0
POLL_BACKOFF_MAX = 30.0


def _sleep_interruptible(seconds):
    deadline = time.time() + max(0.0, float(seconds))
    while not shutting_down:
        rem = deadline - time.time()
        if rem <= 0:
            return True
        time.sleep(min(0.5, rem))
    return False


def _sleep_wait_429(seconds):
    return _sleep_interruptible(seconds)


def _poll_backoff_seconds(streak):
    """Compute capped exponential backoff (2s -> 4s -> 8s -> 16s -> max 30s)."""
    if streak <= 0:
        return 0.0
    return min(POLL_BACKOFF_MAX, POLL_BACKOFF_BASE * (2 ** min(int(streak) - 1, 10)))


def tg(method, _timeout=None, _retry_429=True, _max_429_wait=12, **params):
    """Call Telegram Bot API with configurable timeout and interruptible 429 retry."""
    to = _timeout or DEFAULT_TIMEOUT
    try:
        r = http_session.post(API + "/" + method, json=params, timeout=to)
        slept = 0.0
        for _ in range(2):
            if r is None or r.status_code != 429 or not _retry_429:
                break
            wait_s = _tg_retry_after(r) or 2
            if slept + wait_s > _max_429_wait:
                break
            log("tg %s hit 429 (retry_after=%ss); waiting to retry..." % (method, wait_s))
            if not _sleep_wait_429(wait_s + 0.25):
                break
            slept += wait_s + 0.25
            r = http_session.post(API + "/" + method, json=params, timeout=to)
        return r
    except Exception as e:
        log("tg %s failed: %s" % (method, e))
        return None


def tg_send_in_route(method, chat_id, thread_id=None, _timeout=None, _retry_429=True, _max_429_wait=12, **params):
    """Call Telegram Bot API targeting `chat_id` (and optional topic `thread_id`),
    retrying once without `message_thread_id` if the topic no longer exists and
    retrying without `reply_to_message_id` if Telegram returns 400 message not found.
    """
    norm_tid = _normalize_thread_id(thread_id)
    kw = dict(params)
    kw["chat_id"] = chat_id
    if norm_tid is not None:
        kw["message_thread_id"] = norm_tid
    if not kw.get("reply_to_message_id"):
        kw.pop("reply_to_message_id", None)
    else:
        kw["reply_to_message_id"] = int(kw["reply_to_message_id"])

    r = tg(method, _timeout=_timeout, _retry_429=_retry_429, _max_429_wait=_max_429_wait, **kw)
    if norm_tid is not None and r is not None:
        j = _tg_json(r)
        if not j.get("ok") and "thread not found" in str(j.get("description", "")).lower():
            log("tg_send_in_route %s thread_id=%s failed (%s); retrying without thread_id"
                % (method, norm_tid, _format_tg_err(r)))
            kw.pop("message_thread_id", None)
            r = tg(method, _timeout=_timeout, _retry_429=_retry_429, _max_429_wait=_max_429_wait, **kw)

    if kw.get("reply_to_message_id") and not _tg_ok(r):
        j = _tg_json(r)
        desc = str(j.get("description", "")).lower()
        status_code = getattr(r, "status_code", None)
        log("tg_send_in_route %s reply_to_message_id=%s failed (%s)"
            % (method, kw.get("reply_to_message_id"), _format_tg_err(r)))
        if status_code == 400 and (
            "message not found" in desc
            or "reply message not found" in desc
            or "message to be replied not found" in desc
            or "replied" in desc
        ):
            kw.pop("reply_to_message_id", None)
            r = tg(method, _timeout=_timeout, _retry_429=_retry_429, _max_429_wait=_max_429_wait, **kw)
            if not _tg_ok(r):
                log("tg_send_in_route %s fallback without reply failed (%s)" % (method, _format_tg_err(r)))
    elif not _tg_ok(r):
        log("tg_send_in_route %s failed (%s)" % (method, _format_tg_err(r)))
    return r


def send_file(chat_id, filepath, caption=None, thread_id=None):
    """Send document or photo (if image) via multipart/form-data."""
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    is_image = ext in IMAGE_EXTS
    method = "sendPhoto" if is_image else "sendDocument"
    field = "photo" if is_image else "document"
    norm_tid = _normalize_thread_id(thread_id)
    try:
        if is_image and os.path.getsize(filepath) > 9.5 * 1024 * 1024:
            method, field = "sendDocument", "document"
        for attempt_tid in ((norm_tid, None) if norm_tid is not None else (None,)):
            with open(filepath, "rb") as f:
                files = {field: (filename, f)}
                data = {"chat_id": chat_id}
                if attempt_tid is not None:
                    data["message_thread_id"] = attempt_tid
                if caption:
                    data["caption"] = caption[:1024]
                r = http_session.post(API + "/" + method, data=data, files=files, timeout=(10, 120))
            if attempt_tid is not None and r is not None:
                try:
                    j = r.json()
                except Exception:
                    j = {}
                if not j.get("ok") and "thread not found" in str(j.get("description", "")).lower():
                    continue
            return r
    except Exception as e:
        log("send_file %s failed: %s" % (filepath, e))
        return None


def send_media_group(chat_id, filepaths, caption=None, thread_id=None):
    """Send 2..10 static images in a single Telegram album (`sendMediaGroup`).
    Returns True if accepted by Telegram, else False so caller can fall back per-file.
    """
    paths = list(filepaths or [])[:10]
    if len(paths) < 2:
        return False
    norm_tid = _normalize_thread_id(thread_id)
    media_items = []
    files = {}
    opened = []
    try:
        for idx, fp in enumerate(paths):
            key = f"file_{idx}"
            fobj = open(fp, "rb")
            opened.append(fobj)
            files[key] = (os.path.basename(fp), fobj)
            item = {"type": "photo", "media": f"attach://{key}"}
            if idx == 0 and caption:
                item["caption"] = caption[:1024]
            media_items.append(item)

        data = {
            "chat_id": chat_id,
            "media": json.dumps(media_items, ensure_ascii=False),
        }
        if norm_tid is not None:
            data["message_thread_id"] = norm_tid
        r = http_session.post(API + "/sendMediaGroup", data=data, files=files, timeout=(10, 120))
        if r is not None:
            try:
                j = r.json()
            except Exception:
                j = {}
            if j.get("ok"):
                return True
            if norm_tid is not None and "thread not found" in str(j.get("description", "")).lower():
                data.pop("message_thread_id", None)
                for fobj in opened:
                    fobj.seek(0)
                r2 = http_session.post(API + "/sendMediaGroup", data=data, files=files, timeout=(10, 120))
                if r2 is not None and r2.json().get("ok"):
                    return True
            log("sendMediaGroup rejected (%s); will fallback per-file" % j.get("description", r.status_code))
    except Exception as e:
        log("sendMediaGroup error: %s" % e)
    finally:
        for fobj in opened:
            try:
                fobj.close()
            except Exception:
                pass
    return False


def _current_bot_handle():
    return BOT_META.get("handle") or f"bot_{BOT_INSTANCE_ID}"


def _current_bot_cfg():
    sc = get_scope_state(PRIMARY_SCOPE_KEY)
    return bot_bus.resolve_bot_config(
        _current_bot_handle(),
        env_role=ENV_BOT_ROLE,
        env_model=ENV_BOT_MODEL,
        env_project=ENV_BOT_PROJECT or sc.get("project") or "",
        env_specialty=ENV_BOT_SPECIALTY,
        fallback_workdir=sc.get("workdir") or WORKDIR,
    )


def _current_bot_role():
    return _current_bot_cfg().get("role") or "peer"


def _desired_bus_enable(scope_key=None):
    role = _current_bot_role()
    if role in ("coordinator", "peer"):
        return True
    if role == "worker" and scope_key:
        origin_chat, _ = parse_scope_key(scope_key)
        return bool(origin_chat and int(origin_chat) < 0)
    return False


def _init_bot_identity():
    """Fetch Telegram getMe() so the Bot Bus knows our real @handle and bot_id."""
    try:
        r = http_session.get(API + "/getMe", timeout=FAST_TIMEOUT)
        data = r.json() if r is not None else {}
        if data.get("ok"):
            u = data.get("result") or {}
            uname = bot_bus.normalize_handle(u.get("username") or "")
            if uname:
                BOT_META["bot_id"] = int(u.get("id") or 0)
                BOT_META["handle"] = uname
                BOT_META["first_name"] = str(u.get("first_name") or uname)
                BOT_META["resolved"] = True
                log("Bot identity resolved: @%s (id=%s, role=%s)" % (
                    BOT_META["handle"], BOT_META["bot_id"], _current_bot_role()
                ))
                return True
    except Exception as e:
        log("getMe identity probe failed: %s" % e)
    return False


def ensure_team_mcp_configured():
    """Ensure `acb-team` MCP server is registered in ~/.gemini/config/mcp_config.json without touching existing keys."""
    mcp_cfg_path = os.path.join(HOME, ".gemini", "config", "mcp_config.json")
    mcp_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_bus_mcp.py")
    if not os.path.isfile(mcp_script):
        return
    lock_path = "/tmp/agy_mcp_config.lock"
    try:
        os.makedirs(os.path.dirname(mcp_cfg_path), exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                cfg = {}
                if os.path.isfile(mcp_cfg_path):
                    try:
                        with open(mcp_cfg_path, "r", encoding="utf-8") as rf:
                            cfg = json.load(rf) or {}
                    except Exception:
                        cfg = {}
                if not isinstance(cfg, dict):
                    cfg = {}
                servers = cfg.setdefault("mcpServers", {})
                desired = {"command": sys.executable, "args": [mcp_script]}
                if servers.get("acb-team") != desired:
                    servers["acb-team"] = desired
                    tmp = f"{mcp_cfg_path}.{os.getpid()}.tmp"
                    with open(tmp, "w", encoding="utf-8") as wf:
                        json.dump(cfg, wf, indent=2, ensure_ascii=False)
                    os.replace(tmp, mcp_cfg_path)
                    log("Registered `acb-team` MCP server in %s" % mcp_cfg_path)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        log("ensure_team_mcp_configured error: %r" % e)


def _should_ignore_group_message(msg):
    """In multi-bot group/supergroup chats, route @mentions cleanly so bots don't talk over each other."""
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id or int(chat_id) > 0:
        return False
    if not BOT_META.get("resolved"):
        return False

    my_handle = _current_bot_handle()
    my_id = int(BOT_META.get("bot_id") or 0)
    text = (msg.get("text") or msg.get("caption") or "").strip()

    # 1. Explicit slash command targeted at another bot: /cmd@other_bot
    is_slash = text.startswith("/")
    if is_slash:
        first_tok = text.split()[0]
        if "@" in first_tok:
            target = bot_bus.normalize_handle(first_tok.split("@", 1)[1])
            if target and target != my_handle:
                return True
            if target == my_handle:
                return False

    # 2. Check leading @handles (e.g. "@BotA @BotB: check this") or explicit @my_handle across full text
    #    (ignoring backtick code spans/blocks). Skip for bare slash commands (`/team workdir @worker ...`,
    #    `/delegate @worker ...`) so `@worker` in command arguments does not wake workers alongside Coordinator.
    if not is_slash:
        mentions = bot_bus.extract_at_mentions(text)
        if my_handle in mentions:
            return False
        leading_m = re.match(r"^(?:@[A-Za-z0-9_]{3,32}[\s,:;]*)+", text)
        if leading_m:
            leading_handles = bot_bus.extract_at_mentions(leading_m.group(0))
            if leading_handles and my_handle not in leading_handles:
                return True

    # 3. Direct reply to a bot's message
    reply = msg.get("reply_to_message") or {}
    rfrom = reply.get("from") or {}
    if rfrom.get("is_bot"):
        rid = int(rfrom.get("id") or 0)
        runame = bot_bus.normalize_handle(rfrom.get("username") or "")
        if (my_id and rid == my_id) or (runame and runame == my_handle):
            return False
        return True

    # 4. Unaddressed message in a shared group: let online coordinator handle bare lines; worker waits to be @mentioned
    if _current_bot_role() == "worker":
        try:
            roster = bot_bus.list_roster(include_offline=False)
            for b in roster:
                if b["handle"] != my_handle and b.get("role") == "coordinator":
                    achats = [int(x) for x in (b.get("allowed_chats") or [])]
                    if int(chat_id) in achats:
                        return True
        except Exception:
            pass
    return False


_PRIVATE_COMMANDS = [
    {"command": "new", "description": "Start a new session / clear context"},
    {"command": "retry", "description": "Re-run the previous prompt in this chat/topic"},
    {"command": "undo", "description": "Undo workspace file edits from the last turn"},
    {"command": "team", "description": "Multi-bot Coordinator Bus roster, roles & jobs"},
    {"command": "delegate", "description": "Directly assign a task to a sibling bot (/delegate @bot task)"},
    {"command": "usage", "description": "Overall Antigravity plan quota & reset time"},
    {"command": "cost", "description": "My local token usage, cache rate & USD bill"},
    {"command": "schedule", "description": "Manage scheduled tasks, cron jobs & timers"},
    {"command": "compact", "description": "Compact context now or set auto-compact"},
    {"command": "context", "description": "View session context tokens & auto-compact"},
    {"command": "status", "description": "Check current state & running tasks"},
    {"command": "project", "description": "Switch Antigravity CLI project / repo workspace"},
    {"command": "model", "description": "View or switch AI model"},
    {"command": "effort", "description": "Set reasoning effort level"},
    {"command": "thinking", "description": "Toggle thought chain & tool calls visibility"},
    {"command": "sessions", "description": "List & resume recent sessions"},
    {"command": "files", "description": "List files in workspace"},
    {"command": "get", "description": "Download workspace file (/get <name>)"},
    {"command": "mode", "description": "Switch auto/safe mode"},
    {"command": "reload", "description": "Gracefully reload bridge process"},
    {"command": "cancel", "description": "Cancel currently running task"},
    {"command": "help", "description": "Show commands and instructions"},
]

# In multi-bot groups, only Coordinator/Peer bots register concise team-oriented commands
# under `all_group_chats` while Worker bots stay hidden from the `/` menu to avoid `@bot` clutter.
_GROUP_TEAM_COMMANDS = [
    {"command": "team", "description": "🤝 团队花名册、角色切换与派工单"},
    {"command": "delegate", "description": "📨 直派任务给队员 (/delegate @bot 任务)"},
    {"command": "project", "description": "📂 切换本群/Topic 协同的项目仓库"},
    {"command": "status", "description": "📊 查看团队主控状态与本群会话"},
    {"command": "new", "description": "🔄 开启本群/Topic 新会话 (隔离私聊)"},
    {"command": "cancel", "description": "🛑 中止当前群内正在运行的任务"},
    {"command": "help", "description": "❓ 查看群内团队协作指南"},
]

_cmd_reg_lock = threading.Lock()
_LAST_REGISTERED_CMD_ROLE = None


def register_bot_commands(force=False):
    """Register scoped Telegram command menus: full menu in DMs, clean team-only menu in groups."""
    global _LAST_REGISTERED_CMD_ROLE
    role = _current_bot_role()
    with _cmd_reg_lock:
        if not force and _LAST_REGISTERED_CMD_ROLE == role:
            return True
        try:
            # Clear broad/legacy fallback scopes so workers & stale per-chat menus never pollute `/` in groups
            ok_def = _tg_ok(tg("deleteMyCommands", _timeout=15, scope={"type": "default"}))
            _tg_ok(tg("deleteMyCommands", _timeout=15, scope={"type": "all_chat_administrators"}))
            for cid in sorted(ALLOWED):
                try:
                    cid_int = int(cid)
                except Exception:
                    continue
                if cid_int < 0:
                    tg("deleteMyCommands", _timeout=15, scope={"type": "chat", "chat_id": cid_int})
                    tg("deleteMyCommands", _timeout=15, scope={"type": "chat_administrators", "chat_id": cid_int})

            ok_priv = _tg_ok(tg(
                "setMyCommands",
                _timeout=15,
                commands=_PRIVATE_COMMANDS,
                scope={"type": "all_private_chats"},
            ))
            if role in ("coordinator", "peer"):
                ok_grp = _tg_ok(tg(
                    "setMyCommands",
                    _timeout=15,
                    commands=_GROUP_TEAM_COMMANDS,
                    scope={"type": "all_group_chats"},
                ))
                grp_cnt = len(_GROUP_TEAM_COMMANDS)
            else:
                ok_grp = _tg_ok(tg(
                    "deleteMyCommands",
                    _timeout=15,
                    scope={"type": "all_group_chats"},
                ))
                grp_cnt = 0

            if ok_def and ok_priv and ok_grp:
                _LAST_REGISTERED_CMD_ROLE = role
                log("Bot commands registered (role=%s, dm=%d, group=%d)" % (role, len(_PRIVATE_COMMANDS), grp_cnt))
                return True
            log("register_bot_commands incomplete (role=%s, def=%s, priv=%s, grp=%s)" % (role, ok_def, ok_priv, ok_grp))
            return False
        except Exception as e:
            log("register_bot_commands failed: %s" % e)
            return False


def register_bot_commands_async(force=True):
    threading.Thread(target=register_bot_commands, kwargs={"force": force}, daemon=True).start()


# ---------------------------------------------------------------- persistent agy session
class AgySession:
    """Manages a warm persistent `agy --input-format stream-json --output-format stream-json` process
    with non-blocking stdout event queue for instant cancellation & 60ms result lookahead.
    """

    def __init__(self, conv, mode, model, effort, project=None, workdir=None, scope_key=None):
        self.cid = conv
        self.mode = mode
        self.model = model
        self.effort = effort
        self.scope_key = scope_key or PRIMARY_SCOPE_KEY
        self.project = project
        self.workdir = workdir or WORKDIR
        self.bus_role = _current_bot_role()
        self.bus_enable = _desired_bus_enable(self.scope_key)
        self.spawned_at = time.time()
        self.last_used = self.spawned_at
        self.stderr_tail = collections.deque(maxlen=80)
        self.event_q = queue.Queue()
        self._pushback = collections.deque()
        self.eof_reached = False

        cmd = [
            AGY_BIN,
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--print-timeout", PRINT_TIMEOUT,
        ]
        if mode == "auto":
            cmd.append("--dangerously-skip-permissions")
        if self.project:
            cmd += ["--project", self.project]
        if model:
            cmd += ["--model", model]
        if effort:
            cmd += ["--effort", effort]
        if conv:
            cmd += ["--conversation", conv]
        cmd += ["-p", ""]

        env = dict(os.environ)
        env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
        env.setdefault("HOME", HOME)
        env["AGY_OUTBOX_DIR"] = BOT_OUTBOX_DIR
        origin_chat, origin_tid = parse_scope_key(self.scope_key)
        env["AGY_BOT_BUS_ENABLE"] = "1" if self.bus_enable else "0"
        env["AGY_BOT_BUS_ROLE"] = self.bus_role
        env["AGY_BOT_HANDLE"] = _current_bot_handle()
        env["AGY_BOT_INSTANCE_ID"] = BOT_INSTANCE_ID
        env["AGY_BOT_SCOPE_KEY"] = self.scope_key
        env["AGY_BOT_CHAT_ID"] = str(origin_chat or 0)
        env["AGY_BOT_THREAD_ID"] = str(origin_tid) if origin_tid is not None else ""
        env["AGY_BOT_CHAIN"] = ""
        env["AGY_BOT_MENTION_HOP"] = "0"

        log("Spawning persistent AgySession (conv=%s, project=%s, cwd=%s, model=%s, effort=%s, mode=%s, bus=%s)"
            % ((conv or "new")[:8], self.project or "default", self.workdir, model or "default", effort or "default", mode, self.bus_enable))
        self.proc = subprocess.Popen(
            cmd,
            cwd=self.workdir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        threading.Thread(target=self._drain_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stdout(self):
        try:
            for raw in self.proc.stdout:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except Exception:
                    continue
                if ev.get("event") == "init":
                    cid = ev.get("conversation_id")
                    if cid:
                        self.cid = cid
                self.event_q.put(ev)
        except Exception:
            pass
        finally:
            self.eof_reached = True
            self.event_q.put({"event": "__eof__"})

    def _drain_stderr(self):
        try:
            for line in self.proc.stderr:
                self.stderr_tail.append(line)
        except Exception:
            pass

    def next_event(self, timeout=0.25):
        """Return next parsed event dict, or None on timeout (never blocks cancellation)."""
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self.event_q.get(timeout=timeout)
        except queue.Empty:
            return None

    def peek_immediate_result(self, timeout=0.065):
        """Wait up to 65ms after `agent_response` DONE to see if `result` follows immediately.
        Returns (result_dict, None) if turn finished, or (None, reason) if intermediate step.
        """
        deadline = time.time() + timeout
        while True:
            rem = max(0.0, deadline - time.time())
            ev = self.next_event(timeout=rem)
            if ev is None:
                return None, "waiting"
            kind = ev.get("event")
            if kind == "result":
                return (ev.get("result") or ev), None
            if kind == "init":
                continue
            # Another step (e.g. tool or system_message or __eof__) arrived -> intermediate turn!
            self._pushback.append(ev)
            return None, "more_steps"

    def get_stderr_text(self):
        return "".join(self.stderr_tail)[-1200:]

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None and not self.eof_reached

    def matches(self, conv, mode, model, effort, project=None, workdir=None):
        if not self.is_alive():
            return False
        if getattr(self, "bus_enable", False) != _desired_bus_enable(self.scope_key):
            return False
        if getattr(self, "bus_role", None) != _current_bot_role():
            return False
        if self.mode != mode or self.model != model or self.effort != effort:
            return False
        if self.project != project or self.workdir != (workdir or WORKDIR):
            return False
        return self.cid == conv

    def send_user_prompt(self, prompt, raw_slash=False):
        # Give freshly spawned `agy` ~200ms to finish OAuth file load (`server_oauth.go`) before first RPC
        since_spawn = time.time() - self.spawned_at
        if since_spawn < 0.22:
            time.sleep(0.22 - since_spawn)
        if raw_slash:
            safe_prompt = prompt
        else:
            safe_prompt = (" " + prompt) if prompt.lstrip().startswith("/") else prompt
        payload = json.dumps({"event": "user", "message": {"content": safe_prompt}}, ensure_ascii=False)
        self.proc.stdin.write(payload + "\n")
        self.proc.stdin.flush()
        self.last_used = time.time()

    def close(self, force=False):
        p = self.proc
        if p is None:
            return
        try:
            if p.stdin and not p.stdin.closed:
                p.stdin.close()
        except Exception:
            pass
        if not force:
            try:
                p.wait(timeout=1.5)
                return
            except Exception:
                pass
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.terminate()
                except Exception:
                    pass
            try:
                p.wait(timeout=2.0)
            except Exception:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception:
                    pass


def close_session_async(sess, force=False):
    if sess is None:
        return
    threading.Thread(target=sess.close, kwargs={"force": force}, daemon=True).start()


def invalidate_session(reason="", force=False, scope_key=None):
    """Recycle warm session(s) immediately if idle, or mark dirty to recycle right after active turn."""
    to_close = []
    with session_lock:
        targets = [scope_key] if scope_key is not None else list(_session_pool.keys())
        for sk in targets:
            if turn_running and turn_running_scope == sk and not force:
                session_dirty_scopes.add(sk)
                log("Marked active session dirty (%s · scope=%s); will recycle after current turn" % (reason, sk))
            elif sk in _session_pool:
                sess = _session_pool.pop(sk, None)
                session_dirty_scopes.discard(sk)
                if sess is not None:
                    to_close.append(sess)
                    log("Closing warm session (%s · scope=%s)" % (reason, sk))
    for sess in to_close:
        close_session_async(sess, force=force)


def close_all_sessions_sync():
    with session_lock:
        to_close = list(_session_pool.values())
        _session_pool.clear()
        session_dirty_scopes.clear()
    for sess in to_close:
        sess.close(force=False)


def idle_session_reaper():
    while not shutting_down:
        time.sleep(30)
        if IDLE_SESSION_TTL <= 0:
            continue
        now = time.time()
        to_close = []
        with session_lock:
            for sk in list(_session_pool.keys()):
                if turn_running and turn_running_scope == sk:
                    continue
                sess = _session_pool.get(sk)
                if sess is not None and (now - sess.last_used) > IDLE_SESSION_TTL:
                    _session_pool.pop(sk, None)
                    to_close.append(sess)
                    log("Idle session TTL (%ds) reached for scope=%s; closing warm agy process" % (IDLE_SESSION_TTL, sk))
        for sess in to_close:
            sess.close(force=False)


# ---------------------------------------------------------------- recovery
def check_and_recover_in_flight():
    """If the bridge died while one or more turns were in-flight, recover per scope and notify exact route."""
    pending = []
    with state_lock:
        scopes = state.get("scopes") or {}
        for sk, sc in scopes.items():
            if not isinstance(sc, dict):
                continue
            inf = sc.get("in_flight")
            if isinstance(inf, dict):
                pending.append((sk, dict(inf), sc.get("conversation_id")))
    if not pending:
        return

    for sk, inflight, sc_conv in pending:
        chat_id = inflight.get("chat_id")
        thread_id = inflight.get("thread_id")
        if chat_id is None:
            chat_id, parsed_tid = parse_scope_key(sk)
            if thread_id is None:
                thread_id = parsed_tid
        prompt = inflight.get("prompt", "")
        target_conv = inflight.get("conv") or sc_conv
        already_delivered = (inflight.get("last_delivered_text") or "").strip()
        log("Checking in-flight recovery for scope %s (chat %s, thread %s, conv %s)..." % (
            sk, chat_id, thread_id, target_conv))

        recovered_response = None
        if target_conv:
            tpath = os.path.join(BRAIN_ROOT, target_conv, ".system_generated/logs/transcript.jsonl")
            if os.path.exists(tpath):
                try:
                    with open(tpath, encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for line in reversed(lines[-15:]):
                        obj = json.loads(line)
                        if obj.get("type") == "PLANNER_RESPONSE" and obj.get("status") == "DONE":
                            cnt = obj.get("content")
                            if cnt and not obj.get("tool_calls"):
                                recovered_response = cnt.strip()
                                break
                except Exception as e:
                    log("recovery transcript parse error: %s" % e)

        if recovered_response:
            if already_delivered and recovered_response == already_delivered:
                log("In-flight response was already delivered live before restart; skipping duplicate.")
            else:
                notice = "🔔 <b>服务刚完成重启，已为您自动补发刚才的任务结果：</b>\n\n"
                send_rich(chat_id, notice + recovered_response, thread_id=thread_id)
        elif not already_delivered:
            prompt_snippet = html_mod.escape(prompt[:50]) + ("..." if len(prompt) > 50 else "")
            kb = {"inline_keyboard": [[{"text": "🔁 重试刚才的任务 (/retry)", "callback_data": "action:retry"}]]}
            send(chat_id,
                 f"⚠️ <b>服务经历重启：</b>\n"
                 f"您刚才发送的任务（<code>{prompt_snippet}</code>）可能已被中断。\n\n"
                 f"可直接点击下方按钮重试，或发送新消息继续。",
                 parse_mode="HTML", reply_markup=kb, thread_id=thread_id)

        update_scope_state(sk, in_flight=None)
    save_state()


# ---------------------------------------------------------------- formatting
def format_inline_markdown(text):
    """Format markdown text (outside code blocks) into Telegram HTML."""
    esc = html_mod.escape(text)

    code_tokens = []

    def save_code(m):
        code_tokens.append(m.group(1))
        return f"\x00CODE{len(code_tokens)-1}\x00"

    esc = re.sub(r"`([^`\n]+)`", save_code, esc)
    esc = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", esc)
    esc = re.sub(r"__([^_\n]+)__", r"<b>\1</b>", esc)
    esc = re.sub(r"~~([^~\n]+)~~", r"<s>\1</s>", esc)
    esc = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(
        r"^(#{1,6})\s+(.+)$",
        lambda m: f"<b>{re.sub(r'</?b>', '', m.group(2))}</b>",
        esc,
        flags=re.MULTILINE,
    )

    # Markdown images: ![alt](path) -> 🖼 <code>alt</code>
    esc = re.sub(
        r"!\[([^\]]*)\]\(([^)\s]+)\)",
        lambda m: f"🖼 <code>{m.group(1) or os.path.basename(m.group(2))}</code>",
        esc,
    )
    # Local file:// links -> <code>label</code>
    esc = re.sub(r"\[([^\]]+)\]\(file://[^)\s]+\)", r"<code>\1</code>", esc)
    # Web/Telegram links
    esc = re.sub(r"\[([^\]]+)\]\(((?:https?|tg)://[^)\s]+)\)", r'<a href="\2">\1</a>', esc)

    def replace_quote(m):
        q = m.group(0).replace("&gt; ", "").replace("&gt;", "").strip("\n")
        return f"<blockquote>{q}</blockquote>"

    esc = re.sub(r"(?:^&gt; .*(?:\n|$))+", replace_quote, esc, flags=re.MULTILINE)

    for idx, code_content in enumerate(code_tokens):
        esc = esc.replace(f"\x00CODE{idx}\x00", f"<code>{code_content}</code>")

    return esc


def md_to_html(text):
    """Convert full markdown to Telegram HTML, preserving language in code blocks."""
    if not text:
        return ""

    code_block_pattern = re.compile(r"```([a-zA-Z0-9_\-\+]*)\n?(.*?)```", re.DOTALL)
    parts = []
    last_idx = 0
    for m in code_block_pattern.finditer(text):
        if m.start() > last_idx:
            parts.append(("text", text[last_idx:m.start()]))
        parts.append(("code", (m.group(1).strip(), m.group(2))))
        last_idx = m.end()

    if last_idx < len(text):
        rem = text[last_idx:]
        if rem.startswith("```"):
            first_nl = rem.find("\n")
            if first_nl != -1:
                lang = rem[3:first_nl].strip()
                parts.append(("code", (lang, rem[first_nl + 1:])))
            else:
                parts.append(("code", ("", rem[3:])))
        else:
            parts.append(("text", rem))

    out = []
    for kind, content in parts:
        if kind == "code":
            lang, code = content
            esc_code = html_mod.escape(code.strip("\r\n"))
            if lang:
                out.append(f'<pre><code class="language-{html_mod.escape(lang)}">{esc_code}</code></pre>')
            else:
                out.append(f'<pre><code>{esc_code}</code></pre>')
        else:
            out.append(format_inline_markdown(content))

    return "".join(out)


def split_markdown(text, max_len=3200):
    """Split long markdown text cleanly at line or code boundaries."""
    if len(text) <= max_len:
        return [text]

    lines = text.split("\n")
    chunks = []
    current_chunk = []
    current_len = 0
    in_code_block = False
    code_fence = ""

    for line in lines:
        line_len = len(line) + 1
        m = re.match(r"^(```+)(\w*)", line)

        if current_len + line_len > max_len and current_chunk:
            if in_code_block:
                current_chunk.append("```")
                chunks.append("\n".join(current_chunk))
                current_chunk = [f"```{code_fence}", line]
                current_len = len(current_chunk[0]) + 1 + line_len
            else:
                chunks.append("\n".join(current_chunk))
                current_chunk = [line]
                current_len = line_len
        else:
            current_chunk.append(line)
            current_len += line_len

        if m:
            if not in_code_block:
                in_code_block = True
                code_fence = m.group(2)
            else:
                in_code_block = False
                code_fence = ""

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks


def _extract_msg_id(resp):
    j = _tg_json(resp)
    if j.get("ok"):
        return (j.get("result") or {}).get("message_id")
    return None


def _format_tg_err(resp):
    """Format Telegram API failure without falling into `bool(requests.Response)` 4xx falsiness."""
    if resp is None:
        return "network"
    return f"HTTP {resp.status_code}: {(resp.text or '')[:300]}"


def send(chat_id, text, parse_mode=None, reply_markup=None, thread_id=None, _max_429_wait=45, reply_to_message_id=None):
    """Send text with chunking and HTML parse fallback if needed. Returns last message_id."""
    text = (text or "(empty response)").strip() or "(empty response)"
    last_mid = None
    for i in range(0, len(text), 4000):
        chunk = text[i:i + 4000]
        is_first = (i == 0)
        is_last = (i + 4000 >= len(text))
        kw = {"text": chunk}
        if parse_mode:
            kw["parse_mode"] = parse_mode
        if reply_markup and is_last:
            kw["reply_markup"] = reply_markup
        if reply_to_message_id and is_first:
            kw["reply_to_message_id"] = reply_to_message_id
        r = tg_send_in_route("sendMessage", chat_id, thread_id=thread_id, _max_429_wait=_max_429_wait, **kw)
        mid = _extract_msg_id(r)
        if not mid and parse_mode == "HTML":
            desc = str(_tg_json(r).get("description", "")).lower()
            if "parse entities" in desc or "can't find end" in desc or "byte offset" in desc:
                log("send HTML failed (%s), retrying plain text" % _format_tg_err(r))
                plain_kw = {"text": re.sub(r"<[^>]+>", "", html_mod.unescape(chunk))[:4090] or chunk[:4090]}
                if reply_markup and is_last:
                    plain_kw["reply_markup"] = reply_markup
                if reply_to_message_id and is_first:
                    plain_kw["reply_to_message_id"] = reply_to_message_id
                r = tg_send_in_route("sendMessage", chat_id, thread_id=thread_id, _max_429_wait=_max_429_wait, **plain_kw)
                mid = _extract_msg_id(r)
        if mid:
            last_mid = mid
        else:
            log("send failed: %s" % _format_tg_err(r))
    return last_mid


def send_rich_chunk(chat_id, chunk, prefix_html="", footer_html="", reply_markup=None, thread_id=None, _max_429_wait=65, reply_to_message_id=None):
    """Send a single markdown chunk as HTML, returning (msg_id, sent_html_or_none)."""
    rendered = md_to_html(chunk)
    full_html = prefix_html + rendered + footer_html
    if full_html and len(full_html) <= 4090:
        params = {
            "text": full_html,
            "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": True},
        }
        if reply_markup:
            params["reply_markup"] = reply_markup
        if reply_to_message_id:
            params["reply_to_message_id"] = reply_to_message_id
        r = tg_send_in_route(
            "sendMessage", chat_id, thread_id=thread_id, _max_429_wait=_max_429_wait, **params
        )
        mid = _extract_msg_id(r)
        if mid:
            return mid, full_html
        log("send_rich_chunk HTML failed: %s, falling back to plain text" % _format_tg_err(r))
        # If we still hit 429 after waiting, pause briefly so plain fallback isn't fired blindly at 0ms
        if r is not None and r.status_code == 429:
            _sleep_wait_429(min(_tg_retry_after(r) or 5, 15) + 0.5)

    plain = chunk
    if footer_html:
        plain += "\n\n" + re.sub(r"<[^>]+>", "", html_mod.unescape(footer_html)).strip()
    kw = {"text": plain[:4090] or "(empty)"}
    if reply_markup:
        kw["reply_markup"] = reply_markup
    if reply_to_message_id:
        kw["reply_to_message_id"] = reply_to_message_id
    r = tg_send_in_route(
        "sendMessage", chat_id, thread_id=thread_id, _max_429_wait=_max_429_wait, **kw
    )
    mid = _extract_msg_id(r)
    if not mid:
        log("send_rich_chunk plain fallback failed: %s" % _format_tg_err(r))
    return mid, None


def _rescue_deliver_text(chat_id, text, thread_id=None):
    """Save unsent reply text to BOT_OUTBOX_DIR and send as a document if sendMessage keeps failing."""
    os.makedirs(BOT_OUTBOX_DIR, exist_ok=True)
    rescue_path = os.path.join(BOT_OUTBOX_DIR, f"reply_{int(time.time())}.md")
    try:
        with open(rescue_path, "w", encoding="utf-8") as rf:
            rf.write(text)
    except Exception as e:
        log("_rescue_deliver_text write error: %s" % e)
        return None
    sent = send_file(chat_id, rescue_path, caption="📄 回复受群频控或长度限制，已转为完整文件发送", thread_id=thread_id)
    if _tg_ok(sent):
        return rescue_path
    return rescue_path


def send_rich(chat_id, text, header_html=None, footer_str=None, reply_markup=None, thread_id=None, reply_to_message_id=None):
    """HTML-rendered send with paragraph/code chunking, collapsible thinking header, and optional footer."""
    if not text or not text.strip():
        text = "(empty response)"
    chunks = split_markdown(text, max_len=3000)
    footer_html = ("\n\n" + html_mod.escape(footer_str)) if footer_str else ""
    is_group = bool(chat_id and int(chat_id) < 0)

    last_info = (None, None)
    delivered_chunks = 0
    total_chunks = len(chunks)
    start_idx = 0
    pending_reply_mid = reply_to_message_id
    if header_html:
        first_rendered = md_to_html(chunks[0])
        tail = footer_html if len(chunks) == 1 else ""
        if len(header_html) + len(first_rendered) + len(tail) <= 4050:
            last_info = send_rich_chunk(
                chat_id, chunks[0],
                prefix_html=header_html,
                footer_html=tail,
                reply_markup=reply_markup if len(chunks) == 1 else None,
                thread_id=thread_id,
                reply_to_message_id=pending_reply_mid,
            )
            pending_reply_mid = None
            if last_info[0]:
                delivered_chunks += 1
            start_idx = 1
        else:
            if len(header_html) <= 4090:
                hr = tg_send_in_route(
                    "sendMessage", chat_id, thread_id=thread_id, _max_429_wait=65,
                    text=header_html, parse_mode="HTML", link_preview_options={"is_disabled": True},
                    reply_to_message_id=pending_reply_mid,
                )
                pending_reply_mid = None
                if not _extract_msg_id(hr):
                    log("send_rich header HTML failed: %s" % _format_tg_err(hr))
            else:
                plain_hdr = re.sub(r"<[^>]+>", "", html_mod.unescape(header_html))[:4090]
                if plain_hdr:
                    tg_send_in_route(
                        "sendMessage", chat_id, thread_id=thread_id, _max_429_wait=65, text=plain_hdr,
                        reply_to_message_id=pending_reply_mid,
                    )
                    pending_reply_mid = None
            start_idx = 0

    for idx in range(start_idx, len(chunks)):
        if idx > start_idx and is_group:
            time.sleep(0.35)
        is_last = (idx == len(chunks) - 1)
        info = send_rich_chunk(
            chat_id, chunks[idx],
            footer_html=footer_html if is_last else "",
            reply_markup=reply_markup if is_last else None,
            thread_id=thread_id,
            reply_to_message_id=pending_reply_mid if idx == start_idx else None,
        )
        pending_reply_mid = None
        if info[0]:
            last_info = info
            delivered_chunks += 1

    if delivered_chunks < total_chunks and text.strip():
        log("send_rich partial/failed delivery (%d/%d chunks) in chat %s; triggering document rescue"
            % (delivered_chunks, total_chunks, chat_id))
        _rescue_deliver_text(chat_id, text, thread_id=thread_id)

    return last_info


def format_tool_label(tool_name, tool_info):
    """Format tool execution into a clear, informative label for live streaming."""
    if not tool_name:
        return ""
    params = (tool_info or {}).get("parameters") or {}
    if tool_name == "run_command":
        summary = params.get("toolSummary")
        cmd = params.get("CommandLine", "").strip().split("\n")[0]
        if summary and cmd:
            return f"sh: {summary[:24]} ({cmd[:28]})"
        elif summary:
            return f"sh: {summary[:40]}"
        return f"sh: {cmd[:42]}" if cmd else "sh"
    elif tool_name in ("read_file", "view_file"):
        path = params.get("Path") or params.get("AbsolutePath") or ""
        return f"read: {os.path.basename(path)[:32]}" if path else "read"
    elif tool_name in ("edit_file", "replace_file_content", "multi_replace_file_content"):
        path = params.get("Path") or params.get("TargetFile") or ""
        return f"edit: {os.path.basename(path)[:32]}" if path else "edit"
    elif tool_name in ("write_file", "write_to_file"):
        path = params.get("Path") or params.get("TargetFile") or ""
        return f"write: {os.path.basename(path)[:32]}" if path else "write"
    elif tool_name == "search_web":
        q = params.get("query", "")
        return f"search: {q[:32]}" if q else "search"
    elif tool_name == "invoke_subagent":
        role = params.get("Role") or params.get("TypeName") or "agent"
        return f"agent: {role[:30]}"
    elif tool_name == "call_mcp_tool":
        srv = params.get("ServerName", "")
        tname = params.get("ToolName", "")
        return f"mcp: {srv}.{tname}"[:36] if srv else f"mcp: {tname[:30]}"
    elif tool_name == "context_compaction":
        return "🧹 自动压缩上下文 (Context Compaction)"
    return tool_name[:30]


def summarize_tool_output(tool_info):
    """Extract a crisp 1-line outcome snippet from completed tool_info if available."""
    out = (tool_info or {}).get("output")
    if not isinstance(out, str) or not out.strip():
        return ""
    idx = out.find("Command output:\n")
    if idx != -1:
        body = out[idx + len("Command output:\n"):].strip()
    else:
        body = out.strip()
    for line in body.splitlines():
        s = line.strip()
        if s and not s.startswith("Created At:") and not s.startswith("Completed At:"):
            return s[:48] + ("…" if len(s) > 48 else "")
    return ""


def format_usage_suffix(dur, total_tokens, model=None, effort=None):
    parts = []
    eff_model = model or "gemini-3.8-flash-high"
    if effort:
        eff_effort = effort
    else:
        for lvl in ("xhigh", "high", "medium", "low"):
            if eff_model.endswith("-" + lvl):
                eff_effort = lvl
                break
        else:
            eff_effort = "default"

    parts.append(f"🤖 {eff_model}")
    parts.append(f"🧠 {eff_effort}")

    if dur is not None:
        try:
            parts.append(f"⏱ {float(dur) / 60.0:.2f} min")
        except Exception:
            parts.append(f"⏱ {dur} min")

    if total_tokens is not None:
        try:
            m = float(total_tokens) / 1_000_000.0
            if m < 0.001:
                tok_str = f"{m:.4f}".rstrip("0").rstrip(".") + " m"
            elif m < 0.1:
                tok_str = f"{m:.3f}".rstrip("0").rstrip(".") + " m"
            else:
                tok_str = f"{m:.2f}".rstrip("0").rstrip(".") + " m"
            parts.append(tok_str)
        except Exception:
            parts.append(f"{total_tokens} m")

    return " · ".join(parts)


def format_tokens_k(tokens):
    if tokens is None:
        return "0k"
    if tokens >= 1000:
        val = tokens / 1000.0
        return f"{val:.1f}k" if val < 100 else f"{int(round(val))}k"
    return str(int(tokens))


def get_context_stats(cid):
    """Inspect transcript.jsonl to compute active post-checkpoint context size & compaction metrics."""
    info = {
        "exists": False,
        "total_lines": 0,
        "checkpoints": 0,
        "steps_since_ckpt": 0,
        "turns_since_ckpt": 0,
        "ctx_tokens": 0,
        "raw_ctx_tokens": None,
        "just_compacted": False,
    }
    if not cid:
        return info
    tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl")
    if not os.path.exists(tpath):
        return info
    try:
        with open(tpath) as f:
            lines = f.readlines()
    except Exception:
        return info

    info["exists"] = True
    info["total_lines"] = len(lines)
    last_ckpt_idx = -1
    ckpts = 0
    parsed = []
    for idx, raw in enumerate(lines):
        try:
            obj = json.loads(raw)
        except Exception:
            obj = {}
        parsed.append(obj)
        if obj.get("type") == "CHECKPOINT" and obj.get("status") == "DONE":
            ckpts += 1
            last_ckpt_idx = idx

    info["checkpoints"] = ckpts
    post = parsed[last_ckpt_idx + 1:]
    info["steps_since_ckpt"] = len(post)
    info["turns_since_ckpt"] = sum(1 for o in post if o.get("type") == "USER_INPUT")

    latest_ctx = None
    for o in reversed(post):
        inp = o.get("input_tokens") or 0
        cache = o.get("cache_read_tokens") or 0
        if inp or cache:
            latest_ctx = int(inp) + int(cache)
            break

    info["raw_ctx_tokens"] = latest_ctx
    if latest_ctx is not None:
        info["ctx_tokens"] = latest_ctx
    elif ckpts > 0:
        info["just_compacted"] = True
        info["ctx_tokens"] = 14000
    return info


def should_auto_compact(cid, scope_key=None):
    """Return (should_run: bool, stats: dict) based on scope settings and active uncompacted tokens."""
    sc = get_scope_state(scope_key)
    enabled = bool(sc.get("auto_compact", True))
    thresh = int(sc.get("auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS)
    stats = get_context_stats(cid)
    if not enabled or not cid or not stats["exists"]:
        return False, stats
    raw_ctx = stats["raw_ctx_tokens"]
    if raw_ctx is None or raw_ctx < thresh:
        return False, stats
    if stats["steps_since_ckpt"] < 6:
        return False, stats
    last_line = _last_compacted_line.get(cid, -999)
    if stats["total_lines"] < last_line + 6:
        return False, stats
    return True, stats


_TRANSIENT_ERR_MARKERS = (
    "oauth2:",
    "internal_failure",
    "token refresh",
    "error getting token source",
    "not logged into antigravity",
    "context summarization: request failed",
    "checkpoint_empty_summary",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "status 502",
    "status 503",
    "code = unavailable",
    "connection reset by peer",
    "tls handshake timeout",
    "unexpected eof",
)


def is_transient_agy_error(err_text):
    if not err_text:
        return False
    low = err_text.lower()
    return any(m in low for m in _TRANSIENT_ERR_MARKERS)


def is_summarization_error(err_text):
    if not err_text:
        return False
    low = err_text.lower()
    return ("context summarization" in low) or ("checkpoint_empty_summary" in low)


def get_transcript_line_count(cid):
    if not cid:
        return 0
    tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl")
    if not os.path.exists(tpath):
        return 0
    try:
        with open(tpath) as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def get_turn_details(cid, start_line=0):
    """Extract thinking chains and tool calls from transcript.jsonl starting at start_line."""
    if not cid:
        return [], [], start_line
    tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl")
    if not os.path.exists(tpath):
        return [], [], start_line
    thinkings = []
    tool_calls = []
    total_lines = start_line
    try:
        with open(tpath) as f:
            all_lines = f.readlines()
        total_lines = len(all_lines)
        for line in all_lines[start_line:]:
            try:
                obj = json.loads(line)
                if obj.get("thinking"):
                    thinkings.append(obj["thinking"])
                if obj.get("tool_calls"):
                    for tc in obj["tool_calls"]:
                        tool_calls.append(tc)
            except Exception:
                pass
    except Exception:
        pass
    return thinkings, tool_calls, total_lines


def build_thinking_header(thinkings, tool_calls):
    """Build a collapsible Telegram blockquote (<blockquote expandable>) safely within 3800 chars."""
    open_tag = "<blockquote expandable>"
    close_tag = "</blockquote>\n\n"
    max_inner = 3800 - len(open_tag) - len(close_tag)

    thinking_block = ""
    if thinkings:
        joined_thinking = "\n\n".join(t.strip() for t in thinkings if t and t.strip())
        if len(joined_thinking) > 1600:
            joined_thinking = joined_thinking[:1600] + "... (truncated)"
        while joined_thinking and len(html_mod.escape(joined_thinking)) > 2000:
            joined_thinking = joined_thinking[:max(100, int(len(joined_thinking) * 0.75))] + "... (truncated)"
        if joined_thinking:
            thinking_block = "💭 <b>思考过程 (Thinking Process):</b>\n" + html_mod.escape(joined_thinking)

    blocks = [thinking_block] if thinking_block else []
    used_len = len(thinking_block)

    if tool_calls:
        tool_hdr = f"🛠 <b>工具调用 (Tool Calls - {len(tool_calls)}):</b>"
        sep = 2 if blocks else 0
        if used_len + sep + len(tool_hdr) + 64 <= max_inner:
            tool_lines = [tool_hdr]
            used_len += sep + len(tool_hdr)
            cap = min(len(tool_calls), 25)
            shown = 0
            for tc in tool_calls[:cap]:
                name = tc.get("name", "tool")
                args = tc.get("args") or {}
                label = format_tool_label(name, {"parameters": args})
                line = f"• <code>{html_mod.escape(name)}</code> ({html_mod.escape(label)})"
                more_note = f"\n• <i>... +{len(tool_calls) - (shown + 1)} more</i>"
                reserve = len(more_note) if (shown + 1) < len(tool_calls) else 0
                if used_len + 1 + len(line) + reserve > max_inner:
                    break
                tool_lines.append(line)
                used_len += 1 + len(line)
                shown += 1
            if shown < len(tool_calls):
                tool_lines.append(f"• <i>... +{len(tool_calls) - shown} more</i>")
            blocks.append("\n".join(tool_lines))

    if not blocks:
        return ""
    return open_tag + "\n\n".join(blocks) + close_tag


def extract_live_thought_snippet(raw_thought, max_chars=360):
    """Extract the latest reasoning lines (up to ~4 lines / 360 chars) for live streaming preview."""
    if not raw_thought:
        return ""
    cleaned_lines = []
    for line in raw_thought.strip().splitlines():
        s = re.sub(r"^[#>*\s]+", "", line).strip()
        if s:
            cleaned_lines.append(s)
    if not cleaned_lines:
        return ""
    tail = "\n".join(cleaned_lines[-4:])
    if len(tail) > max_chars:
        tail = "…" + tail[-max_chars:]
    return tail


# ---------------------------------------------------------------- Native Real-Time Draft Streamer
class LiveDraftStreamer:
    """Streams instant native `sendMessageDraft` updates (with automatic fallback to editMessageText).
    - t=0.00s: immediately pops up Telegram native "Thinking…" placeholder + Stop button
    - Event-driven (<50ms) live updates on every thought block, tool start, and tool finish
    - Smooth ~4.5 fps (0.22s) non-blocking animated text streaming during `agent_response`
    """

    def __init__(self, chat_id, started, cid=None, start_line=0, enabled=True, thread_id=None):
        self.chat_id = chat_id
        self.thread_id = _normalize_thread_id(thread_id)
        self.started = started
        self.cid = cid
        self.tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl") if cid else None
        self.start_line = start_line
        self.enabled = enabled

        self.use_draft_api = bool(chat_id and int(chat_id) > 0)  # Native draft API works in private chats / DM topics
        self.status_draft_id, self.text_draft_id = alloc_draft_pair()
        self.fallback_msg_id = None

        self.lock = threading.Lock()
        self.io_lock = threading.Lock()  # Held during HTTP call so finalize never races a late draft
        self.wakeup = threading.Event()
        self.stop_ev = threading.Event()

        self.paused = False
        self.waiting_bg = False
        self.delay_until = 0.0
        self.flood_until = 0.0
        self._fb_min_gap = 3.2
        self._fb_429_logged_at = 0.0
        self.phase = "status"          # "status" | "text"
        self.active_tool = None
        self.tool_history = []         # [(label, dur_str, out_snippet)]
        self.total_tools = 0
        self.latest_thought = ""
        self.stream_text = ""
        self.status_override = None

        self.last_sent_key = None
        self.last_push_at = 0.0
        self.urgent = True             # Push immediately at t=0.00s!
        self._thread = None

    def start(self):
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def set_cid(self, cid):
        if not cid:
            return
        with self.lock:
            if self.cid == cid and self.tpath:
                return
            self.cid = cid
            self.tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl")
            self.start_line = get_transcript_line_count(cid)

    def _refresh_thought_locked(self):
        if not self.tpath or not os.path.exists(self.tpath):
            return
        try:
            with open(self.tpath) as f:
                lines = f.readlines()[self.start_line:]
            for line in reversed(lines):
                obj = json.loads(line)
                th = obj.get("thinking")
                if th:
                    snip = extract_live_thought_snippet(th)
                    if snip and snip != self.latest_thought:
                        self.latest_thought = snip
                    break
        except Exception:
            pass

    def set_status_override(self, template_html):
        """Set or clear a custom status title template (may include `{elapsed}`)."""
        with self.lock:
            self.status_override = template_html
            self.phase = "status"
            self.paused = False
            self.delay_until = 0.0
            self.urgent = True
        self.wakeup.set()

    def on_thinking(self, text):
        if not text:
            return
        with self.lock:
            snip = extract_live_thought_snippet(text)
            if snip:
                self.latest_thought = snip
                self.urgent = True
        self.wakeup.set()

    def on_tool_start(self, tool_name, tool_info):
        label = format_tool_label(tool_name, tool_info)
        with self.lock:
            # Immediately pull the fresh thinking block that agy flushed right before tool start!
            self._refresh_thought_locked()
            self.paused = False
            self.waiting_bg = False
            self.delay_until = 0.0
            self.phase = "status"
            self.active_tool = label
            self.total_tools += 1
            self.urgent = True
        self.wakeup.set()

    def on_tool_done(self, tool_name, tool_info, duration_seconds=None):
        label = format_tool_label(tool_name, tool_info)
        dur_str = f"{duration_seconds:.1f}s" if duration_seconds is not None else ""
        out_snip = summarize_tool_output(tool_info)
        with self.lock:
            self.tool_history.append((label, dur_str, out_snip))
            if len(self.tool_history) > 7:
                self.tool_history = self.tool_history[-7:]
            if self.active_tool == label:
                self.active_tool = None
            self.urgent = True
        self.wakeup.set()

    def on_text_delta(self, accumulated_text):
        if not accumulated_text or not accumulated_text.strip():
            return
        with self.lock:
            was_status = (self.phase != "text")
            self.paused = False
            self.delay_until = 0.0
            self.phase = "text"
            self.stream_text = accumulated_text
            if was_status:
                self.urgent = True
        self.wakeup.set()

    def pause_for_finalize(self):
        """Synchronously pause streaming and wait for any in-flight draft HTTP call to finish."""
        with self.lock:
            self.paused = True
        with self.io_lock:
            pass

    def finalize_step(self, final_text, header_html=None, footer_str=None, reply_markup=None):
        """Deliver permanent step message cleanly, replacing the live draft without losing output."""
        self.pause_for_finalize()
        old_fb_mid = self.fallback_msg_id
        self.fallback_msg_id = None

        # In fallback mode (e.g. group chat), edit single-chunk message in place to save group quota
        if not self.use_draft_api and old_fb_mid is not None:
            chunks = split_markdown(final_text, max_len=3000)
            footer_html = ("\n\n" + html_mod.escape(footer_str)) if footer_str else ""
            if len(chunks) == 1:
                full_html = (header_html or "") + md_to_html(chunks[0]) + footer_html
                if full_html and len(full_html) <= 4050:
                    kw = {
                        "chat_id": self.chat_id,
                        "message_id": old_fb_mid,
                        "text": full_html,
                        "parse_mode": "HTML",
                        "link_preview_options": {"is_disabled": True},
                    }
                    if reply_markup:
                        kw["reply_markup"] = reply_markup
                    r = tg("editMessageText", _max_429_wait=65, **kw)
                    if _tg_ok(r):
                        return old_fb_mid, full_html

        # Deliver permanent response FIRST (with 429 wait + multi-chunk pacing + rescue) BEFORE deleting fallback bubble!
        last_mid, last_html = send_rich(
            self.chat_id, final_text, header_html=header_html,
            footer_str=footer_str, reply_markup=reply_markup, thread_id=self.thread_id,
        )

        if old_fb_mid is not None:
            if last_mid is not None:
                tg("deleteMessage", _timeout=FAST_TIMEOUT, _retry_429=False,
                   chat_id=self.chat_id, message_id=old_fb_mid)
            else:
                snippet = html_mod.escape(final_text[:2800]) + ("\n..." if len(final_text) > 2800 else "")
                notice = (
                    "⚠️ <b>最终消息送达受阻，已保存并尝试文件补发，以下为预览：</b>\n\n"
                    f"{snippet}"
                )
                tg("editMessageText", _max_429_wait=20, chat_id=self.chat_id, message_id=old_fb_mid,
                   text=notice[:4090], parse_mode="HTML", link_preview_options={"is_disabled": True})

        return last_mid, last_html

    def start_next_segment(self, new_start_line):
        """Prepare a fresh draft pair if the turn continues after an intermediate response."""
        d1, d2 = alloc_draft_pair()
        with self.lock:
            self.status_draft_id = d1
            self.text_draft_id = d2
            self.fallback_msg_id = None
            self.phase = "status"
            self.stream_text = ""
            self.tool_history = []
            self.active_tool = None
            self.latest_thought = ""
            self.start_line = new_start_line
            self.last_sent_key = None
            self.waiting_bg = True
            self.paused = False
            # Small 0.5s grace so normal turns never flash after intermediate check
            self.delay_until = time.time() + 0.5
        self.wakeup.set()

    def stop(self):
        self.stop_ev.set()
        with self.lock:
            self.paused = True
            fb_mid = self.fallback_msg_id
            self.fallback_msg_id = None
        self.wakeup.set()
        with self.io_lock:
            pass
        if fb_mid is not None:
            tg("deleteMessage", _timeout=FAST_TIMEOUT, _retry_429=False,
               chat_id=self.chat_id, message_id=fb_mid)

    def _build_status_payload_locked(self):
        elapsed = int(time.time() - self.started)
        self._refresh_thought_locked()

        # At t < 2s before any thoughts/tools arrive, empty string triggers Telegram native "Thinking…" shimmer!
        if (self.use_draft_api and elapsed < 2 and not self.status_override and not self.latest_thought
                and not self.tool_history and not self.active_tool and not self.waiting_bg):
            return self.status_draft_id, ""

        if self.status_override:
            title = self.status_override.replace("{elapsed}", str(elapsed))
        elif self.waiting_bg and not self.active_tool and not self.latest_thought and not self.tool_history:
            title = f"⏳ <b>等待后台任务响应 ({elapsed}s)...</b>"
        elif self.total_tools > 0:
            title = f"⚡ <b>思考与执行中 ({elapsed}s · 第 {self.total_tools} 步)...</b>"
        else:
            title = f"🧠 <b>正在深度思考 ({elapsed}s)...</b>"

        lines = [title]
        if self.latest_thought:
            lines.append(f"\n<blockquote>💭 <i>{html_mod.escape(self.latest_thought)}</i></blockquote>")

        tool_lines = []
        for label, dur, out_snip in self.tool_history[-5:]:
            tag = f" <code>[{dur}]</code>" if dur else ""
            extra = f"\n   ↳ <i>{html_mod.escape(out_snip)}</i>" if out_snip else ""
            tool_lines.append(f"• ✓ <code>{html_mod.escape(label)}</code>{tag}{extra}")
        if self.active_tool:
            tool_lines.append(f"• ⚙️ <code>{html_mod.escape(self.active_tool)}</code> <i>(执行中...)</i>")

        if tool_lines:
            lines.append("\n" + "\n".join(tool_lines))

        return self.status_draft_id, "\n".join(lines)[:3950]

    def _build_text_payload_locked(self):
        raw = self.stream_text.strip()
        snippet = raw if len(raw) <= 3400 else ("…\n" + raw[-3400:])
        if snippet.count("```") % 2 == 1:
            snippet += "\n```"
        rendered = md_to_html(snippet)
        html = rendered + " ▍"
        if len(html) > 4000:
            html = html_mod.escape(raw[-3800:]) + " ▍"
        return self.text_draft_id, html

    def _push_draft(self, draft_id, html_text):
        with self.io_lock:
            with self.lock:
                if self.paused or self.stop_ev.is_set():
                    return

            if self.use_draft_api:
                params = {
                    "draft_id": draft_id,
                    "text": html_text,
                    "can_stop": True,
                    "keep_on_stop": True,
                }
                if html_text:
                    params["parse_mode"] = "HTML"
                r = tg_send_in_route("sendMessageDraft", self.chat_id, thread_id=self.thread_id,
                                     _timeout=FAST_TIMEOUT, _retry_429=False, **params)
                if r is not None:
                    if r.status_code == 429:
                        wait_s = _tg_retry_after(r) or 2
                        with self.lock:
                            self.flood_until = max(self.flood_until, time.time() + min(wait_s, 30) + 0.5)
                        self.last_push_at = time.time()
                        return
                    j = _tg_json(r)
                    if j.get("ok"):
                        self.last_push_at = time.time()
                        return
                    desc = str(j.get("description", ""))
                    # If malformed partial HTML entity, retry plain text draft once
                    if html_text and ("parse entities" in desc or "can't find end" in desc):
                        plain = re.sub(r"<[^>]+>", "", html_mod.unescape(html_text))[:3950]
                        r2 = tg_send_in_route("sendMessageDraft", self.chat_id, thread_id=self.thread_id,
                                              _timeout=FAST_TIMEOUT, _retry_429=False,
                                              draft_id=draft_id, text=plain,
                                              can_stop=True, keep_on_stop=True)
                        if _tg_ok(r2):
                            self.last_push_at = time.time()
                            return
                    # Otherwise fallback cleanly to editMessageText mode
                    log("sendMessageDraft returned %s; switching to editMessageText fallback" % desc)
                    self.use_draft_api = False

            # Fallback path (e.g. group chats / topics)
            fb_text = html_text or "🧠 <b>正在思考中...</b>"
            use_parse_html = True
            for _fb_try in range(2):
                kw_fb = {"text": fb_text, "link_preview_options": {"is_disabled": True}}
                if use_parse_html:
                    kw_fb["parse_mode"] = "HTML"
                if self.fallback_msg_id is None:
                    r = tg_send_in_route(
                        "sendMessage", self.chat_id, thread_id=self.thread_id,
                        _timeout=FAST_TIMEOUT, _retry_429=False, **kw_fb
                    )
                    mid = _extract_msg_id(r)
                    if mid:
                        with self.lock:
                            if self.paused or self.stop_ev.is_set():
                                tg("deleteMessage", _timeout=FAST_TIMEOUT, _retry_429=False,
                                   chat_id=self.chat_id, message_id=mid)
                                return
                            self.fallback_msg_id = mid
                        self.last_push_at = time.time()
                        return
                else:
                    r = tg(
                        "editMessageText", _timeout=FAST_TIMEOUT, _retry_429=False,
                        chat_id=self.chat_id, message_id=self.fallback_msg_id, **kw_fb
                    )
                    if _tg_ok(r):
                        self.last_push_at = time.time()
                        return

                if r is not None and r.status_code == 429:
                    wait_s = _tg_retry_after(r) or 5
                    with self.lock:
                        self._fb_min_gap = min(8.0, self._fb_min_gap + 1.2)
                        self.flood_until = max(self.flood_until, time.time() + min(wait_s, 90) + 1.0)
                        gap_now = self._fb_min_gap
                    if (time.time() - self._fb_429_logged_at) > 10.0:
                        self._fb_429_logged_at = time.time()
                        log("DraftStreamer fallback hit 429 (retry_after=%ss); backing off (gap=%.1fs)" % (wait_s, gap_now))
                    self.last_push_at = time.time()
                    return

                desc = str(_tg_json(r).get("description", ""))
                low_desc = desc.lower()
                if "message is not modified" in low_desc:
                    self.last_push_at = time.time()
                    return
                if use_parse_html and ("parse entities" in low_desc or "can't find end" in low_desc):
                    fb_text = re.sub(r"<[^>]+>", "", html_mod.unescape(fb_text))[:3950] or "Thinking..."
                    use_parse_html = False
                    continue
                if "message to edit not found" in low_desc:
                    with self.lock:
                        self.fallback_msg_id = None
                break
            self.last_push_at = time.time()

    def _loop(self):
        while not self.stop_ev.is_set():
            with self.lock:
                now = time.time()
                is_paused = self.paused
                rem_delay = max(0.0, max(self.delay_until, self.flood_until) - now)
                is_text = (self.phase == "text")
                is_urgent = self.urgent
            if is_paused:
                self.wakeup.wait(timeout=1.0)
            elif rem_delay > 0:
                self.stop_ev.wait(timeout=min(1.0, rem_delay))
            else:
                wait_s = 0.0 if is_urgent else (0.22 if is_text else 1.2)
                if wait_s > 0:
                    self.wakeup.wait(timeout=wait_s)
            self.wakeup.clear()

            if self.stop_ev.is_set():
                break

            now = time.time()
            with self.lock:
                if self.paused or now < max(self.delay_until, self.flood_until):
                    continue
                if self.use_draft_api:
                    min_gap = 0.20 if self.phase == "text" else (0.12 if self.urgent else 1.1)
                else:
                    min_gap = max(3.2, self._fb_min_gap)
                since = now - self.last_push_at
                sleep_rem = max(0.0, min_gap - since)

            if sleep_rem > 0:
                self.stop_ev.wait(timeout=sleep_rem)
                if self.stop_ev.is_set():
                    break

            with self.lock:
                if self.paused or self.stop_ev.is_set() or time.time() < max(self.delay_until, self.flood_until):
                    continue
                self.urgent = False
                if self.phase == "text":
                    did, payload = self._build_text_payload_locked()
                else:
                    did, payload = self._build_status_payload_locked()

                # Keep draft alive every 12s even if text didn't change (draft expires at 30s)
                key = (did, payload)
                if key == self.last_sent_key and (time.time() - self.last_push_at) < 12.0:
                    continue
                self.last_sent_key = key

            self._push_draft(did, payload)


# ---------------------------------------------------------------- workspace & image detection
_SKIP_WALK_DIRS = frozenset({
    ".git", "uploads", "node_modules", ".pnpm", ".pnpm-store", "dist", "build",
    ".next", ".nuxt", ".output", ".svelte-kit", "coverage", "vendor", "venv",
    ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".cache", ".agents",
    ".claude", "target",
})

_NOISE_ASSET_SEGMENTS = (
    "/node_modules/", "/.pnpm/", "/.pnpm-store/", "/vendor/", "/dist/", "/build/",
    "/.next/", "/.nuxt/", "/.output/", "/coverage/", "/.git/", "/.venv/", "/venv/",
    "/__pycache__/", "/.cache/",
)

_VISUAL_TOOL_KEYWORDS_RE = re.compile(
    r"(?:image-generator|workstation_screenshot|playwright|puppeteer|selenium|screenshot|"
    r"qrencode|qrcode|matplotlib|savefig|wkhtmltoimage|chromium|headless|pillow|"
    r"\bPIL\b|magick|graphviz|mermaid|sendPhoto|AGY_OUTBOX_DIR)",
    re.IGNORECASE,
)


def snapshot_workspace_files(workdir=None):
    """Map of file paths -> mtime in workspace (pruning dependency/build/cache trees)."""
    files = {}
    wdir = workdir or current_workdir()
    for root, dirs, fnames in os.walk(wdir):
        dirs[:] = [d for d in dirs if d not in _SKIP_WALK_DIRS]
        for fn in fnames:
            fp = os.path.join(root, fn)
            try:
                files[fp] = os.path.getmtime(fp)
            except OSError:
                pass
    return files


_HOME_RE_PREFIX = re.escape(HOME.rstrip("/") + "/")
_IMG_REF_RE = re.compile(
    rf"(?:file://)?((?:{_HOME_RE_PREFIX}[^\s)`\"'\\]+|/tmp/[^\s)`\"'\\]+|[A-Za-z0-9_./\-]+)\.(?:png|jpg|jpeg|webp|gif))",
    re.IGNORECASE,
)
_MD_ARTIFACT_RE = re.compile(
    rf"file://({_HOME_RE_PREFIX}[^\s)`\"'\\]+\.md)",
    re.IGNORECASE,
)


def _claim_shared_image(rp, mtime):
    """Atomically claim `(realpath, mtime)` for `BOT_INSTANCE_ID` so another bridge instance
    sharing a workspace directory or `/tmp` can never cross-send the same image.
    """
    lock_path = IMG_CLAIMS_FILE + ".lock"
    key = f"{rp}|{mtime:.2f}"
    now = time.time()
    try:
        with open(lock_path, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            claims = {}
            if os.path.isfile(IMG_CLAIMS_FILE):
                try:
                    with open(IMG_CLAIMS_FILE, "r", encoding="utf-8") as cf:
                        claims = json.load(cf)
                    if not isinstance(claims, dict):
                        claims = {}
                except Exception:
                    claims = {}
            # Prune entries older than 1 hour
            claims = {
                k: v for k, v in claims.items()
                if isinstance(v, dict) and (now - float(v.get("ts") or 0)) < 3600
            }
            existing = claims.get(key)
            if existing and existing.get("bot") != BOT_INSTANCE_ID:
                return False
            claims[key] = {"bot": BOT_INSTANCE_ID, "ts": now}
            tmp_f = IMG_CLAIMS_FILE + ".tmp"
            with open(tmp_f, "w", encoding="utf-8") as wf:
                json.dump(claims, wf)
            os.replace(tmp_f, IMG_CLAIMS_FILE)
        return True
    except Exception:
        return True


def try_claim_image(path):
    """Claim `path` for this bridge instance before sending bus artifacts."""
    try:
        rp = os.path.realpath(path)
        st = os.stat(rp)
    except OSError:
        return False
    return _claim_shared_image(rp, st.st_mtime)


def _extract_turn_image_context(cid, turn_start_line, turn_tool_texts):
    """Inspect ONLY this conversation's own tool calls in the current turn to determine:
    1) exact image paths explicitly targeted/created by this bot's tools
    2) whether this bot invoked any screenshot/QR/browser/chart generation tool
    """
    chunks = list(turn_tool_texts or [])
    if cid:
        tpath = os.path.join(BRAIN_ROOT, cid, ".system_generated/logs/transcript.jsonl")
        if os.path.isfile(tpath):
            try:
                with open(tpath, "r", encoding="utf-8", errors="ignore") as tf:
                    lines = tf.readlines()
                for raw in lines[max(0, int(turn_start_line or 0)):]:
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        continue
                    tcs = obj.get("tool_calls")
                    if isinstance(tcs, list) and tcs:
                        chunks.append(json.dumps(tcs, ensure_ascii=False))
            except Exception:
                pass

    combined = "\n".join(chunks).replace('\\"', '"').replace("\\/", "/")
    explicit_tool_paths = []
    if combined:
        for m in _IMG_REF_RE.finditer(combined):
            explicit_tool_paths.append(m.group(1))
    has_visual_tool = bool(combined and _VISUAL_TOOL_KEYWORDS_RE.search(combined))
    return explicit_tool_paths, has_visual_tool, combined


def _other_bridge_is_busy():
    """Check whether a sibling bridge state file currently has an `in_flight` turn."""
    try:
        my_state = os.path.realpath(STATE_FILE)
        for fn in os.listdir(HOME):
            if not (fn.startswith(".agy-tg-bridge") and fn.endswith(".json")):
                continue
            sp = os.path.realpath(os.path.join(HOME, fn))
            if sp == my_state:
                continue
            with open(sp, "r", encoding="utf-8") as f:
                data = json.load(f)
            inf = data.get("in_flight")
            if isinstance(inf, dict) and (time.time() - float(inf.get("started_at") or 0)) < 1800:
                return True
    except Exception:
        pass
    return False


def collect_step_images(
    step_text,
    cid,
    turn_started,
    before_files,
    sent_mtimes,
    live_watch=False,
    turn_tool_texts=None,
    turn_start_line=0,
    workdir=None,
):
    """Find newly generated, updated, or explicitly referenced image files belonging strictly to THIS bot's turn."""
    candidates = []
    active_wdir = workdir or current_workdir()
    allowed_roots = tuple(dict.fromkeys([active_wdir + os.sep, WORKDIR + os.sep, BRAIN_ROOT + os.sep, "/tmp/"]))
    isolated_roots = tuple(
        r for r in (
            (os.path.join(BRAIN_ROOT, cid) + os.sep) if cid else None,
            BOT_OUTBOX_DIR + os.sep,
        )
        if r
    )
    now = time.time()
    my_uid = os.getuid()

    explicit_tool_paths, has_visual_tool, _ = _extract_turn_image_context(cid, turn_start_line, turn_tool_texts)

    def try_add(raw_path, explicit=False, from_reply_text=False):
        if not raw_path:
            return
        p = raw_path if os.path.isabs(raw_path) else os.path.join(active_wdir, raw_path)
        rp = os.path.realpath(p)
        if "/.system_generated/" in rp or (UPLOADDIR + os.sep) in (rp + os.sep):
            return
        if not any(rp.startswith(r) for r in allowed_roots):
            return
        if os.path.splitext(rp)[1].lower() not in IMAGE_EXTS:
            return
        # Block node_modules / dist / build / vendor asset spam unless literally written in model reply text
        if not from_reply_text and any(seg in rp for seg in _NOISE_ASSET_SEGMENTS):
            return
        # Prevent reading another conversation's brain directory
        if rp.startswith(BRAIN_ROOT + os.sep) and cid and not rp.startswith(os.path.join(BRAIN_ROOT, cid) + os.sep) and not from_reply_text:
            return
        try:
            st = os.stat(rp)
        except OSError:
            return
        if rp.startswith("/tmp/") and st.st_uid != my_uid:
            return
        if st.st_size <= 64 or st.st_size > 15 * 1024 * 1024:
            return
        if live_watch and (now - st.st_mtime) < 0.4:
            return
        prev_sent = sent_mtimes.get(rp)
        if prev_sent is not None and st.st_mtime <= (prev_sent + 0.8):
            return
        # Only allow pre-existing older files when explicitly linked in the model's reply text/artifact
        if not from_reply_text and st.st_mtime < (turn_started - 1.5):
            return
        is_isolated = any(rp.startswith(ir) for ir in isolated_roots)
        if not is_isolated and not _claim_shared_image(rp, st.st_mtime):
            return
        if (rp, st.st_mtime) not in candidates:
            candidates.append((rp, st.st_mtime))

    # 1. Explicit references in THIS bot's reply text or linked .md artifacts
    if step_text:
        for m in _IMG_REF_RE.finditer(step_text):
            try_add(m.group(1), explicit=True, from_reply_text=True)
        for md_m in _MD_ARTIFACT_RE.finditer(step_text):
            md_path = os.path.realpath(md_m.group(1))
            if (md_path.startswith(BRAIN_ROOT + os.sep) or md_path.startswith(WORKDIR + os.sep)) and os.path.isfile(md_path):
                try:
                    with open(md_path, "r", encoding="utf-8", errors="ignore") as mf:
                        md_body = mf.read(32768)
                    for im in _IMG_REF_RE.finditer(md_body):
                        try_add(im.group(1), explicit=True, from_reply_text=True)
                except Exception:
                    pass

    # 2. Explicit image output paths found in THIS bot's own tool calls during this turn (e.g. qrencode -o qr.png)
    for tp in explicit_tool_paths:
        try_add(tp, explicit=True, from_reply_text=False)

    # 3. Per-conversation isolated directories (brain/<cid>/ and /tmp/agy-outbox-<bot>/)
    if cid:
        cdir = os.path.join(BRAIN_ROOT, cid)
        if os.path.isdir(cdir):
            for root, dirs, fnames in os.walk(cdir):
                if ".system_generated" in root:
                    dirs[:] = []
                    continue
                for fn in fnames:
                    if os.path.splitext(fn)[1].lower() in IMAGE_EXTS:
                        try_add(os.path.join(root, fn), explicit=False, from_reply_text=False)

    if os.path.isdir(BOT_OUTBOX_DIR):
        try:
            with os.scandir(BOT_OUTBOX_DIR) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and os.path.splitext(entry.name)[1].lower() in IMAGE_EXTS:
                        try_add(entry.path, explicit=False, from_reply_text=False)
        except Exception:
            pass

    # 4. Shared top-level workspace & /tmp fallback ONLY when THIS bot's turn actually invoked a visual/QR/browser tool
    #    (Never walks nested subdirectories like cloud-mail/..., preventing cross-bot & build-asset leakage!)
    if has_visual_tool:
        for shared_dir in tuple(dict.fromkeys([active_wdir, WORKDIR, "/tmp"])):
            try:
                with os.scandir(shared_dir) as it:
                    for entry in it:
                        if entry.is_file(follow_symlinks=False) and os.path.splitext(entry.name)[1].lower() in IMAGE_EXTS:
                            fp = entry.path
                            if shared_dir in (active_wdir, WORKDIR):
                                st_m = entry.stat().st_mtime
                                if fp in before_files and st_m <= before_files.get(fp, 0) + 0.5:
                                    continue
                            try_add(fp, explicit=False, from_reply_text=False)
            except Exception:
                pass

    return candidates[:4]


def push_step_images(
    chat_id,
    step_text,
    cid,
    turn_started,
    before_files,
    sent_mtimes,
    live_watch=False,
    turn_tool_texts=None,
    turn_start_line=0,
    thread_id=None,
    workdir=None,
):
    imgs = collect_step_images(
        step_text,
        cid,
        turn_started,
        before_files,
        sent_mtimes,
        live_watch=live_watch,
        turn_tool_texts=turn_tool_texts,
        turn_start_line=turn_start_line,
        workdir=workdir,
    )
    if not imgs:
        return
    for rp, mtime in imgs:
        sent_mtimes[rp] = mtime

    # Batch 2+ static images into a single clean Telegram album when possible
    album_ok_paths = []
    other_paths = []
    for rp, _mt in imgs:
        ext = os.path.splitext(rp)[1].lower()
        try:
            sz = os.path.getsize(rp)
        except OSError:
            sz = 0
        if ext != ".gif" and 0 < sz <= 9.5 * 1024 * 1024:
            album_ok_paths.append(rp)
        else:
            other_paths.append(rp)

    if len(album_ok_paths) >= 2:
        names = ", ".join(os.path.basename(p) for p in album_ok_paths[:4])
        cap = f"🖼 {names}"
        log("Auto-pushing image album (%d images, live_watch=%s)" % (len(album_ok_paths), live_watch))
        if send_media_group(chat_id, album_ok_paths, caption=cap, thread_id=thread_id):
            album_ok_paths = []
        else:
            other_paths = album_ok_paths + other_paths
            album_ok_paths = []

    for rp in album_ok_paths + other_paths:
        log("Auto-pushing generated/referenced image: %s (live_watch=%s)" % (rp, live_watch))
        send_file(chat_id, rp, caption=f"🖼 {os.path.basename(rp)}", thread_id=thread_id)


# ---------------------------------------------------------------- content-addressed workspace undo/redo
_UNDO_SKIP_DIRS = _SKIP_WALK_DIRS - {".agents"}
_UNDO_MAX_FILE_BYTES = 2 * 1024 * 1024
_UNDO_MAX_TOTAL_BYTES = 60 * 1024 * 1024
_UNDO_MAX_FILES = 3000
_UNDO_STACK_LIMIT = 10
_UNDO_STAT_CACHE = {}  # (realpath, mtime_ns, size) -> sha1_hex


def _undo_blob_path(sha1_hex):
    return os.path.join(ACB_UNDO_BLOBS_DIR, sha1_hex[:2], f"{sha1_hex}.z")


def _undo_store_file_blob(filepath, st=None):
    if st is None:
        st = os.stat(filepath)
    key = (filepath, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)), st.st_size)
    cached = _UNDO_STAT_CACHE.get(key)
    if cached and os.path.isfile(_undo_blob_path(cached)):
        return cached
    h = hashlib.sha1()
    chunks = []
    with open(filepath, "rb") as f:
        while True:
            buf = f.read(65536)
            if not buf:
                break
            h.update(buf)
            chunks.append(buf)
    sha1_hex = h.hexdigest()
    bpath = _undo_blob_path(sha1_hex)
    if not os.path.isfile(bpath):
        os.makedirs(os.path.dirname(bpath), exist_ok=True)
        tmp = bpath + f".tmp.{os.getpid()}"
        try:
            with open(tmp, "wb") as bf:
                bf.write(zlib.compress(b"".join(chunks), level=3))
            os.replace(tmp, bpath)
        except Exception:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    if len(_UNDO_STAT_CACHE) > 20000:
        _UNDO_STAT_CACHE.clear()
    _UNDO_STAT_CACHE[key] = sha1_hex
    return sha1_hex


def _undo_read_blob(sha1_hex):
    bpath = _undo_blob_path(sha1_hex)
    with open(bpath, "rb") as bf:
        return zlib.decompress(bf.read())


def _file_sha1_if_exists(filepath):
    if not os.path.isfile(filepath):
        return None
    try:
        st = os.stat(filepath)
        if st.st_size > _UNDO_MAX_FILE_BYTES:
            return None
        return _undo_store_file_blob(filepath, st=st)
    except OSError:
        return None


def snapshot_undo_manifest(wdir):
    """Capture lightweight content-addressed pre/post file manifest of `wdir`."""
    if not wdir or not os.path.isdir(wdir):
        return {"workdir": wdir, "files": {}, "truncated": False}
    files = {}
    total_bytes = 0
    truncated = False
    for root, dirs, fnames in os.walk(wdir):
        dirs[:] = [d for d in dirs if d not in _UNDO_SKIP_DIRS]
        for fn in fnames:
            if len(files) >= _UNDO_MAX_FILES or total_bytes >= _UNDO_MAX_TOTAL_BYTES:
                truncated = True
                break
            fp = os.path.join(root, fn)
            if os.path.islink(fp):
                continue
            try:
                st = os.stat(fp)
            except OSError:
                continue
            if st.st_size > _UNDO_MAX_FILE_BYTES:
                continue
            total_bytes += st.st_size
            try:
                sha1_hex = _undo_store_file_blob(fp, st=st)
            except OSError:
                continue
            rel = os.path.relpath(fp, wdir)
            files[rel] = {"sha1": sha1_hex, "mode": st.st_mode & 0o777}
        if truncated:
            break
    return {"workdir": wdir, "files": files, "truncated": truncated}


def finalize_turn_undo(scope_key, wdir, pre_manifest, prompt_preview, conv):
    """Diff post-turn workspace against `pre_manifest` and push checkpoint if any file changed."""
    if not pre_manifest or pre_manifest.get("workdir") != wdir:
        return 0
    post_manifest = snapshot_undo_manifest(wdir)
    pre_files = pre_manifest.get("files") or {}
    post_files = post_manifest.get("files") or {}
    changes = []

    for rel, post_info in sorted(post_files.items()):
        pre_info = pre_files.get(rel)
        if pre_info is None:
            changes.append({
                "path": rel,
                "action": "created",
                "post_sha1": post_info["sha1"],
                "post_mode": post_info["mode"],
            })
        elif pre_info["sha1"] != post_info["sha1"]:
            changes.append({
                "path": rel,
                "action": "modified",
                "pre_sha1": pre_info["sha1"],
                "pre_mode": pre_info["mode"],
                "post_sha1": post_info["sha1"],
                "post_mode": post_info["mode"],
            })

    for rel, pre_info in sorted(pre_files.items()):
        if rel not in post_files:
            changes.append({
                "path": rel,
                "action": "deleted",
                "pre_sha1": pre_info["sha1"],
                "pre_mode": pre_info["mode"],
            })

    if not changes:
        return 0

    entry = {
        "id": f"u{int(time.time() * 1000) % 10000000:07x}",
        "ts": int(time.time()),
        "workdir": wdir,
        "conv": conv,
        "prompt": (prompt_preview or "")[:120],
        "truncated": bool(pre_manifest.get("truncated") or post_manifest.get("truncated")),
        "changes": changes[:300],
    }
    with state_lock:
        sc = _ensure_scope_locked(scope_key)
        stack = list(sc.get("undo_stack") or [])
        stack.append(entry)
        sc["undo_stack"] = stack[-_UNDO_STACK_LIMIT:]
        sc["redo_stack"] = []
        _sync_top_level_mirrors_locked()
    save_state()
    return len(changes)


def _safe_under_workdir(wdir, rel_path):
    if not wdir or not rel_path or os.path.isabs(rel_path):
        return None
    rw = os.path.realpath(wdir)
    target = os.path.realpath(os.path.join(rw, rel_path))
    if not target.startswith(rw + os.sep):
        return None
    return target


def _write_blob_atomic(dest, sha1_hex, mode=None):
    raw = _undo_read_blob(sha1_hex)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + f".acbundo.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(raw)
    if mode:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
    os.replace(tmp, dest)


def _apply_checkpoint_changes(entry, reverse=False, force=False):
    """Apply an undo (reverse=False) or redo (reverse=True) checkpoint.
    Returns `(ok, applied_items, conflicts, prepared_reverse_changes)`.
    """
    wdir = entry.get("workdir")
    changes = entry.get("changes") or []
    if not wdir or not os.path.isdir(wdir):
        return False, [], [f"(工作目录不存在: {wdir})"], []

    conflicts = []
    targets = []
    for ch in changes:
        rel = ch.get("path")
        dest = _safe_under_workdir(wdir, rel)
        if not dest:
            conflicts.append(f"{rel} (非法路径)")
            continue
        act = ch.get("action")
        if reverse:
            # Redo: apply turn's post-state
            expected_now = ch.get("pre_sha1") if act != "created" else None
            desired_sha1 = ch.get("post_sha1") if act != "deleted" else None
            desired_mode = ch.get("post_mode")
        else:
            # Undo: restore turn's pre-state
            expected_now = ch.get("post_sha1") if act != "deleted" else None
            desired_sha1 = ch.get("pre_sha1") if act != "created" else None
            desired_mode = ch.get("pre_mode")

        cur_sha1 = _file_sha1_if_exists(dest)
        if not force:
            if expected_now is None and os.path.exists(dest):
                conflicts.append(f"{rel} (本应不存在，但磁盘上已有文件)")
            elif expected_now is not None and cur_sha1 != expected_now:
                conflicts.append(f"{rel} (本轮之后被外部修改/删除)")

        targets.append((rel, dest, act, desired_sha1, desired_mode, cur_sha1))

    if conflicts and not force:
        return False, [], conflicts, []

    # Verify all required blobs exist before mutating disk
    for rel, _dest, _act, desired_sha1, _dmode, _csha1 in targets:
        if desired_sha1 and not os.path.isfile(_undo_blob_path(desired_sha1)):
            return False, [], [f"{rel} (缺失历史备份块 {desired_sha1[:8]})"], []

    applied = []
    for rel, dest, act, desired_sha1, desired_mode, _csha1 in targets:
        if desired_sha1 is None:
            if os.path.exists(dest):
                try:
                    os.remove(dest)
                    parent = os.path.dirname(dest)
                    rw = os.path.realpath(wdir)
                    while parent and parent.startswith(rw + os.sep):
                        try:
                            os.rmdir(parent)
                        except OSError:
                            break
                        parent = os.path.dirname(parent)
                    applied.append(("deleted", rel))
                except OSError as e:
                    return False, applied, [f"{rel}: {e}"], []
        else:
            existed_before = os.path.exists(dest)
            _write_blob_atomic(dest, desired_sha1, mode=desired_mode)
            applied.append(("restored" if existed_before else "recreated", rel))

    return True, applied, [], changes


# ---------------------------------------------------------------- core execution
def _acquire_session(scope_key, conv, mode, model, effort, project, workdir, force_new=False):
    skey = scope_key or PRIMARY_SCOPE_KEY
    to_close = []
    with session_lock:
        existing = _session_pool.get(skey)
        if not force_new and existing is not None and existing.matches(conv, mode, model, effort, project, workdir):
            return existing, True
        if existing is not None:
            _session_pool.pop(skey, None)
            to_close.append(existing)
        if conv:
            for k, s in list(_session_pool.items()):
                if k != skey and s.cid == conv and not (turn_running and turn_running_scope == k):
                    _session_pool.pop(k, None)
                    to_close.append(s)
                    log("Evicting duplicate warm session holding conv=%s from scope=%s" % (conv[:8], k))
        while len(_session_pool) >= MAX_WARM_SESSIONS:
            candidates = [
                (s.last_used, k, s) for k, s in _session_pool.items()
                if not (turn_running and k == turn_running_scope)
            ]
            if not candidates:
                break
            candidates.sort(key=lambda x: x[0])
            _, evict_k, evict_s = candidates[0]
            _session_pool.pop(evict_k, None)
            to_close.append(evict_s)
            log("Warm session pool cap (%d) reached; evicting LRU scope=%s" % (MAX_WARM_SESSIONS, evict_k))
        sess = AgySession(conv, mode, model, effort, project=project, workdir=workdir, scope_key=skey)
        _session_pool[skey] = sess
    for old in to_close:
        close_session_async(old, force=False)
    return sess, False


def _compute_workspace_diff_and_footer(
    result,
    before_files,
    started,
    model,
    effort,
    cid=None,
    turn_start_line=0,
    turn_tool_texts=None,
    step_text="",
    workdir=None,
):
    dur = time.time() - started
    denied = result.get("denied_actions") or []
    finished_reason = result.get("finished_reason")

    active_wdir = workdir or current_workdir()
    current_files = snapshot_workspace_files(workdir=active_wdir)
    raw_new_files = [
        os.path.relpath(fp, active_wdir)
        for fp, mtime in current_files.items()
        if fp not in before_files or mtime > before_files.get(fp, 0)
    ]

    # Avoid cross-bot footer/download leakage when a sibling bridge is simultaneously modifying WORKDIR
    if raw_new_files and _other_bridge_is_busy():
        _, _, turn_blob = _extract_turn_image_context(cid, turn_start_line, turn_tool_texts)
        ref_blob = (turn_blob or "") + "\n" + (step_text or "")
        new_files = [
            rel for rel in raw_new_files
            if (rel in ref_blob) or (os.path.basename(rel) in ref_blob)
        ]
    else:
        new_files = raw_new_files
    new_files.sort()

    reply_markup = None
    if new_files:
        buttons = [[{"text": f"📥 Download {fn}", "callback_data": f"get:{fn}"}] for fn in new_files[:3]]
        reply_markup = {"inline_keyboard": buttons}

    suffix = []
    if denied:
        suffix.append("🔒 Denied: " + ", ".join(d.get("action", "?") for d in denied) + " (/mode auto to approve)")
    if finished_reason == "print_timeout":
        suffix.append("⏰ Timeout reached (partial)")
    usage_str = format_usage_suffix(dur, (result.get("usage") or {}).get("total_tokens"),
                                    model=model, effort=effort)
    if usage_str:
        suffix.append(usage_str)
    if new_files:
        suffix.append("📁 Files: " + ", ".join(new_files[:5]))
    return " · ".join(suffix), reply_markup


def _sleep_interruptible(seconds):
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        if cancel_requested or shutting_down:
            return False
        time.sleep(min(0.2, max(0.01, deadline - time.time())))
    return not (cancel_requested or shutting_down)


def _execute_compact_on_session(scope_key, conv, mode, model, effort, project, workdir, instruction=""):
    """Run `/compact` on `conv` while `turn_running` is held. Auto-retries once on transient OAuth hiccup."""
    if not conv:
        return False, 0.0, "no active conversation"
    slash_cmd = "/compact" if not (instruction and instruction.strip()) else ("/compact " + instruction.strip())
    t0 = time.time()
    last_err = ""

    for attempt in (1, 2):
        if cancel_requested or shutting_down:
            return False, time.time() - t0, "cancelled"
        sess, reused_warm = _acquire_session(
            scope_key, conv, mode, model, effort, project, workdir, force_new=(attempt > 1)
        )
        try:
            sess.send_user_prompt(slash_cmd, raw_slash=True)
        except Exception as e:
            last_err = str(e)
            if reused_warm and attempt == 1:
                invalidate_session("compact_stdin_eof", force=True, scope_key=scope_key)
                continue
            return False, time.time() - t0, last_err

        res = None
        got_ev = False
        while not cancel_requested and not shutting_down:
            ev = sess.next_event(timeout=0.25)
            if ev is None:
                continue
            kind = ev.get("event")
            if kind == "__eof__":
                break
            if kind == "init":
                continue
            got_ev = True
            sess.last_used = time.time()
            if kind == "result":
                res = ev.get("result") or ev
                break

        if cancel_requested or shutting_down:
            invalidate_session("compact_cancelled", force=True, scope_key=scope_key)
            return False, time.time() - t0, "cancelled"

        if res is None and reused_warm and not got_ev and attempt == 1:
            invalidate_session("compact_warm_eof", force=True, scope_key=scope_key)
            continue

        if res is not None and (res.get("status") in (None, "SUCCESS")) and not res.get("error"):
            _last_compacted_line[conv] = get_transcript_line_count(conv)
            return True, time.time() - t0, ""

        last_err = str((res or {}).get("error") or (res or {}).get("response") or sess.get_stderr_text() or "compact failed")
        invalidate_session("compact_error", force=True, scope_key=scope_key)
        if attempt == 1 and is_transient_agy_error(last_err):
            log("Transient error during /compact (attempt 1/2): %s; retrying..." % last_err[:160])
            _sleep_interruptible(1.4 + random.uniform(0.15, 0.65))
            continue
        break

    return False, time.time() - t0, last_err


def _maybe_post_turn_auto_compact(chat_id, conv, mode, model, effort, project=None, workdir=None, thread_id=None, scope_key=None):
    """After a turn completes cleanly, proactively compact if active context crossed auto_compact_tokens."""
    if cancel_requested or shutting_down or not conv:
        return
    need_compact, before_stats = should_auto_compact(conv, scope_key=scope_key)
    if not need_compact:
        return

    sc = get_scope_state(scope_key)
    thresh = int(sc.get("auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS)
    before_k = format_tokens_k(before_stats["raw_ctx_tokens"])
    thresh_k = format_tokens_k(thresh)
    log("Post-turn auto-compact triggered for %s (%s >= %s)" % (conv[:8], before_k, thresh_k))

    c_streamer = LiveDraftStreamer(
        chat_id, time.time(), cid=conv, start_line=before_stats["total_lines"],
        enabled=(mode == "auto"), thread_id=thread_id,
    )
    c_streamer.set_status_override(
        f"🧹 <b>上下文已达 {before_k} (自动阈值 {thresh_k})，正在后台自动压缩 ({{elapsed}}s)...</b>"
    )
    c_streamer.start()
    try:
        ok, dur_s, err_str = _execute_compact_on_session(
            scope_key, conv, mode, model, effort, project, workdir
        )
    finally:
        c_streamer.stop()

    if cancel_requested or shutting_down:
        return
    if ok:
        after_stats = get_context_stats(conv)
        after_k = "~14k" if after_stats["just_compacted"] else format_tokens_k(after_stats["ctx_tokens"])
        msg_html = (
            f"🧹 <b>上下文已自动精简压缩</b>：<code>{before_k}</code> → 检查点摘要 "
            f"(<code>{after_k}</code> · {dur_s:.1f}s)"
        )
        tg_send_in_route("sendMessage", chat_id, thread_id=thread_id,
                          text=msg_html, parse_mode="HTML", disable_notification=True)
    else:
        log("Post-turn auto-compact failed for %s: %s" % (conv[:8], err_str[:200]))
        if mode == "auto" and chat_id and int(chat_id) > 0:
            tg_send_in_route("sendMessage", chat_id, thread_id=thread_id,
                             text="⚠️ <i>后台自动压缩暂遇波动，已跳过（不影响刚才回复，后续自动重试）</i>",
                             parse_mode="HTML", disable_notification=True)


def run_compact(chat_id, instruction="", thread_id=None, scope_key=None):
    """Execute explicit `/compact` job requested by user via command or button."""
    global turn_running, turn_running_scope, turn_running_chat, cancel_requested

    skey = scope_key or scope_key_for(chat_id, thread_id)
    sc = get_scope_state(skey)
    mode = sc.get("mode", "auto")
    model = sc.get("model")
    effort = sc.get("effort")
    conv = sc.get("conversation_id")
    project = current_project(skey)
    workdir = current_workdir(skey)

    if not conv:
        send(chat_id, "ℹ️ 当前没有活跃会话，无需压缩上下文。", thread_id=thread_id)
        return

    before_stats = get_context_stats(conv)
    before_k = format_tokens_k(before_stats["ctx_tokens"])

    with session_lock:
        turn_running = True
        turn_running_scope = skey
        turn_running_chat = chat_id
        cancel_requested = False

    c_streamer = LiveDraftStreamer(
        chat_id, time.time(), cid=conv, start_line=before_stats["total_lines"],
        enabled=True, thread_id=thread_id,
    )
    c_streamer.set_status_override(
        f"🧹 <b>正在压缩会话上下文 (当前 {before_k} · {{elapsed}}s)...</b>"
    )
    c_streamer.start()
    try:
        ok, dur_s, err_str = _execute_compact_on_session(
            skey, conv, mode, model, effort, project, workdir, instruction=instruction
        )
    finally:
        c_streamer.stop()
        recycle = None
        with session_lock:
            turn_running = False
            turn_running_scope = None
            turn_running_chat = None
            if skey in session_dirty_scopes and skey in _session_pool:
                recycle = _session_pool.pop(skey, None)
                session_dirty_scopes.discard(skey)
        if recycle is not None:
            close_session_async(recycle, force=False)

    if cancel_requested:
        send(chat_id, "🛑 已取消上下文压缩。", thread_id=thread_id)
        return
    if ok:
        after_stats = get_context_stats(conv)
        after_k = "~14k" if after_stats["just_compacted"] else format_tokens_k(after_stats["ctx_tokens"])
        note_line = f"\n• <b>保留侧重：</b><code>{html_mod.escape(instruction[:80])}</code>" if instruction else ""
        send(
            chat_id,
            f"✅ <b>上下文压缩完成</b>\n"
            f"• <b>会话：</b><code>{conv[:8]}</code>\n"
            f"• <b>压缩前：</b><code>{before_k}</code> (距上次压缩 {before_stats['steps_since_ckpt']} 步)\n"
            f"• <b>压缩后：</b>检查点摘要 (<code>{after_k}</code> · 累计第 {after_stats['checkpoints']} 次压缩)"
            f"{note_line}\n"
            f"• <b>耗时：</b><code>{dur_s:.1f}s</code>",
            parse_mode="HTML",
            thread_id=thread_id,
        )
    else:
        send(chat_id, "⚠️ 上下文压缩失败：%s" % (err_str or "(unknown error)"), thread_id=thread_id)


def _record_human_group_msg(msg, text_override=None):
    """Record a human group message into the shared Bot Bus ledger and anchor mention chains."""
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id or int(chat_id) >= 0:
        return ""
    frm = msg.get("from") or {}
    if frm.get("is_bot"):
        return ""
    txt = (text_override if text_override is not None else (msg.get("text") or msg.get("caption") or "")).strip()
    if not txt:
        return ""
    thread_id = _extract_thread_id(msg)
    msg_id = int(msg.get("message_id") or 0)
    sender = (frm.get("username") or frm.get("first_name") or "user").strip()
    bot_bus.record_group_message(
        int(chat_id),
        msg_id=msg_id,
        thread_id=thread_id,
        sender_handle=sender,
        sender_role="human",
        is_bot=False,
        text=txt,
        ts=msg.get("date"),
    )
    return bot_bus.mark_human_group_activity(int(chat_id), thread_id=thread_id, msg_id=msg_id) or ""


def _record_and_relay_bot_group_msg(
    chat_id,
    msg_id,
    thread_id,
    text,
    *,
    relay_mentions=True,
    source_hop=0,
    exclude_bots=None,
    mention_scan_text=None,
):
    """Record this bot's outbound group reply in the shared ledger and relay `@handle` mentions."""
    if not chat_id or int(chat_id) >= 0:
        return
    mid = int(msg_id or 0)
    if mid <= 0:
        return
    body = (text or "").strip()
    if not body:
        return
    my_handle = _current_bot_handle()
    my_role = _current_bot_role()
    norm_tid = _normalize_thread_id(thread_id)
    bot_bus.record_group_message(
        int(chat_id),
        msg_id=mid,
        thread_id=norm_tid,
        sender_handle=my_handle,
        sender_role=my_role,
        is_bot=True,
        text=body,
    )
    if relay_mentions:
        scan = mention_scan_text if mention_scan_text is not None else body
        max_hops = int(_current_bot_cfg().get("max_hops") or bot_bus.DEFAULT_MAX_HOPS)
        res = bot_bus.relay_group_mentions(
            my_handle,
            int(chat_id),
            scan,
            thread_id=norm_tid,
            msg_id=mid,
            source_hop=int(source_hop or 0),
            max_hops=max_hops,
            exclude_bots=exclude_bots,
        )
        if res.get("relayed"):
            log("Relayed group_mention from @%s -> %s (chat=%s, hop=%d)"
                % (my_handle, res["relayed"], chat_id, int(source_hop or 0) + 1))
        elif res.get("blocked_reason"):
            log("Blocked group_mention relay from @%s in chat=%s: %s"
                % (my_handle, chat_id, res["blocked_reason"]))


_HEAVY_TASK_KEYWORDS = (
    "修改", "改一下", "改代码", "修复", "实现", "编写", "重构", "提交", "部署",
    "同步", "发布", "发版", "跑单测", "跑测试", "运行测试", "删除", "写入", "编辑",
    "创建文件", "执行脚本", "commit", "push", "deploy", "sync-public", "refactor",
    "implement", "patch", "edit ", "write ", "delete ", "run test", "pytest", "unittest",
)

_FAST_CHAT_HINTS = (
    "?", "？", "进度", "怎么样", "到哪", "好了吗", "多久", "在吗", "怎么看",
    "为什么", "什么", "哪个", "是否", "是不是", "能否", "可以吗", "对吗",
    "怎么", "如何", "确认", "解释", "聊聊", "讨论", "意见", "建议", "收到",
    "辛苦", "谢谢", "status", "progress", "why", "what", "how", "which",
)


def _is_fast_chat_candidate(text, *, has_media=False, is_mention=False):
    """Conservative classifier for read-only fast group replies while the main worker is busy."""
    if has_media:
        return False
    cleaned = (text or "").strip()
    if not cleaned or cleaned.startswith("/") or len(cleaned) > 320:
        return False
    low = cleaned.lower()
    if any(kw in low for kw in _HEAVY_TASK_KEYWORDS):
        return False
    if is_mention:
        return True
    return any(hint in low for hint in _FAST_CHAT_HINTS)


def _describe_active_busy_task():
    """Return `(busy, task_label, pending_count)` safely under `session_lock`."""
    with session_lock:
        busy = bool(turn_running)
        active_jid = _active_bus_job_id
        active_scope = turn_running_scope
        active_chat = turn_running_chat
    pending = job_q.qsize()
    if not busy:
        return False, "", pending
    if active_jid:
        job = bot_bus.get_job(active_jid) or {}
        origin_cid = int(job.get("origin_chat_id") or 0)
        if not origin_cid and job.get("origin_scope_key"):
            parsed_cid, _ = parse_scope_key(job.get("origin_scope_key"))
            origin_cid = int(parsed_cid or 0)
        if origin_cid > 0 or (origin_cid == 0 and active_chat and int(active_chat) > 0):
            return True, "后台私聊任务（已隔离上下文）", pending
        lbl = (job.get("label") or "").strip()
        desc = f"【{lbl}】（单号 {active_jid}）" if lbl else f"派单 {active_jid}"
        return True, desc, pending
    if active_scope:
        sc_cid, _ = parse_scope_key(active_scope)
        if (sc_cid and int(sc_cid) > 0) or (active_chat and int(active_chat) > 0):
            return True, "后台私聊任务（已隔离上下文）", pending
        return True, f"会话 {active_scope}", pending
    if active_chat and int(active_chat) > 0:
        return True, "后台私聊任务（已隔离上下文）", pending
    return True, "上一条任务", pending


def _run_fast_group_reply(
    chat_id,
    prompt_text,
    *,
    thread_id=None,
    scope_key=None,
    origin_msg_id=0,
    mention_hop=0,
    busy_desc="",
):
    """Isolated read-only fast-reply lane that never mutates `turn_running`, `state`, or `undo`."""
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    my_handle = _current_bot_handle()
    try:
        with state_lock:
            sc = _ensure_scope_locked(skey)
            model = sc.get("model")
            project = sc.get("project") or None
            wdir_raw = sc.get("workdir")
        fast_workdir = WORKDIR
        if wdir_raw:
            rw = os.path.realpath(os.path.expanduser(wdir_raw))
            if os.path.isdir(rw):
                fast_workdir = rw
        cfg = _current_bot_cfg()
        exec_model = model or cfg.get("default_model") or None
        history_block = bot_bus.format_unseen_group_history(
            chat_id,
            my_handle,
            thread_id=norm_tid,
            exclude_msg_id=origin_msg_id,
            limit=12,
            advance_cursor=True,
        )
        history_section = f"{history_block}\n\n" if history_block else ""
        fast_prompt = (
            f"[ACB_FAST_GROUP_CHAT bot=@{my_handle}]\n"
            f"你当前正在后台串行执行耗时任务（{busy_desc or '进行中'}），现在通过【只读快答旁路】响应群内的一条简短提问/点名。\n"
            f"- 严禁修改任何工作区文件或执行写入/提交/部署命令（当前为只读安全模式）。\n"
            f"- 请用 1~4 句自然、清晰的中文直接回答或同步当前进度；若需要改动代码或重任务，请说明会在后台任务结束后立即处理。\n\n"
            f"{history_section}"
            f"当前群消息：\n{prompt_text}"
        )
        cmd = [
            AGY_BIN,
            "--input-format", "text",
            "--output-format", "json",
            "--disable-slash-commands",
            "--print-timeout", "45s",
        ]
        if exec_model:
            cmd += ["--model", exec_model]
        if project:
            cmd += ["--project", project]
        cmd += ["-p", fast_prompt]

        env = dict(os.environ)
        env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
        env.setdefault("HOME", HOME)
        env["AGY_BOT_BUS_ENABLE"] = "0"
        env["AGY_INTERNAL_OBSERVER"] = "1"

        rc, raw_out, raw_err = _run_subprocess_group(
            cmd,
            cwd=fast_workdir,
            timeout_s=50,
            env=env,
            shell=False,
        )
        reply_text = ""
        raw_out = (raw_out or "").strip()
        if raw_out:
            try:
                parsed = json.loads(raw_out)
            except Exception:
                brace = raw_out.find("{")
                try:
                    parsed = json.loads(raw_out[brace:]) if brace >= 0 else None
                except Exception:
                    parsed = None
            if isinstance(parsed, dict):
                reply_text = (parsed.get("response") or "").strip()
            else:
                reply_text = raw_out
        if not reply_text:
            reply_text = (
                f"⏳ 我这边正在处理 {busy_desc or '后台任务'}（刚才快答通道未返回完整文本，stderr rc={rc}），"
                f"如需代码修改或详细排查可以再告诉我，我完成后马上跟进。"
            )
        sent_mid, _ = send_rich(
            chat_id,
            reply_text,
            thread_id=norm_tid,
            reply_to_message_id=origin_msg_id or None,
        )
        if sent_mid:
            _record_and_relay_bot_group_msg(
                chat_id,
                sent_mid,
                norm_tid,
                reply_text,
                relay_mentions=True,
                source_hop=mention_hop,
            )
    except Exception as e:
        log("fast_group_reply error: %r" % e)
        send(
            chat_id,
            f"⏳ 我手头正在跑 {busy_desc or '后台任务'}，刚才快答遇到小波动（{type(e).__name__}），请稍候或再 @ 我一次。",
            thread_id=norm_tid,
            reply_to_message_id=origin_msg_id or None,
        )
    finally:
        _fast_chat_sem.release()


def run_agy(chat_id, prompt, thread_id=None, scope_key=None, origin_msg_id=0, mention_hop=0, chain_id=""):
    global turn_running, turn_running_scope, turn_running_chat, cancel_requested

    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    bot_bus.set_origin_context(
        skey,
        bot_handle=_current_bot_handle(),
        chat_id=chat_id,
        thread_id=norm_tid,
        msg_id=origin_msg_id,
        mention_hop=mention_hop,
        chain_id=chain_id,
    )

    with state_lock:
        sc = _ensure_scope_locked(skey)
        mode = sc.get("mode", "auto")
        model = sc.get("model")
        effort = sc.get("effort")
        conv = sc.get("conversation_id")
        show_thinking = sc.get("thinking", True)
        project = sc.get("project") or None
        wdir_raw = sc.get("workdir")
        undo_notice = sc.get("pending_undo_notice")
        sc["pending_undo_notice"] = None

    workdir = WORKDIR
    if wdir_raw:
        rw = os.path.realpath(os.path.expanduser(wdir_raw))
        if os.path.isdir(rw):
            workdir = rw

    base_prompt = prompt
    prompt_parts = []
    if undo_notice:
        prompt_parts.append(undo_notice)
    if chat_id and int(chat_id) < 0 and not (prompt or "").lstrip().startswith("/"):
        history_block = bot_bus.format_unseen_group_history(
            int(chat_id),
            _current_bot_handle(),
            thread_id=norm_tid,
            exclude_msg_id=int(origin_msg_id or 0),
            limit=15,
            advance_cursor=True,
        )
        if history_block:
            prompt_parts.append(history_block)
    prompt_parts.append(prompt)
    effective_prompt = "\n\n".join(prompt_parts)

    before_files = snapshot_workspace_files(workdir=workdir)
    undo_manifest = snapshot_undo_manifest(workdir)
    segment_start_line = get_transcript_line_count(conv)
    started = time.time()

    with session_lock:
        turn_running = True
        turn_running_scope = skey
        turn_running_chat = chat_id
        cancel_requested = False

    update_scope_state(
        skey,
        in_flight={
            "chat_id": chat_id,
            "thread_id": norm_tid,
            "scope_key": skey,
            "prompt": base_prompt,
            "started_at": int(started),
            "conv": conv,
            "last_delivered_text": None,
        },
        last_turn={
            "prompt": base_prompt,
            "display": base_prompt[:120],
            "started_at": int(started),
            "status": "RUNNING",
            "conv": conv,
        },
    )
    save_state()

    # Start instant native sendMessageDraft ("Thinking…" at t=0.00s!) BEFORE even spawning/writing to agy!
    streamer = LiveDraftStreamer(
        chat_id, started, cid=conv, start_line=segment_start_line,
        enabled=(mode == "auto"), thread_id=norm_tid,
    )
    streamer.start()

    sent_images = {}  # realpath -> last_sent_mtime
    turn_start_line = segment_start_line
    turn_tool_texts = []
    last_live_img_scan = time.time()
    delivered_steps = 0
    last_msg_info = (None, None)
    step_buffers = {}
    active_step_idx = None
    coalesced_final_delivered = False
    retry_kb = {"inline_keyboard": [[{"text": "🔁 重试上一轮 (/retry)", "callback_data": "action:retry"}]]}

    try:
        # Pre-turn guard: if resuming a heavy session already >= auto_compact_tokens, compact cleanly first!
        if conv:
            pre_need, pre_stats = should_auto_compact(conv, scope_key=skey)
            if pre_need and not cancel_requested and not shutting_down:
                pre_k = format_tokens_k(pre_stats["raw_ctx_tokens"])
                log("Pre-turn auto-compact triggered for %s (%s)" % (conv[:8], pre_k))
                streamer.set_status_override(
                    f"🧹 <b>当前会话上下文较大 ({pre_k})，正在先自动压缩防超限 ({{elapsed}}s)...</b>"
                )
                _execute_compact_on_session(skey, conv, mode, model, effort, project, workdir)
                streamer.set_status_override(None)
                segment_start_line = get_transcript_line_count(conv)
                turn_start_line = segment_start_line
                streamer.start_line = segment_start_line

        max_attempts = 3
        attempt = 0
        result = None
        sess = None
        while attempt < max_attempts:
            attempt += 1
            attempt_tools = 0
            sess, reused_warm = _acquire_session(
                skey, conv, mode, model, effort, project, workdir, force_new=(attempt > 1)
            )
            if sess.cid and sess.cid != conv:
                conv = sess.cid
                streamer.set_cid(conv)
            try:
                sess.send_user_prompt(effective_prompt)
            except Exception as e:
                log("send_user_prompt failed (reused_warm=%s, attempt=%d): %s" % (reused_warm, attempt, e))
                if reused_warm and attempt == 1 and not cancel_requested and not shutting_down:
                    invalidate_session("stdin_broken_pipe", force=True, scope_key=skey)
                    continue
                raise

            got_turn_event = False
            while not cancel_requested and not shutting_down:
                ev = sess.next_event(timeout=0.25)
                if (time.time() - last_live_img_scan) >= 2.0:
                    last_live_img_scan = time.time()
                    push_step_images(
                        chat_id, "", conv, started, before_files, sent_images,
                        live_watch=True, turn_tool_texts=turn_tool_texts, turn_start_line=turn_start_line,
                        thread_id=norm_tid, workdir=workdir,
                    )
                if ev is None:
                    continue

                kind = ev.get("event")
                if kind == "__eof__":
                    break

                if kind == "init":
                    cid = ev.get("conversation_id")
                    if cid:
                        sess.cid = cid
                        conv = cid
                        with state_lock:
                            sc = _ensure_scope_locked(skey)
                            sc["conversation_id"] = cid
                            if isinstance(sc.get("in_flight"), dict):
                                sc["in_flight"]["conv"] = cid
                            if isinstance(sc.get("last_turn"), dict):
                                sc["last_turn"]["conv"] = cid
                        save_state()
                        streamer.set_cid(cid)
                    continue

                got_turn_event = True
                sess.last_used = time.time()

                if kind == "step_update":
                    su = ev.get("step_update") or {}
                    st = su.get("step_type")
                    state_kind = su.get("state")
                    step_idx = su.get("step_index", 0)

                    th_delta = su.get("thinking_delta") or su.get("thinking")
                    if th_delta:
                        streamer.on_thinking(th_delta)

                    if st == "tool":
                        tinfo = su.get("tool_info")
                        tname = su.get("tool_name") or ""
                        if tname or tinfo:
                            try:
                                turn_tool_texts.append(
                                    tname + " " + json.dumps(tinfo or {}, ensure_ascii=False)[:4000]
                                )
                            except Exception:
                                pass
                        if state_kind == "ACTIVE":
                            attempt_tools += 1
                            streamer.on_tool_start(tname, tinfo)
                        elif state_kind == "DONE":
                            streamer.on_tool_done(tname, tinfo, su.get("duration_seconds"))

                    elif st == "checkpoint":
                        if state_kind == "ACTIVE":
                            streamer.on_tool_start("context_compaction", {})
                        elif state_kind == "DONE":
                            streamer.on_tool_done("context_compaction", {}, su.get("duration_seconds"))
                            if conv:
                                _last_compacted_line[conv] = get_transcript_line_count(conv)

                    elif st == "agent_response":
                        delta = su.get("text_delta") or ""
                        if delta:
                            step_buffers[step_idx] = step_buffers.get(step_idx, "") + delta
                        cur_text = step_buffers.get(step_idx, "")

                        if state_kind == "ACTIVE":
                            if cur_text.strip():
                                active_step_idx = step_idx
                                streamer.on_text_delta(cur_text)

                        elif state_kind == "DONE":
                            if active_step_idx == step_idx:
                                active_step_idx = None
                            final_step_text = cur_text.strip()
                            if not final_step_text:
                                continue

                            cur_cid = conv or get_scope_value(skey, "conversation_id")
                            th_list, tc_list, new_end_line = get_turn_details(cur_cid, segment_start_line)
                            segment_start_line = new_end_line
                            header_html = build_thinking_header(th_list, tc_list) if show_thinking else None

                            # Peek up to 65ms: if `result` is right behind DONE, coalesce into ONE single sendMessage!
                            imm_res, _ = sess.peek_immediate_result(timeout=0.065)
                            if imm_res is not None and imm_res.get("status") == "SUCCESS":
                                result = imm_res
                                footer_str, reply_markup = _compute_workspace_diff_and_footer(
                                    result, before_files, started, model, effort,
                                    cid=cur_cid, turn_start_line=turn_start_line,
                                    turn_tool_texts=turn_tool_texts, step_text=final_step_text,
                                    workdir=workdir,
                                )
                                last_msg_info = streamer.finalize_step(
                                    final_step_text, header_html=header_html,
                                    footer_str=footer_str, reply_markup=reply_markup,
                                )
                                if last_msg_info[0]:
                                    _record_and_relay_bot_group_msg(
                                        chat_id,
                                        last_msg_info[0],
                                        norm_tid,
                                        final_step_text,
                                        relay_mentions=True,
                                        source_hop=mention_hop,
                                    )
                                delivered_steps += 1
                                coalesced_final_delivered = True
                                push_step_images(
                                    chat_id, final_step_text, cur_cid, started, before_files, sent_images,
                                    turn_tool_texts=turn_tool_texts, turn_start_line=turn_start_line,
                                    thread_id=norm_tid, workdir=workdir,
                                )
                                break
                            else:
                                # Intermediate step (e.g. QR code / milestone while background task runs)!
                                last_msg_info = streamer.finalize_step(final_step_text, header_html=header_html)
                                if last_msg_info[0]:
                                    _record_and_relay_bot_group_msg(
                                        chat_id,
                                        last_msg_info[0],
                                        norm_tid,
                                        final_step_text,
                                        relay_mentions=True,
                                        source_hop=mention_hop,
                                    )
                                delivered_steps += 1
                                with state_lock:
                                    sc = _ensure_scope_locked(skey)
                                    if isinstance(sc.get("in_flight"), dict):
                                        sc["in_flight"]["last_delivered_text"] = final_step_text
                                save_state()
                                push_step_images(
                                    chat_id, final_step_text, cur_cid, started, before_files, sent_images,
                                    turn_tool_texts=turn_tool_texts, turn_start_line=turn_start_line,
                                    thread_id=norm_tid, workdir=workdir,
                                )
                                if imm_res is not None:
                                    # Non-SUCCESS terminal result (e.g. WAITING / ERROR)
                                    result = imm_res
                                    break
                                streamer.start_next_segment(segment_start_line)

                elif kind == "result":
                    result = ev.get("result") or ev
                    break

            if cancel_requested or shutting_down:
                break
            if result is not None and result.get("status") != "ERROR":
                break
            if result is None and reused_warm and not got_turn_event and attempt == 1:
                log("Warm AgySession hit EOF before turn started; respawning fresh session...")
                invalidate_session("warm_eof", force=True, scope_key=skey)
                continue

            # Self-healing retry for transient OAuth2 / pre-invocation context summarization failures!
            if attempt < max_attempts and delivered_steps == 0 and attempt_tools == 0:
                err_candidate = ""
                if result is not None and result.get("status") == "ERROR":
                    err_candidate = str(result.get("error") or result.get("response") or "")
                elif result is None and sess is not None:
                    err_candidate = sess.get_stderr_text()

                if is_transient_agy_error(err_candidate):
                    log("Transient agy error on attempt %d/%d (%s); auto-recovering..."
                        % (attempt, max_attempts, err_candidate[:200]))
                    invalidate_session("transient_error_retry", force=True, scope_key=skey)
                    wait_s = 1.3 * attempt + random.uniform(0.15, 0.75)
                    streamer.set_status_override(
                        f"🔄 <b>检测到上游凭证/预压缩瞬时波动，正在自动恢复重试 ({attempt}/{max_attempts - 1} · {{elapsed}}s)...</b>"
                    )
                    if not _sleep_interruptible(wait_s):
                        break
                    if is_summarization_error(err_candidate) and conv:
                        streamer.set_status_override(
                            f"🧹 <b>正在用新凭证压缩上下文后重试 ({attempt}/{max_attempts - 1} · {{elapsed}}s)...</b>"
                        )
                        _execute_compact_on_session(skey, conv, mode, model, effort, project, workdir)
                    streamer.set_status_override(None)
                    step_buffers.clear()
                    turn_tool_texts.clear()
                    active_step_idx = None
                    segment_start_line = get_transcript_line_count(conv)
                    turn_start_line = segment_start_line
                    streamer.start_line = segment_start_line
                    result = None
                    continue

            break

        streamer.stop()

        if result is None:
            invalidate_session("eof_or_cancel", force=True, scope_key=skey)
            with state_lock:
                sc = _ensure_scope_locked(skey)
                if isinstance(sc.get("last_turn"), dict):
                    sc["last_turn"]["status"] = "CANCELLED" if cancel_requested else "ERROR"
            partial = (step_buffers.get(active_step_idx, "") if active_step_idx is not None else "").strip()
            if cancel_requested:
                if partial:
                    send_rich(chat_id, partial + "\n\n*🛑 [已手动停止生成]*",
                              reply_markup=retry_kb, thread_id=norm_tid)
            elif sess and sess.proc.returncode in (-15, 143, -2, 130):
                if partial:
                    send_rich(chat_id, partial + "\n\n*🛑 [任务已中断]*",
                              reply_markup=retry_kb, thread_id=norm_tid)
                else:
                    send(chat_id, "🛑 Task cancelled.", reply_markup=retry_kb, thread_id=norm_tid)
            else:
                rc = sess.proc.returncode if sess else "?"
                err = sess.get_stderr_text() if sess else ""
                send(chat_id, "⚠️ agy produced no result (exit %s)\n%s" % (rc, err),
                     reply_markup=retry_kb, thread_id=norm_tid)
            return

        res_cid = result.get("conversation_id")
        if res_cid:
            conv = res_cid
            if sess:
                sess.cid = res_cid
            with state_lock:
                sc = _ensure_scope_locked(skey)
                sc["conversation_id"] = res_cid
                if isinstance(sc.get("last_turn"), dict):
                    sc["last_turn"]["conv"] = res_cid
            save_state()

        # If final step + footer + images were already delivered atomically via 65ms lookahead, check post-turn auto-compact!
        if coalesced_final_delivered:
            with state_lock:
                sc = _ensure_scope_locked(skey)
                if isinstance(sc.get("last_turn"), dict):
                    sc["last_turn"]["status"] = "SUCCESS"
            push_step_images(
                chat_id, "", conv, started, before_files, sent_images,
                turn_tool_texts=turn_tool_texts, turn_start_line=turn_start_line,
                thread_id=norm_tid, workdir=workdir,
            )
            _maybe_post_turn_auto_compact(
                chat_id, conv, mode, model, effort,
                project=project, workdir=workdir, thread_id=norm_tid, scope_key=skey,
            )
            return

        status = result.get("status")
        finished_reason = result.get("finished_reason")
        resp = (result.get("response") or "").strip()
        with state_lock:
            sc = _ensure_scope_locked(skey)
            if isinstance(sc.get("last_turn"), dict):
                sc["last_turn"]["status"] = status or "UNKNOWN"

        footer_str, reply_markup = _compute_workspace_diff_and_footer(
            result, before_files, started, model, effort,
            cid=conv, turn_start_line=turn_start_line,
            turn_tool_texts=turn_tool_texts, step_text=resp,
            workdir=workdir,
        )
        push_step_images(
            chat_id, resp, conv, started, before_files, sent_images,
            turn_tool_texts=turn_tool_texts, turn_start_line=turn_start_line,
            thread_id=norm_tid, workdir=workdir,
        )

        if status == "SUCCESS":
            if delivered_steps > 0:
                last_mid, last_html = last_msg_info
                attached = False
                if footer_str and last_mid and last_html:
                    footer_html = "\n\n" + html_mod.escape(footer_str)
                    if len(last_html) + len(footer_html) <= 4090:
                        kw = {
                            "chat_id": chat_id,
                            "message_id": last_mid,
                            "text": last_html + footer_html,
                            "parse_mode": "HTML",
                            "link_preview_options": {"is_disabled": True},
                        }
                        if reply_markup:
                            kw["reply_markup"] = reply_markup
                        r = tg("editMessageText", **kw)
                        if _tg_ok(r):
                            attached = True
                if not attached and (footer_str or reply_markup):
                    kw = {
                        "text": html_mod.escape(footer_str or "✓ Done"),
                        "parse_mode": "HTML",
                        "disable_notification": True,
                    }
                    if reply_markup:
                        kw["reply_markup"] = reply_markup
                    tg_send_in_route("sendMessage", chat_id, thread_id=norm_tid, **kw)
            else:
                header_html = None
                if show_thinking:
                    th_list, tc_list, _ = get_turn_details(conv, segment_start_line)
                    header_html = build_thinking_header(th_list, tc_list)
                out = resp or "(agy finished without a text response)"
                sent_info = send_rich(chat_id, out, header_html=header_html,
                          footer_str=footer_str, reply_markup=reply_markup, thread_id=norm_tid)
                if sent_info[0]:
                    _record_and_relay_bot_group_msg(
                        chat_id,
                        sent_info[0],
                        norm_tid,
                        out,
                        relay_mentions=True,
                        source_hop=mention_hop,
                    )
            _maybe_post_turn_auto_compact(
                chat_id, conv, mode, model, effort,
                project=project, workdir=workdir, thread_id=norm_tid, scope_key=skey,
            )

        elif status == "WAITING":
            if delivered_steps > 0:
                send(chat_id, "⏸ agy 正在等待您的输入或确认 — 直接回复即可继续当前会话。", thread_id=norm_tid)
            else:
                send(chat_id, "⏸ agy is waiting on input/permission:\n" + (resp or "(no details)")
                     + "\n\nReply directly — I'll continue the session with your reply.", thread_id=norm_tid)
        else:
            if finished_reason == "interrupted" or cancel_requested:
                if not cancel_requested:
                    send(chat_id, "🛑 Task cancelled.", reply_markup=retry_kb, thread_id=norm_tid)
            else:
                send(chat_id, "⚠️ agy %s: %s" % (status, result.get("error") or resp or "(no details)"),
                     reply_markup=retry_kb, thread_id=norm_tid)

    finally:
        streamer.stop()
        try:
            changed_cnt = finalize_turn_undo(skey, workdir, undo_manifest, base_prompt, conv)
            if changed_cnt:
                log("Recorded undo checkpoint (%d changed file(s)) for scope=%s" % (changed_cnt, skey))
        except Exception as ue:
            log("finalize_turn_undo error: %r" % ue)
        recycle = None
        with session_lock:
            turn_running = False
            turn_running_scope = None
            turn_running_chat = None
            if skey in session_dirty_scopes and skey in _session_pool:
                recycle = _session_pool.pop(skey, None)
                session_dirty_scopes.discard(skey)
        if recycle is not None:
            close_session_async(recycle, force=False)
        update_scope_state(skey, in_flight=None)
        save_state()


def perform_hot_reload(notify_chat_id=None, notify_thread_id=None):
    log("Executing graceful hot reload via execv...")
    if notify_chat_id:
        send(notify_chat_id, "🔄 正在热重载桥接服务...", thread_id=notify_thread_id)
    close_all_sessions_sync()
    time.sleep(0.3)
    os.execv(sys.executable, [sys.executable] + sys.argv)


SCHEDULED_CIDS_LOCK = "/tmp/agy_scheduled_cids.lock"


def _load_scheduled_cids():
    if os.path.isfile(SCHEDULED_CIDS_FILE):
        try:
            with open(SCHEDULED_CIDS_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f) or [])
        except Exception:
            pass
    return set()


def _record_scheduled_cid(cid):
    if not cid:
        return
    try:
        os.makedirs(os.path.dirname(SCHEDULED_CIDS_FILE), exist_ok=True)
        with open(SCHEDULED_CIDS_LOCK, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                ordered = []
                if os.path.isfile(SCHEDULED_CIDS_FILE):
                    try:
                        with open(SCHEDULED_CIDS_FILE, "r", encoding="utf-8") as rf:
                            raw_list = json.load(rf) or []
                        if isinstance(raw_list, list):
                            ordered = [str(x) for x in raw_list if x]
                    except Exception:
                        ordered = []
                if cid not in ordered:
                    ordered.append(cid)
                ordered = ordered[-2000:]
                tmp = f"{SCHEDULED_CIDS_FILE}.{os.getpid()}.tmp"
                with open(tmp, "w", encoding="utf-8") as wf:
                    json.dump(ordered, wf)
                os.replace(tmp, SCHEDULED_CIDS_FILE)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        log("record_scheduled_cid error: %r" % e)


def _run_subprocess_group(cmd_or_str, cwd, timeout_s, env=None, shell=False):
    """Run subprocess in its own session/process-group so timeouts never leave orphan child processes."""
    proc = subprocess.Popen(
        cmd_or_str,
        shell=shell,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout_s)
        return proc.returncode, out or "", err or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            proc.kill()
        out, err = proc.communicate()
        raise TimeoutError(f"执行超时 (> {timeout_s}s)")


def _is_silent_scheduled_reply(text):
    s = (text or "").strip()
    if not s:
        return True
    return bool(re.fullmatch(r"[\s`*_]*\[(?:SILENT|NO_REPLY|NO_OUTPUT)\][\s`*_.]*", s, re.IGNORECASE))


def execute_scheduled_task(task):
    tid = task.get("id")
    tname = task.get("name") or tid
    ttype = task.get("task_type") or "agent"
    payload = task.get("payload") or {}
    exec_cfg = task.get("execution") or {}
    deliv_cfg = task.get("delivery") or {}
    target_chat = deliv_cfg.get("target_chat_id")
    target_thread = _normalize_thread_id(deliv_cfg.get("target_thread_id"))
    if not target_chat and ALLOWED:
        target_chat = PRIMARY_CHAT_ID or next(iter(ALLOWED))

    if not target_chat:
        log("Scheduled task %s skipped: no target chat id" % tid)
        scheduler.task_mgr.record_completion(tid, "failed", error="No target chat id")
        return

    task_scope = scope_key_for(target_chat, target_thread)
    exec_workdir = exec_cfg.get("workdir") or current_workdir(task_scope) or WORKDIR
    if not os.path.isdir(exec_workdir):
        exec_workdir = WORKDIR

    log("Executing scheduled task %s (%s, type=%s, cwd=%s, chat=%s, thread=%s)"
        % (tid, tname, ttype, exec_workdir, target_chat, target_thread))
    try:
        if ttype == "cost_report":
            c_view = payload.get("view", "overview")
            c_scope = payload.get("scope", "all")
            panel_text, panel_kb = build_cost_panel(view=c_view, scope=c_scope, scope_key=task_scope)
            header = f"⏰ <b>[定时报表] {html_mod.escape(tname)}</b>\n\n"
            send(target_chat, header + panel_text, parse_mode="HTML", reply_markup=panel_kb, thread_id=target_thread)
            scheduler.task_mgr.record_completion(tid, "success", last_snippet="Cost report delivered")

        elif ttype == "usage_report":
            panel_text, panel_kb = build_usage_panel(force_live=True)
            header = f"⏰ <b>[定时报表] {html_mod.escape(tname)}</b>\n\n"
            send(target_chat, header + panel_text, parse_mode="HTML", reply_markup=panel_kb, thread_id=target_thread)
            scheduler.task_mgr.record_completion(tid, "success", last_snippet="Plan usage report delivered")

        elif ttype == "script":
            script_cmd = payload.get("script") or payload.get("command")
            if not script_cmd:
                raise ValueError("No script/command provided")
            timeout_s = int(exec_cfg.get("timeout_secs") or 180)
            env = dict(os.environ)
            env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
            env.setdefault("HOME", HOME)
            rc, raw_out, raw_err = _run_subprocess_group(
                script_cmd,
                cwd=exec_workdir,
                timeout_s=timeout_s,
                env=env,
                shell=True,
            )
            out = raw_out.strip()
            err = raw_err.strip()
            if rc != 0:
                err_msg = f"Script exited with {rc}: {err or out}"
                scheduler.task_mgr.record_completion(tid, "failed", error=err_msg, last_snippet=err_msg)
                if deliv_cfg.get("notify_on_failure", True):
                    send(target_chat,
                         f"⚠️ ⏰ <b>[{html_mod.escape(tname)}] 执行失败</b>\n\n<pre>{html_mod.escape(err_msg[:1000])}</pre>",
                         parse_mode="HTML", thread_id=target_thread)
            else:
                combined = out or err or "[NO_OUTPUT]"
                scheduler.task_mgr.record_completion(tid, "success", last_snippet=combined[:300])
                is_silent = deliv_cfg.get("silent_if_empty", True) and (not out or _is_silent_scheduled_reply(combined))
                if not is_silent:
                    send(target_chat,
                         f"⏰ <b>[{html_mod.escape(tname)}]</b>\n\n<pre>{html_mod.escape(combined[:3500])}</pre>",
                         parse_mode="HTML", thread_id=target_thread)

        elif ttype in ("agent", "browser"):
            prompt = (payload.get("prompt") or "").strip()
            if not prompt:
                raise ValueError("No prompt provided for agent task")
            model = exec_cfg.get("model") or "gemini-3.8-flash-low"
            project = exec_cfg.get("project") or current_project(task_scope) or "agy-cli-bot"
            timeout_s = int(exec_cfg.get("timeout_secs") or (300 if ttype == "browser" else 240))
            silent_enabled = bool(deliv_cfg.get("silent_if_empty", True))

            silent_instruction = (
                "若本次检查没有任何新邮件/新异常/需要汇报的内容，请仅回复 `[SILENT]`（不要输出多余文字），系统将自动静默不打扰用户。"
                if silent_enabled
                else "请直接、简明地汇报本次定时任务的检查或执行结果。"
            )
            profile_hint = f" ({AGY_BROWSER_PROFILE_LABEL})" if AGY_BROWSER_PROFILE_LABEL else ""
            media_instruction = (
                f"\n- 当前为浏览器定时任务：涉及 Google 相关站点时必须严格遵循 `google-profile`{profile_hint} (持久化目录 + flock 锁 + 主机直连)；如需向 Telegram 发送截图或二维码，请将图片写入 `{BOT_OUTBOX_DIR}/`。"
                if ttype == "browser"
                else f"\n- 如需向 Telegram 附带推送图片/截图，请写入 `{BOT_OUTBOX_DIR}/`。"
            )
            full_prompt = (
                f"[ACB_SCHEDULED_TASK id={tid} type={ttype}]\n"
                f"你正在后台无人值守执行定时任务「{tname}」，当前无人工实时交互，请勿向用户提问，直接完成任务。\n"
                f"- {silent_instruction}"
                f"{media_instruction}\n\n"
                f"任务内容：\n{prompt}"
            )

            started_ts = time.time()
            before_files = snapshot_workspace_files(workdir=exec_workdir)

            cmd = [
                AGY_BIN,
                "--input-format", "text",
                "--output-format", "json",
                "--dangerously-skip-permissions",
                "--print-timeout", f"{timeout_s}s",
                "-p", full_prompt,
            ]
            if model:
                cmd += ["--model", model]
            if project:
                cmd += ["--project", project]

            env = dict(os.environ)
            env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
            env.setdefault("HOME", HOME)
            env["AGY_OUTBOX_DIR"] = BOT_OUTBOX_DIR
            env["AGY_BOT_BUS_ENABLE"] = "0"
            if not payload.get("use_memory"):
                env["AGY_INTERNAL_OBSERVER"] = "1"

            rc, raw_out, raw_err = _run_subprocess_group(
                cmd,
                cwd=exec_workdir,
                timeout_s=timeout_s + 20,
                env=env,
                shell=False,
            )
            raw_out = raw_out.strip()
            err = raw_err.strip()

            resp_text = ""
            new_cid = None
            if raw_out:
                parsed_json = None
                try:
                    parsed_json = json.loads(raw_out)
                except Exception:
                    brace_idx = raw_out.find("{")
                    if brace_idx >= 0:
                        try:
                            parsed_json = json.loads(raw_out[brace_idx:])
                        except Exception:
                            parsed_json = None
                if isinstance(parsed_json, dict):
                    resp_text = parsed_json.get("response") or ""
                    new_cid = parsed_json.get("conversation_id")
                else:
                    resp_text = raw_out

            if new_cid:
                _record_scheduled_cid(new_cid)

            if rc != 0 and not resp_text:
                err_msg = f"Agent failed ({rc}): {err}"
                scheduler.task_mgr.record_completion(tid, "failed", error=err_msg)
                if deliv_cfg.get("notify_on_failure", True):
                    send(target_chat,
                         f"⚠️ ⏰ <b>[{html_mod.escape(tname)}] 运行失败</b>\n\n<pre>{html_mod.escape(err_msg[:1000])}</pre>",
                         parse_mode="HTML", thread_id=target_thread)
            else:
                final_text = resp_text or err or "[NO_OUTPUT]"
                scheduler.task_mgr.record_completion(tid, "success", last_snippet=final_text[:300])
                is_silent = silent_enabled and _is_silent_scheduled_reply(final_text)
                if not is_silent:
                    prefix_html = f"⏰ <b>[{html_mod.escape(tname)}]</b>\n\n"
                    send_rich(target_chat, final_text, header_html=prefix_html, thread_id=target_thread)
                push_step_images(
                    target_chat,
                    final_text,
                    new_cid,
                    started_ts,
                    before_files,
                    {},
                    live_watch=False,
                    turn_start_line=0,
                    thread_id=target_thread,
                    workdir=exec_workdir,
                )
        else:
            raise ValueError(f"Unknown task type: {ttype}")
    except Exception as e:
        log("execute_scheduled_task error (%s): %r" % (tid, e))
        scheduler.task_mgr.record_completion(tid, "failed", error=str(e))
        if deliv_cfg.get("notify_on_failure", True):
            send(target_chat,
                 f"⚠️ ⏰ <b>[{html_mod.escape(tname)}] 发生异常</b>: <code>{html_mod.escape(str(e))}</code>",
                 parse_mode="HTML", thread_id=target_thread)


def scheduler_loop():
    log("Scheduler loop started (polling every 20s, bot_instance=%s)" % BOT_INSTANCE_ID)
    while not shutting_down:
        try:
            due_tasks = scheduler.task_mgr.get_due_tasks(bot_instance_id=BOT_INSTANCE_ID)
            for task in due_tasks:
                deliv = task.get("delivery", {})
                target_chat = deliv.get("target_chat_id")
                target_thread = _normalize_thread_id(deliv.get("target_thread_id"))
                if not target_chat and ALLOWED:
                    target_chat = PRIMARY_CHAT_ID or next(iter(ALLOWED))
                if target_chat:
                    skey = scope_key_for(target_chat, target_thread)
                    log("Enqueuing scheduled task %s (%s) for scope %s" % (task["id"], task.get("name"), skey))
                    job_q.put((target_chat, target_thread, skey, ("__SCHEDULED__", task)))
        except Exception as e:
            log("scheduler_loop error: %r" % e)
        time.sleep(20)


def _resolve_project_id_by_name_or_id(raw_proj):
    if not raw_proj:
        return None
    for item in list_agy_projects():
        if raw_proj == item["id"] or raw_proj.lower() == item["name"].lower():
            return item["id"]
    return raw_proj


def _summarize_conv_usage(cid, started_ts, skip_steps=0):
    dur = round(max(0.0, time.time() - float(started_ts or time.time())), 2)
    out = {"duration_s": dur, "calls": 0, "input_tokens": 0, "cache_read_tokens": 0, "output_tokens": 0, "cache_hit_pct": 0.0, "usd": 0.0}
    if not cid:
        return out
    tp = os.path.join(BRAIN_ROOT, cid, ".system_generated", "logs", "transcript.jsonl")
    if not os.path.isfile(tp):
        return out
    try:
        _first_ep, steps, _sched = _parse_transcript_cost_steps(tp)
        sub = steps[max(0, int(skip_steps)):]
        inp = sum(s[2] for s in sub)
        ca = sum(s[3] for s in sub)
        ot = sum(s[4] for s in sub)
        usd = sum(s[5] for s in sub)
        tot_in = inp + ca
        out["calls"] = len(sub)
        out["input_tokens"] = inp
        out["cache_read_tokens"] = ca
        out["output_tokens"] = ot
        out["cache_hit_pct"] = round((ca * 100.0 / tot_in), 1) if tot_in > 0 else 0.0
        out["usd"] = round(usd, 5)
    except Exception as e:
        log("summarize_conv_usage failed (%s): %r" % (cid[:8], e))
    return out


def _execute_bus_job(job_id):
    global turn_running, turn_running_scope, turn_running_chat, cancel_requested, _active_bus_job_id
    my_handle = _current_bot_handle()
    job = bot_bus.claim_job(job_id, my_handle, os.getpid())
    if not job:
        return

    cfg = _current_bot_cfg()
    sc = get_scope_state(PRIMARY_SCOPE_KEY)
    exec_workdir = job.get("workdir") or cfg.get("default_workdir") or sc.get("workdir") or WORKDIR
    exec_workdir = os.path.realpath(os.path.expanduser(exec_workdir))
    if not os.path.isdir(exec_workdir):
        exec_workdir = WORKDIR

    raw_proj = job.get("project") or cfg.get("default_project") or ""
    exec_project = _resolve_project_id_by_name_or_id(raw_proj)
    exec_model = job.get("model") or cfg.get("default_model") or sc.get("model") or None
    exec_effort = job.get("effort") or sc.get("effort") or None
    exec_mode = job.get("mode") or sc.get("mode") or "auto"
    from_bot = job.get("from_bot") or "coordinator"
    thread_key = (job.get("thread_key") or "").strip()
    resume_cid = (job.get("resume_cid") or "").strip()
    if not resume_cid and thread_key:
        resume_cid = bot_bus.thread_get(from_bot, my_handle, thread_key)
    if resume_cid and not os.path.isdir(os.path.join(BRAIN_ROOT, resume_cid)):
        resume_cid = ""

    skip_steps = 0
    if resume_cid:
        pre_tp = os.path.join(BRAIN_ROOT, resume_cid, ".system_generated", "logs", "transcript.jsonl")
        if os.path.isfile(pre_tp):
            try:
                skip_steps = len(_parse_transcript_cost_steps(pre_tp)[1])
            except Exception:
                skip_steps = 0

    origin_chat = int(job.get("origin_chat_id") or 0)
    origin_thread = _normalize_thread_id(job.get("origin_thread_id"))
    origin_msg_id = int(job.get("origin_msg_id") or 0)

    silent_group = job.get("notify_group") is False
    if silent_group:
        mirror_chat = 0
        mirror_thread = None
    elif BUS_CHAT_MODE == "conversational" and origin_chat < 0 and _is_authorized(origin_chat):
        mirror_chat = origin_chat
        mirror_thread = origin_thread
    else:
        mirror_chat = int(cfg.get("mirror_chat_id") or 0)
        mirror_thread = _normalize_thread_id(cfg.get("mirror_thread_id"))
        if not mirror_chat and job.get("notify_group") and origin_chat:
            if _is_authorized(origin_chat):
                mirror_chat = origin_chat
                mirror_thread = origin_thread
    if mirror_chat and not _is_authorized(mirror_chat):
        mirror_chat = 0

    mirror_msg_id = None
    label = job.get("label") or (job.get("prompt") or "")[:36]
    if mirror_chat:
        if BUS_CHAT_MODE == "conversational":
            receipt_html = (
                f"👋 收到来自 <code>@{html_mod.escape(from_bot)}</code> 的派单，我开始处理："
                f"【<b>{html_mod.escape(label)}</b>】（单号 <code>{html_mod.escape(job_id)}</code>）"
            )
            r_m = tg_send_in_route(
                "sendMessage",
                mirror_chat,
                thread_id=mirror_thread,
                text=receipt_html,
                parse_mode="HTML",
                reply_to_message_id=origin_msg_id or None,
            )
            mirror_msg_id = _extract_msg_id(r_m)
            if mirror_msg_id:
                _record_and_relay_bot_group_msg(
                    mirror_chat,
                    mirror_msg_id,
                    mirror_thread,
                    f"收到来自 @{from_bot} 的派单，我开始处理：【{label}】（单号 {job_id}）",
                    relay_mentions=False,
                )
            else:
                log("Bus job %s conversational receipt send failed: %s" % (job_id, _format_tg_err(r_m)))
        else:
            start_html = (
                f"🛠 <b>[@{html_mod.escape(my_handle)}] 接单执行</b>\n"
                f"• 来自：<code>@{html_mod.escape(from_bot)}</code> · 单号：<code>{html_mod.escape(job_id)}</code>\n"
                f"• 任务：<code>{html_mod.escape(label)}</code>"
                + (f"\n• 模型：<code>{html_mod.escape(exec_model)}</code>" if exec_model else "")
            )
            r_m = tg_send_in_route("sendMessage", mirror_chat, thread_id=mirror_thread, text=start_html, parse_mode="HTML")
            mirror_msg_id = _extract_msg_id(r_m)
            if not mirror_msg_id:
                log("Bus job %s card receipt send failed: %s" % (job_id, _format_tg_err(r_m)))

    started_ts = time.time()
    before_files = snapshot_workspace_files(workdir=exec_workdir)
    before_outbox = snapshot_workspace_files(workdir=BOT_OUTBOX_DIR) if os.path.isdir(BOT_OUTBOX_DIR) else {}
    full_prompt = bot_bus.format_worker_envelope(
        job,
        exec_workdir,
        BOT_OUTBOX_DIR,
        worker_specialty=cfg.get("specialty") or "",
    )

    cmd = [
        AGY_BIN,
        "--input-format", "text",
        "--output-format", "stream-json",
        "--print-timeout", PRINT_TIMEOUT,
    ]
    if exec_mode == "auto":
        cmd.append("--dangerously-skip-permissions")
    if exec_model:
        cmd += ["--model", exec_model]
    if exec_effort:
        cmd += ["--effort", exec_effort]
    if exec_project:
        cmd += ["--project", exec_project]
    if resume_cid:
        cmd += ["--conversation", resume_cid]
    cmd += ["-p", full_prompt]

    env = dict(os.environ)
    env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
    env.setdefault("HOME", HOME)
    env["AGY_OUTBOX_DIR"] = BOT_OUTBOX_DIR
    if mirror_chat and int(mirror_chat) < 0:
        worker_skey = scope_key_for(mirror_chat, mirror_thread)
        bot_bus.set_origin_context(
            worker_skey,
            bot_handle=my_handle,
            chat_id=mirror_chat,
            thread_id=mirror_thread,
            msg_id=origin_msg_id,
            mention_hop=0,
            chain_id=str(job.get("chain_id") or ""),
        )
        env["AGY_BOT_BUS_ENABLE"] = "1"
        env["AGY_BOT_BUS_ROLE"] = "worker"
        env["AGY_BOT_CHAT_ID"] = str(mirror_chat)
        env["AGY_BOT_THREAD_ID"] = str(mirror_thread) if mirror_thread is not None else ""
        env["AGY_BOT_SCOPE_KEY"] = worker_skey
        env["AGY_BOT_ORIGIN_MSG_ID"] = str(origin_msg_id or 0)
        env["AGY_BOT_MENTION_HOP"] = "0"
    else:
        env["AGY_BOT_BUS_ENABLE"] = "0"
        env["AGY_BOT_BUS_ROLE"] = "disabled"
    env["AGY_BOT_HANDLE"] = my_handle
    env["AGY_BOT_CHAIN"] = ",".join(job.get("chain") or [])

    with session_lock:
        turn_running = True
        turn_running_scope = f"bus:{job_id}"
        turn_running_chat = mirror_chat or (PRIMARY_CHAT_ID or 0)
        cancel_requested = False
        _active_bus_job_id = job_id

    _publish_bot_heartbeat()
    proc = None
    final_status = "error"
    final_text = ""
    err_msg = ""
    new_cid = resume_cid
    artifacts = []
    usage = {}

    try:
        log("Starting Bus job %s (from=@%s, model=%s, cwd=%s, conv=%s)" % (
            job_id, from_bot, exec_model or "default", exec_workdir, (resume_cid or "new")[:8]
        ))
        proc = subprocess.Popen(
            cmd,
            cwd=exec_workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        ev_q = queue.Queue()
        stderr_tail = collections.deque(maxlen=60)

        def _read_out():
            try:
                for line in proc.stdout:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        ev_q.put(json.loads(s))
                    except Exception:
                        pass
            finally:
                ev_q.put({"event": "__eof__"})

        def _read_err():
            try:
                for line in proc.stderr:
                    stderr_tail.append(line)
            except Exception:
                pass

        threading.Thread(target=_read_out, daemon=True).start()
        threading.Thread(target=_read_err, daemon=True).start()

        step_buffers = {}
        turn_tool_texts = []
        last_prog_ts = 0.0
        result_ev = None
        aborted_reason = ""

        while True:
            if shutting_down or cancel_requested or bot_bus.is_job_cancelled(job_id):
                aborted_reason = "shutdown" if shutting_down else ("cancelled_local" if cancel_requested else "cancelled_by_coordinator")
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                break
            try:
                ev = ev_q.get(timeout=0.25)
            except queue.Empty:
                continue

            kind = ev.get("event")
            if kind == "__eof__":
                break
            if kind == "init":
                cid = ev.get("conversation_id")
                if cid:
                    new_cid = cid
                continue
            if kind == "step_update":
                su = ev.get("step_update") or {}
                st = su.get("step_type")
                skind = su.get("state")
                sidx = su.get("step_index", 0)
                if st == "tool":
                    tname = su.get("tool_name") or ""
                    tinfo = su.get("tool_info")
                    if tname or tinfo:
                        try:
                            turn_tool_texts.append(tname + " " + json.dumps(tinfo or {}, ensure_ascii=False)[:3000])
                        except Exception:
                            pass
                    if skind == "ACTIVE" and (time.time() - last_prog_ts) >= 1.5:
                        last_prog_ts = time.time()
                        bot_bus.update_job(job_id, progress=f"running tool: {tname}")
                elif st == "agent_response":
                    delta = su.get("text_delta") or ""
                    if delta:
                        step_buffers[sidx] = step_buffers.get(sidx, "") + delta
            elif kind == "result":
                result_ev = ev.get("result") or ev
                break

        try:
            proc.wait(timeout=5)
        except Exception:
            pass

        if aborted_reason:
            final_status = "cancelled"
            err_msg = aborted_reason
        elif result_ev is not None:
            new_cid = result_ev.get("conversation_id") or new_cid
            st = result_ev.get("status")
            resp = (result_ev.get("response") or "").strip()
            if not resp and step_buffers:
                resp = step_buffers[max(step_buffers.keys())].strip()
            if st == "SUCCESS":
                final_status = "done"
                final_text = resp or "(completed with empty text)"
            else:
                final_status = "error"
                err_msg = str(result_ev.get("error") or resp or f"status={st}")
                final_text = resp
        else:
            rc = proc.returncode if proc else -1
            err_msg = f"agy exited ({rc}): {''.join(stderr_tail)[-600:]}"
            final_status = "error"

        if new_cid and thread_key:
            bot_bus.thread_set(from_bot, my_handle, thread_key, new_cid)

        # Gather generated workspace/outbox files without stealing coordinator deliverables
        cur_files = snapshot_workspace_files(workdir=exec_workdir)
        for fp, mt in cur_files.items():
            if fp not in before_files or mt > before_files.get(fp, 0):
                artifacts.append(fp)
        if os.path.isdir(BOT_OUTBOX_DIR):
            cur_out = snapshot_workspace_files(workdir=BOT_OUTBOX_DIR)
            for fp, mt in cur_out.items():
                if fp not in before_outbox or mt > before_outbox.get(fp, 0):
                    if fp not in artifacts:
                        artifacts.append(fp)
        artifacts.sort()
        usage = _summarize_conv_usage(new_cid, started_ts, skip_steps=skip_steps)

    except Exception as e:
        log("Bus job %s exception: %r" % (job_id, e))
        final_status = "error"
        err_msg = repr(e)
        usage = _summarize_conv_usage(new_cid, started_ts, skip_steps=skip_steps)
    finally:
        with session_lock:
            turn_running = False
            turn_running_scope = None
            turn_running_chat = None
            _active_bus_job_id = None

        delivered_to_group = False
        if mirror_chat:
            try:
                icon = {"done": "✅", "error": "⚠️", "cancelled": "🛑"}.get(final_status, "ℹ️")
                dur_s = usage.get("duration_s", round(time.time() - started_ts, 1))
                usd_s = _fmt_usd(float(usage.get("usd") or 0.0)) if usage.get("usd") else "$0.00"
                body_raw = final_text if final_status == "done" else (err_msg or final_text or "(no output)")
                if BUS_CHAT_MODE == "conversational":
                    status_zh = {"done": "已完成", "error": "执行失败", "cancelled": "已取消"}.get(final_status, final_status)
                    header_html = (
                        f"{icon} <b>任务{status_zh}</b> · 【{html_mod.escape(label)}】\n"
                        f"• 单号：<code>{html_mod.escape(job_id)}</code> · 派单：@{html_mod.escape(from_bot)}\n\n"
                    )
                    footer_str = f"🤖 {exec_model or 'default'} · ⏱ {dur_s}s · {usd_s}"
                    sent_mid, _ = send_rich(
                        mirror_chat,
                        body_raw,
                        header_html=header_html,
                        footer_str=footer_str,
                        thread_id=mirror_thread,
                        reply_to_message_id=origin_msg_id or mirror_msg_id or None,
                    )
                    if sent_mid:
                        delivered_to_group = True
                        _record_and_relay_bot_group_msg(
                            mirror_chat,
                            sent_mid,
                            mirror_thread,
                            body_raw,
                            relay_mentions=True,
                            source_hop=0,
                            exclude_bots=[from_bot] if job.get("wake_on_async") else None,
                            mention_scan_text=body_raw,
                        )
                else:
                    summary_html = (
                        f"{icon} <b>[@{html_mod.escape(my_handle)}] {final_status.upper()}</b> "
                        f"(<code>{dur_s}s · {usd_s}</code>)\n"
                        f"• 单号：<code>{html_mod.escape(job_id)}</code> · 来自：<code>@{html_mod.escape(from_bot)}</code>\n"
                        f"• 摘要：{html_mod.escape(body_raw[:600])}"
                    )
                    if mirror_msg_id:
                        r_ed = tg("editMessageText", chat_id=mirror_chat, message_id=mirror_msg_id,
                                  text=summary_html, parse_mode="HTML", link_preview_options={"is_disabled": True})
                        if not _tg_ok(r_ed):
                            log("Bus job %s card edit failed: %s" % (job_id, _format_tg_err(r_ed)))
                        else:
                            delivered_to_group = True
                    else:
                        r_sd = tg_send_in_route("sendMessage", mirror_chat, thread_id=mirror_thread,
                                                text=summary_html, parse_mode="HTML")
                        if _extract_msg_id(r_sd):
                            delivered_to_group = True

                img_paths = [p for p in artifacts if os.path.splitext(p)[1].lower() in IMAGE_EXTS and os.path.isfile(p)]
                if img_paths:
                    claimed = [p for p in img_paths if try_claim_image(p)]
                    if len(claimed) == 1:
                        send_file(mirror_chat, claimed[0], thread_id=mirror_thread)
                    elif len(claimed) > 1:
                        send_media_group(mirror_chat, claimed[:10], thread_id=mirror_thread)
            except Exception as de:
                log("Bus job %s group delivery failed: %r" % (job_id, de))

        if delivered_to_group:
            bot_bus.update_job(job_id, group_delivered=True)
        bot_bus.finish_job(
            job_id,
            status=final_status,
            result_text=final_text,
            error=err_msg,
            worker_cid=new_cid or "",
            artifacts=artifacts,
            usage=usage,
        )
        _publish_bot_heartbeat()


def _publish_bot_heartbeat():
    try:
        cfg = _current_bot_cfg()
        sc = get_scope_state(PRIMARY_SCOPE_KEY)
        with session_lock:
            busy = turn_running
            cur_job = _active_bus_job_id
        bot_bus.heartbeat_bot({
            "handle": _current_bot_handle(),
            "display_name": BOT_META.get("first_name") or _current_bot_handle(),
            "bot_id": BOT_META.get("bot_id") or 0,
            "instance_id": BOT_INSTANCE_ID,
            "pid": os.getpid(),
            "role": cfg.get("role") or "peer",
            "specialty": cfg.get("specialty") or "",
            "active_model": sc.get("model") or "",
            "workdir": sc.get("workdir") or WORKDIR,
            "project": current_project(PRIMARY_SCOPE_KEY) or "",
            "allowed_chats": sorted(ALLOWED),
            "busy": busy,
            "current_job": cur_job,
            "queue_depth": job_q.qsize(),
        })
    except Exception as e:
        log("publish_bot_heartbeat failed: %r" % e)


def _bot_bus_loop():
    """Poll Bot Bus inbox packets (job, broadcast, async batch_done) & publish liveness heartbeats."""
    last_hb = 0.0
    last_id_retry = 0.0
    while not shutting_down:
        now = time.time()
        if not BOT_META.get("resolved") and (now - last_id_retry) >= 20.0:
            last_id_retry = now
            _init_bot_identity()
        if (now - last_hb) >= 6.0:
            last_hb = now
            _publish_bot_heartbeat()
            if BOT_META.get("resolved") and _current_bot_role() != _LAST_REGISTERED_CMD_ROLE:
                register_bot_commands()

        try:
            packets = bot_bus.pop_inbox_packets(_current_bot_handle())
            for pkt in packets:
                ptype = pkt.get("type")
                if ptype in ("broadcast", "group_say"):
                    c_id = int(pkt.get("chat_id") or 0)
                    t_id = _normalize_thread_id(pkt.get("thread_id"))
                    msg_txt = pkt.get("message") or ""
                    if c_id and msg_txt and _is_authorized(c_id):
                        sent_mid, _ = send_rich(
                            c_id,
                            msg_txt,
                            thread_id=t_id,
                            reply_to_message_id=pkt.get("reply_to_message_id"),
                        )
                        if c_id < 0 and sent_mid:
                            _record_and_relay_bot_group_msg(
                                c_id,
                                sent_mid,
                                t_id,
                                msg_txt,
                                relay_mentions=True,
                                source_hop=int(pkt.get("source_hop") or 0),
                            )
                elif ptype == "group_mention":
                    c_id = int(pkt.get("chat_id") or 0)
                    t_id = _normalize_thread_id(pkt.get("thread_id"))
                    skey = scope_key_for(c_id, t_id)
                    if c_id < 0 and _is_authorized(c_id):
                        if not bot_bus.loop_guard_allow(f"mention:{skey}"):
                            log("BotLoopGuard blocked group_mention wake for %s" % skey)
                            continue
                        from_b = pkt.get("from_bot") or "colleague"
                        hop = int(pkt.get("hop") or 1)
                        excerpt = (pkt.get("text_excerpt") or "").strip()
                        mention_prompt = (
                            f"[ACB_GROUP_MENTION from=@{from_b} hop={hop}]\n"
                            f"同事 @{from_b} 在群里提到了你（消息摘要：{excerpt}）。\n"
                            f"请结合上方群聊上下文自然简短回应或接力处理；若无需额外操作或话题已收尾，请简洁确认即可，避免无意义互相客套引发循环。"
                        )
                        enqueue(
                            c_id,
                            mention_prompt,
                            thread_id=t_id,
                            scope_key=skey,
                            origin_msg_id=int(pkt.get("msg_id") or 0),
                            mention_hop=hop,
                            chain_id=str(pkt.get("chain_id") or ""),
                            is_mention=True,
                            raw_text=excerpt,
                        )
                elif ptype == "job":
                    jid = pkt.get("job_id")
                    if jid and not bot_bus.is_job_cancelled(jid):
                        job_q.put((PRIMARY_CHAT_ID or 0, None, f"bus:{jid}", ("__BUS_JOB__", jid)))
                elif ptype == "batch_done":
                    c_id = int(pkt.get("origin_chat_id") or PRIMARY_CHAT_ID or 0)
                    t_id = _normalize_thread_id(pkt.get("origin_thread_id"))
                    skey = pkt.get("origin_scope_key") or scope_key_for(c_id, t_id)
                    jids = pkt.get("job_ids") or []
                    if not bot_bus.loop_guard_allow(skey):
                        log("BotLoopGuard blocked automated async wake for %s" % skey)
                        continue
                    jobs = [bot_bus.get_job(jid) for jid in jids if bot_bus.get_job(jid)]
                    briefs = [bot_bus.summarize_job_brief(j) for j in jobs]
                    brief_json = json.dumps(briefs, ensure_ascii=False, indent=2)
                    all_group_delivered = bool(briefs) and all(b.get("group_delivered") for b in briefs)
                    any_group_delivered = any(b.get("group_delivered") for b in briefs)
                    if all_group_delivered:
                        delivery_note = "- 注意：以上任务的 `group_delivered=true`，Worker 已在群内直接交付结果，无需整段复述，只需做简短串接、验收或下一步派单即可；\n"
                    elif any_group_delivered:
                        delivery_note = "- 注意：其中 `group_delivered=true` 的任务已由 Worker 在群内直接交付结果（无需整段复述），`group_delivered=false` 的任务尚未在群内交付；\n"
                    else:
                        delivery_note = "- 注意：`group_delivered=false`，Worker 未在群内直接交付结果，请由你汇总关键结论给用户；\n"
                    if c_id:
                        wake_prompt = (
                            f"[ACB_TEAM_ASYNC_DONE group={pkt.get('group_id')}]\n"
                            f"你此前异步分派的团队子任务已全部落定。请验收以下结果：\n"
                            f"{delivery_note}"
                            f"- 如后续仍需接力下一步（例如开发/发版完成后，异步派发测试进行验证或采集发版后 Issue/PR/CI 反馈），"
                            f"请直接用 `team_dispatch`（默认 `wait=false`）异步派发并向用户简报当前进展后立即结束本轮；\n"
                            f"- 如全流程已闭环，请向用户简洁汇报最终结论；请勿再次重复派发完全相同的已完成任务：\n\n{brief_json}"
                        )
                        job_q.put((c_id, t_id, skey, wake_prompt))
        except Exception as e:
            log("bot_bus_loop error: %r" % e)
        time.sleep(0.35)


def worker():
    while True:
        item = job_q.get()
        if isinstance(item, tuple) and len(item) == 4:
            chat_id, thread_id, skey, prompt = item
        else:
            chat_id, prompt = item
            thread_id = None
            skey = scope_key_for(chat_id, None)

        if prompt == "__RELOAD__":
            job_q.task_done()
            perform_hot_reload(notify_chat_id=chat_id, notify_thread_id=thread_id)
            return
        try:
            if isinstance(prompt, tuple) and len(prompt) == 2 and prompt[0] == "__COMPACT__":
                run_compact(chat_id, instruction=prompt[1], thread_id=thread_id, scope_key=skey)
            elif isinstance(prompt, tuple) and len(prompt) == 2 and prompt[0] == "__SCHEDULED__":
                execute_scheduled_task(prompt[1])
            elif isinstance(prompt, tuple) and len(prompt) == 2 and prompt[0] == "__BUS_JOB__":
                _execute_bus_job(prompt[1])
            elif isinstance(prompt, tuple) and len(prompt) == 2 and prompt[0] == "__CHAT_TURN__":
                meta = prompt[1]
                run_agy(
                    chat_id,
                    meta["prompt"],
                    thread_id=thread_id,
                    scope_key=skey,
                    origin_msg_id=int(meta.get("origin_msg_id") or 0),
                    mention_hop=int(meta.get("mention_hop") or 0),
                    chain_id=str(meta.get("chain_id") or ""),
                )
            else:
                run_agy(chat_id, prompt, thread_id=thread_id, scope_key=skey)
        except Exception as e:
            log("worker error: %r" % e)
            send(chat_id, "⚠️ bridge error: %r" % e, thread_id=thread_id)
        finally:
            job_q.task_done()
            if os.path.exists(RELOAD_TRIGGER):
                try:
                    os.remove(RELOAD_TRIGGER)
                except Exception:
                    pass
                log("Detected %s after job, reloading via execv..." % RELOAD_TRIGGER)
                perform_hot_reload()


# ---------------------------------------------------------------- helpers
def agy_models():
    env = dict(os.environ)
    env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
    try:
        r = subprocess.run([AGY_BIN, "models"], capture_output=True, text=True,
                           timeout=60, env=env, cwd=WORKDIR)
        models = []
        for line in (r.stdout or "").splitlines():
            if "\t" in line:
                slug, desc = line.split("\t", 1)
                models.append((slug.strip(), desc.strip()))
        return models
    except Exception as e:
        log("agy_models failed: %s" % e)
        return []


def list_sessions(limit=8, scope_key=None):
    cur_proj = current_project(scope_key)
    sched_cids = _load_scheduled_cids()
    if os.path.isfile(SUMMARIES_DB):
        try:
            conn = sqlite3.connect(f"file:{SUMMARIES_DB}?mode=ro", uri=True, timeout=2.0)
            try:
                rows = conn.execute(
                    "SELECT last_modified_time, conversation_id, preview, workspace_uris, project_id, agent_name "
                    "FROM conversation_summaries ORDER BY last_modified_time DESC LIMIT 120"
                ).fetchall()
            finally:
                conn.close()
            items = []
            for upd, cid, preview, ws_raw, pid, agent_name in rows:
                if agent_name == "pure-llm" or "observer-sandbox" in (ws_raw or ""):
                    continue
                if cid in sched_cids or "[ACB_SCHEDULED_TASK" in (preview or "") or "[ACB_TEAM_DELEGATION" in (preview or ""):
                    continue
                if cur_proj and pid != cur_proj:
                    continue
                try:
                    uris = json.loads(ws_raw or "[]")
                    ws = (uris[0] if uris else "").replace("file://", "")
                except Exception:
                    ws = ""
                items.append((str(upd or ""), cid, (preview or "")[:60], ws))
                if len(items) >= limit:
                    break
            if items:
                return items
        except Exception as e:
            log("list_sessions sqlite fallback: %r" % e)
    try:
        with open(META_FILE) as f:
            data = json.load(f)
        convs = data.get("conversations", {})
        items = []
        for cid, entry in convs.items():
            s = entry.get("summary", {})
            if s.get("Internal") or entry.get("is_internal"):
                continue
            prev = s.get("Preview", "")
            if cid in sched_cids or "[ACB_SCHEDULED_TASK" in prev:
                continue
            items.append((s.get("UpdatedAt", ""), cid, prev[:60],
                          s.get("WorkspaceURIs", [""])[0].replace("file://", "")))
        items.sort(reverse=True)
        return items[:limit]
    except Exception as e:
        log("list_sessions: %r" % e)
        return []


def tg_download(file_id, dest):
    r = tg("getFile", file_id=file_id)
    path = r.json()["result"]["file_path"]
    url = "https://api.telegram.org/file/bot%s/%s" % (BOT_TOKEN, path)
    data = http_session.get(url, timeout=180).content
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def transcribe(src):
    if not (STT_BASE and STT_KEY):
        return None
    with open(src, "rb") as f:
        r = http_session.post(STT_BASE.rstrip("/") + "/audio/transcriptions",
                             headers={"Authorization": "Bearer " + STT_KEY},
                             files={"file": (os.path.basename(src), f)},
                             data={"model": STT_MODEL}, timeout=180)
    r.raise_for_status()
    return r.json().get("text")


def safe_workspace_path(name, scope_key=None):
    wdir = current_workdir(scope_key)
    p = os.path.realpath(os.path.join(wdir, name))
    if not p.startswith(wdir + os.sep) and p != wdir:
        return None
    return p


def cancel_current_task(chat_id, clear_all=False, from_native_stop=False, thread_id=None, scope_key=None):
    global cancel_requested
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)

    cancelled = False
    to_kill = None
    active_was_other_scope = False
    with session_lock:
        if turn_running:
            is_same_scope = (turn_running_scope == skey)
            queued_in_scope = job_q.count_scope(skey)
            # Cancel active turn if triggered in same scope, clear_all, native Stop, or nothing else in this scope is queued
            if is_same_scope or clear_all or from_native_stop or queued_in_scope == 0:
                cancel_requested = True
                target_sk = turn_running_scope or skey
                to_kill = _session_pool.pop(target_sk, None)
                cancelled = True
                active_was_other_scope = not is_same_scope
            else:
                active_was_other_scope = True

    if to_kill is not None:
        try:
            close_session_async(to_kill, force=True)
        except Exception as e:
            send(chat_id, f"cancel failed: {e}", thread_id=norm_tid)
            return

    if clear_all:
        cleared = job_q.clear_all()
    else:
        cleared = job_q.cancel_scope(skey)

    if cancelled:
        scope_note = "（跨会话中断正在运行的任务）" if active_was_other_scope else ""
        extra = f" (已清空 {cleared} 个排队任务)" if cleared else (
            f" (队列中仍有 {job_q.qsize()} 个其它会话任务)" if job_q.qsize() else ""
        )
        send(chat_id, f"🛑 已终止当前任务{scope_note}{extra}", thread_id=norm_tid)
    elif cleared:
        send(chat_id, f"🗑 已取消本会话排队中的 {cleared} 个任务。", thread_id=norm_tid)
    elif not from_native_stop:
        send(chat_id, "No running task.", thread_id=norm_tid)


# ---------------------------------------------------------------- keyboard builders
def make_model_keyboard(cur_model):
    models = agy_models()
    buttons = []
    for slug, desc in models:
        mark = "✓ " if slug == cur_model else ""
        buttons.append([{"text": f"{mark}{desc}", "callback_data": f"model:{slug}"}])
    buttons.append([{"text": "⚙️ Reset to Default (Clear)", "callback_data": "model:default"}])
    return {"inline_keyboard": buttons}


def make_effort_keyboard(cur_effort):
    buttons = []
    row = []
    for eff in EFFORTS:
        mark = "✓ " if eff == cur_effort else ""
        row.append({"text": f"{mark}{eff}", "callback_data": f"effort:{eff}"})
    buttons.append(row)
    buttons.append([{"text": "⚙️ Reset to Default", "callback_data": "effort:default"}])
    return {"inline_keyboard": buttons}


def make_sessions_keyboard(scope_key=None):
    items = list_sessions(6, scope_key=scope_key)
    buttons = []
    cur = get_scope_value(scope_key, "conversation_id")
    for updated, cid, preview, ws in items:
        tag = "★ " if cid == cur else ""
        label = f"{tag}{preview[:30] or cid[:8]}"
        buttons.append([{"text": label, "callback_data": f"resume:{cid[:8]}"}])
    return {"inline_keyboard": buttons}


def make_project_keyboard(cur_proj=None, scope_key=None):
    cur_p = cur_proj if cur_proj is not None else (current_project(scope_key) or "default-cli-project")
    buttons = []
    for item in list_agy_projects():
        pid = item["id"]
        mark = "✓ " if pid == cur_p else ""
        short_wd = item["workdir"].replace(HOME, "~")
        buttons.append([{
            "text": f"{mark}📂 {item['name']} ({short_wd})",
            "callback_data": f"project:{pid}",
        }])
    return {"inline_keyboard": buttons}


def make_status_keyboard(scope_key=None):
    sc = get_scope_state(scope_key)
    th_on = sc.get("thinking", True)
    ac_on = sc.get("auto_compact", True)
    th_label = "💭 思考链: 开启" if th_on else "💭 思考链: 关闭"
    ac_label = "⚡ 自动压缩: 开" if ac_on else "⚡ 自动压缩: 关"
    return {"inline_keyboard": [
        [{"text": "🔄 New Session", "callback_data": "action:new"},
         {"text": "🔁 Retry", "callback_data": "action:retry"},
         {"text": "⏪ Undo", "callback_data": "action:undo"}],
        [{"text": "🧹 Compact", "callback_data": "action:compact"},
         {"text": "📂 Project", "callback_data": "action:project"}],
        [{"text": "🤖 Model", "callback_data": "action:model"},
         {"text": "🧠 Effort", "callback_data": "action:effort"}],
        [{"text": th_label, "callback_data": "action:thinking"},
         {"text": ac_label, "callback_data": "action:context"}],
        [{"text": "📊 Usage (套餐)", "callback_data": "action:usage"},
         {"text": "💰 Cost (我的)", "callback_data": "action:cost"}],
        [{"text": "⏰ Schedule", "callback_data": "action:schedule"},
         {"text": "🤝 Team (/team)", "callback_data": "action:team"}],
        [{"text": "📁 Files", "callback_data": "action:files"},
         {"text": "🔄 Reload", "callback_data": "action:reload"}],
        [{"text": "🛑 Stop / Cancel", "callback_data": "action:cancel"}]
    ]}


# ---------------------------------------------------------------- commands
def cmd_model(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    if not arg:
        models = agy_models()
        cur = get_scope_value(skey, "model")
        lines = ["<b>🤖 Models</b> (tap to switch):"]
        for slug, desc in models:
            mark = "✓" if slug == cur else "·"
            lines.append(f"{mark} <code>{slug}</code> — {desc}")
        lines.append(f"\nCurrent: <b>{cur or '(agy default)'}</b>")
        kb = make_model_keyboard(cur)
        send(chat_id, "\n".join(lines), parse_mode="HTML", reply_markup=kb, thread_id=thread_id)
        return

    new_val = None if arg in ("default", "reset", "clear", "none") else arg
    update_scope_state(skey, model=new_val)
    save_state()
    invalidate_session("model_change", scope_key=skey)
    if new_val is None:
        send(chat_id, "model → default (cleared)", thread_id=thread_id)
    else:
        send(chat_id, f"model → {new_val} (applies from the next task)", thread_id=thread_id)


def cmd_effort(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    if not arg:
        cur = get_scope_value(skey, "effort")
        lines = [f"<b>🧠 Reasoning Effort</b> (Current: <b>{cur or '(default)'}</b>):",
                 "Tap an option below to set:"]
        kb = make_effort_keyboard(cur)
        send(chat_id, "\n".join(lines), parse_mode="HTML", reply_markup=kb, thread_id=thread_id)
        return

    if arg in ("default", "reset", "clear", "none"):
        update_scope_state(skey, effort=None)
        save_state()
        invalidate_session("effort_clear", scope_key=skey)
        send(chat_id, "effort → default (cleared)", thread_id=thread_id)
        return

    if arg not in EFFORTS:
        send(chat_id, "usage: /effort low|medium|high|xhigh|max|default", thread_id=thread_id)
        return

    update_scope_state(skey, effort=arg)
    save_state()
    invalidate_session("effort_change", scope_key=skey)
    send(chat_id, f"effort → {arg}", thread_id=thread_id)


def cmd_sessions(chat_id, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    items = list_sessions(scope_key=skey)
    if not items:
        send(chat_id, "No session records", thread_id=thread_id)
        return
    cur = get_scope_value(skey, "conversation_id")
    lines = ["<b>Recent Sessions</b> (tap or <code>/resume &lt;id&gt;</code>):"]
    for updated, cid, preview, ws in items:
        tag = "★" if cid == cur else "·"
        lines.append(f"{tag} <code>{cid[:8]}</code> {updated[:16].replace('T', ' ')}\n   {html_mod.escape(preview)}")
    kb = make_sessions_keyboard(scope_key=skey)
    send(chat_id, "\n".join(lines), parse_mode="HTML", reply_markup=kb, thread_id=thread_id)


def cmd_resume(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    if not arg:
        cmd_sessions(chat_id, thread_id=thread_id, scope_key=skey)
        return
    items = list_sessions(50, scope_key=skey)
    match = [cid for _, cid, _, _ in items if cid.startswith(arg)]
    if not match:
        send(chat_id, "No matching session found", thread_id=thread_id)
        return
    update_scope_state(skey, conversation_id=match[0])
    save_state()
    invalidate_session("resume", scope_key=skey)
    send(chat_id, f"resumed → <code>{match[0][:8]}</code> (the next message continues this session)",
         parse_mode="HTML", thread_id=thread_id)


def _latest_session_for_project(project_id, workdir, exclude_cids=None):
    """Find the most recently modified non-internal conversation matching `project_id` or `workdir`."""
    target_uri = "file://" + os.path.realpath(workdir)
    excluded = set(exclude_cids or ())
    if os.path.isfile(SUMMARIES_DB):
        try:
            conn = sqlite3.connect(f"file:{SUMMARIES_DB}?mode=ro", uri=True, timeout=2.0)
            try:
                rows = conn.execute(
                    "SELECT last_modified_time, conversation_id, workspace_uris, project_id, agent_name "
                    "FROM conversation_summaries ORDER BY last_modified_time DESC LIMIT 80"
                ).fetchall()
            finally:
                conn.close()
            for _upd, cid, ws_raw, pid, agent_name in rows:
                if agent_name == "pure-llm" or "observer-sandbox" in (ws_raw or ""):
                    continue
                if cid in excluded:
                    continue
                if project_id and pid == project_id:
                    return cid
                if not project_id and target_uri in (ws_raw or ""):
                    return cid
        except Exception:
            pass
    try:
        with open(META_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        convs = data.get("conversations", {})
        best = None
        for cid, entry in convs.items():
            if cid in excluded:
                continue
            s = entry.get("summary", {})
            if s.get("Internal") or entry.get("is_internal"):
                continue
            pid = s.get("ProjectID") or ""
            uris = s.get("WorkspaceURIs") or []
            if (project_id and pid == project_id) or (target_uri in uris):
                upd = s.get("UpdatedAt", "")
                if best is None or upd > best[0]:
                    best = (upd, cid)
        return best[1] if best else None
    except Exception:
        return None


def _switch_project(target_arg, scope_key=None):
    """Switch active Antigravity CLI project & workdir for `scope_key`. Returns (ok, info_dict_or_err)."""
    skey = scope_key or PRIMARY_SCOPE_KEY
    arg_clean = (target_arg or "").strip()
    projs = list_agy_projects()
    matched = None
    if arg_clean.lower() in ("default", "reset", "clear", "none", "default-cli-project"):
        for p in projs:
            if p["id"] == "default-cli-project":
                matched = p
                break
        if matched is None:
            matched = {"id": "default-cli-project", "name": "CLI Project", "workdir": WORKDIR, "repo_url": ""}
    else:
        for p in projs:
            if arg_clean == p["id"] or arg_clean.lower() == p["name"].lower():
                matched = p
                break
        if matched is None and os.path.isdir(os.path.expanduser(arg_clean)):
            rdir = os.path.realpath(os.path.expanduser(arg_clean))
            for p in projs:
                if os.path.realpath(p["workdir"]) == rdir:
                    matched = p
                    break
            if matched is None:
                matched = {"id": None, "name": os.path.basename(rdir), "workdir": rdir, "repo_url": ""}
    if matched is None:
        return False, f"未找到项目 <code>{html_mod.escape(arg_clean)}</code>（输入 <code>/project</code> 查看列表）"

    is_default = (matched["id"] == "default-cli-project" and os.path.realpath(matched["workdir"]) == WORKDIR)
    new_pid = None if is_default else matched["id"]
    new_wdir = None if is_default else matched["workdir"]
    with state_lock:
        prim_scope = state.get("primary_scope") or PRIMARY_SCOPE_KEY
        cur_sc = (state.get("scopes") or {}).get(skey) or {}
        cur_proj = cur_sc.get("project") or None
        cur_wdir = cur_sc.get("workdir")
        cur_cid = cur_sc.get("conversation_id")
        claimed_cids = {
            sc.get("conversation_id")
            for k, sc in (state.get("scopes") or {}).items()
            if k != skey and isinstance(sc, dict) and sc.get("conversation_id")
        }
    same_target = (cur_proj == new_pid) and ((cur_wdir or None) == (new_wdir or None))
    if same_target and cur_cid and cur_cid not in claimed_cids:
        resume_cid = cur_cid
    elif skey == prim_scope:
        resume_cid = _latest_session_for_project(matched["id"], matched["workdir"], exclude_cids=claimed_cids)
    else:
        resume_cid = None

    update_scope_state(skey, project=new_pid, workdir=new_wdir, conversation_id=resume_cid)
    save_state()
    invalidate_session("project_switch", scope_key=skey)
    return True, {
        "id": matched["id"] or "default-cli-project",
        "name": matched["name"],
        "workdir": matched["workdir"],
        "repo_url": matched.get("repo_url") or "",
        "conversation_id": resume_cid,
    }


def cmd_project(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    if not arg:
        cur_p = current_project(skey) or "default-cli-project"
        cur_w = current_workdir(skey)
        projs = list_agy_projects()
        lines = ["<b>📂 Antigravity CLI Projects</b> (点按切换项目与仓库目录):"]
        for item in projs:
            mark = "✓" if item["id"] == cur_p else "·"
            repo_note = f"\n   🔗 <code>{html_mod.escape(item['repo_url'])}</code>" if item.get("repo_url") else ""
            lines.append(
                f"{mark} <b>{html_mod.escape(item['name'])}</b> (<code>{html_mod.escape(item['id'])}</code>)\n"
                f"   📁 <code>{html_mod.escape(item['workdir'])}</code>{repo_note}"
            )
        lines.append(
            f"\n当前生效：<b>{html_mod.escape(cur_p)}</b> → <code>{html_mod.escape(cur_w)}</code>"
        )
        send(chat_id, "\n".join(lines), parse_mode="HTML",
             reply_markup=make_project_keyboard(cur_p, scope_key=skey), thread_id=thread_id)
        return

    ok, info = _switch_project(arg, scope_key=skey)
    if not ok:
        send(chat_id, f"⚠️ {info}", parse_mode="HTML", thread_id=thread_id)
        return
    sess_note = f"已自动续接该项目最近会话 <code>{info['conversation_id'][:8]}</code>" if info["conversation_id"] else "下次发消息将在该项目新建会话"
    repo_line = f"\n• <b>GitHub：</b><code>{html_mod.escape(info['repo_url'])}</code>" if info["repo_url"] else ""
    send(
        chat_id,
        f"✅ <b>已切换 Antigravity CLI 项目</b>\n"
        f"• <b>Project：</b><b>{html_mod.escape(info['name'])}</b> (<code>{html_mod.escape(info['id'])}</code>)\n"
        f"• <b>工作目录：</b><code>{html_mod.escape(info['workdir'])}</code>{repo_line}\n"
        f"• <b>会话状态：</b>{sess_note}",
        parse_mode="HTML",
        thread_id=thread_id,
    )


def cmd_files(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    wdir = current_workdir(skey)
    entries = []
    for root, dirs, files in os.walk(wdir):
        dirs[:] = [d for d in dirs if d not in _SKIP_WALK_DIRS]
        depth = os.path.relpath(root, wdir).count(os.sep)
        if depth >= 2:
            dirs[:] = []
            continue
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            entries.append((os.path.relpath(fp, wdir), sz))
    entries.sort()
    if arg:
        entries = [e for e in entries if arg.lower() in e[0].lower()]
    if not entries:
        send(chat_id, "No files in workspace" + (f" matching {arg!r}" if arg else ""), thread_id=thread_id)
        return

    lines = ["<b>📁 Workspace Files</b> (/get &lt;name&gt; to fetch):"]
    buttons = []
    for rel, sz in entries[:30]:
        human = "%.1fK" % (sz / 1024) if sz < 1024 * 1024 else "%.1fM" % (sz / 1048576)
        lines.append(f"· <code>{html_mod.escape(rel)}</code> ({human})")
        if len(buttons) < 6:
            buttons.append([{"text": f"📥 {rel} ({human})", "callback_data": f"get:{rel}"}])

    if len(entries) > 30:
        lines.append(f"… {len(entries) - 30} more in total")

    reply_markup = {"inline_keyboard": buttons} if buttons else None
    send(chat_id, "\n".join(lines), parse_mode="HTML", reply_markup=reply_markup, thread_id=thread_id)


def cmd_get(chat_id, arg, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    if not arg:
        send(chat_id, "usage: /get <filename>", thread_id=thread_id)
        return
    p = safe_workspace_path(arg, scope_key=skey)
    if not p or not os.path.isfile(p):
        send(chat_id, "File does not exist or is outside the workspace", thread_id=thread_id)
        return
    r = send_file(chat_id, p, thread_id=thread_id)
    if r is None or not r.json().get("ok"):
        err = r.json().get("description") if r else "network error"
        send(chat_id, f"Send failed: {err}", thread_id=thread_id)


def _parse_token_threshold(raw):
    s = (raw or "").strip().lower().replace(",", "").replace("_", "")
    if not s:
        return None
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([km]?)$", s)
    if not m:
        return None
    val = float(m.group(1))
    unit = m.group(2)
    if unit == "k":
        val *= 1000
    elif unit == "m":
        val *= 1000000
    elif val < 1000:
        # e.g. user typed `180` meaning `180k`
        val *= 1000
    n = int(round(val))
    if 50000 <= n <= 245000:
        return n
    return None


def enqueue_compact(chat_id, instruction="", thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    conv = get_scope_value(skey, "conversation_id")
    if not conv:
        send(chat_id, "ℹ️ 当前还没有活跃会话，无需压缩上下文。", thread_id=norm_tid)
        return
    pending = job_q.qsize()
    with session_lock:
        busy = turn_running
    if pending or busy:
        send(chat_id, "📋 已加入压缩队列（排在当前任务之后立即执行）", thread_id=norm_tid)
    job_q.put((chat_id, norm_tid, skey, ("__COMPACT__", instruction)))


def build_context_panel(scope_key=None):
    sc = get_scope_state(scope_key)
    conv = sc.get("conversation_id")
    ac_on = bool(sc.get("auto_compact", True))
    thresh = int(sc.get("auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS)
    stats = get_context_stats(conv)
    ctx_tok = stats["ctx_tokens"]
    pct_auto = min(100, int(round(ctx_tok * 100.0 / max(1, thresh)))) if conv else 0
    pct_hard = min(100, int(round(ctx_tok * 100.0 / AGY_HARD_COMPACT_CEILING))) if conv else 0
    filled = min(10, max(0, int(round(pct_auto / 10.0))))
    bar = "▓" * filled + "░" * (10 - filled)

    state_note = " (刚完成压缩)" if stats["just_compacted"] else ""
    text = (
        f"<b>📊 会话上下文与自动压缩面板</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"• <b>当前会话：</b><code>{(conv or '(none)')[:8]}</code>\n"
        f"• <b>活跃上下文：</b><code>{format_tokens_k(ctx_tok)}</code>{state_note}\n"
        f"• <b>自动压缩阈值：</b><code>{format_tokens_k(thresh)}</code> "
        f"(<code>{'开启' if ac_on else '关闭'}</code>)\n"
        f"• <b>距离自动压缩：</b><code>[{bar}] {pct_auto}%</code> (系统上限 ~254k 占 {pct_hard}%)\n"
        f"• <b>距上次压缩：</b><code>{stats['steps_since_ckpt']}</code> 步 / <code>{stats['turns_since_ckpt']}</code> 轮\n"
        f"• <b>累计已压缩：</b><code>{stats['checkpoints']}</code> 次\n\n"
        f"<i>用法：<code>/compact</code> 立即压缩 · <code>/compact 保留xxx</code> 定向压缩 · "
        f"<code>/compact auto 160k</code> 设阈值 · <code>/compact on|off</code></i>"
    )
    ac_btn = f"⚡ 自动压缩: {'开启 ✓' if ac_on else '已关闭'}"
    preset_row = []
    for preset in (100000, 140000, 180000):
        mark = "✓ " if (ac_on and abs(thresh - preset) < 2000) else ""
        preset_row.append({
            "text": f"{mark}{int(preset // 1000)}k",
            "callback_data": f"compact:thresh:{preset}",
        })
    kb = {"inline_keyboard": [
        [{"text": "🧹 立即压缩 (/compact)", "callback_data": "action:compact"},
         {"text": ac_btn, "callback_data": "compact:toggle"}],
        preset_row,
    ]}
    return text, kb


def cmd_context(chat_id, thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    text, kb = build_context_panel(scope_key=skey)
    send(chat_id, text, parse_mode="HTML", reply_markup=kb, thread_id=thread_id)


# ---------------------------------------------------------------- token usage, cache rate & Google USD cost card (/cost)
_cost_cache_lock = threading.Lock()
_cost_mem_cache = {}  # cid -> (mtime_ns, size, first_epoch, steps_list)

_MODEL_SETTINGS_RE = re.compile(r"Model Selection` from .+? to (.+?)\. No need")
_WEEKDAY_CN = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")

_MODEL_FAMILY_LABELS = {
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


def _get_cost_tz():
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if zoneinfo is not None and COST_TZ_NAME:
        try:
            tz = zoneinfo.ZoneInfo(COST_TZ_NAME)
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


def _canonical_model_family(raw_model):
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


def _google_model_rates_per_m(family, ymd_utc, prompt_tokens=0):
    """Return (uncached_input_usd, cache_read_usd, output_usd) per 1M tokens
    based on official Google AI Studio / Vertex AI API pricing schedules.
    """
    if family == "gemini-3.8-flash":
        # Official Google paid tier: $0.75 / $0.075 / $3.75 through 2026-12-31, then $1.50 / $0.15 / $7.50
        return (0.75, 0.075, 3.75) if ymd_utc <= "2026-12-31" else (1.50, 0.15, 7.50)
    if family == "gemini-4-hydrogen":
        # Official Gemini 4 Hydrogen unified 1M context tier (95% implicit cache read discount)
        return (1.50, 0.075, 7.50)
    if family in ("gemini-4-carbon", "gemini-4-argon", "gemini-pro-orchestrator"):
        # Official Gemini 4 Carbon/Argon: $2.00 / $0.10 / $10.00 through 2026-11-30, then $4.00 / $0.20 / $20.00
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


def _load_conv_meta_map():
    """Return {cid: {'project_id': str, 'is_observer': bool, 'is_scheduled': bool}} across SQLite summaries and metadata json."""
    meta = {}
    sched_cids = _load_scheduled_cids()
    if os.path.isfile(SUMMARIES_DB):
        try:
            conn = sqlite3.connect(f"file:{SUMMARIES_DB}?mode=ro", uri=True, timeout=2.0)
            try:
                rows = conn.execute(
                    "SELECT conversation_id, project_id, agent_name, workspace_uris, preview FROM conversation_summaries"
                ).fetchall()
            finally:
                conn.close()
            for cid, pid, agent_name, ws_raw, preview in rows:
                is_obs = (agent_name == "pure-llm") or ("observer-sandbox" in (ws_raw or ""))
                is_sched = (cid in sched_cids) or ("[ACB_SCHEDULED_TASK" in (preview or ""))
                meta[cid] = {
                    "project_id": pid or "default-cli-project",
                    "is_observer": bool(is_obs),
                    "is_scheduled": bool(is_sched),
                }
        except Exception as e:
            log("cost meta sqlite fallback: %r" % e)
    if os.path.isfile(META_FILE):
        try:
            with open(META_FILE, "r", encoding="utf-8") as f:
                convs = (json.load(f) or {}).get("conversations", {})
            for cid, entry in convs.items():
                if cid in meta:
                    continue
                s = entry.get("summary", {})
                ws_list = s.get("Workspaces") or entry.get("workspace_uris") or []
                ws_str = json.dumps(ws_list)
                prev = str(s.get("Preview") or "")
                is_obs = bool(s.get("Internal") or entry.get("is_internal") or "observer-sandbox" in ws_str)
                is_sched = (cid in sched_cids) or ("[ACB_SCHEDULED_TASK" in prev)
                pid = "default-cli-project"
                if "/agy-cli-bot" in ws_str:
                    for item in list_agy_projects():
                        if item["name"] == "agy-cli-bot":
                            pid = item["id"]
                            break
                meta[cid] = {
                    "project_id": pid,
                    "is_observer": is_obs,
                    "is_scheduled": bool(is_sched),
                }
        except Exception:
            pass
    for scid in sched_cids:
        if scid in meta:
            meta[scid]["is_scheduled"] = True
        else:
            meta[scid] = {
                "project_id": "default-cli-project",
                "is_observer": False,
                "is_scheduled": True,
            }
    return meta


def _parse_transcript_cost_steps(tpath):
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
                    m = _MODEL_SETTINGS_RE.search(c)
                    if m:
                        cur_family = _canonical_model_family(m.group(1))
                if o.get("type") not in ("PLANNER_RESPONSE", "CHECKPOINT"):
                    continue
                inp = int(o.get("input_tokens") or 0)
                ca = int(o.get("cache_read_tokens") or 0)
                out = int(o.get("output_tokens") or 0)
                if not (inp or ca or out):
                    continue
                if o.get("model"):
                    cur_family = _canonical_model_family(o.get("model"))
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
                pi, pc, po = _google_model_rates_per_m(cur_family, ymd_utc, prompt_tokens=(inp + ca))
                cost_usd = (inp * pi + ca * pc + out * po) / 1_000_000.0
                nocache_usd = ((inp + ca) * pi + out * po) / 1_000_000.0
                sig = (int(o.get("step_index") or 0), ts, inp, ca, out)
                steps.append((hour_utc, cur_family, inp, ca, out, cost_usd, nocache_usd, sig))
    except Exception as e:
        log("parse transcript cost failed (%s): %r" % (tpath, e))
    if first_epoch == float("inf"):
        first_epoch = 0.0
    return first_epoch, steps, has_sched_marker


def _collect_cost_hourly_buckets():
    """Return list of (dt_utc_hour, cid, project_id, is_observer, is_scheduled, family, inp, ca, out, calls, cost_usd, nocache_usd).
    Uses mtime/size memory cache + persistent multi-process ledger so even pruned conversations retain history.
    """
    meta_map = _load_conv_meta_map()
    tpaths = glob.glob(os.path.join(BRAIN_ROOT, "*", ".system_generated", "logs", "transcript.jsonl"))

    dirty = False
    live_convs = {}
    with _cost_cache_lock:
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
            cached = _cost_mem_cache.get(cid)
            if cached and len(cached) >= 5 and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                first_ep, steps, has_sched = cached[2], cached[3], cached[4]
            else:
                first_ep, steps, has_sched = _parse_transcript_cost_steps(tp)
                _cost_mem_cache[cid] = (st.st_mtime_ns, st.st_size, first_ep, steps, has_sched)
                dirty = True
            live_convs[cid] = (st.st_mtime_ns, st.st_size, first_ep, steps, has_sched)

    # Deduplicate any forked parent steps in chronological conversation order & build per-conversation UTC hour buckets
    seen_sigs = set()
    conv_hours = {}
    for cid, (mtime_ns, size, _first_ep, steps, has_sched) in sorted(live_convs.items(), key=lambda kv: (kv[1][2], kv[0])):
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

    # Merge with persistent disk ledger (protects historical data if old brain/<cid> directories are ever pruned)
    archived_convs = {}
    try:
        os.makedirs(os.path.dirname(COST_LEDGER_FILE), exist_ok=True)
        with open(COST_LEDGER_LOCK, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                ledger = {}
                if os.path.isfile(COST_LEDGER_FILE):
                    try:
                        with open(COST_LEDGER_FILE, "r", encoding="utf-8") as rf:
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
                if dirty or not os.path.isfile(COST_LEDGER_FILE):
                    merged = dict(archived_convs)
                    merged.update(conv_hours)
                    tmp_path = f"{COST_LEDGER_FILE}.{os.getpid()}.tmp"
                    with open(tmp_path, "w", encoding="utf-8") as wf:
                        json.dump({"version": 1, "conversations": merged}, wf, separators=(",", ":"))
                    os.replace(tmp_path, COST_LEDGER_FILE)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        log("cost ledger sync error: %r" % e)

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


def _new_cost_agg():
    return {"inp": 0, "ca": 0, "out": 0, "calls": 0, "cost": 0.0, "nocache": 0.0}


def _add_cost_agg(agg, inp, ca, out, calls, cost, nocache):
    agg["inp"] += inp
    agg["ca"] += ca
    agg["out"] += out
    agg["calls"] += calls
    agg["cost"] += cost
    agg["nocache"] += nocache


def _fmt_m_tokens(tokens):
    if tokens <= 0:
        return "0 M"
    m = tokens / 1_000_000.0
    if m < 0.01:
        return f"{m:.4f} M"
    if m < 0.1:
        return f"{m:.3f} M"
    return f"{m:,.2f} M"


def _fmt_m_num(tokens):
    if tokens <= 0:
        return "0"
    m = tokens / 1_000_000.0
    if m < 0.01:
        return f"{m:.3f}"
    return f"{m:,.2f}"


def _fmt_usd(val):
    if val <= 0.0:
        return "$0.00"
    if val < 0.01:
        return f"${val:.4f}"
    if val < 1.0:
        return f"${val:.3f}"
    return f"${val:,.2f}"


def _agg_metrics(agg):
    tot_in = agg["inp"] + agg["ca"]
    tot_tok = tot_in + agg["out"]
    cache_pct = (agg["ca"] * 100.0 / tot_in) if tot_in > 0 else 0.0
    saved = max(0.0, agg["nocache"] - agg["cost"])
    save_pct = (saved * 100.0 / agg["nocache"]) if agg["nocache"] > 0 else 0.0
    filled = min(10, max(0, int(round(cache_pct / 10.0))))
    bar = "▓" * filled + "░" * (10 - filled)
    return tot_tok, cache_pct, bar, saved, save_pct


def _render_period_block(icon, title, sub_label, agg):
    tot_tok, cache_pct, bar, saved, save_pct = _agg_metrics(agg)
    if tot_tok == 0:
        return (
            f"{icon} <b>{title}</b> ({sub_label})\n"
            f"• 消耗：<code>0 M</code> · 缓存率：<code>0.0%</code> · 美金：<code>$0.00</code>"
        )
    save_note = (
        f"无缓存{_fmt_usd(agg['nocache'])} · 省{_fmt_usd(saved)} / -{save_pct:.0f}%"
        if saved >= 0.005 else f"共 {agg['calls']} 次调用"
    )
    return (
        f"{icon} <b>{title}</b> ({sub_label})\n"
        f"• 消耗：<b><code>{_fmt_m_tokens(tot_tok)}</code></b> "
        f"<code>(新{_fmt_m_num(agg['inp'])} + 缓{_fmt_m_num(agg['ca'])} + 出{_fmt_m_num(agg['out'])})</code>\n"
        f"• 缓存率：<b><code>{cache_pct:.1f}%</code></b> <code>[{bar}]</code>\n"
        f"• 折算美金：<b><code>{_fmt_usd(agg['cost'])}</code></b> <code>({save_note})</code>"
    )


def _make_cost_keyboard(view="overview", scope="all"):
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
        {
            "text": f"{'✓ ' if v == view else ''}{lbl}",
            "callback_data": f"cost:{v}:{scope}",
        }
        for v, lbl in views
    ]
    row_scopes = [
        {
            "text": f"{'✓ ' if s == scope else ''}{lbl}",
            "callback_data": f"cost:{view}:{s}",
        }
        for s, lbl in scopes
    ]
    row_refresh = [
        {"text": "🔄 刷新我的用量", "callback_data": f"cost:{view}:{scope}"},
        {"text": "📊 总套餐配额 (/usage)", "callback_data": "action:usage"},
    ]
    return {"inline_keyboard": [row_views, row_scopes, row_refresh]}


# Default weekly quota reset anchor: Friday 23:00 UTC (override via `/cost calibrate` or COST_CONFIG_FILE)
_DEFAULT_WEEKLY_RESET_UTC = (4, 23, 0)  # (weekday: 0=Mon..4=Fri..6=Sun, hour, minute)


def _load_weekly_reset_utc():
    if os.path.isfile(COST_CONFIG_FILE):
        try:
            with open(COST_CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f) or {}
            wd = int(cfg.get("weekly_reset_utc_weekday", _DEFAULT_WEEKLY_RESET_UTC[0])) % 7
            hr = int(cfg.get("weekly_reset_utc_hour", _DEFAULT_WEEKLY_RESET_UTC[1])) % 24
            mn = int(cfg.get("weekly_reset_utc_minute", _DEFAULT_WEEKLY_RESET_UTC[2])) % 60
            return wd, hr, mn
        except Exception:
            pass
    return _DEFAULT_WEEKLY_RESET_UTC


def _save_weekly_reset_utc(wd, hr, mn):
    os.makedirs(os.path.dirname(COST_CONFIG_FILE), exist_ok=True)
    tmp = f"{COST_CONFIG_FILE}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({
            "weekly_reset_utc_weekday": int(wd) % 7,
            "weekly_reset_utc_hour": int(hr) % 24,
            "weekly_reset_utc_minute": int(mn) % 60,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, f, indent=2)
    os.replace(tmp, COST_CONFIG_FILE)


def _get_weekly_quota_bounds(now_utc, local_tz):
    """Return (cycle_start_utc, cycle_end_utc, cycle_start_local, cycle_end_local, rem_str)."""
    wd, hr, mn = _load_weekly_reset_utc()
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


def _calibrate_weekly_reset_from_text(raw_arg):
    """Parse e.g. '5 days, 11 hours' or '5d 11h' or 'default' and persist new UTC weekly anchor."""
    s = (raw_arg or "").strip().lower()
    if s in ("default", "reset"):
        _save_weekly_reset_utc(*_DEFAULT_WEEKLY_RESET_UTC)
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
        # Google UI truncates remaining minutes (e.g. 5d 11h 09m -> '5 days, 11 hours'); snap to nearest whole hour
        if target.minute >= 30:
            target = (target + datetime.timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        else:
            target = target.replace(minute=0, second=0, microsecond=0)
    else:
        target = target.replace(second=0, microsecond=0)
    _save_weekly_reset_utc(target.weekday(), target.hour, target.minute)
    return True


def build_cost_panel(view="overview", scope="all", scope_key=None):
    if view not in ("overview", "daily", "models"):
        view = "overview"
    if scope not in ("all", "agent", "sched", "project"):
        scope = "all"

    tz, tz_lbl = _get_cost_tz()
    now_local = datetime.datetime.now(tz)
    now_utc = now_local.astimezone(datetime.timezone.utc)
    cur_proj = current_project(scope_key=scope_key) or "default-cli-project"
    proj_name = cur_proj
    for p_item in list_agy_projects():
        if p_item["id"] == cur_proj:
            proj_name = p_item["name"]
            break

    if scope == "agent":
        scope_desc = "👤 仅主对话 (不含后台观测/定时)"
    elif scope == "sched":
        scope_desc = "⏰ 定时任务消耗"
    elif scope == "project":
        scope_desc = f"📂 当前项目 ({html_mod.escape(proj_name)})"
    else:
        scope_desc = "🌐 全部消耗 (主对话 + 后台记忆 + 定时)"

    today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start_utc, _week_end_utc, week_start_loc, week_end_loc, week_rem_str = _get_weekly_quota_bounds(now_utc, tz)
    d7_start = today_start - datetime.timedelta(days=6)
    d14_start = today_start - datetime.timedelta(days=13)
    d30_start = today_start - datetime.timedelta(days=29)
    month_prefix = now_local.strftime("%Y-%m")
    today_ymd = now_local.strftime("%Y-%m-%d")

    agg_today = _new_cost_agg()
    agg_week = _new_cost_agg()
    agg_d7 = _new_cost_agg()
    agg_d30 = _new_cost_agg()
    agg_month = _new_cost_agg()
    by_day = {}
    by_model_today = {}
    by_model_week = {}
    by_model_month = {}

    records = _collect_cost_hourly_buckets()
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
            _add_cost_agg(agg_today, inp, ca, out, calls, cost_u, nocache_u)
            _add_cost_agg(by_model_today.setdefault(fam, _new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_utc_h >= week_start_utc:
            _add_cost_agg(agg_week, inp, ca, out, calls, cost_u, nocache_u)
            _add_cost_agg(by_model_week.setdefault(fam, _new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d7_start:
            _add_cost_agg(agg_d7, inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d14_start:
            _add_cost_agg(by_day.setdefault(ymd, _new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)
        if dt_loc >= d30_start:
            _add_cost_agg(agg_d30, inp, ca, out, calls, cost_u, nocache_u)
        if ymd.startswith(month_prefix):
            _add_cost_agg(agg_month, inp, ca, out, calls, cost_u, nocache_u)
            _add_cost_agg(by_model_month.setdefault(fam, _new_cost_agg()), inp, ca, out, calls, cost_u, nocache_u)

    header = (
        f"<b>💰 我的用量与缓存账单 (/cost)</b>\n"
        f"<code>口径: {scope_desc} · 本机统计 · {tz_lbl}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
    )
    wk_reset_note = f"{_WEEKDAY_CN[week_end_loc.weekday()]} {week_end_loc.strftime('%H:%M')} 重置"
    footer = (
        f"\n\n<i>🕒 刷新于 {now_local.strftime('%H:%M:%S')} · 周周期每{wk_reset_note} · "
        f"按 Google 官方阶梯及缓存计费</i>"
    )

    if view == "overview":
        b_today = _render_period_block("📅", "今日", now_local.strftime("%m-%d"), agg_today)
        week_lbl = f"{week_start_loc.strftime('%m-%d %H:%M')}起 · {week_rem_str}"
        b_week = _render_period_block("📆", "本周累计", week_lbl, agg_week)
        b_month = _render_period_block("🗓", "本月", month_prefix, agg_month)

        def _fmt_overview_models(mdict, title):
            lines = []
            for fam, magg in sorted(mdict.items(), key=lambda kv: -kv[1]["cost"]):
                mtok, mcr, _, _, _ = _agg_metrics(magg)
                mlbl = _MODEL_FAMILY_LABELS.get(fam, fam)
                lines.append(
                    f"• <code>{html_mod.escape(mlbl)}</code> · "
                    f"<code>{_fmt_m_tokens(mtok)}</code> · 缓<code>{mcr:.1f}%</code> · "
                    f"<b><code>{_fmt_usd(magg['cost'])}</code></b>"
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
            dtok, dcr, _, dsaved, _ = _agg_metrics(dagg)
            wk = _WEEKDAY_CN[d_dt.weekday()]
            day_lines.append(
                f"• <code>{d_dt.strftime('%m-%d')} {wk}</code> · "
                f"<b><code>{_fmt_m_tokens(dtok)}</code></b> · "
                f"缓<code>{dcr:.1f}%</code> · "
                f"<b><code>{_fmt_usd(dagg['cost'])}</code></b> "
                f"<code>(省{_fmt_usd(dsaved)})</code>"
            )
        if not day_lines:
            day_lines.append("• <code>近 14 天暂无 Token 消耗记录</code>")

        wk_tok, wk_cr, _, wk_saved, _ = _agg_metrics(agg_week)
        d7_tok, d7_cr, _, d7_saved, _ = _agg_metrics(agg_d7)
        d30_tok, d30_cr, _, d30_saved, _ = _agg_metrics(agg_d30)
        body = (
            "📅 <b>近 14 天每日明细</b>\n"
            + "\n".join(day_lines)
            + "\n\n📊 <b>配额周期与滚动合计</b>\n"
            + f"• <b>本周配额 ({week_rem_str})：</b><code>{_fmt_m_tokens(wk_tok)}</code> · 缓<code>{wk_cr:.1f}%</code> · "
              f"<b><code>{_fmt_usd(agg_week['cost'])}</code></b> <code>(省{_fmt_usd(wk_saved)})</code>\n"
            + f"• <b>近7天滚动：</b><code>{_fmt_m_tokens(d7_tok)}</code> · 缓<code>{d7_cr:.1f}%</code> · "
              f"<b><code>{_fmt_usd(agg_d7['cost'])}</code></b> <code>(省{_fmt_usd(d7_saved)})</code>\n"
            + f"• <b>近30天滚动：</b><code>{_fmt_m_tokens(d30_tok)}</code> · 缓<code>{d30_cr:.1f}%</code> · "
              f"<b><code>{_fmt_usd(agg_d30['cost'])}</code></b> <code>(省{_fmt_usd(d30_saved)})</code>"
        )

    else:  # view == "models"
        def _fmt_model_group(title, mdict):
            if not mdict:
                return f"<b>{title}</b>\n• <code>暂无消耗</code>"
            rows = [f"<b>{title}</b>"]
            for fam, magg in sorted(mdict.items(), key=lambda kv: -kv[1]["cost"]):
                mtok, mcr, _, msaved, _ = _agg_metrics(magg)
                mlbl = _MODEL_FAMILY_LABELS.get(fam, fam)
                tot_in = magg["inp"] + magg["ca"]
                pi, pc, _ = _google_model_rates_per_m(fam, now_utc.strftime("%Y-%m-%d"))
                eff_in = ((magg["inp"] * pi + magg["ca"] * pc) / tot_in) if tot_in > 0 else pi
                rows.append(
                    f"• <b>{html_mod.escape(mlbl)}</b>\n"
                    f"  <code>{_fmt_m_tokens(mtok)}</code> · 缓<code>{mcr:.1f}%</code> "
                    f"(等效输入<code>${eff_in:.2f}/M</code>) · "
                    f"<b><code>{_fmt_usd(magg['cost'])}</code></b> <code>(省{_fmt_usd(msaved)})</code>"
                )
            return "\n".join(rows)

        ymd_now = now_utc.strftime("%Y-%m-%d")
        f_pi, f_pc, f_po = _google_model_rates_per_m("gemini-3.8-flash", ymd_now)
        h_pi, h_pc, h_po = _google_model_rates_per_m("gemini-4-hydrogen", ymd_now)
        c_pi, c_pc, c_po = _google_model_rates_per_m("gemini-4-carbon", ymd_now)
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

    return header + body + footer, _make_cost_keyboard(view=view, scope=scope)


def cmd_cost(chat_id, raw_rest="", thread_id=None, scope_key=None):
    skey = scope_key or scope_key_for(chat_id, thread_id)
    rest = (raw_rest or "").strip()
    if rest.lower().startswith("reset "):
        ok = _calibrate_weekly_reset_from_text(rest[6:])
        if not ok:
            send(
                chat_id,
                "用法：<code>/cost reset 5d 11h</code>（或直接粘贴 <code>/cost reset 5 days, 11 hours</code> 校准账号周配额刷新时间）",
                parse_mode="HTML",
                thread_id=thread_id,
            )
            return
        tokens = []
    else:
        tokens = [t.lower() for t in rest.split() if t.strip()]
    view = "overview"
    scope = "all"
    for t in tokens:
        if t in ("day", "daily", "days", "14d", "7d"):
            view = "daily"
        elif t in ("model", "models", "price", "pricing"):
            view = "models"
        elif t in ("overview", "summary"):
            view = "overview"
        elif t in ("agent", "main", "user"):
            scope = "agent"
        elif t in ("sched", "schedule", "cron", "timer"):
            scope = "sched"
        elif t in ("project", "proj", "repo"):
            scope = "project"
        elif t in ("all", "global"):
            scope = "all"
    text, kb = build_cost_panel(view=view, scope=scope, scope_key=skey)
    send(chat_id, text, parse_mode="HTML", reply_markup=kb, thread_id=thread_id)


# ---------------------------------------------------------------- overall Antigravity subscription plan quota card (/usage)
_usage_fetch_lock = threading.Lock()
QUOTA_LOCK_FILE = "/tmp/agy_quota_usage.lock"


def _load_cached_plan_quota():
    if not os.path.isfile(QUOTA_CACHE_FILE):
        return None
    try:
        with open(QUOTA_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("groups"), list) and data["groups"]:
            return data
    except Exception:
        pass
    return None


def _parse_iso_z(ts_str):
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


def fetch_plan_quota_data(force_live=True):
    """Fetch live account subscription quota from `agy -p /usage --output-format json` (0 LLM tokens).
    Returns (snapshot_dict_or_none, is_cached_fallback, error_str).
    """
    with _usage_fetch_lock:
        cached = _load_cached_plan_quota()
        now_ts = time.time()
        if cached:
            age = now_ts - float(cached.get("fetched_at_epoch") or 0)
            if (not force_live and age < 60.0) or (force_live and age < 5.0):
                return cached, False, ""

        env = dict(os.environ)
        env["AGY_INTERNAL_OBSERVER"] = "1"
        env["PATH"] = os.path.join(HOME, ".local/bin") + ":" + env.get("PATH", "")
        env.setdefault("HOME", HOME)
        try:
            rc, out, err = _run_subprocess_group(
                [AGY_BIN, "-p", "/usage", "--output-format", "json", "--print-timeout", "20s"],
                cwd=HOME,
                timeout_s=25,
                env=env,
                shell=False,
            )
            if rc != 0:
                raise RuntimeError((err or out or f"exit {rc}").strip()[:180])

            payload_obj = None
            for line in reversed([ln.strip() for ln in out.splitlines() if ln.strip()]):
                if line.startswith("{") and line.endswith("}"):
                    try:
                        cand = json.loads(line)
                        if isinstance(cand, dict) and ("command" in cand or "response" in cand):
                            payload_obj = cand
                            break
                    except Exception:
                        continue
            if payload_obj is None:
                payload_obj = json.loads(out.strip())

            cmd_data = ((payload_obj.get("command") or {}).get("data")) or {}
            groups = cmd_data.get("groups") or []
            if not groups:
                raise RuntimeError("Empty quota groups in CLI response")

            # Auto-sync weekly reset anchor for /cost from official gemini-weekly reset_time
            for grp in groups:
                for b in (grp.get("buckets") or []):
                    if b.get("id") == "gemini-weekly" or (
                        "gemini" in (grp.get("name") or "").lower() and b.get("window") == "weekly"
                    ):
                        rst_dt = _parse_iso_z(b.get("reset_time"))
                        if rst_dt is not None:
                            _save_weekly_reset_utc(rst_dt.weekday(), rst_dt.hour, rst_dt.minute)
                        break

            snap = {
                "fetched_at_epoch": time.time(),
                "fetched_at_iso": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "description": cmd_data.get("description") or "",
                "groups": groups,
            }
            os.makedirs(os.path.dirname(QUOTA_CACHE_FILE), exist_ok=True)
            try:
                with open(QUOTA_LOCK_FILE, "w") as lf:
                    fcntl.flock(lf, fcntl.LOCK_EX)
                    tmp = f"{QUOTA_CACHE_FILE}.{os.getpid()}.tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        json.dump(snap, f, ensure_ascii=False, indent=2)
                    os.replace(tmp, QUOTA_CACHE_FILE)
            except Exception as we:
                log("quota cache write warning: %r" % we)
            return snap, False, ""
        except Exception as e:
            err_msg = str(e)
            log("fetch_plan_quota_data failed: %s" % err_msg)
            if cached:
                return cached, True, err_msg
            return None, False, err_msg


def _make_usage_keyboard():
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


def _fmt_quota_countdown(rst_utc, now_utc):
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


def build_usage_panel(force_live=True):
    tz, tz_lbl = _get_cost_tz()
    now_local = datetime.datetime.now(tz)
    now_utc = now_local.astimezone(datetime.timezone.utc)
    snap, is_fallback, err_str = fetch_plan_quota_data(force_live=force_live)

    header = (
        "<b>📊 反重力总套餐配额卡片 (/usage)</b>\n"
        f"<code>口径: ☁️ 官方云端总套餐实时配额 (全端共享) · {tz_lbl}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
    )
    kb = _make_usage_keyboard()

    if not snap:
        body = (
            "⚠️ <b>暂无法获取云端总套餐实时配额</b>\n"
            f"<code>{html_mod.escape(err_str[:220] or '未知错误')}</code>\n\n"
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

            rst_utc = _parse_iso_z(b.get("reset_time"))
            if rst_utc is not None:
                rst_loc = rst_utc.astimezone(tz)
                if rst_loc.date() == now_local.date():
                    rst_str = f"今日 {rst_loc.strftime('%H:%M')}"
                else:
                    rst_str = f"{rst_loc.strftime('%m-%d')} {_WEEKDAY_CN[rst_loc.weekday()]} {rst_loc.strftime('%H:%M')}"
                cd_str = _fmt_quota_countdown(rst_utc, now_utc)
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
            f"\n\n<i>⚠️ 云端刷新超时，展示 {ft_loc.strftime('%m-%d %H:%M:%S')} 最近缓存 · "
            f"本机明细请看 /cost</i>"
        )
    else:
        footer = (
            f"\n\n<i>🕒 实时同步于 {ft_loc.strftime('%H:%M:%S')} · "
            f"0 Token 直连官方配额接口 · 本机明细请看 /cost</i>"
        )

    body = "\n\n".join(group_blocks) + tip
    return header + body + footer, kb


def cmd_usage(chat_id, raw_rest="", edit_msg_id=None, thread_id=None):
    """Asynchronously fetch and send/edit overall Antigravity subscription plan quota card."""
    placeholder_mid = edit_msg_id
    if not placeholder_mid:
        placeholder_mid = send(
            chat_id,
            "⏳ <b>正在查询反重力总套餐实时配额...</b>",
            parse_mode="HTML",
            thread_id=thread_id,
        )

    def _bg():
        try:
            panel_text, panel_kb = build_usage_panel(force_live=True)
            if placeholder_mid:
                r = tg(
                    "editMessageText",
                    chat_id=chat_id,
                    message_id=placeholder_mid,
                    text=panel_text,
                    parse_mode="HTML",
                    reply_markup=panel_kb,
                )
                if r is None or not r.json().get("ok"):
                    desc = (r.json().get("description", "") if r is not None else "").lower()
                    if "message is not modified" not in desc:
                        send(chat_id, panel_text, parse_mode="HTML", reply_markup=panel_kb, thread_id=thread_id)
            else:
                send(chat_id, panel_text, parse_mode="HTML", reply_markup=panel_kb, thread_id=thread_id)
        except Exception as e:
            log("cmd_usage error: %r" % e)
            send(chat_id, f"❌ 查询总套餐配额失败: <code>{html_mod.escape(str(e))}</code>",
                 parse_mode="HTML", thread_id=thread_id)

    threading.Thread(target=_bg, daemon=True).start()


def _send_schedule_created(chat_id, t, title_prefix="定时任务", thread_id=None):
    nxt = scheduler.parse_iso_utc(t["state"]["next_run_at"])
    tz, _ = scheduler.get_scheduler_tz()
    nxt_str = nxt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S") if nxt else "未定"
    rem = scheduler.format_countdown(nxt)
    ttype = t.get("task_type")
    extra = (
        f"\n• 模型: <code>{t['execution']['model']}</code> (隔离会话)"
        if ttype in ("agent", "browser")
        else "\n• 通道: <code>原生零 Token 直连</code>"
    )
    silent_str = "开启" if t.get("delivery", {}).get("silent_if_empty") else "关闭"
    tgt_tid = t.get("delivery", {}).get("target_thread_id")
    route_note = f"\n• 投递位置: <code>Topic #{tgt_tid}</code>" if tgt_tid else ""
    send(
        chat_id,
        f"✅ 已创建{title_prefix} <b>{html_mod.escape(t['name'])}</b> (<code>{t['id']}</code>)\n"
        f"• 计划: <code>{html_mod.escape(t['schedule_expr'])}</code> ({t['schedule_type']})"
        f"{extra}{route_note}\n"
        f"• 静默空结果: <code>{silent_str}</code>\n"
        f"• 下次执行: <code>{nxt_str}</code> (<b>{rem}</b>)",
        parse_mode="HTML",
        thread_id=thread_id,
    )


def cmd_schedule(chat_id, raw_rest="", thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    rest = (raw_rest or "").strip()
    if not rest or rest.lower() in ("list", "show", "panel"):
        text, kb = scheduler.build_schedule_panel(view="list", bot_instance_id=BOT_INSTANCE_ID)
        send(chat_id, text, parse_mode="HTML", reply_markup=kb, thread_id=norm_tid)
        return

    parts = rest.split(None, 2)
    subcmd = parts[0].lower()

    if subcmd in ("help", "-h", "--help"):
        help_text = (
            "<b>⏰ 定时任务完整语法指南</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "<b>1. 管理与查看</b>\n"
            "• <code>/schedule</code> — 打开可视化任务控制面板\n"
            "• <code>/schedule run &lt;id&gt;</code> — 立即触发一次指定任务\n"
            "• <code>/schedule pause &lt;id&gt;</code> / <code>/schedule resume &lt;id&gt;</code>\n"
            "• <code>/schedule del &lt;id&gt;</code> — 删除任务\n\n"
            "<b>2. 四类任务创建语法</b>\n"
            "• <b>零Token账单/套餐配额报表</b>:\n"
            "  <code>/schedule cost 0 9 * * *</code>  或  <code>/schedule usage 0 9 * * *</code>\n"
            "• <b>Agent智能任务</b> (如定时查收邮件，默认 <code>gemini-3.8-flash-low</code>):\n"
            "  <code>/schedule add 0 9 * * * 用 mail-ctl 检查未读重要邮件并总结</code>\n"
            "• <b>浏览器自动化任务</b> (如定时登录保活/巡检截图):\n"
            "  <code>/schedule browser 30 9 * * * 用 google-browser 检查登录状态</code>\n"
            "• <b>零Token纯脚本任务</b>:\n"
            "  <code>/schedule script 0 0 * * * python3 /path/to/job.py</code>\n"
            "• <b>单次倒计时提醒</b>:\n"
            "  <code>/schedule in 30m 提醒我检查部署状态</code>\n"
            "  <code>/schedule add in 1h 30m 检查后台构建结果</code>\n\n"
            "<b>3. 可选参数</b> (置于时间表达式前)\n"
            "• <code>--loud</code> (每次必通知) / <code>--silent</code> (无新内容静默)\n"
            "• <code>--model gemini-3.8-flash-high</code> (覆盖默认轻量模型)\n"
            "• <code>--timeout 300</code> (自定义超时秒数)\n"
            "<i>注: 周期 Cron 时区为 UTC+8，安全最小间隔为 5 分钟；在群 Topic 内创建会自动把结果推回该 Topic。</i>"
        )
        send(chat_id, help_text, parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("del", "delete", "rm"):
        if len(parts) < 2:
            send(chat_id, "用法：<code>/schedule del &lt;task_id&gt;</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        tid = parts[1].strip()
        ok = scheduler.task_mgr.delete_task(tid)
        if ok:
            send(chat_id, f"✅ 已删除定时任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        else:
            send(chat_id, f"❌ 未找到任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("pause", "stop"):
        if len(parts) < 2:
            send(chat_id, "用法：<code>/schedule pause &lt;task_id&gt;</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        tid = parts[1].strip()
        res = scheduler.task_mgr.toggle_task(tid, enable=False)
        if res is False:
            send(chat_id, f"⏸ 已暂停定时任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        else:
            send(chat_id, f"❌ 未找到任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("resume", "start", "enable"):
        if len(parts) < 2:
            send(chat_id, "用法：<code>/schedule resume &lt;task_id&gt;</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        tid = parts[1].strip()
        res = scheduler.task_mgr.toggle_task(tid, enable=True)
        if res is True:
            send(chat_id, f"▶ 已启用定时任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        else:
            send(chat_id, f"❌ 未找到任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("run", "trigger", "exec"):
        if len(parts) < 2:
            send(chat_id, "用法：<code>/schedule run &lt;task_id&gt;</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        tid = parts[1].strip()
        t = scheduler.task_mgr.get_task(tid)
        if not t:
            send(chat_id, f"❌ 未找到任务 <code>{html_mod.escape(tid)}</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        send(chat_id, f"⚡ 正在触发定时任务 <b>{html_mod.escape(t.get('name', ''))}</b>...",
             parse_mode="HTML", thread_id=norm_tid)
        t_chat = t.get("delivery", {}).get("target_chat_id") or chat_id
        t_thread = _normalize_thread_id(t.get("delivery", {}).get("target_thread_id"))
        job_q.put((t_chat, t_thread, scope_key_for(t_chat, t_thread), ("__SCHEDULED__", t)))
        return

    if subcmd in ("cost", "bill"):
        sub_rest = rest[len(subcmd):].strip()
        try:
            if not sub_rest:
                sched_expr, custom_title, opts = "0 9 * * *", "", {}
            else:
                sched_expr, custom_title, opts = scheduler.split_schedule_and_body(sub_rest)
            t = scheduler.task_mgr.create_task(
                name=custom_title[:24] if custom_title else "每日晨报与Token账单",
                schedule_expr=sched_expr,
                task_type="cost_report",
                payload={"view": "overview", "scope": "all"},
                target_chat_id=chat_id,
                target_thread_id=norm_tid,
                project=current_project(skey) or "agy-cli-bot",
                workdir=current_workdir(skey),
                silent_if_empty=False,
                bot_instance_id=BOT_INSTANCE_ID,
            )
            _send_schedule_created(chat_id, t, title_prefix="定时报表任务", thread_id=norm_tid)
        except Exception as e:
            send(chat_id, f"❌ 创建失败: {html_mod.escape(str(e))}", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("usage", "quota"):
        sub_rest = rest[len(subcmd):].strip()
        try:
            if not sub_rest:
                sched_expr, custom_title, opts = "0 9 * * *", "", {}
            else:
                sched_expr, custom_title, opts = scheduler.split_schedule_and_body(sub_rest)
            t = scheduler.task_mgr.create_task(
                name=custom_title[:24] if custom_title else "每日总套餐配额播报",
                schedule_expr=sched_expr,
                task_type="usage_report",
                payload={},
                target_chat_id=chat_id,
                target_thread_id=norm_tid,
                project=current_project(skey) or "agy-cli-bot",
                workdir=current_workdir(skey),
                silent_if_empty=False,
                bot_instance_id=BOT_INSTANCE_ID,
            )
            _send_schedule_created(chat_id, t, title_prefix="定时套餐配额任务", thread_id=norm_tid)
        except Exception as e:
            send(chat_id, f"❌ 创建失败: {html_mod.escape(str(e))}", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("script", "cmd"):
        sub_rest = rest[len(subcmd):].strip()
        try:
            sched_expr, cmd_str, opts = scheduler.split_schedule_and_body(sub_rest)
            if not cmd_str:
                send(chat_id, "用法：<code>/schedule script 0 0 * * * python3 /path/to/script.py</code>",
                     parse_mode="HTML", thread_id=norm_tid)
                return
            t = scheduler.task_mgr.create_task(
                name=cmd_str[:25],
                schedule_expr=sched_expr,
                task_type="script",
                payload={"script": cmd_str},
                target_chat_id=chat_id,
                target_thread_id=norm_tid,
                project=current_project(skey) or "agy-cli-bot",
                workdir=current_workdir(skey),
                timeout_secs=opts.get("timeout_secs"),
                silent_if_empty=opts.get("silent_if_empty"),
                bot_instance_id=BOT_INSTANCE_ID,
            )
            _send_schedule_created(chat_id, t, title_prefix="定时脚本任务", thread_id=norm_tid)
        except Exception as e:
            send(chat_id, f"❌ 创建失败: {html_mod.escape(str(e))}", parse_mode="HTML", thread_id=norm_tid)
        return

    if subcmd in ("browser", "web"):
        sub_rest = rest[len(subcmd):].strip()
        try:
            sched_expr, prompt, opts = scheduler.split_schedule_and_body(sub_rest)
            if not prompt:
                send(chat_id, "用法：<code>/schedule browser 30 9 * * * 用 google-browser 检查登录状态</code>",
                     parse_mode="HTML", thread_id=norm_tid)
                return
            t = scheduler.task_mgr.create_task(
                name=prompt[:22],
                schedule_expr=sched_expr,
                task_type="browser",
                payload={"prompt": prompt},
                target_chat_id=chat_id,
                target_thread_id=norm_tid,
                model=opts.get("model") or "gemini-3.8-flash-low",
                session_mode="isolated",
                project=current_project(skey) or "agy-cli-bot",
                workdir=current_workdir(skey),
                timeout_secs=opts.get("timeout_secs"),
                silent_if_empty=opts.get("silent_if_empty"),
                bot_instance_id=BOT_INSTANCE_ID,
            )
            _send_schedule_created(chat_id, t, title_prefix="浏览器定时任务", thread_id=norm_tid)
        except Exception as e:
            send(chat_id, f"❌ 创建失败: {html_mod.escape(str(e))}", parse_mode="HTML", thread_id=norm_tid)
        return

    # Either explicit `/schedule add ...` OR direct shorthand `/schedule in 30m ...` / `/schedule 0 9 * * * ...`
    add_rest = rest[len(subcmd):].strip() if subcmd in ("add", "new", "agent") else rest
    try:
        sched_expr, prompt, opts = scheduler.split_schedule_and_body(add_rest)
        if not prompt:
            raise ValueError("缺少任务描述 (prompt)")
        t = scheduler.task_mgr.create_task(
            name=prompt[:22],
            schedule_expr=sched_expr,
            task_type="agent",
            payload={"prompt": prompt},
            target_chat_id=chat_id,
            target_thread_id=norm_tid,
            model=opts.get("model") or "gemini-3.8-flash-low",
            session_mode="isolated",
            project=current_project(skey) or "agy-cli-bot",
            workdir=current_workdir(skey),
            timeout_secs=opts.get("timeout_secs"),
            silent_if_empty=opts.get("silent_if_empty"),
            bot_instance_id=BOT_INSTANCE_ID,
        )
        _send_schedule_created(chat_id, t, title_prefix="定时任务", thread_id=norm_tid)
    except Exception as e:
        if subcmd in ("add", "new", "agent", "in") or rest.startswith("@") or rest[0].isdigit() or rest.startswith("*"):
            send(
                chat_id,
                f"❌ 创建失败: {html_mod.escape(str(e))}\n"
                f"示例: <code>/schedule add 0 9 * * * 检查未读邮件</code> 或 <code>/schedule in 30m 提醒我检查服务</code>",
                parse_mode="HTML",
                thread_id=norm_tid,
            )
        else:
            cmd_schedule(chat_id, "help", thread_id=norm_tid, scope_key=skey)


def cmd_compact(chat_id, raw_rest, thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    rest = (raw_rest or "").strip()
    if not rest:
        enqueue_compact(chat_id, "", thread_id=norm_tid, scope_key=skey)
        return

    parts = rest.split()
    sub = parts[0].lower()

    if sub in ("status", "info", "panel"):
        cmd_context(chat_id, thread_id=norm_tid, scope_key=skey)
        return

    if sub in ("on", "enable", "true"):
        update_scope_state(skey, auto_compact=True)
        thresh = int(get_scope_value(skey, "auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS)
        save_state()
        send(chat_id, f"✅ 已开启自动上下文压缩（阈值：<code>{format_tokens_k(thresh)}</code>）",
             parse_mode="HTML", thread_id=norm_tid)
        return

    if sub in ("off", "disable", "false"):
        update_scope_state(skey, auto_compact=False)
        save_state()
        send(chat_id, "⏸ 已关闭桥接层自动预压缩（仍保留手动 <code>/compact</code> 与 OAuth 失败自愈重试）",
             parse_mode="HTML", thread_id=norm_tid)
        return

    if sub in ("auto", "threshold", "limit"):
        if len(parts) < 2:
            cmd_context(chat_id, thread_id=norm_tid, scope_key=skey)
            return
        parsed = _parse_token_threshold(parts[1])
        if parsed is None:
            send(chat_id, "用法：<code>/compact auto 160k</code>（范围支持 50k ~ 245k）",
                 parse_mode="HTML", thread_id=norm_tid)
            return
        update_scope_state(skey, auto_compact=True, auto_compact_tokens=parsed)
        save_state()
        send(chat_id, f"✅ 自动压缩已开启，触发阈值设为 <code>{format_tokens_k(parsed)}</code> tokens",
             parse_mode="HTML", thread_id=norm_tid)
        return

    # Support shorthand `/compact 160k` when single argument looks like a token threshold
    if len(parts) == 1:
        parsed_single = _parse_token_threshold(sub)
        if parsed_single is not None:
            update_scope_state(skey, auto_compact=True, auto_compact_tokens=parsed_single)
            save_state()
            send(chat_id, f"✅ 自动压缩触发阈值已设为 <code>{format_tokens_k(parsed_single)}</code> tokens",
                 parse_mode="HTML", thread_id=norm_tid)
            return

    # Otherwise treat `rest` as custom focus instructions for `/compact <instructions>`!
    enqueue_compact(chat_id, rest, thread_id=norm_tid, scope_key=skey)


def cmd_retry(chat_id, raw_rest="", thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    sc = get_scope_state(skey)
    lt = sc.get("last_turn")
    if not isinstance(lt, dict) or not lt.get("prompt"):
        send(chat_id, "ℹ️ 当前会话/Topic 还没有可重试的上一轮指令。", thread_id=norm_tid)
        return
    base_prompt = lt["prompt"]
    extra = (raw_rest or "").strip()
    retry_prompt = f"{base_prompt}\n\n[重试附加说明]: {extra}" if extra else base_prompt
    snip = html_mod.escape((lt.get("display") or base_prompt)[:80])
    extra_line = f"\n• <b>附加说明：</b><code>{html_mod.escape(extra[:80])}</code>" if extra else ""
    send(
        chat_id,
        f"🔁 <b>正在重试上一轮请求</b>\n• <b>内容：</b><code>{snip}</code>{extra_line}",
        parse_mode="HTML",
        thread_id=norm_tid,
    )
    enqueue(chat_id, retry_prompt, thread_id=norm_tid, scope_key=skey)


def _format_undo_changes_lines(changes, limit=12):
    icons = {"created": "➕ 删除新建", "modified": "↩️ 还原修改", "deleted": "♻️ 恢复删除"}
    lines = []
    for ch in changes[:limit]:
        act = ch.get("action") or "modified"
        lines.append(f"• {icons.get(act, act)} <code>{html_mod.escape(ch.get('path', '?'))}</code>")
    if len(changes) > limit:
        lines.append(f"• … 其余 <code>{len(changes) - limit}</code> 个文件")
    return "\n".join(lines)


def cmd_undo(chat_id, raw_rest="", thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    with session_lock:
        busy_here = turn_running and (turn_running_scope == skey)
    if busy_here:
        send(chat_id, "⏳ 当前会话仍有任务正在运行，请先 <code>/cancel</code> 后再执行 <code>/undo</code>。",
             parse_mode="HTML", thread_id=norm_tid)
        return

    arg = (raw_rest or "").strip().lower()
    sc = get_scope_state(skey)
    stack = list(sc.get("undo_stack") or [])
    if not stack:
        send(chat_id, "ℹ️ 当前会话/Topic 没有可撤销的工作区文件改动检查点。", thread_id=norm_tid)
        return

    entry = stack[-1]
    changes = entry.get("changes") or []
    snip = html_mod.escape((entry.get("prompt") or "")[:60])

    if arg in ("preview", "list", "info", "diff"):
        lines = [
            f"<b>⏪ 最近可撤销检查点（共 {len(stack)} 个）</b>",
            f"• <b>来源任务：</b><code>{snip}</code>",
            f"• <b>工作目录：</b><code>{html_mod.escape(entry.get('workdir', ''))}</code>",
            f"• <b>涉及文件（{len(changes)} 个）：</b>",
            _format_undo_changes_lines(changes),
            "\n<i>发送 <code>/undo</code> 即可回滚，或发送 <code>/undo force</code> 忽略外部修改冲突强行回滚。</i>",
        ]
        kb = {"inline_keyboard": [[{"text": "⏪ 立即撤销 (/undo)", "callback_data": "undo:exec"}]]}
        send(chat_id, "\n".join(lines), parse_mode="HTML", reply_markup=kb, thread_id=norm_tid)
        return

    force = arg in ("force", "-f", "--force")
    ok, applied, conflicts, _ = _apply_checkpoint_changes(entry, reverse=False, force=force)
    if not ok:
        conflict_lines = "\n".join(f"• <code>{html_mod.escape(c)}</code>" for c in conflicts[:10])
        kb = {"inline_keyboard": [[{"text": "⚠️ 强制覆盖撤销 (/undo force)", "callback_data": "undo:force"}]]}
        send(
            chat_id,
            f"⚠️ <b>安全拦截：检测到以下文件在本轮之后又被外部修改过</b>\n\n"
            f"{conflict_lines}\n\n"
            f"为防止误覆盖你的后续改动，本次未动任何文件。如确认丢弃上述外部改动并回滚，请点击下方按钮或输入 <code>/undo force</code>。",
            parse_mode="HTML",
            reply_markup=kb,
            thread_id=norm_tid,
        )
        return

    reverted_paths = [rel for _act, rel in applied]
    ts_str = datetime.datetime.now().strftime("%H:%M:%S")
    notice = (
        f"[系统提示：用户在 {ts_str} 执行了 /undo，已将工作区文件回滚恢复到改动前状态"
        f"（涉及：{', '.join(reverted_paths[:10])}{' 等' if len(reverted_paths) > 10 else ''}）。"
        f"请以当前磁盘上真实文件内容为准，勿假设上一轮的编辑仍然存在。]"
    )
    with state_lock:
        sc_w = _ensure_scope_locked(skey)
        st_list = list(sc_w.get("undo_stack") or [])
        if st_list and st_list[-1].get("id") == entry.get("id"):
            popped = st_list.pop()
        else:
            popped = entry
        rd_list = list(sc_w.get("redo_stack") or [])
        rd_list.append(popped)
        sc_w["undo_stack"] = st_list
        sc_w["redo_stack"] = rd_list[-_UNDO_STACK_LIMIT:]
        sc_w["pending_undo_notice"] = notice
        _sync_top_level_mirrors_locked()
    save_state()

    kb = {"inline_keyboard": [[{"text": "↪️ 取消撤销 (Redo)", "callback_data": "undo:redo"}]]}
    send(
        chat_id,
        f"⏪ <b>已撤销工作区文件改动</b>（剩余可撤销 {len(stack) - 1} 步）\n"
        f"• <b>原任务：</b><code>{snip}</code>\n"
        f"• <b>恢复清单（{len(applied)} 个文件）：</b>\n"
        f"{_format_undo_changes_lines(changes)}\n\n"
        f"<i>下次发消息会自动通知 Agent 以当前磁盘状态为准。</i>",
        parse_mode="HTML",
        reply_markup=kb,
        thread_id=norm_tid,
    )


def cmd_redo(chat_id, thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    with session_lock:
        busy_here = turn_running and (turn_running_scope == skey)
    if busy_here:
        send(chat_id, "⏳ 当前会话仍有任务正在运行，请稍后再试。", thread_id=norm_tid)
        return

    sc = get_scope_state(skey)
    rd = list(sc.get("redo_stack") or [])
    if not rd:
        send(chat_id, "ℹ️ 没有可重做（取消撤销）的检查点。", thread_id=norm_tid)
        return

    entry = rd[-1]
    ok, applied, conflicts, _ = _apply_checkpoint_changes(entry, reverse=True, force=True)
    if not ok:
        send(chat_id, f"❌ Redo 失败：{html_mod.escape(', '.join(conflicts[:5]))}",
             parse_mode="HTML", thread_id=norm_tid)
        return

    with state_lock:
        sc_w = _ensure_scope_locked(skey)
        rd_list = list(sc_w.get("redo_stack") or [])
        popped = rd_list.pop() if rd_list else entry
        st_list = list(sc_w.get("undo_stack") or [])
        st_list.append(popped)
        sc_w["redo_stack"] = rd_list
        sc_w["undo_stack"] = st_list[-_UNDO_STACK_LIMIT:]
        sc_w["pending_undo_notice"] = None
        _sync_top_level_mirrors_locked()
    save_state()

    snip = html_mod.escape((entry.get("prompt") or "")[:60])
    send(
        chat_id,
        f"↪️ <b>已恢复被撤销的改动</b>\n"
        f"• <b>原任务：</b><code>{snip}</code>\n"
        f"• <b>重放文件（{len(applied)} 个）：</b>\n"
        f"{_format_undo_changes_lines(entry.get('changes') or [])}",
        parse_mode="HTML",
        thread_id=norm_tid,
    )


def _role_badge(role):
    return {
        "coordinator": "👑 Coordinator (主控)",
        "worker": "🛠 Worker (专职子Bot)",
        "peer": "🤝 Peer (平级可调度)",
    }.get(role, str(role))


def build_team_panel(scope_key=None):
    roster = bot_bus.list_roster(include_offline=True)
    jobs = bot_bus.list_jobs(limit=5)
    me = _current_bot_handle()
    my_cfg = _current_bot_cfg()

    lines = [
        "<b>🤝 Antigravity Bot Team Bus</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"• <b>当前 Bot</b>: <code>@{html_mod.escape(me)}</code> — {_role_badge(my_cfg.get('role'))}",
    ]
    m_chat = int(my_cfg.get("mirror_chat_id") or 0)
    m_tid = _normalize_thread_id(my_cfg.get("mirror_thread_id"))
    if m_chat:
        m_label = _format_scope_badge(m_chat, m_tid)
        lines.append(f"• <b>播报频道</b>: <code>{html_mod.escape(m_label)}</code>")
    else:
        lines.append("• <b>播报频道</b>: <code>未绑定（静默后台交付）</code>")

    lines.append("\n<b>📋 在线花名册 (Roster)</b>")
    if not roster:
        lines.append("<i>暂无已注册 Bot</i>")
    for b in roster:
        st_icon = "🔴 离线" if not b["online"] else ("🟡 忙碌" if b["busy"] else "🟢 空闲")
        r_tag = {"coordinator": "👑", "worker": "🛠", "peer": "🤝"}.get(b["role"], "🤖")
        self_tag = " <i>(我)</i>" if b["handle"] == me else ""
        mdl = b.get("default_model") or "(跟随会话)"
        wdir = (b.get("default_workdir") or "").replace(HOME, "~") or "~"
        lines.append(
            f"{st_icon} {r_tag} <b><code>@{html_mod.escape(b['handle'])}</code></b>{self_tag} · {html_mod.escape(b.get('display_name') or '')}\n"
            f"   角色: <code>{html_mod.escape(b['role'])}</code> · 模型: <code>{html_mod.escape(mdl)}</code> · 队列: <code>{b.get('queue_depth', 0)}</code>\n"
            f"   目录: <code>{html_mod.escape(wdir)}</code>"
            + (f" · 专长: {html_mod.escape(b['specialty'])}" if b.get("specialty") else "")
            + (f"\n   执行中: <code>{html_mod.escape(str(b['current_job']))}</code>" if b.get("current_job") else "")
        )

    lines.append("\n<b>📦 最近派工单 (Jobs)</b>")
    if not jobs:
        lines.append("<i>暂无派工记录 — 正常对话或用 /delegate @bot 任务 即可派单</i>")
    else:
        for j in jobs:
            st = j.get("status")
            j_icon = {"done": "✅", "running": "⏳", "queued": "📋", "error": "⚠️", "cancelled": "🛑"}.get(st, "ℹ️")
            usd = (j.get("usage") or {}).get("usd")
            usd_s = f" · {_fmt_usd(float(usd))}" if usd else ""
            dur_s = (j.get("usage") or {}).get("duration_s")
            dur_txt = f" · {dur_s}s" if dur_s is not None else ""
            lbl = j.get("label") or (j.get("prompt") or "")[:28]
            lines.append(
                f"{j_icon} <code>{html_mod.escape(j.get('job_id') or '')}</code> "
                f"<code>@{html_mod.escape(j.get('from_bot') or '')}</code>→<code>@{html_mod.escape(j.get('target_bot') or '')}</code>"
                f" ({html_mod.escape(lbl[:28])}{dur_txt}{usd_s})"
            )

    kb_rows = [
        [
            {"text": "👑 设我为唯一主控 (其余→Worker)", "callback_data": "team:sole_coord"},
            {"text": "🤝 全员设平级 (Peer)", "callback_data": "team:all_peer"},
        ],
    ]
    for b in roster[:6]:
        h = b["handle"]
        next_r = {"coordinator": "worker", "worker": "peer", "peer": "coordinator"}.get(b["role"], "worker")
        w_mdl = b.get("default_model") or "default"
        kb_rows.append([
            {"text": f"切换 @{h} ({b['role']}→{next_r})", "callback_data": f"team:cycle:{h[:40]}"},
            {"text": f"⚡ 模型:{'flash-low' if 'flash-low' in w_mdl else '跟随'}", "callback_data": f"team:model:{h[:40]}"},
        ])
    kb_rows.append([
        {"text": "📌 播报台设在此处", "callback_data": "team:mirror_here"},
        {"text": "🔇 关闭播报", "callback_data": "team:mirror_off"},
    ])
    kb_rows.append([
        {"text": "🔁 重试最近失败单", "callback_data": "team:retry_last"},
        {"text": "🔄 刷新团队状态", "callback_data": "team:refresh"},
    ])
    return "\n".join(lines), {"inline_keyboard": kb_rows}


def cmd_team(chat_id, raw_rest="", thread_id=None, scope_key=None, edit_msg_id=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    raw = (raw_rest or "").strip()
    if raw:
        parts = raw.split()
        sub = parts[0].lower()
        if sub == "sole":
            bot_bus.promote_sole_coordinator(_current_bot_handle())
            invalidate_session("cmd_team_sole")
            register_bot_commands_async(force=True)
            send(chat_id, f"👑 已将 <code>@{html_mod.escape(_current_bot_handle())}</code> 设为唯一主控，其余 Bot 设为 Worker (<code>gemini-3.8-flash-low</code>)。", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "peer":
            bot_bus.set_all_peers()
            invalidate_session("cmd_team_peer")
            register_bot_commands_async(force=True)
            send(chat_id, "🤝 已将全部已知 Bot 设为平级 (Peer) 模式。", thread_id=norm_tid)
            return
        elif sub == "role" and len(parts) >= 3:
            target = bot_bus.resolve_target_bot(parts[1])
            role = parts[2].lower()
            bot_bus.update_bot_config(target["handle"], role=role)
            if target["handle"] == _current_bot_handle():
                invalidate_session("cmd_team_role")
                register_bot_commands_async(force=True)
            send(chat_id, f"✅ <code>@{html_mod.escape(target['handle'])}</code> 角色已设为 <code>{html_mod.escape(role)}</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "model" and len(parts) >= 3:
            target = bot_bus.resolve_target_bot(parts[1])
            mdl = "" if parts[2].lower() in ("default", "none", "auto") else parts[2]
            bot_bus.update_bot_config(target["handle"], default_model=mdl)
            send(chat_id, f"✅ <code>@{html_mod.escape(target['handle'])}</code> Worker 默认模型已设为 <code>{html_mod.escape(mdl or '跟随会话')}</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "workdir" and len(parts) >= 3:
            target = bot_bus.resolve_target_bot(parts[1])
            wd = os.path.realpath(os.path.expanduser(parts[2]))
            if not os.path.isdir(wd):
                send(chat_id, f"⚠️ 目录不存在：<code>{html_mod.escape(wd)}</code>", parse_mode="HTML", thread_id=norm_tid)
                return
            bot_bus.update_bot_config(target["handle"], default_workdir=wd)
            send(chat_id, f"✅ <code>@{html_mod.escape(target['handle'])}</code> 默认目录已设为 <code>{html_mod.escape(wd)}</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "project" and len(parts) >= 3:
            target = bot_bus.resolve_target_bot(parts[1])
            pid = "" if parts[2].lower() in ("default", "none") else (_resolve_project_id_by_name_or_id(parts[2]) or parts[2])
            bot_bus.update_bot_config(target["handle"], default_project=pid)
            send(chat_id, f"✅ <code>@{html_mod.escape(target['handle'])}</code> 默认项目已设为 <code>{html_mod.escape(pid or 'default')}</code>", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "specialty" and len(parts) >= 3:
            target = bot_bus.resolve_target_bot(parts[1])
            spec = raw.split(None, 2)[2].strip()
            bot_bus.update_bot_config(target["handle"], specialty=spec)
            send(chat_id, f"✅ <code>@{html_mod.escape(target['handle'])}</code> 专长描述已更新。", parse_mode="HTML", thread_id=norm_tid)
            return
        elif sub == "mirror":
            arg2 = (parts[1].lower() if len(parts) >= 2 else "here")
            if arg2 == "off":
                bot_bus.set_team_mirror(0, None)
                send(chat_id, "🔇 已关闭团队进度播报。", thread_id=norm_tid)
            else:
                bot_bus.set_team_mirror(chat_id, norm_tid)
                send(chat_id, f"📌 已将团队 Worker 进度播报台绑定至当前位置 <code>{html_mod.escape(_format_scope_badge(chat_id, norm_tid))}</code>。", parse_mode="HTML", thread_id=norm_tid)
            return

    text, kb = build_team_panel(scope_key=skey)
    if edit_msg_id:
        tg("editMessageText", chat_id=chat_id, message_id=edit_msg_id, text=text, parse_mode="HTML", reply_markup=kb)
    else:
        send(chat_id, text, parse_mode="HTML", reply_markup=kb, thread_id=norm_tid)


def cmd_delegate(chat_id, raw_rest="", thread_id=None, scope_key=None, origin_msg_id=None):
    """Directly dispatch `/delegate @bot1[,@bot2] <task>` over Bot Bus without waking Coordinator LLM first."""
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    raw = (raw_rest or "").strip()
    parts = raw.split(None, 1)
    if len(parts) < 2:
        send(
            chat_id,
            "用法：<code>/delegate @目标Bot 任务内容</code>\n支持逗号并行：<code>/delegate @bot1,@bot2 任务内容</code>",
            parse_mode="HTML",
            thread_id=norm_tid,
        )
        return

    targets = [t.strip() for t in parts[0].split(",") if t.strip()]
    task_prompt = parts[1].strip()
    assignments = [{"bot": t, "prompt": task_prompt, "label": task_prompt[:40]} for t in targets]
    try:
        res = bot_bus.dispatch_assignments(
            _current_bot_handle(),
            assignments,
            origin_scope_key=skey,
            origin_chat_id=chat_id,
            origin_thread_id=norm_tid,
            origin_msg_id=origin_msg_id,
            default_notify_group=(int(chat_id or 0) < 0 and BUS_CHAT_MODE == "conversational"),
        )
    except Exception as e:
        send(chat_id, f"⚠️ 直派失败：<code>{html_mod.escape(str(e))}</code>", parse_mode="HTML", thread_id=norm_tid)
        return

    jids = [j["job_id"] for j in res["jobs"]]
    tg_list = ", ".join(f"<code>@{html_mod.escape(j['target_bot'])}</code>" for j in res["jobs"])
    send(
        chat_id,
        f"📨 已直派给 {tg_list}（单号：{', '.join(f'<code>{html_mod.escape(x)}</code>' for x in jids)}），完成后自动回传结果…",
        parse_mode="HTML",
        thread_id=norm_tid,
    )

    def _wait_and_deliver():
        settled, all_done = bot_bus.wait_for_jobs(jids, timeout_sec=600.0)
        for j in settled:
            if j.get("group_delivered"):
                continue
            st = j.get("status")
            icon = {"done": "✅", "error": "⚠️", "cancelled": "🛑"}.get(st, "⏳")
            usage = j.get("usage") or {}
            dur_s = usage.get("duration_s")
            usd = usage.get("usd")
            meta_parts = [f"@{j.get('target_bot')}"]
            if dur_s is not None:
                meta_parts.append(f"{dur_s}s")
            if usd:
                meta_parts.append(_fmt_usd(float(usd)))
            header = f"{icon} <b>[{' · '.join(html_mod.escape(p) for p in meta_parts)}]</b>\n\n"
            body = j.get("result_text") or j.get("error") or ("仍在后台运行，请用 /team 查看" if not all_done else "(no output)")
            send_rich(chat_id, body, header_html=header, thread_id=norm_tid)
            for ap in (j.get("artifacts") or []):
                if os.path.splitext(ap)[1].lower() in IMAGE_EXTS and os.path.isfile(ap) and try_claim_image(ap):
                    send_file(chat_id, ap, thread_id=norm_tid)

    threading.Thread(target=_wait_and_deliver, daemon=True).start()


def cmd_status(chat_id, thread_id=None, scope_key=None):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    sc = get_scope_state(skey)
    conv = sc.get("conversation_id")
    mode = sc.get("mode", "auto")
    model = sc.get("model")
    effort = sc.get("effort")
    th_on = sc.get("thinking", True)
    ac_on = bool(sc.get("auto_compact", True))
    thresh = int(sc.get("auto_compact_tokens") or DEFAULT_AUTO_COMPACT_TOKENS)
    undo_cnt = len(sc.get("undo_stack") or [])
    has_retry = bool((sc.get("last_turn") or {}).get("prompt"))

    with session_lock:
        is_running_here = turn_running and (turn_running_scope == skey)
        is_running_any = turn_running
        warm_sess = _session_pool.get(skey)
        is_warm = warm_sess is not None and warm_sess.is_alive()
        warm_total = sum(1 for s in _session_pool.values() if s.is_alive())
    with state_lock:
        scope_total = len(state.get("scopes") or {})

    stats = get_context_stats(conv)
    ctx_str = (
        f"<code>{format_tokens_k(stats['ctx_tokens'])}</code> / <code>{format_tokens_k(thresh)}</code> "
        f"({'auto ON' if ac_on else 'auto OFF'} · {stats['checkpoints']} ckpts)"
    ) if conv else "<code>0k</code>"
    proj_label = current_project(skey) or "default-cli-project"
    wdir_short = current_workdir(skey).replace(HOME, "~")
    if is_running_here:
        run_str = "yes (native draft streaming ⚡)"
    elif is_running_any:
        run_str = f"idle here (busy in <code>{html_mod.escape(str(turn_running_scope))}</code>)"
    elif is_warm:
        run_str = f"idle (warm ⚡ · pool {warm_total}/{MAX_WARM_SESSIONS})"
    else:
        run_str = f"idle (pool {warm_total}/{MAX_WARM_SESSIONS})"

    scope_label = _format_scope_badge(chat_id, norm_tid)
    q_here = job_q.count_scope(skey)
    q_all = job_q.qsize()
    q_str = f"{q_here} here" + (f" / {q_all} total" if q_all != q_here else "")
    team_role = _current_bot_role()
    roster_online = sum(1 for b in bot_bus.list_roster(include_offline=False))

    text = (f"<b>🤖 Antigravity Bridge v3.2 (Scoped Topics &amp; Bot Bus)</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Team Role:</b> <code>@{html_mod.escape(_current_bot_handle())}</code> · {_role_badge(team_role)} ({roster_online} online)\n"
            f"• <b>Scope:</b> <code>{html_mod.escape(scope_label)}</code> ({scope_total} isolated scopes)\n"
            f"• <b>Project:</b> <code>{html_mod.escape(proj_label)}</code> (<code>{html_mod.escape(wdir_short)}</code>)\n"
            f"• <b>Mode:</b> <code>{mode}</code>\n"
            f"• <b>Model:</b> <code>{model or '(default)'}</code>\n"
            f"• <b>Effort:</b> <code>{effort or '(default)'}</code>\n"
            f"• <b>Thinking:</b> <code>{'enabled' if th_on else 'disabled'}</code>\n"
            f"• <b>Session:</b> <code>{(conv or '(none)')[:8]}</code>\n"
            f"• <b>Context:</b> {ctx_str}\n"
            f"• <b>Safety:</b> Retry <code>{'ready' if has_retry else 'none'}</code> · Undo <code>{undo_cnt}</code> ckpts\n"
            f"• <b>Running:</b> {run_str}\n"
            f"• <b>Queue:</b> {q_str} pending")
    kb = make_status_keyboard(scope_key=skey)
    send(chat_id, text, parse_mode="HTML", reply_markup=kb, thread_id=norm_tid)


# ---------------------------------------------------------------- callback handling
def handle_callback(cb):
    cb_id = cb.get("id")
    from_user = cb.get("from", {})
    msg = cb.get("message", {})
    chat_id = msg.get("chat", {}).get("id") or from_user.get("id")
    thread_id = _extract_thread_id(msg)
    skey = scope_key_for(chat_id, thread_id)
    msg_id = msg.get("message_id")

    if not _is_authorized(chat_id, from_user=from_user, allow_uid_fallback=True):
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Unauthorized", show_alert=True)
        return

    data = cb.get("data", "")

    if data.startswith("model:"):
        target = data[6:]
        new_model = None if target == "default" else target
        update_scope_state(skey, model=new_model)
        save_state()
        invalidate_session("callback_model", scope_key=skey)
        tg("answerCallbackQuery", callback_query_id=cb_id,
           text=f"Model set to: {new_model or 'default'}")
        if msg_id:
            kb = make_model_keyboard(new_model)
            tg("editMessageReplyMarkup", chat_id=chat_id, message_id=msg_id, reply_markup=kb)

    elif data.startswith("effort:"):
        target = data[7:]
        new_effort = None if target == "default" else target
        update_scope_state(skey, effort=new_effort)
        save_state()
        invalidate_session("callback_effort", scope_key=skey)
        tg("answerCallbackQuery", callback_query_id=cb_id,
           text=f"Effort set to: {new_effort or 'default'}")
        if msg_id:
            kb = make_effort_keyboard(new_effort)
            tg("editMessageReplyMarkup", chat_id=chat_id, message_id=msg_id, reply_markup=kb)

    elif data.startswith("resume:"):
        cid_prefix = data[7:]
        items = list_sessions(50, scope_key=skey)
        match = [cid for _, cid, _, _ in items if cid.startswith(cid_prefix)]
        if match:
            update_scope_state(skey, conversation_id=match[0])
            save_state()
            invalidate_session("callback_resume", scope_key=skey)
            tg("answerCallbackQuery", callback_query_id=cb_id, text=f"Resumed {match[0][:8]}")
            send(chat_id, f"✅ Resumed session <code>{match[0][:8]}</code>. Next message continues here.",
                 parse_mode="HTML", thread_id=thread_id)
        else:
            tg("answerCallbackQuery", callback_query_id=cb_id, text="Session not found", show_alert=True)

    elif data.startswith("get:"):
        fn = data[4:]
        tg("answerCallbackQuery", callback_query_id=cb_id, text=f"Sending {fn}...")
        cmd_get(chat_id, fn, thread_id=thread_id, scope_key=skey)

    elif data == "action:new":
        update_scope_state(skey, conversation_id=None, pending_undo_notice=None)
        save_state()
        invalidate_session("callback_new", scope_key=skey)
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Started new session")
        send(chat_id, "🔄 New session started (context cleared).", thread_id=thread_id)

    elif data == "action:retry":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Retrying last turn...")
        cmd_retry(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "action:undo":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Checking undo checkpoint...")
        cmd_undo(chat_id, "preview", thread_id=thread_id, scope_key=skey)

    elif data == "undo:exec":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Undoing last file changes...")
        cmd_undo(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "undo:force":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Force undoing last file changes...")
        cmd_undo(chat_id, "force", thread_id=thread_id, scope_key=skey)

    elif data == "undo:redo":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Redoing reverted changes...")
        cmd_redo(chat_id, thread_id=thread_id, scope_key=skey)

    elif data == "action:compact":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Compacting context...")
        enqueue_compact(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "action:context":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_context(chat_id, thread_id=thread_id, scope_key=skey)

    elif data == "action:usage":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="正在查询总套餐配额...")
        cmd_usage(chat_id, "", thread_id=thread_id)

    elif data == "usage:refresh":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="正在刷新总套餐实时配额...")
        cmd_usage(chat_id, "", edit_msg_id=msg_id, thread_id=thread_id)

    elif data == "action:cost":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_cost(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data.startswith("cost:"):
        parts = data.split(":")
        c_view = parts[1] if len(parts) > 1 else "overview"
        c_scope = parts[2] if len(parts) > 2 else "all"
        panel_text, panel_kb = build_cost_panel(view=c_view, scope=c_scope, scope_key=skey)
        tg("answerCallbackQuery", callback_query_id=cb_id, text="我的用量已更新")
        if msg_id:
            tg("editMessageText", chat_id=chat_id, message_id=msg_id,
               text=panel_text, parse_mode="HTML", reply_markup=panel_kb)

    elif data == "action:schedule":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_schedule(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data.startswith("sched:"):
        parts = data.split(":")
        sub = parts[1] if len(parts) > 1 else "list"
        arg = parts[2] if len(parts) > 2 else ""

        if sub == "view":
            panel_text, panel_kb = scheduler.build_schedule_panel(
                view="detail", selected_task_id=arg, bot_instance_id=BOT_INSTANCE_ID
            )
            tg("answerCallbackQuery", callback_query_id=cb_id)
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)
        elif sub == "list":
            panel_text, panel_kb = scheduler.build_schedule_panel(view="list", bot_instance_id=BOT_INSTANCE_ID)
            tg("answerCallbackQuery", callback_query_id=cb_id, text="列表已刷新")
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)
        elif sub == "toggle":
            new_st = scheduler.task_mgr.toggle_task(arg)
            tg("answerCallbackQuery", callback_query_id=cb_id, text="任务已启用" if new_st else "任务已暂停")
            panel_text, panel_kb = scheduler.build_schedule_panel(
                view="detail", selected_task_id=arg, bot_instance_id=BOT_INSTANCE_ID
            )
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)
        elif sub == "silent":
            new_silent = scheduler.task_mgr.toggle_silent(arg)
            tg(
                "answerCallbackQuery",
                callback_query_id=cb_id,
                text="静默空结果: 已开启" if new_silent else "静默空结果: 已关闭 (每次必报)",
            )
            panel_text, panel_kb = scheduler.build_schedule_panel(
                view="detail", selected_task_id=arg, bot_instance_id=BOT_INSTANCE_ID
            )
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)
        elif sub == "del":
            scheduler.task_mgr.delete_task(arg)
            tg("answerCallbackQuery", callback_query_id=cb_id, text="任务已删除")
            panel_text, panel_kb = scheduler.build_schedule_panel(view="list", bot_instance_id=BOT_INSTANCE_ID)
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)
        elif sub == "run":
            t = scheduler.task_mgr.get_task(arg)
            if t:
                tg("answerCallbackQuery", callback_query_id=cb_id, text="已加入执行队列")
                t_chat = t.get("delivery", {}).get("target_chat_id") or chat_id
                t_thread = _normalize_thread_id(t.get("delivery", {}).get("target_thread_id"))
                job_q.put((t_chat, t_thread, scope_key_for(t_chat, t_thread), ("__SCHEDULED__", t)))
            else:
                tg("answerCallbackQuery", callback_query_id=cb_id, text="任务不存在", show_alert=True)
        elif sub == "preset":
            bot_sfx = BOT_INSTANCE_ID[:4]
            if arg == "cost":
                scheduler.task_mgr.create_task(
                    name="每日晨报与Token账单",
                    schedule_expr="0 9 * * *",
                    task_type="cost_report",
                    payload={"view": "overview", "scope": "all"},
                    target_chat_id=chat_id,
                    target_thread_id=thread_id,
                    project=current_project(skey) or "agy-cli-bot",
                    workdir=current_workdir(skey),
                    silent_if_empty=False,
                    custom_id=f"task-cost-{bot_sfx}",
                    bot_instance_id=BOT_INSTANCE_ID,
                )
                tg("answerCallbackQuery", callback_query_id=cb_id, text="已创建早9点账单预设")
            elif arg == "hourly":
                scheduler.task_mgr.create_task(
                    name="系统健康与进程巡检",
                    schedule_expr="0 * * * *",
                    task_type="script",
                    payload={"script": f"python3 {shlex.quote(os.path.join(AGY_REPO_DIR, 'scripts', 'sync_live.py'))} status"},
                    target_chat_id=chat_id,
                    target_thread_id=thread_id,
                    project=current_project(skey) or "agy-cli-bot",
                    workdir=current_workdir(skey),
                    silent_if_empty=False,
                    custom_id=f"task-health-{bot_sfx}",
                    bot_instance_id=BOT_INSTANCE_ID,
                )
                tg("answerCallbackQuery", callback_query_id=cb_id, text="已创建每小时巡检预设")
            panel_text, panel_kb = scheduler.build_schedule_panel(view="list", bot_instance_id=BOT_INSTANCE_ID)
            if msg_id:
                tg("editMessageText", chat_id=chat_id, message_id=msg_id,
                   text=panel_text, parse_mode="HTML", reply_markup=panel_kb)

    elif data == "compact:toggle":
        now_ac = not bool(get_scope_value(skey, "auto_compact", True))
        update_scope_state(skey, auto_compact=now_ac)
        save_state()
        tg("answerCallbackQuery", callback_query_id=cb_id,
           text=f"自动压缩: {'已开启' if now_ac else '已关闭'}")
        if msg_id:
            panel_text, panel_kb = build_context_panel(scope_key=skey)
            tg("editMessageText", chat_id=chat_id, message_id=msg_id,
               text=panel_text, parse_mode="HTML", reply_markup=panel_kb)

    elif data.startswith("compact:thresh:"):
        try:
            preset_val = int(data.split(":")[2])
        except Exception:
            preset_val = DEFAULT_AUTO_COMPACT_TOKENS
        update_scope_state(skey, auto_compact=True, auto_compact_tokens=preset_val)
        save_state()
        tg("answerCallbackQuery", callback_query_id=cb_id,
           text=f"自动压缩阈值已设为 {format_tokens_k(preset_val)}")
        if msg_id:
            panel_text, panel_kb = build_context_panel(scope_key=skey)
            tg("editMessageText", chat_id=chat_id, message_id=msg_id,
               text=panel_text, parse_mode="HTML", reply_markup=panel_kb)

    elif data == "action:project":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_project(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data.startswith("project:"):
        target_pid = data.split(":", 1)[1]
        ok, info = _switch_project(target_pid, scope_key=skey)
        if ok:
            tg("answerCallbackQuery", callback_query_id=cb_id, text=f"Project → {info['name']}")
            if msg_id:
                kb = make_project_keyboard(info["id"], scope_key=skey)
                tg("editMessageReplyMarkup", chat_id=chat_id, message_id=msg_id, reply_markup=kb)
            sess_note = f"续接会话 <code>{info['conversation_id'][:8]}</code>" if info["conversation_id"] else "新建会话"
            send(
                chat_id,
                f"✅ 已切换至项目 <b>{html_mod.escape(info['name'])}</b> (<code>{html_mod.escape(info['workdir'])}</code> · {sess_note})",
                parse_mode="HTML",
                thread_id=thread_id,
            )
        else:
            tg("answerCallbackQuery", callback_query_id=cb_id, text="Project not found", show_alert=True)

    elif data == "action:model":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_model(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "action:effort":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_effort(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "action:thinking":
        now_th = not bool(get_scope_value(skey, "thinking", True))
        update_scope_state(skey, thinking=now_th)
        save_state()
        tg("answerCallbackQuery", callback_query_id=cb_id,
           text=f"Thinking chain: {'Enabled' if now_th else 'Disabled'}")
        if msg_id:
            kb = make_status_keyboard(scope_key=skey)
            tg("editMessageReplyMarkup", chat_id=chat_id, message_id=msg_id, reply_markup=kb)

    elif data == "action:files":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_files(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data == "action:reload":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Reloading bridge...")
        with session_lock:
            busy = turn_running
        if busy:
            send(chat_id, "⏳ 当前有任务正在运行，将在任务完成后自动热重载...", thread_id=thread_id)
            job_q.put((chat_id, thread_id, skey, "__RELOAD__"))
        else:
            perform_hot_reload(notify_chat_id=chat_id, notify_thread_id=thread_id)

    elif data == "action:team":
        tg("answerCallbackQuery", callback_query_id=cb_id)
        cmd_team(chat_id, "", thread_id=thread_id, scope_key=skey)

    elif data.startswith("team:"):
        _handle_team_callback(cb_id, chat_id, thread_id, skey, msg_id, data)

    elif data == "action:cancel":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Cancelling task...")
        cancel_current_task(chat_id, thread_id=thread_id, scope_key=skey)


def _handle_team_callback(cb_id, chat_id, thread_id, skey, msg_id, data):
    sub = data[5:]
    if sub == "refresh":
        tg("answerCallbackQuery", callback_query_id=cb_id, text="团队状态已刷新")
    elif sub == "sole_coord":
        me = _current_bot_handle()
        bot_bus.promote_sole_coordinator(me)
        invalidate_session("cb_team_sole_coord")
        register_bot_commands_async(force=True)
        tg("answerCallbackQuery", callback_query_id=cb_id, text=f"@{me} 已设为唯一主控")
    elif sub == "all_peer":
        bot_bus.set_all_peers()
        invalidate_session("cb_team_all_peer")
        register_bot_commands_async(force=True)
        tg("answerCallbackQuery", callback_query_id=cb_id, text="已全部切换为 Peer 平级模式")
    elif sub == "mirror_here":
        bot_bus.set_team_mirror(chat_id, _normalize_thread_id(thread_id))
        tg("answerCallbackQuery", callback_query_id=cb_id, text="播报台已绑定至当前会话/Topic")
    elif sub == "mirror_off":
        bot_bus.set_team_mirror(0, None)
        tg("answerCallbackQuery", callback_query_id=cb_id, text="已关闭团队播报")
    elif sub == "retry_last":
        failed = [j for j in bot_bus.list_jobs(limit=25) if j.get("status") in ("error", "cancelled")]
        if not failed:
            tg("answerCallbackQuery", callback_query_id=cb_id, text="暂无失败/取消的历史派工单", show_alert=True)
            return
        try:
            nj = bot_bus.retry_job(failed[0]["job_id"], _current_bot_handle())
            tg("answerCallbackQuery", callback_query_id=cb_id, text=f"已重派 {nj['job_id']} → @{nj['target_bot']}")
        except Exception as e:
            tg("answerCallbackQuery", callback_query_id=cb_id, text=f"重试失败: {e}", show_alert=True)
            return
    elif sub.startswith("cycle:"):
        target_h = bot_bus.normalize_handle(sub[6:])
        roster_map = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
        cur_role = (roster_map.get(target_h) or {}).get("role") or "peer"
        next_role = {"coordinator": "worker", "worker": "peer", "peer": "coordinator"}.get(cur_role, "worker")
        bot_bus.update_bot_config(target_h, role=next_role)
        if target_h == _current_bot_handle():
            invalidate_session("cb_team_cycle")
            register_bot_commands_async(force=True)
        tg("answerCallbackQuery", callback_query_id=cb_id, text=f"@{target_h} → {next_role}")
    elif sub.startswith("model:"):
        target_h = bot_bus.normalize_handle(sub[6:])
        roster_map = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
        cur_mdl = (roster_map.get(target_h) or {}).get("default_model") or ""
        next_mdl = "" if "flash-low" in cur_mdl else "gemini-3.8-flash-low"
        bot_bus.update_bot_config(target_h, default_model=next_mdl)
        tg("answerCallbackQuery", callback_query_id=cb_id, text=f"@{target_h} 模型 → {next_mdl or '跟随会话'}")
    else:
        tg("answerCallbackQuery", callback_query_id=cb_id)
        return

    _publish_bot_heartbeat()
    if msg_id:
        cmd_team(chat_id, "", thread_id=thread_id, scope_key=skey, edit_msg_id=msg_id)


# ---------------------------------------------------------------- reply quote & album helpers
def _extract_reply_context(msg):
    """Extract quoted message text, highlight quote (Bot API 7.0+), author, and optional media."""
    rep = msg.get("reply_to_message")
    if not isinstance(rep, dict):
        return ""
    raw_tid = msg.get("message_thread_id")
    quote_obj = msg.get("quote") if isinstance(msg.get("quote"), dict) else None
    highlighted = (quote_obj.get("text") or "").strip() if quote_obj else ""
    # Telegram Forum Topics attach a synthetic `reply_to_message` for `forum_topic_created` / root thread id
    if rep.get("forum_topic_created") or (raw_tid is not None and rep.get("message_id") == raw_tid and not highlighted):
        return ""

    rep_from = rep.get("from") or {}
    if rep_from.get("is_bot"):
        author = "Bot"
    else:
        author = rep_from.get("first_name") or rep_from.get("username") or "用户"

    time_str = ""
    rep_ts = rep.get("date")
    if rep_ts:
        try:
            tz, _ = _get_cost_tz()
            time_str = " " + datetime.datetime.fromtimestamp(int(rep_ts), tz=tz).strftime("%H:%M")
        except Exception:
            pass

    body = (rep.get("text") or rep.get("caption") or "").strip()
    if len(body) > 1500:
        body = body[:1500] + "..."

    saved_media = None
    media_note = None
    reply_cache_dir = os.path.join(UPLOADDIR, "reply_cache")
    if rep.get("photo"):
        ph = rep["photo"][-1]
        uid = re.sub(r"[^A-Za-z0-9_-]", "", ph.get("file_unique_id") or ph["file_id"])[:32]
        dest = os.path.join(reply_cache_dir, f"reply_{uid}.jpg")
        if not os.path.isfile(dest):
            try:
                tg_download(ph["file_id"], dest)
            except Exception as e:
                log("reply photo download failed: %r" % e)
        if os.path.isfile(dest):
            saved_media = dest
    elif rep.get("document"):
        doc = rep["document"]
        sz = doc.get("file_size") or 0
        raw_name = os.path.basename(doc.get("file_name") or "file.bin")
        if sz <= 20 * 1024 * 1024:
            uid = re.sub(r"[^A-Za-z0-9_-]", "", doc.get("file_unique_id") or doc["file_id"])[:24]
            dest = os.path.join(reply_cache_dir, f"{uid}_{raw_name}")
            if not os.path.isfile(dest):
                try:
                    tg_download(doc["file_id"], dest)
                except Exception as e:
                    log("reply doc download failed: %r" % e)
            if os.path.isfile(dest):
                saved_media = dest
        else:
            media_note = f"附件文档 {raw_name} (>{sz // (1024 * 1024)}MB 未下载)"
    elif rep.get("voice") or rep.get("audio"):
        media_note = "一条语音/音频消息"

    lines = []
    if highlighted:
        h_clip = highlighted if len(highlighted) <= 800 else highlighted[:800] + "..."
        lines.append("> 高亮引用: " + h_clip.replace("\n", "\n> "))
    if body and body != highlighted:
        lines.append("> 原文: " + body.replace("\n", "\n> "))
    if saved_media:
        lines.append(f"> 引用媒体文件已保存至: {saved_media}")
    elif media_note:
        lines.append(f"> 引用附件: {media_note}")

    if not lines:
        return ""
    return f"[引用回复自 {author}{time_str}]:\n" + "\n".join(lines)


def _apply_reply_context(user_text, msg):
    ctx = _extract_reply_context(msg)
    if not ctx:
        return user_text
    return f"{ctx}\n\n{user_text}" if user_text else ctx


_album_lock = threading.Lock()
_album_buffers = {}  # album_key -> dict

MAX_TG_FILE_BYTES = 20 * 1024 * 1024
_MEDIA_MIME_EXTS = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/quicktime": ".mov",
    "video/x-matroska": ".mkv",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/png": ".png",
    "image/jpeg": ".jpg",
}
# Check `animation` BEFORE `document` because Telegram populates both on GIF messages.
_MEDIA_KEY_ORDER = ("animation", "video", "video_note", "sticker", "document", "photo")


def _has_msg_media(msg):
    return isinstance(msg, dict) and any(msg.get(k) for k in _MEDIA_KEY_ORDER)


def _extract_media_spec(msg):
    """Return `(kind, media_obj)` for supported Telegram media fields, or `(None, None)`."""
    if not isinstance(msg, dict):
        return None, None
    for kind in _MEDIA_KEY_ORDER:
        val = msg.get(kind)
        if not val:
            continue
        if kind == "photo":
            if isinstance(val, list) and val:
                return "photo", val[-1]
            continue
        if isinstance(val, dict):
            return kind, val
    return None, None


def _safe_media_filename(kind, media_obj, msg_id, ts=None, unique_album_names=False):
    stamp = int(ts if ts is not None else time.time())
    if kind == "sticker":
        ext = ".webm" if media_obj.get("is_video") else (".tgs" if media_obj.get("is_animated") else ".webp")
        fname = f"sticker_{stamp}_{msg_id}{ext}"
    elif kind == "video_note":
        fname = f"video_note_{stamp}_{msg_id}.mp4"
    elif kind == "photo":
        fname = f"photo_{stamp}_{msg_id}.jpg"
    else:
        mime = str(media_obj.get("mime_type") or "").split(";", 1)[0].strip().lower()
        default_ext = _MEDIA_MIME_EXTS.get(mime) or (".mp4" if kind in ("video", "animation") else "")
        raw_fn = media_obj.get("file_name") or ""
        raw_base = os.path.basename(str(raw_fn).replace("\x00", "").strip())
        if raw_base in ("", ".", ".."):
            prefix = "file" if kind == "document" else kind
            fname = f"{prefix}_{stamp}_{msg_id}{default_ext}"
        else:
            _stem, ext = os.path.splitext(raw_base)
            fname = f"{raw_base}{default_ext}" if (not ext and default_ext) else raw_base
    if unique_album_names and os.path.exists(os.path.join(UPLOADDIR, fname)):
        stem, ext = os.path.splitext(fname)
        fname = f"{stem}_{msg_id}{ext}"
    return fname


def _describe_msg_media(msg):
    """Return `(kind, ledger_label, meta_text)` describing semantic Telegram media attributes."""
    kind, obj = _extract_media_spec(msg)
    if not kind or not obj:
        return None, "文件", ""
    if kind == "sticker":
        fmt = "video .webm" if obj.get("is_video") else ("animated .tgs" if obj.get("is_animated") else "static .webp")
        parts = [fmt]
        if obj.get("emoji"):
            parts.append(f"emoji={obj['emoji']}")
        if obj.get("set_name"):
            parts.append(f"set={obj['set_name']}")
        if obj.get("width") and obj.get("height"):
            parts.append(f"{obj['width']}x{obj['height']}")
        return kind, "贴纸", f"Sticker ({', '.join(parts)})"
    if kind == "video":
        parts = []
        if obj.get("duration") is not None:
            parts.append(f"{obj['duration']}s")
        if obj.get("width") and obj.get("height"):
            parts.append(f"{obj['width']}x{obj['height']}")
        if obj.get("file_name"):
            parts.append(f"name={os.path.basename(str(obj['file_name']))}")
        meta = f"Video ({', '.join(parts)})" if parts else "Video"
        return kind, "视频", meta
    if kind == "video_note":
        parts = []
        if obj.get("duration") is not None:
            parts.append(f"{obj['duration']}s")
        if obj.get("length"):
            parts.append(f"{obj['length']}x{obj['length']}")
        meta = f"Video Note ({', '.join(parts)})" if parts else "Video Note"
        return kind, "圆视频", meta
    if kind == "animation":
        parts = []
        if obj.get("duration") is not None:
            parts.append(f"{obj['duration']}s")
        if obj.get("width") and obj.get("height"):
            parts.append(f"{obj['width']}x{obj['height']}")
        if obj.get("file_name"):
            parts.append(f"name={os.path.basename(str(obj['file_name']))}")
        meta = f"Animation/GIF ({', '.join(parts)})" if parts else "Animation/GIF"
        return kind, "动图", meta
    if kind == "photo":
        return kind, "图片", ""
    return kind, "文件", ""


def _note_poll_album_batch(updates):
    """Pre-register every album item in the current getUpdates poll batch so slow downloads never split an album."""
    counts = {}
    for u in updates or ():
        m = u.get("message") or u.get("edited_message")
        if not isinstance(m, dict):
            continue
        mg_id = m.get("media_group_id")
        if not mg_id or not _has_msg_media(m):
            continue
        chat_id = (m.get("chat") or {}).get("id")
        if not _is_authorized(chat_id, from_user=m.get("from")):
            continue
        thread_id = _extract_thread_id(m)
        skey = scope_key_for(chat_id, thread_id)
        akey = f"{skey}:{mg_id}"
        m_mid = int(m.get("message_id") or 0)
        frm = m.get("from") or {}
        m_sender = (frm.get("username") or frm.get("first_name") or "").strip() if not frm.get("is_bot") else ""
        prev_cnt = counts[akey][3] if akey in counts else 0
        prev_mid = counts[akey][4] if akey in counts else 0
        prev_sender = counts[akey][5] if akey in counts else ""
        first_mid = min(prev_mid, m_mid) if (prev_mid > 0 and m_mid > 0) else (prev_mid or m_mid)
        counts[akey] = (chat_id, thread_id, skey, prev_cnt + 1, first_mid, prev_sender or m_sender)

    if not counts:
        return
    with _album_lock:
        for akey, (chat_id, thread_id, skey, cnt, first_mid, sender_handle) in counts.items():
            entry = _album_buffers.get(akey)
            if entry is None:
                entry = {
                    "chat_id": chat_id,
                    "thread_id": thread_id,
                    "scope_key": skey,
                    "first_msg_id": first_mid,
                    "sender_handle": sender_handle or "user",
                    "batch_pending": 0,
                    "downloading": 0,
                    "items": [],
                    "captions": [],
                    "reply_ctxs": [],
                    "errors": [],
                    "timer": None,
                }
                _album_buffers[akey] = entry
            elif first_mid > 0 and (not entry.get("first_msg_id") or first_mid < int(entry["first_msg_id"])):
                entry["first_msg_id"] = first_mid
            if sender_handle and entry.get("sender_handle") in ("", "user"):
                entry["sender_handle"] = sender_handle
            entry["batch_pending"] += cnt
            t = entry.get("timer")
            if t is not None:
                t.cancel()
                entry["timer"] = None


def _cancel_all_album_timers():
    with _album_lock:
        for entry in _album_buffers.values():
            t = entry.get("timer")
            if t is not None:
                t.cancel()
        _album_buffers.clear()


def _flush_album(akey):
    with _album_lock:
        entry = _album_buffers.get(akey)
        if entry is None:
            return
        if entry.get("downloading", 0) > 0 or entry.get("batch_pending", 0) > 0:
            return
        _album_buffers.pop(akey, None)

    if shutting_down:
        return

    chat_id = entry["chat_id"]
    thread_id = entry["thread_id"]
    skey = entry["scope_key"]
    items = entry["items"]
    errors = entry["errors"]

    if not items:
        if errors:
            send(chat_id, "⚠️ 相册文件下载失败：" + "; ".join(errors[:3]), thread_id=thread_id)
        return

    captions = list(dict.fromkeys(c for c in entry["captions"] if c))
    reply_ctxs = list(dict.fromkeys(r for r in entry["reply_ctxs"] if r))
    caption_block = "\n".join(captions) if captions else "Please review these uploaded files"
    file_lines = "\n".join(
        f"- {it['dest']}" + (f" ({it['meta']})" if it.get("meta") else "")
        for it in items
    )
    err_note = ("\n(Failed items: " + "; ".join(errors[:5]) + ")") if errors else ""

    parts = []
    if reply_ctxs:
        parts.append("\n\n".join(reply_ctxs))
    parts.append(f"{caption_block}\n(Album with {len(items)} files saved at:\n{file_lines}){err_note}")
    combined_prompt = "\n\n".join(parts)

    send(chat_id, f"📥 已收齐相册共 {len(items)} 个文件 — 正在合并提交处理", thread_id=thread_id)
    first_mid = int(entry.get("first_msg_id") or 0)
    sender_handle = entry.get("sender_handle") or "user"
    chain_id = ""
    if chat_id and int(chat_id) < 0:
        meta_tags = [it.get("meta") for it in items if it.get("meta")]
        ledger_suffix = f" ({'; '.join(meta_tags[:4])})" if (not captions and meta_tags) else ""
        bot_bus.record_group_message(
            int(chat_id),
            msg_id=first_mid,
            thread_id=thread_id,
            sender_handle=sender_handle,
            sender_role="human",
            is_bot=False,
            text=f"[相册 {len(items)} 个文件] {caption_block}{ledger_suffix}",
        )
        chain_id = bot_bus.mark_human_group_activity(int(chat_id), thread_id=thread_id, msg_id=first_mid) or ""
    enqueue(
        chat_id,
        combined_prompt,
        thread_id=thread_id,
        scope_key=skey,
        origin_msg_id=first_mid,
        chain_id=chain_id,
        has_media=True,
        raw_text=caption_block,
    )


def _download_msg_media(msg, unique_album_names=False):
    """Download supported Telegram media from `msg` into UPLOADDIR. Returns `(dest, rel, err_str)`."""
    kind, media_obj = _extract_media_spec(msg)
    if not kind or not media_obj or not media_obj.get("file_id"):
        return None, None, "Unsupported or empty media payload"
    if (media_obj.get("file_size") or 0) > MAX_TG_FILE_BYTES:
        return None, None, "File over 20MB — Telegram Bot API limit"
    msg_id = msg.get("message_id") or int(time.time() * 1000) % 100000
    fname = _safe_media_filename(kind, media_obj, msg_id, unique_album_names=unique_album_names)
    dest = os.path.join(UPLOADDIR, fname)
    try:
        tg_download(media_obj["file_id"], dest)
    except Exception as e:
        return None, None, f"Download failed: {e!r}"
    rel = os.path.relpath(dest, WORKDIR)
    return dest, rel, None


def _handle_album_item(msg, chat_id, thread_id, skey, mg_id):
    akey = f"{skey}:{mg_id}"
    msg_mid = int(msg.get("message_id") or 0)
    frm = msg.get("from") or {}
    msg_sender = (frm.get("username") or frm.get("first_name") or "").strip() if not frm.get("is_bot") else ""
    with _album_lock:
        entry = _album_buffers.get(akey)
        if entry is None:
            entry = {
                "chat_id": chat_id,
                "thread_id": thread_id,
                "scope_key": skey,
                "first_msg_id": msg_mid,
                "sender_handle": msg_sender or "user",
                "batch_pending": 0,
                "downloading": 0,
                "items": [],
                "captions": [],
                "reply_ctxs": [],
                "errors": [],
                "timer": None,
            }
            _album_buffers[akey] = entry
        else:
            if msg_mid > 0 and (not entry.get("first_msg_id") or msg_mid < int(entry["first_msg_id"])):
                entry["first_msg_id"] = msg_mid
            if msg_sender and entry.get("sender_handle") in ("", "user"):
                entry["sender_handle"] = msg_sender
            t = entry.get("timer")
            if t is not None:
                t.cancel()
                entry["timer"] = None
        if entry["batch_pending"] > 0:
            entry["batch_pending"] -= 1
        entry["downloading"] += 1

    try:
        dest, rel, err = _download_msg_media(msg, unique_album_names=True)
        _, _, media_meta = _describe_msg_media(msg)
        caption = (msg.get("caption") or "").strip()
        reply_ctx = _extract_reply_context(msg)
    except Exception as exc:
        dest, rel, err, media_meta, caption, reply_ctx = None, None, f"Download error: {exc!r}", "", "", ""
    finally:
        with _album_lock:
            entry = _album_buffers.get(akey)
            if entry is not None:
                entry["downloading"] = max(0, entry["downloading"] - 1)
                if err:
                    entry["errors"].append(err)
                elif dest:
                    entry["items"].append({"dest": dest, "rel": rel, "meta": media_meta})
                if caption:
                    entry["captions"].append(caption)
                if reply_ctx:
                    entry["reply_ctxs"].append(reply_ctx)
                if entry["downloading"] == 0 and entry["batch_pending"] == 0:
                    t = threading.Timer(ALBUM_DEBOUNCE_SECONDS, _flush_album, args=(akey,))
                    t.daemon = True
                    entry["timer"] = t
                    t.start()


# ---------------------------------------------------------------- message dispatch
def handle_message(msg):
    chat_id = msg.get("chat", {}).get("id")
    if not _is_authorized(chat_id, from_user=msg.get("from")):
        log("rejected chat %s" % chat_id)
        return
    chain_id = _record_human_group_msg(msg) or ""
    if _should_ignore_group_message(msg):
        return
    thread_id = _extract_thread_id(msg)
    skey = scope_key_for(chat_id, thread_id)
    msg_id = int(msg.get("message_id") or 0)
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if not text:
        return

    if text.startswith("/"):
        parts = text.split()
        cmd = parts[0].split("@")[0]
        arg = parts[1] if len(parts) > 1 else ""
        raw_rest = text[len(parts[0]):].strip()
        if cmd in ("/new", "/reset"):
            update_scope_state(skey, conversation_id=None, pending_undo_notice=None)
            save_state()
            invalidate_session("cmd_new", scope_key=skey)
            send(chat_id, "🔄 New session (context cleared)", thread_id=thread_id)
        elif cmd == "/retry":
            cmd_retry(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/undo",):
            cmd_undo(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd == "/redo":
            cmd_redo(chat_id, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/team", "/bots"):
            cmd_team(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/delegate", "/ask"):
            cmd_delegate(chat_id, raw_rest, thread_id=thread_id, scope_key=skey, origin_msg_id=msg_id or None)
        elif cmd == "/compact":
            cmd_compact(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd == "/context":
            cmd_context(chat_id, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/usage", "/quota"):
            cmd_usage(chat_id, raw_rest, thread_id=thread_id)
        elif cmd in ("/cost", "/bill"):
            cmd_cost(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/schedule", "/cron", "/timer", "/timers"):
            cmd_schedule(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/project", "/projects"):
            cmd_project(chat_id, raw_rest, thread_id=thread_id, scope_key=skey)
        elif cmd == "/model":
            cmd_model(chat_id, arg, thread_id=thread_id, scope_key=skey)
        elif cmd == "/effort":
            cmd_effort(chat_id, arg, thread_id=thread_id, scope_key=skey)
        elif cmd == "/thinking":
            if arg in ("on", "true", "yes", "1"):
                update_scope_state(skey, thinking=True)
                save_state()
                send(chat_id, "💭 思考链与工具调用展示已开启 (可折叠展示)", thread_id=thread_id)
            elif arg in ("off", "false", "no", "0"):
                update_scope_state(skey, thinking=False)
                save_state()
                send(chat_id, "💭 思考链与工具调用展示已关闭", thread_id=thread_id)
            else:
                cur_th = not bool(get_scope_value(skey, "thinking", True))
                update_scope_state(skey, thinking=cur_th)
                save_state()
                st_text = "已开启 (可折叠查看)" if cur_th else "已关闭"
                send(chat_id,
                     f"💭 思考链展示当前: <b>{st_text}</b>\n(输入 <code>/thinking on</code> 或 <code>/thinking off</code> 切换)",
                     parse_mode="HTML", thread_id=thread_id)
        elif cmd == "/sessions":
            cmd_sessions(chat_id, thread_id=thread_id, scope_key=skey)
        elif cmd == "/resume":
            cmd_resume(chat_id, arg, thread_id=thread_id, scope_key=skey)
        elif cmd == "/files":
            cmd_files(chat_id, arg, thread_id=thread_id, scope_key=skey)
        elif cmd == "/get":
            cmd_get(chat_id, arg, thread_id=thread_id, scope_key=skey)
        elif cmd == "/mode":
            if arg in ("auto", "safe"):
                update_scope_state(skey, mode=arg)
                save_state()
                invalidate_session("cmd_mode", scope_key=skey)
                send(chat_id, "mode → %s%s" % (
                    arg, " (tools auto-approved)" if arg == "auto" else " (permission-requiring tools denied)"),
                     thread_id=thread_id)
            else:
                send(chat_id, "usage: /mode auto | /mode safe", thread_id=thread_id)
        elif cmd == "/reload":
            with session_lock:
                busy = turn_running
            if busy:
                send(chat_id, "⏳ 当前有任务正在运行，将在任务完成后自动热重载...", thread_id=thread_id)
                job_q.put((chat_id, thread_id, skey, "__RELOAD__"))
            else:
                perform_hot_reload(notify_chat_id=chat_id, notify_thread_id=thread_id)
        elif cmd in ("/cancel", "/stop"):
            cancel_current_task(chat_id, clear_all=(arg == "all"), thread_id=thread_id, scope_key=skey)
        elif cmd == "/status":
            cmd_status(chat_id, thread_id=thread_id, scope_key=skey)
        elif cmd in ("/start", "/help"):
            if int(chat_id) < 0:
                send(chat_id,
                     "<b>🤝 Antigravity 团队群协作指南 (Coordinator Bot Bus)</b>\n\n"
                     "• <b>直接发消息：</b>由主控 Bot 统一接单，按专长自动分派给团队成员并汇总验收。\n"
                     "• <b>点名指定：</b>发送 <code>@目标Bot 任务内容</code> 或回复它的消息，即可直接与单个队员对话。\n"
                     "• <b>Topic 隔离：</b>开启话题（Topics）后，每个话题各自绑定独立会话与工作目录，互不干扰私聊。\n\n"
                     "<b>群聊快捷团队指令：</b>\n"
                     "/team — 查看/切换团队角色、模型、播报台与派工单\n"
                     "/delegate @bot 任务 — 绕过主控 LLM，直接向指定队员派单\n"
                     "/project [名称] — 切换本群/当前 Topic 协同的项目仓库\n"
                     "/status — 查看当前主控状态、Scope 与在线队员数\n"
                     "/new — 清空本群/当前 Topic 主控上下文（不影响私聊）\n"
                     "/cancel [all] — 中止当前群内正在运行的任务\n\n"
                     "<i>私聊各 Bot 仍保留全部 22 项个人指令与独立上下文；其余单机高阶指令（如 /undo、/model、/cost）在群里手动输入也可直接调用。</i>",
                     parse_mode="HTML", thread_id=thread_id)
                return
            send(chat_id,
                 "<b>🤖 Antigravity CLI Telegram Bridge v3.2 (Scoped Topics &amp; Bot Bus)</b>\n\n"
                 "Send any prompt to task the agent in <code>~/agy-workspace</code>.\n"
                 "• ⚡ <b>Native Draft Streaming:</b> Telegram Bot API <code>sendMessageDraft</code> (0ms Thinking + 4.5fps token animation + built-in Stop button)\n"
                 "• 🤝 <b>Coordinator Bot Bus:</b> Main coordinator dispatches &amp; fans out specialist tasks across sibling bots (<code>/team</code>, <code>/delegate</code>)\n"
                 "• 📌 <b>Topic &amp; Reply Context:</b> Group Forum Topics keep isolated sessions/workdirs; swiping to reply injects quoted context\n"
                 "• 🖼 <b>Album Batching:</b> Multi-photo albums aggregate cleanly into one turn &amp; reply albums\n"
                 "• 🔁 <b>Safety &amp; Rollback:</b> <code>/retry</code> re-runs the previous prompt; <code>/undo</code> reverts workspace edits with conflict checks\n\n"
                 "<b>Commands:</b>\n"
                 "/new — clear context &amp; start fresh session\n"
                 "/retry [note] — re-run last turn in current scope\n"
                 "/undo [preview|force] · /redo — revert or replay workspace edits\n"
                 "/team — multi-bot team roster, coordinator/worker roles &amp; jobs\n"
                 "/delegate @bot task — directly dispatch work to a sibling bot (0 Coordinator LLM)\n"
                 "/usage — overall Antigravity subscription plan live quota &amp; reset time\n"
                 "/cost — my local daily/weekly/monthly M-tokens, cache rate &amp; USD bill\n"
                 "/schedule — manage scheduled tasks, cron jobs &amp; timers\n"
                 "/compact [note|on|off|auto 160k] — compact context or configure auto-compact\n"
                 "/context — inspect active context tokens &amp; compaction stats\n"
                 "/status — check agent state, scope &amp; active jobs\n"
                 "/project [name] — switch Antigravity CLI project &amp; repo\n"
                 "/model — switch AI models with interactive menu\n"
                 "/effort — configure reasoning effort\n"
                 "/thinking [on|off] — toggle live &amp; expandable thinking chain\n"
                 "/sessions — browse &amp; resume recent sessions\n"
                 "/files — list files in workspace\n"
                 "/get &lt;name&gt; — download file or view photo\n"
                 "/mode auto|safe — tool permission mode\n"
                 "/reload — gracefully reload bridge without dropping jobs\n"
                 "/cancel [all] — kill running task &amp; optionally clear queue\n\n"
                 "<i>Send documents/photos (single or album) to automatically load them into the workspace.</i>",
                 parse_mode="HTML", thread_id=thread_id)
        else:
            send(chat_id, f"ℹ️ 未知桥接命令 <code>{html_mod.escape(cmd)}</code>（输入 <code>/help</code> 查看可用命令）",
                 parse_mode="HTML", thread_id=thread_id)
        return

    full_prompt = _apply_reply_context(text, msg)
    enqueue(
        chat_id,
        full_prompt,
        thread_id=thread_id,
        scope_key=skey,
        origin_msg_id=msg_id,
        chain_id=chain_id,
        raw_text=text,
    )


def enqueue(
    chat_id,
    prompt,
    thread_id=None,
    scope_key=None,
    *,
    origin_msg_id=0,
    mention_hop=0,
    chain_id="",
    is_mention=False,
    has_media=False,
    raw_text=None,
):
    norm_tid = _normalize_thread_id(thread_id)
    skey = scope_key or scope_key_for(chat_id, norm_tid)
    busy, busy_desc, pending = _describe_active_busy_task()

    if (
        busy
        and chat_id
        and int(chat_id) < 0
        and BUS_FAST_CHAT_ENABLED
        and _is_fast_chat_candidate(raw_text if raw_text is not None else prompt, has_media=has_media, is_mention=is_mention)
    ):
        if _fast_chat_sem.acquire(blocking=False):
            log("Routing group message to isolated read-only fast-reply lane (chat=%s, busy=%s)" % (chat_id, busy_desc))
            threading.Thread(
                target=_run_fast_group_reply,
                args=(chat_id, prompt),
                kwargs={
                    "thread_id": norm_tid,
                    "scope_key": skey,
                    "origin_msg_id": int(origin_msg_id or 0),
                    "mention_hop": int(mention_hop or 0),
                    "busy_desc": busy_desc,
                },
                daemon=True,
            ).start()
            return

    if pending or busy:
        if (chat_id and int(chat_id) < 0) or BUS_CHAT_MODE == "conversational":
            if busy_desc:
                q_text = (
                    f"⏳ 我手头正在跑 {busy_desc}，这条需求我已接下排队（第 {pending + 1} 位），完成后马上处理。"
                )
            else:
                q_text = (
                    f"⏳ 我手头正在处理上一条任务，这条需求我已接下排队（第 {pending + 1} 位），完成后马上处理。"
                )
            send(chat_id, q_text, thread_id=norm_tid, reply_to_message_id=origin_msg_id or None)
        else:
            send(
                chat_id,
                "📋 Queued (position %d) — starts right after current turn (/cancel to interrupt)" % (pending + 1),
                thread_id=norm_tid,
            )

    if origin_msg_id or mention_hop or chain_id:
        item_payload = (
            "__CHAT_TURN__",
            {
                "prompt": prompt,
                "origin_msg_id": int(origin_msg_id or 0),
                "mention_hop": int(mention_hop or 0),
                "chain_id": str(chain_id or ""),
            },
        )
    else:
        item_payload = prompt
    job_q.put((chat_id, norm_tid, skey, item_payload))


def handle_voice(msg):
    chat_id = msg.get("chat", {}).get("id")
    if not _is_authorized(chat_id, from_user=msg.get("from")):
        return
    if _should_ignore_group_message(msg):
        return
    thread_id = _extract_thread_id(msg)
    skey = scope_key_for(chat_id, thread_id)
    v = msg.get("voice") or msg.get("audio")
    ext = ".oga" if msg.get("voice") else (os.path.splitext(v.get("file_name") or "audio.mp3")[1] or ".mp3")
    msg_id = msg.get("message_id") or 0
    dest = os.path.join(UPLOADDIR, f"voice_{int(time.time())}_{msg_id}{ext}")
    try:
        tg_download(v["file_id"], dest)
    except Exception as e:
        send(chat_id, "Voice download failed: %r" % e, thread_id=thread_id)
        return
    try:
        text = transcribe(dest)
    except Exception as e:
        send(chat_id, "Transcription failed: %r" % e, thread_id=thread_id)
        return
    if not text:
        send(chat_id,
             "Voice received but STT is not configured (AGY_TG_STT_BASE/AGY_TG_STT_KEY) — send text for now",
             thread_id=thread_id)
        return
    send(chat_id, "🎙 %s" % text, thread_id=thread_id)
    chain_id = _record_human_group_msg(msg, text_override=f"🎙 {text}") or ""
    full_prompt = _apply_reply_context(text, msg)
    enqueue(
        chat_id,
        full_prompt,
        thread_id=thread_id,
        scope_key=skey,
        origin_msg_id=msg_id,
        chain_id=chain_id,
        has_media=True,
        raw_text=text,
    )


def handle_media(msg):
    chat_id = msg.get("chat", {}).get("id")
    if not _is_authorized(chat_id, from_user=msg.get("from")):
        return
    if _should_ignore_group_message(msg):
        return
    thread_id = _extract_thread_id(msg)
    skey = scope_key_for(chat_id, thread_id)
    mg_id = msg.get("media_group_id")
    if mg_id:
        _handle_album_item(msg, chat_id, thread_id, skey, str(mg_id))
        return

    _kind, ledger_label, media_meta = _describe_msg_media(msg)
    user_caption = (msg.get("caption") or "").strip()
    dest, rel, err = _download_msg_media(msg, unique_album_names=False)
    if err:
        send(chat_id, err, thread_id=thread_id)
        return
    send(chat_id, "📥 Saved as %s — tasking agent" % rel, thread_id=thread_id)
    if media_meta:
        lead = user_caption or f"User sent {media_meta}"
        prompt_body = f"{lead}\n({media_meta}; the file is saved at: {dest})"
        ledger_text = f"[{ledger_label} {rel}] {media_meta}" + (f" {user_caption}" if user_caption else "")
        raw_text = f"{media_meta} {user_caption}".strip()
    else:
        lead = user_caption or "Please review this file"
        prompt_body = f"{lead}\n(The file is saved at: {dest})"
        ledger_text = f"[文件 {rel}] {lead}"
        raw_text = lead
    chain_id = _record_human_group_msg(msg, text_override=ledger_text) or ""
    full_prompt = _apply_reply_context(prompt_body, msg)
    enqueue(
        chat_id,
        full_prompt,
        thread_id=thread_id,
        scope_key=skey,
        origin_msg_id=int(msg.get("message_id") or 0),
        chain_id=chain_id,
        has_media=True,
        raw_text=raw_text,
    )


def _run_poll_iteration(offset, first_poll, poll_err_streak):
    """Execute one getUpdates cycle with self-healing session rebuild & exponential backoff."""
    try:
        poll_params = {"offset": offset, "timeout": 15}
        if first_poll:
            # Reset allowed_updates to default [] so stopped_message_generation is delivered
            poll_params["allowed_updates"] = json.dumps([])
        r = http_session.get(API + "/getUpdates", params=poll_params, timeout=(8, 20))
        first_poll = False
        data = r.json()
        if not data.get("ok"):
            poll_err_streak += 1
            err_code = data.get("error_code") or getattr(r, "status_code", None)
            desc = str(data.get("description", ""))
            if err_code == 409 or "conflict" in desc.lower():
                log(
                    "getUpdates 409 Conflict (streak=%d): %s — another process or webhook is polling this bot token!"
                    % (poll_err_streak, data)
                )
            else:
                log("getUpdates error (streak=%d): %s" % (poll_err_streak, data))
            if poll_err_streak >= 3 or (isinstance(err_code, int) and err_code >= 500):
                _reset_http_session(reason=f"getUpdates_api_error_{err_code or 'unknown'}")
            _sleep_interruptible(_poll_backoff_seconds(poll_err_streak))
            return offset, first_poll, poll_err_streak

        poll_err_streak = 0
        updates = data.get("result", [])
        _note_poll_album_batch(updates)
        for u in updates:
            offset = u["update_id"] + 1
            try:
                smg = u.get("stopped_message_generation")
                if smg:
                    smg_chat = (smg.get("chat") or {}).get("id")
                    smg_tid = _normalize_thread_id(smg.get("message_thread_id"))
                    if _is_authorized(smg_chat, from_user=smg.get("from")):
                        log("Native Stop button pressed in chat %s (thread %s, draft %s)"
                            % (smg_chat, smg_tid, smg.get("draft_id")))
                        cancel_current_task(smg_chat, from_native_stop=True, thread_id=smg_tid)
                    continue
                cb = u.get("callback_query")
                if cb:
                    handle_callback(cb)
                    continue
                msg = u.get("message") or u.get("edited_message")
                if not msg:
                    continue
                if _has_msg_media(msg):
                    handle_media(msg)
                elif msg.get("voice") or msg.get("audio"):
                    handle_voice(msg)
                else:
                    handle_message(msg)
            except Exception as e:
                log("dispatch error: %r" % e)
        return offset, first_poll, poll_err_streak
    except requests.exceptions.ReadTimeout:
        return offset, False, poll_err_streak
    except Exception as e:
        if not shutting_down:
            poll_err_streak += 1
            log("poll error (streak=%d): %r" % (poll_err_streak, e))
            _reset_http_session(reason=f"poll_error:{type(e).__name__}")
            _sleep_interruptible(_poll_backoff_seconds(poll_err_streak))
        return offset, first_poll, poll_err_streak


def main():
    _acquire_instance_lock()
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    os.makedirs(WORKDIR, exist_ok=True)
    os.makedirs(UPLOADDIR, exist_ok=True)
    _init_bot_identity()
    ensure_team_mcp_configured()
    _publish_bot_heartbeat()
    register_bot_commands()
    check_and_recover_in_flight()

    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=idle_session_reaper, daemon=True).start()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    threading.Thread(target=_bot_bus_loop, daemon=True).start()
    offset = 0
    first_poll = True
    poll_err_streak = 0
    prim = get_scope_state(PRIMARY_SCOPE_KEY)
    log("bridge v3.2 (Coordinator Bot Bus + scoped topics/albums/undo) started, role: %s, allowed chats: %s, mode: %s, model: %s"
        % (_current_bot_role(), ALLOWED, prim.get("mode"), prim.get("model")))

    while not shutting_down:
        if os.path.exists(RELOAD_TRIGGER):
            with session_lock:
                busy = turn_running
            if not busy and job_q.empty():
                try:
                    os.remove(RELOAD_TRIGGER)
                except Exception:
                    pass
                log("Detected %s while idle, reloading via execv..." % RELOAD_TRIGGER)
                perform_hot_reload()

        offset, first_poll, poll_err_streak = _run_poll_iteration(offset, first_poll, poll_err_streak)

    _cancel_all_album_timers()
    log("Polling loop exited. Waiting for in-flight tasks to complete before shutdown...")
    deadline = time.time() + 75
    while True:
        with session_lock:
            busy = turn_running
        if (not busy and job_q.empty()) or time.time() >= deadline:
            break
        time.sleep(0.5)

    with session_lock:
        still_busy = turn_running
    if still_busy:
        log("Task exceeded graceful shutdown timeout, terminating active session...")
        invalidate_session("shutdown_timeout", force=True)
    else:
        close_all_sessions_sync()

    log("Graceful shutdown complete. Exiting.")
    _release_instance_lock()


if __name__ == "__main__":
    main()
