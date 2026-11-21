#!/usr/bin/env python3
"""AGY Studio — Secrets Storage Configuration & Host OpenBao Auto-Detection Service.

Provides:
- Generic `SecretStore` abstraction foundation (`openbao` / reserved `security_card` / `local_0600`)
- Runtime host OpenBao auto-detection (strictly zero hardcoded personal URLs/cards/tokens)
- Protected `0600` persistence (`~/.config/agy-tg-bridge/studio_secrets.json`, `0700` dir,
  `flock` atomic write, symlink refusal)
- Authenticated & 4-layer write-gated REST APIs:
  - `GET  /api/secrets/openbao`
  - `PUT  /api/secrets/openbao`
  - `POST /api/secrets/openbao/test`
"""

from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)

log = logging.getLogger("agy-studio.secrets_config")

DEFAULT_KV_MOUNT = "secret"
DEFAULT_GATEWAY_PATH_PREFIX = "agy-studio/gateways"
DEFAULT_FALLBACK_MODE = "local_0600"
DEFAULT_SECURITY_CARD_STATUS = "reserved"

_VALID_AUTH_MODES = frozenset({"host_card", "token", "approle"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_KV_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_GATEWAY_SECRET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_FORBIDDEN_SECRET_IDS = frozenset({"__proto__", "prototype", "constructor", "probe"})
_KV_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_AUTH_LABEL_RE = re.compile(r"^[A-Za-z0-9 _.:/@-]{0,64}$")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_ADDR_LEN = 256
_MAX_CRED_LEN = 1024
_MAX_PROBE_BODY_BYTES = 64 * 1024
_PROBE_TIMEOUT_SEC = 4.5
_AUTH_PROBE_TIMEOUT_SEC = 3.0
_KV_IO_TIMEOUT_SEC = 6.0


def _contains_ctrl(value: str) -> bool:
    return bool(_CTRL_CHARS_RE.search(value))


def _validate_openbao_addr(raw: Any, *, allow_empty: bool = False) -> tuple[bool, str, str]:
    """Validate OpenBao server URL strictly (`https://` or explicit loopback `http://`)."""
    if raw is None:
        return (True, "", "") if allow_empty else (False, "", "OpenBao 服务地址不能为空")
    if not isinstance(raw, str):
        return False, "", "OpenBao 服务地址必须为字符串"
    s = raw.strip()
    if not s:
        return (True, "", "") if allow_empty else (False, "", "OpenBao 服务地址不能为空")
    if len(s) > _MAX_ADDR_LEN:
        return False, "", f"OpenBao 服务地址长度不能超过 {_MAX_ADDR_LEN} 字符"
    if _contains_ctrl(s) or any(ch.isspace() for ch in s):
        return False, "", "OpenBao 服务地址包含非法空白或控制字符"

    try:
        parsed = urlsplit(s)
    except ValueError:
        return False, "", "OpenBao 服务地址格式无效"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https", "http"):
        return False, "", "OpenBao 服务地址仅允许 https:// 或本机 loopback http:// 协议"
    if parsed.username is not None or parsed.password is not None:
        return False, "", "OpenBao 服务地址禁止内嵌用户名或密码"
    if parsed.query or parsed.fragment:
        return False, "", "OpenBao 服务地址禁止包含查询参数或锚点"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "", "OpenBao 服务地址缺少有效主机名"
    if scheme == "http" and hostname not in _LOOPBACK_HOSTS:
        return False, "", "明文 http:// 仅允许本机 loopback 地址（127.0.0.1 / localhost）"

    try:
        port = parsed.port
    except ValueError:
        return False, "", "OpenBao 服务地址端口无效"
    if port is not None and not (1 <= port <= 65535):
        return False, "", "OpenBao 服务地址端口超出有效范围"

    clean_path = (parsed.path or "").rstrip("/")
    if ".." in clean_path.split("/"):
        return False, "", "OpenBao 服务地址路径不允许包含 .."

    netloc = parsed.netloc
    normalized = f"{scheme}://{netloc}{clean_path}"
    return True, normalized, ""


def _validate_kv_mount(raw: Any) -> tuple[bool, str, str]:
    if not isinstance(raw, str):
        return False, "", "KV 挂载点必须为字符串"
    s = raw.strip().strip("/")
    if not s or ".." in s or not _KV_SEGMENT_RE.fullmatch(s):
        return False, "", "KV 挂载点仅允许字母、数字、点、下划线与连字符（1-64 字符）"
    return True, s, ""


def _validate_gateway_path_prefix(raw: Any) -> tuple[bool, str, str]:
    if not isinstance(raw, str):
        return False, "", "外部模型存储前缀必须为字符串"
    s = raw.strip().strip("/")
    if not s:
        return False, "", "外部模型存储前缀不能为空"
    parts = s.split("/")
    if len(parts) > 6:
        return False, "", "外部模型存储前缀层级不能超过 6 层"
    for seg in parts:
        if seg in ("", ".", "..") or not _KV_SEGMENT_RE.fullmatch(seg):
            return False, "", "外部模型存储前缀每段仅允许字母、数字、点、下划线与连字符"
    return True, "/".join(parts), ""


def _validate_auth_label(raw: Any) -> tuple[bool, str, str]:
    if raw is None:
        return True, "", ""
    if not isinstance(raw, str):
        return False, "", "认证标识必须为字符串"
    s = raw.strip()
    if len(s) > 64 or _contains_ctrl(s) or not _AUTH_LABEL_RE.fullmatch(s):
        return False, "", "认证标识包含非法字符或超过 64 字符"
    return True, s, ""


def _validate_secret_input(raw: Any, field_name: str) -> tuple[bool, str, str]:
    if raw is None:
        return True, "", ""
    if not isinstance(raw, str):
        return False, "", f"{field_name} 必须为字符串"
    s = raw.strip()
    if len(s) > _MAX_CRED_LEN:
        return False, "", f"{field_name} 超过最大长度限制"
    if _contains_ctrl(s):
        return False, "", f"{field_name} 包含非法控制字符"
    return True, s, ""


def _validate_gateway_secret_id(raw: Any) -> tuple[bool, str, str]:
    if not isinstance(raw, str):
        return False, "", "网关 ID 必须为字符串"
    if raw != raw.strip() or _contains_ctrl(raw):
        return False, "", "网关 ID 包含非法空白或控制字符"
    if not raw or ".." in raw or "/" in raw or "\\" in raw:
        return False, "", "网关 ID 包含非法路径字符"
    if raw in _FORBIDDEN_SECRET_IDS or not _GATEWAY_SECRET_ID_RE.fullmatch(raw):
        return False, "", "网关 ID 仅允许小写字母、数字、下划线与连字符（1-32 字符，须以字母或数字开头）"
    return True, raw, ""


def _validate_kv_path(raw: Any) -> tuple[bool, str, str]:
    if not isinstance(raw, str):
        return False, "", "KV 密钥路径必须为字符串"
    s = raw.strip().strip("/")
    if not s or _contains_ctrl(s):
        return False, "", "KV 密钥路径无效"
    parts = s.split("/")
    if len(parts) > 8:
        return False, "", "KV 密钥路径层级超出限制"
    for seg in parts:
        if seg in ("", ".", "..") or not _KV_SEGMENT_RE.fullmatch(seg):
            return False, "", "KV 密钥路径包含非法分段"
    return True, "/".join(parts), ""


def _validate_kv_field(raw: Any) -> tuple[bool, str, str]:
    if not isinstance(raw, str):
        return False, "", "KV 字段名必须为字符串"
    s = raw.strip()
    if not s or _contains_ctrl(s) or not _KV_FIELD_RE.fullmatch(s):
        return False, "", "KV 字段名无效"
    return True, s, ""


def _mask_secret_hint(secret: str) -> str:
    """Return a non-reversible masked hint for display (never returns plaintext)."""
    s = (secret or "").strip()
    if not s:
        return ""
    if "••••" in s:
        return s
    if len(s) <= 6:
        return "••••"
    if len(s) <= 10:
        return f"{s[:2]}••••{s[-2:]}"
    prefix = "sk-" if s.startswith("sk-") else s[:3]
    return f"{prefix}••••{s[-4:]}"


def _ensure_secure_parent_dir(target_path: Path) -> Path:
    parent = target_path.parent
    if parent.is_symlink():
        raise OSError("Refusing symlink config directory")
    parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    return parent


def _write_json_0600_atomic(target_path: Path, payload: dict[str, Any]) -> None:
    """Atomically write JSON with `0700` dir, `0600` file, `O_NOFOLLOW`, and `flock`."""
    parent = _ensure_secure_parent_dir(target_path)
    if target_path.is_symlink():
        raise OSError("Refusing to write symlink file")

    lock_path = parent / f".{target_path.name}.lock"
    if lock_path.is_symlink():
        raise OSError("Refusing symlink lock file")

    lock_flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(str(lock_path), lock_flags, 0o600)
    try:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if target_path.is_symlink():
                raise OSError("Refusing to overwrite symlink file")
            serialized = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{target_path.name}.tmp.",
                dir=str(parent),
            )
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, serialized)
                os.fsync(fd)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
            os.close(fd)
            os.replace(tmp_name, str(target_path))
            try:
                os.chmod(target_path, 0o600)
            except OSError:
                pass
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _read_regular_json_no_symlink(path: Path, max_bytes: int = 128 * 1024) -> dict[str, Any] | None:
    """Safely read a regular JSON file refusing symlinks (`O_NOFOLLOW`)."""
    try:
        if path.is_symlink():
            log.warning("Refusing symlink config file: %s", path.name)
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        try:
            st = os.fstat(fd)
            if not os.path.isfile(path) or st.st_size > max_bytes:
                return None
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                buf = os.read(fd, min(8192, remaining))
                if not buf:
                    break
                chunks.append(buf)
                remaining -= len(buf)
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                return None
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
        finally:
            os.close(fd)
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
            log.debug("Could not read JSON file %s: %s", path.name, type(exc).__name__)
        return None
    except Exception:
        return None


def _read_regular_text_no_symlink(path: Path, max_bytes: int = 8192) -> str:
    try:
        if path.is_symlink():
            return ""
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        try:
            raw = os.read(fd, max_bytes)
            return raw.decode("utf-8", errors="ignore").strip()
        finally:
            os.close(fd)
    except OSError:
        return ""


class SecretStoreError(RuntimeError):
    """Sanitized SecretStore operation failure (never carries raw secret values)."""


class SecretStoreBackend:
    """Base interface for unified pluggable SecretStore backends."""

    backend_id: str = "base"
    priority: int = 99
    status: str = "reserved"

    def describe(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "priority": self.priority,
            "status": self.status,
        }

    def is_available(self) -> bool:
        return False

    async def put_secret(
        self,
        gateway_id: str,
        value: str,
        *,
        field: str = "api_key",
    ) -> dict[str, Any]:
        raise NotImplementedError(f"Secret backend {self.backend_id!r} does not support put_secret")

    async def get_secret(self, ref: dict[str, Any]) -> str | None:
        raise NotImplementedError(f"Secret backend {self.backend_id!r} does not support get_secret")

    async def delete_secret(self, ref: dict[str, Any]) -> bool:
        raise NotImplementedError(f"Secret backend {self.backend_id!r} does not support delete_secret")


class OpenBaoSecretBackend(SecretStoreBackend):
    """OpenBao / Vault KV v2 HTTP backend (zero shell/subprocess calls)."""

    backend_id = "openbao"
    priority = 1
    status = "configurable"

    def __init__(self, config_service: SecretsConfigService | None = None) -> None:
        self._cfg_svc = config_service
        self._cached_approle_tok: tuple[str, float, str] | None = None  # (addr, expires_ts, token)

    def is_available(self) -> bool:
        if self._cfg_svc is None:
            return False
        rt = self._cfg_svc.resolve_openbao_runtime()
        return bool(rt["enabled"] and rt["addr"] and rt["credential_configured"])

    async def _resolve_client_token(
        self,
        cli: aiohttp.ClientSession,
        rt: dict[str, Any],
    ) -> str:
        addr = str(rt["addr"] or "")
        auth_mode = str(rt["auth_mode"] or "host_card")
        if auth_mode == "token":
            return str(rt.get("token") or "")

        # host_card: prefer valid host cached token when targeting exact host addr
        if auth_mode == "host_card" and rt.get("is_host_addr_match"):
            cached_tok = str(rt.get("host_cached_token") or "")
            if cached_tok:
                return cached_tok

        # In-memory AppRole token cache
        now = time.time()
        if (
            self._cached_approle_tok is not None
            and self._cached_approle_tok[0] == addr
            and self._cached_approle_tok[1] > (now + 30.0)
            and self._cached_approle_tok[2]
        ):
            return self._cached_approle_tok[2]

        role_id = str(rt.get("role_id") or "")
        secret_id = str(rt.get("secret_id") or "")
        if not role_id or not secret_id:
            return ""

        login_url = f"{addr}/v1/auth/approle/login"
        async with cli.post(
            login_url,
            json={"role_id": role_id, "secret_id": secret_id},
            allow_redirects=False,
            headers={"Accept": "application/json"},
        ) as resp:
            raw = await resp.content.read(_MAX_PROBE_BODY_BYTES + 1)
            if resp.status != 200 or len(raw) > _MAX_PROBE_BODY_BYTES:
                raise SecretStoreError(f"OpenBao AppRole 鉴权失败（HTTP {resp.status}）")
            try:
                data = json.loads(raw.decode("utf-8", errors="ignore"))
            except Exception as exc:
                raise SecretStoreError("OpenBao AppRole 响应解析失败") from exc
            auth_obj = data.get("auth") if isinstance(data, dict) else None
            tok = str((auth_obj or {}).get("client_token") or "").strip()
            lease = (auth_obj or {}).get("lease_duration")
            if not tok:
                raise SecretStoreError("OpenBao AppRole 未返回有效 Token")
            ttl = float(lease) if isinstance(lease, (int, float)) and lease > 60 else 1800.0
            self._cached_approle_tok = (addr, now + ttl, tok)
            return tok

    async def put_secret(
        self,
        gateway_id: str,
        value: str,
        *,
        field: str = "api_key",
    ) -> dict[str, Any]:
        if self._cfg_svc is None:
            raise SecretStoreError("OpenBao 配置服务未初始化")
        ok_id, norm_id, err_id = _validate_gateway_secret_id(gateway_id)
        if not ok_id:
            raise ValueError(err_id)
        ok_f, norm_field, err_f = _validate_kv_field(field)
        if not ok_f:
            raise ValueError(err_f)

        rt = self._cfg_svc.resolve_openbao_runtime()
        if not rt["enabled"] or not rt["addr"]:
            raise SecretStoreError("OpenBao 未启用或未配置有效地址")
        ok_m, kv_mount, err_m = _validate_kv_mount(rt["kv_mount"])
        if not ok_m:
            raise ValueError(err_m)
        ok_p, prefix, err_p = _validate_gateway_path_prefix(rt["gateway_path_prefix"])
        if not ok_p:
            raise ValueError(err_p)

        secret_path = f"{prefix}/{norm_id}"
        ok_fp, norm_path, err_fp = _validate_kv_path(secret_path)
        if not ok_fp:
            raise ValueError(err_fp)

        url = f"{rt['addr']}/v1/{kv_mount}/data/{norm_path}"
        now_ts = int(time.time())
        timeout = aiohttp.ClientTimeout(total=_KV_IO_TIMEOUT_SEC, connect=3.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as cli:
                token = await self._resolve_client_token(cli, rt)
                if not token:
                    raise SecretStoreError("OpenBao 缺少有效认证凭据")
                async with cli.post(
                    url,
                    json={"data": {norm_field: value, "updated_at": now_ts}},
                    headers={"X-Vault-Token": token, "Accept": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    raw = await resp.content.read(_MAX_PROBE_BODY_BYTES + 1)
                    if 300 <= resp.status < 400:
                        raise SecretStoreError(f"OpenBao 写入返回重定向（HTTP {resp.status}），已拒绝")
                    if resp.status not in (200, 204):
                        raise SecretStoreError(f"OpenBao KV 写入失败（HTTP {resp.status}）")
                    ver = 1
                    try:
                        parsed = json.loads(raw.decode("utf-8", errors="ignore"))
                        v = ((parsed.get("data") or {}) if isinstance(parsed, dict) else {}).get("version")
                        if isinstance(v, int) and v > 0:
                            ver = v
                    except Exception:
                        pass
        except (ValueError, SecretStoreError):
            raise
        except Exception as exc:
            raise SecretStoreError(f"OpenBao KV 写入网络异常（{type(exc).__name__}）") from exc

        return {
            "backend": self.backend_id,
            "kv_mount": kv_mount,
            "path": norm_path,
            "field": norm_field,
            "version": ver,
            "updated_at": now_ts,
        }

    async def get_secret(self, ref: dict[str, Any]) -> str | None:
        if self._cfg_svc is None or not isinstance(ref, dict):
            return None
        rt = self._cfg_svc.resolve_openbao_runtime()
        if not rt["addr"]:
            return None
        ok_m, kv_mount, _ = _validate_kv_mount(ref.get("kv_mount") or rt["kv_mount"])
        ok_p, norm_path, _ = _validate_kv_path(ref.get("path") or "")
        ok_f, norm_field, _ = _validate_kv_field(ref.get("field") or "api_key")
        if not (ok_m and ok_p and ok_f):
            return None

        url = f"{rt['addr']}/v1/{kv_mount}/data/{norm_path}"
        timeout = aiohttp.ClientTimeout(total=_KV_IO_TIMEOUT_SEC, connect=3.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as cli:
                token = await self._resolve_client_token(cli, rt)
                if not token:
                    return None
                async with cli.get(
                    url,
                    headers={"X-Vault-Token": token, "Accept": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    raw = await resp.content.read(_MAX_PROBE_BODY_BYTES + 1)
                    if resp.status != 200 or len(raw) > _MAX_PROBE_BODY_BYTES:
                        return None
                    parsed = json.loads(raw.decode("utf-8", errors="ignore"))
                    inner = (
                        ((parsed.get("data") or {}).get("data"))
                        if isinstance(parsed, dict)
                        else None
                    )
                    if isinstance(inner, dict):
                        val = inner.get(norm_field)
                        return str(val).strip() if isinstance(val, str) and val.strip() else None
        except Exception as exc:
            log.warning("OpenBao KV read failed: %s", type(exc).__name__)
            return None
        return None

    async def delete_secret(self, ref: dict[str, Any]) -> bool:
        if self._cfg_svc is None or not isinstance(ref, dict):
            return False
        rt = self._cfg_svc.resolve_openbao_runtime()
        if not rt["addr"]:
            return False
        ok_m, kv_mount, _ = _validate_kv_mount(ref.get("kv_mount") or rt["kv_mount"])
        ok_p, norm_path, _ = _validate_kv_path(ref.get("path") or "")
        if not (ok_m and ok_p):
            return False

        meta_url = f"{rt['addr']}/v1/{kv_mount}/metadata/{norm_path}"
        data_url = f"{rt['addr']}/v1/{kv_mount}/data/{norm_path}"
        timeout = aiohttp.ClientTimeout(total=_KV_IO_TIMEOUT_SEC, connect=3.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as cli:
                token = await self._resolve_client_token(cli, rt)
                if not token:
                    return False
                async with cli.delete(
                    meta_url,
                    headers={"X-Vault-Token": token, "Accept": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    await resp.content.read(4096)
                    if resp.status in (200, 204, 404):
                        return True
                async with cli.delete(
                    data_url,
                    headers={"X-Vault-Token": token, "Accept": "application/json"},
                    allow_redirects=False,
                ) as resp2:
                    await resp2.content.read(4096)
                    return resp2.status in (200, 204, 404)
        except Exception as exc:
            log.warning("OpenBao KV delete failed: %s", type(exc).__name__)
            return False


class SecurityCardSecretBackend(SecretStoreBackend):
    """Reserved pluggable slot for future hardware/software security card integration."""

    backend_id = "security_card"
    priority = 2
    status = DEFAULT_SECURITY_CARD_STATUS

    def is_available(self) -> bool:
        return False


class LocalFile0600SecretBackend(SecretStoreBackend):
    """Managed local `0600` JSON secret store (`0700` dir, `O_NOFOLLOW`, `flock` atomic write)."""

    backend_id = "local_0600"
    priority = 3
    status = "fallback_ready"

    def __init__(self, secrets_path: Path | None = None) -> None:
        env_p = os.environ.get("AGY_STUDIO_GATEWAY_SECRETS_FILE", "").strip()
        default_p = Path.home() / ".config" / "agy-tg-bridge" / "gateway_secrets.json"
        self.secrets_path = Path(secrets_path) if secrets_path else Path(env_p or str(default_p))

    def is_available(self) -> bool:
        return True

    def _load_slots(self) -> dict[str, Any]:
        doc = _read_regular_json_no_symlink(self.secrets_path, max_bytes=512 * 1024)
        if not isinstance(doc, dict):
            return {}
        slots = doc.get("slots")
        return dict(slots) if isinstance(slots, dict) else {}

    def _mutate_slots_atomic(self, mutator: Any) -> Any:
        parent = _ensure_secure_parent_dir(self.secrets_path)
        if self.secrets_path.is_symlink():
            raise OSError("Refusing symlink gateway secrets file")
        lock_path = parent / f".{self.secrets_path.name}.lock"
        if lock_path.is_symlink():
            raise OSError("Refusing symlink gateway secrets lock file")

        lock_flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(str(lock_path), lock_flags, 0o600)
        try:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if self.secrets_path.is_symlink():
                    raise OSError("Refusing to overwrite symlink gateway secrets file")
                slots = self._load_slots()
                result = mutator(slots)
                payload = {
                    "version": 1,
                    "updated_at": int(time.time()),
                    "slots": slots,
                }
                serialized = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{self.secrets_path.name}.tmp.",
                    dir=str(parent),
                )
                try:
                    os.fchmod(fd, 0o600)
                    os.write(fd, serialized)
                    os.fsync(fd)
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
                os.close(fd)
                os.replace(tmp_name, str(self.secrets_path))
                try:
                    os.chmod(self.secrets_path, 0o600)
                except OSError:
                    pass
                return result
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    async def put_secret(
        self,
        gateway_id: str,
        value: str,
        *,
        field: str = "api_key",
    ) -> dict[str, Any]:
        ok_id, norm_id, err_id = _validate_gateway_secret_id(gateway_id)
        if not ok_id:
            raise ValueError(err_id)
        ok_f, norm_field, err_f = _validate_kv_field(field)
        if not ok_f:
            raise ValueError(err_f)
        now_ts = int(time.time())

        def _write(slots: dict[str, Any]) -> None:
            entry = dict(slots.get(norm_id)) if isinstance(slots.get(norm_id), dict) else {}
            entry[norm_field] = value
            entry["updated_at"] = now_ts
            slots[norm_id] = entry

        self._mutate_slots_atomic(_write)
        return {
            "backend": self.backend_id,
            "slot": norm_id,
            "field": norm_field,
            "updated_at": now_ts,
        }

    async def get_secret(self, ref: dict[str, Any]) -> str | None:
        if not isinstance(ref, dict):
            return None
        ok_id, norm_id, _ = _validate_gateway_secret_id(ref.get("slot") or "")
        ok_f, norm_field, _ = _validate_kv_field(ref.get("field") or "api_key")
        if not (ok_id and ok_f):
            return None
        slots = self._load_slots()
        entry = slots.get(norm_id)
        if not isinstance(entry, dict):
            return None
        val = entry.get(norm_field)
        return str(val).strip() if isinstance(val, str) and val.strip() else None

    async def delete_secret(self, ref: dict[str, Any]) -> bool:
        if not isinstance(ref, dict):
            return False
        ok_id, norm_id, _ = _validate_gateway_secret_id(ref.get("slot") or "")
        if not ok_id:
            return False

        def _remove(slots: dict[str, Any]) -> bool:
            return slots.pop(norm_id, None) is not None

        try:
            return bool(self._mutate_slots_atomic(_remove))
        except OSError as exc:
            log.warning("Local 0600 secret delete failed: %s", type(exc).__name__)
            return False


class SecretStore:
    """Unified SecretStore orchestrator: OpenBao (priority 1) -> SecurityCard (reserved) -> local_0600 (fallback)."""

    def __init__(
        self,
        config_service: SecretsConfigService,
        *,
        local_secrets_path: Path | None = None,
    ) -> None:
        self.config_service = config_service
        self.openbao = OpenBaoSecretBackend(config_service)
        self.security_card = SecurityCardSecretBackend()
        self.local_0600 = LocalFile0600SecretBackend(secrets_path=local_secrets_path)
        self.backends: list[SecretStoreBackend] = [
            self.openbao,
            self.security_card,
            self.local_0600,
        ]

    def active_default_backend(self) -> str:
        return "openbao" if self.openbao.is_available() else "local_0600"

    def describe_status(self) -> dict[str, Any]:
        ob_ready = self.openbao.is_available()
        return {
            "active_backend": "openbao" if ob_ready else "local_0600",
            "openbao_ready": ob_ready,
            "fallback_mode": DEFAULT_FALLBACK_MODE,
            "security_card_status": DEFAULT_SECURITY_CARD_STATUS,
            "backends": [b.describe() for b in self.backends],
        }

    async def store_gateway_secret(
        self,
        gateway_id: str,
        api_key: str,
        *,
        preferred_backend: str | None = None,
    ) -> tuple[dict[str, Any], str, bool]:
        """Store gateway API key in best available backend.

        Returns `(secret_ref, backend_used, fallback_used)`.
        Raises `ValueError` on invalid `gateway_id`/mount/prefix; raises `OSError` on local storage refusal.
        """
        ok_id, norm_id, err_id = _validate_gateway_secret_id(gateway_id)
        if not ok_id:
            raise ValueError(err_id)
        ok_key, norm_key, err_key = _validate_secret_input(api_key, "API Key")
        if not ok_key or not norm_key:
            raise ValueError(err_key or "API Key 不能为空")

        pref = (preferred_backend or "").strip().lower()
        if pref == "security_card":
            raise ValueError("安全卡（security_card）当前为预留后端，暂未开放写入")

        if pref != "local_0600" and self.openbao.is_available():
            try:
                ref = await self.openbao.put_secret(norm_id, norm_key)
                return ref, "openbao", False
            except ValueError:
                raise
            except SecretStoreError as exc:
                log.warning("OpenBao put_secret unavailable (%s); falling back to local_0600", exc)
                ref = await self.local_0600.put_secret(norm_id, norm_key)
                return ref, "local_0600", True

        ref = await self.local_0600.put_secret(norm_id, norm_key)
        return ref, "local_0600", False

    async def resolve_gateway_secret(self, ref: dict[str, Any] | None) -> str:
        if not isinstance(ref, dict):
            return ""
        backend = str(ref.get("backend") or "").strip().lower()
        if backend == "openbao":
            val = await self.openbao.get_secret(ref)
            return val or ""
        if backend == "local_0600":
            val = await self.local_0600.get_secret(ref)
            return val or ""
        return ""

    async def delete_gateway_secret(self, ref: dict[str, Any] | None) -> bool:
        if not isinstance(ref, dict):
            return False
        backend = str(ref.get("backend") or "").strip().lower()
        if backend == "openbao":
            return await self.openbao.delete_secret(ref)
        if backend == "local_0600":
            return await self.local_0600.delete_secret(ref)
        return False


class SecretsConfigService:
    """Manages OpenBao configuration, host runtime auto-detection, SecretStore, and connectivity tests."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        audit: StudioAuditLogger,
        *,
        config_path: Path | None = None,
        host_openbao_dir: Path | None = None,
        local_secrets_path: Path | None = None,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.audit = audit
        env_cfg = os.environ.get("AGY_STUDIO_SECRETS_CONFIG", "").strip()
        default_cfg = Path.home() / ".config" / "agy-tg-bridge" / "studio_secrets.json"
        self.config_path = Path(config_path) if config_path else Path(env_cfg or str(default_cfg))
        self.host_openbao_dir = (
            Path(host_openbao_dir)
            if host_openbao_dir
            else (Path.home() / ".config" / "openbao")
        )
        self.secret_store = SecretStore(self, local_secrets_path=local_secrets_path)
        self.backends: list[SecretStoreBackend] = list(self.secret_store.backends)

    # ---------------------------------------------------------------- Storage (0700 / 0600 + flock)
    def _ensure_secure_parent(self) -> Path:
        parent = self.config_path.parent
        if parent.is_symlink():
            raise OSError("Refusing symlink config directory")
        parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        return parent

    def _load_saved_config(self) -> dict[str, Any]:
        data = _read_regular_json_no_symlink(self.config_path)
        return data if isinstance(data, dict) else {}

    def _save_config_atomic(self, payload: dict[str, Any]) -> None:
        parent = self._ensure_secure_parent()
        if self.config_path.is_symlink():
            raise OSError("Refusing to write symlink config file")

        lock_path = parent / f".{self.config_path.name}.lock"
        if lock_path.is_symlink():
            raise OSError("Refusing symlink lock file")

        lock_flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(str(lock_path), lock_flags, 0o600)
        try:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if self.config_path.is_symlink():
                    raise OSError("Refusing to overwrite symlink config file")
                serialized = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{self.config_path.name}.tmp.",
                    dir=str(parent),
                )
                try:
                    os.fchmod(fd, 0o600)
                    os.write(fd, serialized)
                    os.fsync(fd)
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
                os.close(fd)
                os.replace(tmp_name, str(self.config_path))
                try:
                    os.chmod(self.config_path, 0o600)
                except OSError:
                    pass
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    # ---------------------------------------------------------------- Host OpenBao Runtime Auto-Detection
    def _detect_host_openbao(self) -> dict[str, Any]:
        """Auto-detect existing OpenBao config from host runtime without hardcoding personal values.

        Never returns raw secrets; extracts only non-sensitive metadata and presence flags.
        """
        env_card = os.environ.get("OPENBAO_CONFIG_PATH", "").strip()
        card_path = Path(env_card) if env_card else (self.host_openbao_dir / "card.json")
        token_cache_path = self.host_openbao_dir / "token.json"

        card_data = _read_regular_json_no_symlink(card_path)
        token_cache = _read_regular_json_no_symlink(token_cache_path)

        addr = ""
        auth_mode = "host_card"
        auth_label = ""
        has_approle_cred = False
        has_cached_token = False
        has_env_token = False

        if card_data:
            raw_addr = (
                card_data.get("base_url")
                or card_data.get("bao_addr")
                or card_data.get("addr")
                or ""
            )
            ok_addr, norm_addr, _ = _validate_openbao_addr(raw_addr, allow_empty=True)
            if ok_addr and norm_addr:
                addr = norm_addr

            raw_label = card_data.get("card_name") or card_data.get("card") or ""
            ok_lbl, norm_lbl, _ = _validate_auth_label(raw_label)
            if ok_lbl and norm_lbl:
                auth_label = norm_lbl

            role_id = str(card_data.get("role_id") or "").strip()
            secret_id = str(card_data.get("secret_id") or "").strip()
            if role_id and secret_id:
                has_approle_cred = True
                auth_mode = "host_card"

        if token_cache:
            cached_tok = str(token_cache.get("client_token") or "").strip()
            expires_ms = token_cache.get("expires_at_approx")
            if cached_tok:
                if isinstance(expires_ms, (int, float)) and expires_ms > (time.time() * 1000 + 60_000):
                    has_cached_token = True
                elif expires_ms is None:
                    has_cached_token = True

        # Fallback to standard BAO_ADDR / VAULT_ADDR env vars
        if not addr:
            env_addr = (os.environ.get("BAO_ADDR") or os.environ.get("VAULT_ADDR") or "").strip()
            ok_addr, norm_addr, _ = _validate_openbao_addr(env_addr, allow_empty=True)
            if ok_addr and norm_addr:
                addr = norm_addr

        # Fallback to standard token env or ~/.bao-token / ~/.vault-token
        env_tok = (os.environ.get("BAO_TOKEN") or os.environ.get("VAULT_TOKEN") or "").strip()
        if env_tok:
            has_env_token = True
        else:
            for tok_file in (Path.home() / ".bao-token", Path.home() / ".vault-token"):
                if _read_regular_text_no_symlink(tok_file):
                    has_env_token = True
                    break

        if not has_approle_cred and has_env_token:
            auth_mode = "token"
            if not auth_label:
                auth_label = "env-token"

        credential_configured = bool(has_approle_cred or has_cached_token or has_env_token)
        if has_approle_cred and has_cached_token:
            credential_hint = "本机 OpenBao 卡片凭据已就绪（AppRole + 有效缓存 Token，0600 保护）"
        elif has_approle_cred:
            credential_hint = "本机 OpenBao 卡片凭据已就绪（AppRole，0600 保护）"
        elif has_cached_token:
            credential_hint = "本机 OpenBao 缓存 Token 已就绪（0600 保护）"
        elif has_env_token:
            credential_hint = "本机环境变量 / Token 文件已就绪"
        else:
            credential_hint = "未检测到本机 OpenBao 凭据"

        detected = bool(addr)
        return {
            "detected": detected,
            "addr": addr,
            "kv_mount": DEFAULT_KV_MOUNT,
            "gateway_path_prefix": DEFAULT_GATEWAY_PATH_PREFIX,
            "auth_mode": auth_mode,
            "auth_label": auth_label,
            "credential_configured": credential_configured,
            "credential_hint": credential_hint,
            "bao_cli_available": bool(shutil.which("bao")),
        }

    def _get_host_cached_token_if_valid(self) -> str:
        """Return valid host cached token strictly for local probe against the exact host addr."""
        token_cache = _read_regular_json_no_symlink(self.host_openbao_dir / "token.json")
        if not token_cache:
            return ""
        tok = str(token_cache.get("client_token") or "").strip()
        if not tok:
            return ""
        expires_ms = token_cache.get("expires_at_approx")
        if isinstance(expires_ms, (int, float)) and expires_ms <= (time.time() * 1000 + 30_000):
            return ""
        return tok

    def _get_host_env_or_file_token(self) -> str:
        env_tok = (os.environ.get("BAO_TOKEN") or os.environ.get("VAULT_TOKEN") or "").strip()
        if env_tok:
            return env_tok
        for tok_file in (Path.home() / ".bao-token", Path.home() / ".vault-token"):
            val = _read_regular_text_no_symlink(tok_file)
            if val:
                return val
        return ""

    def _get_host_card_approle(self) -> tuple[str, str]:
        env_card = os.environ.get("OPENBAO_CONFIG_PATH", "").strip()
        card_path = Path(env_card) if env_card else (self.host_openbao_dir / "card.json")
        card_data = _read_regular_json_no_symlink(card_path)
        if not card_data:
            return "", ""
        return (
            str(card_data.get("role_id") or "").strip(),
            str(card_data.get("secret_id") or "").strip(),
        )

    def resolve_openbao_runtime(self) -> dict[str, Any]:
        """Resolve effective OpenBao runtime settings + internal auth creds for SecretStore.

        Internal only: MUST NEVER be returned directly in any HTTP response.
        """
        saved = self._load_saved_config()
        saved_ob = saved.get("openbao") if isinstance(saved.get("openbao"), dict) else {}
        host = self._detect_host_openbao()
        saved_mode = str(saved_ob.get("mode") or "").strip().lower()

        if saved_mode == "custom":
            enabled = bool(saved_ob.get("enabled", True))
            ok_addr, addr, _ = _validate_openbao_addr(saved_ob.get("addr"), allow_empty=True)
            addr = addr if ok_addr else ""
            kv_mount = str(saved_ob.get("kv_mount") or DEFAULT_KV_MOUNT)
            gateway_path_prefix = str(
                saved_ob.get("gateway_path_prefix") or DEFAULT_GATEWAY_PATH_PREFIX
            )
            auth_mode = str(saved_ob.get("auth_mode") or "host_card").strip().lower()
            if auth_mode not in _VALID_AUTH_MODES:
                auth_mode = "host_card"
            is_host_match = bool(host["detected"] and addr and addr == host["addr"])

            token = ""
            role_id = ""
            secret_id = ""
            host_cached_token = ""
            if auth_mode == "token":
                token = str(saved_ob.get("token") or "").strip()
            elif auth_mode == "approle":
                role_id = str(saved_ob.get("role_id") or "").strip()
                secret_id = str(saved_ob.get("secret_id") or "").strip()
            else:
                if is_host_match:
                    host_cached_token = self._get_host_cached_token_if_valid()
                    role_id, secret_id = self._get_host_card_approle()
        else:
            kv_mount = str(saved_ob.get("kv_mount") or host["kv_mount"] or DEFAULT_KV_MOUNT)
            gateway_path_prefix = str(
                saved_ob.get("gateway_path_prefix")
                or host["gateway_path_prefix"]
                or DEFAULT_GATEWAY_PATH_PREFIX
            )
            enabled = bool(saved_ob.get("enabled", True)) if host["detected"] else False
            addr = host["addr"] if host["detected"] else ""
            auth_mode = host["auth_mode"] if host["detected"] else "host_card"
            is_host_match = bool(host["detected"] and addr)

            token = self._get_host_env_or_file_token() if auth_mode == "token" else ""
            host_cached_token = self._get_host_cached_token_if_valid() if is_host_match else ""
            role_id, secret_id = self._get_host_card_approle() if is_host_match else ("", "")

        credential_configured = bool(
            token or host_cached_token or (role_id and secret_id)
        )
        return {
            "enabled": enabled,
            "addr": addr,
            "kv_mount": kv_mount,
            "gateway_path_prefix": gateway_path_prefix,
            "auth_mode": auth_mode,
            "token": token,
            "host_cached_token": host_cached_token,
            "role_id": role_id,
            "secret_id": secret_id,
            "is_host_addr_match": is_host_match,
            "credential_configured": credential_configured,
        }

    def _build_effective_view(self, *, is_admin: bool) -> dict[str, Any]:
        saved = self._load_saved_config()
        saved_ob = saved.get("openbao") if isinstance(saved.get("openbao"), dict) else {}
        host = self._detect_host_openbao()

        saved_mode = str(saved_ob.get("mode") or "").strip().lower()
        updated_at = saved.get("updated_at") if isinstance(saved.get("updated_at"), (int, float)) else None

        if saved_mode == "custom":
            source = "custom"
            enabled = bool(saved_ob.get("enabled", True))
            addr = str(saved_ob.get("addr") or "")
            kv_mount = str(saved_ob.get("kv_mount") or DEFAULT_KV_MOUNT)
            gateway_path_prefix = str(
                saved_ob.get("gateway_path_prefix") or DEFAULT_GATEWAY_PATH_PREFIX
            )
            auth_mode = str(saved_ob.get("auth_mode") or "host_card")
            if auth_mode not in _VALID_AUTH_MODES:
                auth_mode = "host_card"
            auth_label = str(saved_ob.get("auth_label") or "")

            has_saved_token = bool(str(saved_ob.get("token") or "").strip())
            has_saved_approle = bool(
                str(saved_ob.get("role_id") or "").strip()
                and str(saved_ob.get("secret_id") or "").strip()
            )
            if auth_mode == "host_card":
                credential_configured = bool(host["credential_configured"])
                credential_hint = (
                    host["credential_hint"]
                    if host["credential_configured"]
                    else "已选择本机 OpenBao 卡模式，但未检测到本机卡片凭据"
                )
            elif auth_mode == "token":
                credential_configured = has_saved_token
                credential_hint = (
                    "已保存自定义 Client Token（服务端 0600 保护，不回显明文）"
                    if has_saved_token
                    else "尚未填写 Client Token"
                )
            else:
                credential_configured = has_saved_approle
                credential_hint = (
                    "已保存自定义 AppRole 凭据（服务端 0600 保护，不回显明文）"
                    if has_saved_approle
                    else "尚未完整填写 AppRole Role ID 与 Secret ID"
                )
        else:
            # Default: auto-inherit host OpenBao configuration if present
            kv_mount = str(saved_ob.get("kv_mount") or host["kv_mount"] or DEFAULT_KV_MOUNT)
            gateway_path_prefix = str(
                saved_ob.get("gateway_path_prefix")
                or host["gateway_path_prefix"]
                or DEFAULT_GATEWAY_PATH_PREFIX
            )
            if host["detected"]:
                source = "host_auto"
                enabled = bool(saved_ob.get("enabled", True))
                addr = host["addr"]
                auth_mode = host["auth_mode"]
                auth_label = host["auth_label"]
                credential_configured = bool(host["credential_configured"])
                credential_hint = host["credential_hint"]
            else:
                source = "unconfigured"
                enabled = False
                addr = ""
                auth_mode = "host_card"
                auth_label = ""
                credential_configured = False
                credential_hint = "未检测到本机 OpenBao 配置，可手动填写或使用本机 0600 兜底"

        if not is_admin:
            # Readonly users MUST NOT see real OpenBao addr or auth_label
            return {
                "ok": True,
                "enabled": enabled,
                "source": source,
                "addr": "",
                "kv_mount": kv_mount,
                "gateway_path_prefix": gateway_path_prefix,
                "auth_mode": auth_mode,
                "auth_label": "",
                "credential_configured": credential_configured,
                "credential_hint": (
                    "已配置凭据（只读视图已隐藏地址与认证详情）"
                    if credential_configured
                    else "未配置凭据"
                ),
                "fallback_mode": DEFAULT_FALLBACK_MODE,
                "security_card_status": DEFAULT_SECURITY_CARD_STATUS,
                "can_edit": False,
                "host_auto_available": bool(host["detected"]),
                "bao_cli_available": bool(host["bao_cli_available"]),
                "updated_at": updated_at,
            }

        return {
            "ok": True,
            "enabled": enabled,
            "source": source,
            "addr": addr,
            "kv_mount": kv_mount,
            "gateway_path_prefix": gateway_path_prefix,
            "auth_mode": auth_mode,
            "auth_label": auth_label,
            "credential_configured": credential_configured,
            "credential_hint": credential_hint,
            "fallback_mode": DEFAULT_FALLBACK_MODE,
            "security_card_status": DEFAULT_SECURITY_CARD_STATUS,
            "can_edit": True,
            "host_auto_available": bool(host["detected"]),
            "bao_cli_available": bool(host["bao_cli_available"]),
            "updated_at": updated_at,
        }

    # ---------------------------------------------------------------- 4-Layer Write Gate
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "openbao",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)

        # Gate 1: Strict Same-Origin
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_origin",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 2: Non-simple Content-Type
        media_type = _extract_media_type(request)
        if media_type != "application/json":
            self.audit.record(
                action=action,
                status_code=415,
                outcome="denied_content_type",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(
                "写接口仅接受 Content-Type: application/json",
                status=415,
            )

        # Gate 3: Authenticated session + live RBAC + must_change_password=False
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(
                action=action,
                status_code=status_code,
                outcome="denied_auth",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(err_auth, status=status_code)

        # Gate 4a: CSRF token verification
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_csrf",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC admin role
        if sess.get("role") != "admin":
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_rbac",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return False, None, studio_auth_error(
                "只读权限（readonly）禁止修改或测试 OpenBao 配置",
                status=403,
            )

        return True, sess, None

    # ---------------------------------------------------------------- Handlers
    async def handle_get_openbao(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        is_admin = sess.get("role") == "admin"
        return web.json_response(self._build_effective_view(is_admin=is_admin))

    async def handle_put_openbao(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="secrets_openbao_update",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("写操作被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_status, body_outcome, body_err = await _read_bounded_json_body(
            request,
            allow_empty=False,
        )
        if not ok_body or body is None:
            self.audit.record(
                action="secrets_openbao_update",
                status_code=body_status,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id="openbao",
                sess=sess,
            )
            return studio_auth_error(body_err, status=body_status)

        now_ts = int(time.time())

        # Support one-click reset to host auto-detection
        if body.get("reset_to_host_auto") is True:
            reset_doc: dict[str, Any] = {
                "version": 1,
                "updated_at": now_ts,
                "openbao": {
                    "mode": "host_auto",
                    "enabled": True,
                    "kv_mount": DEFAULT_KV_MOUNT,
                    "gateway_path_prefix": DEFAULT_GATEWAY_PATH_PREFIX,
                },
                "fallback_mode": DEFAULT_FALLBACK_MODE,
                "security_card": {"status": DEFAULT_SECURITY_CARD_STATUS},
            }
            try:
                self._save_config_atomic(reset_doc)
            except OSError as exc:
                log.warning("Failed to reset OpenBao config: %s", type(exc).__name__)
                self.audit.record(
                    action="secrets_openbao_reset",
                    status_code=500,
                    outcome="io_error",
                    client_ip=client_ip,
                    target_id="openbao",
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "保存配置失败（文件权限或路径受限）"},
                    status=500,
                )
            self.audit.record(
                action="secrets_openbao_reset",
                status_code=200,
                outcome="ok",
                client_ip=client_ip,
                target_id="openbao",
                sess=sess,
            )
            return web.json_response(self._build_effective_view(is_admin=True))

        # Regular custom update
        existing_doc = self._load_saved_config()
        existing_ob = (
            existing_doc.get("openbao")
            if isinstance(existing_doc.get("openbao"), dict)
            else {}
        )
        host = self._detect_host_openbao()

        enabled = bool(body.get("enabled", True))

        raw_addr = body.get("addr", existing_ob.get("addr") or host["addr"])
        ok_addr, addr, err_addr = _validate_openbao_addr(raw_addr, allow_empty=(not enabled))
        if not ok_addr:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_addr}, status=400)

        raw_mount = body.get("kv_mount", existing_ob.get("kv_mount") or DEFAULT_KV_MOUNT)
        ok_mount, kv_mount, err_mount = _validate_kv_mount(raw_mount)
        if not ok_mount:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_mount}, status=400)

        raw_prefix = body.get(
            "gateway_path_prefix",
            existing_ob.get("gateway_path_prefix") or DEFAULT_GATEWAY_PATH_PREFIX,
        )
        ok_prefix, gateway_path_prefix, err_prefix = _validate_gateway_path_prefix(raw_prefix)
        if not ok_prefix:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_prefix}, status=400)

        auth_mode = str(
            body.get("auth_mode") or existing_ob.get("auth_mode") or host["auth_mode"] or "host_card"
        ).strip().lower()
        if auth_mode not in _VALID_AUTH_MODES:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "不支持的认证方式（仅限 host_card / token / approle）"},
                status=400,
            )

        raw_label = body.get("auth_label", existing_ob.get("auth_label") or host["auth_label"])
        ok_lbl, auth_label, err_lbl = _validate_auth_label(raw_label)
        if not ok_lbl:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_lbl}, status=400)

        ok_tok, new_token, err_tok = _validate_secret_input(body.get("token"), "Token")
        if not ok_tok:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_tok}, status=400)
        ok_rid, new_role_id, err_rid = _validate_secret_input(body.get("role_id"), "Role ID")
        if not ok_rid:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_rid}, status=400)
        ok_sid, new_secret_id, err_sid = _validate_secret_input(body.get("secret_id"), "Secret ID")
        if not ok_sid:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_sid}, status=400)

        clear_credentials = bool(body.get("clear_credentials", False))
        stored_token = "" if clear_credentials else str(existing_ob.get("token") or "").strip()
        stored_role_id = "" if clear_credentials else str(existing_ob.get("role_id") or "").strip()
        stored_secret_id = "" if clear_credentials else str(existing_ob.get("secret_id") or "").strip()

        if new_token:
            stored_token = new_token
        if new_role_id:
            stored_role_id = new_role_id
        if new_secret_id:
            stored_secret_id = new_secret_id

        next_ob: dict[str, Any] = {
            "mode": "custom",
            "enabled": enabled,
            "addr": addr,
            "kv_mount": kv_mount,
            "gateway_path_prefix": gateway_path_prefix,
            "auth_mode": auth_mode,
            "auth_label": auth_label,
        }
        if stored_token:
            next_ob["token"] = stored_token
        if stored_role_id:
            next_ob["role_id"] = stored_role_id
        if stored_secret_id:
            next_ob["secret_id"] = stored_secret_id

        next_doc: dict[str, Any] = {
            "version": 1,
            "updated_at": now_ts,
            "openbao": next_ob,
            "fallback_mode": DEFAULT_FALLBACK_MODE,
            "security_card": {"status": DEFAULT_SECURITY_CARD_STATUS},
        }

        try:
            self._save_config_atomic(next_doc)
        except OSError as exc:
            log.warning("Failed to save OpenBao config: %s", type(exc).__name__)
            self.audit.record(
                action="secrets_openbao_update",
                status_code=500,
                outcome="io_error",
                client_ip=client_ip,
                target_id="openbao",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "保存配置失败（文件权限或路径受限）"},
                status=500,
            )

        self.audit.record(
            action="secrets_openbao_update",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id="openbao",
            sess=sess,
        )
        return web.json_response(self._build_effective_view(is_admin=True))

    async def handle_test_openbao(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="secrets_openbao_test",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("测试请求被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_status, body_outcome, body_err = await _read_bounded_json_body(
            request,
            allow_empty=True,
        )
        if not ok_body or body is None:
            self.audit.record(
                action="secrets_openbao_test",
                status_code=body_status,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id="openbao",
                sess=sess,
            )
            return studio_auth_error(body_err, status=body_status)

        effective = self._build_effective_view(is_admin=True)
        host = self._detect_host_openbao()

        raw_addr = body.get("addr") if isinstance(body.get("addr"), str) and body.get("addr").strip() else effective["addr"]
        ok_addr, target_addr, err_addr = _validate_openbao_addr(raw_addr, allow_empty=False)
        if not ok_addr:
            self.audit.record(
                action="secrets_openbao_test",
                status_code=400,
                outcome="invalid_addr",
                client_ip=client_ip,
                target_id="openbao",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "reachable": False,
                    "initialized": None,
                    "sealed": None,
                    "latency_ms": 0,
                    "message": err_addr,
                },
                status=400,
            )

        health_url = f"{target_addr}/v1/sys/health"
        t0 = time.monotonic()
        reachable = False
        initialized: bool | None = None
        sealed: bool | None = None
        auth_verified: bool | None = None
        http_status: int | None = None
        message = ""
        ok_result = False

        timeout = aiohttp.ClientTimeout(total=_PROBE_TIMEOUT_SEC, connect=3.0)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as cli:
                async with cli.get(
                    health_url,
                    allow_redirects=False,
                    headers={"Accept": "application/json"},
                ) as resp:
                    http_status = resp.status
                    raw_bytes = await resp.content.read(_MAX_PROBE_BODY_BYTES + 1)
                    if len(raw_bytes) > _MAX_PROBE_BODY_BYTES:
                        raw_bytes = raw_bytes[:_MAX_PROBE_BODY_BYTES]

                    if 300 <= resp.status < 400:
                        reachable = False
                        message = f"服务端返回重定向（HTTP {resp.status}），已出于安全策略拒绝跟随"
                    else:
                        reachable = True
                        parsed_health: dict[str, Any] = {}
                        try:
                            obj = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                            if isinstance(obj, dict):
                                parsed_health = obj
                        except Exception:
                            parsed_health = {}

                        if "initialized" in parsed_health:
                            initialized = bool(parsed_health.get("initialized"))
                        if "sealed" in parsed_health:
                            sealed = bool(parsed_health.get("sealed"))

                        if resp.status in (200, 429, 472, 473):
                            ok_result = True if (initialized is not False and sealed is not True) else False
                            if resp.status == 200:
                                message = "OpenBao 服务健康，已初始化且处于解封活跃状态"
                            else:
                                message = f"OpenBao 节点可达且已解封（备用/只读状态 HTTP {resp.status}）"
                        elif resp.status == 501:
                            initialized = False
                            ok_result = False
                            message = "OpenBao 服务可达，但尚未初始化（HTTP 501）"
                        elif resp.status == 503:
                            sealed = True
                            ok_result = False
                            message = "OpenBao 服务可达，但当前处于封印状态（Sealed，HTTP 503）"
                        else:
                            ok_result = False
                            message = f"OpenBao 健康接口返回异常状态码 HTTP {resp.status}"

                # Optional read-only token self-check ONLY when testing the exact host-detected addr
                # with host_card mode (never send host credentials to any other URL)
                auth_mode_req = str(body.get("auth_mode") or effective["auth_mode"] or "").strip().lower()
                if ok_result and auth_mode_req == "host_card" and host["detected"] and target_addr == host["addr"]:
                    cached_tok = self._get_host_cached_token_if_valid()
                    if cached_tok:
                        try:
                            async with cli.get(
                                f"{target_addr}/v1/auth/token/lookup-self",
                                allow_redirects=False,
                                headers={"X-Vault-Token": cached_tok, "Accept": "application/json"},
                                timeout=aiohttp.ClientTimeout(total=_AUTH_PROBE_TIMEOUT_SEC),
                            ) as auth_resp:
                                await auth_resp.content.read(4096)
                                if auth_resp.status == 200:
                                    auth_verified = True
                                    message = "OpenBao 服务健康且本机卡片缓存 Token 鉴权通过"
                                else:
                                    auth_verified = False
                                    message = "OpenBao 服务健康（本机缓存 Token 需刷新）"
                        except Exception:
                            auth_verified = None
        except TimeoutError:
            reachable = False
            ok_result = False
            message = "连接 OpenBao 超时（> 4.5s），请检查服务地址与网络连通性"
        except aiohttp.ClientSSLError:
            reachable = False
            ok_result = False
            message = "OpenBao TLS 证书校验失败，请检查 HTTPS 证书配置"
        except aiohttp.ClientError as exc:
            reachable = False
            ok_result = False
            message = f"无法连接 OpenBao 服务（{type(exc).__name__}）"
        except Exception as exc:
            reachable = False
            ok_result = False
            log.warning("OpenBao health test unexpected error: %s", type(exc).__name__)
            message = "OpenBao 连通性测试失败"

        latency_ms = max(1, int(round((time.monotonic() - t0) * 1000)))
        self.audit.record(
            action="secrets_openbao_test",
            status_code=200,
            outcome="ok" if ok_result else f"probe_failed_{http_status or 'net'}",
            client_ip=client_ip,
            target_id="openbao",
            sess=sess,
        )
        return web.json_response(
            {
                "ok": ok_result,
                "reachable": reachable,
                "initialized": initialized,
                "sealed": sealed,
                "latency_ms": latency_ms,
                "auth_verified": auth_verified,
                "message": message,
            }
        )
