"""X OAuth 2.0 authorization-code flow with a local callback.

The manually configured ``api.user_access_token`` remains valid on its own.
Client ID and Client Secret add a second path: this module binds ``0.0.0.0``,
logs the authorize URL, exchanges the authorization code, and writes the
access token, refresh token, and expiry back into ``config.toml``.
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import hashlib
import html
import ipaddress
import secrets
import socket
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx

AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
CALLBACK_BIND_HOST = "0.0.0.0"
DEFAULT_REDIRECT_PORT = 18765
DEFAULT_TIMEOUT_SEC = 180
TOKEN_REFRESH_SKEW_SEC = 60
OAUTH_SCOPES = "dm.read dm.write tweet.read users.read media.write offline.access"
TOKEN_CONFIG_KEYS = ("user_access_token", "refresh_token", "access_token_expires_at")
_LOOPBACK_FALLBACK = "127.0.0.1"
_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
_IFF_UP = 0x1
_IFF_LOOPBACK = 0x8
_BSD_SOCKADDR = sys.platform in {"darwin", "freebsd", "netbsd", "openbsd"}
_CALLBACK_RANK = ("public", "lan", "cgnat")


class OAuthError(RuntimeError):
    """Raised when X rejects or the local callback cannot complete the flow."""

    def __init__(self, message: str, *, code: str = "") -> None:
        super().__init__(message)
        self.code = code


class OAuthCancelled(OAuthError):
    """Raised when the local callback wait is cancelled."""


@dataclass(frozen=True)
class OAuthTokens:
    access_token: str = ""
    refresh_token: str = ""
    expires_at: int = 0

    def as_config(self) -> dict[str, str | int]:
        return {
            "user_access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "access_token_expires_at": int(self.expires_at),
        }


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, S256 code_challenge)``."""
    verifier = secrets.token_urlsafe(64)
    return verifier, code_challenge_s256(verifier)


def redirect_uri(host: str, port: int) -> str:
    return f"http://{host}:{int(port)}/callback"


def classify_ipv4(address: str) -> str | None:
    """Return ``public``, ``lan``, ``cgnat``, or None when the address should not be advertised."""
    try:
        ip = ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError):
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return None
    if any(ip in network for network in _RFC1918):
        return "lan"
    if ip in _CGNAT:
        return "cgnat"
    if ip.is_global:
        return "public"
    return None


def select_callback_host(addresses: list[str], default_route: str | None = None) -> str:
    """Prefer a public IPv4, then RFC1918, then CGNAT. Within one class, prefer the default route."""
    grouped: dict[str, list[str]] = {kind: [] for kind in _CALLBACK_RANK}
    for address in addresses:
        kind = classify_ipv4(address)
        if kind is None or address in grouped[kind]:
            continue
        grouped[kind].append(address)
    for kind in _CALLBACK_RANK:
        pool = grouped[kind]
        if not pool:
            continue
        if default_route in pool:
            return default_route
        return pool[0]
    return _LOOPBACK_FALLBACK


def preferred_callback_host() -> str:
    """Choose the host shown in the callback URL from addresses on local adapters."""
    addresses = local_ipv4_addresses()
    route = default_route_ipv4()
    if route and route not in addresses:
        addresses.append(route)
    return select_callback_host(addresses, route)


def local_ipv4_addresses() -> list[str]:
    """IPv4 addresses on interfaces that are up and are not loopback."""
    try:
        return _ipv4_from_getifaddrs()
    except Exception:
        return []


def default_route_ipv4() -> str | None:
    """Local IPv4 selected by the route toward the public Internet, without sending a packet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        host = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    if classify_ipv4(host) is None:
        return None
    return host


class _Ifaddrs(ctypes.Structure):
    pass


_Ifaddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_Ifaddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.c_void_p),
    ("ifa_netmask", ctypes.c_void_p),
    ("ifa_dstaddr", ctypes.c_void_p),
    ("ifa_data", ctypes.c_void_p),
]


def _ipv4_from_getifaddrs() -> list[str]:
    libc = ctypes.CDLL(None, use_errno=True)
    getifaddrs = libc.getifaddrs
    freeifaddrs = libc.freeifaddrs
    getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_Ifaddrs))]
    getifaddrs.restype = ctypes.c_int
    freeifaddrs.argtypes = [ctypes.POINTER(_Ifaddrs)]
    freeifaddrs.restype = None
    head = ctypes.POINTER(_Ifaddrs)()
    if getifaddrs(ctypes.byref(head)) != 0:
        return []
    found: list[str] = []
    try:
        current = head
        while current:
            item = current.contents
            flags = int(item.ifa_flags)
            if (flags & _IFF_UP) and not (flags & _IFF_LOOPBACK):
                address = _sockaddr_ipv4(item.ifa_addr)
                if address and address not in found:
                    found.append(address)
            current = item.ifa_next
    finally:
        freeifaddrs(head)
    return found


def _sockaddr_ipv4(address: int | None) -> str | None:
    """Read an IPv4 address from a sockaddr. BSD keeps the family after sa_len; Linux stores it first."""
    if not address:
        return None
    raw = ctypes.string_at(address, 8)
    if _BSD_SOCKADDR:
        is_ipv4 = raw[1] == socket.AF_INET
    else:
        is_ipv4 = int.from_bytes(raw[:2], sys.byteorder) == socket.AF_INET
    if not is_ipv4:
        return None
    try:
        return str(ipaddress.IPv4Address(raw[4:8]))
    except (ipaddress.AddressValueError, ValueError):
        return None


def build_authorize_url(*, client_id: str, redirect_uri: str, state: str, code_challenge: str) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": OAUTH_SCOPES,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


def basic_authorization(client_id: str, client_secret: str) -> str:
    raw = f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}"
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def needs_refresh(tokens: OAuthTokens, now: int | None = None) -> bool:
    """Refresh only an OAuth-managed token whose expiry is known."""
    if not tokens.refresh_token or not tokens.expires_at:
        return False
    current = int(time.time() if now is None else now)
    return current >= int(tokens.expires_at) - TOKEN_REFRESH_SKEW_SEC


def tokens_from_response(payload: Mapping[str, Any], *, now: int | None = None, previous: OAuthTokens | None = None) -> OAuthTokens:
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise OAuthError("X OAuth2 响应缺少 access_token", code="missing_access_token")
    refresh_token = str(payload.get("refresh_token") or "").strip()
    if not refresh_token and previous is not None:
        refresh_token = previous.refresh_token
    try:
        expires_in = int(payload.get("expires_in") or 0)
    except (TypeError, ValueError):
        expires_in = 0
    current = int(time.time() if now is None else now)
    expires_at = current + expires_in if expires_in > 0 else 0
    return OAuthTokens(access_token, refresh_token, expires_at)


def parse_callback_target(target: str, expected_state: str) -> str:
    """Return the authorization code from a loopback redirect target."""
    parsed = urlsplit(target)
    if parsed.path != "/callback":
        raise OAuthError("忽略非回调请求", code="ignored")
    query = parse_qs(parsed.query, keep_blank_values=False)
    state = (query.get("state") or [""])[0]
    if not state or state != expected_state:
        raise OAuthError("OAuth2 回调 state 不匹配，已拒绝这次授权", code="state_mismatch")
    error = (query.get("error") or [""])[0]
    if error:
        description = (query.get("error_description") or [error])[0]
        raise OAuthError(f"X 授权未完成：{description}", code=error)
    code = (query.get("code") or [""])[0].strip()
    if not code:
        raise OAuthError("OAuth2 回调缺少 authorization code", code="missing_code")
    return code


def render_toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def upsert_toml_section(text: str, section: str, updates: Mapping[str, object]) -> str:
    """Replace or append keys inside one TOML table without reformatting the file."""
    lines = text.splitlines()
    header = f"[{section}]"
    start = next((index for index, line in enumerate(lines) if line.strip() == header), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(header)
        lines.extend(f"{key} = {render_toml_value(value)}" for key, value in updates.items())
        return "\n".join(lines) + "\n"

    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = index
            break

    remaining = dict(updates)
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            lines[index] = f"{indent}{key} = {render_toml_value(remaining.pop(key))}"
    if remaining:
        insert_at = end
        extra = [f"{key} = {render_toml_value(value)}" for key, value in remaining.items()]
        lines[insert_at:insert_at] = extra
    suffix = "\n" if text.endswith("\n") or not text else "\n"
    return "\n".join(lines) + suffix


def persist_tokens(config_path: Path, tokens: OAuthTokens) -> None:
    """Write OAuth tokens into the existing ``[api]`` table of ``config.toml``."""
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    updated = upsert_toml_section(existing, "api", tokens.as_config())
    config_path.write_text(updated, encoding="utf-8")


def non_token_config_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Compare plugin config dicts while ignoring persisted OAuth token fields."""
    return _without_token_fields(left) == _without_token_fields(right)


def _without_token_fields(value: Mapping[str, Any]) -> dict[str, Any]:
    copied = {key: _copy_plain(item) for key, item in value.items()}
    api = copied.get("api")
    if isinstance(api, dict):
        for key in TOKEN_CONFIG_KEYS:
            api.pop(key, None)
    return copied


def _copy_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_plain(item) for item in value]
    return value


def _http_response(status: int, reason: str, body: str) -> bytes:
    payload = body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n"
    )
    return head.encode("ascii") + payload


def _read_request_target(data: bytes) -> str:
    text = data.decode("iso-8859-1", errors="replace")
    line = text.split("\r\n", 1)[0]
    parts = line.split(" ")
    if len(parts) < 2 or parts[0].upper() != "GET":
        raise OAuthError("OAuth2 回调仅接受 GET", code="bad_request")
    return parts[1]


class OAuthCallbackServer:
    """One-shot callback server. It listens on ``0.0.0.0`` and advertises a routable host."""

    def __init__(
        self,
        port: int,
        expected_state: str,
        timeout: float,
        *,
        display_host: str = _LOOPBACK_FALLBACK,
    ) -> None:
        self.port = int(port)
        self.expected_state = expected_state
        self.timeout = timeout
        self.display_host = display_host or _LOOPBACK_FALLBACK
        self.bound_port = int(port)
        self._future: asyncio.Future[str] | None = None
        self._server: asyncio.AbstractServer | None = None

    async def wait_for_code(self) -> str:
        loop = asyncio.get_running_loop()
        self._future = loop.create_future()
        try:
            self._server = await asyncio.start_server(self._handle, CALLBACK_BIND_HOST, self.port)
        except OSError as exc:
            raise OAuthError(
                f"无法在 {CALLBACK_BIND_HOST}:{self.port} 监听 OAuth2 回调，请更换 api.oauth_redirect_port 或关闭占用该端口的程序"
            ) from exc
        sockets = tuple(self._server.sockets or ())
        if sockets:
            self.bound_port = int(sockets[0].getsockname()[1])
        try:
            return await asyncio.wait_for(self._future, self.timeout)
        except TimeoutError as exc:
            raise OAuthError(
                f"等待 X 授权回调超时（{int(self.timeout)} 秒）。请确认开发者门户已登记 "
                f"{redirect_uri(self.display_host, self.bound_port)}"
            ) from exc
        finally:
            server = self._server
            self._server = None
            if server is not None:
                server.close()
                await server.wait_closed()

    def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
        future = self._future
        if future is not None and not future.done():
            future.cancel()

    def cancel(self) -> None:
        future = self._future
        if future is not None and not future.done():
            future.set_exception(OAuthCancelled("OAuth2 授权已取消"))
        self.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        status = 500
        reason = "Internal Server Error"
        body = _page("授权失败", "回调处理失败。")
        outcome: str | OAuthError | None = None
        try:
            data = await reader.readuntil(b"\r\n\r\n")
            if len(data) > 8192:
                raise OAuthError("OAuth2 回调请求头过长", code="bad_request")
            target = _read_request_target(data)
            if urlsplit(target).path != "/callback":
                status, reason, body = 404, "Not Found", _page("未找到", "这个地址不是 OAuth2 回调。")
            else:
                outcome = parse_callback_target(target, self.expected_state)
                status, reason, body = 200, "OK", _page("授权成功", "X 授权已完成，可以关闭此页面。")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            status, reason, body = 400, "Bad Request", _page("请求无效", "没有收到完整的 HTTP 请求。")
        except OAuthError as exc:
            outcome = exc
            if exc.code == "ignored":
                status, reason, body = 404, "Not Found", _page("未找到", "这个地址不是 OAuth2 回调。")
            else:
                status, reason, body = 400, "Bad Request", _page("授权失败", str(exc))
        try:
            writer.write(_http_response(status, reason, body))
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        future = self._future
        if future is None or future.done() or outcome is None:
            return
        if isinstance(outcome, str):
            future.set_result(outcome)
        elif outcome.code != "ignored":
            future.set_exception(outcome)


def _page(title: str, message: str) -> str:
    safe_title = html.escape(title)
    safe_message = html.escape(message)
    return (
        "<!DOCTYPE html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
        f"<title>{safe_title}</title><body><h1>{safe_title}</h1><p>{safe_message}</p></body></html>"
    )


class OAuthSession:
    """Resolve an access token from config, refresh it, or log an authorize URL."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_port: int,
        timeout: float,
        token_url: str,
        tokens: OAuthTokens,
        config_path: Path,
        logger: Any,
        on_persist: Callable[[OAuthTokens], None] | None = None,
    ) -> None:
        self.client_id = client_id.strip()
        self.client_secret = client_secret.strip()
        self.redirect_port = int(redirect_port)
        self.timeout = float(timeout)
        self.token_url = token_url
        self.tokens = tokens
        self.config_path = config_path
        self.logger = logger
        self.on_persist = on_persist
        self._lock = asyncio.Lock()
        self._server: OAuthCallbackServer | None = None
        self._interactive_attempted = False
        self._cancelled = False

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def cancel(self) -> None:
        self._cancelled = True
        server = self._server
        if server is not None:
            server.cancel()

    async def ensure_access_token(self) -> str:
        async with self._lock:
            if self.enabled and needs_refresh(self.tokens):
                try:
                    self.tokens = await self._refresh(self.tokens)
                except OAuthError as exc:
                    self.logger.warning("刷新 X access token 失败：%s", exc)
                    if exc.code != "invalid_grant":
                        raise
                    self.tokens = await self._interactive()
                self._write(self.tokens)
            elif self.enabled and not self.tokens.access_token:
                self.tokens = await self._interactive()
                self._write(self.tokens)
            if not self.tokens.access_token:
                raise OAuthError("需要 api.user_access_token，或同时填写 api.client_id 与 api.client_secret 以启动 OAuth2")
            return self.tokens.access_token

    async def force_refresh(self) -> str:
        """Recover from HTTP 401. A pasted token with no refresh token stays unchanged."""
        async with self._lock:
            if not self.enabled:
                raise OAuthError("X access token 已失效。填写 Client ID 和 Client Secret 后可自动重新授权")
            if self.tokens.refresh_token:
                try:
                    self.tokens = await self._refresh(self.tokens)
                    self._write(self.tokens)
                    return self.tokens.access_token
                except OAuthError as exc:
                    self.logger.warning("刷新 X access token 失败：%s", exc)
                    if exc.code != "invalid_grant":
                        raise
            if self._interactive_attempted:
                raise OAuthError("X access token 已失效，且本轮启动已经打印过一次授权链接")
            self._interactive_attempted = True
            self.tokens = await self._interactive()
            self._write(self.tokens)
            return self.tokens.access_token

    async def _refresh(self, current: OAuthTokens) -> OAuthTokens:
        self.logger.info("正在用 refresh token 刷新 X access token")
        payload = await self._token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": current.refresh_token,
                "client_id": self.client_id,
            }
        )
        updated = tokens_from_response(payload, previous=current)
        if not updated.refresh_token:
            updated = OAuthTokens(updated.access_token, current.refresh_token, updated.expires_at)
        return updated

    async def _interactive(self) -> OAuthTokens:
        if self._cancelled:
            raise OAuthCancelled("OAuth2 授权已取消")
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(24)
        display_host = preferred_callback_host()
        server = OAuthCallbackServer(
            self.redirect_port,
            state,
            self.timeout,
            display_host=display_host,
        )
        self._server = server
        waiter = asyncio.create_task(server.wait_for_code())
        try:
            await asyncio.sleep(0)
            if self._cancelled:
                raise OAuthCancelled("OAuth2 授权已取消")
            callback = redirect_uri(display_host, server.bound_port or self.redirect_port)
            if not waiter.done():
                url = build_authorize_url(
                    client_id=self.client_id,
                    redirect_uri=callback,
                    state=state,
                    code_challenge=challenge,
                )
                self.logger.info("OAuth2 回调正在监听 %s:%s", CALLBACK_BIND_HOST, server.bound_port)
                if display_host == _LOOPBACK_FALLBACK:
                    self.logger.warning("未在本机网卡上找到公网或局域网 IPv4，回调地址回退为 %s", callback)
                else:
                    self.logger.info("请在 X 开发者门户登记回调地址：%s", callback)
                self.logger.info("请在浏览器中手动打开授权链接：%s", url)
            code = await waiter
        finally:
            self._server = None
            server.close()
            if not waiter.done():
                waiter.cancel()
                with _suppress_cancel():
                    await waiter
        self.logger.info("已收到 OAuth2 授权码，正在交换 access token")
        payload = await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback,
                "code_verifier": verifier,
                "client_id": self.client_id,
            }
        )
        return tokens_from_response(payload)

    async def _token_request(self, form: Mapping[str, str]) -> dict[str, Any]:
        headers = {
            "Authorization": basic_authorization(self.client_id, self.client_secret),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.token_url, data=dict(form), headers=headers)
        try:
            payload = response.json()
        except ValueError:
            payload = {"error_description": response.text}
        if response.status_code >= 400:
            if not isinstance(payload, Mapping):
                payload = {}
            code = str(payload.get("error") or "")
            description = str(payload.get("error_description") or payload.get("error") or response.text)
            raise OAuthError(f"X OAuth2 token 请求失败（{response.status_code}）：{description}", code=code)
        if not isinstance(payload, dict):
            raise OAuthError("X OAuth2 token 响应不是 JSON 对象")
        return payload

    def _write(self, tokens: OAuthTokens) -> None:
        self.tokens = tokens
        if self.on_persist is not None:
            self.on_persist(tokens)
        try:
            persist_tokens(self.config_path, tokens)
        except OSError as exc:
            self.logger.warning("无法把 OAuth2 token 写回 %s：%s", self.config_path, exc)
            return
        self.logger.info("已将 access token 与 refresh token 写回配置")


class _suppress_cancel:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        return exc_type is asyncio.CancelledError
