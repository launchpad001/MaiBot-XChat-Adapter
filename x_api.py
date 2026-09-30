"""Minimal asynchronous X API client used by the adapter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import quote

import httpx


# The Activity Stream sends a newline heartbeat about every 20 seconds.
# The read timeout has to outlive that heartbeat, independent of REST timeouts.
STREAM_READ_TIMEOUT_SEC = 90.0


class XApiError(RuntimeError):
    """Raised when X API returns an unsuccessful response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class XApiClient:
    def __init__(
        self,
        base_url: str,
        user_token: str,
        timeout: float = 30.0,
        *,
        on_unauthorized: Callable[[], Awaitable[str]] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.user_token = user_token.strip()
        self.timeout = timeout
        self._on_unauthorized = on_unauthorized
        self._client = httpx.AsyncClient(timeout=timeout)

    def set_user_token(self, token: str) -> None:
        self.user_token = token.strip()

    async def close(self) -> None:
        await self._client.aclose()

    async def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        response = await self._request("GET", path, token=token, params=params)
        return self._decode(response)

    async def get_stream(self, path: str, *, bearer_token: str, params: Mapping[str, Any] | None = None):
        token = bearer_token
        response = await self._send_stream(path, token, params)
        if response.status_code != 401 or token != self.user_token:
            return response
        try:
            refreshed = await self._recover_unauthorized(token)
        except Exception:
            await response.aclose()
            raise
        if not refreshed:
            return response
        await response.aclose()
        return await self._send_stream(path, self.user_token, params)

    async def post_json(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        response = await self._request("POST", path, json=dict(payload))
        return self._decode(response)

    async def get_bytes(self, path: str) -> bytes:
        response = await self._request("GET", path)
        if response.is_error:
            raise XApiError(f"X API {response.status_code}: {response.text}", response.status_code)
        return response.content

    async def _request(self, method: str, path: str, *, token: str | None = None, **kwargs: Any) -> httpx.Response:
        # An explicit token is the app bearer. A 401 on it is not a user-token expiry.
        sent = self.user_token if token is None else token.strip()
        response = await self._client.request(method, self._url(path), headers=self._headers(sent), **kwargs)
        if token is None and response.status_code == 401 and await self._recover_unauthorized(sent):
            response = await self._client.request(
                method,
                self._url(path),
                headers=self._headers(self.user_token),
                **kwargs,
            )
        return response

    async def _send_stream(self, path: str, bearer_token: str, params: Mapping[str, Any] | None) -> httpx.Response:
        timeout = httpx.Timeout(
            connect=self.timeout,
            read=STREAM_READ_TIMEOUT_SEC,
            write=self.timeout,
            pool=self.timeout,
        )
        request = self._client.build_request(
            "GET",
            self._url(path),
            headers=self._headers(bearer_token),
            params=params,
            timeout=timeout,
        )
        return await self._client.send(request, stream=True)

    async def _recover_unauthorized(self, sent_token: str) -> bool:
        """Refresh once, or reuse a token another request already rotated in."""
        if sent_token != self.user_token:
            return bool(self.user_token)
        if self._on_unauthorized is None:
            return False
        refreshed = (await self._on_unauthorized()).strip()
        if not refreshed or refreshed == sent_token:
            return False
        self.user_token = refreshed
        return True

    async def upload_chat_media(self, conversation_id: str, encrypted: bytes, *, chunk_size: int = 4 * 1024 * 1024) -> str:
        """Encrypts are uploaded as base64 JSON chunks using X Chat's three-step API."""
        import base64

        init = await self.post_json(
            "/2/chat/media/upload/initialize",
            {"conversation_id": conversation_id, "total_bytes": len(encrypted)},
        )
        data = init.get("data") or {}
        session_id = str(data.get("session_id") or "")
        media_hash_key = str(data.get("media_hash_key") or "")
        if not session_id or not media_hash_key:
            raise XApiError("X Chat media initialize 未返回 session_id 或 media_hash_key")
        parts = list(encrypted[i : i + chunk_size] for i in range(0, len(encrypted), chunk_size)) or [b""]
        for index, part in enumerate(parts):
            await self.post_json(
                f"/2/chat/media/upload/{quote(session_id, safe='')}/append",
                {
                    "conversation_id": conversation_id,
                    "media_hash_key": media_hash_key,
                    "segment_index": index,
                    "media": base64.b64encode(part).decode("ascii"),
                },
            )
        await self.post_json(
            f"/2/chat/media/upload/{quote(session_id, safe='')}/finalize",
            {
                "conversation_id": conversation_id,
                "media_hash_key": media_hash_key,
                "num_parts": str(len(parts)),
            },
        )
        return media_hash_key

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    @staticmethod
    def _headers(token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError:
            payload = {"text": response.text}
        if response.is_error:
            if isinstance(payload, Mapping):
                detail = payload.get("detail") or payload.get("title") or payload.get("message") or response.text
            else:
                detail = response.text
            raise XApiError(f"X API {response.status_code}: {detail}", response.status_code)
        if not isinstance(payload, dict):
            raise XApiError("X API returned a non-object JSON response", response.status_code)
        return payload

    @staticmethod
    def conversation_path(conversation_id: str) -> str:
        return quote(conversation_id.replace(":", "-"), safe="")
