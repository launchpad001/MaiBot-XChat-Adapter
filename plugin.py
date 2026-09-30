"""MaiBot X Chat 双工消息网关。"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

from maibot_sdk import MaiBotPlugin, MessageGateway, PluginConfigBase

from .activity import (
    CHAT_EVENT_TYPES,
    CHAT_SENT,
    backfill_minutes,
    decrypted_message_id,
    desired_chat_subscriptions,
    event_timestamp,
    group_metadata,
    inbound_media_segment,
    next_page_token,
    outbound_target,
    parse_activity_line,
    stream_rejects_backfill,
    subscription_rows,
    subscriptions_to_create,
)
from .config import XChatSettings
from .constants import ACTIVITY_STREAM_PATH, API_BASE_URL, GATEWAY_NAME, PLATFORM, PROTOCOL
from .crypto import XChatCrypto, identity_key_source, juicebox_config_text, select_public_key_record
from .oauth import OAuthSession, OAuthTokens, non_token_config_equal
from .profiles import UserProfileCache
from .x_api import XApiClient, XApiError

_CONFIG_PATH = Path(__file__).resolve().parent / "config.toml"


class XChatAdapterPlugin(MaiBotPlugin):
    """将加密 X Chat 私信转换为 MaiBot 消息流并发送回复。"""

    config_model: ClassVar[type[PluginConfigBase] | None] = XChatSettings

    def __init__(self) -> None:
        super().__init__()
        self._api: XApiClient | None = None
        self._crypto: XChatCrypto | None = None
        self._profiles: UserProfileCache | None = None
        self._stream_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._seen_events: set[str] = set()
        self._seen_messages: set[str] = set()
        self._known_users: set[str] = set()
        self._key_misses: set[str] = set()
        self._oauth: OAuthSession | None = None
        self._suppress_config_restart = False
        self._suppress_task: asyncio.TimerHandle | None = None
        self._lifecycle_lock = asyncio.Lock()

    async def on_load(self) -> None:
        if not self.config.should_connect():
            self.ctx.logger.info("X Chat 适配器已加载但未启用")
            return
        async with self._lifecycle_lock:
            await self._start()

    async def on_unload(self) -> None:
        if self._oauth is not None:
            self._oauth.cancel()
        async with self._lifecycle_lock:
            await self._stop()

    async def on_config_update(self, scope: str, config_data: dict[str, object], version: str) -> None:
        del version
        if scope != "self":
            return
        previous = self.get_plugin_config_data()
        self.set_plugin_config(config_data)
        if self._suppress_config_restart and non_token_config_equal(previous, config_data):
            self.ctx.logger.info("OAuth2 token 已写回配置，保持当前连接")
            return
        if self._oauth is not None:
            self._oauth.cancel()
        async with self._lifecycle_lock:
            await self._stop()
            if self.config.should_connect():
                await self._start()

    @MessageGateway(
        name=GATEWAY_NAME,
        route_type="duplex",
        platform=PLATFORM,
        protocol=PROTOCOL,
        description="X Chat 加密私信双工消息网关",
    )
    async def handle_xchat_gateway(
        self,
        message: dict[str, Any],
        route: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        del metadata, kwargs
        crypto = self._crypto
        api = self._api
        if crypto is None or api is None:
            return {"success": False, "error": "X Chat 适配器尚未连接"}

        target = outbound_target(message, route or {})
        if not target:
            return {"success": False, "error": "出站消息缺少 X Chat 会话或对方用户 ID"}
        conversation_id = await self._prepare_outbound_conversation(target)
        text, media_segments = self._outbound_content(message)
        if not text and not media_segments:
            return {"success": False, "error": "消息中没有可发送的文本或媒体"}

        try:
            attachments: list[dict[str, Any]] = []
            for media in media_segments:
                raw = media["bytes"]
                encrypted_media, _ = await asyncio.to_thread(crypto.encrypt_stream, conversation_id, raw)
                media_hash_key = await api.upload_chat_media(conversation_id, encrypted_media)
                attachments.append(
                    {
                        "attachment_type": "media",
                        "media_hash_key": media_hash_key,
                        "width": media.get("width", 0),
                        "height": media.get("height", 0),
                        "filesize_bytes": len(raw),
                        "filename": media.get("filename", "attachment"),
                    }
                )
            encrypted = await asyncio.to_thread(
                crypto.encrypt_message,
                conversation_id,
                text,
                attachments=attachments or None,
            )
            response = await api.post_json(
                f"/2/chat/conversations/{api.conversation_path(conversation_id)}/messages",
                encrypted,
            )
        except Exception as exc:
            self.ctx.logger.error("X Chat 消息发送失败: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}
        return {
            "success": True,
            "external_message_id": encrypted["message_id"],
            "metadata": {"conversation_id": conversation_id, "response": response},
        }

    async def _start(self) -> None:
        settings = self.config
        self._oauth = OAuthSession(
            client_id=settings.api.client_id,
            client_secret=settings.api.client_secret,
            redirect_port=settings.api.oauth_redirect_port,
            timeout=settings.api.oauth_timeout_sec,
            token_url=f"{API_BASE_URL}/2/oauth2/token",
            tokens=OAuthTokens(
                access_token=settings.api.user_access_token.strip(),
                refresh_token=settings.api.refresh_token.strip(),
                expires_at=int(settings.api.access_token_expires_at or 0),
            ),
            config_path=_CONFIG_PATH,
            logger=self.ctx.logger,
            on_persist=self._apply_oauth_tokens,
        )
        access_token = await self._oauth.ensure_access_token()
        self._api = XApiClient(
            API_BASE_URL,
            access_token,
            settings.plugin.request_timeout_sec,
            on_unauthorized=self._oauth.force_refresh,
        )
        try:
            user_id = await self._resolve_user_id()
            self._crypto = await self._load_crypto(user_id)
        except Exception:
            await self._api.close()
            self._api = None
            raise
        source = "私钥" if self._crypto.key_source == "private_key" else "JuiceBox PIN"
        self.ctx.logger.info("X Chat 身份已加载，密钥来源：%s", source)
        self._profiles = UserProfileCache(
            self._api,
            self.ctx.logger,
            data_dir=self.ctx.paths.data_dir,
            ttl_sec=int(self.config.profile_cache_ttl_hours) * 3600,
        )
        self._key_misses.clear()
        self._stop_event.clear()
        self._stream_task = asyncio.create_task(self._stream_loop(), name="xchat-activity-stream")

    def _apply_oauth_tokens(self, tokens: OAuthTokens) -> None:
        """Keep the running config aligned with tokens written back to config.toml."""
        self._suppress_config_restart = True
        if self._suppress_task is not None:
            self._suppress_task.cancel()
        loop = asyncio.get_running_loop()

        def clear_suppression() -> None:
            self._suppress_config_restart = False
            self._suppress_task = None

        self._suppress_task = loop.call_later(3.0, clear_suppression)
        self.config.api.user_access_token = tokens.access_token
        self.config.api.refresh_token = tokens.refresh_token
        self.config.api.access_token_expires_at = int(tokens.expires_at)

    async def _resolve_user_id(self) -> str:
        configured = self.config.identity.user_id.strip()
        if configured:
            return configured
        payload = await self._require_api().get_json("/2/users/me")
        data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
        user_id = str(data.get("id") or "").strip()
        if not user_id:
            raise RuntimeError("identity.user_id 为空，且 /2/users/me 没有返回用户 ID")
        self.ctx.logger.info("已从 /2/users/me 解析 X 用户 ID %s", user_id)
        return user_id

    async def _load_crypto(self, user_id: str) -> XChatCrypto:
        identity = self.config.identity
        source = identity_key_source(identity.private_keys_b64, identity.juicebox_pin)
        version = identity.signing_key_version.strip()
        config_json = ""
        if source == "private_key":
            if not version:
                raise ValueError("使用私钥时必须填写 identity.signing_key_version")
            self.ctx.logger.info("已配置私钥，跳过 JuiceBox PIN 还原")
        else:
            record = await self._own_key_record(user_id, version)
            version = version or str(record.get("public_key_version") or "")
            config_json = juicebox_config_text(record)
            self.ctx.logger.info("正在用 JuiceBox PIN 还原私钥，公钥版本 %s", version)
        return await asyncio.to_thread(
            XChatCrypto,
            self._require_api(),
            user_id,
            version,
            identity.private_keys_b64,
            juicebox_pin=identity.juicebox_pin,
            juicebox_config_json=config_json,
        )

    async def _own_key_record(self, user_id: str, version: str) -> dict[str, Any]:
        payload = await self._require_api().get_json(
            f"/2/users/{user_id}/public_keys",
            params={
                "public_key.fields": (
                    "public_key_version,public_key,signing_public_key,"
                    "identity_public_key_signature,juicebox_config"
                ),
            },
        )
        rows = payload.get("data") or []
        if not isinstance(rows, list):
            rows = [rows]
        return select_public_key_record(rows, version)

    async def _stop(self) -> None:
        self._stop_event.set()
        if self._stream_task is not None:
            self._stream_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stream_task
            self._stream_task = None
        if self._api is not None:
            await self._api.close()
        self._api = None
        self._crypto = None
        self._profiles = None
        self._oauth = None
        await self.ctx.gateway.update_state(gateway_name=GATEWAY_NAME, ready=False)

    async def _stream_loop(self) -> None:
        settings = self.config
        api = self._require_api()
        account_id = self._crypto.user_id if self._crypto is not None else settings.identity.user_id
        await self.ctx.gateway.update_state(
            gateway_name=GATEWAY_NAME,
            ready=False,
            platform=PLATFORM,
            account_id=account_id,
            scope="primary",
            metadata={"protocol": PROTOCOL},
        )
        disconnected_at: float | None = None
        backfill_enabled = True
        while not self._stop_event.is_set():
            try:
                await self._ensure_chat_subscriptions(account_id)
                gap = None if disconnected_at is None else time.monotonic() - disconnected_at
                minutes = backfill_minutes(settings.backfill_minutes, gap) if backfill_enabled else 0
                params: dict[str, Any] = {}
                if minutes:
                    params["backfill_minutes"] = minutes
                bearer = self._app_bearer()
                response = await api.get_stream(ACTIVITY_STREAM_PATH, bearer_token=bearer, params=params)
                # httpx 0.28 Response is no longer an async context manager. aclosing calls aclose().
                async with contextlib.aclosing(response):
                    if response.status_code >= 400:
                        body = (await response.aread()).decode(errors="replace")
                        if params and stream_rejects_backfill(body):
                            backfill_enabled = False
                            self.ctx.logger.warning(
                                "Activity Stream 无权使用 backfill_minutes，改为不回溯并立即重连: %s",
                                body,
                            )
                            continue
                        raise XApiError(f"Activity Stream {response.status_code}: {body}")
                    disconnected_at = None
                    await self.ctx.gateway.update_state(
                        gateway_name=GATEWAY_NAME,
                        ready=True,
                        platform=PLATFORM,
                        account_id=account_id,
                        scope="primary",
                        metadata={"protocol": PROTOCOL},
                    )
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            await self._handle_stream_line(line)
                        except Exception as exc:
                            # One rejected payload must not drop the live stream.
                            self.ctx.logger.warning("X Chat 事件处理失败，已跳过: %s", exc)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.ctx.logger.warning("X Chat Activity Stream 已断开: %s", exc)
                await self.ctx.gateway.update_state(gateway_name=GATEWAY_NAME, ready=False)
                disconnected_at = time.monotonic()
                await asyncio.sleep(settings.plugin.reconnect_delay_sec)

    def _app_bearer(self) -> str:
        """App-only bearer. The stream and the subscription list both reject a user token."""
        bearer = self.config.api.app_bearer_token.strip()
        if not bearer:
            raise RuntimeError(
                "缺少 api.app_bearer_token。Activity Stream 和订阅列表必须使用 app bearer，"
                "user access token 只用于创建订阅"
            )
        return bearer

    async def _ensure_chat_subscriptions(self, user_id: str) -> None:
        """Create missing chat subscriptions with the user access token.

        GET /2/activity/subscriptions returns 403 for that same user token.
        POST of a chat event returns 400 when sent with the app bearer.
        """
        if not user_id:
            raise RuntimeError("无法创建 Activity 订阅：缺少机器人用户 ID")
        api = self._require_api()
        desired = desired_chat_subscriptions(user_id, include_sent=not self.config.ignore_self_messages)
        existing = await self._list_subscriptions()
        missing = subscriptions_to_create(existing, desired)
        for body in missing:
            await api.post_json("/2/activity/subscriptions", body)
            self.ctx.logger.info("已创建 Activity 订阅 %s，用户 %s", body["event_type"], user_id)

    async def _list_subscriptions(self) -> list[dict[str, Any]]:
        api = self._require_api()
        bearer = self._app_bearer()
        rows: list[dict[str, Any]] = []
        token = ""
        for _ in range(20):
            params: dict[str, Any] = {"max_results": 1000}
            if token:
                params["pagination_token"] = token
            payload = await api.get_json("/2/activity/subscriptions", params=params, token=bearer)
            rows.extend(subscription_rows(payload))
            token = next_page_token(payload)
            if not token:
                break
        return rows

    def _remember(self, seen: set[str], key: str) -> bool:
        if not key or key in seen:
            return False
        seen.add(key)
        if len(seen) > 10000:
            seen.clear()
            seen.add(key)
        return True

    async def _handle_stream_line(self, line: str) -> None:
        payload = parse_activity_line(line)
        if payload is None:
            if line.strip():
                self.ctx.logger.debug("忽略非 JSON Activity Stream 行")
            return
        if payload.get("connection_issue") or payload.get("title") == "ConnectionException":
            detail = payload.get("detail") or payload.get("message") or payload.get("title")
            raise XApiError(f"Activity Stream 连接被拒绝：{detail}")
        errors = payload.get("errors")
        data = payload.get("data") if isinstance(payload.get("data"), Mapping) else None
        if data is None:
            if errors:
                self.ctx.logger.warning("Activity Stream 返回错误：%s", errors)
            return
        event_uuid = str(data.get("event_uuid") or "")
        if event_uuid and not self._remember(self._seen_events, event_uuid):
            return
        event_type = str(data.get("event_type") or "")
        if event_type not in CHAT_EVENT_TYPES:
            return
        event_payload = data.get("payload")
        if not isinstance(event_payload, Mapping):
            return
        await self._handle_chat_event(event_payload, event_type)

    async def _handle_chat_event(self, payload: Mapping[str, Any], event_type: str) -> None:
        crypto = self._require_crypto()
        sender_id = str(payload.get("sender_id") or "")
        conversation_id = str(payload.get("conversation_id") or "")
        if not conversation_id:
            return
        participants = [crypto.user_id]
        if sender_id:
            participants.append(sender_id)
        if any(user_id not in self._known_users for user_id in participants):
            await crypto.refresh_signing_keys(participants)
            self._known_users.update(participants)
        try:
            event = await asyncio.to_thread(crypto.decrypt_event, payload)
        except Exception:
            # A new signing-key version is fetched once, then the same payload is retried.
            try:
                await crypto.refresh_signing_keys(participants)
                self._known_users.update(user_id for user_id in participants if user_id)
                event = await asyncio.to_thread(crypto.decrypt_event, payload)
            except Exception as exc:
                self.ctx.logger.warning("X Chat 事件解密失败 conversation=%s: %s", conversation_id, exc)
                return
        if isinstance(event, Mapping):
            conversation_id = str(event.get("conversation_id") or conversation_id).strip() or conversation_id
            if conversation_id.startswith("g"):
                await self._capture_group_metadata(event, conversation_id)
        if not isinstance(event, Mapping) or str(event.get("type") or "") != "Message":
            return
        sender_id = str(event.get("sender_id") or sender_id)
        if event_type == CHAT_SENT and self.config.ignore_self_messages:
            return
        content = event.get("content")
        if not isinstance(content, Mapping):
            return
        segments, plain_text = await self._inbound_segments(conversation_id, event, content)
        if not segments:
            return
        message_id = decrypted_message_id(event, conversation_id)
        if not message_id:
            self.ctx.logger.warning("X Chat 解密事件缺少 message_id，已跳过 conversation=%s", conversation_id)
            return
        if not sender_id:
            self.ctx.logger.warning("X Chat 解密事件缺少 sender_id，已跳过 conversation=%s", conversation_id)
            return
        if not self._remember(self._seen_messages, message_id):
            return
        is_group = conversation_id.startswith("g")
        nickname = await self._sender_nickname(sender_id)
        message_info: dict[str, Any] = {
            "user_info": {"user_id": sender_id, "user_nickname": nickname},
            "additional_config": {
                "conversation_id": conversation_id,
                "chat_type": "group" if is_group else "private",
            },
        }
        if is_group:
            message_info["group_info"] = {
                "group_id": conversation_id,
                "group_name": await self._group_display_name(conversation_id),
            }
        message = {
            "message_id": message_id,
            "platform": PLATFORM,
            "message_info": message_info,
            "raw_message": segments,
            "plain_text": plain_text,
        }
        timestamp = event_timestamp(event)
        if timestamp:
            message["timestamp"] = timestamp
        await self.ctx.gateway.route_message(
            gateway_name=GATEWAY_NAME,
            message=message,
            route_metadata={"self_id": crypto.user_id, "connection_id": "primary", "conversation_id": conversation_id},
            external_message_id=message_id,
            dedupe_key=message_id or conversation_id,
        )

    async def _inbound_segments(
        self,
        conversation_id: str,
        event: Mapping[str, Any],
        content: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], str]:
        """Convert decrypted X Chat text and media into MaiBot segments."""
        segments: list[dict[str, Any]] = []
        plain_parts: list[str] = []
        text = str(content.get("text") or "")
        if text:
            text = text[: self.config.max_message_length]
            segments.append({"type": "text", "data": text})
            plain_parts.append(text)

        attachments = content.get("attachments") or content.get("media") or content.get("media_hashes") or []
        if isinstance(attachments, Mapping):
            attachments = [attachments]
        if not isinstance(attachments, list):
            attachments = []
        key_version = str(event.get("key_version") or "") or None
        for attachment in attachments:
            if isinstance(attachment, str):
                attachment = {"media_hash_key": attachment}
            if not isinstance(attachment, Mapping):
                continue
            media_hash_key = str(attachment.get("media_hash_key") or attachment.get("mediaHashKey") or "")
            if not media_hash_key:
                continue
            try:
                encrypted = await self._require_api().get_bytes(
                    f"/2/chat/media/{self._require_api().conversation_path(conversation_id)}/{media_hash_key}"
                )
                plain = await asyncio.to_thread(
                    self._require_crypto().decrypt_stream,
                    conversation_id,
                    encrypted,
                    key_version,
                )
            except Exception as exc:
                self.ctx.logger.warning("X Chat 媒体下载或解密失败 conversation=%s: %s", conversation_id, exc)
                continue
            encoded = base64.b64encode(plain).decode("ascii")
            filename = str(attachment.get("filename") or "attachment")
            mime = str(attachment.get("mime_type") or attachment.get("media_type") or "")
            segments.append(
                inbound_media_segment(
                    mime=mime,
                    filename=filename,
                    encoded=encoded,
                    media_hash_key=media_hash_key,
                )
            )
        return segments, "".join(plain_parts)

    def _outbound_content(self, message: Mapping[str, Any]) -> tuple[str, list[dict[str, Any]]]:
        """Extract text and base64/local media from a Host outbound message."""
        text_parts: list[str] = []
        media: list[dict[str, Any]] = []
        raw = message.get("raw_message")
        if not isinstance(raw, list):
            raw = message.get("message_segments")
        if not isinstance(raw, list):
            raw = []
        from pathlib import Path

        for segment in raw:
            if not isinstance(segment, Mapping):
                continue
            kind = str(segment.get("type") or "")
            data = segment.get("data")
            data_map = data if isinstance(data, Mapping) else {}
            if kind == "text":
                text_parts.append(str(data_map.get("text") or data_map.get("content") or data or ""))
                continue
            if kind not in {"image", "file", "video", "audio", "voice"}:
                continue
            raw_b64 = data_map.get("base64") or data_map.get("data") or segment.get("binary_data_base64")
            if isinstance(raw_b64, str) and raw_b64.startswith("base64://"):
                raw_b64 = raw_b64[9:]
            if isinstance(raw_b64, str) and raw_b64:
                try:
                    raw_bytes = base64.b64decode(raw_b64, validate=False)
                except Exception:
                    continue
            else:
                path = data_map.get("path")
                if not path:
                    continue
                try:
                    raw_bytes = Path(str(path)).read_bytes()
                except OSError:
                    continue
            media.append({
                "bytes": raw_bytes,
                "filename": str(data_map.get("filename") or data_map.get("name") or "attachment"),
                "width": int(data_map.get("width") or 0),
                "height": int(data_map.get("height") or 0),
            })
        if not text_parts:
            fallback = str(
                message.get("processed_plain_text") or message.get("plain_text") or message.get("content") or ""
            ).strip()
            if fallback:
                text_parts.append(fallback)
        return "".join(text_parts).strip(), media

    @staticmethod
    def _key_change_body(prepared: Any) -> dict[str, Any]:
        value = dict(prepared) if isinstance(prepared, Mapping) else vars(prepared)
        participant_keys = value.get("participant_keys", [])
        signatures = value.get("action_signatures", [])
        return {
            "conversation_key_version": value.get("conversation_key_version"),
            "conversation_participant_keys": [
                {
                    "user_id": item.get("user_id"),
                    "encrypted_conversation_key": item.get("encrypted_key"),
                    "public_key_version": item.get("public_key_version"),
                }
                for item in participant_keys
            ],
            "action_signatures": [
                {
                    "message_id": item.get("message_id"),
                    "encoded_message_event_detail": item.get("encoded_message_event_detail"),
                    "message_event_signature": {
                        "signature": item.get("signature"),
                        "public_key_version": item.get("public_key_version"),
                        "signature_version": item.get("signature_version"),
                    },
                }
                for item in signatures
            ],
        }

    @staticmethod
    def _text_from_message(message: Mapping[str, Any]) -> str:
        raw = message.get("raw_message")
        if isinstance(raw, list):
            parts: list[str] = []
            for segment in raw:
                if not isinstance(segment, Mapping) or segment.get("type") != "text":
                    continue
                data = segment.get("data")
                if isinstance(data, Mapping):
                    parts.append(str(data.get("text") or data.get("content") or ""))
                else:
                    parts.append(str(data or ""))
            if parts:
                return "".join(parts).strip()
        return str(message.get("plain_text") or message.get("content") or "").strip()

    async def _prepare_outbound_conversation(self, target: str) -> str:
        """Use a cached conversation key, or load one from conversation history.

        The history request accepts a 1:1 peer id. It runs only when this process
        has not already decrypted that conversation's key.
        """
        crypto = self._require_crypto()
        resolved = crypto.resolve_conversation_id(target)
        try:
            crypto._key_for(resolved)
        except RuntimeError:
            pass
        else:
            self._key_misses.discard(resolved)
            return resolved
        if resolved in self._key_misses:
            return resolved
        try:
            await self._recover_conversation_keys(resolved)
        except Exception as exc:
            self.ctx.logger.warning("X Chat 会话密钥恢复失败 conversation=%s: %s", resolved, exc)
            return crypto.resolve_conversation_id(resolved)
        resolved = crypto.resolve_conversation_id(resolved)
        try:
            crypto._key_for(resolved)
        except RuntimeError:
            self._key_misses.add(resolved)
        return resolved

    async def _recover_conversation_keys(self, conversation_id: str) -> None:
        crypto = self._require_crypto()
        api = self._require_api()
        token = ""
        for _ in range(5):
            params: dict[str, Any] = {"max_results": 100}
            if token:
                params["pagination_token"] = token
            payload = await api.get_json(
                f"/2/chat/conversations/{api.conversation_path(conversation_id)}/events",
                params=params,
            )
            meta = payload.get("meta") if isinstance(payload.get("meta"), Mapping) else {}
            blobs = [
                str(item).strip()
                for item in (meta.get("conversation_key_events") or [])
                if str(item).strip()
            ]
            rows = payload.get("data") if isinstance(payload.get("data"), list) else []
            canonical = ""
            participants = [crypto.user_id]
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                row_conversation = str(row.get("conversation_id") or "").strip()
                if row_conversation and not canonical:
                    canonical = row_conversation
                sender_id = str(row.get("sender_id") or "").strip()
                if sender_id:
                    participants.append(sender_id)
            target = canonical or conversation_id
            missing = [user_id for user_id in participants if user_id and user_id not in self._known_users]
            if missing:
                try:
                    await crypto.refresh_signing_keys(missing)
                except Exception as exc:
                    self.ctx.logger.warning("X Chat 签名公钥读取失败，改用本地解包: %s", exc)
                else:
                    self._known_users.update(missing)
            if blobs:
                await asyncio.to_thread(crypto.absorb_key_events, target, blobs)
            resolved = crypto.resolve_conversation_id(target)
            try:
                crypto._key_for(resolved)
            except RuntimeError:
                pass
            else:
                self.ctx.logger.info("已从会话事件恢复密钥 conversation=%s", resolved)
                self._key_misses.discard(resolved)
                return
            token = str(meta.get("next_token") or "").strip()
            if not token:
                break
        self.ctx.logger.warning("会话事件里没有可用的密钥 conversation=%s", conversation_id)

    async def _capture_group_metadata(self, event: Mapping[str, Any], conversation_id: str) -> None:
        """Remember a group title, avatar, and member roster without routing the event as chat."""
        title, avatar, members = group_metadata(event)
        crypto = self._require_crypto()
        profiles = self._profiles

        def plain_fields() -> tuple[str, str]:
            return (
                crypto.decrypt_text(conversation_id, title) if title else "",
                crypto.decrypt_text(conversation_id, avatar) if avatar else "",
            )

        plain_title, plain_avatar = await asyncio.to_thread(plain_fields)
        if profiles is not None and (plain_title or plain_avatar or members):
            profiles.remember_group(
                conversation_id,
                name=plain_title,
                avatar_url=plain_avatar,
                member_ids=members,
            )
        if profiles is not None and plain_avatar:
            await profiles.ensure_group_avatar(conversation_id)
        if members:
            await self._refresh_signing_keys(members)

    async def _group_display_name(self, conversation_id: str) -> str:
        """Decrypted group title. An unknown title stays the placeholder ``群聊``."""
        profiles = self._profiles
        crypto = self._crypto
        if profiles is None or crypto is None:
            return "群聊"
        try:
            record = await profiles.group_record(
                conversation_id,
                lambda value: crypto.decrypt_text(conversation_id, value),
            )
        except Exception as exc:
            self.ctx.logger.warning("X 群资料读取失败 conversation=%s: %s", conversation_id, exc)
            return "群聊"
        members = record.get("member_ids")
        if isinstance(members, list):
            await self._refresh_signing_keys([str(item) for item in members if str(item).strip()])
        return str(record.get("name") or "").strip() or "群聊"

    async def _refresh_signing_keys(self, user_ids: list[str]) -> None:
        crypto = self._crypto
        if crypto is None:
            return
        missing = [user_id for user_id in dict.fromkeys(user_ids) if user_id and user_id not in self._known_users]
        if not missing:
            return
        try:
            await crypto.refresh_signing_keys(missing)
        except Exception as exc:
            self.ctx.logger.warning("X Chat 签名公钥读取失败: %s", exc)
            return
        self._known_users.update(missing)

    async def _sender_nickname(self, user_id: str) -> str:
        """X display name, cached because ``GET /2/users/:id`` is metered."""
        profiles = self._profiles
        if profiles is None:
            return user_id
        try:
            return await profiles.display_name(user_id) or user_id
        except Exception as exc:
            self.ctx.logger.warning("X 用户昵称读取失败 user=%s: %s", user_id, exc)
            return user_id

    def _require_api(self) -> XApiClient:
        if self._api is None:
            raise RuntimeError("X Chat API 未初始化")
        return self._api

    def _require_crypto(self) -> XChatCrypto:
        if self._crypto is None:
            raise RuntimeError("X Chat 加密模块未初始化")
        return self._crypto


def create_plugin() -> XChatAdapterPlugin:
    return XChatAdapterPlugin()
