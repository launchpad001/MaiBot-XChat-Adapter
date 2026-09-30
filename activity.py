"""X Activity API helpers for the chat stream.

Chat events are private. A user-context token creates the subscriptions.
The app-only bearer lists them and reads ``GET /2/activity/stream``; a user
token is rejected on both of those calls. Live chat payloads are ciphertext:
apply ``conversation_key_change_event`` before ``encoded_event``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

STREAM_BACKFILL_MAX = 5
CHAT_RECEIVED = "chat.received"
CHAT_SENT = "chat.sent"
CHAT_JOIN = "chat.conversation.join"
CHAT_JOIN_ALIAS = "chat.conversation_join"
CHAT_EVENT_TYPES = frozenset({CHAT_RECEIVED, CHAT_SENT, CHAT_JOIN, CHAT_JOIN_ALIAS})


def desired_chat_subscriptions(user_id: str, *, include_sent: bool) -> list[dict[str, Any]]:
    """Subscriptions required to deliver this bot's encrypted chats to the stream."""
    event_types = [CHAT_RECEIVED, CHAT_JOIN]
    if include_sent:
        event_types.append(CHAT_SENT)
    return [
        {
            "event_type": event_type,
            "filter": {"user_id": user_id},
            "tag": f"maibot-xchat-{event_type}",
        }
        for event_type in event_types
    ]


def subscription_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize the list and create responses, which wrap rows differently."""
    data = payload.get("data")
    rows: list[Mapping[str, Any]] = []
    if isinstance(data, list):
        rows = [item for item in data if isinstance(item, Mapping)]
    elif isinstance(data, Mapping):
        nested = data.get("subscriptions") or data.get("subscription")
        if isinstance(nested, list):
            rows = [item for item in nested if isinstance(item, Mapping)]
        elif isinstance(nested, Mapping):
            rows = [nested]
        elif "event_type" in data or "subscription_id" in data:
            rows = [data]
    return [dict(row) for row in rows]


def next_page_token(payload: Mapping[str, Any]) -> str:
    meta = payload.get("meta")
    if not isinstance(meta, Mapping):
        return ""
    return str(meta.get("next_token") or meta.get("pagination_token") or "").strip()


def _event_types_match(existing: str, desired: str) -> bool:
    if desired == CHAT_JOIN:
        return existing in {CHAT_JOIN, CHAT_JOIN_ALIAS}
    return existing == desired


def subscription_covers(existing: Mapping[str, Any], desired: Mapping[str, Any]) -> bool:
    """True when an existing row already delivers the desired chat events to the stream."""
    if not _event_types_match(str(existing.get("event_type") or ""), str(desired.get("event_type") or "")):
        return False
    current = existing.get("filter") if isinstance(existing.get("filter"), Mapping) else {}
    wanted = desired.get("filter") if isinstance(desired.get("filter"), Mapping) else {}
    if str(current.get("user_id") or "") != str(wanted.get("user_id") or ""):
        return False
    # A webhook_id selects webhook delivery. The stream only sees subscriptions without one.
    if str(existing.get("webhook_id") or "").strip():
        return False
    qualifiers = current.get("qualifiers")
    return not (isinstance(qualifiers, Mapping) and qualifiers)


def subscriptions_to_create(
    existing: Sequence[Mapping[str, Any]],
    desired: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [dict(item) for item in desired if not any(subscription_covers(row, item) for row in existing)]


def backfill_minutes(configured: int, gap_seconds: float | None) -> int:
    """Clamp to the Activity Stream limit. Reconnects cover the gap, still at most 5 minutes."""
    initial = max(0, min(STREAM_BACKFILL_MAX, int(configured)))
    if gap_seconds is None:
        return initial
    gap = max(0, math.ceil(gap_seconds / 60))
    return max(initial, min(STREAM_BACKFILL_MAX, gap))


def _text_id(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _looks_like_session_hash(value: str) -> bool:
    """MaiBot session ids are MD5 hex. X conversation ids are not."""
    return len(value) == 32 and all(char in "0123456789abcdef" for char in value.lower())


def outbound_target(message: Mapping[str, Any], route: Mapping[str, Any] | None = None) -> str:
    """X conversation or peer id carried by a MaiBot outbound message.

    The host rewrites ``session_id`` to ``md5(platform + account + peer)``.
    That hash is not an X conversation id. Group replies use
    ``platform_io_target_group_id`` / ``group_info.group_id``. Private replies
    use ``platform_io_target_user_id``.
    """
    route = route or {}
    info = message.get("message_info") if isinstance(message.get("message_info"), Mapping) else {}
    additional = info.get("additional_config") if isinstance(info.get("additional_config"), Mapping) else {}
    group = info.get("group_info") if isinstance(info.get("group_info"), Mapping) else {}
    for source in (additional, route, message):
        group_id = str(source.get("platform_io_target_group_id") or "").strip()
        if group_id and not _looks_like_session_hash(group_id):
            return group_id
    group_id = str(group.get("group_id") or "").strip()
    if group_id and not _looks_like_session_hash(group_id):
        return group_id
    for source in (additional, route, message):
        conversation_id = str(source.get("conversation_id") or "").strip()
        if conversation_id and not _looks_like_session_hash(conversation_id):
            return conversation_id
    user_id = str(additional.get("platform_io_target_user_id") or "").strip()
    if user_id:
        return user_id
    return ""


def inbound_media_segment(
    *,
    mime: str,
    filename: str,
    encoded: str,
    media_hash_key: str,
) -> dict[str, Any]:
    """Build one MaiBot segment. Text and image ``data`` are strings, not objects."""
    lower_name = filename.lower()
    image = mime.startswith("image/") or lower_name.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"))
    audio = mime.startswith("audio/") or lower_name.endswith((".mp3", ".m4a", ".wav", ".ogg", ".opus"))
    if image or audio:
        return {
            "type": "image" if image else "voice",
            "data": "",
            "binary_data_base64": encoded,
        }
    return {
        "type": "file",
        "data": {
            "name": filename or "attachment",
            "mime_type": mime or "application/octet-stream",
            "base64": encoded,
            "file_id": media_hash_key,
        },
    }


def group_metadata(event: Mapping[str, Any]) -> tuple[str, str, list[str]]:
    """Title, avatar URL, and member ids carried by a decrypted group event."""
    sources: list[Mapping[str, Any]] = [event]
    for key in ("group_change", "change", "detail", "content"):
        value = event.get(key)
        if isinstance(value, Mapping):
            sources.append(value)
    title = ""
    avatar = ""
    members: list[str] = []
    for source in sources:
        if not title:
            for key in ("new_title", "title", "group_name"):
                text = str(source.get(key) or "").strip()
                if text:
                    title = text
                    break
        if not avatar:
            for key in ("new_avatar_url", "avatar_url", "group_avatar_url"):
                text = str(source.get(key) or "").strip()
                if text:
                    avatar = text
                    break
        for key in ("member_ids", "admin_ids", "current_member_ids", "current_admin_ids"):
            raw = source.get(key)
            if isinstance(raw, list):
                members.extend(str(item).strip() for item in raw if str(item).strip())
    return title, avatar, list(dict.fromkeys(members))


def event_timestamp(event: Mapping[str, Any]) -> str:
    """MaiBot timestamp is epoch seconds. X Chat stores ``created_at_msec``."""
    raw = event.get("created_at_msec")
    if raw is None or raw == "":
        return ""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return ""
    if value > 10_000_000_000:
        value /= 1000
    if value <= 0:
        return ""
    return str(value)


def decrypted_message_id(event: Mapping[str, Any], conversation_id: str = "") -> str:
    """MaiBot message id for one decrypted Chat XDK event.

    ``decrypt_event`` exposes the signed id as ``id``. ``message_id`` is the
    send-payload name. ``sequence_id`` is unsigned backend metadata and is used
    only when the signed id is absent, scoped to the conversation.
    """
    for key in ("message_id", "id"):
        text = _text_id(event.get(key))
        if text:
            return text
    sequence_id = _text_id(event.get("sequence_id"))
    if not sequence_id:
        return ""
    conversation = conversation_id.strip()
    if conversation:
        return f"{conversation}:{sequence_id}"
    return sequence_id


def stream_rejects_backfill(body: str) -> bool:
    """True when this app's Activity Stream refuses the backfill_minutes query parameter.

    Backfill is not available on every stream. A rejected reconnect must drop the
    parameter; retrying with it keeps the connection in a 400 loop.
    """
    text = body.lower()
    return "backfill_minutes" in text and "not authorized" in text


def parse_activity_line(line: str) -> dict[str, Any] | None:
    """Parse one NDJSON stream line. Blank lines are the 20-second heartbeat."""
    raw = line.strip()
    if raw.startswith("data:"):
        raw = raw[5:].strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload
