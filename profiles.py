"""Cached X user and group profiles for MaiBot display.

``GET /2/users/:id`` is a metered call, and a group conversation lookup is
kept on the same clock. A successful nickname and avatar stay fresh for
``ttl_sec`` (72 hours by default). Records live in the data directory the
host grants the plugin. Avatar bytes are stored there and mirrored into
MaiBot's ``data/avatar/<platform>/`` cache, which is what the WebUI loads.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from .constants import PLATFORM

_FAILURE_TTL_SEC = 6 * 3600
_DEFAULT_TTL_SEC = 72 * 3600
_IMAGE_SUFFIXES = (".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp")
_CIPHER_TEXT = re.compile(r"^[A-Za-z0-9+/_=-]+$")


def display_name(record: Mapping[str, Any], user_id: str) -> str:
    """Prefer the X display name, then the handle, then the numeric id."""
    name = str(record.get("name") or "").strip()
    username = str(record.get("username") or "").strip()
    return name or username or user_id


def larger_profile_image(url: str) -> str:
    """Ask the image CDN for a larger file. This is not another user lookup."""
    return url.replace("_normal.", "_400x400.")


def looks_encrypted(value: str) -> bool:
    """Heuristic for a conversation-key ciphertext. Plain titles and URLs stay as-is."""
    text = value.strip()
    if len(text) < 24 or any(character.isspace() for character in text):
        return False
    lowered = text.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return False
    return _CIPHER_TEXT.fullmatch(text) is not None


def _safe_token(value: str, *, lower: bool) -> str:
    """Match ``src/webui/routers/avatar.py`` path sanitization."""
    text = value.strip().lower() if lower else value.strip()
    return re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("_")


def host_avatar_root(data_dir: Path) -> Path | None:
    """Return the WebUI avatar cache next to the directory the runner grants.

    ``build_plugin_paths`` gives the plugin ``<data>/plugins/<plugin_id>``.
    The WebUI reads ``<data>/avatar/<platform>/``. Any other data directory
    stays inside itself.
    """
    if data_dir.parent.name != "plugins":
        return None
    return data_dir.parent.parent / "avatar"


def avatar_path(avatar_root: Path, user_id: str, suffix: str, *, group: bool = False) -> Path:
    """Match ``src/webui/routers/avatar.py`` file names under one avatar root.

    Group files use the ``group_<id>`` token the WebUI requests for a group chat.
    """
    platform = _safe_token(PLATFORM, lower=True) or "xchat"
    token = f"group_{user_id}" if group else user_id
    target = _safe_token(token, lower=False)
    if suffix.lower() not in _IMAGE_SUFFIXES:
        suffix = ".jpg"
    return avatar_root / platform / f"{target}{suffix}"


def _suffix_for(content_type: str, image: bytes) -> str:
    kind = content_type.split(";", 1)[0].strip().lower()
    by_type = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/gif": ".gif",
        "image/bmp": ".bmp",
    }
    if kind in by_type:
        return by_type[kind]
    if image.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if image.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if image.startswith(b"RIFF") and image[8:12] == b"WEBP":
        return ".webp"
    if image.startswith(b"BM"):
        return ".bmp"
    return ""


def _string_list(source: Mapping[str, Any], keys: Sequence[str]) -> list[str]:
    found: list[str] = []
    for key in keys:
        raw = source.get(key)
        if isinstance(raw, list):
            found.extend(str(item).strip() for item in raw if str(item).strip())
    return list(dict.fromkeys(found))


class UserProfileCache:
    """Remember display names and avatars until ``ttl_sec`` elapses."""

    def __init__(
        self,
        api: Any,
        logger: Any,
        *,
        data_dir: Path,
        ttl_sec: float = _DEFAULT_TTL_SEC,
    ) -> None:
        self._api = api
        self._logger = logger
        self._data_dir = Path(data_dir)
        self._ttl_sec = ttl_sec
        self._path = self._data_dir / "users.json"
        self._groups_path = self._data_dir / "groups.json"
        self._records = self._load(self._path)
        self._groups = self._load(self._groups_path)
        self._avatar_errors: set[str] = set()

    async def display_name(self, user_id: str) -> str:
        user_id = user_id.strip()
        if not user_id:
            return ""
        record = await self._ensure(user_id)
        return display_name(record, user_id)

    def remember_group(
        self,
        conversation_id: str,
        *,
        name: str = "",
        avatar_url: str = "",
        member_ids: Sequence[str] | None = None,
    ) -> None:
        """Store a title or avatar already recovered from a group event."""
        conversation_id = conversation_id.strip()
        if not conversation_id:
            return
        record = dict(self._groups.get(conversation_id) or {})
        changed = False
        name = name.strip()
        avatar_url = avatar_url.strip()
        if name and name != str(record.get("name") or ""):
            record["name"] = name
            record["fetched_at"] = time.time()
            record.pop("failed_at", None)
            changed = True
        if avatar_url and avatar_url != str(record.get("avatar_url") or ""):
            record["avatar_url"] = avatar_url
            record.pop("avatar_saved", None)
            self._avatar_errors.discard(self._group_avatar_key(conversation_id))
            record["fetched_at"] = time.time()
            record.pop("failed_at", None)
            changed = True
        members = list(dict.fromkeys(str(item).strip() for item in (member_ids or []) if str(item).strip()))
        if members and members != list(record.get("member_ids") or []):
            record["member_ids"] = members
            changed = True
        if not changed:
            return
        self._groups[conversation_id] = record
        self._save(self._groups_path, self._groups)

    async def group_record(
        self,
        conversation_id: str,
        decrypt: Callable[[str], str],
    ) -> dict[str, Any]:
        """Return the cached group profile, refreshing it after ``ttl_sec``."""
        conversation_id = conversation_id.strip()
        if not conversation_id:
            return {}
        record = dict(self._groups.get(conversation_id) or {})
        if self._fresh(record) and "name" in record:
            await self._ensure_group_avatar(conversation_id, record)
            return record
        if self._failure_is_recent(record):
            await self._ensure_group_avatar(conversation_id, record)
            return record
        try:
            payload = await self._api.get_json(
                f"/2/chat/conversations/{self._api.conversation_path(conversation_id)}",
                params={"chat_conversation.fields": "group_name,group_avatar_url,id,type"},
            )
        except Exception as exc:
            self._logger.warning("X 群资料请求失败 conversation=%s: %s", conversation_id, exc)
            self._mark_failed(self._groups, self._groups_path, conversation_id, record)
            return record
        data = payload.get("data") if isinstance(payload, Mapping) else None
        if not isinstance(data, Mapping):
            self._mark_failed(self._groups, self._groups_path, conversation_id, record)
            return record
        raw_name = str(data.get("group_name") or "").strip()
        raw_avatar = str(data.get("group_avatar_url") or "").strip()
        plain_name = self._decrypt_field(decrypt, raw_name)
        plain_avatar = self._decrypt_field(decrypt, raw_avatar)
        if raw_name and looks_encrypted(raw_name) and not plain_name:
            self._logger.warning("X 群名称解密失败 conversation=%s", conversation_id)
            self._mark_failed(self._groups, self._groups_path, conversation_id, record)
            return record
        if plain_name or "group_name" in data:
            record["name"] = plain_name
        elif "name" not in record:
            self._mark_failed(self._groups, self._groups_path, conversation_id, record)
            return record
        if raw_avatar and looks_encrypted(raw_avatar) and not plain_avatar:
            self._logger.warning("X 群头像地址解密失败 conversation=%s", conversation_id)
        elif plain_avatar:
            if plain_avatar != str(record.get("avatar_url") or ""):
                record["avatar_url"] = plain_avatar
            record.pop("avatar_saved", None)
            self._avatar_errors.discard(self._group_avatar_key(conversation_id))
        else:
            record.pop("avatar_saved", None)
            self._avatar_errors.discard(self._group_avatar_key(conversation_id))
        members = _string_list(data, ("member_ids", "admin_ids", "participant_ids"))
        if members:
            record["member_ids"] = members
        record["fetched_at"] = time.time()
        record.pop("failed_at", None)
        self._groups[conversation_id] = record
        self._save(self._groups_path, self._groups)
        await self._ensure_group_avatar(conversation_id, record)
        return record

    async def ensure_group_avatar(self, conversation_id: str) -> None:
        conversation_id = conversation_id.strip()
        record = self._groups.get(conversation_id)
        if isinstance(record, dict):
            await self._ensure_group_avatar(conversation_id, record)

    async def _ensure(self, user_id: str) -> dict[str, Any]:
        record = dict(self._records.get(user_id) or {})
        if self._fresh(record) and ("name" in record or "username" in record):
            await self._ensure_avatar(user_id, record)
            return record
        if self._failure_is_recent(record):
            return record
        try:
            payload = await self._api.get_json(
                f"/2/users/{user_id}",
                params={"user.fields": "name,username,profile_image_url"},
            )
        except Exception as exc:
            self._logger.warning("X 用户资料请求失败 user=%s: %s", user_id, exc)
            self._mark_failed(self._records, self._path, user_id, record)
            return record
        data = payload.get("data") if isinstance(payload, Mapping) else None
        if not isinstance(data, Mapping):
            self._mark_failed(self._records, self._path, user_id, record)
            return record
        refreshed = {
            "name": str(data.get("name") or "").strip(),
            "username": str(data.get("username") or "").strip(),
            "profile_image_url": str(data.get("profile_image_url") or "").strip(),
            "fetched_at": time.time(),
        }
        self._records[user_id] = refreshed
        self._save(self._path, self._records)
        self._avatar_errors.discard(user_id)
        await self._ensure_avatar(user_id, refreshed)
        return refreshed

    def _fresh(self, record: Mapping[str, Any]) -> bool:
        try:
            fetched_at = float(record.get("fetched_at") or 0)
        except (TypeError, ValueError):
            return False
        return fetched_at > 0 and time.time() - fetched_at < self._ttl_sec

    @staticmethod
    def _failure_is_recent(record: Mapping[str, Any]) -> bool:
        try:
            failed_at = float(record.get("failed_at") or 0)
        except (TypeError, ValueError):
            return False
        return failed_at > 0 and time.time() - failed_at < _FAILURE_TTL_SEC

    def _mark_failed(
        self,
        store: dict[str, dict[str, Any]],
        path: Path,
        key: str,
        record: dict[str, Any],
    ) -> None:
        record["failed_at"] = time.time()
        store[key] = record
        self._save(path, store)

    @staticmethod
    def _decrypt_field(decrypt: Callable[[str], str], value: str) -> str:
        if not value:
            return ""
        try:
            return str(decrypt(value) or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _group_avatar_key(conversation_id: str) -> str:
        return f"group:{conversation_id}"

    async def _ensure_avatar(self, user_id: str, record: dict[str, Any]) -> None:
        await self._save_avatar(
            user_id,
            record,
            url_field="profile_image_url",
            error_key=user_id,
            store=self._records,
            path=self._path,
            group=False,
        )

    async def _ensure_group_avatar(self, conversation_id: str, record: dict[str, Any]) -> None:
        await self._save_avatar(
            conversation_id,
            record,
            url_field="avatar_url",
            error_key=self._group_avatar_key(conversation_id),
            store=self._groups,
            path=self._groups_path,
            group=True,
        )

    async def _save_avatar(
        self,
        target_id: str,
        record: dict[str, Any],
        *,
        url_field: str,
        error_key: str,
        store: dict[str, dict[str, Any]],
        path: Path,
        group: bool,
    ) -> None:
        existing = self._existing_avatar(target_id, group=group)
        if record.get("avatar_saved") and existing is not None:
            self._mirror_avatar(target_id, existing, group=group)
            return
        if error_key in self._avatar_errors:
            return
        url = str(record.get(url_field) or "").strip()
        if not url:
            return
        if group and not url.lower().startswith(("http://", "https://")):
            return
        label = "group" if group else "user"
        try:
            saved = await self._download_avatar(target_id, larger_profile_image(url), group=group)
        except Exception as exc:
            self._logger.warning("X 头像下载失败 %s=%s: %s", label, target_id, exc)
            self._avatar_errors.add(error_key)
            return
        if saved:
            record["avatar_saved"] = True
            store[target_id] = record
            self._save(path, store)

    def _avatar_roots(self) -> list[Path]:
        roots = [self._data_dir / "avatar"]
        host_root = host_avatar_root(self._data_dir)
        if host_root is not None and host_root not in roots:
            roots.append(host_root)
        return roots

    def _existing_avatar(self, target_id: str, *, group: bool) -> Path | None:
        for root in self._avatar_roots():
            for suffix in _IMAGE_SUFFIXES:
                path = avatar_path(root, target_id, suffix, group=group)
                if path.is_file():
                    return path
        return None

    def _mirror_avatar(self, target_id: str, source: Path, *, group: bool) -> None:
        host_root = host_avatar_root(self._data_dir)
        if host_root is None:
            return
        destination = avatar_path(host_root, target_id, source.suffix, group=group)
        if destination == source or destination.is_file():
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        for other in _IMAGE_SUFFIXES:
            existing = avatar_path(host_root, target_id, other, group=group)
            if existing != destination and existing.is_file():
                existing.unlink()
        destination.write_bytes(source.read_bytes())

    async def _download_avatar(self, target_id: str, url: str, *, group: bool) -> bool:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "MaiBot-XChat-Adapter"})
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}")
        content_type = str(response.headers.get("content-type") or "")
        image = response.content
        suffix = _suffix_for(content_type, image)
        if not image or not suffix or len(image) > 5 * 1024 * 1024:
            raise RuntimeError("头像内容不是受支持的图片")
        for root in self._avatar_roots():
            path = avatar_path(root, target_id, suffix, group=group)
            path.parent.mkdir(parents=True, exist_ok=True)
            for other in _IMAGE_SUFFIXES:
                existing = avatar_path(root, target_id, other, group=group)
                if existing != path and existing.is_file():
                    existing.unlink()
            path.write_bytes(image)
        return True

    def _load(self, path: Path) -> dict[str, dict[str, Any]]:
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        return {str(key): dict(value) for key, value in payload.items() if isinstance(value, dict)}

    def _save(self, path: Path, records: dict[str, dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
