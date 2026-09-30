"""Chat XDK integration and encrypted media helpers."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .x_api import XApiClient


def identity_key_source(private_keys_b64: str, juicebox_pin: str) -> str:
    """Prefer a pasted private-key blob over JuiceBox PIN recovery."""
    if private_keys_b64.strip():
        return "private_key"
    if juicebox_pin.strip():
        return "juicebox"
    raise ValueError("需要 identity.private_keys_b64，或 identity.juicebox_pin")


def select_public_key_record(rows: Sequence[Any], preferred_version: str = "") -> dict[str, Any]:
    """Pick the configured key version, otherwise the highest registered version."""
    records = [dict(row) for row in rows if isinstance(row, Mapping)]
    if not records:
        raise ValueError("X 账号没有已注册的 Chat 公钥")
    preferred = preferred_version.strip()
    if preferred:
        for row in records:
            if str(row.get("public_key_version") or "") == preferred:
                return row
        available = ", ".join(str(row.get("public_key_version") or "") for row in records)
        raise ValueError(f"未找到 public_key_version={preferred}，当前已注册版本：{available}")

    def sort_key(row: Mapping[str, Any]) -> tuple[int, str]:
        raw = str(row.get("public_key_version") or "")
        try:
            return int(raw), raw
        except ValueError:
            return 0, raw

    return dict(max(records, key=sort_key))


def _result_errors(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    errors = result.get("errors")
    if isinstance(errors, Mapping) or isinstance(errors, list):
        return bool(errors)
    return False


_PAIR_ID = re.compile(r"^([0-9]{1,19})[-:]([0-9]{1,19})$")


def _id_forms(conversation_id: str) -> list[str]:
    """Hyphen and colon forms of a 1:1 id. Group ids stay unchanged."""
    conversation_id = conversation_id.strip()
    if not conversation_id or conversation_id.startswith("g"):
        return [conversation_id] if conversation_id else []
    match = _PAIR_ID.fullmatch(conversation_id)
    if not match:
        return [conversation_id]
    left, right = match.group(1), match.group(2)
    return [f"{left}-{right}", f"{left}:{right}"]


def _keys_mapping(value: Any) -> dict[str, Any] | None:
    """Normalize decrypt_events and extract_conversation_keys key bundles."""
    if not isinstance(value, Mapping):
        return None
    keys = value.get("keys")
    if isinstance(keys, Mapping):
        return dict(keys)
    nested = value.get("conversation_keys")
    if isinstance(nested, Mapping) and isinstance(nested.get("keys"), Mapping):
        return dict(nested["keys"])
    return None


def _version_rank(version: str) -> tuple[int, int, str]:
    """Rank key versions numerically so ``1000`` is newer than ``999``."""
    try:
        return (1, int(version), version)
    except ValueError:
        return (0, 0, version)


def _looks_encrypted(value: str) -> bool:
    """Same ciphertext heuristic as profile fields. Kept here to avoid an import cycle."""
    text = value.strip()
    if len(text) < 24 or any(character.isspace() for character in text):
        return False
    lowered = text.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return False
    return re.fullmatch(r"[A-Za-z0-9+/_=-]+", text) is not None


def juicebox_config_text(record: Mapping[str, Any]) -> str:
    """Serialize the X API ``juicebox_config`` object for ``Chat(config_json)``."""
    raw = record.get("juicebox_config")
    if isinstance(raw, str) and raw.strip():
        return raw
    if isinstance(raw, Mapping) and raw:
        return json.dumps(dict(raw), separators=(",", ":"), ensure_ascii=False)
    raise ValueError("该公钥版本没有 JuiceBox 备份配置，请改用 private_keys_b64")


class XChatCrypto:
    """Owns one Chat XDK instance and verified conversation-key caches."""

    def __init__(
        self,
        api: XApiClient,
        user_id: str,
        signing_key_version: str,
        private_keys_b64: str = "",
        *,
        juicebox_pin: str = "",
        juicebox_config_json: str = "",
    ) -> None:
        try:
            from chat_xdk import Chat
        except ImportError as exc:  # pragma: no cover - exercised in deployment
            raise RuntimeError("缺少 chatxdk，请先安装 requirements.txt") from exc

        source = identity_key_source(private_keys_b64, juicebox_pin)
        if not user_id or not signing_key_version:
            raise ValueError("identity.user_id 和 identity.signing_key_version 必须完整配置")

        self.api = api
        self.user_id = user_id
        self.signing_key_version = signing_key_version
        self.key_source = source
        if source == "private_key":
            self.chat = Chat()
            self.chat.import_keys(base64.b64decode(private_keys_b64.strip()), signing_key_version)
        else:
            if not juicebox_config_json.strip():
                raise ValueError("JuiceBox PIN 还原需要公钥记录中的 juicebox_config")
            self.chat = Chat(juicebox_config_json)
            pin = juicebox_pin.strip()
            try:
                self.chat.unlock(pin)
            except Exception as exc:
                detail = str(exc)
                if pin and pin in detail:
                    detail = "JuiceBox 拒绝了这次还原"
                raise RuntimeError(
                    f"JuiceBox PIN 还原私钥失败：{detail}。错误 PIN 会消耗猜测次数，连续失败约 20 次后备份会永久失效。"
                ) from exc
        self.chat.set_identity(user_id, signing_key_version)
        self.chat.set_cache_keys(True)
        self._conversation_keys: dict[str, dict[str, Any]] = {}
        # Peer user id -> conversation id seen on a decrypted 1:1 key or message.
        self._peers: dict[str, str] = {}
        # set_signing_keys replaces the whole store, so each refresh merges into this map first.
        self._signing_entries: dict[tuple[str, str], dict[str, Any]] = {}

    async def refresh_signing_keys(self, user_ids: Sequence[str]) -> None:
        entries: list[dict[str, Any]] = []
        for user_id in dict.fromkeys(str(item) for item in user_ids if str(item)):
            payload = await self.api.get_json(
                f"/2/users/{user_id}/public_keys",
                params={
                    "public_key.fields": "public_key_version,public_key,signing_public_key,identity_public_key_signature",
                },
            )
            for row in payload.get("data", []) or []:
                if not isinstance(row, Mapping):
                    continue
                entries.append(
                    {
                        "user_id": user_id,
                        "public_key_version": str(row.get("public_key_version") or ""),
                        "public_key": row.get("signing_public_key", ""),
                        "identity_public_key": row.get("public_key", ""),
                        "identity_public_key_signature": row.get("identity_public_key_signature", ""),
                    }
                )
        if entries:
            self._store_signing_entries(entries)

    def _store_signing_entries(self, entries: Sequence[Mapping[str, Any]]) -> None:
        """Merge participant signing keys, then install the full set.

        Chat XDK replaces the signing-key store on every ``set_signing_keys`` call.
        A later direct chat must not drop keys already loaded for another conversation.
        """
        for entry in entries:
            user_id = str(entry.get("user_id") or "")
            version = str(entry.get("public_key_version") or "")
            if user_id:
                self._signing_entries[(user_id, version)] = dict(entry)
        if self._signing_entries:
            self.chat.set_signing_keys(list(self._signing_entries.values()))

    def decrypt_event(self, payload: Mapping[str, Any]) -> dict[str, Any] | None:
        """Decrypt one live Activity payload.

        A key-change blob is verified with ``decrypt_events`` before ``encoded_event``.
        When that verification cannot see every participant's signing key, the key
        encrypted to this member is recovered with ``extract_conversation_keys`` and
        passed explicitly. The message itself stays signature-checked.
        """
        encoded_event = str(payload.get("encoded_event") or "").strip()
        key_change = str(payload.get("conversation_key_change_event") or "").strip()
        conversation_id = str(payload.get("conversation_id") or "").strip()
        sender_id = str(payload.get("sender_id") or "").strip()
        self.bind_conversation(conversation_id, sender_id)
        explicit_keys = None
        if key_change:
            explicit_keys = self._apply_key_change(conversation_id, key_change)
        if not encoded_event:
            return None
        if explicit_keys:
            event = self.chat.decrypt_event(encoded_event, explicit_keys)
        else:
            event = self.chat.decrypt_event(encoded_event)
        if not isinstance(event, Mapping):
            return None
        decrypted = dict(event)
        if not decrypted.get("key_version") and payload.get("conversation_key_version"):
            decrypted["key_version"] = str(payload["conversation_key_version"])
        event_conversation = str(decrypted.get("conversation_id") or conversation_id).strip()
        event_sender = str(decrypted.get("sender_id") or sender_id).strip()
        self.bind_conversation(event_conversation, sender_id, event_sender)
        return decrypted

    def _apply_key_change(self, conversation_id: Any, key_change: str) -> dict[str, Any] | None:
        """Return explicit keys only when the verified path rejected the key change."""
        try:
            result = self.chat.decrypt_events([key_change])
        except Exception:
            return self._extract_key_change(conversation_id, key_change)
        self._remember_result_keys(conversation_id, result)
        if not _result_errors(result):
            return None
        return self._extract_key_change(conversation_id, key_change)

    def _extract_key_change(self, conversation_id: Any, key_change: str) -> dict[str, Any] | None:
        keys = _keys_mapping(self.chat.extract_conversation_keys([key_change]))
        if conversation_id and keys:
            self._store_keys(conversation_id, keys)
        return keys or None

    def absorb_key_events(self, conversation_id: str, encoded_events: Sequence[str]) -> None:
        """Load keys from ``meta.conversation_key_events`` on the history endpoint.

        A verified ``decrypt_events`` fills the SDK cache. When verification cannot
        see a participant's signing key, ``extract_conversation_keys`` still returns
        the key encrypted to this account.
        """
        blobs = [str(item).strip() for item in encoded_events if str(item).strip()]
        conversation_id = str(conversation_id or "").strip()
        if not blobs or not conversation_id:
            return
        try:
            result = self.chat.decrypt_events(blobs)
        except Exception:
            result = None
        else:
            self._remember_result_keys(conversation_id, result)
            if not _result_errors(result):
                self.bind_conversation(conversation_id)
                return
        keys = _keys_mapping(self.chat.extract_conversation_keys(blobs))
        if keys:
            self._store_keys(conversation_id, keys)
        self.bind_conversation(conversation_id)

    def bind_conversation(self, conversation_id: str, *user_ids: Any) -> None:
        """Remember which peer a 1:1 conversation belongs to, and copy its keys across aliases.

        Group members are not indexed. A person can belong to several groups, and a
        direct reply is addressed by that person's user id.
        """
        conversation_id = str(conversation_id or "").strip()
        if not conversation_id:
            return
        if conversation_id.startswith("g"):
            # Keep every stored version on the group id. Members stay unindexed:
            # one person can belong to several groups, and a direct reply uses their user id.
            self._replicate_keys(conversation_id)
            return
        peers: list[str] = []
        match = _PAIR_ID.fullmatch(conversation_id)
        if match:
            peers.extend((match.group(1), match.group(2)))
        for user_id in user_ids:
            text = str(user_id or "").strip()
            if text:
                peers.append(text)
        for peer in peers:
            if not peer or peer == self.user_id or peer == conversation_id or peer.startswith("g"):
                continue
            self._peers[peer] = conversation_id
        self._replicate_keys(conversation_id)

    def resolve_conversation_id(self, target: str) -> str:
        """Return the conversation id previously bound to a peer, otherwise the target itself."""
        target = str(target or "").strip()
        if not target:
            return ""
        return self._peers.get(target) or target

    def _candidate_ids(self, conversation_id: str) -> list[str]:
        seen: list[str] = []

        def add(value: object) -> None:
            text = str(value or "").strip()
            if text and text not in seen:
                seen.append(text)

        add(conversation_id)
        add(self._peers.get(str(conversation_id or "").strip(), ""))
        index = 0
        while index < len(seen):
            for form in _id_forms(seen[index]):
                add(form)
            index += 1
        targets = set(seen)
        for peer, conv in self._peers.items():
            forms = _id_forms(conv)
            if conv in targets or any(form in targets for form in forms):
                add(peer)
                add(conv)
                for form in forms:
                    add(form)
        return seen

    def _store_keys(self, conversation_id: Any, keys: Mapping[str, Any]) -> None:
        conversation_id = str(conversation_id or "").strip()
        normalized = {str(version): key for version, key in keys.items() if str(version)}
        if not conversation_id or not normalized:
            return
        for candidate in self._candidate_ids(conversation_id):
            self._conversation_keys.setdefault(candidate, {}).update(normalized)

    def _replicate_keys(self, conversation_id: str) -> None:
        merged: dict[str, Any] = {}
        candidates = self._candidate_ids(conversation_id)
        for candidate in candidates:
            merged.update(self._conversation_keys.get(candidate, {}))
        if not merged:
            return
        for candidate in candidates:
            self._conversation_keys.setdefault(candidate, {}).update(merged)

    def encrypt_message(
        self,
        conversation_id: str,
        text: str,
        *,
        attachments: list[dict[str, Any]] | None = None,
        conversation_key: Any = None,
        conversation_key_version: str | None = None,
    ) -> dict[str, Any]:
        resolved = self.resolve_conversation_id(conversation_id)
        if not resolved:
            raise RuntimeError("缺少 X Chat conversation_id")
        kwargs: dict[str, Any] = {}
        if attachments:
            kwargs["attachments"] = attachments
        key = conversation_key
        version = "" if conversation_key_version is None else str(conversation_key_version).strip()
        if key is None or not version:
            try:
                found_key, found_version = self._key_for(resolved, version or None)
            except RuntimeError:
                found_key, found_version = None, ""
            if key is None:
                key = found_key
            if not version:
                version = found_version
        # The SDK accepts both, or neither. One without the other is rejected.
        if key is not None and version:
            kwargs["conversation_key"] = key
            kwargs["conversation_key_version"] = version
        payload = self.chat.encrypt_message(resolved, text, **kwargs)
        return {
            "message_id": str(payload.message_id),
            "encoded_message_create_event": str(payload.encrypted_content),
            "encoded_message_event_signature": str(payload.encoded_event_signature),
        }

    def encrypt_stream(self, conversation_id: str, data: bytes) -> tuple[bytes, str]:
        key, version = self._key_for(conversation_id)
        return bytes(self.chat.encrypt_stream(data, key)), version

    def decrypt_stream(self, conversation_id: str, data: bytes, key_version: str | None = None) -> bytes:
        key, _ = self._key_for(conversation_id, key_version)
        return bytes(self.chat.decrypt_stream(data, key))

    def decrypt_text(self, conversation_id: str, value: str) -> str:
        """Decrypt a group title or avatar URL. Plaintext and URLs are returned unchanged.

        A field that looks encrypted but cannot be opened returns an empty string,
        so the ciphertext itself is never shown as the group name.
        """
        text = str(value or "").strip()
        if not text or not _looks_encrypted(text):
            return text
        for _version, key in self._versions_newest_first(conversation_id):
            try:
                plain = str(self.chat.decrypt(text, key) or "").strip()
            except Exception:
                continue
            if plain:
                return plain
        return ""

    def remember_prepared(self, conversation_id: str, prepared: Any) -> None:
        value = dict(prepared) if isinstance(prepared, Mapping) else vars(prepared)
        key = value.get("conversation_key")
        version = str(value.get("conversation_key_version") or "")
        if key is not None and version:
            self._store_keys(conversation_id, {version: key})

    def _remember_result_keys(self, conversation_id: Any, result: Any) -> None:
        if not isinstance(result, Mapping):
            return
        bundle = result.get("conversation_keys")
        if not isinstance(bundle, Mapping):
            return
        direct = _keys_mapping(bundle) or _keys_mapping(result)
        requested = str(conversation_id or "").strip()
        if direct and requested:
            self._store_keys(requested, direct)
        for ident, value in bundle.items():
            if ident in {"keys", "latest_version"} or not isinstance(value, Mapping):
                continue
            nested = _keys_mapping(value)
            if nested:
                self._store_keys(str(ident), nested)

    def _versions_newest_first(self, conversation_id: str) -> list[tuple[str, Any]]:
        merged: dict[str, Any] = {}
        for candidate in self._candidate_ids(conversation_id):
            merged.update(self._conversation_keys.get(candidate, {}))
        return sorted(merged.items(), key=lambda item: _version_rank(item[0]), reverse=True)

    def _key_for(self, conversation_id: str, version: str | None = None) -> tuple[Any, str]:
        wanted = str(version or "").strip()
        candidates = self._candidate_ids(conversation_id)
        if wanted:
            for candidate in candidates:
                keys = self._conversation_keys.get(candidate, {})
                if wanted in keys:
                    return keys[wanted], wanted
        selected_version = ""
        selected_key = None
        selected_rank: tuple[int, int, str] | None = None
        for candidate in candidates:
            keys = self._conversation_keys.get(candidate, {})
            if not keys:
                continue
            latest = max(keys, key=lambda item: _version_rank(str(item)))
            rank = _version_rank(str(latest))
            if selected_rank is None or rank > selected_rank:
                selected_rank = rank
                selected_version = str(latest)
                selected_key = keys[latest]
        if selected_key is not None and selected_version:
            return selected_key, selected_version
        raise RuntimeError(f"conversation {conversation_id} 没有可用的已验证会话密钥")

    @staticmethod
    def key_change_body(prepared: Any) -> dict[str, Any]:
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
