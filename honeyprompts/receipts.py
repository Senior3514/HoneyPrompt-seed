"""HMAC-SHA256 execution receipts.

The signing key is a secret. Pass it as ``signing_key`` or set
``HONEYPROMPTS_SIGNING_KEY``. The key is the UTF-8 bytes of that string,
not a hex decoding of it. It is never written into a receipt.

Canonical payload: UTF-8 JSON of every receipt field except ``signature``,
with sorted keys and separators ``(',', ':')``. Unknown fields fail
verification so a future SOC view cannot treat unsigned data as attested.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from honeyprompts.registry import DecoyType, coerce_decoy_type

RECEIPT_VERSION = 1
ENV_SIGNING_KEY = "HONEYPROMPTS_SIGNING_KEY"
MIN_KEY_BYTES = 16

_SIGNED_FIELDS = (
    "agent_id",
    "decoys",
    "event",
    "receipt_id",
    "session_id",
    "timestamp",
    "trigger_reason",
    "v",
)

_EVENTS = frozenset({"trap", "clean"})


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_signing_key(signing_key: str | bytes | None = None) -> bytes:
    """Return the HMAC key from the argument or ``HONEYPROMPTS_SIGNING_KEY``.

    Raises ``ValueError`` when the key is missing or shorter than 16 bytes.
    The key string is encoded as UTF-8 and is not hex-decoded.
    """
    if signing_key is None:
        signing_key = os.environ.get(ENV_SIGNING_KEY)
    if signing_key is None or signing_key == "" or signing_key == b"":
        raise ValueError(
            "Signing key required: pass signing_key or set HONEYPROMPTS_SIGNING_KEY. "
            "Treat the key as a secret."
        )
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    if not isinstance(key, bytes):
        raise TypeError("signing_key must be str or bytes")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"Signing key must be at least {MIN_KEY_BYTES} bytes.")
    return key


def _bounded_str(value: Any, *, max_len: int, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{field_name} must be a non-empty string of at most {max_len} characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _optional_id(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _bounded_str(value, max_len=256, field_name=field_name)


def canonical_fields(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the signed receipt fields (no signature)."""
    if not isinstance(data, Mapping):
        raise TypeError("receipt fields must be a mapping")
    unknown = set(data) - set(_SIGNED_FIELDS)
    missing = set(_SIGNED_FIELDS) - set(data)
    if unknown or missing:
        raise ValueError("receipt fields must be exactly the signed set")

    version = data["v"]
    if type(version) is not int or version != RECEIPT_VERSION:
        raise ValueError("unsupported receipt version")

    event = data["event"]
    if event not in _EVENTS:
        raise ValueError("event must be 'trap' or 'clean'")

    trigger_reason = data["trigger_reason"]
    if event == "trap":
        trigger_reason = _bounded_str(trigger_reason, max_len=200, field_name="trigger_reason")
    elif trigger_reason is not None:
        raise ValueError("clean receipt trigger_reason must be null")

    decoys_raw = data["decoys"]
    if not isinstance(decoys_raw, list):
        raise ValueError("decoys must be a list")
    decoys: list[dict[str, str]] = []
    for item in decoys_raw:
        if not isinstance(item, Mapping) or set(item) != {"id", "type"}:
            raise ValueError("each decoy must contain only id and type")
        decoy_id = _bounded_str(item["id"], max_len=128, field_name="decoy id")
        decoy_type = _bounded_str(item["type"], max_len=64, field_name="decoy type")
        coerce_decoy_type(decoy_type)
        decoys.append({"id": decoy_id, "type": decoy_type})
    decoys.sort(key=lambda entry: (entry["id"], entry["type"]))
    if len({item["id"] for item in decoys}) != len(decoys):
        raise ValueError("duplicate decoy id in receipt")
    if event == "trap" and not decoys:
        raise ValueError("trap receipt requires at least one decoy")

    return {
        "v": RECEIPT_VERSION,
        "receipt_id": _bounded_str(data["receipt_id"], max_len=80, field_name="receipt_id"),
        "timestamp": _bounded_str(data["timestamp"], max_len=40, field_name="timestamp"),
        "agent_id": _optional_id(data["agent_id"], "agent_id"),
        "session_id": _optional_id(data["session_id"], "session_id"),
        "event": event,
        "decoys": decoys,
        "trigger_reason": trigger_reason,
    }


def canonical_bytes(fields: Mapping[str, Any]) -> bytes:
    normalized = canonical_fields(fields)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign(fields: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_bytes(fields), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    """JSON-serializable HMAC-SHA256 execution receipt.

    ``decoys`` carries id and type only. The synthetic secret is not a
    receipt field. ``signature`` is the hex HMAC of the other fields.
    """

    v: int
    receipt_id: str
    timestamp: str
    agent_id: str | None
    session_id: str | None
    event: str
    decoys: tuple[tuple[str, str], ...]
    trigger_reason: str | None
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "event": self.event,
            "decoys": [{"id": decoy_id, "type": decoy_type} for decoy_id, decoy_type in self.decoys],
            "trigger_reason": self.trigger_reason,
            "signature": self.signature,
        }


def _split_signature(receipt: ExecutionReceipt | Mapping[str, Any]) -> tuple[dict[str, Any], Any]:
    if isinstance(receipt, ExecutionReceipt):
        data = receipt.to_dict()
    elif isinstance(receipt, Mapping):
        data = dict(receipt)
    else:
        raise TypeError("receipt must be an ExecutionReceipt or a mapping")
    if "signature" not in data:
        raise ValueError("receipt is missing a signature")
    signature = data.pop("signature")
    return data, signature


def verify_receipt(
    receipt: ExecutionReceipt | Mapping[str, Any],
    signing_key: str | bytes | None = None,
) -> bool:
    """Return True when ``signature`` is a valid HMAC-SHA256 of the other fields.

    A missing or short signing key raises ``ValueError``. Malformed receipts
    and bad signatures return False.
    """
    key = resolve_signing_key(signing_key)
    try:
        fields, signature = _split_signature(receipt)
        expected = _sign(fields, key)
    except (TypeError, ValueError):
        return False
    if not isinstance(signature, str) or len(signature) != len(expected):
        return False
    try:
        return hmac.compare_digest(expected, signature)
    except (TypeError, ValueError):
        return False


class ReceiptSigner:
    """Issues execution receipts. The signing key is redacted in ``repr``."""

    def __init__(self, signing_key: str | bytes | None = None) -> None:
        self._key = resolve_signing_key(signing_key)

    def issue(
        self,
        *,
        event: str,
        decoys: Sequence[tuple[str, str]],
        trigger_reason: str | None,
        agent_id: str | None = None,
        session_id: str | None = None,
        timestamp: str | None = None,
        receipt_id: str | None = None,
    ) -> ExecutionReceipt:
        """Sign a trap or clean receipt.

        ``decoys`` is a sequence of ``(id, type)`` pairs. Types must be
        known ``DecoyType`` values. Secret values are not accepted here.
        Omit ``timestamp`` and ``receipt_id`` unless the caller needs a
        deterministic receipt; they default to the current UTC time and a
        new id.
        """
        fields = canonical_fields(
            {
                "v": RECEIPT_VERSION,
                "receipt_id": receipt_id or ("rcpt_" + uuid.uuid4().hex),
                "timestamp": timestamp or utc_timestamp(),
                "agent_id": agent_id,
                "session_id": session_id,
                "event": event,
                "decoys": [{"id": decoy_id, "type": decoy_type} for decoy_id, decoy_type in decoys],
                "trigger_reason": trigger_reason,
            }
        )
        signature = _sign(fields, self._key)
        return ExecutionReceipt(
            v=fields["v"],
            receipt_id=fields["receipt_id"],
            timestamp=fields["timestamp"],
            agent_id=fields["agent_id"],
            session_id=fields["session_id"],
            event=fields["event"],
            decoys=tuple((item["id"], item["type"]) for item in fields["decoys"]),
            trigger_reason=fields["trigger_reason"],
            signature=signature,
        )

    def __repr__(self) -> str:
        return "ReceiptSigner(signing_key=***)"


def decoy_pairs(decoys: Sequence[Any]) -> list[tuple[str, str]]:
    """Build ``(id, type)`` pairs from decoy objects. Values are not read."""
    pairs: list[tuple[str, str]] = []
    for decoy in decoys:
        kind = decoy.type if isinstance(decoy.type, DecoyType) else coerce_decoy_type(decoy.type)
        pairs.append((decoy.id, kind.value))
    return pairs
