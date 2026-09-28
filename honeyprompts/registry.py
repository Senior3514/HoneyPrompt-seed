"""Synthetic decoy registry.

HoneyPrompt only mints and stores synthetic secrets. ``mint`` has no
parameter for a caller-supplied value. ``register`` reloads a value that
already matches a synthetic pattern (so a future store can round-trip
what this package minted). Any other value is refused.

Rejected values are not copied into error messages. Do not put real
production secrets in labels either; labels are display metadata and are
included in ``repr``.
"""

from __future__ import annotations

import re
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DecoyType(str, Enum):
    """Kinds of synthetic decoy this package knows how to mint."""

    AWS_ACCESS_KEY = "aws_access_key"
    API_TOKEN = "api_token"
    DATABASE_URL = "database_url"
    GENERIC_SECRET = "generic_secret"


# Exact shapes produced by ``_mint_value``. Real AWS keys, API tokens, and
# database URLs do not match these patterns. ``decoy.invalid`` is a reserved
# name (RFC 2606), not a production host.
SYNTHETIC_PATTERNS: Mapping[DecoyType, re.Pattern[str]] = {
    DecoyType.AWS_ACCESS_KEY: re.compile(r"^AKIA-HONEY-[A-Z0-9]{16}$"),
    DecoyType.API_TOKEN: re.compile(r"^hp_honey_[0-9a-f]{32}$"),
    DecoyType.GENERIC_SECRET: re.compile(r"^HONEY-SECRET-[0-9a-f]{24}$"),
    DecoyType.DATABASE_URL: re.compile(
        r"^postgres://honey:HONEY-[0-9a-f]{16}@decoy\.invalid:5432/honeyprompt$"
    ),
}

_DEFAULT_LABELS: Mapping[DecoyType, str] = {
    DecoyType.AWS_ACCESS_KEY: "synthetic aws access key",
    DecoyType.API_TOKEN: "synthetic api token",
    DecoyType.DATABASE_URL: "synthetic database url",
    DecoyType.GENERIC_SECRET: "synthetic generic secret",
}

_ENV_NAMES: Mapping[DecoyType, str] = {
    DecoyType.AWS_ACCESS_KEY: "AWS_ACCESS_KEY_ID",
    DecoyType.API_TOKEN: "API_TOKEN",
    DecoyType.DATABASE_URL: "DATABASE_URL",
    DecoyType.GENERIC_SECRET: "SECRET",
}

_DECOY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AWS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def coerce_decoy_type(decoy_type: DecoyType | str) -> DecoyType:
    if isinstance(decoy_type, DecoyType):
        return decoy_type
    if isinstance(decoy_type, str):
        try:
            return DecoyType(decoy_type)
        except ValueError:
            pass
    known = ", ".join(item.value for item in DecoyType)
    raise ValueError(f"Unknown decoy type {decoy_type!r}. Expected one of: {known}.")


def is_synthetic_decoy(value: Any, decoy_type: DecoyType | str) -> bool:
    """Return True when ``value`` matches the synthetic pattern for ``decoy_type``."""
    if not isinstance(value, str):
        return False
    try:
        kind = coerce_decoy_type(decoy_type)
    except ValueError:
        return False
    return SYNTHETIC_PATTERNS[kind].fullmatch(value) is not None


def env_var_name(decoy_type: DecoyType | str) -> str:
    """Environment-style name used when a decoy is injected into a system message."""
    return _ENV_NAMES[coerce_decoy_type(decoy_type)]


def _mint_value(kind: DecoyType) -> str:
    if kind is DecoyType.AWS_ACCESS_KEY:
        suffix = "".join(secrets.choice(_AWS_ALPHABET) for _ in range(16))
        return f"AKIA-HONEY-{suffix}"
    if kind is DecoyType.API_TOKEN:
        return "hp_honey_" + secrets.token_hex(16)
    if kind is DecoyType.GENERIC_SECRET:
        return "HONEY-SECRET-" + secrets.token_hex(12)
    if kind is DecoyType.DATABASE_URL:
        password = "HONEY-" + secrets.token_hex(8)
        return f"postgres://honey:{password}@decoy.invalid:5432/honeyprompt"
    raise ValueError(f"unsupported decoy type: {kind!r}")


def _validate_label(label: str) -> str:
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must be a non-empty string")
    if label != label.strip():
        raise ValueError("label must not have leading or trailing whitespace")
    if len(label) > 200:
        raise ValueError("label must be at most 200 characters")
    if any(ord(ch) < 32 for ch in label):
        raise ValueError("label must not contain control characters")
    if any(pattern.fullmatch(label) for pattern in SYNTHETIC_PATTERNS.values()):
        raise ValueError("label must not be a synthetic decoy value")
    return label


def _validate_decoy_id(decoy_id: str) -> str:
    if not isinstance(decoy_id, str) or _DECOY_ID_RE.fullmatch(decoy_id) is None:
        raise ValueError(
            "decoy id must be 1-128 characters and use only letters, digits, and . _ : -"
        )
    return decoy_id


def _refusal_message(kind: DecoyType) -> str:
    return (
        "Refusing to register a non-synthetic decoy value for type "
        f"{kind.value}. HoneyPrompt only stores synthetic secrets "
        "(for example AKIA-HONEY-…). Never register real production secrets."
    )


@dataclass(frozen=True, slots=True)
class Decoy:
    """A synthetic decoy. ``value`` is omitted from ``repr``."""

    id: str
    type: DecoyType
    value: str = field(repr=False)
    label: str
    created_at: str

    def describe(self) -> dict[str, str]:
        """Identity fields only. Does not include the secret value."""
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "created_at": self.created_at,
        }


class DecoyRegistry:
    """Append-only registry of synthetic decoys.

    ``mint`` creates a new decoy. ``register`` reloads one that already
    matches a synthetic pattern. Neither method accepts a real production
    secret. Phase 1 has no delete API.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Decoy] = {}
        self._lock = threading.Lock()

    def mint(self, decoy_type: DecoyType | str, *, label: str | None = None) -> Decoy:
        """Mint a new synthetic decoy.

        There is no ``value`` argument. The secret is generated here and
        checked against the synthetic pattern before it is stored.
        """
        kind = coerce_decoy_type(decoy_type)
        chosen_label = _DEFAULT_LABELS[kind] if label is None else _validate_label(label)
        value = _mint_value(kind)
        if not is_synthetic_decoy(value, kind):
            raise RuntimeError("internal error: minted value is not synthetic")
        with self._lock:
            decoy = Decoy(
                id=self._new_id_locked(),
                type=kind,
                value=value,
                label=chosen_label,
                created_at=utc_timestamp(),
            )
            self._add_locked(decoy)
            return decoy

    def register(
        self,
        *,
        decoy_type: DecoyType | str,
        value: str,
        decoy_id: str | None = None,
        label: str | None = None,
        created_at: str | None = None,
    ) -> Decoy:
        """Reload a previously minted synthetic decoy.

        ``value`` must already match the synthetic pattern for
        ``decoy_type``. This is the round-trip path for a future store.
        It is not a way to load a production secret. The refused value is
        not included in the error.
        """
        kind = coerce_decoy_type(decoy_type)
        if not is_synthetic_decoy(value, kind):
            raise ValueError(_refusal_message(kind))
        chosen_label = _DEFAULT_LABELS[kind] if label is None else _validate_label(label)
        if created_at is None:
            created_at = utc_timestamp()
        elif not isinstance(created_at, str) or not created_at or len(created_at) > 40:
            raise ValueError("created_at must be a short non-empty string")
        with self._lock:
            assigned_id = self._new_id_locked() if decoy_id is None else _validate_decoy_id(decoy_id)
            decoy = Decoy(
                id=assigned_id,
                type=kind,
                value=value,
                label=chosen_label,
                created_at=created_at,
            )
            self._add_locked(decoy)
            return decoy

    def get(self, decoy_id: str) -> Decoy | None:
        with self._lock:
            return self._by_id.get(decoy_id)

    def list_decoys(self) -> list[Decoy]:
        with self._lock:
            decoys = list(self._by_id.values())
        decoys.sort(key=lambda decoy: decoy.id)
        return decoys

    def find_in_text(self, text: str) -> list[Decoy]:
        """Return registered decoys whose synthetic value appears in ``text``.

        Match is an exact substring check. It is not a semantic classifier.
        """
        if not isinstance(text, str) or not text:
            return []
        with self._lock:
            found = [
                decoy
                for decoy in self._by_id.values()
                if decoy.value and decoy.value in text
            ]
        found.sort(key=lambda decoy: decoy.id)
        return found

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    def __contains__(self, decoy_id: object) -> bool:
        if not isinstance(decoy_id, str):
            return False
        with self._lock:
            return decoy_id in self._by_id

    def _new_id_locked(self) -> str:
        for _ in range(8):
            decoy_id = "dec_" + secrets.token_hex(8)
            if decoy_id not in self._by_id:
                return decoy_id
        raise RuntimeError("could not allocate a decoy id")

    def _add_locked(self, decoy: Decoy) -> None:
        if decoy.id in self._by_id:
            raise ValueError(f"decoy id already registered: {decoy.id}")
        if not decoy.value:
            raise ValueError("refusing an empty decoy value")
        for existing in self._by_id.values():
            if existing.value == decoy.value:
                raise ValueError(
                    f"synthetic value already registered as {existing.id}. "
                    "Refusing a duplicate decoy value."
                )
        self._by_id[decoy.id] = decoy
