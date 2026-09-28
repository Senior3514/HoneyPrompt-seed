"""Inject synthetic decoys into OpenAI-style chat messages.

Placement is the system message only. User text is not rewritten. The
caller's message list is copied; it is not mutated. If every selected
decoy value is already present, the copy is returned unchanged so a
second inject does not stack another credential block.

Injected lines look like environment assignments (for example
``AWS_ACCESS_KEY_ID=AKIA-HONEY-…``). They are not labeled as honeypots.
The values are still synthetic secrets from the registry.
"""

from __future__ import annotations

from collections.abc import Sequence

from honeyprompts._messages import copy_message, text_fragments, tool_call_strings
from honeyprompts.registry import Decoy, DecoyRegistry, env_var_name

_BLOCK_HEADER = "Environment credentials provisioned for this session:"


def render_credential_block(decoys: Sequence[Decoy]) -> str:
    """Render decoys as environment-style assignments, without their ids."""
    ordered = sorted(decoys, key=lambda decoy: decoy.id)
    lines = [_BLOCK_HEADER]
    for decoy in ordered:
        lines.append(f"{env_var_name(decoy.type)}={decoy.value}")
    return "\n".join(lines)


class Injector:
    """Middleware that plants registered decoys into the context window."""

    def __init__(self, registry: DecoyRegistry) -> None:
        if not isinstance(registry, DecoyRegistry):
            raise TypeError("registry must be a DecoyRegistry")
        self.registry = registry

    def inject_messages(
        self,
        messages: list[dict],
        *,
        decoy_ids: Sequence[str] | None = None,
        placement: str = "system",
    ) -> list[dict]:
        """Return a new message list with missing decoys planted in a system message.

        ``placement`` must be ``"system"``. Phase 1 does not inject into
        user, assistant, or tool messages. ``decoy_ids`` limits which
        registered decoys are planted. ``None`` means every decoy currently
        in the registry. An empty list plants nothing.
        """
        if placement != "system":
            raise ValueError("Phase 1 only supports placement='system'")
        if not isinstance(messages, list):
            raise TypeError("messages must be a list")
        copied = [copy_message(message) for message in messages]
        selected = self._select(decoy_ids)
        if not selected:
            return copied
        existing = _collected_text(copied)
        missing = [decoy for decoy in selected if decoy.value not in existing]
        if not missing:
            return copied
        block = render_credential_block(missing)
        for index, message in enumerate(copied):
            if message.get("role") == "system":
                copied[index] = _append_block(message, block)
                return copied
        copied.insert(0, {"role": "system", "content": block})
        return copied

    def _select(self, decoy_ids: Sequence[str] | None) -> list[Decoy]:
        if decoy_ids is None:
            return self.registry.list_decoys()
        selected: list[Decoy] = []
        for decoy_id in decoy_ids:
            decoy = self.registry.get(decoy_id)
            if decoy is None:
                raise KeyError(f"unknown decoy id: {decoy_id}")
            selected.append(decoy)
        return selected


def _collected_text(messages: list[dict]) -> str:
    parts: list[str] = []
    for message in messages:
        parts.extend(text_fragments(message.get("content")))
        parts.extend(tool_call_strings(message.get("tool_calls")))
    return "\n".join(parts)


def _append_block(message: dict, block: str) -> dict:
    content = message.get("content")
    if content is None or content == "":
        message["content"] = block
        return message
    if isinstance(content, str):
        message["content"] = content + "\n\n" + block
        return message
    if isinstance(content, list):
        message["content"] = [*content, {"type": "text", "text": block}]
        return message
    raise TypeError("system message content must be a string, a list of parts, or empty")
