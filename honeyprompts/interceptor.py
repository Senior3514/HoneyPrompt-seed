"""Kill-switch for leaks of registered synthetic decoys.

Detection is an exact substring match of a registered decoy value. It is
not a semantic classifier and does not claim to catch a leak that never
repeats the secret value.

On a match, ``HoneyTrapTriggeredException`` is raised and the leaking
response is not returned. The exception carries a signed receipt and does
not include the secret value.

``inspect_messages`` scans prior assistant, tool, and function messages
before another model hop. It does not scan system or user messages, so
credentials planted by the injector are not themselves a trap.
``inspect_response`` scans the model response paths documented in
``_messages.response_blobs``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from honeyprompts._messages import response_blobs, text_fragments, tool_call_strings
from honeyprompts.exceptions import HoneyTrapTriggeredException
from honeyprompts.receipts import ExecutionReceipt, ReceiptSigner, decoy_pairs
from honeyprompts.registry import Decoy, DecoyRegistry

_REASONS = {
    "response_content": "response_content_leak",
    "tool_call": "tool_call_leak",
    "output_text": "output_text_leak",
    "tool_output": "tool_output_leak",
    "assistant_message": "assistant_message_leak",
}

_TEXT_SOURCES = frozenset(_REASONS)


class Interceptor:
    """Stops a cascade when a registered decoy is accessed or leaked."""

    def __init__(
        self,
        registry: DecoyRegistry,
        signing_key: str | bytes | None = None,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        emit_clean_receipts: bool = False,
        on_receipt: Callable[[ExecutionReceipt], None] | None = None,
    ) -> None:
        if not isinstance(registry, DecoyRegistry):
            raise TypeError("registry must be a DecoyRegistry")
        self.registry = registry
        self.agent_id = agent_id
        self.session_id = session_id
        self.emit_clean_receipts = emit_clean_receipts
        self._on_receipt = on_receipt
        self._signer = ReceiptSigner(signing_key)
        self.last_receipt: ExecutionReceipt | None = None

    def inspect_text(self, text: str, *, source: str = "output_text") -> ExecutionReceipt | None:
        """Scan one text blob (a tool result or other output path).

        Raises ``HoneyTrapTriggeredException`` when a registered decoy
        appears. When ``emit_clean_receipts`` is true and the text is
        clean, returns the clean receipt; otherwise returns None.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a str")
        if source not in _TEXT_SOURCES:
            known = ", ".join(sorted(_TEXT_SOURCES))
            raise ValueError(f"unknown scan source {source!r}. Expected one of: {known}.")
        self.last_receipt = None
        matched: dict[str, Decoy] = {}
        for decoy in self.registry.find_in_text(text):
            matched[decoy.id] = decoy
        if matched:
            self._trip(matched, {_REASONS[source]})
        return self._maybe_clean_receipt()

    def inspect_messages(self, messages: list) -> None:
        """Scan prior assistant and tool/function messages.

        System and user roles are ignored. A match raises
        ``HoneyTrapTriggeredException``. A clean conversation does not
        emit a receipt; the completion receipt belongs to the response
        scan so one ``create`` call does not sign two clean receipts.
        """
        if not isinstance(messages, list):
            raise TypeError("messages must be a list")
        self.last_receipt = None
        matched: dict[str, Decoy] = {}
        reasons: set[str] = set()
        for message in messages:
            if not isinstance(message, Mapping):
                raise TypeError("each message must be a dict")
            role = message.get("role")
            if role == "assistant":
                source = "assistant_message"
            elif role in ("tool", "function"):
                source = "tool_output"
            else:
                continue
            for text in text_fragments(message.get("content")):
                self._collect(text, source, matched, reasons)
            if role == "assistant":
                for text in tool_call_strings(message.get("tool_calls")):
                    self._collect(text, "tool_call", matched, reasons)
        if matched:
            self._trip(matched, reasons)

    def inspect_response(self, response: Any) -> Any:
        """Scan a model response and return it only when it is clean.

        A match raises ``HoneyTrapTriggeredException`` instead of
        returning ``response``. ``None`` is rejected.
        """
        if response is None:
            raise TypeError("response is None")
        self.last_receipt = None
        matched: dict[str, Decoy] = {}
        reasons: set[str] = set()
        for source, text in response_blobs(response):
            self._collect(text, source, matched, reasons)
        if matched:
            self._trip(matched, reasons)
        self._maybe_clean_receipt()
        return response

    def _collect(
        self,
        text: str,
        source: str,
        matched: dict[str, Decoy],
        reasons: set[str],
    ) -> None:
        found = self.registry.find_in_text(text)
        if not found:
            return
        reasons.add(_REASONS[source])
        for decoy in found:
            matched[decoy.id] = decoy

    def _maybe_clean_receipt(self) -> ExecutionReceipt | None:
        if not self.emit_clean_receipts:
            return None
        receipt = self._signer.issue(
            event="clean",
            decoys=decoy_pairs(self.registry.list_decoys()),
            trigger_reason=None,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )
        self._emit(receipt)
        return receipt

    def _trip(self, matched: dict[str, Decoy], reasons: set[str]) -> None:
        decoys = [matched[decoy_id] for decoy_id in sorted(matched)]
        reason = "+".join(sorted(reasons))
        receipt = self._signer.issue(
            event="trap",
            decoys=decoy_pairs(decoys),
            trigger_reason=reason,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )
        self.last_receipt = receipt
        exception = HoneyTrapTriggeredException(
            receipt=receipt,
            decoy_ids=[decoy.id for decoy in decoys],
            reason=reason,
        )
        if self._on_receipt is not None:
            try:
                self._on_receipt(receipt)
            except Exception as callback_error:
                raise exception from callback_error
        raise exception

    def _emit(self, receipt: ExecutionReceipt) -> None:
        self.last_receipt = receipt
        if self._on_receipt is not None:
            self._on_receipt(receipt)

    def __repr__(self) -> str:
        return (
            "Interceptor("
            f"agent_id={self.agent_id!r}, session_id={self.session_id!r}, "
            f"emit_clean_receipts={self.emit_clean_receipts!r})"
        )
