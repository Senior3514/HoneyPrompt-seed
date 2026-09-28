"""Exceptions raised by the Phase 1 kill-switch."""

from __future__ import annotations

from honeyprompts.receipts import ExecutionReceipt


class HoneyTrapTriggeredException(Exception):
    """A registered synthetic decoy showed up on a scanned path.

    The agent cascade should stop. ``receipt`` is an HMAC-SHA256
    execution receipt. The exception message lists decoy ids and the
    trigger reason only; it does not include the secret value.
    """

    def __init__(
        self,
        *,
        receipt: ExecutionReceipt,
        decoy_ids: list[str],
        reason: str,
    ) -> None:
        self.receipt = receipt
        self.decoy_ids = list(decoy_ids)
        self.reason = reason
        id_list = ", ".join(self.decoy_ids)
        super().__init__(
            f"Honey trap triggered ({reason}); decoy ids: {id_list}. Cascade stopped."
        )
