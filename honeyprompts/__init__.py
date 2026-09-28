"""HoneyPrompt Phase 1 SDK.

Synthetic context decoys, a kill-switch for leaks of those decoys, and
HMAC-SHA256 execution receipts.

This package mints synthetic secrets only (for example ``AKIA-HONEY-…``).
It does not store real production secrets and it does not include exploit
or attack tooling. Phases 2–4 (Supabase, dashboard, CEF webhook) are not
part of this package.
"""

from honeyprompts.exceptions import HoneyTrapTriggeredException
from honeyprompts.injector import Injector
from honeyprompts.interceptor import Interceptor
from honeyprompts.protect import ProtectedClient, protect
from honeyprompts.receipts import ExecutionReceipt, ReceiptSigner, verify_receipt
from honeyprompts.registry import Decoy, DecoyRegistry, DecoyType, is_synthetic_decoy

__version__ = "0.1.0"

__all__ = [
    "Decoy",
    "DecoyRegistry",
    "DecoyType",
    "ExecutionReceipt",
    "HoneyTrapTriggeredException",
    "Injector",
    "Interceptor",
    "ProtectedClient",
    "ReceiptSigner",
    "__version__",
    "is_synthetic_decoy",
    "protect",
    "verify_receipt",
]
