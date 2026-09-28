"""Wrap an OpenAI-style client so ``chat.completions.create`` is protected.

The original client object is not modified. Phase 1 wraps
``chat.completions.create`` only. Other methods are delegated unchanged
and are not scanned. ``stream=True`` is rejected: a chunked response
would skip the kill-switch if it were passed through.

Call order on ``create``:

1. Scan prior assistant/tool/function messages (stop before the model if
   a decoy is already in the cascade).
2. Reject ``stream=True``.
3. Inject synthetic decoys into a copy of the messages.
4. Call the inner ``create``.
5. Scan the response. On a leak, raise ``HoneyTrapTriggeredException``
   and do not return the response.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from typing import Any

from honeyprompts.injector import Injector
from honeyprompts.interceptor import Interceptor
from honeyprompts.receipts import ExecutionReceipt
from honeyprompts.registry import DecoyRegistry


class _CompletionsProxy:
    def __init__(
        self,
        inner: Any,
        injector: Injector,
        interceptor: Interceptor,
        decoy_ids: Sequence[str] | None,
    ) -> None:
        self._inner = inner
        self._injector = injector
        self._interceptor = interceptor
        self._decoy_ids = decoy_ids

    def create(self, *args: Any, **kwargs: Any) -> Any:
        if "messages" not in kwargs:
            raise TypeError(
                "chat.completions.create must be called with keyword argument 'messages'"
            )
        messages = kwargs["messages"]
        self._interceptor.inspect_messages(messages)
        if kwargs.get("stream"):
            raise ValueError(
                "honeyprompts Phase 1 does not wrap streamed completions. "
                "Call create(stream=False) so the kill-switch can scan the full response."
            )
        call_kwargs = dict(kwargs)
        call_kwargs["messages"] = self._injector.inject_messages(
            messages,
            decoy_ids=self._decoy_ids,
        )
        result = self._inner.create(*args, **call_kwargs)
        if inspect.iscoroutine(result):
            return self._finish_async(result)
        return self._interceptor.inspect_response(result)

    async def _finish_async(self, coro: Any) -> Any:
        response = await coro
        return self._interceptor.inspect_response(response)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _ChatProxy:
    def __init__(self, inner: Any, completions: _CompletionsProxy) -> None:
        self._inner = inner
        self.completions = completions

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class ProtectedClient:
    """Client facade. ``chat.completions.create`` injects decoys and scans I/O.

    ``interceptor.last_receipt`` is the latest receipt from a trap or, when
    enabled, a clean completion. The signing key is not stored on this
    object beyond the interceptor's signer, and it is not shown in ``repr``.
    """

    def __init__(
        self,
        client: Any,
        *,
        registry: DecoyRegistry,
        injector: Injector,
        interceptor: Interceptor,
        decoy_ids: Sequence[str] | None,
    ) -> None:
        self._client = client
        self.registry = registry
        self.injector = injector
        self.interceptor = interceptor
        completions = _CompletionsProxy(
            client.chat.completions,
            injector,
            interceptor,
            decoy_ids,
        )
        self.chat = _ChatProxy(client.chat, completions)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def __repr__(self) -> str:
        return (
            "ProtectedClient("
            f"agent_id={self.interceptor.agent_id!r}, "
            f"session_id={self.interceptor.session_id!r})"
        )


def protect(
    client: Any,
    *,
    registry: DecoyRegistry,
    signing_key: str | bytes | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    emit_clean_receipts: bool = False,
    on_receipt: Callable[[ExecutionReceipt], None] | None = None,
    decoy_ids: Sequence[str] | None = None,
) -> ProtectedClient:
    """Return a wrapper around an OpenAI-style client.

    ``signing_key`` falls back to ``HONEYPROMPTS_SIGNING_KEY``. Decoys are
    read from ``registry`` on each call, so a decoy minted after ``protect``
    is still injected. ``decoy_ids`` limits injection only; the kill-switch
    still watches every decoy in the registry.
    """
    chat = getattr(client, "chat", None)
    completions = getattr(chat, "completions", None) if chat is not None else None
    create = getattr(completions, "create", None) if completions is not None else None
    if not callable(create):
        raise TypeError(
            "client must expose chat.completions.create (OpenAI-style). "
            "Phase 1 does not wrap other call shapes."
        )
    injector = Injector(registry)
    interceptor = Interceptor(
        registry,
        signing_key,
        agent_id=agent_id,
        session_id=session_id,
        emit_clean_receipts=emit_clean_receipts,
        on_receipt=on_receipt,
    )
    return ProtectedClient(
        client,
        registry=registry,
        injector=injector,
        interceptor=interceptor,
        decoy_ids=decoy_ids,
    )
