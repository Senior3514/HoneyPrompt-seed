"""Shared stubs for OpenAI-style clients. No network."""

from __future__ import annotations

from typing import Any

SIGNING_KEY = "test-signing-key!"


class Recorder:
    """Minimal ``chat.completions.create`` client that records the call."""

    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls = 0
        self.seen: list[dict] | None = None
        self.kwargs: dict | None = None
        self.chat = self
        self.completions = self

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        self.kwargs = kwargs
        self.seen = kwargs.get("messages")
        return self.response


class AsyncRecorder(Recorder):
    async def create(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        self.kwargs = kwargs
        self.seen = kwargs.get("messages")
        return self.response
