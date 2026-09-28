"""Internal helpers for copying chat messages and reading text paths.

Not part of the public API. Scanners only read the fields listed in the
README. They do not walk arbitrary object graphs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def get_field(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def text_fragments(content: Any) -> list[str]:
    """Return text pieces from a string or OpenAI-style content parts."""
    if content is None:
        return []
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return []
    parts: list[str] = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
            continue
        text = get_field(part, "text")
        if isinstance(text, str):
            parts.append(text)
            continue
        nested = get_field(part, "content")
        if isinstance(nested, str):
            parts.append(nested)
    return parts


def tool_call_strings(tool_calls: Any) -> list[str]:
    """Return function names and arguments from chat-completions tool calls."""
    if not isinstance(tool_calls, list):
        return []
    texts: list[str] = []
    for call in tool_calls:
        function = get_field(call, "function")
        if function is not None:
            name = get_field(function, "name")
            arguments = get_field(function, "arguments")
        else:
            name = get_field(call, "name")
            arguments = get_field(call, "arguments")
        if isinstance(name, str):
            texts.append(name)
        texts.extend(_argument_strings(arguments))
    return texts


def _argument_strings(arguments: Any) -> list[str]:
    if isinstance(arguments, str):
        return [arguments]
    if isinstance(arguments, Mapping):
        return [json.dumps(dict(arguments), sort_keys=True, separators=(",", ":"))]
    return []


def copy_message(message: Any) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise TypeError("each message must be a dict")
    if "role" not in message:
        raise TypeError("each message must include a role")
    copied = dict(message)
    content = copied.get("content")
    if isinstance(content, list):
        copied["content"] = [dict(part) if isinstance(part, dict) else part for part in content]
    return copied


def response_blobs(response: Any) -> list[tuple[str, str]]:
    """Explicit text paths on a model response.

    Sources:
    - ``output_text``: a bare string, ``output_text``, or ``output[]`` content
    - ``response_content``: ``choices[].message.content`` and ``choices[].text``
    - ``tool_call``: tool-call name/arguments, and ``output[]`` name/arguments
    """
    blobs: list[tuple[str, str]] = []
    if isinstance(response, str):
        return [("output_text", response)]

    output_text = get_field(response, "output_text")
    if isinstance(output_text, str):
        blobs.append(("output_text", output_text))

    choices = get_field(response, "choices")
    if isinstance(choices, list):
        for choice in choices:
            legacy = get_field(choice, "text")
            if isinstance(legacy, str):
                blobs.append(("response_content", legacy))
            message = get_field(choice, "message")
            if message is None:
                continue
            for text in text_fragments(get_field(message, "content")):
                blobs.append(("response_content", text))
            for text in tool_call_strings(get_field(message, "tool_calls")):
                blobs.append(("tool_call", text))

    output = get_field(response, "output")
    if isinstance(output, list):
        for item in output:
            for text in text_fragments(get_field(item, "content")):
                blobs.append(("output_text", text))
            name = get_field(item, "name")
            if isinstance(name, str):
                blobs.append(("tool_call", name))
            for text in _argument_strings(get_field(item, "arguments")):
                blobs.append(("tool_call", text))
    return blobs
