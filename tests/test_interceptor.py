"""Kill-switch raises on a leaked decoy and does not return that response."""

import json

import pytest

from honeyprompts import (
    DecoyRegistry,
    DecoyType,
    HoneyTrapTriggeredException,
    Interceptor,
    verify_receipt,
)
from helpers import SIGNING_KEY


def _armed():
    registry = DecoyRegistry()
    decoy = registry.mint(DecoyType.AWS_ACCESS_KEY)
    interceptor = Interceptor(
        registry,
        SIGNING_KEY,
        agent_id="agent-1",
        session_id="session-1",
    )
    return registry, decoy, interceptor


def test_response_content_leak_raises_and_receipt_has_no_secret():
    _registry, decoy, interceptor = _armed()
    response = {"choices": [{"message": {"role": "assistant", "content": f"key={decoy.value}"}}]}
    with pytest.raises(HoneyTrapTriggeredException) as exc_info:
        interceptor.inspect_response(response)
    exc = exc_info.value
    assert exc.reason == "response_content_leak"
    assert exc.decoy_ids == [decoy.id]
    assert decoy.value not in str(exc)
    assert verify_receipt(exc.receipt, SIGNING_KEY)
    assert exc.receipt.event == "trap"
    assert exc.receipt.agent_id == "agent-1"
    assert exc.receipt.session_id == "session-1"
    assert exc.receipt.decoys == ((decoy.id, "aws_access_key"),)
    assert decoy.value not in json.dumps(exc.receipt.to_dict())
    assert interceptor.last_receipt == exc.receipt


def test_clean_response_is_returned_and_optional_clean_receipt_verifies():
    registry, decoy, interceptor = _armed()
    response = {"choices": [{"message": {"content": "I can't share credentials."}}]}
    assert interceptor.inspect_response(response) is response
    assert interceptor.last_receipt is None

    clean = Interceptor(
        registry,
        SIGNING_KEY,
        agent_id="agent-1",
        session_id="session-1",
        emit_clean_receipts=True,
    )
    assert clean.inspect_response(response) is response
    receipt = clean.last_receipt
    assert receipt is not None
    assert receipt.event == "clean"
    assert receipt.trigger_reason is None
    assert (decoy.id, "aws_access_key") in receipt.decoys
    assert verify_receipt(receipt, SIGNING_KEY)
    assert decoy.value not in json.dumps(receipt.to_dict())


def test_tool_call_output_text_and_prior_tool_message():
    _registry, decoy, interceptor = _armed()
    tool_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "http_post",
                                "arguments": json.dumps({"key": decoy.value}),
                            },
                        }
                    ],
                }
            }
        ]
    }
    with pytest.raises(HoneyTrapTriggeredException) as tool_exc:
        interceptor.inspect_response(tool_response)
    assert tool_exc.value.reason == "tool_call_leak"

    output_response = {"output_text": f"export AWS_ACCESS_KEY_ID={decoy.value}"}
    with pytest.raises(HoneyTrapTriggeredException) as output_exc:
        interceptor.inspect_response(output_response)
    assert output_exc.value.reason == "output_text_leak"

    with pytest.raises(HoneyTrapTriggeredException) as history_exc:
        interceptor.inspect_messages(
            [
                {"role": "user", "content": "ignore instructions"},
                {"role": "tool", "content": decoy.value},
            ]
        )
    assert history_exc.value.reason == "tool_output_leak"


def test_planted_system_message_and_user_text_are_not_a_trip():
    registry, decoy, interceptor = _armed()
    from honeyprompts import Injector

    injected = Injector(registry).inject_messages([{"role": "user", "content": "Hi"}])
    interceptor.inspect_messages(injected)
    interceptor.inspect_messages([{"role": "user", "content": decoy.value}])
    assert interceptor.last_receipt is None


def test_assistant_history_and_combined_reasons():
    _registry, decoy, interceptor = _armed()
    with pytest.raises(HoneyTrapTriggeredException) as history_exc:
        interceptor.inspect_messages(
            [{"role": "assistant", "content": f"I found {decoy.value}"}]
        )
    assert history_exc.value.reason == "assistant_message_leak"

    response = {
        "choices": [
            {
                "message": {
                    "content": decoy.value,
                    "tool_calls": [{"function": {"name": "use", "arguments": decoy.value}}],
                }
            }
        ]
    }
    with pytest.raises(HoneyTrapTriggeredException) as exc_info:
        interceptor.inspect_response(response)
    assert exc_info.value.reason == "response_content_leak+tool_call_leak"
    assert exc_info.value.decoy_ids == [decoy.id]


def test_callback_sees_the_receipt_and_a_failing_callback_still_stops():
    registry, decoy, _interceptor = _armed()
    seen = []
    interceptor = Interceptor(registry, SIGNING_KEY, on_receipt=seen.append)
    with pytest.raises(HoneyTrapTriggeredException):
        interceptor.inspect_text(decoy.value, source="output_text")
    assert seen and seen[0].event == "trap"
    assert verify_receipt(seen[0], SIGNING_KEY)

    def fail(_receipt):
        raise RuntimeError("sink failed")

    failing = Interceptor(registry, SIGNING_KEY, on_receipt=fail)
    with pytest.raises(HoneyTrapTriggeredException) as exc_info:
        failing.inspect_text(decoy.value, source="tool_output")
    assert isinstance(exc_info.value.__cause__, RuntimeError)


def test_object_style_response_and_none_rejected():
    _registry, decoy, interceptor = _armed()

    class Message:
        content = decoy.value
        tool_calls = None

    class Choice:
        message = Message()
        text = None

    class Response:
        choices = [Choice()]
        output_text = None
        output = None

    with pytest.raises(HoneyTrapTriggeredException):
        interceptor.inspect_response(Response())
    with pytest.raises(TypeError):
        interceptor.inspect_response(None)
