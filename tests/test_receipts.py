"""HMAC-SHA256 receipts verify, and tampering or the wrong key does not."""

import hashlib
import hmac
import json

import pytest

from honeyprompts import ExecutionReceipt, ReceiptSigner, verify_receipt
from honeyprompts.receipts import ENV_SIGNING_KEY, canonical_bytes, resolve_signing_key
from helpers import SIGNING_KEY

_FIELDS = {
    "v": 1,
    "receipt_id": "rcpt_" + "ab" * 16,
    "timestamp": "2026-01-01T00:00:00.000000Z",
    "agent_id": "agent-1",
    "session_id": "sess-1",
    "event": "trap",
    "decoys": [{"id": "dec_0123456789abcdef", "type": "aws_access_key"}],
    "trigger_reason": "response_content_leak",
}


def _signed(fields: dict, key: str = SIGNING_KEY) -> dict:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    signature = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {**fields, "signature": signature}


def test_documented_canonical_hmac_verifies():
    receipt = _signed(_FIELDS)
    assert verify_receipt(receipt, SIGNING_KEY)
    assert verify_receipt(receipt, SIGNING_KEY.encode("utf-8"))
    assert canonical_bytes(_FIELDS) == json.dumps(
        _FIELDS, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_issued_receipt_matches_documented_hmac_and_json():
    receipt = ReceiptSigner(SIGNING_KEY).issue(
        event="trap",
        decoys=[("dec_0123456789abcdef", "aws_access_key")],
        trigger_reason="response_content_leak",
        agent_id="agent-1",
        session_id="sess-1",
        timestamp=_FIELDS["timestamp"],
        receipt_id=_FIELDS["receipt_id"],
    )
    assert isinstance(receipt, ExecutionReceipt)
    data = receipt.to_dict()
    signature = data.pop("signature")
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    expected = hmac.new(SIGNING_KEY.encode(), payload, hashlib.sha256).hexdigest()
    assert signature == expected
    assert len(signature) == 64
    json.dumps(receipt.to_dict())
    assert verify_receipt(receipt, SIGNING_KEY)
    assert "dec_0123456789abcdef" in json.dumps(receipt.to_dict())


def test_tamper_extra_field_and_wrong_key_fail():
    receipt = _signed(_FIELDS)
    tampered = dict(receipt)
    tampered["trigger_reason"] = "tool_call_leak"
    assert verify_receipt(tampered, SIGNING_KEY) is False

    flipped = dict(receipt)
    flipped["signature"] = "0" + receipt["signature"][1:]
    assert verify_receipt(flipped, SIGNING_KEY) is False

    assert verify_receipt(receipt, "another-signing-key") is False

    extra = dict(receipt)
    extra["note"] = "unsigned"
    assert verify_receipt(extra, SIGNING_KEY) is False

    fields = {
        **_FIELDS,
        "decoys": [
            {"id": "dec_0123456789abcdef", "type": "aws_access_key"},
            {"id": "dec_ffffffffffffffff", "type": "aws_access_key"},
        ],
    }
    signed = _signed(fields)
    signed["decoys"] = list(reversed(fields["decoys"]))
    assert verify_receipt(signed, SIGNING_KEY) is True


def test_signing_key_from_env_and_rejected_keys(monkeypatch):
    monkeypatch.delenv(ENV_SIGNING_KEY, raising=False)
    with pytest.raises(ValueError, match="HONEYPROMPTS_SIGNING_KEY"):
        resolve_signing_key(None)

    short = "unique-short"
    with pytest.raises(ValueError) as exc:
        resolve_signing_key(short)
    assert short not in str(exc.value)

    monkeypatch.setenv(ENV_SIGNING_KEY, SIGNING_KEY)
    signer = ReceiptSigner()
    receipt = signer.issue(
        event="clean",
        decoys=[],
        trigger_reason=None,
        agent_id=None,
        session_id=None,
        timestamp="2026-01-01T00:00:00.000000Z",
        receipt_id="rcpt_" + "cd" * 16,
    )
    assert receipt.agent_id is None
    assert receipt.event == "clean"
    assert verify_receipt(receipt, None)
    assert SIGNING_KEY not in repr(signer)


def test_clean_receipt_with_a_reason_does_not_verify():
    fields = {
        "v": 1,
        "receipt_id": "rcpt_" + "ef" * 16,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "agent_id": None,
        "session_id": None,
        "event": "clean",
        "decoys": [],
        "trigger_reason": "response_content_leak",
    }
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(SIGNING_KEY.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_receipt({**fields, "signature": signature}, SIGNING_KEY) is False
