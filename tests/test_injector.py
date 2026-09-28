"""Injector plants decoys in system context without mutating the caller."""

import pytest

from honeyprompts import DecoyRegistry, DecoyType, Injector


def _registry_with_aws():
    registry = DecoyRegistry()
    decoy = registry.mint(DecoyType.AWS_ACCESS_KEY)
    return registry, decoy


def test_inject_adds_a_system_message_and_leaves_the_user_message():
    registry, decoy = _registry_with_aws()
    original = [{"role": "user", "content": "What is my AWS key?"}]
    snapshot = [{"role": "user", "content": "What is my AWS key?"}]
    injected = Injector(registry).inject_messages(original)
    assert original == snapshot
    assert injected is not original
    assert injected[0]["role"] == "system"
    assert f"AWS_ACCESS_KEY_ID={decoy.value}" in injected[0]["content"]
    assert "honeypot" not in injected[0]["content"].lower()
    assert injected[1] == original[0]
    assert injected[1] is not original[0]
    assert decoy.value not in injected[1]["content"]


def test_inject_appends_to_an_existing_system_message_once():
    registry, decoy = _registry_with_aws()
    messages = [
        {"role": "system", "content": "You are a helper."},
        {"role": "user", "content": "Hi"},
    ]
    injector = Injector(registry)
    first = injector.inject_messages(messages)
    second = injector.inject_messages(first)
    assert messages[0]["content"] == "You are a helper."
    assert first[0]["content"].startswith("You are a helper.")
    assert first[0]["content"].count(decoy.value) == 1
    assert second[0]["content"].count(decoy.value) == 1
    assert second[1]["content"] == "Hi"


def test_inject_only_missing_decoys_and_can_target_ids():
    registry = DecoyRegistry()
    present = registry.mint(DecoyType.API_TOKEN)
    missing = registry.mint(DecoyType.GENERIC_SECRET)
    messages = [{"role": "system", "content": f"API_TOKEN={present.value}"}]
    injected = Injector(registry).inject_messages(messages)
    assert injected[0]["content"].count(present.value) == 1
    assert f"SECRET={missing.value}" in injected[0]["content"]

    only_present = Injector(registry).inject_messages(
        [{"role": "user", "content": "Hi"}],
        decoy_ids=[present.id],
    )
    assert present.value in only_present[0]["content"]
    assert missing.value not in only_present[0]["content"]


def test_empty_selection_and_unknown_id():
    registry, _decoy = _registry_with_aws()
    injector = Injector(registry)
    messages = [{"role": "user", "content": "Hi"}]
    untouched = injector.inject_messages(messages, decoy_ids=[])
    assert untouched == messages
    assert untouched is not messages
    with pytest.raises(KeyError, match="unknown decoy id"):
        injector.inject_messages(messages, decoy_ids=["dec_missing"])


def test_system_list_content_and_rejected_placement():
    registry, decoy = _registry_with_aws()
    messages = [
        {"role": "system", "content": [{"type": "text", "text": "Stay helpful."}]},
        {"role": "user", "content": "Hi"},
    ]
    injected = Injector(registry).inject_messages(messages)
    parts = injected[0]["content"]
    assert parts[0]["text"] == "Stay helpful."
    assert decoy.value in parts[-1]["text"]
    assert messages[0]["content"] == [{"type": "text", "text": "Stay helpful."}]
    with pytest.raises(ValueError, match="placement"):
        Injector(registry).inject_messages(messages, placement="user")


def test_empty_registry_does_not_invent_a_system_message():
    injected = Injector(DecoyRegistry()).inject_messages(
        [{"role": "user", "content": "Hi"}]
    )
    assert injected == [{"role": "user", "content": "Hi"}]
