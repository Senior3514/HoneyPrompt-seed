"""Decoy registry: mint synthetic secrets and refuse anything else."""

import re

import pytest

from honeyprompts import DecoyRegistry, DecoyType, is_synthetic_decoy

_REAL_LOOKING = "AKIAIOSFODNN7EXAMPLE"


def test_mint_aws_access_key_matches_synthetic_pattern():
    registry = DecoyRegistry()
    decoy = registry.mint(DecoyType.AWS_ACCESS_KEY)
    assert decoy.type is DecoyType.AWS_ACCESS_KEY
    assert is_synthetic_decoy(decoy.value, DecoyType.AWS_ACCESS_KEY)
    assert re.fullmatch(r"dec_[0-9a-f]{16}", decoy.id)
    assert decoy.value not in repr(decoy)
    assert "value" not in decoy.describe()
    assert decoy.describe()["id"] == decoy.id
    assert len(registry) == 1
    assert decoy.id in registry


def test_mint_covers_each_synthetic_type():
    registry = DecoyRegistry()
    minted = [registry.mint(kind) for kind in DecoyType]
    values = [decoy.value for decoy in minted]
    assert len(set(values)) == len(values)
    for decoy in minted:
        assert is_synthetic_decoy(decoy.value, decoy.type)
        assert not is_synthetic_decoy(decoy.value, _other(decoy.type))
    database = next(decoy for decoy in minted if decoy.type is DecoyType.DATABASE_URL)
    assert "@decoy.invalid:5432/" in database.value


def test_mint_does_not_accept_a_caller_supplied_secret():
    registry = DecoyRegistry()
    with pytest.raises(TypeError):
        registry.mint(DecoyType.AWS_ACCESS_KEY, value="AKIA-HONEY-AAAAAAAAAAAAAAAA")


def test_two_mints_differ():
    registry = DecoyRegistry()
    first = registry.mint("aws_access_key")
    second = registry.mint("aws_access_key")
    assert first.value != second.value
    assert first.id != second.id


def test_register_reloads_a_minted_decoy_and_rejects_real_looking_values():
    source = DecoyRegistry()
    minted = source.mint(DecoyType.API_TOKEN, label="round trip")
    target = DecoyRegistry()
    loaded = target.register(
        decoy_type=minted.type,
        value=minted.value,
        decoy_id=minted.id,
        label=minted.label,
        created_at=minted.created_at,
    )
    assert loaded.value == minted.value
    assert target.find_in_text("leaked " + minted.value)[0].id == minted.id

    refused = DecoyRegistry()
    with pytest.raises(ValueError) as exc:
        refused.register(decoy_type=DecoyType.AWS_ACCESS_KEY, value=_REAL_LOOKING)
    assert _REAL_LOOKING not in str(exc.value)
    assert "synthetic" in str(exc.value).lower() or "AKIA-HONEY" in str(exc.value)
    assert len(refused) == 0


def test_register_rejects_synthetic_value_for_the_wrong_type_without_echoing_it():
    source = DecoyRegistry()
    minted = source.mint(DecoyType.AWS_ACCESS_KEY)
    target = DecoyRegistry()
    with pytest.raises(ValueError) as exc:
        target.register(decoy_type=DecoyType.GENERIC_SECRET, value=minted.value)
    assert minted.value not in str(exc.value)
    assert len(target) == 0


def test_register_rejects_duplicate_id_and_duplicate_value():
    registry = DecoyRegistry()
    minted = registry.mint(DecoyType.GENERIC_SECRET)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(
            decoy_type=minted.type,
            value=minted.value,
            decoy_id="other-id",
        )
    fresh = DecoyRegistry().mint(DecoyType.GENERIC_SECRET)
    with pytest.raises(ValueError, match="decoy id already registered"):
        registry.register(
            decoy_type=fresh.type,
            value=fresh.value,
            decoy_id=minted.id,
        )


def test_find_in_text_is_exact_and_ordered():
    registry = DecoyRegistry()
    first = registry.mint(DecoyType.GENERIC_SECRET)
    second = registry.mint(DecoyType.API_TOKEN)
    assert registry.find_in_text("nothing to see") == []
    found = registry.find_in_text(f"{second.value} then {first.value}")
    assert [decoy.id for decoy in found] == sorted([first.id, second.id])
    assert registry.get(first.id) == first
    assert registry.get("missing") is None


def test_unknown_type_and_bad_label_are_rejected():
    registry = DecoyRegistry()
    with pytest.raises(ValueError, match="Unknown decoy type"):
        registry.mint("production_password")
    with pytest.raises(ValueError, match="label"):
        registry.mint(DecoyType.API_TOKEN, label="  padded  ")


def _other(kind: DecoyType) -> DecoyType:
    for candidate in DecoyType:
        if candidate is not kind:
            return candidate
    raise AssertionError(kind)
