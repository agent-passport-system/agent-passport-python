# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""verify_delegation on a signed legacy record with no maxDepth member.

docs/SPEC-v1.1.md section 4.1 says an absent max_depth has no ceiling on verification,
and the TypeScript verifyDelegation applies none. This verifier used to read absence as
0. The vendored TypeScript case delegation-without-max-depth-at-depth-64 and the locally
minted record at currentDepth 3 fail before the change. Explicit limits behave as before.
A present maxDepth that is not a non-negative integer is invalid (#223).
"""
import json
from pathlib import Path

from agent_passport import create_delegation, generate_key_pair, sign, canonicalize, verify_delegation

VECTORS = Path(__file__).parent / "cross_impl" / "action-receipt-v1.1-vectors.json"


def _ts_case(name: str) -> dict:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    return next(c for c in data["delegation_cases"] if c["name"] == name)


def _signed(changes: dict, drop: tuple = ()) -> dict:
    """A fresh delegation with the given members changed or removed, signed again by its issuer."""
    h, a = generate_key_pair(), generate_key_pair()
    d = create_delegation(
        delegated_by=h["publicKey"], delegated_to=a["publicKey"], scope=["data:read"],
        private_key=h["privateKey"], max_depth=1,
    )
    d = {k: v for k, v in d.items() if k != "signature" and k not in drop}
    d.update(changes)
    d["signature"] = sign(canonicalize(d), h["privateKey"])
    return d


def test_vendored_ts_record_without_max_depth_at_depth_64_verifies():
    case = _ts_case("delegation-without-max-depth-at-depth-64")
    assert "maxDepth" not in case["record"]
    assert case["verification"]["valid"] is True
    status = verify_delegation(case["record"])
    assert status["depthExceeded"] is False
    assert status["valid"] is True, status["errors"]


def test_absent_max_depth_at_depth_3_has_no_ceiling():
    status = verify_delegation(_signed({"currentDepth": 3}, drop=("maxDepth",)))
    assert status["depthExceeded"] is False
    assert status["valid"] is True, status["errors"]


def test_absent_max_depth_at_root_verifies():
    status = verify_delegation(_signed({"currentDepth": 0}, drop=("maxDepth",)))
    assert status["valid"] is True, status["errors"]


def test_explicit_limits_unchanged():
    assert verify_delegation(_signed({"maxDepth": 0, "currentDepth": 0}))["valid"] is True
    assert verify_delegation(_signed({"maxDepth": 1, "currentDepth": 1}))["valid"] is True
    over = verify_delegation(_signed({"maxDepth": 1, "currentDepth": 2}))
    assert over["depthExceeded"] is True and over["valid"] is False
    zero = verify_delegation(_signed({"maxDepth": 0, "currentDepth": 1}))
    assert zero["depthExceeded"] is True and zero["valid"] is False


def test_present_malformed_max_depth_is_invalid():
    # #223: a present maxDepth that is not a non-negative integer used to be skipped, so the
    # record verified at any depth. It is now invalid, at depth 0 as well as above, and no depth
    # result is claimed for it.
    for value in ("1", "0", True, False, 1.5, -1, 2**53, [1], {"n": 1}):
        for depth in (0, 2):
            status = verify_delegation(_signed({"maxDepth": value, "currentDepth": depth}))
            assert status["valid"] is False, (repr(value), depth)
            assert status["depthExceeded"] is False, (repr(value), depth)
            assert any(e.startswith("Malformed maxDepth") for e in status["errors"]), (repr(value), depth)


def test_integer_valued_float_max_depth_is_compared():
    assert verify_delegation(_signed({"maxDepth": 2.0, "currentDepth": 2}))["valid"] is True
    over = verify_delegation(_signed({"maxDepth": 1.0, "currentDepth": 2}))
    assert over["depthExceeded"] is True and over["valid"] is False


def test_null_max_depth_is_still_absent():
    status = verify_delegation(_signed({"maxDepth": None, "currentDepth": 3}))
    assert status["valid"] is True, status["errors"]
    assert status["depthExceeded"] is False


def test_present_malformed_current_depth_is_invalid():
    # Same comparison, same split: TypeScript coerced "5" to 5 and this verifier skipped it.
    for value in ("5", "0", True, 0.5, -1, 2**53, [1]):
        for max_depth in (1, None):
            status = verify_delegation(_signed({"maxDepth": max_depth, "currentDepth": value}))
            label = (repr(value), max_depth)
            assert status["valid"] is False, label
            assert status["depthExceeded"] is False, label
            assert any(e.startswith("Malformed currentDepth") for e in status["errors"]), label


def test_absent_or_null_current_depth_is_not_compared():
    for record in (_signed({"maxDepth": 0}, drop=("currentDepth",)),
                   _signed({"maxDepth": 0, "currentDepth": None})):
        status = verify_delegation(record)
        assert status["valid"] is True, status["errors"]
        assert status["depthExceeded"] is False


# ── Minting a child is a separate question from verifying a record ──

import pytest  # noqa: E402

from agent_passport import sub_delegate  # noqa: E402


def _parent_and_delegate(changes: dict, drop: tuple = ()):
    h, a = generate_key_pair(), generate_key_pair()
    d = create_delegation(
        delegated_by=h["publicKey"], delegated_to=a["publicKey"], scope=["data:read"],
        private_key=h["privateKey"], spend_limit=10, max_depth=2,
    )
    d = {k: v for k, v in d.items() if k != "signature" and k not in drop}
    d.update(changes)
    d["signature"] = sign(canonicalize(d), h["privateKey"])
    return d, a


def test_sub_delegate_refuses_a_parent_without_max_depth():
    parent, a = _parent_and_delegate({}, drop=("maxDepth",))
    assert verify_delegation(parent)["valid"] is True
    with pytest.raises(ValueError, match="integer maxDepth"):
        sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                     scope=["data:read"], private_key=a["privateKey"])


def test_sub_delegate_refuses_a_non_integer_or_negative_parent_max_depth():
    # sub_delegate verifies the parent first, so -1 at currentDepth 0 is refused there.
    # inf and NaN cannot be canonicalized, so no signed parent can carry them.
    for value in (None, "2", True, False, 1.5, -1, 2**53):
        parent, a = _parent_and_delegate({"maxDepth": value})
        with pytest.raises(ValueError, match="integer maxDepth|invalid parent"):
            sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])


def test_sub_delegate_with_explicit_max_depth_unchanged():
    parent, a = _parent_and_delegate({})
    child = sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])
    assert child["maxDepth"] == 2 and child["currentDepth"] == 1


def test_max_depth_null_and_absent_are_one_signed_form():
    absent = _signed({"currentDepth": 2}, drop=("maxDepth",))
    with_null = dict(absent)
    with_null["maxDepth"] = None
    assert canonicalize({k: v for k, v in with_null.items() if k != "signature"}) == \
        canonicalize({k: v for k, v in absent.items() if k != "signature"})
    a, b = verify_delegation(absent), verify_delegation(with_null)
    assert a["valid"] is True, a["errors"]
    assert (b["valid"], b["depthExceeded"]) == (a["valid"], a["depthExceeded"])


def test_sub_delegate_accepts_integer_valued_floats_like_typescript():
    # 2.0 and 0.0 canonicalize to the same signed bytes as 2 and 0.
    parent, a = _parent_and_delegate({"maxDepth": 2.0, "currentDepth": 0.0})
    ints, _ = _parent_and_delegate({"maxDepth": 2, "currentDepth": 0})
    strip = lambda d: {k: v for k, v in d.items() if k not in ("signature", "delegationId", "delegatedTo", "delegatedBy", "createdAt", "expiresAt")}
    assert canonicalize(strip(parent)) == canonicalize(strip(ints))
    assert verify_delegation(parent)["valid"] is True
    child = sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])
    assert child["currentDepth"] == 1


def test_sub_delegate_refuses_a_non_integer_parent_current_depth():
    for value in (0.5, True, -1):
        parent, a = _parent_and_delegate({"currentDepth": value})
        with pytest.raises(ValueError, match="integer currentDepth|invalid parent"):
            sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])


# ── Writer side of #223: create_delegation refuses a depth its own verifier reports malformed ──

def test_create_delegation_refuses_a_malformed_max_depth():
    h, a = generate_key_pair(), generate_key_pair()
    for value in (1.5, -1, 2**53, float("nan"), float("inf"), "1", True):
        with pytest.raises(ValueError, match="max_depth must be a non-negative integer"):
            create_delegation(delegated_by=h["publicKey"], delegated_to=a["publicKey"],
                              scope=["data:read"], private_key=h["privateKey"], max_depth=value)


def test_create_delegation_signs_the_boundary_values_and_they_verify():
    h, a = generate_key_pair(), generate_key_pair()
    # None is unchanged: it signs as no maxDepth member, which verifies with no ceiling.
    for value in (0, 1, 2.0, 2**53 - 1, None):
        d = create_delegation(delegated_by=h["publicKey"], delegated_to=a["publicKey"],
                              scope=["data:read"], private_key=h["privateKey"], max_depth=value)
        assert verify_delegation(d)["valid"] is True, value
