# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""verify_delegation on a signed legacy record with no maxDepth member.

docs/SPEC-v1.1.md section 4.1 says an absent max_depth has no ceiling on verification,
and the TypeScript verifyDelegation applies none. This verifier used to read absence as
0. The vendored TypeScript case delegation-without-max-depth-at-depth-64 and the locally
minted record at currentDepth 3 fail before the change. Explicit limits, and present
values that are not numbers, behave as before.
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


def test_present_non_numeric_max_depth_behaves_as_before():
    # Not part of this change: a present maxDepth that is not a number is not compared, as it
    # was not before. Pinned so the absence rule does not silently move these cases.
    for value in (None, "1", True):
        status = verify_delegation(_signed({"maxDepth": value, "currentDepth": 3}))
        assert status["depthExceeded"] is False, repr(value)


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
    with pytest.raises(ValueError, match="numeric maxDepth"):
        sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                     scope=["data:read"], private_key=a["privateKey"])


def test_sub_delegate_refuses_a_non_numeric_parent_max_depth():
    for value in (None, "2", True):
        parent, a = _parent_and_delegate({"maxDepth": value})
        with pytest.raises(ValueError, match="numeric maxDepth"):
            sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])


def test_sub_delegate_with_explicit_max_depth_unchanged():
    parent, a = _parent_and_delegate({})
    child = sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["data:read"], private_key=a["privateKey"])
    assert child["maxDepth"] == 2 and child["currentDepth"] == 1
