"""Legacy Action Receipt v1.1: a receipt written by this SDK must verify in the TypeScript SDK.

The portable tests compare against the TypeScript SDK's frozen vectors vendored in
tests/cross_impl and run everywhere. The live tests call the TypeScript verifier from a
sibling checkout and skip when it is absent, as in CI.

create_action_receipt used to write version "1.0.0". The TypeScript verifyReceipt accepts only
"1.1", so every receipt this SDK produced failed there on the version alone. Receipts already
signed with "1.0.0" keep verifying here, because verify_action_receipt checks only the signature.
"""

import hashlib
import json
import os
import subprocess

import pytest

from agent_passport import create_delegation, create_action_receipt, generate_key_pair
from agent_passport.delegation import verify_action_receipt
from agent_passport.crypto import sign
from agent_passport.canonical import canonicalize_for_write

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
TS_SDK_ROOT = os.path.normpath(os.path.join(_REPO_ROOT, "..", "agent-passport-system"))
VERIFIER = os.path.join(os.path.dirname(__file__), "_cross_language_action_receipt_verify.mjs")
SIBLING_SKIP_REASON = (
    "needs the agent-passport-system TS SDK as a sibling checkout "
    "(../agent-passport-system) with tsx installed (run npm install there)"
)


def _receipt():
    principal = generate_key_pair()
    agent = generate_key_pair()
    delegation = create_delegation(
        delegated_by=principal["publicKey"],
        delegated_to=agent["publicKey"],
        scope=["data:read"],
        private_key=principal["privateKey"],
        spend_limit=100,
    )
    receipt = create_action_receipt(
        agent_id=agent["publicKey"],
        delegation=delegation,
        action_type="api_call",
        target="db.example",
        scope_used="data:read",
        result_status="success",
        result_summary="rows read",
        private_key=agent["privateKey"],
        delegation_chain=[principal["publicKey"], agent["publicKey"]],
    )
    return receipt, agent


def test_writer_emits_version_1_1():
    receipt, agent = _receipt()
    assert receipt["version"] == "1.1"
    assert verify_action_receipt(receipt, agent["publicKey"])["valid"]


def test_receipt_signed_with_version_1_0_0_still_verifies_here():
    receipt, agent = _receipt()
    old = {k: v for k, v in receipt.items() if k != "signature"}
    old["version"] = "1.0.0"
    old["signature"] = sign(canonicalize_for_write(old), agent["privateKey"])
    assert verify_action_receipt(old, agent["publicKey"])["valid"]


# Portable checks against the TypeScript SDK's frozen vectors, vendored in tests/cross_impl.
# They need no node and no sibling checkout, so they run in CI.
VECTORS = os.path.join(os.path.dirname(__file__), "cross_impl", "action-receipt-v1.1-vectors.json")
VECTORS_SHA256 = "2452c818e916f516d238c756fea913228a2a6e28696f86aae4b85776ee8938a3"


def _vectors():
    with open(VECTORS, "rb") as f:
        raw = f.read()
    assert hashlib.sha256(raw).hexdigest() == VECTORS_SHA256
    return json.loads(raw)


def _ts_case(vectors, name):
    return next(c for c in vectors["receipt_cases"] if c["name"] == name)


def test_vendored_ts_receipt_verifies_here():
    v = _vectors()
    case = _ts_case(v, "valid-receipt-under-root")
    key = next(k["public_key_hex"] for k in v["keys"] if k["label"] == case["verify_with_key"])
    assert verify_action_receipt(case["record"], key)["valid"]


def test_writer_matches_what_the_ts_verifier_accepted():
    v = _vectors()
    accepted = _ts_case(v, "valid-receipt-under-root")
    refused = _ts_case(v, "receipt-version-1.0")
    # The TypeScript verifyReceipt accepted 1.1 and refused 1.0 on version alone.
    assert accepted["verification"] == {"valid": True, "errors": []}
    assert refused["verification"] == {"valid": False, "errors": ["Unsupported receipt version"]}
    receipt, _ = _receipt()
    assert receipt["version"] == accepted["record"]["version"]
    assert set(receipt) == set(accepted["record"])


def _ts_verify(receipt, public_key):
    tsx = os.path.join(TS_SDK_ROOT, "node_modules", ".bin", "tsx")
    if not os.path.isfile(tsx):
        pytest.skip(SIBLING_SKIP_REASON)
    try:
        result = subprocess.run(
            [tsx, VERIFIER],
            input=json.dumps({"receipt": receipt, "publicKey": public_key}),
            capture_output=True, text=True, cwd=TS_SDK_ROOT, check=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"{SIBLING_SKIP_REASON}; tsx exited {e.returncode}: {(e.stderr or '')[:200]}")
    return json.loads(result.stdout)


def test_python_receipt_verifies_in_typescript():
    receipt, agent = _receipt()
    assert _ts_verify(receipt, agent["publicKey"]) == {"valid": True, "errors": []}


def test_typescript_still_rejects_a_1_0_0_receipt_on_version_only():
    receipt, agent = _receipt()
    old = {k: v for k, v in receipt.items() if k != "signature"}
    old["version"] = "1.0.0"
    old["signature"] = sign(canonicalize_for_write(old), agent["privateKey"])
    assert _ts_verify(old, agent["publicKey"]) == {"valid": False, "errors": ["Unsupported receipt version"]}
