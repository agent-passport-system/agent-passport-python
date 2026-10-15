# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cross-language parity for the Cycles receipt to envelope correspondence rule.

The vector file is the TypeScript SDK's own, vendored byte for byte (see
cycles-correspondence-vectors.PROVENANCE.md, source commit ababe0f of
agent-passport-system). Every case is run through the matching Python verifier
and compared with what the TypeScript implementation recorded. A behaviour
difference between the two SDKs fails this test. No Node runs and nothing calls
into the TypeScript SDK.

Because the vectors' keys come from published, test-only seeds and Ed25519 is
deterministic, the test also re-signs each receipt body and each re-signed
envelope in Python and requires the signature to equal the recorded one. That
proves signing and canonical bytes match, not only verification.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private, sign
from agent_passport.v2.payment_rails.cycles import (
    verify_cycles_denial,
    verify_cycles_permit_receipt,
    verify_cycles_release_receipt,
)

HERE = Path(__file__).resolve().parent
VECTOR_PATH = HERE / "cycles-correspondence-vectors.json"

# Pinned in cycles-correspondence-vectors.PROVENANCE.md.
VECTOR_SHA256 = "38b732b990dd11d0f016a94fa2d865f685c34005e72b70ea35d5140534b2aa31"

RAW = VECTOR_PATH.read_bytes()
VECTORS = json.loads(RAW.decode("utf-8"))
CASES = VECTORS["cases"]

VERIFIERS = {
    "permit": verify_cycles_permit_receipt,
    "release": verify_cycles_release_receipt,
    "denial": verify_cycles_denial,
}

# The seeds are published in the TypeScript generator and protect nothing.
RECEIPT_KEY = hashlib.sha256(
    b"aps cycles correspondence vectors v0: receipt issuer (test only)"
).hexdigest()
CYCLES_KEY = hashlib.sha256(
    b"aps cycles correspondence vectors v0: re-signed envelope (test only)"
).hexdigest()


def _now_for(case: dict) -> datetime:
    """The receipts were issued when the vectors were generated, so the default
    24 hour TTL would expire them. Verify one minute after issuance."""
    issued = case["receipt"]["issued_at"]
    return datetime.fromisoformat(issued.replace("Z", "+00:00")) + timedelta(minutes=1)


def test_vendored_vector_file_matches_its_recorded_digest() -> None:
    assert hashlib.sha256(RAW).hexdigest() == VECTOR_SHA256


def test_vector_file_declares_the_expected_issuer_keys() -> None:
    assert public_key_from_private(RECEIPT_KEY) == VECTORS["receipt_issuer_public_key"]
    assert public_key_from_private(CYCLES_KEY) == VECTORS["resigned_envelope_signer"]


def test_there_are_thirteen_cases_and_the_negatives_are_counted() -> None:
    assert len(CASES) == 13
    correspondence = [
        c
        for c in CASES
        if not c["expected"]["valid"] and c["expected"]["reason"].startswith("EVIDENCE_CORRESPONDENCE_")
    ]
    assert len(correspondence) == 9


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case: dict) -> None:
    verify = VERIFIERS[case["verifier"]]
    expected = case["expected"]
    result = verify(case["receipt"], evidence=case["envelope"], now=_now_for(case))
    if expected["valid"]:
        assert result == {"valid": True, "evidence_authenticity": expected["evidence_authenticity"]}
        assert result == expected
    else:
        assert result["valid"] is False
        assert result["reason"] == expected["reason"]
        if "detail_prefix" in expected:
            assert result["detail"].startswith(expected["detail_prefix"]), result["detail"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_receipt_signature_is_reproduced_byte_for_byte(case: dict) -> None:
    body = {k: v for k, v in case["receipt"].items() if k != "signature"}
    assert sign(canonicalize_jcs(body), RECEIPT_KEY) == case["receipt"]["signature"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_envelope_hash_is_reproduced_byte_for_byte(case: dict) -> None:
    env = case["envelope"]
    recomputed = hashlib.sha256(
        canonicalize_jcs({**env, "evidence_id": "", "signature": ""}).encode("utf-8")
    ).hexdigest()
    if env["signer_did"] == VECTORS["resigned_envelope_signer"] and env.get("evidence_id") == recomputed:
        # A re-signed envelope: Python reproduces its signature too.
        assert sign(canonicalize_jcs({**env, "signature": ""}), CYCLES_KEY) == env["signature"]
    if case["id"] != "hash-check-runs-first":
        assert recomputed == env["evidence_id"]


def test_every_receipt_verifies_without_its_envelope() -> None:
    """Signature only. Pins that dropping the envelope drops only the envelope
    checks, as in the TypeScript SDK."""
    for case in CASES:
        result = VERIFIERS[case["verifier"]](case["receipt"], now=_now_for(case))
        assert result == {"valid": True}, case["id"]
