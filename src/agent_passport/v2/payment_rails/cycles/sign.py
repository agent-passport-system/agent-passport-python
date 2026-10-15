# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Signing for Cycles permit receipts, release receipts and denials.

Python port of ``signCyclesPermitReceipt``, ``signCyclesReleaseReceipt`` and
``signCyclesDenial`` from the TypeScript SDK's
src/v2/payment-rails/cycles/index.ts.

The canonical bytes are RFC 8785 JCS over the receipt with ``signature``
absent, written through the write-policy canonicalizer so an integer outside
the interoperable range is refused. ``receipt_id`` is a random UUID, not
content addressed. (The CyclesEvidence envelope a receipt binds to is content
addressed. The APS receipt carries its own identifier.)

An optional member whose value is ``None`` is left out of the receipt, as the
TypeScript functions leave out a member that is undefined.
"""

from __future__ import annotations

import copy
import uuid
from typing import Dict, Optional, cast

from ....canonical import canonicalize_jcs_for_write
from ....crypto import public_key_from_private, sign
from ...._time import now_rfc3339
from .types import (
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    CyclesDenial,
    CyclesPermitReceipt,
    CyclesReleaseReceipt,
    CyclesScopeOfClaim,
    SignCyclesDenialInput,
    SignCyclesPermitReceiptInput,
    SignCyclesReleaseReceiptInput,
)

# The three default scope strings below carry an em dash (U+2014) in the
# TypeScript SDK and in every published vector. It is written as an escape so
# the bytes match while the source file stays ASCII.
_DASH = "—"


def _signer_for(
    private_key_hex: str, agent_id: Optional[str], key_ref: Optional[str]
) -> str:
    """Either a DID URI, when both ``issuer_agent_id`` and ``issuer_key_ref``
    are supplied, or the raw hex public key derived from the private key."""
    if agent_id and key_ref:
        if not agent_id.startswith("did:"):
            raise ValueError(f"sign_cycles_*: issuer_agent_id must be a DID, got '{agent_id}'")
        if "#" in key_ref:
            raise ValueError("sign_cycles_*: issuer_key_ref must not contain '#'")
        return f"{agent_id}#{key_ref}"
    return public_key_from_private(private_key_hex)


def _default_permit_scope() -> CyclesScopeOfClaim:
    return {
        "asserts": (
            f"aps:cycles.permit:emit {_DASH} a budget reservation was authorized on the Cycles "
            "rail under the named delegation; reservation_id anchors the rail-side outcome and "
            "cycles_evidence binds to the signed CyclesEvidence envelope."
        ),
        "does_not_assert": [
            "the reservation was committed",
            "the action governed by the reservation completed",
            "live ledger state at any time after issuance",
        ],
        "capture_mode": "gateway_observed",
        "completeness": "complete",
        "self_attested": False,
    }


def _default_release_scope() -> CyclesScopeOfClaim:
    return {
        "asserts": (
            f"aps:cycles.release:emit {_DASH} a budget reservation was released without commit "
            "under the named delegation; reservation_id ties to the prior permit-receipt."
        ),
        "does_not_assert": [
            "the underlying action was cancelled (the reason field, when populated, is rail-reported)",
            "no separate commit occurred on a different reservation",
        ],
        "capture_mode": "gateway_observed",
        "completeness": "complete",
        "self_attested": False,
    }


def _default_denial_scope() -> CyclesScopeOfClaim:
    return {
        "asserts": (
            f"aps:cycles.deny:emit {_DASH} a Cycles budget-authority operation was refused with a "
            "closed-taxonomy Tier-1 denial reason; cycles.denial_detail preserves the canonical "
            "Cycles-side code Tier-2."
        ),
        "does_not_assert": [
            "the rail itself is unavailable",
            "the agent acted maliciously",
            "the underlying delegation is invalid (denial may flag a single missing constraint)",
        ],
        "capture_mode": "gateway_observed",
        "completeness": "complete",
        "self_attested": False,
    }


def _finish(unsigned: Dict[str, object], signer_private_key_hex: str) -> Dict[str, object]:
    signature = sign(canonicalize_jcs_for_write(unsigned), signer_private_key_hex)
    signed = dict(unsigned)
    signed["signature"] = signature
    return signed


def sign_cycles_permit_receipt(
    input: SignCyclesPermitReceiptInput, signer_private_key_hex: str
) -> CyclesPermitReceipt:
    """Sign a permit receipt, emitted when a Cycles reserve is allowed."""
    signer = _signer_for(
        signer_private_key_hex, input.get("issuer_agent_id"), input.get("issuer_key_ref")
    )
    issued_at = now_rfc3339()
    scope = input.get("scope_of_claim")
    unsigned: Dict[str, object] = {
        "claim_type": RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
        "receipt_id": f"cycles_permit_{uuid.uuid4()}",
        "signer": signer,
        "agent_id": input["agent_id"],
        "delegation_ref": input["delegation_ref"],
        "action_ref": input["action_ref"],
        "rail_name": "cycles",
        "reservation_id": input["reservation_id"],
        "reserved": copy.deepcopy(input["reserved"]),
        "decision": input["decision"],
        "cycles_evidence": copy.deepcopy(input["cycles_evidence"]),
        "issued_at": issued_at,
        "timestamp": issued_at,
        "scope_of_claim": copy.deepcopy(scope) if scope is not None else _default_permit_scope(),
    }
    expires_at_ms = input.get("expires_at_ms")
    if expires_at_ms is not None:
        unsigned["expires_at_ms"] = expires_at_ms
    admission = input.get("authority_state_at_admission")
    if admission is not None:
        unsigned["authority_state_at_admission"] = copy.deepcopy(admission)
    trust_policy_ref = input.get("trust_policy_ref")
    if trust_policy_ref is not None:
        unsigned["trust_policy_ref"] = trust_policy_ref
    return cast(CyclesPermitReceipt, _finish(unsigned, signer_private_key_hex))


def sign_cycles_release_receipt(
    input: SignCyclesReleaseReceiptInput, signer_private_key_hex: str
) -> CyclesReleaseReceipt:
    """Sign a release receipt, emitted when a Cycles reservation is released."""
    signer = _signer_for(
        signer_private_key_hex, input.get("issuer_agent_id"), input.get("issuer_key_ref")
    )
    issued_at = now_rfc3339()
    scope = input.get("scope_of_claim")
    unsigned: Dict[str, object] = {
        "claim_type": RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
        "receipt_id": f"cycles_release_{uuid.uuid4()}",
        "signer": signer,
        "agent_id": input["agent_id"],
        "delegation_ref": input["delegation_ref"],
        "action_ref": input["action_ref"],
        "rail_name": "cycles",
        "reservation_id": input["reservation_id"],
        "released": copy.deepcopy(input["released"]),
        "cycles_evidence": copy.deepcopy(input["cycles_evidence"]),
        "issued_at": issued_at,
        "timestamp": issued_at,
        "scope_of_claim": copy.deepcopy(scope) if scope is not None else _default_release_scope(),
    }
    reason = input.get("reason")
    if reason is not None:
        unsigned["reason"] = reason
    return cast(CyclesReleaseReceipt, _finish(unsigned, signer_private_key_hex))


def sign_cycles_denial(input: SignCyclesDenialInput, signer_private_key_hex: str) -> CyclesDenial:
    """Sign a denial, emitted on a live 4xx, a decide DENY or a dry run DENY."""
    signer = _signer_for(
        signer_private_key_hex, input.get("issuer_agent_id"), input.get("issuer_key_ref")
    )
    issued_at = now_rfc3339()
    scope = input.get("scope_of_claim")
    unsigned: Dict[str, object] = {
        "claim_type": RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
        "receipt_id": f"cycles_denial_{uuid.uuid4()}",
        "signer": signer,
        "agent_id": input["agent_id"],
        "delegation_ref": input["delegation_ref"],
        "action_ref": input["action_ref"],
        "rail_name": "cycles",
        "denial_reason": input["denial_reason"],
        "cycles": copy.deepcopy(input["cycles"]),
        "cycles_evidence": copy.deepcopy(input["cycles_evidence"]),
        "issued_at": issued_at,
        "timestamp": issued_at,
        "scope_of_claim": copy.deepcopy(scope) if scope is not None else _default_denial_scope(),
    }
    return cast(CyclesDenial, _finish(unsigned, signer_private_key_hex))
