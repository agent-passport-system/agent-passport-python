# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cycles budget-authority rail, offline path.

Python port of the TypeScript SDK's src/v2/payment-rails/cycles at
agent-passport-system 8.0.0. Cycles (https://runcycles.io) is an external
budget authority protocol with a reserve, commit and release lifecycle. APS
signs a permit receipt at reserve, a release receipt at release and a denial on
refusal, each bound by content hash to a signed Cycles evidence envelope.

In this package:

* the three receipt types and the evidence reference and envelope shapes
* :func:`map_cycles_denial_to_foundation` and its two constant tables
* sign and verify for permit, release and denial, synchronous
* verification options for a supplied envelope and a pinned issuer, including
  the 8.0.0 receipt to envelope correspondence check

Not in this package: the async ``*WithDID`` variants, the ``*WithEvidence``
fetch and resolver path, did:cycles and JWKS key resolution, and
``verifyCyclesEvidenceSignerAuthority``. The shared cross-language vectors are
tests/cross_impl/cycles-correspondence-vectors.json.
"""

from .denial import (
    DECISION_REASON_TO_TIER1,
    ERROR_CODE_TO_TIER1,
    map_cycles_denial_to_foundation,
)
from .sign import (
    sign_cycles_denial,
    sign_cycles_permit_receipt,
    sign_cycles_release_receipt,
)
from .types import (
    CYCLES_EVIDENCE_SCHEMA_VERSION,
    CYCLES_PROTOCOL_VERSION,
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    AuthorityStateSnapshot,
    CyclesAmount,
    CyclesDenial,
    CyclesDenialDetail,
    CyclesDenialMapping,
    CyclesEvidenceCorrespondence,
    CyclesEvidenceEnvelopeInput,
    CyclesEvidenceRef,
    CyclesEvidenceView,
    CyclesPermitReceipt,
    CyclesReleaseReceipt,
    CyclesScopeOfClaim,
    CyclesVerifyReason,
    CyclesVerifyResult,
    EvidenceAuthenticity,
    SignCyclesDenialInput,
    SignCyclesPermitReceiptInput,
    SignCyclesReleaseReceiptInput,
)
from .verify import (
    CORRESPONDENCE_NOT_COMPARED,
    verify_cycles_denial,
    verify_cycles_permit_receipt,
    verify_cycles_release_receipt,
)

__all__ = [
    "CORRESPONDENCE_NOT_COMPARED",
    "CYCLES_EVIDENCE_SCHEMA_VERSION",
    "CYCLES_PROTOCOL_VERSION",
    "DECISION_REASON_TO_TIER1",
    "ERROR_CODE_TO_TIER1",
    "RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE",
    "RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE",
    "RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE",
    "AuthorityStateSnapshot",
    "CyclesAmount",
    "CyclesDenial",
    "CyclesDenialDetail",
    "CyclesDenialMapping",
    "CyclesEvidenceCorrespondence",
    "CyclesEvidenceEnvelopeInput",
    "CyclesEvidenceRef",
    "CyclesEvidenceView",
    "CyclesPermitReceipt",
    "CyclesReleaseReceipt",
    "CyclesScopeOfClaim",
    "CyclesVerifyReason",
    "CyclesVerifyResult",
    "EvidenceAuthenticity",
    "SignCyclesDenialInput",
    "SignCyclesPermitReceiptInput",
    "SignCyclesReleaseReceiptInput",
    "map_cycles_denial_to_foundation",
    "sign_cycles_denial",
    "sign_cycles_permit_receipt",
    "sign_cycles_release_receipt",
    "verify_cycles_denial",
    "verify_cycles_permit_receipt",
    "verify_cycles_release_receipt",
]
