# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Types for the Cycles budget-authority rail (offline path).

Python port of the TypeScript SDK's src/v2/payment-rails/cycles/types.ts at
agent-passport-system 8.0.0. Receipts, denials and envelopes are plain JSON
objects, so they are typed here as ``TypedDict`` shapes over ``dict``. The
shapes document what the signing functions produce. The verifiers accept any
mapping, because their input is untrusted and is checked rather than assumed.

Cycles (https://runcycles.io) is a pre-execution budget and action authority
protocol with a reserve, commit and release lifecycle. APS signs a permit
receipt at reserve, a release receipt at release and a denial on refusal. Each
carries a ``cycles_evidence`` reference that binds it by content hash to the
signed CyclesEvidence envelope on the Cycles side.
"""

from __future__ import annotations

from typing import List, Literal, Mapping, Optional, TypedDict, Union

from ...accountability.types import CaptureMode, Completeness

#: Cycles protocol pin. Bump when the upstream protocol revision changes.
CYCLES_PROTOCOL_VERSION = "cycles-protocol-v0.1.25"

#: CyclesEvidence schema version this adapter consumes.
CYCLES_EVIDENCE_SCHEMA_VERSION = "cycles-evidence/v0.1"

RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE = "rail.budget_reservation.permit.v1"
RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE = "rail.budget_reservation.release.v1"
RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE = "rail.budget_reservation.denial.v1"


# ── Evidence reference and scope of claim ────────────────────────────────


class _CyclesEvidenceRefRequired(TypedDict):
    #: Where to fetch the signed CyclesEvidence envelope. Opaque to APS.
    cycles_evidence_url: str
    #: sha256 hex of the JCS canonical envelope bytes with both ``evidence_id``
    #: and ``signature`` emptied.
    cycles_evidence_id_sha256: str
    #: APS side action anchor.
    action_ref: str
    #: APS side delegation anchor.
    delegation_ref: str


class CyclesEvidenceRef(_CyclesEvidenceRefRequired, total=False):
    """The join between an APS receipt and a Cycles evidence envelope."""

    #: For commit and release receipts, the prior permit receipt's id.
    prior_permit_receipt_id: str


class CyclesScopeOfClaim(TypedDict):
    """The honest scope declaration every Cycles receipt carries."""

    asserts: str
    does_not_assert: List[str]
    capture_mode: CaptureMode
    completeness: Completeness
    self_attested: bool


class _AuthorityStateSnapshotRequired(TypedDict):
    #: Admission time ISO 8601, when APS evaluated this authority state.
    checked_at: str
    #: Revocation state APS saw at admission.
    delegation_revoked: bool
    #: Origin of the snapshot. Fixed for the APS admission path.
    source: Literal["aps_admission"]


class AuthorityStateSnapshot(_AuthorityStateSnapshotRequired, total=False):
    """Delegation authority state APS saw at admission, before calling Cycles."""

    #: Delegation expiry APS saw at admission, when known.
    delegation_expires_at: str


class CyclesAmount(TypedDict):
    """An amount in canonical (unit, amount) form."""

    unit: str
    amount: float


# ── Evidence view used by the denial mapper ──────────────────────────────

CyclesDecision = Literal["ALLOW", "ALLOW_WITH_CAPS", "DENY"]
CyclesArtifactType = Literal["decide", "reserve", "commit", "release", "error"]

#: A read-only view of a CyclesEvidence envelope. ``mapping`` of ``object``
#: values because only a few fields are read and the rest is not modelled. The
#: expected shape is ``{"artifact_type": ..., "trace_id": ..., "payload": {...}}``.
CyclesEvidenceView = Mapping[str, object]

#: A CyclesEvidence envelope as supplied to a verifier. APS treats it as opaque
#: beyond ``evidence_id``, ``signature``, ``signer_did`` and the fields the
#: correspondence check reads, and hashes every field, so each field the Cycles
#: server emitted must survive the round trip.
CyclesEvidenceEnvelopeInput = Mapping[str, object]


# ── Denial ───────────────────────────────────────────────────────────────

CyclesDenialSource = Literal["ErrorCode", "DecisionReasonCode"]


class _CyclesDenialDetailRequired(TypedDict):
    layer: Literal["cycles"]
    #: Which Cycles axis surfaced the denial.
    source: CyclesDenialSource
    #: The canonical Cycles code, preserved byte for byte.
    code: str
    #: W3C Trace Context trace-id, or None. Always present (explicit null keeps
    #: the shipped preimage bytes).
    trace_id: Optional[str]


class CyclesDenialDetail(_CyclesDenialDetailRequired, total=False):
    """Cycles specific denial detail, Tier-2 in the APS denial."""

    #: HTTP status on the wire (only when source is ErrorCode).
    http_status: int
    #: Server message (only when source is ErrorCode).
    message: str
    #: Request correlation id (only when source is ErrorCode).
    request_id: str


class CyclesDenialPayload(TypedDict):
    """The ``cycles`` member of a denial."""

    denial_detail: CyclesDenialDetail


class CyclesDenialMapping(TypedDict):
    """Result of :func:`map_cycles_denial_to_foundation`."""

    denial_reason: str
    cycles: CyclesDenialPayload


# ── Receipts ─────────────────────────────────────────────────────────────


class _CyclesReceiptCommon(TypedDict):
    receipt_id: str
    signer: str
    agent_id: str
    delegation_ref: str
    action_ref: str
    rail_name: Literal["cycles"]
    cycles_evidence: CyclesEvidenceRef
    issued_at: str
    #: Hex Ed25519 signature over the canonical receipt body, signature cleared.
    signature: str
    timestamp: str
    scope_of_claim: CyclesScopeOfClaim


class _CyclesPermitReceiptRequired(_CyclesReceiptCommon):
    claim_type: Literal["rail.budget_reservation.permit.v1"]
    reservation_id: str
    reserved: CyclesAmount
    #: ALLOW or ALLOW_WITH_CAPS. A DENY rides a denial.
    decision: Literal["ALLOW", "ALLOW_WITH_CAPS"]


class CyclesPermitReceipt(_CyclesPermitReceiptRequired, total=False):
    """Signed receipt emitted at reserve allow."""

    #: Reservation TTL deadline (Cycles ``expires_at_ms``).
    expires_at_ms: int
    authority_state_at_admission: AuthorityStateSnapshot
    #: ``policy_id@policy_version``. A reference, not an assurance.
    trust_policy_ref: str


class _CyclesReleaseReceiptRequired(_CyclesReceiptCommon):
    claim_type: Literal["rail.budget_reservation.release.v1"]
    reservation_id: str
    released: CyclesAmount


class CyclesReleaseReceipt(_CyclesReleaseReceiptRequired, total=False):
    """Signed receipt emitted at release."""

    #: Optional reason from the release request body.
    reason: str


class CyclesDenial(_CyclesReceiptCommon):
    """Signed denial, emitted on a live 4xx, a decide DENY or a dry run DENY."""

    claim_type: Literal["rail.budget_reservation.denial.v1"]
    #: APS Tier-1 reason from the closed denial vocabulary.
    denial_reason: str
    cycles: CyclesDenialPayload


# ── Sign inputs ──────────────────────────────────────────────────────────


class _SignInputCommon(TypedDict):
    agent_id: str
    delegation_ref: str
    action_ref: str
    cycles_evidence: CyclesEvidenceRef


class _SignInputOptional(TypedDict, total=False):
    #: Overrides the default scope_of_claim.
    scope_of_claim: CyclesScopeOfClaim
    #: With ``issuer_key_ref``, the signer becomes ``<issuer_agent_id>#<issuer_key_ref>``.
    #: Otherwise it is the raw hex public key derived from the private key.
    issuer_agent_id: str
    issuer_key_ref: str


class _SignPermitRequired(_SignInputCommon):
    reservation_id: str
    reserved: CyclesAmount
    decision: Literal["ALLOW", "ALLOW_WITH_CAPS"]


class SignCyclesPermitReceiptInput(_SignPermitRequired, _SignInputOptional, total=False):
    expires_at_ms: int
    authority_state_at_admission: AuthorityStateSnapshot
    trust_policy_ref: str


class _SignReleaseRequired(_SignInputCommon):
    reservation_id: str
    released: CyclesAmount


class SignCyclesReleaseReceiptInput(_SignReleaseRequired, _SignInputOptional, total=False):
    reason: str


class _SignDenialRequired(_SignInputCommon):
    denial_reason: str
    cycles: CyclesDenialPayload


class SignCyclesDenialInput(_SignDenialRequired, _SignInputOptional, total=False):
    pass


# ── Verification results ─────────────────────────────────────────────────

#: The reasons an offline verify can return. The TypeScript SDK also returns
#: the five DID_* reasons from its async DID path, which this port does not
#: have.
CyclesVerifyReason = Literal[
    "INVALID_CLAIM_TYPE",
    "INVALID_SCHEMA_VERSION",
    "INVALID_RAIL_NAME",
    "MISSING_REQUIRED_FIELD",
    "SIGNATURE_INVALID",
    "EXPIRED",
    "EVIDENCE_REF_HASH_MISMATCH",
    "EVIDENCE_SIGNATURE_INVALID",
    "EVIDENCE_CORRESPONDENCE_FIELD_MISSING",
    "EVIDENCE_CORRESPONDENCE_MISMATCH",
    "DID_RESOLVER_MISSING",
]

#: Which envelope authenticity guarantee a passing verify checked.
#:
#: ``signature_valid``: the envelope's own Ed25519 signature verifies against
#: the key named in its ``signer_did``. That proves the bytes were signed by
#: that key. It does not prove the key is the legitimate Cycles signer.
#:
#: ``pinned_issuer``: ``signature_valid`` and the caller pinned the receipt
#: issuer with ``expected_signer``. The pin is on the APS receipt signer, not
#: on the envelope's ``signer_did``, so envelope authenticity holds only to the
#: extent the pinned issuer is trusted to bind receipts to legitimate envelopes.
EvidenceAuthenticity = Literal["signature_valid", "pinned_issuer"]


class _CyclesVerifyOk(TypedDict):
    valid: Literal[True]


class CyclesVerifyValid(_CyclesVerifyOk, total=False):
    #: Present only on a pass that carried an envelope.
    evidence_authenticity: EvidenceAuthenticity


class _CyclesVerifyFailedRequired(TypedDict):
    valid: Literal[False]
    reason: CyclesVerifyReason


class CyclesVerifyFailed(_CyclesVerifyFailedRequired, total=False):
    detail: str


CyclesVerifyResult = Union[CyclesVerifyValid, CyclesVerifyFailed]


class CyclesCorrespondenceMatched(TypedDict):
    status: Literal["matched"]
    stage: Literal["reserve", "release"]
    reservation_id: str
    not_compared: List[str]


class CyclesCorrespondenceFieldMissing(TypedDict):
    status: Literal["field_missing"]
    field: str
    detail: str


class CyclesCorrespondenceMismatch(TypedDict):
    status: Literal["mismatch"]
    field: str
    detail: str


#: Receipt to envelope correspondence (8.0.0). ``matched`` means stage and
#: reservation_id agree and nothing more. Amount, unit, action and server
#: identity are not compared. ``field_missing`` and ``mismatch`` are failures.
CyclesEvidenceCorrespondence = Union[
    CyclesCorrespondenceMatched,
    CyclesCorrespondenceFieldMissing,
    CyclesCorrespondenceMismatch,
]
