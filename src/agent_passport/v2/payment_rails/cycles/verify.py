# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Offline verification of Cycles permit receipts, release receipts and denials.

Python port of ``verifyCyclesPermitReceipt``, ``verifyCyclesReleaseReceipt`` and
``verifyCyclesDenial`` from the TypeScript SDK's
src/v2/payment-rails/cycles/index.ts at agent-passport-system 8.0.0. The checks
run in the same order and return the same reasons.

Order of checks (each returns the first failure):

1. Capture of the receipt, then of the supplied envelope.
2. ``claim_type``, required fields, ``rail_name``, ``cycles_evidence`` shape.
3. When an envelope is supplied:

   a. hash binding. The envelope's content hash is recomputed per
      cycles-evidence-v0.1 (``evidence_id`` and ``signature`` set to the empty
      string, JCS canonicalized, sha256 hex) and must equal both the envelope's
      ``evidence_id`` and the receipt's ``cycles_evidence.cycles_evidence_id_sha256``
      (``EVIDENCE_REF_HASH_MISMATCH``).
   b. the envelope's own Ed25519 signature over the JCS bytes with ``signature``
      emptied and ``evidence_id`` populated (``EVIDENCE_SIGNATURE_INVALID``).
   c. correspondence, permit and release only: the envelope is the reserve
      event (permit) or release event (release) and names the receipt's own
      ``reservation_id`` (``EVIDENCE_CORRESPONDENCE_FIELD_MISSING``,
      ``EVIDENCE_CORRESPONDENCE_MISMATCH``). Amount, unit, action and server
      identity are not compared. Denials get no correspondence check.

4. ``expected_signer`` pin, ``issued_at``, TTL, ``timestamp == issued_at``,
   ``scope_of_claim.asserts``, then the receipt's own signature.

Fail closed. A receipt or envelope that is not a plain JSON object, that does
not canonicalize, or that is nested too deeply is a structured failure. No
input of that kind raises out of a verifier.

What a pass proves. ``valid`` with no envelope means the receipt's signature
verifies against ``signer`` and its shape is sound. With an envelope it also
means the envelope matches the receipt by hash, carries a signature that
verifies against its own ``signer_did`` key, and is the right stage for the
right reservation. It does NOT mean the ``signer_did`` key is the legitimate
Cycles signer, and ``evidence_authenticity`` says which guarantee held.

Not ported: the async DID variants, the fetch and resolver path, did:cycles
and JWKS key resolution, and signer authority resolution. A receipt whose
``signer`` is a DID URI returns ``DID_RESOLVER_MISSING``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Mapping, Optional, Tuple, Union

from ....canonical import canonicalize_jcs
from ....crypto import verify as _ed25519_verify
from ...._time import parse_rfc3339
from .types import (
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    CyclesCorrespondenceFieldMissing,
    CyclesCorrespondenceMatched,
    CyclesCorrespondenceMismatch,
    CyclesEvidenceCorrespondence,
    CyclesEvidenceEnvelopeInput,
    CyclesVerifyFailed,
    CyclesVerifyReason,
    CyclesVerifyResult,
    CyclesVerifyValid,
)

#: Fields deliberately outside the correspondence check. No equivalence rule is
#: defined for them yet (estimate vs reserved vs actual amounts, unit families,
#: action naming, server identity). Reported, never compared.
CORRESPONDENCE_NOT_COMPARED: Tuple[str, ...] = ("amount", "unit", "action", "server_id")

#: Default receipt TTL, as in the TypeScript SDK.
DEFAULT_TTL_SECONDS = 24 * 60 * 60

#: A receipt or envelope with more nesting or more values than this is refused
#: by capture. Real receipts and envelopes are a few levels deep and a few
#: hundred values. The bounds also stop a self-referencing container, and a
#: shared substructure that expands exponentially, from running without end.
MAX_CAPTURE_DEPTH = 200
MAX_CAPTURE_VALUES = 200_000

_HEX = re.compile(r"[0-9a-fA-F]+")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class _Missing:
    """Marks an absent key, so a detail can say ``undefined`` as the
    TypeScript detail does, apart from a present ``null``."""

    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


def _get(obj: Mapping[str, object], key: str) -> object:
    return obj[key] if key in obj else _MISSING


def _show(value: object) -> str:
    """Detail text for any value, close to JavaScript's ``String(value)``."""
    if value is _MISSING:
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        try:
            return canonicalize_jcs(value)
        except Exception:
            return "NaN"
    if isinstance(value, (list, tuple)):
        return ",".join("" if item is None else _show(item) for item in value)
    if isinstance(value, dict):
        return "[object Object]"
    return "unprintable"


def _truthy(value: object) -> bool:
    """JavaScript truthiness. An empty list or object is truthy there."""
    if value is None or value is _MISSING or value is False:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return not (value == 0 or (isinstance(value, float) and math.isnan(value)))
    if isinstance(value, str):
        return len(value) > 0
    return True


def _fail(reason: CyclesVerifyReason, detail: Optional[str] = None) -> CyclesVerifyFailed:
    result: CyclesVerifyFailed = {"valid": False, "reason": reason}
    if detail is not None:
        result["detail"] = detail
    return result


def _ed_verify(message: str, signature_hex: object, public_key_hex: object) -> bool:
    """Ed25519 verify that is False for anything but a 64 hex character key and
    a 128 hex character signature, as the TypeScript verify is. ``bytes.fromhex``
    alone would also accept embedded whitespace."""
    if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
        return False
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        return False
    if _HEX.fullmatch(public_key_hex) is None or _HEX.fullmatch(signature_hex) is None:
        return False
    try:
        return _ed25519_verify(message, signature_hex, public_key_hex)
    except Exception:
        return False


# ── Capture ──────────────────────────────────────────────────────────────


def _check_bounds(value: object) -> Optional[str]:
    """Walk a value without recursion and report if it is too deep or too large."""
    stack: List[Tuple[object, int]] = [(value, 0)]
    seen = 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > MAX_CAPTURE_VALUES:
            return f"more than {MAX_CAPTURE_VALUES} values"
        if isinstance(node, dict):
            if depth >= MAX_CAPTURE_DEPTH:
                return f"nesting deeper than {MAX_CAPTURE_DEPTH} levels"
            for child in node.values():
                stack.append((child, depth + 1))
        elif isinstance(node, (list, tuple)):
            if depth >= MAX_CAPTURE_DEPTH:
                return f"nesting deeper than {MAX_CAPTURE_DEPTH} levels"
            for child in node:
                stack.append((child, depth + 1))
    return None


def _capture(value: object) -> Tuple[Optional[Dict[str, object]], str]:
    """Capture an input as the data its canonical bytes encode.

    One JCS canonicalization, parsed back into plain dicts. Verification reads
    only the captured copy, so the hash, the signatures and the correspondence
    check all see the same fields, exactly those in the signed bytes. A value
    with no canonical JSON form (a datetime, a set, bytes, NaN, a non-string
    key, an unpaired surrogate), one nested past the bounds, or one that is not
    a JSON object is refused with a detail. Returns ``(captured, "")`` or
    ``(None, detail)``.
    """
    too_big = _check_bounds(value)
    if too_big is not None:
        return None, f"has no canonical JSON form ({too_big})"
    try:
        text = canonicalize_jcs(value)
    except Exception as err:
        return None, f"has no canonical JSON form ({err})"
    try:
        parsed = json.loads(text)
    except Exception as err:
        return None, f"has no capturable JSON form ({err})"
    if not isinstance(parsed, dict):
        return None, "is not a JSON object"
    return parsed, ""


# ── Correspondence ───────────────────────────────────────────────────────


def _stage_for(claim_type: str) -> Optional[str]:
    """The stage a receipt kind references. Taken from the verifier entry
    point, never from the input, so a changing ``claim_type`` cannot switch the
    check off."""
    if claim_type == RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE:
        return "reserve"
    if claim_type == RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE:
        return "release"
    return None


def _evaluate_correspondence(
    stage: str, receipt: Mapping[str, object], env: Mapping[str, object]
) -> CyclesEvidenceCorrespondence:
    """Receipt to envelope correspondence (8.0.0).

    A permit references the reserve event for its reservation. A release
    references the release event for its reservation. Checks, in order: the
    receipt's ``reservation_id``, the envelope's ``artifact_type``, agreement
    of the single payload variant with that ``artifact_type``, and the
    envelope's reservation_id at the stage path (reserve:
    ``payload.reserve.response.reservation_id``, release:
    ``payload.release.reservation_id``). A missing or malformed field is
    ``field_missing``, never a pass. Callers pass the stage from the verifier
    entry point and captured inputs only.
    """
    receipt_reservation = receipt.get("reservation_id")
    if not isinstance(receipt_reservation, str) or len(receipt_reservation) == 0:
        return CyclesCorrespondenceFieldMissing(
            status="field_missing",
            field="receipt.reservation_id",
            detail="absent or not a non-empty string",
        )
    artifact_type = env.get("artifact_type")
    if not isinstance(artifact_type, str) or len(artifact_type) == 0:
        return CyclesCorrespondenceFieldMissing(
            status="field_missing",
            field="artifact_type",
            detail="absent or not a non-empty string",
        )
    if artifact_type != stage:
        return CyclesCorrespondenceMismatch(
            status="mismatch",
            field="artifact_type",
            detail=f"receipt references a {stage} event, envelope is {artifact_type}",
        )
    payload = env.get("payload")
    if not isinstance(payload, dict):
        return CyclesCorrespondenceFieldMissing(
            status="field_missing", field="payload", detail="absent or not an object"
        )
    variants = list(payload.keys())
    if len(variants) == 0:
        return CyclesCorrespondenceFieldMissing(
            status="field_missing", field="payload", detail="no payload variant"
        )
    if len(variants) != 1 or variants[0] != stage:
        return CyclesCorrespondenceMismatch(
            status="mismatch",
            field="payload",
            detail=f"payload variant [{', '.join(variants)}] does not agree with artifact_type {stage}",
        )
    variant = payload[stage]
    if not isinstance(variant, dict):
        return CyclesCorrespondenceFieldMissing(
            status="field_missing", field=f"payload.{stage}", detail="absent or not an object"
        )
    holder = variant.get("response") if stage == "reserve" else variant
    path = (
        "payload.reserve.response.reservation_id"
        if stage == "reserve"
        else "payload.release.reservation_id"
    )
    env_reservation = holder.get("reservation_id") if isinstance(holder, dict) else None
    if not isinstance(env_reservation, str) or len(env_reservation) == 0:
        return CyclesCorrespondenceFieldMissing(
            status="field_missing", field=path, detail="absent or not a non-empty string"
        )
    if env_reservation != receipt_reservation:
        return CyclesCorrespondenceMismatch(
            status="mismatch",
            field="reservation_id",
            detail=f"receipt {receipt_reservation} != envelope {env_reservation}",
        )
    return CyclesCorrespondenceMatched(
        status="matched",
        stage="reserve" if stage == "reserve" else "release",
        reservation_id=receipt_reservation,
        not_compared=list(CORRESPONDENCE_NOT_COMPARED),
    )


# ── Join integrity ───────────────────────────────────────────────────────


def _check_evidence_join(
    receipt: Mapping[str, object], env: Mapping[str, object], stage: Optional[str]
) -> Optional[CyclesVerifyFailed]:
    """Bind the receipt to the Cycles side evidence it references.

    Returns a failure, or None when every check passes. Callers pass captured
    inputs only. See the module docstring for the three checks and their order.
    """
    # 1. Hash binding and self-consistency. Both evidence_id and signature are
    # set to the empty string (not removed) before hashing.
    recomputed = hashlib.sha256(
        canonicalize_jcs({**env, "evidence_id": "", "signature": ""}).encode("utf-8")
    ).hexdigest()
    evidence_id = _get(env, "evidence_id")
    if recomputed != evidence_id:
        return _fail(
            "EVIDENCE_REF_HASH_MISMATCH",
            f"envelope evidence_id {_show(evidence_id)} != recomputed {recomputed}",
        )
    cycles_evidence = receipt["cycles_evidence"]
    assert isinstance(cycles_evidence, dict)  # checked by the caller
    claimed = _get(cycles_evidence, "cycles_evidence_id_sha256")
    if recomputed != claimed:
        return _fail(
            "EVIDENCE_REF_HASH_MISMATCH",
            f"receipt cycles_evidence_id_sha256 {_show(claimed)} != envelope {recomputed}",
        )

    # 2. The envelope's own signature, over the envelope with `signature`
    # emptied and `evidence_id` left populated. Fails closed when either field
    # is absent. A did: method signer_did is not resolvable here.
    signer_did = env.get("signer_did")
    if not isinstance(signer_did, str) or len(signer_did) == 0:
        return _fail("EVIDENCE_SIGNATURE_INVALID", "envelope missing signer_did")
    signature = env.get("signature")
    if not isinstance(signature, str) or len(signature) == 0:
        return _fail("EVIDENCE_SIGNATURE_INVALID", "envelope missing signature")
    envelope_bytes = canonicalize_jcs({**env, "signature": ""})
    if not _ed_verify(envelope_bytes, signature, signer_did):
        return _fail(
            "EVIDENCE_SIGNATURE_INVALID",
            "envelope Ed25519 signature does not verify against signer_did",
        )

    # 3. Correspondence, permit and release only, after hash and signature so a
    # semantic failure is reported as such.
    if stage is None:
        return None
    correspondence = _evaluate_correspondence(stage, receipt, env)
    if correspondence["status"] == "field_missing":
        return _fail(
            "EVIDENCE_CORRESPONDENCE_FIELD_MISSING",
            f"{correspondence['field']}: {correspondence['detail']}",
        )
    if correspondence["status"] == "mismatch":
        return _fail(
            "EVIDENCE_CORRESPONDENCE_MISMATCH",
            f"{correspondence['field']}: {correspondence['detail']}",
        )
    return None


# ── Core verifier ────────────────────────────────────────────────────────


def _verify_core(
    obj: Dict[str, object],
    expected_claim_type: str,
    *,
    now_ms: int,
    ttl_seconds: float,
    expected_signer: Optional[str],
    env: Optional[Dict[str, object]],
) -> CyclesVerifyResult:
    claim_type = _get(obj, "claim_type")
    if claim_type != expected_claim_type:
        return _fail(
            "INVALID_CLAIM_TYPE", f"expected {expected_claim_type} got {_show(claim_type)}"
        )
    for key in ("receipt_id", "signer", "agent_id", "delegation_ref", "action_ref"):
        if not _truthy(obj.get(key)):
            return _fail("MISSING_REQUIRED_FIELD")
    rail_name = _get(obj, "rail_name")
    if rail_name != "cycles":
        return _fail("INVALID_RAIL_NAME", f"expected 'cycles' got {_show(rail_name)}")
    # cycles_evidence must be an object, so its fields are read from the signed
    # bytes and never found some other way.
    cycles_evidence = obj.get("cycles_evidence")
    if (
        not isinstance(cycles_evidence, dict)
        or not _truthy(cycles_evidence.get("cycles_evidence_url"))
        or not _truthy(cycles_evidence.get("cycles_evidence_id_sha256"))
    ):
        return _fail("MISSING_REQUIRED_FIELD", "cycles_evidence")

    # Join integrity runs before the signer pin and the receipt signature, so a
    # broken receipt to envelope join surfaces regardless of signer type.
    if env is not None:
        join_failure = _check_evidence_join(obj, env, _stage_for(expected_claim_type))
        if join_failure is not None:
            return join_failure

    if expected_signer and obj.get("signer") != expected_signer:
        return _fail("SIGNATURE_INVALID", "signer mismatch")

    issued = parse_rfc3339(obj.get("issued_at"))
    if issued.ms is None:
        return _fail("MISSING_REQUIRED_FIELD", "issued_at")
    if now_ms - issued.ms > ttl_seconds * 1000:
        return _fail("EXPIRED", f"older than ttl={_show(ttl_seconds)}s")

    # Accountability shape invariants. Cycles receipts always carry them.
    if obj.get("timestamp") != obj.get("issued_at"):
        return _fail("MISSING_REQUIRED_FIELD", "timestamp != issued_at")
    scope = obj.get("scope_of_claim")
    if (
        not isinstance(scope, dict)
        or not isinstance(scope.get("asserts"), str)
        or len(str(scope.get("asserts"))) == 0
    ):
        return _fail("MISSING_REQUIRED_FIELD", "scope_of_claim")

    # Signature: strip it, canonicalize, verify.
    signature = obj.get("signature")
    rest = {key: value for key, value in obj.items() if key != "signature"}
    try:
        signed_bytes = canonicalize_jcs(rest)
    except Exception as err:
        return _fail("SIGNATURE_INVALID", f"receipt has no canonical JSON form ({err})")
    signer = obj.get("signer")
    if isinstance(signer, str) and signer.startswith("did:"):
        return _fail(
            "DID_RESOLVER_MISSING",
            "a DID URI signer needs key resolution, which the offline verifier does not do",
        )
    if not _ed_verify(signed_bytes, signature, signer):
        return _fail("SIGNATURE_INVALID", "Ed25519 verify failed")

    if env is None:
        return CyclesVerifyValid(valid=True)
    return CyclesVerifyValid(
        valid=True,
        evidence_authenticity="pinned_issuer" if expected_signer else "signature_valid",
    )


def _verify(
    receipt: Mapping[str, object],
    expected_claim_type: str,
    now: Optional[datetime],
    ttl_seconds: Union[int, float, None],
    expected_signer: Optional[str],
    evidence: Optional[CyclesEvidenceEnvelopeInput],
) -> CyclesVerifyResult:
    if now is not None and not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if ttl_seconds is not None and (
        isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float))
    ):
        raise TypeError("ttl_seconds must be a number")
    if expected_signer is not None and not isinstance(expected_signer, str):
        raise TypeError("expected_signer must be a string")

    captured, detail = _capture(receipt)
    if captured is None:
        return _fail("SIGNATURE_INVALID", f"receipt {detail}, so its signature cannot be checked")
    env: Optional[Dict[str, object]] = None
    if evidence is not None:
        env, detail = _capture(evidence)
        if env is None:
            return _fail(
                "EVIDENCE_REF_HASH_MISMATCH",
                f"envelope {detail}, so its content hash cannot be recomputed",
            )

    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    now_ms = (moment - _EPOCH) // timedelta(milliseconds=1)
    return _verify_core(
        captured,
        expected_claim_type,
        now_ms=now_ms,
        ttl_seconds=DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds,
        expected_signer=expected_signer if expected_signer else None,
        env=env,
    )


def verify_cycles_permit_receipt(
    receipt: Mapping[str, object],
    *,
    now: Optional[datetime] = None,
    ttl_seconds: Union[int, float, None] = None,
    expected_signer: Optional[str] = None,
    evidence: Optional[CyclesEvidenceEnvelopeInput] = None,
) -> CyclesVerifyResult:
    """Verify a Cycles permit receipt.

    ``evidence`` is the Cycles envelope the receipt's ``cycles_evidence``
    references, fetched by the caller. When given, the hash binding, the
    envelope's own signature and the reserve-stage correspondence are checked.
    ``expected_signer`` pins the APS receipt issuer. ``now`` and ``ttl_seconds``
    bound receipt age (default 24 hours). A naive ``now`` is read as UTC.

    A pass with an envelope reports ``evidence_authenticity``. It is
    ``signature_valid`` or, with ``expected_signer`` set, ``pinned_issuer``.
    Neither proves ``signer_did`` is the legitimate Cycles signer.

    Never raises on a malformed receipt or envelope. Raises ``TypeError`` for
    an option of the wrong type.
    """
    return _verify(
        receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, now, ttl_seconds, expected_signer, evidence
    )


def verify_cycles_release_receipt(
    receipt: Mapping[str, object],
    *,
    now: Optional[datetime] = None,
    ttl_seconds: Union[int, float, None] = None,
    expected_signer: Optional[str] = None,
    evidence: Optional[CyclesEvidenceEnvelopeInput] = None,
) -> CyclesVerifyResult:
    """Verify a Cycles release receipt. Options as for
    :func:`verify_cycles_permit_receipt`, with release-stage correspondence."""
    return _verify(
        receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, now, ttl_seconds, expected_signer, evidence
    )


def verify_cycles_denial(
    denial: Mapping[str, object],
    *,
    now: Optional[datetime] = None,
    ttl_seconds: Union[int, float, None] = None,
    expected_signer: Optional[str] = None,
    evidence: Optional[CyclesEvidenceEnvelopeInput] = None,
) -> CyclesVerifyResult:
    """Verify a Cycles denial. Options as for
    :func:`verify_cycles_permit_receipt`. An envelope gets the hash binding and
    signature checks but no correspondence check, because a denial's envelope
    may be an error, decide or dry run reserve event."""
    return _verify(
        denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, now, ttl_seconds, expected_signer, evidence
    )
