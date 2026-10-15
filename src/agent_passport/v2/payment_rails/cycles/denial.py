# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cycles denial mapping: Cycles codes to APS Tier-1 denial reasons.

Python port of ``mapCyclesDenialToFoundation`` and its two constant tables from
the TypeScript SDK's src/v2/payment-rails/cycles/index.ts. The tables are
ported entry for entry from the merged mapping spec,
``cycles-aps-denial-mapping-v0.1.md`` in runcycles/cycles-protocol.

Only the 15 ErrorCode values and 6 DecisionReasonCode values of Cycles protocol
v0.1.25 are mapped. A code outside those tables maps to ``rail_error`` and the
original code is preserved in ``cycles.denial_detail.code``.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, Optional

from .types import CyclesDenialDetail, CyclesDenialMapping, CyclesEvidenceView

#: Cycles ErrorCode to APS Tier-1 denial reason.
ERROR_CODE_TO_TIER1: Mapping[str, str] = MappingProxyType(
    {
        "INVALID_REQUEST": "rail_error",
        "UNAUTHORIZED": "rail_error",
        "FORBIDDEN": "no_commerce_scope",
        "NOT_FOUND": "rail_error",
        "BUDGET_EXCEEDED": "spend_limit_exceeded",
        "BUDGET_FROZEN": "wallet_revoked",
        "BUDGET_CLOSED": "wallet_revoked",
        "RESERVATION_EXPIRED": "time_window_violation",
        "RESERVATION_FINALIZED": "rail_error",
        "IDEMPOTENCY_MISMATCH": "rail_error",
        "UNIT_MISMATCH": "rail_error",
        "OVERDRAFT_LIMIT_EXCEEDED": "spend_limit_exceeded",
        "DEBT_OUTSTANDING": "wallet_revoked",
        "MAX_EXTENSIONS_EXCEEDED": "time_window_violation",
        "INTERNAL_ERROR": "rail_error",
    }
)

#: Cycles DecisionReasonCode to APS Tier-1 denial reason.
DECISION_REASON_TO_TIER1: Mapping[str, str] = MappingProxyType(
    {
        "BUDGET_EXCEEDED": "spend_limit_exceeded",
        "BUDGET_FROZEN": "wallet_revoked",
        "BUDGET_CLOSED": "wallet_revoked",
        "BUDGET_NOT_FOUND": "rail_error",
        "OVERDRAFT_LIMIT_EXCEEDED": "spend_limit_exceeded",
        "DEBT_OUTSTANDING": "wallet_revoked",
    }
)


def _lookup(table: Mapping[str, str], code: object) -> str:
    """Table lookup that falls back to ``rail_error`` for any other code,
    including one that is not a string."""
    if isinstance(code, str):
        return table.get(code, "rail_error")
    return "rail_error"


def _member(value: object, key: str) -> object:
    """``value[key]`` when value is a mapping, else None."""
    if isinstance(value, Mapping):
        return value.get(key)
    return None


def _require_mapping(value: object, what: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"map_cycles_denial_to_foundation: {what} is not an object")
    return value


def _trace(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def map_cycles_denial_to_foundation(evidence: CyclesEvidenceView) -> Optional[CyclesDenialMapping]:
    """Map a Cycles denial signal to an APS Tier-1 denial reason.

    Preserves the full Cycles side detail, Tier-2, in ``cycles.denial_detail``.
    Returns ``None`` when the evidence view is not a denial (decide ALLOW,
    reserve ALLOW, commit, release).

    Denial paths, checked in this order:

    * HTTP 4xx or 5xx, ``payload.error``. Source ``ErrorCode``.
    * ``/v1/decide`` DENY, ``payload.decide``. Source ``DecisionReasonCode``.
    * Dry run reserve DENY, ``payload.reserve``. Source ``DecisionReasonCode``.

    ``trace_id`` is always present in the detail, as None when the evidence
    carries none. The explicit null keeps the preimage bytes the TypeScript SDK
    ships, and omitting it would change signatures.

    Raises ``ValueError`` when ``evidence`` is not an object or its ``error``
    payload lacks the members the mapping reads, including a string ErrorCode. The
    TypeScript function throws a TypeError for the same inputs.
    """
    view = _require_mapping(evidence, "evidence")
    payload = _require_mapping(view.get("payload"), "evidence.payload")
    evidence_trace = view.get("trace_id")

    if "error" in payload:
        err = _require_mapping(payload["error"], "payload.error")
        response = _require_mapping(err.get("response"), "payload.error.response")
        code = response.get("error")
        if not isinstance(code, str):
            raise ValueError("map_cycles_denial_to_foundation: payload.error.response.error is not a string")
        detail: CyclesDenialDetail = {
            "layer": "cycles",
            "source": "ErrorCode",
            "code": code,
            "trace_id": None,
        }
        http_status = err.get("http_status")
        if isinstance(http_status, int) and not isinstance(http_status, bool):
            detail["http_status"] = http_status
        message = response.get("message")
        if isinstance(message, str):
            detail["message"] = message
        request_id = response.get("request_id")
        if isinstance(request_id, str):
            detail["request_id"] = request_id
        trace = _trace(response.get("trace_id"))
        detail["trace_id"] = trace if trace is not None else _trace(evidence_trace)
        return {
            "denial_reason": _lookup(ERROR_CODE_TO_TIER1, code),
            "cycles": {"denial_detail": detail},
        }

    for variant in ("decide", "reserve"):
        if variant in payload:
            body = _require_mapping(payload[variant], f"payload.{variant}")
            response = _require_mapping(body.get("response"), f"payload.{variant}.response")
            if response.get("decision") != "DENY":
                # The TypeScript function tests decide, then reserve, and a
                # payload with both keys falls through to reserve.
                continue
            reason_code = response.get("reason_code")
            code = reason_code if isinstance(reason_code, str) else "UNKNOWN"
            return {
                "denial_reason": _lookup(DECISION_REASON_TO_TIER1, code),
                "cycles": {
                    "denial_detail": {
                        "layer": "cycles",
                        "source": "DecisionReasonCode",
                        "code": code,
                        "trace_id": _trace(evidence_trace),
                    }
                },
            }

    return None
