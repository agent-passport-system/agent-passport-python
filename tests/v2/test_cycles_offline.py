# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cycles budget-authority rail, offline path.

Ports the offline tests of the TypeScript SDK's tests/v2/payment-rails/cycles.test.ts
(agent-passport-system 8.0.0): denial mapping goldens, sign and verify round trips,
hash binding, envelope signature, pinned issuer, correspondence, and the shape checks.
The DID, fetch, resolver and signer authority tests are not ported because those
paths are not ported. JavaScript prototype and getter tests have no Python
counterpart. The Python-specific equivalents (non-dict inputs, non-JSON values,
containers nested without bound or referring to themselves) are at the end.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import generate_key_pair, public_key_from_private, sign
from agent_passport.v2.payment_rails.cycles import (
    DECISION_REASON_TO_TIER1,
    ERROR_CODE_TO_TIER1,
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    map_cycles_denial_to_foundation,
    sign_cycles_denial,
    sign_cycles_permit_receipt,
    sign_cycles_release_receipt,
    verify_cycles_denial,
    verify_cycles_permit_receipt,
    verify_cycles_release_receipt,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cycles"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "fixtures" / name).read_text(encoding="utf-8"))


def load_vector(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "evidence-vectors" / name).read_text(encoding="utf-8"))


def evidence_ref() -> dict[str, Any]:
    return {
        "cycles_evidence_url": "https://cycles.example.com/v1/evidence/abc",
        "cycles_evidence_id_sha256": "a" * 64,
        "action_ref": "aps:action:cycles-test-001",
        "delegation_ref": "aps:delegation:cycles-test-001",
    }


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def keypair() -> tuple[str, str]:
    pair = generate_key_pair()
    return pair["privateKey"], pair["publicKey"]


COMMON = {
    "agent_id": "agent-cycles-001",
    "delegation_ref": "aps:delegation:cycles-001",
    "action_ref": "aps:action:cycles-001",
}


def permit(private_key: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        **COMMON,
        "reservation_id": "rsv_x",
        "reserved": {"unit": "USD_MICROCENTS", "amount": 1000},
        "decision": "ALLOW",
        "cycles_evidence": evidence_ref(),
    }
    body.update(overrides)
    return dict(sign_cycles_permit_receipt(body, private_key))  # type: ignore[arg-type]


def release(private_key: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        **COMMON,
        "reservation_id": "rsv_x",
        "released": {"unit": "TOKENS", "amount": 8000},
        "cycles_evidence": evidence_ref(),
    }
    body.update(overrides)
    return dict(sign_cycles_release_receipt(body, private_key))  # type: ignore[arg-type]


def denial(private_key: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        **COMMON,
        "denial_reason": "spend_limit_exceeded",
        "cycles": {
            "denial_detail": {
                "layer": "cycles",
                "source": "ErrorCode",
                "code": "BUDGET_EXCEEDED",
                "http_status": 409,
                "trace_id": None,
            }
        },
        "cycles_evidence": evidence_ref(),
    }
    body.update(overrides)
    return dict(sign_cycles_denial(body, private_key))  # type: ignore[arg-type]


def resign(receipt: dict[str, Any], private_key: str, **changes: Any) -> dict[str, Any]:
    """A receipt with `changes` applied (None removes a key) and a valid signature."""
    body = {k: v for k, v in receipt.items() if k != "signature"}
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return {**body, "signature": sign(canonicalize_jcs(body), private_key)}


def assert_fail(result: Any, reason: str, detail_prefix: str | None = None) -> None:
    assert result["valid"] is False, result
    assert result["reason"] == reason, result
    if detail_prefix is not None:
        assert result.get("detail", "").startswith(detail_prefix), result


# ── Denial mapping ────────────────────────────────────────────────────────


def test_mapping_tables_are_the_published_sizes() -> None:
    assert len(ERROR_CODE_TO_TIER1) == 15
    assert len(DECISION_REASON_TO_TIER1) == 6


def test_mapping_tables_are_the_published_values() -> None:
    assert dict(ERROR_CODE_TO_TIER1) == {
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
    assert dict(DECISION_REASON_TO_TIER1) == {
        "BUDGET_EXCEEDED": "spend_limit_exceeded",
        "BUDGET_FROZEN": "wallet_revoked",
        "BUDGET_CLOSED": "wallet_revoked",
        "BUDGET_NOT_FOUND": "rail_error",
        "OVERDRAFT_LIMIT_EXCEEDED": "spend_limit_exceeded",
        "DEBT_OUTSTANDING": "wallet_revoked",
    }


def test_mapping_dry_run_reserve_deny() -> None:
    mapped = map_cycles_denial_to_foundation(load_fixture("03-reserve-dry-run-deny.json"))
    assert mapped is not None
    assert mapped["denial_reason"] == "spend_limit_exceeded"
    detail = mapped["cycles"]["denial_detail"]
    assert detail["source"] == "DecisionReasonCode"
    assert detail["code"] == "BUDGET_EXCEEDED"
    assert "trace_id" in detail


def test_mapping_live_error_budget_exceeded() -> None:
    mapped = map_cycles_denial_to_foundation(load_fixture("11-reserve-live-budget-exceeded.json"))
    assert mapped is not None
    assert mapped["denial_reason"] == "spend_limit_exceeded"
    detail = mapped["cycles"]["denial_detail"]
    assert detail["source"] == "ErrorCode"
    assert detail["code"] == "BUDGET_EXCEEDED"
    assert detail["http_status"] == 409
    assert detail["layer"] == "cycles"


def test_mapping_decide_forbidden() -> None:
    mapped = map_cycles_denial_to_foundation(load_fixture("12-decide-live-forbidden.json"))
    assert mapped is not None
    assert mapped["denial_reason"] == "no_commerce_scope"
    detail = mapped["cycles"]["denial_detail"]
    assert detail["source"] == "ErrorCode"
    assert detail["code"] == "FORBIDDEN"
    assert detail["http_status"] == 403


def test_mapping_unknown_error_code_falls_back_to_rail_error() -> None:
    view = {
        "artifact_type": "error",
        "payload": {
            "error": {
                "endpoint": "POST /v1/reservations",
                "http_status": 500,
                "response": {
                    "error": "FUTURE_UNKNOWN_CODE",
                    "message": "something new",
                    "request_id": "req_x",
                },
            }
        },
    }
    mapped = map_cycles_denial_to_foundation(view)
    assert mapped is not None
    assert mapped["denial_reason"] == "rail_error"
    assert mapped["cycles"]["denial_detail"]["code"] == "FUTURE_UNKNOWN_CODE"
    # An inherited name is a code like any other, never a table hit.
    for name in ("constructor", "__proto__", "toString"):
        view["payload"]["error"]["response"]["error"] = name  # type: ignore[index]
        again = map_cycles_denial_to_foundation(view)
        assert again is not None and again["denial_reason"] == "rail_error"


def test_mapping_trace_id_precedence_and_explicit_null() -> None:
    base = {
        "artifact_type": "error",
        "trace_id": "envelope-trace",
        "payload": {"error": {"http_status": 409, "response": {"error": "BUDGET_EXCEEDED", "message": "m", "request_id": "r"}}},
    }
    first = map_cycles_denial_to_foundation(base)
    assert first is not None and first["cycles"]["denial_detail"]["trace_id"] == "envelope-trace"
    with_response_trace = copy.deepcopy(base)
    with_response_trace["payload"]["error"]["response"]["trace_id"] = "response-trace"  # type: ignore[index]
    second = map_cycles_denial_to_foundation(with_response_trace)
    assert second is not None and second["cycles"]["denial_detail"]["trace_id"] == "response-trace"
    del base["trace_id"]
    third = map_cycles_denial_to_foundation(base)
    assert third is not None
    assert "trace_id" in third["cycles"]["denial_detail"]
    assert third["cycles"]["denial_detail"]["trace_id"] is None


def test_mapping_returns_none_for_non_denials() -> None:
    assert map_cycles_denial_to_foundation({"artifact_type": "commit", "payload": {"commit": {"reservation_id": "r"}}}) is None
    allow = {"artifact_type": "reserve", "payload": {"reserve": {"response": {"decision": "ALLOW"}}}}
    assert map_cycles_denial_to_foundation(allow) is None
    decide_allow = {"artifact_type": "decide", "payload": {"decide": {"response": {"decision": "ALLOW_WITH_CAPS"}}}}
    assert map_cycles_denial_to_foundation(decide_allow) is None


def test_mapping_deny_without_reason_code_is_unknown() -> None:
    view = {"artifact_type": "decide", "payload": {"decide": {"response": {"decision": "DENY"}}}}
    mapped = map_cycles_denial_to_foundation(view)
    assert mapped is not None
    assert mapped["denial_reason"] == "rail_error"
    assert mapped["cycles"]["denial_detail"]["code"] == "UNKNOWN"


def test_mapping_rejects_a_malformed_view() -> None:
    with pytest.raises(ValueError):
        map_cycles_denial_to_foundation({"payload": {"error": {}}})
    with pytest.raises(ValueError):
        map_cycles_denial_to_foundation("not an object")  # type: ignore[arg-type]


# ── Permit round trip ─────────────────────────────────────────────────────


def test_permit_round_trip() -> None:
    private_key, public_key = keypair()
    receipt = sign_cycles_permit_receipt(
        {
            **COMMON,  # type: ignore[typeddict-item]
            "reservation_id": "rsv_01HZZ8N4F8FBQX5K6TGYR0M0A3",
            "reserved": {"unit": "USD_MICROCENTS", "amount": 2000000},
            "decision": "ALLOW",
            "expires_at_ms": 1810000030100,
            "cycles_evidence": evidence_ref(),  # type: ignore[typeddict-item]
        },
        private_key,
    )
    assert receipt["claim_type"] == RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    assert receipt["rail_name"] == "cycles"
    assert receipt["decision"] == "ALLOW"
    assert receipt["receipt_id"].startswith("cycles_permit_")
    assert len(receipt["signature"]) == 128
    assert receipt["signer"] == public_key
    assert receipt["timestamp"] == receipt["issued_at"]
    assert receipt["expires_at_ms"] == 1810000030100
    assert verify_cycles_permit_receipt(receipt) == {"valid": True}


def test_permit_tampered_reservation_id() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, reservation_id="rsv_original")
    assert_fail(verify_cycles_permit_receipt({**receipt, "reservation_id": "rsv_tampered"}), "SIGNATURE_INVALID")


def test_permit_missing_cycles_evidence_hash() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    broken = {**receipt, "cycles_evidence": {**receipt["cycles_evidence"], "cycles_evidence_id_sha256": ""}}
    assert_fail(verify_cycles_permit_receipt(broken), "MISSING_REQUIRED_FIELD", "cycles_evidence")


def test_permit_wrong_claim_type() -> None:
    private_key, _ = keypair()
    assert_fail(verify_cycles_permit_receipt(release(private_key)), "INVALID_CLAIM_TYPE")  # type: ignore[arg-type]
    assert_fail(verify_cycles_release_receipt(permit(private_key)), "INVALID_CLAIM_TYPE")
    assert_fail(verify_cycles_denial(permit(private_key)), "INVALID_CLAIM_TYPE")


def test_permit_wrong_claim_type_detail_names_both_values() -> None:
    private_key, _ = keypair()
    result = verify_cycles_permit_receipt(release(private_key))
    assert result == {
        "valid": False,
        "reason": "INVALID_CLAIM_TYPE",
        "detail": f"expected {RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE} got {RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE}",
    }
    absent = {k: v for k, v in permit(private_key).items() if k != "claim_type"}
    assert verify_cycles_permit_receipt(absent)["detail"].endswith("got undefined")  # type: ignore[typeddict-item]


def test_permit_expected_signer_mismatch_and_match() -> None:
    private_key, public_key = keypair()
    receipt = permit(private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, expected_signer="f" * 64), "SIGNATURE_INVALID", "signer mismatch")
    assert verify_cycles_permit_receipt(receipt, expected_signer=public_key) == {"valid": True}


def test_permit_past_ttl() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    issued = datetime.fromisoformat(receipt["issued_at"].replace("Z", "+00:00"))
    later = issued + timedelta(hours=48)
    assert_fail(verify_cycles_permit_receipt(receipt, now=later, ttl_seconds=24 * 3600), "EXPIRED", "older than ttl=86400s")
    assert_fail(verify_cycles_permit_receipt(receipt, now=later), "EXPIRED")
    assert verify_cycles_permit_receipt(receipt, now=later, ttl_seconds=72 * 3600) == {"valid": True}


def test_permit_naive_now_is_read_as_utc() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    issued = datetime.fromisoformat(receipt["issued_at"].replace("Z", "+00:00"))
    naive_later = (issued + timedelta(hours=48)).replace(tzinfo=None)
    assert_fail(verify_cycles_permit_receipt(receipt, now=naive_later), "EXPIRED")


def test_permit_tampered_rail_name() -> None:
    private_key, _ = keypair()
    assert_fail(verify_cycles_permit_receipt({**permit(private_key), "rail_name": "cycles_v2"}), "INVALID_RAIL_NAME", "expected 'cycles' got cycles_v2")


def test_permit_timestamp_must_equal_issued_at() -> None:
    private_key, _ = keypair()
    tampered = {**permit(private_key), "timestamp": "2020-01-01T00:00:00.000Z"}
    assert_fail(verify_cycles_permit_receipt(tampered), "MISSING_REQUIRED_FIELD", "timestamp != issued_at")


def test_permit_empty_scope_asserts() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    tampered = {**receipt, "scope_of_claim": {**receipt["scope_of_claim"], "asserts": ""}}
    assert_fail(verify_cycles_permit_receipt(tampered), "MISSING_REQUIRED_FIELD", "scope_of_claim")


def test_permit_issued_at_must_parse() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for bad in ("not a date", "", None):
        broken = resign(receipt, private_key, issued_at=bad, timestamp=bad)
        assert_fail(verify_cycles_permit_receipt(broken), "MISSING_REQUIRED_FIELD", "issued_at")


def test_did_uri_signer_is_resolver_missing() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, issuer_agent_id="did:cycles:example", issuer_key_ref="key-1")
    assert receipt["signer"] == "did:cycles:example#key-1"
    assert_fail(verify_cycles_permit_receipt(receipt), "DID_RESOLVER_MISSING")


def test_sign_rejects_a_bad_issuer() -> None:
    private_key, _ = keypair()
    with pytest.raises(ValueError):
        permit(private_key, issuer_agent_id="not-a-did", issuer_key_ref="key-1")
    with pytest.raises(ValueError):
        permit(private_key, issuer_agent_id="did:cycles:example", issuer_key_ref="key#1")


def test_each_required_receipt_field_must_be_present_and_non_empty() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for key in ("receipt_id", "signer", "agent_id", "delegation_ref", "action_ref"):
        emptied = {**receipt, key: ""}
        removed = {k: v for k, v in receipt.items() if k != key}
        assert_fail(verify_cycles_permit_receipt(emptied), "MISSING_REQUIRED_FIELD")
        assert_fail(verify_cycles_permit_receipt(removed), "MISSING_REQUIRED_FIELD")


# ── authority_state_at_admission and trust_policy_ref ─────────────────────

SNAPSHOT = {
    "checked_at": "2026-05-30T12:00:00.000Z",
    "delegation_revoked": False,
    "delegation_expires_at": "2026-06-30T00:00:00.000Z",
    "source": "aps_admission",
}


def test_admission_snapshot_is_carried_and_signed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, authority_state_at_admission=SNAPSHOT)
    assert receipt["authority_state_at_admission"] == SNAPSHOT
    assert verify_cycles_permit_receipt(receipt) == {"valid": True}


def test_admission_snapshot_tamper_is_caught() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, authority_state_at_admission=SNAPSHOT)
    tampered = {**receipt, "authority_state_at_admission": {**SNAPSHOT, "delegation_revoked": True}}
    assert_fail(verify_cycles_permit_receipt(tampered), "SIGNATURE_INVALID")


def test_optional_members_are_absent_when_not_supplied() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for key in ("authority_state_at_admission", "trust_policy_ref", "expires_at_ms"):
        assert key not in receipt
    assert verify_cycles_permit_receipt(receipt) == {"valid": True}
    # None is treated as absent, not signed as null.
    none_valued = permit(private_key, authority_state_at_admission=None, trust_policy_ref=None, expires_at_ms=None)
    assert "trust_policy_ref" not in none_valued


def test_trust_policy_ref_is_carried_and_signed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, trust_policy_ref="policy-1@3")
    assert receipt["trust_policy_ref"] == "policy-1@3"
    assert verify_cycles_permit_receipt(receipt) == {"valid": True}
    assert_fail(verify_cycles_permit_receipt({**receipt, "trust_policy_ref": "policy-1@4"}), "SIGNATURE_INVALID")


def test_signing_does_not_alias_the_callers_objects() -> None:
    private_key, _ = keypair()
    ref = evidence_ref()
    receipt = permit(private_key, cycles_evidence=ref)
    ref["cycles_evidence_url"] = "https://elsewhere.example.com"
    assert receipt["cycles_evidence"]["cycles_evidence_url"] == "https://cycles.example.com/v1/evidence/abc"


def test_signing_refuses_an_unsafe_integer() -> None:
    private_key, _ = keypair()
    with pytest.raises(ValueError):
        permit(private_key, reserved={"unit": "TOKENS", "amount": 2**60})


# ── Release and denial round trips ────────────────────────────────────────


def test_release_round_trip_with_reason() -> None:
    private_key, _ = keypair()
    receipt = release(private_key, reservation_id="rsv_release_001", reason="handler_timeout")
    assert receipt["claim_type"] == RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    assert receipt["reason"] == "handler_timeout"
    assert receipt["receipt_id"].startswith("cycles_release_")
    assert verify_cycles_release_receipt(receipt) == {"valid": True}
    assert "reason" not in release(private_key)


def test_release_tampered_amount() -> None:
    private_key, _ = keypair()
    receipt = release(private_key)
    tampered = {**receipt, "released": {**receipt["released"], "amount": 999999999}}
    assert_fail(verify_cycles_release_receipt(tampered), "SIGNATURE_INVALID")


def test_denial_round_trip_error_code() -> None:
    private_key, _ = keypair()
    mapped = map_cycles_denial_to_foundation(load_fixture("11-reserve-live-budget-exceeded.json"))
    assert mapped is not None
    signed = denial(private_key, denial_reason=mapped["denial_reason"], cycles=mapped["cycles"])
    assert signed["claim_type"] == RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE
    assert signed["denial_reason"] == "spend_limit_exceeded"
    assert signed["cycles"]["denial_detail"]["code"] == "BUDGET_EXCEEDED"
    assert signed["receipt_id"].startswith("cycles_denial_")
    assert verify_cycles_denial(signed) == {"valid": True}


def test_denial_round_trip_decision_reason_code() -> None:
    private_key, _ = keypair()
    mapped = map_cycles_denial_to_foundation(load_fixture("03-reserve-dry-run-deny.json"))
    assert mapped is not None
    signed = denial(private_key, denial_reason=mapped["denial_reason"], cycles=mapped["cycles"])
    assert signed["cycles"]["denial_detail"]["source"] == "DecisionReasonCode"
    assert verify_cycles_denial(signed) == {"valid": True}


def test_denial_tampered_detail_code() -> None:
    private_key, _ = keypair()
    signed = denial(private_key)
    tampered = copy.deepcopy(signed)
    tampered["cycles"]["denial_detail"]["code"] = "TAMPERED"
    assert_fail(verify_cycles_denial(tampered), "SIGNATURE_INVALID")


def test_denial_null_trace_id_is_part_of_the_signed_bytes() -> None:
    private_key, _ = keypair()
    signed = denial(private_key)
    assert signed["cycles"]["denial_detail"]["trace_id"] is None
    stripped = copy.deepcopy(signed)
    del stripped["cycles"]["denial_detail"]["trace_id"]
    assert_fail(verify_cycles_denial(stripped), "SIGNATURE_INVALID")


def test_default_scope_of_claim_text_is_the_typescript_text() -> None:
    private_key, _ = keypair()
    dash = "—"
    assert permit(private_key)["scope_of_claim"]["asserts"].startswith(f"aps:cycles.permit:emit {dash} a budget reservation")
    assert release(private_key)["scope_of_claim"]["asserts"].startswith(f"aps:cycles.release:emit {dash} a budget reservation")
    assert denial(private_key)["scope_of_claim"]["asserts"].startswith(f"aps:cycles.deny:emit {dash} a Cycles budget-authority")
    custom = {
        "asserts": "custom",
        "does_not_assert": [],
        "capture_mode": "partial",
        "completeness": "best_effort",
        "self_attested": True,
    }
    assert permit(private_key, scope_of_claim=custom)["scope_of_claim"] == custom


# ── Join integrity ────────────────────────────────────────────────────────


def reserve_envelope() -> dict[str, Any]:
    return load_fixture("02-reserve-allow.json")


def reservation_of(env: dict[str, Any]) -> str:
    payload = env["payload"]
    if "reserve" in payload:
        return str(payload["reserve"]["response"]["reservation_id"])
    if "release" in payload:
        return str(payload["release"]["reservation_id"])
    return str(payload["commit"]["reservation_id"])


def resign_envelope(env: dict[str, Any], private_key: str) -> dict[str, Any]:
    """A fully self-consistent envelope signed by `private_key`."""
    signer_did = public_key_from_private(private_key)
    evidence_id = sha256_hex(canonicalize_jcs({**env, "signer_did": signer_did, "evidence_id": "", "signature": ""}))
    signature = sign(canonicalize_jcs({**env, "signer_did": signer_did, "evidence_id": evidence_id, "signature": ""}), private_key)
    return {**env, "signer_did": signer_did, "evidence_id": evidence_id, "signature": signature}


def permit_for(env: dict[str, Any], reservation_id: str, private_key: str) -> dict[str, Any]:
    return permit(
        private_key,
        reservation_id=reservation_id,
        reserved={"unit": "USD_MICROCENTS", "amount": 2000000},
        cycles_evidence={**evidence_ref(), "cycles_evidence_id_sha256": env["evidence_id"]},
    )


def release_for(env: dict[str, Any], reservation_id: str, private_key: str) -> dict[str, Any]:
    return release(
        private_key,
        reservation_id=reservation_id,
        cycles_evidence={**evidence_ref(), "cycles_evidence_id_sha256": env["evidence_id"]},
    )


def permit_bound_to(env: dict[str, Any], private_key: str) -> dict[str, Any]:
    return permit_for(env, reservation_of(env), private_key)


def test_fixture_evidence_ids_are_reproduced() -> None:
    """The Cycles server derived these ids. Reproducing them shows the JCS and
    sha256 here are byte compatible with cycles-evidence-v0.1."""
    for name in ("02-reserve-allow.json", "03-reserve-dry-run-deny.json", "11-reserve-live-budget-exceeded.json", "12-decide-live-forbidden.json"):
        env = load_fixture(name)
        assert sha256_hex(canonicalize_jcs({**env, "evidence_id": "", "signature": ""})) == env["evidence_id"]
    for name in ("05-commit-success.json", "06-release-success.json"):
        env = load_vector(name)
        assert sha256_hex(canonicalize_jcs({**env, "evidence_id": "", "signature": ""})) == env["evidence_id"]


def test_join_matching_envelope_is_valid() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert verify_cycles_permit_receipt(receipt, evidence=env) == {"valid": True, "evidence_authenticity": "signature_valid"}


def test_join_envelope_omitted_skips_the_check() -> None:
    private_key, _ = keypair()
    assert verify_cycles_permit_receipt(permit_bound_to(reserve_envelope(), private_key)) == {"valid": True}


def test_join_tampered_envelope() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    result = verify_cycles_permit_receipt(receipt, evidence={**env, "server_id": "https://evil.example.com/v1"})
    assert_fail(result, "EVIDENCE_REF_HASH_MISMATCH", "envelope evidence_id")


def test_join_receipt_bound_to_a_different_envelope() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key, reservation_id="rsv_wrong_binding")
    result = verify_cycles_permit_receipt(receipt, evidence=reserve_envelope())
    assert_fail(result, "EVIDENCE_REF_HASH_MISMATCH", "receipt cycles_evidence_id_sha256")


def test_join_applies_to_denials() -> None:
    private_key, _ = keypair()
    env = load_fixture("11-reserve-live-budget-exceeded.json")
    mapped = map_cycles_denial_to_foundation(env)
    assert mapped is not None
    signed = denial(
        private_key,
        denial_reason=mapped["denial_reason"],
        cycles=mapped["cycles"],
        cycles_evidence={**evidence_ref(), "cycles_evidence_id_sha256": env["evidence_id"]},
    )
    assert verify_cycles_denial(signed, evidence=env) == {"valid": True, "evidence_authenticity": "signature_valid"}
    assert_fail(verify_cycles_denial(signed, evidence={**env, "server_id": "https://evil.example.com/v1"}), "EVIDENCE_REF_HASH_MISMATCH")


def test_join_non_string_evidence_id() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence={**env, "evidence_id": ["not", "a", "string"]}), "EVIDENCE_REF_HASH_MISMATCH")
    without = {k: v for k, v in env.items() if k != "evidence_id"}
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=without), "EVIDENCE_REF_HASH_MISMATCH", "envelope evidence_id undefined")


def test_join_is_byte_exact_with_no_case_folding() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    upper = permit(
        private_key,
        reservation_id=reservation_of(env),
        cycles_evidence={**evidence_ref(), "cycles_evidence_id_sha256": env["evidence_id"].upper()},
    )
    assert_fail(verify_cycles_permit_receipt(upper, evidence=env), "EVIDENCE_REF_HASH_MISMATCH", "receipt cycles_evidence_id_sha256")


def test_empty_evidence_object_is_an_envelope_not_an_absent_one() -> None:
    private_key, _ = keypair()
    receipt = permit_bound_to(reserve_envelope(), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence={}), "EVIDENCE_REF_HASH_MISMATCH")


# ── Envelope authenticity ────────────────────────────────────────────────


def test_authenticity_pinned_issuer() -> None:
    private_key, public_key = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert verify_cycles_permit_receipt(receipt, evidence=env, expected_signer=public_key) == {
        "valid": True,
        "evidence_authenticity": "pinned_issuer",
    }


def test_authenticity_empty_expected_signer_is_no_pin() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert verify_cycles_permit_receipt(receipt, evidence=env, expected_signer="") == {
        "valid": True,
        "evidence_authenticity": "signature_valid",
    }


def test_authenticity_bad_signature_with_consistent_hash() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    result = verify_cycles_permit_receipt(receipt, evidence={**env, "signature": "0" * 128})
    assert_fail(result, "EVIDENCE_SIGNATURE_INVALID", "envelope Ed25519 signature does not verify")


def test_authenticity_attacker_self_signed_envelope_is_signature_valid_only() -> None:
    issuer_key, _ = keypair()
    attacker_key, _ = keypair()
    forged = resign_envelope(reserve_envelope(), attacker_key)
    receipt = permit_bound_to(forged, issuer_key)
    # signature_valid is not authenticity. A forger can embed their own key.
    assert verify_cycles_permit_receipt(receipt, evidence=forged) == {"valid": True, "evidence_authenticity": "signature_valid"}


def test_authenticity_missing_signer_did() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    reduced = {k: v for k, v in env.items() if k != "signer_did"}
    reduced["evidence_id"] = sha256_hex(canonicalize_jcs({**reduced, "evidence_id": "", "signature": ""}))
    receipt = permit_bound_to(reduced, private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=reduced), "EVIDENCE_SIGNATURE_INVALID", "envelope missing signer_did")


def test_authenticity_empty_or_missing_signature() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence={**env, "signature": ""}), "EVIDENCE_SIGNATURE_INVALID", "envelope missing signature")
    removed = {k: v for k, v in env.items() if k != "signature"}
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=removed), "EVIDENCE_SIGNATURE_INVALID", "envelope missing signature")


def test_authenticity_signer_did_is_strict_hex() -> None:
    """A did: method signer_did is not resolvable here, and a key padded with
    whitespace must not verify as it does not in the TypeScript SDK."""
    private_key, _ = keypair()
    attacker_key, _ = keypair()
    base = reserve_envelope()
    forged = resign_envelope(base, attacker_key)
    spaced = {**forged, "signer_did": forged["signer_did"][:32] + " " + forged["signer_did"][32:]}
    receipt = permit_bound_to(forged, private_key)
    result = verify_cycles_permit_receipt(receipt, evidence=spaced)
    assert result["valid"] is False


# ── Correspondence ───────────────────────────────────────────────────────


def test_correspondence_permit_own_reserve() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, reservation_of(env), private_key)
    assert verify_cycles_permit_receipt(receipt, evidence=env) == {"valid": True, "evidence_authenticity": "signature_valid"}


def test_correspondence_other_reservation() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, "rsv_some_other_reservation", private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "reservation_id")


def test_correspondence_commit_envelope() -> None:
    private_key, _ = keypair()
    env = load_vector("05-commit-success.json")
    receipt = permit_for(env, reservation_of(env), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "artifact_type")


def test_correspondence_reported_probe_with_pinned_issuer() -> None:
    private_key, public_key = keypair()
    env = load_vector("05-commit-success.json")
    receipt = permit_for(env, "WRONG-RESERVATION", private_key)
    result = verify_cycles_permit_receipt(receipt, evidence=env, expected_signer=public_key)
    assert_fail(result, "EVIDENCE_CORRESPONDENCE_MISMATCH", "artifact_type")


def test_correspondence_reserve_without_reservation_id() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    base = reserve_envelope()
    payload = copy.deepcopy(base["payload"])
    del payload["reserve"]["response"]["reservation_id"]
    env = resign_envelope({**base, "payload": payload}, cycles_key)
    receipt = permit_for(env, reservation_of(base), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload.reserve.response.reservation_id")


def test_correspondence_envelope_without_artifact_type() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    base = reserve_envelope()
    env = resign_envelope({k: v for k, v in base.items() if k != "artifact_type"}, cycles_key)
    receipt = permit_for(env, reservation_of(base), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "artifact_type")


def test_correspondence_reserve_type_with_commit_payload() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    reserve = reserve_envelope()
    commit = load_vector("05-commit-success.json")
    env = resign_envelope({**reserve, "payload": commit["payload"]}, cycles_key)
    receipt = permit_for(env, reservation_of(reserve), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "payload")


def test_correspondence_payload_with_two_variants() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    reserve = reserve_envelope()
    commit = load_vector("05-commit-success.json")
    env = resign_envelope({**reserve, "payload": {**reserve["payload"], "commit": commit["payload"]["commit"]}}, cycles_key)
    receipt = permit_for(env, reservation_of(reserve), private_key)
    result = verify_cycles_permit_receipt(receipt, evidence=env)
    assert_fail(result, "EVIDENCE_CORRESPONDENCE_MISMATCH", "payload")
    assert "[commit, reserve]" in result["detail"]  # type: ignore[typeddict-item]


def test_correspondence_artifact_type_commit_over_reserve_payload() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    reserve = reserve_envelope()
    env = resign_envelope({**reserve, "artifact_type": "commit"}, cycles_key)
    receipt = permit_for(env, reservation_of(reserve), private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "artifact_type")


def test_correspondence_payload_not_an_object_or_empty() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    reserve = reserve_envelope()
    for payload, reason, prefix in (
        ("text", "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload"),
        ([], "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload"),
        ({}, "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload"),
        ({"reserve": "text"}, "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload.reserve"),
        ({"reserve": {"response": []}}, "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload.reserve.response.reservation_id"),
    ):
        env = resign_envelope({**reserve, "payload": payload}, cycles_key)
        receipt = permit_for(env, reservation_of(reserve), private_key)
        assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), reason, prefix)


def test_correspondence_receipt_without_reservation_id() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    issued = permit_for(env, reservation_of(env), private_key)
    receipt = resign(issued, private_key, reservation_id=None)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "receipt.reservation_id")
    empty = resign(issued, private_key, reservation_id="")
    assert_fail(verify_cycles_permit_receipt(empty, evidence=env), "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "receipt.reservation_id")


def test_correspondence_release_own_release() -> None:
    private_key, _ = keypair()
    env = load_vector("06-release-success.json")
    receipt = release_for(env, reservation_of(env), private_key)
    assert verify_cycles_release_receipt(receipt, evidence=env) == {"valid": True, "evidence_authenticity": "signature_valid"}


def test_correspondence_release_other_reservation() -> None:
    private_key, _ = keypair()
    env = load_vector("06-release-success.json")
    receipt = release_for(env, "rsv_some_other_reservation", private_key)
    assert_fail(verify_cycles_release_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "reservation_id")


def test_correspondence_release_commit_envelope() -> None:
    private_key, _ = keypair()
    env = load_vector("05-commit-success.json")
    receipt = release_for(env, reservation_of(env), private_key)
    assert_fail(verify_cycles_release_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "artifact_type")


def test_correspondence_release_envelope_without_reservation_id() -> None:
    private_key, _ = keypair()
    cycles_key, _ = keypair()
    base = load_vector("06-release-success.json")
    payload = copy.deepcopy(base["payload"])
    del payload["release"]["reservation_id"]
    env = resign_envelope({**base, "payload": payload}, cycles_key)
    receipt = release_for(env, reservation_of(base), private_key)
    assert_fail(verify_cycles_release_receipt(receipt, evidence=env), "EVIDENCE_CORRESPONDENCE_FIELD_MISSING", "payload.release.reservation_id")


def test_correspondence_stage_comes_from_the_verifier_not_the_input() -> None:
    """A release receipt given to the permit verifier is refused on claim_type,
    and re-labelling claim_type breaks the signature. The release verifier
    never treats a reserve envelope as a release event."""
    private_key, _ = keypair()
    env = reserve_envelope()
    as_release = release_for(env, reservation_of(env), private_key)
    assert_fail(verify_cycles_release_receipt(as_release, evidence=env), "EVIDENCE_CORRESPONDENCE_MISMATCH", "artifact_type")
    relabelled = {**as_release, "claim_type": RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE}
    assert_fail(verify_cycles_release_receipt(relabelled, evidence=env), "INVALID_CLAIM_TYPE")


def test_correspondence_runs_after_the_hash_check() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, "rsv_some_other_reservation", private_key)
    result = verify_cycles_permit_receipt(receipt, evidence={**env, "server_id": "https://evil.example.com/v1"})
    assert_fail(result, "EVIDENCE_REF_HASH_MISMATCH")


def test_correspondence_runs_after_the_envelope_signature_check() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, "rsv_some_other_reservation", private_key)
    assert_fail(verify_cycles_permit_receipt(receipt, evidence={**env, "signature": "0" * 128}), "EVIDENCE_SIGNATURE_INVALID")


def test_correspondence_does_not_compare_amount_unit_action_or_server() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, reservation_of(env), private_key)
    receipt = resign(receipt, private_key, reserved={"unit": "TOKENS", "amount": 1})
    assert verify_cycles_permit_receipt(receipt, evidence=env)["valid"] is True


def test_correspondence_denials_are_not_checked() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    mapped = map_cycles_denial_to_foundation(load_fixture("11-reserve-live-budget-exceeded.json"))
    assert mapped is not None
    signed = denial(
        private_key,
        denial_reason=mapped["denial_reason"],
        cycles=mapped["cycles"],
        cycles_evidence={**evidence_ref(), "cycles_evidence_id_sha256": env["evidence_id"]},
    )
    assert verify_cycles_denial(signed, evidence=env) == {"valid": True, "evidence_authenticity": "signature_valid"}


def test_correspondence_checks_run_in_the_documented_order() -> None:
    """The first failing check wins, in the order of the module docstring."""
    private_key, _ = keypair()
    env = reserve_envelope()
    bad_everything = permit(private_key, reservation_id="other", cycles_evidence={**evidence_ref()})
    bad_everything = {**bad_everything, "rail_name": "x"}
    assert verify_cycles_permit_receipt(bad_everything, evidence=env)["reason"] == "INVALID_RAIL_NAME"
    bound = permit_for(env, "other", private_key)
    stale = {**bound}
    issued = datetime.fromisoformat(bound["issued_at"].replace("Z", "+00:00"))
    result = verify_cycles_permit_receipt(stale, evidence=env, now=issued + timedelta(days=3), expected_signer="f" * 64)
    # Correspondence precedes the signer pin, which precedes expiry.
    assert result["reason"] == "EVIDENCE_CORRESPONDENCE_MISMATCH"
    ok = permit_for(env, reservation_of(env), private_key)
    pinned_wrong = verify_cycles_permit_receipt(ok, evidence=env, now=issued + timedelta(days=3), expected_signer="f" * 64)
    assert pinned_wrong["reason"] == "SIGNATURE_INVALID"
    expired = verify_cycles_permit_receipt(ok, evidence=env, now=issued + timedelta(days=3))
    assert expired["reason"] == "EXPIRED"


# ── Shape checks and fail closed behaviour ───────────────────────────────


def test_cycles_evidence_that_is_not_an_object_is_missing_required_field() -> None:
    private_key, _ = keypair()
    issued = permit(private_key)
    for value in ([], ["x"], "text", 5, None):
        broken = resign(issued, private_key, cycles_evidence=value) if value is not None else {
            k: v for k, v in issued.items() if k != "cycles_evidence"
        }
        assert_fail(verify_cycles_permit_receipt(broken), "MISSING_REQUIRED_FIELD", "cycles_evidence")


def test_scope_of_claim_that_is_not_an_object_is_missing_required_field() -> None:
    private_key, _ = keypair()
    issued = permit(private_key)
    for value in ([], ["asserts"], "asserts", 5):
        broken = resign(issued, private_key, scope_of_claim=value)
        assert_fail(verify_cycles_permit_receipt(broken), "MISSING_REQUIRED_FIELD", "scope_of_claim")
    not_a_string = resign(issued, private_key, scope_of_claim={**issued["scope_of_claim"], "asserts": 5})
    assert_fail(verify_cycles_permit_receipt(not_a_string), "MISSING_REQUIRED_FIELD", "scope_of_claim")


@pytest.mark.parametrize("bad", [None, [], "text", 5, 1.5, True, (), b"bytes"])
def test_receipt_that_is_not_a_dict_is_a_structured_failure(bad: Any) -> None:
    for verify in (verify_cycles_permit_receipt, verify_cycles_release_receipt, verify_cycles_denial):
        result = verify(bad)
        assert result["valid"] is False
        assert result["reason"] == "SIGNATURE_INVALID"
        assert result["detail"].startswith("receipt ")


@pytest.mark.parametrize("bad", [[], "text", 5, True, b"bytes", {"a": object()}])
def test_envelope_that_is_not_an_object_is_a_hash_mismatch(bad: Any) -> None:
    private_key, _ = keypair()
    receipt = permit_bound_to(reserve_envelope(), private_key)
    result = verify_cycles_permit_receipt(receipt, evidence=bad)
    assert_fail(result, "EVIDENCE_REF_HASH_MISMATCH", "envelope ")


def non_json_values() -> list[Any]:
    return [
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        {1, 2},
        b"bytes",
        float("nan"),
        float("inf"),
        object(),
        "\ud800",
    ]


def test_non_json_values_in_a_receipt_fail_closed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for value in non_json_values():
        for verify in (verify_cycles_permit_receipt, verify_cycles_release_receipt, verify_cycles_denial):
            result = verify({**receipt, "extra": value})
            assert_fail(result, "SIGNATURE_INVALID", "receipt has no canonical JSON form")
        nested = {**receipt, "scope_of_claim": {**receipt["scope_of_claim"], "does_not_assert": [value]}}
        assert_fail(verify_cycles_permit_receipt(nested), "SIGNATURE_INVALID", "receipt has no")


def test_non_json_values_in_an_envelope_fail_closed() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    for value in non_json_values():
        for verify in (verify_cycles_permit_receipt, verify_cycles_denial):
            result = verify(receipt, evidence={**env, "extra": value})
            assert_fail(result, "EVIDENCE_REF_HASH_MISMATCH", "envelope has no canonical JSON form")


def test_non_string_keys_fail_closed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for key in (1, None, (1, 2), True):
        assert_fail(verify_cycles_permit_receipt({**receipt, key: "x"}), "SIGNATURE_INVALID", "receipt has no canonical JSON form")


def nested(depth: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    node = root
    for _ in range(depth):
        child: dict[str, Any] = {}
        node["child"] = child
        node = child
    return root


def test_deeply_nested_receipt_fails_closed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    for depth in (500, 3000, 100_000):
        assert_fail(verify_cycles_permit_receipt({**receipt, "extra": nested(depth)}), "SIGNATURE_INVALID", "receipt has no")
        lists: Any = []
        for _ in range(depth):
            lists = [lists]
        assert_fail(verify_cycles_permit_receipt({**receipt, "extra": lists}), "SIGNATURE_INVALID", "receipt has no")


def test_deeply_nested_envelope_fails_closed() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    for depth in (500, 3000, 100_000):
        assert_fail(verify_cycles_permit_receipt(receipt, evidence={**env, "extra": nested(depth)}), "EVIDENCE_REF_HASH_MISMATCH", "envelope has no")


def test_self_referencing_containers_fail_closed() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    loop: dict[str, Any] = {}
    loop["self"] = loop
    assert_fail(verify_cycles_permit_receipt({**receipt, "extra": loop}), "SIGNATURE_INVALID", "receipt has no")
    assert_fail(verify_cycles_permit_receipt(receipt, evidence={**env, "extra": loop}), "EVIDENCE_REF_HASH_MISMATCH", "envelope has no")
    ring: list[Any] = []
    ring.append(ring)
    assert_fail(verify_cycles_permit_receipt({**receipt, "extra": ring}), "SIGNATURE_INVALID", "receipt has no")


def test_shared_substructure_that_expands_exponentially_fails_closed() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    layer: list[Any] = [0]
    for _ in range(60):
        layer = [layer, layer]
    assert_fail(verify_cycles_permit_receipt({**receipt, "extra": layer}), "SIGNATURE_INVALID", "receipt has no")


def test_dict_subclasses_and_ordered_dicts_verify_like_dicts() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    assert verify_cycles_permit_receipt(OrderedDict(reversed(list(receipt.items()))), evidence=OrderedDict(env)) == {
        "valid": True,
        "evidence_authenticity": "signature_valid",
    }


def test_a_receipt_is_read_once_through_capture() -> None:
    """A dict whose answers change between reads cannot make verification read
    two different receipts. Capture reads each member once. The hash, the
    signature and the correspondence check all see the captured copy."""
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_for(env, reservation_of(env), private_key)
    reads = {"reservation_id": 0}

    class Flipping(dict):  # type: ignore[type-arg]
        def __getitem__(self, key: str) -> Any:
            if key == "reservation_id":
                reads["reservation_id"] += 1
                if reads["reservation_id"] > 1:
                    return "rsv_changed"
            return super().__getitem__(key)

    result = verify_cycles_permit_receipt(Flipping(receipt), evidence=env)
    assert result == {"valid": True, "evidence_authenticity": "signature_valid"}
    assert reads["reservation_id"] == 1


def test_option_types_are_checked() -> None:
    private_key, _ = keypair()
    receipt = permit(private_key)
    with pytest.raises(TypeError):
        verify_cycles_permit_receipt(receipt, now="today")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_cycles_permit_receipt(receipt, ttl_seconds="60")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_cycles_permit_receipt(receipt, ttl_seconds=True)
    with pytest.raises(TypeError):
        verify_cycles_permit_receipt(receipt, expected_signer=5)  # type: ignore[arg-type]


def test_signature_and_signer_must_be_exact_length_hex() -> None:
    private_key, public_key = keypair()
    receipt = permit(private_key)
    signature = receipt["signature"]
    for bad in (signature[:-2], signature + "00", "", None, 5, " " * 128, signature[:64] + " " + signature[65:]):
        assert verify_cycles_permit_receipt({**receipt, "signature": bad})["valid"] is False, bad
    spaced = {**receipt, "signer": public_key[:32] + " " + public_key[32:]}
    assert verify_cycles_permit_receipt(spaced)["valid"] is False
    # Hex digits of either case are accepted, as the TypeScript verify does.
    assert verify_cycles_permit_receipt({**receipt, "signature": signature.upper()}) == {"valid": True}


def test_verify_never_mutates_its_inputs() -> None:
    private_key, _ = keypair()
    env = reserve_envelope()
    receipt = permit_bound_to(env, private_key)
    receipt_before, env_before = copy.deepcopy(receipt), copy.deepcopy(env)
    verify_cycles_permit_receipt(receipt, evidence=env)
    assert receipt == receipt_before and env == env_before
