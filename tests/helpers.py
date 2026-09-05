from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mergegrounds_verifier.canonical import sha256_digest
from mergegrounds_verifier.crypto import load_private_key, sign_document

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)

PRODUCER_ID = "spiffe://verifier.test/producer/quality"
WAIVER_AUTHORITY_ID = "spiffe://verifier.test/authority/security"
PRODUCER_PUBLIC = "9q6WkUc98pmPifJdClxNugteRK-y7P9fPavCt-GRrFw"
WAIVER_PUBLIC = "ZbYtMr2XLssq6FoRWXshK5iz3I9jLfng5vRmdrSBcEM"
DECISION_PUBLIC = "ZNIGxIB2Lf2Zjz1GDaa2t9C16R77QCZXOKpr2i9DpR8"
ROGUE_PUBLIC = "Yq0EVtI91cTVCVDUgcNrMAwRDRrmnSFnmAJzBOA0lrc"


def private(name: str):
    return load_private_key(FIXTURES / f"{name}-private.pem")


def subject() -> dict[str, Any]:
    return {
        "schema": "https://mergegrounds.chawax.chatgpt.site/schemas/subject-v1.schema.json",
        "repository": "https://github.com/example/service",
        "commit": "a" * 40,
        "tree": "c" * 40,
        "base_commit": "b" * 40,
        "canonical_diff_digest": "sha256:" + "d" * 64,
    }


def subject_payload() -> dict[str, Any]:
    value = subject()
    value.pop("schema")
    return value


def policy(
    *, controls: tuple[str, ...] = ("MG-QUALITY-001",), waivable: bool = True
) -> dict[str, Any]:
    return {
        "schema": "https://mergegrounds.chawax.chatgpt.site/schemas/policy-v1.schema.json",
        "policy_id": "example/default",
        "version": "2026.09.1",
        "clock_skew_seconds": 60,
        "max_evidence_documents": 64,
        "trusted_keys": [
            {
                "key_id": "producer-2026-09",
                "algorithm": "ed25519",
                "purpose": "evidence",
                "public_key": PRODUCER_PUBLIC,
            },
            {
                "key_id": "waiver-2026-09",
                "algorithm": "ed25519",
                "purpose": "waiver",
                "public_key": WAIVER_PUBLIC,
            },
            {
                "key_id": "decision-2026-09",
                "algorithm": "ed25519",
                "purpose": "decision",
                "public_key": DECISION_PUBLIC,
            },
        ],
        "trusted_producers": [{"identity": PRODUCER_ID, "key_ids": ["producer-2026-09"]}],
        "waiver_authorities": [{"identity": WAIVER_AUTHORITY_ID, "key_ids": ["waiver-2026-09"]}],
        "required_controls": [
            {
                "id": control,
                "allowed_producers": [PRODUCER_ID],
                "allowed_isolation_classes": ["ephemeral-read-only-source"],
                "allowed_tool_digests": ["sha256:" + "1" * 64],
                "allowed_runner_image_digests": ["sha256:" + "2" * 64],
                "allowed_workflow_digests": ["sha256:" + "3" * 64],
                "max_age_seconds": 7200,
                "required_scope": ["repository"],
                "waivable": waivable,
            }
            for control in controls
        ],
    }


def binding(active_policy: dict[str, Any]) -> dict[str, str]:
    return {
        "policy_id": active_policy["policy_id"],
        "version": active_policy["version"],
        "digest": sha256_digest(active_policy),
    }


def finding() -> dict[str, str]:
    return {
        "fingerprint": "finding-1",
        "rule_id": "example.rule",
        "severity": "high",
        "message_digest": "sha256:" + "e" * 64,
    }


def waiver(active_policy: dict[str, Any], control: str, *, underlying: str) -> dict[str, Any]:
    unsigned = {
        "schema": "https://mergegrounds.chawax.chatgpt.site/schemas/waiver-v1.schema.json",
        "waiver_id": "59ff40cf-d453-438a-bf08-e5655b778dde",
        "subject": subject_payload(),
        "policy": binding(active_policy),
        "control_id": control,
        "scope": ["repository"],
        "underlying_state": underlying,
        "authority": WAIVER_AUTHORITY_ID,
        "reason": "Time-bounded operator-approved exception for a tracked risk.",
        "issued_at": "2026-09-05T11:53:00Z",
        "expires_at": "2026-09-05T12:53:00Z",
    }
    return sign_document(unsigned, private("waiver"), "waiver-2026-09")


def evidence(
    active_policy: dict[str, Any],
    control: str = "MG-QUALITY-001",
    *,
    state: str = "pass",
    evidence_id: str = "de117c2c-b3ec-48a1-b320-9d42b29b3492",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": state,
        "complete": state != "not_evaluated",
        "findings": [finding()] if state == "fail" else [],
    }
    if state == "waived":
        result["findings"] = [finding()]
        result["waiver"] = waiver(active_policy, control, underlying="fail")
    unsigned = {
        "schema": "https://mergegrounds.chawax.chatgpt.site/schemas/evidence-v1.schema.json",
        "information_class": "evidence",
        "evidence_id": evidence_id,
        "subject": subject_payload(),
        "control": {"id": control},
        "producer": {
            "identity": PRODUCER_ID,
            "isolation_class": "ephemeral-read-only-source",
            "tool_name": "example-runner",
            "tool_version": "1.0.0",
            "tool_digest": "sha256:" + "1" * 64,
            "runner_image_digest": "sha256:" + "2" * 64,
            "workflow_digest": "sha256:" + "3" * 64,
        },
        "invocation": {
            "id": "218a70ac-457b-4fb0-8bd3-abf66f0d8a59",
            "started_at": "2026-09-05T11:50:00Z",
            "finished_at": "2026-09-05T11:51:00Z",
            "attempt": 1,
        },
        "scope": {
            "expected": ["repository"],
            "evaluated": ["repository"],
            "omitted": [],
            "complete": True,
        },
        "result": result,
        "policy": binding(active_policy),
        "validity": {
            "issued_at": "2026-09-05T11:52:00Z",
            "expires_at": "2026-09-05T12:52:00Z",
        },
        "references": ["sha256:" + "4" * 64],
    }
    if state == "not_evaluated":
        unsigned["scope"] = {
            "expected": ["repository"],
            "evaluated": [],
            "omitted": [{"item": "repository", "reason": "runner unavailable"}],
            "complete": False,
        }
    return sign_document(unsigned, private("producer"), "producer-2026-09")


def resign(
    value: dict[str, Any], key_name: str = "producer", key_id: str = "producer-2026-09"
) -> dict[str, Any]:
    unsigned = deepcopy(value)
    unsigned.pop("signature", None)
    return sign_document(unsigned, private(key_name), key_id)
