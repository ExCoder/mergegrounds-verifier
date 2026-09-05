"""Fail-closed verification of subject-bound, signed evidence."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import sha256_digest
from .crypto import (
    CryptoError,
    public_key_from_text,
    public_key_text,
    sign_document,
    verify_document,
)
from .schema import validation_messages
from .timeutil import format_time, parse_time, utc_now


class VerificationError(ValueError):
    """Trusted configuration or invocation input is invalid."""

    def __init__(self, code: str, details: Iterable[str]):
        self.code = code
        self.details = tuple(details)
        super().__init__(f"{code}: {'; '.join(self.details)}")


@dataclass(frozen=True)
class Issue:
    code: str
    detail: str
    control_id: str | None = None
    evidence_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "detail": self.detail,
            "control_id": self.control_id,
            "evidence_id": self.evidence_id,
        }


@dataclass
class EvidenceRecord:
    document: dict[str, Any]
    digest: str
    control_id: str | None
    evidence_id: str | None
    state: str
    valid: bool = True


STABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


def _safe_control_id(value: Any) -> str | None:
    return value if isinstance(value, str) and STABLE_ID.fullmatch(value) else None


def _safe_evidence_id(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value else None


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return sorted(repeated)


def _subject_payload(subject: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in subject.items() if key != "schema"}


def _binding(policy: dict[str, Any]) -> dict[str, str]:
    return {
        "policy_id": policy["policy_id"],
        "version": policy["version"],
        "digest": sha256_digest(policy),
    }


def validate_policy(policy: Any) -> None:
    schema_errors = validation_messages("policy", policy)
    if schema_errors:
        raise VerificationError("POLICY_SCHEMA_INVALID", schema_errors)
    policy = cast(dict[str, Any], policy)

    errors: list[str] = []
    integer_fields = (
        ("clock_skew_seconds", policy["clock_skew_seconds"]),
        ("max_evidence_documents", policy["max_evidence_documents"]),
    )
    integer_fields += tuple(
        (f"required_controls[{index}].max_age_seconds", control["max_age_seconds"])
        for index, control in enumerate(policy["required_controls"])
    )
    for field, value in integer_fields:
        if type(value) is not int:
            errors.append(f"{field} must use an integral JSON representation")
    keys = {entry["key_id"]: entry for entry in policy["trusted_keys"]}
    duplicate_keys = _duplicates(entry["key_id"] for entry in policy["trusted_keys"])
    if duplicate_keys:
        errors.append(f"duplicate trusted key ids: {', '.join(duplicate_keys)}")
    duplicate_public_keys = _duplicates(entry["public_key"] for entry in policy["trusted_keys"])
    if duplicate_public_keys:
        reused_ids = sorted(
            entry["key_id"]
            for entry in policy["trusted_keys"]
            if entry["public_key"] in duplicate_public_keys
        )
        errors.append(
            "public key material must not be reused across trusted key ids: "
            + ", ".join(reused_ids)
        )
    for entry in policy["trusted_keys"]:
        try:
            public_key_from_text(entry["public_key"])
        except (CryptoError, ValueError) as exc:
            errors.append(f"invalid public key {entry['key_id']}: {exc}")

    producers = {entry["identity"]: entry for entry in policy["trusted_producers"]}
    duplicate_producers = _duplicates(entry["identity"] for entry in policy["trusted_producers"])
    if duplicate_producers:
        errors.append(f"duplicate producer identities: {', '.join(duplicate_producers)}")
    producer_key_owners: dict[str, str] = {}
    for producer in policy["trusted_producers"]:
        for key_id in producer["key_ids"]:
            previous_owner = producer_key_owners.setdefault(key_id, producer["identity"])
            if previous_owner != producer["identity"]:
                errors.append(
                    f"evidence key {key_id} is assigned to multiple producer identities: "
                    f"{previous_owner}, {producer['identity']}"
                )
            if key_id not in keys:
                errors.append(f"producer {producer['identity']} references unknown key {key_id}")
            elif keys[key_id]["purpose"] != "evidence":
                errors.append(
                    f"producer {producer['identity']} key {key_id} is not an evidence key"
                )

    authorities = {entry["identity"]: entry for entry in policy["waiver_authorities"]}
    duplicate_authorities = _duplicates(entry["identity"] for entry in policy["waiver_authorities"])
    if duplicate_authorities:
        errors.append(f"duplicate waiver authority identities: {', '.join(duplicate_authorities)}")
    overlapping_identities = sorted(producers.keys() & authorities.keys())
    if overlapping_identities:
        errors.append(
            "producer and waiver authority identities must be separate: "
            + ", ".join(overlapping_identities)
        )
    authority_key_owners: dict[str, str] = {}
    for authority in policy["waiver_authorities"]:
        for key_id in authority["key_ids"]:
            previous_owner = authority_key_owners.setdefault(key_id, authority["identity"])
            if previous_owner != authority["identity"]:
                errors.append(
                    f"waiver key {key_id} is assigned to multiple authority identities: "
                    f"{previous_owner}, {authority['identity']}"
                )
            if key_id not in keys:
                errors.append(
                    f"waiver authority {authority['identity']} references unknown key {key_id}"
                )
            elif keys[key_id]["purpose"] != "waiver":
                errors.append(
                    f"waiver authority {authority['identity']} key {key_id} is not a waiver key"
                )

    duplicate_controls = _duplicates(entry["id"] for entry in policy["required_controls"])
    if duplicate_controls:
        errors.append(f"duplicate required control ids: {', '.join(duplicate_controls)}")
    for control in policy["required_controls"]:
        for identity in control["allowed_producers"]:
            if identity not in producers:
                errors.append(f"control {control['id']} references unknown producer {identity}")
        if control["waivable"] and not authorities:
            errors.append(f"control {control['id']} is waivable but no waiver authority exists")

    if errors:
        raise VerificationError("POLICY_SEMANTIC_INVALID", sorted(errors))


def validate_subject(subject: Any) -> None:
    errors = validation_messages("subject", subject)
    if errors:
        raise VerificationError("SUBJECT_SCHEMA_INVALID", errors)
    subject = cast(dict[str, Any], subject)
    if subject["commit"] == subject["base_commit"]:
        raise VerificationError(
            "SUBJECT_SEMANTIC_INVALID", ["candidate commit must differ from base commit"]
        )


def validate_decision_signer(
    policy: dict[str, Any], private_key: Ed25519PrivateKey, key_id: str
) -> None:
    matching = [entry for entry in policy["trusted_keys"] if entry["key_id"] == key_id]
    if len(matching) != 1 or matching[0]["purpose"] != "decision":
        raise VerificationError(
            "DECISION_SIGNING_CONFIG_INVALID",
            ["decision key id is not a unique policy-trusted decision key"],
        )
    if matching[0]["public_key"] != public_key_text(private_key):
        raise VerificationError(
            "DECISION_SIGNING_CONFIG_INVALID",
            ["decision private key does not match the policy public key"],
        )


def _add(
    issues: list[Issue],
    record: EvidenceRecord,
    code: str,
    detail: str,
    *,
    valid: bool = False,
) -> None:
    issues.append(Issue(code, detail, record.control_id, record.evidence_id))
    if not valid:
        record.valid = False


def _verify_times(
    record: EvidenceRecord,
    control: dict[str, Any],
    now: datetime,
    skew: timedelta,
    issues: list[Issue],
) -> None:
    document = record.document
    try:
        started = parse_time(document["invocation"]["started_at"])
        finished = parse_time(document["invocation"]["finished_at"])
        issued = parse_time(document["validity"]["issued_at"])
        expires = parse_time(document["validity"]["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        _add(issues, record, "TIME_INVALID", str(exc))
        return
    if not started <= finished <= issued < expires:
        _add(
            issues,
            record,
            "TIME_ORDER_INVALID",
            "required ordering is started_at <= finished_at <= issued_at < expires_at",
        )
    if issued - now > skew:
        _add(issues, record, "EVIDENCE_FROM_FUTURE", "issued_at exceeds allowed clock skew")
    if expires <= now:
        _add(issues, record, "EVIDENCE_EXPIRED", "expires_at is at or before evaluation time")
    max_age = timedelta(seconds=control["max_age_seconds"])
    if now - issued > max_age:
        _add(issues, record, "EVIDENCE_STALE", "issued_at exceeds control max_age_seconds")
    if expires - issued > max_age:
        _add(
            issues,
            record,
            "EVIDENCE_TTL_TOO_LONG",
            "evidence validity interval exceeds control max_age_seconds",
        )


def _verify_scope(record: EvidenceRecord, control: dict[str, Any], issues: list[Issue]) -> None:
    scope = record.document["scope"]
    expected = set(scope["expected"])
    evaluated = set(scope["evaluated"])
    omitted_items = [entry["item"] for entry in scope["omitted"]]
    omitted = set(omitted_items)
    required = set(control["required_scope"])
    if expected != required:
        _add(issues, record, "SCOPE_MISMATCH", "declared expected scope differs from policy")
    if len(omitted_items) != len(omitted):
        _add(issues, record, "SCOPE_INVALID", "omitted scope items must be unique")
    if evaluated & omitted:
        _add(issues, record, "SCOPE_INVALID", "an item cannot be both evaluated and omitted")
    if evaluated | omitted != expected:
        _add(
            issues,
            record,
            "SCOPE_INCOMPLETE",
            "evaluated and omitted items do not reconcile to expected scope",
        )
    complete_should_be = evaluated == expected and not omitted
    if scope["complete"] != complete_should_be:
        _add(issues, record, "SCOPE_COMPLETENESS_FALSE", "scope.complete contradicts scope lists")


def _verify_waiver(
    record: EvidenceRecord,
    control: dict[str, Any],
    policy: dict[str, Any],
    subject_payload: dict[str, Any],
    policy_binding: dict[str, str],
    now: datetime,
    issues: list[Issue],
) -> None:
    waiver = record.document["result"].get("waiver")
    errors = validation_messages("waiver", waiver)
    if errors:
        _add(issues, record, "WAIVER_SCHEMA_INVALID", "; ".join(errors[:4]))
        return
    waiver = cast(dict[str, Any], waiver)
    if not control["waivable"]:
        _add(issues, record, "WAIVER_PROHIBITED", "policy marks this control non-waivable")
    if waiver["subject"] != subject_payload:
        _add(issues, record, "WAIVER_SUBJECT_MISMATCH", "waiver subject differs from request")
    if waiver["policy"] != policy_binding:
        _add(issues, record, "WAIVER_POLICY_MISMATCH", "waiver policy binding differs")
    if waiver["control_id"] != control["id"]:
        _add(issues, record, "WAIVER_CONTROL_MISMATCH", "waiver control differs")
    if set(waiver["scope"]) != set(control["required_scope"]):
        _add(issues, record, "WAIVER_SCOPE_MISMATCH", "waiver scope differs from policy")

    keys = {entry["key_id"]: entry for entry in policy["trusted_keys"]}
    authorities = {entry["identity"]: entry for entry in policy["waiver_authorities"]}
    authority = authorities.get(waiver["authority"])
    key_id = waiver["signature"]["key_id"]
    key = keys.get(key_id)
    if authority is None or key_id not in authority["key_ids"]:
        _add(issues, record, "WAIVER_AUTHORITY_UNTRUSTED", "authority/key is not allowed")
    elif key is None or key["purpose"] != "waiver":
        _add(issues, record, "WAIVER_KEY_UNTRUSTED", "waiver key has wrong trust purpose")
    elif not verify_document(waiver, key["public_key"]):
        _add(issues, record, "WAIVER_SIGNATURE_INVALID", "Ed25519 signature did not verify")

    try:
        issued = parse_time(waiver["issued_at"])
        expires = parse_time(waiver["expires_at"])
    except (TypeError, ValueError) as exc:
        _add(issues, record, "WAIVER_TIME_INVALID", str(exc))
        return
    skew = timedelta(seconds=policy["clock_skew_seconds"])
    if not issued < expires:
        _add(issues, record, "WAIVER_TIME_ORDER_INVALID", "issued_at must precede expires_at")
    if issued - now > skew:
        _add(issues, record, "WAIVER_FROM_FUTURE", "waiver exceeds allowed clock skew")
    if expires <= now:
        _add(issues, record, "WAIVER_EXPIRED", "waiver expires_at is at or before evaluation time")
    if expires - issued > timedelta(seconds=control["max_age_seconds"]):
        _add(issues, record, "WAIVER_TTL_TOO_LONG", "waiver TTL exceeds control max age")


def _verify_state(
    record: EvidenceRecord,
    control: dict[str, Any],
    policy: dict[str, Any],
    subject_payload: dict[str, Any],
    policy_binding: dict[str, str],
    now: datetime,
    issues: list[Issue],
) -> None:
    result = record.document["result"]
    scope = record.document["scope"]
    state = result["state"]
    findings = result["findings"]
    if state == "pass":
        if not result["complete"] or not scope["complete"]:
            _add(issues, record, "PASS_INCOMPLETE", "pass requires complete result and scope")
        if findings:
            _add(issues, record, "PASS_HAS_FINDINGS", "pass cannot contain findings")
    elif state == "fail":
        if not result["complete"]:
            _add(issues, record, "FAIL_INCOMPLETE", "fail must be a complete determination")
        if not findings:
            _add(issues, record, "FAIL_WITHOUT_FINDING", "fail requires at least one finding")
    elif state == "not_evaluated":
        if result["complete"]:
            _add(
                issues,
                record,
                "NOT_EVALUATED_MARKED_COMPLETE",
                "not_evaluated cannot be a complete determination",
            )
    elif state == "waived":
        if not result["complete"]:
            _add(issues, record, "WAIVER_RESULT_INCOMPLETE", "waived result must be complete")
        underlying = result["waiver"]["underlying_state"]
        if underlying == "fail" and not findings:
            _add(issues, record, "WAIVED_FAIL_WITHOUT_FINDING", "waived fail needs a finding")
        _verify_waiver(record, control, policy, subject_payload, policy_binding, now, issues)


def _verify_one(
    document: Any,
    policy: dict[str, Any],
    subject_payload: dict[str, Any],
    policy_binding: dict[str, str],
    controls: dict[str, dict[str, Any]],
    now: datetime,
    issues: list[Issue],
) -> EvidenceRecord:
    digest = sha256_digest(document)
    control_id = None
    evidence_id = None
    state = "not_evaluated"
    if isinstance(document, dict):
        control_value = document.get("control")
        if isinstance(control_value, dict):
            control_id = _safe_control_id(control_value.get("id"))
        evidence_id = _safe_evidence_id(document.get("evidence_id"))
        result_value = document.get("result")
        if isinstance(result_value, dict) and result_value.get("state") in {
            "pass",
            "fail",
            "not_evaluated",
            "waived",
        }:
            state = result_value["state"]
    record = EvidenceRecord(
        document if isinstance(document, dict) else {}, digest, control_id, evidence_id, state
    )

    schema_errors = validation_messages("evidence", document)
    if schema_errors:
        _add(
            issues,
            record,
            "EVIDENCE_SCHEMA_INVALID",
            "; ".join(schema_errors[:4]),
        )
        return record
    document = cast(dict[str, Any], document)
    control = controls.get(control_id or "")
    if control is None:
        _add(issues, record, "UNKNOWN_CONTROL", "evidence control is not required by policy")
        return record

    if document["subject"] != subject_payload:
        _add(issues, record, "SUBJECT_MISMATCH", "evidence subject differs from trusted subject")
    if document["policy"] != policy_binding:
        _add(
            issues,
            record,
            "POLICY_BINDING_MISMATCH",
            "evidence does not bind the exact active policy",
        )

    producer_identity = document["producer"]["identity"]
    producers = {entry["identity"]: entry for entry in policy["trusted_producers"]}
    producer = producers.get(producer_identity)
    if producer_identity not in control["allowed_producers"] or producer is None:
        _add(issues, record, "UNTRUSTED_PRODUCER", "producer is not allowed for control")
    if document["producer"]["isolation_class"] not in control["allowed_isolation_classes"]:
        _add(issues, record, "ISOLATION_CLASS_MISMATCH", "isolation class is not allowed")
    digest_controls = (
        ("tool_digest", "allowed_tool_digests", "TOOL_DIGEST_MISMATCH"),
        (
            "runner_image_digest",
            "allowed_runner_image_digests",
            "RUNNER_IMAGE_DIGEST_MISMATCH",
        ),
        ("workflow_digest", "allowed_workflow_digests", "WORKFLOW_DIGEST_MISMATCH"),
    )
    for evidence_field, policy_field, issue_code in digest_controls:
        if document["producer"][evidence_field] not in control[policy_field]:
            _add(
                issues,
                record,
                issue_code,
                f"producer {evidence_field} is not allowlisted for control",
            )

    key_id = document["signature"]["key_id"]
    keys = {entry["key_id"]: entry for entry in policy["trusted_keys"]}
    key = keys.get(key_id)
    if producer is None or key_id not in producer["key_ids"]:
        _add(issues, record, "UNTRUSTED_EVIDENCE_KEY", "key is not bound to producer")
    elif key is None or key["purpose"] != "evidence":
        _add(issues, record, "UNTRUSTED_EVIDENCE_KEY", "key has wrong trust purpose")
    elif not verify_document(document, key["public_key"]):
        _add(issues, record, "EVIDENCE_SIGNATURE_INVALID", "Ed25519 signature did not verify")

    _verify_times(
        record,
        control,
        now,
        timedelta(seconds=policy["clock_skew_seconds"]),
        issues,
    )
    _verify_scope(record, control, issues)
    _verify_state(record, control, policy, subject_payload, policy_binding, now, issues)
    return record


def verify(
    policy: dict[str, Any],
    subject: dict[str, Any],
    evidence: list[Any],
    *,
    now: datetime | None = None,
    decision_private_key: Ed25519PrivateKey | None = None,
    decision_key_id: str | None = None,
) -> dict[str, Any]:
    """Verify all required controls and return a deterministic admission decision.

    Determinism includes the explicit evaluation time. Calling code should pass
    ``now`` when replaying a decision; the CLI's ``--now`` option does this.
    """

    validate_policy(policy)
    validate_subject(subject)
    if not isinstance(evidence, list):
        raise VerificationError("EVIDENCE_INPUT_INVALID", ["evidence must be a JSON array"])
    if decision_private_key is not None and not decision_key_id:
        raise VerificationError(
            "DECISION_SIGNING_CONFIG_INVALID", ["decision_key_id is required with a key"]
        )
    if decision_private_key is None and decision_key_id:
        raise VerificationError(
            "DECISION_SIGNING_CONFIG_INVALID", ["decision key is required with key id"]
        )
    if decision_private_key is not None:
        validate_decision_signer(policy, decision_private_key, cast(str, decision_key_id))

    if now is not None and now.tzinfo is None:
        raise VerificationError(
            "EVALUATION_TIME_INVALID", ["evaluation time must be timezone-aware"]
        )
    evaluation_time = (now or utc_now()).astimezone(UTC)
    binding = _binding(policy)
    subject_payload = _subject_payload(subject)
    controls = {entry["id"]: entry for entry in policy["required_controls"]}
    issues: list[Issue] = []

    if len(evidence) > policy["max_evidence_documents"]:
        issues.append(
            Issue(
                "TOO_MANY_EVIDENCE_DOCUMENTS",
                "evidence count exceeds policy max_evidence_documents",
            )
        )

    records = [
        _verify_one(item, policy, subject_payload, binding, controls, evaluation_time, issues)
        for item in evidence[: policy["max_evidence_documents"]]
    ]

    by_id: dict[str, list[EvidenceRecord]] = {}
    by_control: dict[str, list[EvidenceRecord]] = {}
    for record in records:
        if record.evidence_id:
            by_id.setdefault(record.evidence_id, []).append(record)
        if record.control_id in controls:
            by_control.setdefault(record.control_id or "", []).append(record)

    for _evidence_id, duplicates in sorted(by_id.items()):
        if len(duplicates) > 1:
            for record in duplicates:
                _add(
                    issues,
                    record,
                    "DUPLICATE_EVIDENCE_ID",
                    f"evidence_id occurs {len(duplicates)} times",
                )

    for _control_id, candidates in sorted(by_control.items()):
        if len(candidates) > 1:
            distinct = {record.digest for record in candidates}
            code = "DUPLICATE_EVIDENCE" if len(distinct) == 1 else "CONFLICTING_EVIDENCE"
            for record in candidates:
                _add(
                    issues,
                    record,
                    code,
                    f"control has {len(candidates)} evidence documents",
                )

    summaries: list[dict[str, Any]] = []
    for control_id in sorted(controls):
        candidates = sorted(
            by_control.get(control_id, []),
            key=lambda record: (record.digest, record.evidence_id or ""),
        )
        if not candidates:
            issues.append(Issue("MISSING_CONTROL", "required evidence is absent", control_id))
            summaries.append(
                {
                    "control_id": control_id,
                    "state": "not_evaluated",
                    "satisfied": False,
                    "evidence_id": None,
                    "evidence_digest": None,
                }
            )
            continue
        candidate = candidates[0]
        state = candidate.state if len(candidates) == 1 and candidate.valid else "not_evaluated"
        satisfied = state in {"pass", "waived"} and candidate.valid
        if candidate.valid and state == "fail":
            issues.append(
                Issue("CONTROL_FAILED", "control reported fail", control_id, candidate.evidence_id)
            )
        elif candidate.valid and state == "not_evaluated":
            issues.append(
                Issue(
                    "CONTROL_NOT_EVALUATED",
                    "control did not produce a determination",
                    control_id,
                    candidate.evidence_id,
                )
            )
        summaries.append(
            {
                "control_id": control_id,
                "state": state,
                "satisfied": satisfied,
                "evidence_id": candidate.evidence_id,
                "evidence_digest": candidate.digest,
            }
        )

    unique_issues = {
        (issue.code, issue.detail, issue.control_id, issue.evidence_id): issue for issue in issues
    }
    ordered_issues = [
        unique_issues[key]
        for key in sorted(
            unique_issues, key=lambda item: tuple("" if value is None else value for value in item)
        )
    ]
    reason_codes = sorted({issue.code for issue in ordered_issues})
    admitted = not ordered_issues and all(summary["satisfied"] for summary in summaries)
    decision: dict[str, Any] = {
        "schema": "https://mergegrounds.chawax.chatgpt.site/schemas/decision-v1.schema.json",
        "decision": "admit" if admitted else "deny",
        "evaluated_at": format_time(evaluation_time),
        "subject": subject_payload,
        "policy": binding,
        "controls": summaries,
        "evidence_digests": sorted({record.digest for record in records}),
        "reason_codes": reason_codes,
        "issues": [issue.as_dict() for issue in ordered_issues],
        "signed": decision_private_key is not None,
    }
    decision["decision_digest"] = sha256_digest(decision)
    if decision_private_key is not None:
        decision = sign_document(decision, decision_private_key, cast(str, decision_key_id))

    decision_errors = validation_messages("decision", decision)
    if decision_errors:
        raise RuntimeError(f"internal decision schema violation: {decision_errors}")
    return decision
