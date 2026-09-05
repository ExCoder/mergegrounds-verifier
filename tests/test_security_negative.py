from __future__ import annotations

import unittest
from copy import deepcopy
from unittest.mock import patch

from mergegrounds_verifier.canonical import sha256_digest
from mergegrounds_verifier.crypto import sign_document
from mergegrounds_verifier.verifier import verify
from tests.helpers import (
    NOW,
    PRODUCER_ID,
    evidence,
    finding,
    policy,
    private,
    resign,
    subject,
)


class NegativeVerificationTests(unittest.TestCase):
    def reason_codes(self, active: dict, document: dict) -> set[str]:
        return set(verify(active, subject(), [document], now=NOW)["reason_codes"])

    def assert_denied_with(self, active: dict, document: dict, code: str) -> None:
        decision = verify(active, subject(), [document], now=NOW)
        self.assertEqual("deny", decision["decision"])
        self.assertIn(code, decision["reason_codes"])

    def test_repository_binding_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["subject"]["repository"] = "https://github.com/attacker/fork"
        self.assert_denied_with(active, resign(document), "SUBJECT_MISMATCH")

    def test_commit_binding_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["subject"]["commit"] = "f" * 40
        self.assert_denied_with(active, resign(document), "SUBJECT_MISMATCH")

    def test_tree_binding_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["subject"]["tree"] = "f" * 40
        self.assert_denied_with(active, resign(document), "SUBJECT_MISMATCH")

    def test_base_binding_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["subject"]["base_commit"] = "f" * 40
        self.assert_denied_with(active, resign(document), "SUBJECT_MISMATCH")

    def test_diff_binding_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["subject"]["canonical_diff_digest"] = "sha256:" + "f" * 64
        self.assert_denied_with(active, resign(document), "SUBJECT_MISMATCH")

    def test_policy_digest_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["policy"]["digest"] = "sha256:" + "f" * 64
        self.assert_denied_with(active, resign(document), "POLICY_BINDING_MISMATCH")

    def test_policy_id_mismatch(self) -> None:
        active = policy()
        document = evidence(active)
        document["policy"]["policy_id"] = "attacker/policy"
        self.assert_denied_with(active, resign(document), "POLICY_BINDING_MISMATCH")

    def test_untrusted_producer(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["identity"] = "spiffe://attacker.invalid/producer"
        self.assert_denied_with(active, resign(document), "UNTRUSTED_PRODUCER")

    def test_wrong_isolation_class(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["isolation_class"] = "candidate-hosted"
        self.assert_denied_with(active, resign(document), "ISOLATION_CLASS_MISMATCH")

    def test_unallowlisted_tool_digest_denies(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["tool_digest"] = "sha256:" + "a" * 64
        self.assert_denied_with(active, resign(document), "TOOL_DIGEST_MISMATCH")

    def test_unallowlisted_runner_image_digest_denies(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["runner_image_digest"] = "sha256:" + "a" * 64
        self.assert_denied_with(active, resign(document), "RUNNER_IMAGE_DIGEST_MISMATCH")

    def test_unallowlisted_workflow_digest_denies(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["workflow_digest"] = "sha256:" + "a" * 64
        self.assert_denied_with(active, resign(document), "WORKFLOW_DIGEST_MISMATCH")

    def test_signature_tamper(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["tool_version"] = "attacker-rewrite"
        self.assert_denied_with(active, document, "EVIDENCE_SIGNATURE_INVALID")

    def test_rogue_signature_key(self) -> None:
        active = policy()
        document = evidence(active)
        document = resign(document, "rogue", "rogue-key")
        self.assert_denied_with(active, document, "UNTRUSTED_EVIDENCE_KEY")

    def test_expired_evidence(self) -> None:
        active = policy()
        document = evidence(active)
        document["validity"]["expires_at"] = "2026-09-05T11:59:59Z"
        self.assert_denied_with(active, resign(document), "EVIDENCE_EXPIRED")

    def test_evidence_expiring_at_evaluation_time_is_expired(self) -> None:
        active = policy()
        document = evidence(active)
        document["validity"]["expires_at"] = "2026-09-05T12:00:00Z"
        self.assert_denied_with(active, resign(document), "EVIDENCE_EXPIRED")

    def test_fractional_evaluation_time_is_not_truncated_before_expiry_check(self) -> None:
        active = policy()
        document = evidence(active)
        document["validity"]["expires_at"] = "2026-09-05T12:00:00.500000Z"
        decision = verify(
            active,
            subject(),
            [resign(document)],
            now=NOW.replace(microsecond=999_999),
        )
        self.assertEqual("deny", decision["decision"])
        self.assertIn("EVIDENCE_EXPIRED", decision["reason_codes"])
        self.assertEqual("2026-09-05T12:00:00.999999Z", decision["evaluated_at"])

    def test_default_clock_microseconds_are_not_truncated_before_expiry_check(self) -> None:
        active = policy()
        document = evidence(active)
        document["validity"]["expires_at"] = "2026-09-05T12:00:00.500000Z"
        with patch(
            "mergegrounds_verifier.verifier.utc_now",
            return_value=NOW.replace(microsecond=999_999),
        ):
            decision = verify(active, subject(), [resign(document)])
        self.assertEqual("deny", decision["decision"])
        self.assertIn("EVIDENCE_EXPIRED", decision["reason_codes"])

    def test_maximum_datetime_does_not_overflow_future_skew_check(self) -> None:
        active = policy()
        document = evidence(active)
        document["invocation"] = {
            "id": document["invocation"]["id"],
            "started_at": "9999-12-31T23:59:55Z",
            "finished_at": "9999-12-31T23:59:56Z",
            "attempt": 1,
        }
        document["validity"] = {
            "issued_at": "9999-12-31T23:59:57Z",
            "expires_at": "9999-12-31T23:59:59.900000Z",
        }
        decision = verify(
            active,
            subject(),
            [resign(document)],
            now=NOW.replace(
                year=9999,
                month=12,
                day=31,
                hour=23,
                minute=59,
                second=59,
            ),
        )
        self.assertEqual("admit", decision["decision"])

    def test_stale_evidence(self) -> None:
        active = policy()
        active["required_controls"][0]["max_age_seconds"] = 60
        document = evidence(active)
        document["validity"]["issued_at"] = "2026-09-05T11:52:00Z"
        document["validity"]["expires_at"] = "2026-09-05T12:00:30Z"
        self.assert_denied_with(active, resign(document), "EVIDENCE_STALE")

    def test_future_evidence(self) -> None:
        active = policy()
        document = evidence(active)
        document["invocation"]["started_at"] = "2026-09-05T12:01:00Z"
        document["invocation"]["finished_at"] = "2026-09-05T12:01:10Z"
        document["validity"]["issued_at"] = "2026-09-05T12:01:30Z"
        document["validity"]["expires_at"] = "2026-09-05T13:01:30Z"
        self.assert_denied_with(active, resign(document), "EVIDENCE_FROM_FUTURE")

    def test_invalid_time_order(self) -> None:
        active = policy()
        document = evidence(active)
        document["invocation"]["finished_at"] = "2026-09-05T11:49:00Z"
        self.assert_denied_with(active, resign(document), "TIME_ORDER_INVALID")

    def test_evidence_ttl_cannot_exceed_policy(self) -> None:
        active = policy()
        document = evidence(active)
        document["validity"]["expires_at"] = "2026-09-06T11:52:00Z"
        self.assert_denied_with(active, resign(document), "EVIDENCE_TTL_TOO_LONG")

    def test_expected_scope_must_equal_policy(self) -> None:
        active = policy()
        document = evidence(active)
        document["scope"]["expected"] = ["src/only.py"]
        document["scope"]["evaluated"] = ["src/only.py"]
        self.assert_denied_with(active, resign(document), "SCOPE_MISMATCH")

    def test_scope_lists_must_reconcile(self) -> None:
        active = policy()
        document = evidence(active)
        document["scope"]["evaluated"] = []
        document["scope"]["complete"] = False
        self.assert_denied_with(active, resign(document), "SCOPE_INCOMPLETE")

    def test_scope_cannot_evaluate_and_omit_same_item(self) -> None:
        active = policy()
        document = evidence(active)
        document["scope"]["omitted"] = [{"item": "repository", "reason": "contradictory omission"}]
        document["scope"]["complete"] = False
        self.assert_denied_with(active, resign(document), "SCOPE_INVALID")

    def test_omitted_scope_items_must_be_unique(self) -> None:
        active = policy()
        document = evidence(active, state="not_evaluated")
        document["scope"]["omitted"].append(dict(document["scope"]["omitted"][0]))
        self.assert_denied_with(active, resign(document), "SCOPE_INVALID")

    def test_scope_complete_must_match_lists(self) -> None:
        active = policy()
        document = evidence(active)
        document["scope"]["complete"] = False
        self.assert_denied_with(active, resign(document), "SCOPE_COMPLETENESS_FALSE")

    def test_pass_requires_complete_scope(self) -> None:
        active = policy()
        document = evidence(active)
        document["scope"]["evaluated"] = []
        document["scope"]["omitted"] = [
            {"item": "repository", "reason": "candidate asked us to skip it"}
        ]
        document["scope"]["complete"] = False
        self.assert_denied_with(active, resign(document), "PASS_INCOMPLETE")

    def test_pass_cannot_hide_findings(self) -> None:
        active = policy()
        document = evidence(active)
        document["result"]["findings"] = [finding()]
        self.assert_denied_with(active, resign(document), "PASS_HAS_FINDINGS")

    def test_fail_requires_finding(self) -> None:
        active = policy()
        document = evidence(active, state="fail")
        document["result"]["findings"] = []
        self.assert_denied_with(active, resign(document), "FAIL_WITHOUT_FINDING")

    def test_not_evaluated_cannot_be_complete(self) -> None:
        active = policy()
        document = evidence(active, state="not_evaluated")
        document["result"]["complete"] = True
        self.assert_denied_with(active, resign(document), "NOT_EVALUATED_MARKED_COMPLETE")

    def test_schema_unknown_field_denies(self) -> None:
        active = policy()
        document = evidence(active)
        document["allow_on_parse_error"] = True
        self.assert_denied_with(active, document, "EVIDENCE_SCHEMA_INVALID")

    def test_expired_waiver_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["expires_at"] = "2026-09-05T11:59:00Z"
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_EXPIRED")

    def test_waiver_expiring_at_evaluation_time_is_expired(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["expires_at"] = "2026-09-05T12:00:00Z"
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_EXPIRED")

    def test_waiver_subject_mismatch_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["subject"]["tree"] = "f" * 40
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_SUBJECT_MISMATCH")

    def test_waiver_signature_tamper_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        document["result"]["waiver"]["reason"] = "Attacker changed this already-valid explanation."
        self.assert_denied_with(active, resign(document), "WAIVER_SIGNATURE_INVALID")

    def test_waiver_policy_mismatch_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["policy"]["digest"] = "sha256:" + "0" * 64
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_POLICY_MISMATCH")

    def test_waiver_control_mismatch_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["control_id"] = "OTHER-CONTROL"
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_CONTROL_MISMATCH")

    def test_waiver_scope_mismatch_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["scope"] = ["component:other"]
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_SCOPE_MISMATCH")

    def test_future_waiver_denies(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["issued_at"] = "2026-09-05T12:02:00Z"
        nested["expires_at"] = "2026-09-05T12:30:00Z"
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_FROM_FUTURE")

    def test_waiver_ttl_cannot_exceed_control_age(self) -> None:
        active = policy()
        document = evidence(active, state="waived")
        nested = document["result"]["waiver"]
        nested["expires_at"] = "2026-09-06T11:53:00Z"
        nested = sign_document(
            {key: value for key, value in nested.items() if key != "signature"},
            private("waiver"),
            "waiver-2026-09",
        )
        document["result"]["waiver"] = nested
        self.assert_denied_with(active, resign(document), "WAIVER_TTL_TOO_LONG")

    def test_identical_duplicate_evidence_denies(self) -> None:
        active = policy()
        document = evidence(active)
        decision = verify(active, subject(), [document, deepcopy(document)], now=NOW)
        self.assertIn("DUPLICATE_EVIDENCE", decision["reason_codes"])
        self.assertIn("DUPLICATE_EVIDENCE_ID", decision["reason_codes"])

    def test_conflicting_evidence_for_control_denies(self) -> None:
        active = policy()
        first = evidence(active)
        second = evidence(
            active,
            state="fail",
            evidence_id="6aa435ac-2114-4fef-a838-5e68be9e0413",
        )
        decision = verify(active, subject(), [first, second], now=NOW)
        self.assertIn("CONFLICTING_EVIDENCE", decision["reason_codes"])

    def test_conflicting_evidence_order_does_not_change_decision(self) -> None:
        active = policy()
        first = evidence(active)
        second = evidence(
            active,
            state="fail",
            evidence_id="6aa435ac-2114-4fef-a838-5e68be9e0413",
        )
        forward = verify(active, subject(), [first, second], now=NOW)
        reverse = verify(active, subject(), [second, first], now=NOW)
        self.assertEqual(forward, reverse)

    def test_duplicate_id_across_controls_denies(self) -> None:
        active = policy(controls=("MG-A", "MG-B"))
        first = evidence(active, "MG-A")
        second = evidence(active, "MG-B")
        decision = verify(active, subject(), [first, second], now=NOW)
        self.assertIn("DUPLICATE_EVIDENCE_ID", decision["reason_codes"])

    def test_unknown_control_denies(self) -> None:
        active = policy()
        document = evidence(active)
        document["control"]["id"] = "ATTACKER-CONTROL"
        self.assert_denied_with(active, resign(document), "UNKNOWN_CONTROL")

    def test_document_limit_is_enforced(self) -> None:
        active = policy(controls=("MG-A", "MG-B"))
        active["max_evidence_documents"] = 1
        documents = [
            evidence(active, "MG-A"),
            evidence(active, "MG-B", evidence_id="6aa435ac-2114-4fef-a838-5e68be9e0413"),
        ]
        decision = verify(active, subject(), documents, now=NOW)
        self.assertIn("TOO_MANY_EVIDENCE_DOCUMENTS", decision["reason_codes"])
        self.assertIn("MISSING_CONTROL", decision["reason_codes"])

    def test_tool_digest_tamper_is_detected_by_signature(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["tool_digest"] = "sha256:" + "9" * 64
        self.assert_denied_with(active, document, "EVIDENCE_SIGNATURE_INVALID")

    def test_policy_digest_is_over_canonical_full_policy(self) -> None:
        active = policy()
        document = evidence(active)
        self.assertEqual(sha256_digest(active), document["policy"]["digest"])

    def test_producer_identity_binding_is_exact(self) -> None:
        active = policy()
        document = evidence(active)
        document["producer"]["identity"] = PRODUCER_ID + "/lookalike"
        self.assertIn("UNTRUSTED_PRODUCER", self.reason_codes(active, resign(document)))


if __name__ == "__main__":
    unittest.main()
