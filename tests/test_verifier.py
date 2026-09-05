from __future__ import annotations

import unittest
from copy import deepcopy
from datetime import datetime

from mergegrounds_verifier.crypto import verify_document
from mergegrounds_verifier.verifier import VerificationError, verify
from tests.helpers import DECISION_PUBLIC, NOW, evidence, policy, private, resign, subject


class VerifierDecisionTests(unittest.TestCase):
    def test_single_passing_control_admits(self) -> None:
        active = policy()
        decision = verify(active, subject(), [evidence(active)], now=NOW)
        self.assertEqual("admit", decision["decision"])
        self.assertEqual([], decision["reason_codes"])
        self.assertTrue(decision["controls"][0]["satisfied"])

    def test_all_required_controls_must_pass(self) -> None:
        active = policy(controls=("MG-A", "MG-B"))
        documents = [
            evidence(active, "MG-A"),
            evidence(active, "MG-B", evidence_id="9a04077d-e8b2-478c-8822-1b3d68b93a92"),
        ]
        self.assertEqual("admit", verify(active, subject(), documents, now=NOW)["decision"])

    def test_missing_control_denies(self) -> None:
        active = policy(controls=("MG-A", "MG-B"))
        decision = verify(active, subject(), [evidence(active, "MG-A")], now=NOW)
        self.assertEqual("deny", decision["decision"])
        self.assertIn("MISSING_CONTROL", decision["reason_codes"])

    def test_fail_denies(self) -> None:
        active = policy()
        decision = verify(active, subject(), [evidence(active, state="fail")], now=NOW)
        self.assertEqual("deny", decision["decision"])
        self.assertIn("CONTROL_FAILED", decision["reason_codes"])

    def test_not_evaluated_denies(self) -> None:
        active = policy()
        decision = verify(active, subject(), [evidence(active, state="not_evaluated")], now=NOW)
        self.assertEqual("deny", decision["decision"])
        self.assertIn("CONTROL_NOT_EVALUATED", decision["reason_codes"])

    def test_valid_waiver_satisfies_waivable_control(self) -> None:
        active = policy(waivable=True)
        decision = verify(active, subject(), [evidence(active, state="waived")], now=NOW)
        self.assertEqual("admit", decision["decision"])
        self.assertEqual("waived", decision["controls"][0]["state"])

    def test_waiver_cannot_satisfy_nonwaivable_control(self) -> None:
        active = policy(waivable=False)
        document = evidence(active, state="waived")
        decision = verify(active, subject(), [document], now=NOW)
        self.assertEqual("deny", decision["decision"])
        self.assertIn("WAIVER_PROHIBITED", decision["reason_codes"])

    def test_decision_can_be_signed(self) -> None:
        active = policy()
        decision = verify(
            active,
            subject(),
            [evidence(active)],
            now=NOW,
            decision_private_key=private("decision"),
            decision_key_id="decision-2026-09",
        )
        self.assertTrue(decision["signed"])
        self.assertTrue(verify_document(decision, DECISION_PUBLIC))

    def test_decision_private_key_must_match_policy_key(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError) as caught:
            verify(
                active,
                subject(),
                [evidence(active)],
                now=NOW,
                decision_private_key=private("rogue"),
                decision_key_id="decision-2026-09",
            )
        self.assertEqual("DECISION_SIGNING_CONFIG_INVALID", caught.exception.code)

    def test_decision_key_id_must_be_policy_trusted(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError) as caught:
            verify(
                active,
                subject(),
                [evidence(active)],
                now=NOW,
                decision_private_key=private("decision"),
                decision_key_id="unknown-decision-key",
            )
        self.assertEqual("DECISION_SIGNING_CONFIG_INVALID", caught.exception.code)

    def test_decision_key_requires_key_id(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError):
            verify(
                active,
                subject(),
                [evidence(active)],
                now=NOW,
                decision_private_key=private("decision"),
            )

    def test_decision_key_id_requires_private_key(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError):
            verify(
                active,
                subject(),
                [evidence(active)],
                now=NOW,
                decision_key_id="decision-2026-09",
            )

    def test_evidence_collection_must_be_list(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError) as caught:
            verify(active, subject(), {}, now=NOW)  # type: ignore[arg-type]
        self.assertEqual("EVIDENCE_INPUT_INVALID", caught.exception.code)

    def test_evaluation_time_must_be_timezone_aware(self) -> None:
        active = policy()
        with self.assertRaises(VerificationError) as caught:
            verify(active, subject(), [evidence(active)], now=datetime(2026, 9, 5, 12))
        self.assertEqual("EVALUATION_TIME_INVALID", caught.exception.code)

    def test_unsigned_decision_is_explicit(self) -> None:
        active = policy()
        decision = verify(active, subject(), [evidence(active)], now=NOW)
        self.assertFalse(decision["signed"])
        self.assertNotIn("signature", decision)

    def test_same_inputs_and_time_are_deterministic(self) -> None:
        active = policy()
        documents = [evidence(active)]
        first = verify(active, subject(), documents, now=NOW)
        second = verify(active, subject(), documents, now=NOW)
        self.assertEqual(first, second)

    def test_issue_order_is_deterministic(self) -> None:
        active = policy(controls=("MG-A", "MG-B"))
        first = verify(active, subject(), [], now=NOW)
        second = verify(active, subject(), [], now=NOW)
        self.assertEqual(first["issues"], second["issues"])

    def test_policy_change_invalidates_existing_evidence(self) -> None:
        original = policy()
        document = evidence(original)
        changed = deepcopy(original)
        changed["version"] = "2026.09.2"
        decision = verify(changed, subject(), [document], now=NOW)
        self.assertIn("POLICY_BINDING_MISMATCH", decision["reason_codes"])

    def test_resigning_after_policy_change_is_not_enough_without_binding_change(self) -> None:
        original = policy()
        document = evidence(original)
        changed = deepcopy(original)
        changed["clock_skew_seconds"] = 30
        document = resign(document)
        decision = verify(changed, subject(), [document], now=NOW)
        self.assertIn("POLICY_BINDING_MISMATCH", decision["reason_codes"])


if __name__ == "__main__":
    unittest.main()
