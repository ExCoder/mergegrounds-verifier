from __future__ import annotations

import unittest
from copy import deepcopy

from mergegrounds_verifier.schema import SCHEMAS, validation_messages, validator
from mergegrounds_verifier.verifier import verify
from tests.helpers import NOW, evidence, policy, subject


class SchemaTests(unittest.TestCase):
    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        for kind in SCHEMAS:
            with self.subTest(kind=kind):
                self.assertIsNotNone(validator(kind))

    def test_standalone_and_embedded_waiver_scope_caps_match(self) -> None:
        waiver_scope = validator("waiver").schema["$defs"]["waiver"]["properties"]["scope"]
        evidence_schema = validator("evidence").schema
        embedded_scope_ref = evidence_schema["$defs"]["waiver"]["properties"]["scope"]["$ref"]
        embedded_scope = evidence_schema["$defs"][embedded_scope_ref.rsplit("/", 1)[-1]]
        self.assertEqual(100_000, waiver_scope["maxItems"])
        self.assertEqual(waiver_scope, embedded_scope)

    def test_unknown_schema_kind_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validator("unknown")

    def test_valid_subject(self) -> None:
        self.assertEqual([], validation_messages("subject", subject()))

    def test_subject_rejects_unknown_field(self) -> None:
        value = subject()
        value["branch"] = "main"
        self.assertTrue(validation_messages("subject", value))

    def test_subject_rejects_uppercase_commit(self) -> None:
        value = subject()
        value["commit"] = "A" * 40
        self.assertTrue(validation_messages("subject", value))

    def test_policy_rejects_unknown_top_level_field(self) -> None:
        value = policy()
        value["allow_on_error"] = True
        self.assertTrue(validation_messages("policy", value))

    def test_policy_rejects_unknown_nested_field(self) -> None:
        value = policy()
        value["required_controls"][0]["fallback"] = "pass"
        self.assertTrue(validation_messages("policy", value))

    def test_evidence_rejects_unknown_top_level_field(self) -> None:
        active = policy()
        value = evidence(active)
        value["score"] = 1.0
        self.assertTrue(validation_messages("evidence", value))

    def test_evidence_rejects_unknown_nested_field(self) -> None:
        active = policy()
        value = evidence(active)
        value["result"]["vendor_state"] = "green"
        self.assertTrue(validation_messages("evidence", value))

    def test_evidence_rejects_noncanonical_uuid(self) -> None:
        active = policy()
        value = evidence(active)
        value["evidence_id"] = value["evidence_id"].upper()
        self.assertTrue(validation_messages("evidence", value))

    def test_decision_rejects_non_utc_timestamp(self) -> None:
        active = policy()
        value = verify(active, subject(), [evidence(active)], now=NOW)
        value["evaluated_at"] = "2026-09-05T12:00:00+00:00"
        self.assertTrue(validation_messages("decision", value))

    def test_evidence_rejects_duplicate_scope_items(self) -> None:
        active = policy()
        value = evidence(active)
        value["scope"]["expected"] = ["repository", "repository"]
        self.assertTrue(validation_messages("evidence", value))

    def test_waived_state_requires_waiver(self) -> None:
        active = policy()
        value = evidence(active)
        value["result"] = {"state": "waived", "complete": True, "findings": []}
        self.assertTrue(validation_messages("evidence", value))

    def test_nonwaived_state_rejects_waiver(self) -> None:
        active = policy()
        value = evidence(active, state="waived")
        value["result"]["state"] = "pass"
        self.assertTrue(validation_messages("evidence", value))

    def test_signature_requires_exact_closed_fields(self) -> None:
        active = policy()
        value = deepcopy(evidence(active))
        value["signature"]["certificate"] = "candidate-controlled"
        self.assertTrue(validation_messages("evidence", value))


if __name__ == "__main__":
    unittest.main()
