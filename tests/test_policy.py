from __future__ import annotations

import unittest

from mergegrounds_verifier.verifier import VerificationError, validate_policy, validate_subject
from tests.helpers import policy, subject


class PolicySemanticTests(unittest.TestCase):
    def assert_policy_error(self, value: dict, code: str) -> None:
        with self.assertRaises(VerificationError) as caught:
            validate_policy(value)
        self.assertEqual(code, caught.exception.code)

    def test_valid_policy(self) -> None:
        validate_policy(policy())

    def test_policy_schema_error_is_typed(self) -> None:
        value = policy()
        value["unexpected"] = True
        self.assert_policy_error(value, "POLICY_SCHEMA_INVALID")

    def test_float_encoded_document_limit_is_rejected_semantically(self) -> None:
        value = policy()
        value["max_evidence_documents"] = 64.0
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_duplicate_key_ids_are_rejected(self) -> None:
        value = policy()
        value["trusted_keys"].append(dict(value["trusted_keys"][0]))
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_duplicate_producers_are_rejected(self) -> None:
        value = policy()
        value["trusted_producers"].append(dict(value["trusted_producers"][0]))
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_evidence_key_cannot_be_shared_between_producer_identities(self) -> None:
        value = policy()
        value["trusted_producers"].append(
            {
                "identity": "spiffe://verifier.test/producer/other",
                "key_ids": ["producer-2026-09"],
            }
        )
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_duplicate_controls_are_rejected(self) -> None:
        value = policy()
        value["required_controls"].append(dict(value["required_controls"][0]))
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_unknown_control_producer_is_rejected(self) -> None:
        value = policy()
        value["required_controls"][0]["allowed_producers"] = [
            "spiffe://verifier.test/producer/unknown"
        ]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_unknown_producer_key_is_rejected(self) -> None:
        value = policy()
        value["trusted_producers"][0]["key_ids"] = ["unknown"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_wrong_producer_key_purpose_is_rejected(self) -> None:
        value = policy()
        value["trusted_producers"][0]["key_ids"] = ["decision-2026-09"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_wrong_waiver_key_purpose_is_rejected(self) -> None:
        value = policy()
        value["waiver_authorities"][0]["key_ids"] = ["producer-2026-09"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_duplicate_waiver_authorities_are_rejected(self) -> None:
        value = policy()
        value["waiver_authorities"].append(dict(value["waiver_authorities"][0]))
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_waiver_key_cannot_be_shared_between_authority_identities(self) -> None:
        value = policy()
        value["waiver_authorities"].append(
            {
                "identity": "spiffe://verifier.test/authority/other",
                "key_ids": ["waiver-2026-09"],
            }
        )
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_producer_cannot_also_be_waiver_authority(self) -> None:
        value = policy()
        value["waiver_authorities"][0]["identity"] = value["trusted_producers"][0]["identity"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_unknown_waiver_authority_key_is_rejected(self) -> None:
        value = policy()
        value["waiver_authorities"][0]["key_ids"] = ["unknown"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_waivable_control_requires_authority(self) -> None:
        value = policy()
        value["waiver_authorities"] = []
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_nonwaivable_control_allows_no_authority(self) -> None:
        value = policy(waivable=False)
        value["waiver_authorities"] = []
        validate_policy(value)

    def test_malformed_public_key_is_rejected(self) -> None:
        value = policy()
        value["trusted_keys"][0]["public_key"] = "A" * 43
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_public_key_material_cannot_be_reused_across_purposes(self) -> None:
        value = policy()
        value["trusted_keys"][1]["public_key"] = value["trusted_keys"][0]["public_key"]
        self.assert_policy_error(value, "POLICY_SEMANTIC_INVALID")

    def test_equal_candidate_and_base_are_rejected(self) -> None:
        value = subject()
        value["base_commit"] = value["commit"]
        with self.assertRaises(VerificationError) as caught:
            validate_subject(value)
        self.assertEqual("SUBJECT_SEMANTIC_INVALID", caught.exception.code)

    def test_subject_schema_error_is_typed(self) -> None:
        value = subject()
        value["commit"] = "not-an-object-id"
        with self.assertRaises(VerificationError) as caught:
            validate_subject(value)
        self.assertEqual("SUBJECT_SCHEMA_INVALID", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
