from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mergegrounds_verifier.canonical import (
    StrictJSONError,
    _enforce_shape,
    canonical_text,
    load_strict,
    loads_strict,
    sha256_digest,
)
from mergegrounds_verifier.crypto import (
    CryptoError,
    b64url_decode,
    b64url_encode,
    public_key_from_text,
    verify_document,
)


class CanonicalJSONTests(unittest.TestCase):
    def test_keys_are_sorted_without_whitespace(self) -> None:
        self.assertEqual('{"a":1,"b":2}', canonical_text({"b": 2, "a": 1}))

    def test_unicode_is_not_ascii_escaped(self) -> None:
        self.assertEqual('{"value":"✓"}', canonical_text({"value": "✓"}))

    def test_duplicate_object_member_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"a":1,"a":2}')

    def test_nested_duplicate_object_member_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"outer":{"a":1,"a":2}}')

    def test_non_finite_number_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"value":NaN}')

    def test_overflowing_finite_syntax_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"value":1e9999}')

    def test_integer_exceeding_interpreter_limit_is_normalized_to_strict_error(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict("1" * 5000)

    def test_invalid_json_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict("{")

    def test_non_utf8_json_encoding_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"value":"not utf-8"}'.encode("utf-16"))

    def test_utf8_bom_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict(b'\xef\xbb\xbf{"value":"bom"}')

    def test_unpaired_unicode_surrogate_value_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"value":"\\ud800"}')

    def test_unpaired_unicode_surrogate_key_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            loads_strict('{"\\udfff":"value"}')

    def test_excessive_nesting_is_rejected(self) -> None:
        raw = "[" * 66 + "0" + "]" * 66
        with self.assertRaises(StrictJSONError):
            loads_strict(raw)

    def test_structural_node_limit_is_enforced(self) -> None:
        with self.assertRaises(StrictJSONError):
            _enforce_shape([1, 2], max_nodes=1)

    def test_file_size_limit_is_enforced_before_parse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "large.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(StrictJSONError):
                load_strict(path, max_bytes=1)

    def test_unsupported_canonical_value_is_rejected(self) -> None:
        with self.assertRaises(StrictJSONError):
            canonical_text({"not-json": {1, 2}})

    def test_digest_is_stable_across_key_order(self) -> None:
        self.assertEqual(sha256_digest({"a": 1, "b": 2}), sha256_digest({"b": 2, "a": 1}))

    def test_digest_is_sha256_prefixed(self) -> None:
        self.assertRegex(sha256_digest({}), r"^sha256:[0-9a-f]{64}$")

    def test_padded_base64url_is_rejected(self) -> None:
        with self.assertRaises(CryptoError):
            b64url_decode("AAAA=", expected_length=3)

    def test_noncanonical_base64url_is_rejected(self) -> None:
        with self.assertRaises(CryptoError):
            b64url_decode("AB", expected_length=1)

    def test_invalid_base64url_characters_are_rejected(self) -> None:
        with self.assertRaises(CryptoError):
            b64url_decode("***", expected_length=2)

    def test_base64url_length_is_checked(self) -> None:
        with self.assertRaises(CryptoError):
            b64url_decode("AA", expected_length=2)

    def test_low_order_ed25519_public_keys_are_rejected(self) -> None:
        field_prime = 2**255 - 19
        low_order_encodings = (
            bytes(32),
            bytes([1]) + bytes(31),
            (field_prime - 1).to_bytes(32, "little"),
        )
        for raw in low_order_encodings:
            with self.subTest(raw=raw.hex()), self.assertRaises(CryptoError):
                public_key_from_text(b64url_encode(raw))

    def test_identity_key_trivial_signature_is_rejected(self) -> None:
        identity = bytes([1]) + bytes(31)
        document = {
            "value": "arbitrary",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "identity",
                "value": b64url_encode(identity + bytes(32)),
            },
        }
        self.assertFalse(verify_document(document, b64url_encode(identity)))


if __name__ == "__main__":
    unittest.main()
