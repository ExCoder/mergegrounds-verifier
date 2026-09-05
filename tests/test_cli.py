from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from mergegrounds_verifier.canonical import sha256_digest
from mergegrounds_verifier.cli import main
from mergegrounds_verifier.crypto import signature_payload
from mergegrounds_verifier.schema import validation_messages
from tests.helpers import evidence, policy, private, subject


class CLITests(unittest.TestCase):
    def write_json(self, root: Path, name: str, value: object) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_policy_digest_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            policy_path = self.write_json(root, "policy.json", active)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["policy-digest", "--policy", str(policy_path)])
            self.assertEqual(0, status)
            self.assertEqual(sha256_digest(active), output.getvalue().strip())

    def test_policy_digest_invalid_policy_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", {"schema": "wrong"})
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(["policy-digest", "--policy", str(policy_path)]))

    def test_verify_command_admits(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            policy_path = self.write_json(root, "policy.json", active)
            subject_path = self.write_json(root, "subject.json", subject())
            evidence_path = self.write_json(root, "evidence.json", evidence(active))
            output_path = root / "decision.json"
            status = main(
                [
                    "verify",
                    "--policy",
                    str(policy_path),
                    "--subject",
                    str(subject_path),
                    "--evidence",
                    str(evidence_path),
                    "--now",
                    "2026-09-05T12:00:00Z",
                    "--output",
                    str(output_path),
                ]
            )
            self.assertEqual(0, status)
            self.assertEqual("admit", json.loads(output_path.read_text())["decision"])

    def test_verify_command_returns_one_for_policy_denial(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            policy_path = self.write_json(root, "policy.json", active)
            subject_path = self.write_json(root, "subject.json", subject())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "verify",
                        "--policy",
                        str(policy_path),
                        "--subject",
                        str(subject_path),
                        "--now",
                        "2026-09-05T12:00:00Z",
                    ]
                )
            self.assertEqual(1, status)
            self.assertEqual("deny", json.loads(output.getvalue())["decision"])

    def test_verify_command_reports_unwritable_output_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            policy_path = self.write_json(root, "policy.json", active)
            subject_path = self.write_json(root, "subject.json", subject())
            evidence_path = self.write_json(root, "evidence.json", evidence(active))
            output_path = root / "missing" / "decision.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "verify",
                        "--policy",
                        str(policy_path),
                        "--subject",
                        str(subject_path),
                        "--evidence",
                        str(evidence_path),
                        "--now",
                        "2026-09-05T12:00:00Z",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(2, status)
            self.assertIn("unable to write verification result", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_invalid_json_fails_closed_with_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = root / "policy.json"
            policy_path.write_text('{"a":1,"a":2}', encoding="utf-8")
            subject_path = self.write_json(root, "subject.json", subject())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "verify",
                        "--policy",
                        str(policy_path),
                        "--subject",
                        str(subject_path),
                    ]
                )
            self.assertEqual(2, status)
            self.assertEqual("deny", json.loads(output.getvalue())["decision"])

    def test_sign_command_creates_schema_valid_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            unsigned = evidence(active)
            unsigned.pop("signature")
            input_path = self.write_json(root, "unsigned.json", unsigned)
            output_path = root / "signed.json"
            fixture = Path(__file__).parent / "fixtures" / "producer-private.pem"
            status = main(
                [
                    "sign",
                    "--kind",
                    "evidence",
                    "--input",
                    str(input_path),
                    "--private-key",
                    str(fixture),
                    "--key-id",
                    "producer-2026-09",
                    "--output",
                    str(output_path),
                ]
            )
            self.assertEqual(0, status)
            self.assertEqual(
                [], validation_messages("evidence", json.loads(output_path.read_text()))
            )

    def test_sign_refuses_to_replace_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            input_path = self.write_json(root, "signed.json", evidence(active))
            output_path = root / "out.json"
            fixture = Path(__file__).parent / "fixtures" / "producer-private.pem"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "sign",
                        "--kind",
                        "evidence",
                        "--input",
                        str(input_path),
                        "--private-key",
                        str(fixture),
                        "--key-id",
                        "producer-2026-09",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(2, status)
            self.assertFalse(output_path.exists())

    def test_keygen_uses_private_file_mode_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            private_path = root / "private.pem"
            public_path = root / "public.txt"
            args = [
                "keygen",
                "--private-key-out",
                str(private_path),
                "--public-key-out",
                str(public_path),
            ]
            self.assertEqual(0, main(args))
            self.assertEqual(0o600, os.stat(private_path).st_mode & 0o777)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(args))

    def test_keygen_rejects_same_private_and_public_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "key.txt"
            with contextlib.redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "keygen",
                        "--private-key-out",
                        str(target),
                        "--public-key-out",
                        str(target),
                    ]
                )
            self.assertEqual(2, status)
            self.assertFalse(target.exists())

    def test_canonicalize_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bad.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, main(["canonicalize", "--input", str(path)]))

    def test_canonicalize_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.write_json(root, "input.json", {"b": 2, "a": 1})
            target = root / "out.json"
            self.assertEqual(
                0,
                main(
                    [
                        "canonicalize",
                        "--input",
                        str(source),
                        "--output",
                        str(target),
                    ]
                ),
            )
            self.assertEqual('{"a":1,"b":2}\n', target.read_text())

    def test_canonicalize_removes_top_level_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            document = evidence(policy())
            source = self.write_json(root, "signed.json", document)
            target = root / "payload.json"
            self.assertEqual(
                0,
                main(
                    [
                        "canonicalize",
                        "--input",
                        str(source),
                        "--output",
                        str(target),
                    ]
                ),
            )
            self.assertEqual(signature_payload(document) + b"\n", target.read_bytes())

    def test_serve_command_validates_then_dispatches(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            with patch("mergegrounds_verifier.cli.serve") as mocked:
                self.assertEqual(0, main(["serve", "--policy", str(policy_path)]))
                mocked.assert_called_once()

    def test_serve_command_reports_bind_failure_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            stderr = io.StringIO()
            with (
                patch("mergegrounds_verifier.cli.serve", side_effect=OSError("address in use")),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(2, main(["serve", "--policy", str(policy_path)]))
            self.assertEqual("service failed: address in use\n", stderr.getvalue())

    def test_serve_command_treats_keyboard_interrupt_as_clean_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            with patch("mergegrounds_verifier.cli.serve", side_effect=KeyboardInterrupt):
                self.assertEqual(0, main(["serve", "--policy", str(policy_path)]))

    def test_serve_command_rejects_partial_signing_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    2,
                    main(
                        [
                            "serve",
                            "--policy",
                            str(policy_path),
                            "--decision-key-id",
                            "missing",
                        ]
                    ),
                )

    def test_serve_rejects_wrong_purpose_decision_key_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            with (
                patch("mergegrounds_verifier.cli.serve") as mocked,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    [
                        "serve",
                        "--policy",
                        str(policy_path),
                        "--decision-signing-key",
                        str(Path(__file__).parent / "fixtures" / "producer-private.pem"),
                        "--decision-key-id",
                        "producer-2026-09",
                    ]
                )
            self.assertEqual(2, status)
            mocked.assert_not_called()

    def test_serve_rejects_malformed_private_key_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            invalid_key = root / "invalid.pem"
            invalid_key.write_text("not a private key", encoding="ascii")
            with (
                patch("mergegrounds_verifier.cli.serve") as mocked,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    [
                        "serve",
                        "--policy",
                        str(policy_path),
                        "--decision-signing-key",
                        str(invalid_key),
                        "--decision-key-id",
                        "decision-2026-09",
                    ]
                )
            self.assertEqual(2, status)
            mocked.assert_not_called()

    def test_serve_rejects_encrypted_private_key_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            policy_path = self.write_json(root, "policy.json", policy())
            encrypted_key = root / "encrypted.pem"
            encrypted_key.write_bytes(
                private("decision").private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"test-only"),
                )
            )
            with (
                patch("mergegrounds_verifier.cli.serve") as mocked,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    [
                        "serve",
                        "--policy",
                        str(policy_path),
                        "--decision-signing-key",
                        str(encrypted_key),
                        "--decision-key-id",
                        "decision-2026-09",
                    ]
                )
            self.assertEqual(2, status)
            mocked.assert_not_called()

    def test_signing_key_and_id_must_be_supplied_together(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active = policy()
            policy_path = self.write_json(root, "policy.json", active)
            subject_path = self.write_json(root, "subject.json", subject())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "verify",
                        "--policy",
                        str(policy_path),
                        "--subject",
                        str(subject_path),
                        "--decision-key-id",
                        "missing-key",
                    ]
                )
            self.assertEqual(2, status)
            self.assertIn("DECISION_SIGNING_CONFIG_INVALID", output.getvalue())


if __name__ == "__main__":
    unittest.main()
