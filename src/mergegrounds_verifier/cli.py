"""Command-line interface for offline and service verification."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import StrictJSONError, canonical_text, load_strict, sha256_digest
from .crypto import (
    CryptoError,
    generate_keypair,
    load_private_key,
    sign_document,
    signature_payload,
)
from .schema import validation_messages
from .service import serve
from .timeutil import parse_time
from .verifier import VerificationError, validate_decision_signer, validate_policy, verify


def _write(value: Any, path: str | None = None) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path:
        Path(path).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def _denial(code: str, detail: str) -> dict[str, Any]:
    return {"decision": "deny", "reason_codes": [code], "error": detail}


def _key_options_valid(args: argparse.Namespace) -> bool:
    return bool(args.decision_signing_key) == bool(args.decision_key_id)


def command_verify(args: argparse.Namespace) -> int:
    try:
        if not _key_options_valid(args):
            raise VerificationError(
                "DECISION_SIGNING_CONFIG_INVALID",
                ["--decision-signing-key and --decision-key-id must be supplied together"],
            )
        policy = load_strict(args.policy)
        validate_policy(policy)
        subject = load_strict(args.subject)
        paths = [Path(item) for item in args.evidence]
        if args.evidence_dir:
            paths.extend(sorted(Path(args.evidence_dir).glob("*.json")))
        normalized_paths = sorted(paths, key=lambda path: str(path.resolve()))
        limit = policy["max_evidence_documents"]
        evidence = [load_strict(path) for path in normalized_paths[:limit]]
        if len(normalized_paths) > limit:
            evidence.append(None)
        now = parse_time(args.now) if args.now else None
        key = load_private_key(args.decision_signing_key) if args.decision_signing_key else None
        decision = verify(
            policy,
            subject,
            evidence,
            now=now,
            decision_private_key=key,
            decision_key_id=args.decision_key_id,
        )
        _write(decision, args.output)
    except (OSError, StrictJSONError, CryptoError, VerificationError, ValueError) as exc:
        code = exc.code if isinstance(exc, VerificationError) else "INPUT_INVALID"
        detail = "; ".join(exc.details) if isinstance(exc, VerificationError) else str(exc)
        try:
            _write(_denial(code, detail), args.output)
        except OSError as output_error:
            sys.stderr.write(f"unable to write verification result: {output_error}\n")
        return 2
    return 0 if decision["decision"] == "admit" else 1


def command_policy_digest(args: argparse.Namespace) -> int:
    try:
        policy = load_strict(args.policy)
        validate_policy(policy)
    except (OSError, StrictJSONError, VerificationError) as exc:
        sys.stderr.write(f"policy invalid: {exc}\n")
        return 2
    sys.stdout.write(sha256_digest(policy) + "\n")
    return 0


def command_sign(args: argparse.Namespace) -> int:
    try:
        document = load_strict(args.input)
        if not isinstance(document, dict):
            raise StrictJSONError("document must be a JSON object")
        if "signature" in document:
            raise StrictJSONError("refusing to replace an existing signature")
        placeholder = dict(document)
        placeholder["signature"] = {
            "algorithm": "ed25519",
            "key_id": args.key_id,
            "value": "A" * 86,
        }
        errors = validation_messages(args.kind, placeholder)
        if errors:
            raise StrictJSONError("; ".join(errors[:8]))
        key = load_private_key(args.private_key)
        signed = sign_document(document, key, args.key_id)
        _write(signed, args.output)
    except (OSError, StrictJSONError, CryptoError, ValueError) as exc:
        sys.stderr.write(f"signing failed: {exc}\n")
        return 2
    return 0


def command_keygen(args: argparse.Namespace) -> int:
    try:
        generate_keypair(args.private_key_out, args.public_key_out)
    except (OSError, CryptoError) as exc:
        sys.stderr.write(f"key generation failed: {exc}\n")
        return 2
    return 0


def command_canonicalize(args: argparse.Namespace) -> int:
    try:
        value = load_strict(args.input)
        rendered = (
            signature_payload(value).decode("utf-8")
            if isinstance(value, dict)
            else canonical_text(value)
        ) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, StrictJSONError) as exc:
        sys.stderr.write(f"canonicalization failed: {exc}\n")
        return 2
    return 0


def command_serve(args: argparse.Namespace) -> int:
    try:
        if not _key_options_valid(args):
            raise VerificationError(
                "DECISION_SIGNING_CONFIG_INVALID",
                ["--decision-signing-key and --decision-key-id must be supplied together"],
            )
        policy = load_strict(args.policy)
        validate_policy(policy)
        key = load_private_key(args.decision_signing_key) if args.decision_signing_key else None
        if key is not None:
            validate_decision_signer(policy, key, args.decision_key_id)
    except (OSError, StrictJSONError, CryptoError, VerificationError) as exc:
        sys.stderr.write(f"service configuration invalid: {exc}\n")
        return 2
    try:
        serve(
            args.listen,
            args.port,
            policy,
            max_body_bytes=args.max_body_bytes,
            decision_private_key=key,
            decision_key_id=args.decision_key_id,
        )
    except OSError as exc:
        sys.stderr.write(f"service failed: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mergegrounds-verifier",
        description="Independently verify exact-subject MergeGrounds evidence.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    verify_parser = commands.add_parser("verify", help="emit an admit/deny decision")
    verify_parser.add_argument("--policy", required=True)
    verify_parser.add_argument("--subject", required=True)
    verify_parser.add_argument("--evidence", action="append", default=[])
    verify_parser.add_argument("--evidence-dir")
    verify_parser.add_argument("--now", help="RFC 3339 UTC replay/evaluation time")
    verify_parser.add_argument("--decision-signing-key")
    verify_parser.add_argument("--decision-key-id")
    verify_parser.add_argument("--output")
    verify_parser.set_defaults(handler=command_verify)

    digest_parser = commands.add_parser("policy-digest", help="validate and digest policy")
    digest_parser.add_argument("--policy", required=True)
    digest_parser.set_defaults(handler=command_policy_digest)

    sign_parser = commands.add_parser("sign", help="sign an unsigned evidence or waiver object")
    sign_parser.add_argument("--kind", required=True, choices=("evidence", "waiver"))
    sign_parser.add_argument("--input", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--key-id", required=True)
    sign_parser.add_argument("--output", required=True)
    sign_parser.set_defaults(handler=command_sign)

    keygen_parser = commands.add_parser("keygen", help="create an Ed25519 operator keypair")
    keygen_parser.add_argument("--private-key-out", required=True)
    keygen_parser.add_argument("--public-key-out", required=True)
    keygen_parser.set_defaults(handler=command_keygen)

    canonical_parser = commands.add_parser("canonicalize", help="render canonical signing JSON")
    canonical_parser.add_argument("--input", required=True)
    canonical_parser.add_argument("--output")
    canonical_parser.set_defaults(handler=command_canonicalize)

    serve_parser = commands.add_parser("serve", help="serve POST /v1/verify on a trusted host")
    serve_parser.add_argument("--policy", required=True)
    serve_parser.add_argument("--listen", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--max-body-bytes", type=int, default=4 * 1024 * 1024)
    serve_parser.add_argument("--decision-signing-key")
    serve_parser.add_argument("--decision-key-id")
    serve_parser.set_defaults(handler=command_serve)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))
