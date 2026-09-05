"""Small stdlib HTTP adapter around the verifier core.

Authentication, TLS, webhook validation, rate limiting and evidence collection are
operator responsibilities and intentionally not pretended by this adapter.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import StrictJSONError, loads_strict
from .verifier import VerificationError, verify


def _error(code: str, detail: str) -> dict[str, Any]:
    return {"decision": "deny", "reason_codes": [code], "error": detail}


class VerifierHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        policy: dict[str, Any],
        *,
        max_body_bytes: int,
        decision_private_key: Ed25519PrivateKey | None,
        decision_key_id: str | None,
    ) -> None:
        super().__init__(address, VerifierHandler)
        self.policy = policy
        self.max_body_bytes = max_body_bytes
        self.decision_private_key = decision_private_key
        self.decision_key_id = decision_key_id


class VerifierHandler(BaseHTTPRequestHandler):
    server: VerifierHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Never log request bodies/evidence. The default access-line metadata is safe.
        super().log_message(fmt, *args)

    def _send(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        body = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(HTTPStatus.OK, {"status": "ok"})
        else:
            self._send(HTTPStatus.NOT_FOUND, _error("NOT_FOUND", "route does not exist"))

    def do_POST(self) -> None:
        if self.path != "/v1/verify":
            self._send(HTTPStatus.NOT_FOUND, _error("NOT_FOUND", "route does not exist"))
            return
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self._send(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                _error("CONTENT_TYPE_INVALID", "Content-Type must be application/json"),
            )
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError:
            self._send(
                HTTPStatus.LENGTH_REQUIRED,
                _error("CONTENT_LENGTH_INVALID", "valid Content-Length is required"),
            )
            return
        if length < 1 or length > self.server.max_body_bytes:
            self._send(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                _error("BODY_SIZE_INVALID", "request body length is outside configured limit"),
            )
            return
        try:
            body = loads_strict(self.rfile.read(length))
            if not isinstance(body, dict) or set(body) != {"subject", "evidence"}:
                raise StrictJSONError("body must contain exactly subject and evidence")
            decision = verify(
                self.server.policy,
                body["subject"],
                body["evidence"],
                decision_private_key=self.server.decision_private_key,
                decision_key_id=self.server.decision_key_id,
            )
        except StrictJSONError as exc:
            self._send(HTTPStatus.BAD_REQUEST, _error("REQUEST_JSON_INVALID", str(exc)))
            return
        except VerificationError as exc:
            self._send(
                HTTPStatus.BAD_REQUEST,
                _error(exc.code, "; ".join(exc.details)),
            )
            return
        status = (
            HTTPStatus.OK if decision["decision"] == "admit" else HTTPStatus.UNPROCESSABLE_ENTITY
        )
        self._send(status, decision)


def serve(
    host: str,
    port: int,
    policy: dict[str, Any],
    *,
    max_body_bytes: int,
    decision_private_key: Ed25519PrivateKey | None,
    decision_key_id: str | None,
) -> None:
    server = VerifierHTTPServer(
        (host, port),
        policy,
        max_body_bytes=max_body_bytes,
        decision_private_key=decision_private_key,
        decision_key_id=decision_key_id,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
