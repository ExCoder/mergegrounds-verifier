from __future__ import annotations

import http.client
import json
import threading
import unittest
from datetime import UTC, datetime, timedelta

from mergegrounds_verifier.service import VerifierHTTPServer
from mergegrounds_verifier.timeutil import format_time
from tests.helpers import evidence, policy, resign, subject


class HTTPServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.active = policy()
        self.server = VerifierHTTPServer(
            ("127.0.0.1", 0),
            self.active,
            max_body_bytes=1024 * 1024,
            decision_private_key=None,
            decision_key_id=None,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self, method: str, path: str, body: bytes | None = None, content_type: str | None = None
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        headers = {"Content-Type": content_type} if content_type else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        parsed = json.loads(response.read())
        connection.close()
        return response.status, parsed

    def fresh_evidence(self) -> dict:
        document = evidence(self.active)
        now = datetime.now(UTC).replace(microsecond=0)
        document["invocation"]["started_at"] = format_time(now - timedelta(minutes=3))
        document["invocation"]["finished_at"] = format_time(now - timedelta(minutes=2))
        document["validity"]["issued_at"] = format_time(now - timedelta(minutes=1))
        document["validity"]["expires_at"] = format_time(now + timedelta(minutes=30))
        return resign(document)

    def test_health_endpoint(self) -> None:
        status, body = self.request("GET", "/healthz")
        self.assertEqual(200, status)
        self.assertEqual({"status": "ok"}, body)

    def test_valid_request_admits(self) -> None:
        payload = json.dumps({"subject": subject(), "evidence": [self.fresh_evidence()]}).encode()
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(200, status)
        self.assertEqual("admit", body["decision"])

    def test_policy_denial_uses_unprocessable_status(self) -> None:
        payload = json.dumps({"subject": subject(), "evidence": []}).encode()
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(422, status)
        self.assertEqual("deny", body["decision"])

    def test_unknown_request_field_is_rejected(self) -> None:
        payload = json.dumps(
            {"subject": subject(), "evidence": [], "now": "attacker-controlled"}
        ).encode()
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(400, status)
        self.assertEqual("deny", body["decision"])

    def test_duplicate_json_member_is_rejected(self) -> None:
        payload = b'{"subject":{},"subject":{},"evidence":[]}'
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(400, status)
        self.assertIn("REQUEST_JSON_INVALID", body["reason_codes"])

    def test_oversized_integer_literal_returns_bad_request(self) -> None:
        payload = b'{"subject":{},"evidence":[' + b"1" * 5000 + b"]}"
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(400, status)
        self.assertIn("REQUEST_JSON_INVALID", body["reason_codes"])

    def test_wrong_content_type_is_rejected(self) -> None:
        status, body = self.request("POST", "/v1/verify", b"{}", "text/plain")
        self.assertEqual(415, status)
        self.assertEqual("deny", body["decision"])

    def test_post_to_unknown_route_is_rejected(self) -> None:
        status, body = self.request("POST", "/unknown", b"{}", "application/json")
        self.assertEqual(404, status)
        self.assertEqual("deny", body["decision"])

    def test_oversized_body_is_rejected_before_parse(self) -> None:
        self.server.max_body_bytes = 1
        status, body = self.request("POST", "/v1/verify", b"{}", "application/json")
        self.assertEqual(413, status)
        self.assertIn("BODY_SIZE_INVALID", body["reason_codes"])

    def test_missing_content_length_is_rejected(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.putrequest("POST", "/v1/verify")
        connection.putheader("Content-Type", "application/json")
        connection.endheaders()
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        self.assertEqual(411, response.status)
        self.assertIn("CONTENT_LENGTH_INVALID", body["reason_codes"])

    def test_invalid_subject_is_a_bad_request(self) -> None:
        payload = json.dumps({"subject": {}, "evidence": []}).encode()
        status, body = self.request("POST", "/v1/verify", payload, "application/json")
        self.assertEqual(400, status)
        self.assertIn("SUBJECT_SCHEMA_INVALID", body["reason_codes"])

    def test_unknown_route_is_rejected(self) -> None:
        status, _ = self.request("GET", "/admin")
        self.assertEqual(404, status)


if __name__ == "__main__":
    unittest.main()
