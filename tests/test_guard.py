"""Offline contract tests; no SIF credentials or deployment required."""

import io
import json
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock, patch

from scripts.guard import (
    GuardBlocked, GuardClient, GuardReviewRequired, GuardUnavailable, main,
)


def verdict(**changes):
    result = {"request_id": "test-request", "action": "allow", "blocked": False}
    result.update(changes)
    return result


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.client = GuardClient("https://sif.example", "private-key", "test-policy")
        self.next_handler = Mock(return_value="handled")
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.read.return_value = json.dumps(verdict()).encode()
        self.transport = patch("scripts.guard.http.client.HTTPSConnection",
                               return_value=self.connection)
        self.transport.start()
        self.addCleanup(self.transport.stop)

    def respond(self, **changes):
        self.response.read.return_value = json.dumps(verdict(**changes)).encode()

    def run_guard(self, **kwargs):
        return self.client.screen_then("original", self.next_handler, **kwargs)

    def test_allow_forwards_once_with_actual_role_and_explicit_policy(self):
        self.assertEqual(self.run_guard(role="tool"), "handled")
        self.next_handler.assert_called_once_with("original")
        args, kwargs = self.connection.request.call_args
        self.assertEqual(args, ("POST", "/api/v1/guard"))
        self.assertEqual(json.loads(kwargs["body"]), {
            "messages": [{"role": "tool", "content": "original"}],
            "policy_id": "test-policy", "config": {"return_detections": True},
        })
        self.assertEqual(kwargs["headers"]["X-API-Key"], "private-key")
        self.connection.close.assert_called_once()

    def test_class_bound_omits_policy(self):
        self.client = GuardClient("https://sif.example", "private-key", None)
        self.run_guard()
        self.assertNotIn("policy_id", json.loads(self.connection.request.call_args.kwargs["body"]))

    def test_modify_forwards_only_replacement_including_empty_string(self):
        for replacement in ("[redacted]", ""):
            with self.subTest(replacement=replacement):
                self.next_handler.reset_mock()
                self.respond(action="modify", modified_content=replacement)
                self.run_guard()
                self.next_handler.assert_called_once_with(replacement)

    def test_block_never_reaches_next_handler(self):
        for changes in ({"action": "block", "blocked": True}, {"blocked": True}):
            with self.subTest(changes=changes):
                self.respond(**changes)
                with self.assertRaises(GuardBlocked):
                    self.run_guard()
                self.next_handler.assert_not_called()

    def test_flag_requires_explicit_review_behavior(self):
        self.respond(action="flag")
        for callback in (None, Mock(return_value=False), Mock(return_value="yes")):
            with self.subTest(callback=callback):
                with self.assertRaises(GuardReviewRequired):
                    self.run_guard(on_flag=callback)
                self.next_handler.assert_not_called()
        callback = Mock(return_value=True)
        self.run_guard(on_flag=callback)
        callback.assert_called_once_with(verdict(action="flag"))
        self.next_handler.assert_called_once_with("original")

    def test_invalid_or_degraded_verdicts_stop_before_handler(self):
        samples = [None, [], {}, verdict(action="unknown"), verdict(action=[]),
                   verdict(request_id=""), verdict(request_id=4),
                   verdict(blocked="false"), verdict(blocked=0),
                   verdict(degraded=True), verdict(degraded="false"),
                   verdict(action="modify"), verdict(action="modify", modified_content=None),
                   verdict(action="modify", modified_content=42)]
        for sample in samples:
            with self.subTest(sample=sample):
                self.response.read.return_value = json.dumps(sample).encode()
                with self.assertRaises(GuardUnavailable):
                    self.run_guard()
                self.next_handler.assert_not_called()

    def test_bad_json_and_encoding_stop_before_handler(self):
        for body in (b"not-json", b"\xff"):
            with self.subTest(body=body):
                self.response.read.return_value = body
                with self.assertRaises(GuardUnavailable):
                    self.run_guard()
                self.next_handler.assert_not_called()

    def test_http_errors_and_redirects_are_not_retried_or_followed(self):
        for status in (301, 302, 307, 401, 403, 429, 500):
            with self.subTest(status=status):
                self.connection.request.reset_mock()
                self.response.status = status
                with self.assertRaises(GuardUnavailable):
                    self.run_guard()
                self.connection.request.assert_called_once()
                self.next_handler.assert_not_called()

    def test_network_failure_is_not_retried_and_exception_is_sanitized(self):
        self.connection.getresponse.side_effect = TimeoutError("private-key original")
        with self.assertRaises(GuardUnavailable) as caught:
            self.run_guard()
        self.assertNotIn("private-key", str(caught.exception))
        self.assertNotIn("original", str(caught.exception))
        self.connection.request.assert_called_once()
        self.connection.close.assert_called_once()
        self.next_handler.assert_not_called()

    def test_timeout_is_finite_and_passed_to_transport(self):
        with patch("scripts.guard.http.client.HTTPSConnection", return_value=self.connection) as transport:
            self.run_guard()
            self.assertEqual(transport.call_args.kwargs["timeout"], 10.0)
            context = transport.call_args.kwargs["context"]
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                GuardClient("https://sif.example", "key", "policy", timeout=timeout)

    def test_rejects_invalid_role_before_network(self):
        with self.assertRaises(ValueError):
            self.run_guard(role="developer")
        self.connection.request.assert_not_called()
        self.next_handler.assert_not_called()

    def test_origin_must_not_embed_credentials_or_extra_url_parts(self):
        for url in ("https://user:secret@sif.example", "https://sif.example/dashboard",
                    "https://sif.example?key=secret", "https://sif.example#fragment",
                    "http://sif.example", "http://localhost:8080", "https://"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                GuardClient(url, "key", "policy", allow_local_http=True)

    def test_http_requires_opt_in_and_literal_loopback(self):
        for url in ("http://127.0.0.1:8080", "http://[::1]:8080"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    GuardClient(url, "key", "policy")
                client = GuardClient(url, "key", "policy", allow_local_http=True)
                with patch("scripts.guard.http.client.HTTPConnection", return_value=self.connection):
                    client.screen_then("original", self.next_handler)

    def test_environment_does_not_guess_key_mode_from_missing_policy(self):
        env = {"SIF_API_KEY": "key", "SIF_POLICY_ID": "policy"}
        self.assertEqual(GuardClient.from_env(env).policy_id, "policy")
        for bad in ({"SIF_API_KEY": "key"}, {**env, "SIF_KEY_MODE": "typo"},
                    {**env, "SIF_KEY_MODE": "class-bound"}, {"SIF_POLICY_ID": "policy"}):
            with self.subTest(env=bad), self.assertRaises(ValueError):
                GuardClient.from_env(bad)
        client = GuardClient.from_env({"SIF_API_KEY": "key", "SIF_KEY_MODE": "class-bound"})
        self.assertIsNone(client.policy_id)

    def test_cli_reports_metadata_without_content_or_credentials(self):
        env = {"SIF_API_KEY": "private-key", "SIF_POLICY_ID": "test-policy"}
        output = io.StringIO()
        with patch.dict("os.environ", env, clear=True), patch("sys.stdin", io.StringIO("original")), \
                patch("sys.stdout", output):
            self.assertEqual(main(), 0)
        self.assertEqual(json.loads(output.getvalue()), {"request_id": "test-request", "action": "allow"})

    def test_cli_exit_codes_do_not_echo_private_response(self):
        env = {"SIF_API_KEY": "private-key", "SIF_POLICY_ID": "test-policy"}
        for sample, expected in ((verdict(action="block", blocked=True), 2),
                                 (verdict(action="flag"), 3),
                                 (verdict(degraded=True), 1),
                                 (verdict(action="modify", modified_content="private replacement"), 0)):
            with self.subTest(sample=sample):
                sample["detections"] = [{"matched_text": "private detection"}]
                self.response.read.return_value = json.dumps(sample).encode()
                out, err = io.StringIO(), io.StringIO()
                with patch.dict("os.environ", env, clear=True), \
                        patch("sys.stdin", io.StringIO("private input")), \
                        patch("sys.stdout", out), patch("sys.stderr", err):
                    self.assertEqual(main(), expected)
                self.assertNotIn("private", out.getvalue() + err.getvalue())


class LocalHTTPTests(unittest.TestCase):
    def test_real_transport_posts_once_and_refuses_redirect(self):
        requests = []
        status = [200]

        class Stub(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.headers["X-API-Key"],
                                 json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(status[0])
                if status[0] == 307:
                    self.send_header("Location", "/must-not-follow")
                self.end_headers()
                self.wfile.write(json.dumps(verdict(action="modify", modified_content="safe")).encode())

            def log_message(self, *_):
                pass

        server = HTTPServer(("127.0.0.1", 0), Stub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = GuardClient(f"http://127.0.0.1:{server.server_port}", "synthetic-key",
                                 "test-policy", allow_local_http=True)
            handler = Mock()
            client.screen_then("synthetic input", handler, role="assistant")
            handler.assert_called_once_with("safe")
            path, key, body = requests[0]
            self.assertEqual(path, "/api/v1/guard")
            self.assertEqual(key, "synthetic-key")
            self.assertEqual(body["policy_id"], "test-policy")
            self.assertEqual(body["messages"], [{"role": "assistant", "content": "synthetic input"}])
            status[0] = 307
            handler.reset_mock()
            with self.assertRaises(GuardUnavailable):
                client.screen_then("synthetic input", handler)
            handler.assert_not_called()
            self.assertEqual(len(requests), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
