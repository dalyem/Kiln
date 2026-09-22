from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from kiln import KilnApiError, KilnClient


class RedirectSafetyTests(unittest.TestCase):
    def test_status_does_not_follow_redirect_to_another_server(self) -> None:
        target_requests = 0

        class TargetHandler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return

            def do_GET(self) -> None:
                nonlocal target_requests
                target_requests += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "installationId": "unexpected",
                    "providerMode": "fake",
                    "mutationEnabled": False,
                    "persistence": "memory",
                }).encode())

        target = _start(TargetHandler)

        class SourceHandler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/captured")
                self.end_headers()

        source = _start(SourceHandler)
        self.addCleanup(_stop, source)
        self.addCleanup(_stop, target)

        client = KilnClient(f"http://127.0.0.1:{source.server_port}", "test-token")
        with self.assertRaises(KilnApiError):
            client.status()
        self.assertEqual(target_requests, 0)

    def test_unknown_server_error_code_is_not_exposed(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":{"code":"secret_must_not_escape"}}')

        server = _start(Handler)
        self.addCleanup(_stop, server)
        client = KilnClient(f"http://127.0.0.1:{server.server_port}", "test-token")
        with self.assertRaises(KilnApiError) as raised:
            client.status()
        self.assertEqual(raised.exception.code, "request_failed")
        self.assertNotIn("secret_must_not_escape", str(raised.exception))

    def test_known_server_error_code_is_preserved(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":{"code":"UNAUTHENTICATED"}}')

        server = _start(Handler)
        self.addCleanup(_stop, server)
        client = KilnClient(f"http://127.0.0.1:{server.server_port}", "test-token")
        with self.assertRaises(KilnApiError) as raised:
            client.status()
        self.assertEqual(raised.exception.code, "UNAUTHENTICATED")

    def test_client_rejects_ambiguous_base_urls(self) -> None:
        for base_url in (
            "https://token@example.test",
            "https://example.test/control",
            "https://example.test/?next=https://attacker.test",
            "https://example.test/#fragment",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    KilnClient(base_url, "test-token")


def _start(handler: type[BaseHTTPRequestHandler]) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    server._kiln_thread = thread  # type: ignore[attr-defined]
    return server


def _stop(server: HTTPServer) -> None:
    server.shutdown()
    server._kiln_thread.join()  # type: ignore[attr-defined]
    server.server_close()
