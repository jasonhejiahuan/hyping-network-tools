import json
import tempfile
import threading
import unittest
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit

from hyping.storage import save_device_records
from hyping.web import HypingWebHandler, HypingWebServer, _display_web_host


class FakePasskeyAuthHandler(BaseHTTPRequestHandler):
    server: "FakePasskeyAuthServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b"{}"
        payload = json.loads(body.decode("utf-8"))

        if self.path == "/api/login/options":
            self.server.options_requests.append(payload)
            self._json(
                {
                    "publicKey": {
                        "challenge": "Y2hhbGxlbmdl",
                        "rpId": "localhost",
                        "timeout": 60000,
                        "allowCredentials": [],
                        "userVerification": "preferred",
                    }
                },
                headers={"Set-Cookie": "session=fake-auth-session; Path=/"},
            )
            return

        if self.path == "/api/login/verify":
            self.server.verify_requests.append(
                {
                    "cookie": self.headers.get("Cookie", ""),
                    "payload": payload,
                }
            )
            self._json({"ok": True})
            return

        if self.path == "/api/server/session/verify":
            self.server.session_verify_requests.append(
                {
                    "authorization": self.headers.get("Authorization", ""),
                    "payload": payload,
                }
            )
            authenticated = (
                self.headers.get("Authorization") == "Bearer test-token"
                and "session=fake-auth-session" in payload.get("sessionCookie", "")
            )
            self._json(
                {
                    "ok": True,
                    "authenticated": authenticated,
                    "user": {
                        "sub": "stable-user",
                        "id": 7,
                        "username": "jason",
                        "createdAt": 1780000000,
                    }
                    if authenticated
                    else None,
                }
            )
            return

        if self.path == "/oauth/token":
            self.server.token_requests.append(payload)
            authenticated = (
                payload.get("client_id") == "passkey-demo-client"
                and payload.get("client_secret") == "passkey-demo-secret"
                and payload.get("code") == "code-123"
            )
            if not authenticated:
                self._json(
                    {
                        "ok": False,
                        "error": "invalid_client",
                    },
                    status=HTTPStatus.UNAUTHORIZED,
                )
                return
            self._json(
                {
                    "ok": True,
                    "access_token": "access-token-123",
                    "token_type": "Bearer",
                    "authenticated": True,
                    "user": {
                        "sub": "stable-user",
                        "id": 7,
                        "username": "jason",
                        "createdAt": 1780000000,
                    },
                }
            )
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def _json(
        self,
        payload: dict[str, object],
        *,
        headers: dict[str, str] | None = None,
        status: int = HTTPStatus.OK,
    ) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


class FakePasskeyAuthServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), FakePasskeyAuthHandler)
        self.options_requests: list[dict[str, object]] = []
        self.verify_requests: list[dict[str, object]] = []
        self.session_verify_requests: list[dict[str, object]] = []
        self.token_requests: list[dict[str, object]] = []


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object):
        return None


class WebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = Path(self.tmp.name) / "devices.json"
        save_device_records(
            [
                {
                    "hostname": "printer.local",
                    "ip": "192.168.1.20",
                    "mac": "aa:bb:cc:dd:ee:20",
                    "note": "office printer",
                }
            ],
            self.store_path,
        )
        self.server = HypingWebServer(
            ("127.0.0.1", 0),
            HypingWebHandler,
            config={},
            store_path=self.store_path,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def restart_hyping(self, config: dict[str, object]) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.server = HypingWebServer(
            ("127.0.0.1", 0),
            HypingWebHandler,
            config=config,
            store_path=self.store_path,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def get(self, path: str) -> bytes:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=2) as response:
            return response.read()

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_with_opener(
        self,
        opener,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_json_with_opener(self, opener, path: str) -> dict[str, object]:
        with opener.open(f"{self.base_url}{path}", timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def get_no_redirect(
        self,
        path: str,
        *,
        cookie: str | None = None,
    ):
        opener = urllib.request.build_opener(NoRedirectHandler())
        request = urllib.request.Request(f"{self.base_url}{path}")
        if cookie:
            request.add_header("Cookie", cookie)
        try:
            return opener.open(request, timeout=2)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                return exc
            raise

    def get_json_with_cookie(
        self,
        path: str,
        cookie: str,
    ) -> dict[str, object]:
        request = urllib.request.Request(f"{self.base_url}{path}")
        request.add_header("Cookie", cookie)
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_serves_static_ui_assets(self) -> None:
        self.assertIn(b"Hyping Web UI", self.get("/"))
        self.assertIn(b"--ink", self.get("/app.css"))
        self.assertIn(b"drawTopology", self.get("/app.js"))

    def test_default_display_host_prefers_localhost(self) -> None:
        self.assertEqual(_display_web_host("localhost", "127.0.0.1"), "localhost")
        self.assertEqual(_display_web_host("127.0.0.1", "127.0.0.1"), "localhost")

    def test_devices_api_can_save_and_delete_records(self) -> None:
        saved = self.post(
            "/api/devices/save",
            {
                "record": {
                    "hostname": "nas.local",
                    "ip": "192.168.1.30",
                    "mac": "aa:bb:cc:dd:ee:30",
                    "note": "NAS",
                }
            },
        )

        self.assertTrue(saved["ok"])
        self.assertEqual(len(saved["devices"]), 2)

        deleted = self.post("/api/devices/delete", {"index": 1})

        self.assertTrue(deleted["ok"])
        self.assertEqual(len(deleted["devices"]), 1)
        self.assertEqual(deleted["removed"]["hostname"], "nas.local")

    def test_passkey_auth_gate_blocks_api_until_login(self) -> None:
        fake_auth = FakePasskeyAuthServer()
        fake_thread = threading.Thread(
            target=fake_auth.serve_forever,
            daemon=True,
        )
        fake_thread.start()
        host, port = fake_auth.server_address
        self.restart_hyping(
            {
                "web_auth": {
                    "enabled": True,
                    "auth_base_url": f"http://{host}:{port}",
                    "server_api_token": "test-token",
                    "username": "jason",
                    "session_ttl_seconds": 600,
                    "challenge_ttl_seconds": 60,
                    "request_timeout": 2,
                }
            }
        )

        try:
            with self.assertRaises(HTTPError) as error_context:
                self.get("/api/status")
            self.assertEqual(error_context.exception.code, 401)
            blocked = json.loads(error_context.exception.read().decode("utf-8"))
            self.assertTrue(blocked["authRequired"])

            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            status = self.get_json_with_opener(opener, "/api/auth/status")
            self.assertTrue(status["enabled"])
            self.assertFalse(status["authenticated"])

            options = self.post_with_opener(
                opener,
                "/api/auth/options",
                {"username": ""},
            )
            self.assertTrue(options["ok"])
            self.assertEqual(fake_auth.options_requests[0]["username"], "jason")

            verified = self.post_with_opener(
                opener,
                "/api/auth/verify",
                {
                    "challengeId": options["challengeId"],
                    "credential": {
                        "id": "credential-id",
                        "rawId": "credential-id",
                        "type": "public-key",
                        "response": {},
                    },
                },
            )
            self.assertTrue(verified["authenticated"])
            self.assertEqual(verified["user"]["username"], "jason")
            self.assertEqual(
                fake_auth.session_verify_requests[0]["authorization"],
                "Bearer test-token",
            )

            allowed = self.get_json_with_opener(opener, "/api/devices")
            self.assertTrue(allowed["ok"])
            self.assertEqual(allowed["devices"][0]["hostname"], "printer.local")
        finally:
            fake_auth.shutdown()
            fake_thread.join(timeout=2)
            fake_auth.server_close()

    def test_passkey_auth_redirect_flow_sets_hyping_session(self) -> None:
        fake_auth = FakePasskeyAuthServer()
        fake_thread = threading.Thread(
            target=fake_auth.serve_forever,
            daemon=True,
        )
        fake_thread.start()
        host, port = fake_auth.server_address
        self.restart_hyping(
            {
                "web_auth": {
                    "enabled": True,
                    "login_flow": "redirect",
                    "auth_base_url": f"http://{host}:{port}",
                    "callback_url": "http://localhost:8765/api/auth/callback",
                    "client_id": "passkey-demo-client",
                    "client_secret": "passkey-demo-secret",
                    "session_ttl_seconds": 600,
                    "challenge_ttl_seconds": 60,
                    "request_timeout": 2,
                }
            }
        )

        try:
            redirect = self.get_no_redirect("/api/auth/login?next=/devices?tab=all")

            self.assertEqual(redirect.code, 303)
            location = redirect.headers["Location"]
            parsed = urlsplit(location)
            params = {
                key: values[0]
                for key, values in parse_qs(parsed.query).items()
            }
            self.assertEqual(parsed.path, "/oauth/authorize")
            self.assertEqual(params["response_type"], "code")
            self.assertEqual(params["client_id"], "passkey-demo-client")
            self.assertEqual(
                params["redirect_uri"],
                "http://localhost:8765/api/auth/callback",
            )

            callback_query = urlencode(
                {
                    "code": "code-123",
                    "state": params["state"],
                }
            )
            callback = self.get_no_redirect(f"/api/auth/callback?{callback_query}")

            self.assertEqual(callback.code, 303)
            self.assertEqual(
                callback.headers["Location"],
                "/devices?tab=all&auth=success",
            )
            self.assertEqual(
                fake_auth.token_requests[0]["redirect_uri"],
                "http://localhost:8765/api/auth/callback",
            )
            auth_cookie = callback.headers["Set-Cookie"].split(";", 1)[0]
            allowed = self.get_json_with_cookie("/api/devices", auth_cookie)
            self.assertTrue(allowed["ok"])
            self.assertEqual(allowed["devices"][0]["hostname"], "printer.local")
        finally:
            fake_auth.shutdown()
            fake_thread.join(timeout=2)
            fake_auth.server_close()

    def test_redirect_flow_canonicalizes_loopback_callback_to_localhost(self) -> None:
        fake_auth = FakePasskeyAuthServer()
        fake_thread = threading.Thread(
            target=fake_auth.serve_forever,
            daemon=True,
        )
        fake_thread.start()
        host, port = fake_auth.server_address
        self.restart_hyping(
            {
                "web_auth": {
                    "enabled": True,
                    "login_flow": "redirect",
                    "auth_base_url": f"http://{host}:{port}",
                    "client_id": "passkey-demo-client",
                    "client_secret": "passkey-demo-secret",
                    "session_ttl_seconds": 600,
                    "challenge_ttl_seconds": 60,
                    "request_timeout": 2,
                }
            }
        )

        try:
            redirect = self.get_no_redirect("/api/auth/login?next=/")

            self.assertEqual(redirect.code, 303)
            params = {
                key: values[0]
                for key, values in parse_qs(
                    urlsplit(redirect.headers["Location"]).query
                ).items()
            }
            _, bound_port = self.server.server_address
            self.assertEqual(
                params["redirect_uri"],
                f"http://localhost:{bound_port}/api/auth/callback",
            )
        finally:
            fake_auth.shutdown()
            fake_thread.join(timeout=2)
            fake_auth.server_close()


if __name__ == "__main__":
    unittest.main()
