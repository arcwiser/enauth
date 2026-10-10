import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from utils.api_errors import (
    safe_http_exception,
    safe_unhandled_exception,
    safe_validation_exception,
)
from utils.crypto import verify_password_constant_time


class LoginInput(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=10)


def build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_exception_handler(StarletteHTTPException, safe_http_exception)
    app.add_exception_handler(RequestValidationError, safe_validation_exception)
    app.add_exception_handler(Exception, safe_unhandled_exception)

    @app.post("/validate")
    async def validate(body: LoginInput):
        return {"ok": True}

    @app.get("/explode")
    async def explode():
        raise RuntimeError("sqlite error near SECRET_API_KEY_123")

    @app.get("/explicit-500")
    async def explicit_500():
        raise HTTPException(500, "database password was hunter2")

    @app.get("/safe-client-error")
    async def safe_client_error():
        raise HTTPException(400, "INVALID_REQUEST")

    return app


async def asgi_request(app: FastAPI, method: str, path: str, payload: dict | None = None):
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    sent = []
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode("ascii"), "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345), "server": ("testserver", 80),
    }
    try:
        await app(scope, receive, send)
    except Exception:
        # Starlette's outer error middleware re-raises after sending the
        # registered 500 response so production servers can log the failure.
        if not sent:
            raise
    start = next(message for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return start["status"], response_body.decode("utf-8"), json.loads(response_body)


class ApiErrorSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = build_test_app()

    async def test_validation_errors_never_echo_submitted_secrets(self):
        secret = "SECRET_PASSWORD_VALUE"
        status, text, _ = await asgi_request(
            self.app, "POST", "/validate", {"username": "x", "password": secret}
        )
        self.assertEqual(status, 422)
        self.assertNotIn(secret, text)
        self.assertNotIn('"input"', text)

    async def test_unhandled_exceptions_return_only_generic_error(self):
        with self.assertLogs("root", level="ERROR") as captured:
            status, text, body = await asgi_request(self.app, "GET", "/explode")
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"], "INTERNAL_SERVER_ERROR")
        self.assertNotIn("sqlite", text.lower())
        self.assertNotIn("SECRET_API_KEY_123", text)
        self.assertNotIn("SECRET_API_KEY_123", "\n".join(captured.output))

    async def test_explicit_server_errors_are_also_sanitized(self):
        status, text, body = await asgi_request(self.app, "GET", "/explicit-500")
        self.assertEqual(status, 500)
        self.assertEqual(body["detail"], "INTERNAL_SERVER_ERROR")
        self.assertNotIn("hunter2", text)

    async def test_safe_client_error_codes_remain_available(self):
        status, _, body = await asgi_request(self.app, "GET", "/safe-client-error")
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"], "INVALID_REQUEST")

    def test_missing_accounts_still_execute_password_verification(self):
        with patch("utils.crypto.verify_password", return_value=False) as verify:
            self.assertFalse(verify_password_constant_time("attempt", None))
        verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
