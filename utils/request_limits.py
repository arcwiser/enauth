"""Count streamed ASGI request bytes without buffering upload bodies."""

import re

from starlette.formparsers import MultiPartException
from starlette.responses import JSONResponse


class _BodyTooLarge(MultiPartException):
    # Starlette closes any partially spooled multipart files for this exception.
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_request_bytes=105 * 1024 * 1024,
                 max_json_bytes=2 * 1024 * 1024):
        self.app = app
        self.max_request_bytes = max(1, min(int(max_request_bytes), 105 * 1024 * 1024))
        self.max_json_bytes = max(1, min(int(max_json_bytes), self.max_request_bytes))

    def limit_for(self, scope):
        path = scope.get("path", "").rstrip("/")
        is_upload = (scope.get("method") == "POST" and (
            path in {"/api/admin/files", "/api/admin/loaders"}
            or re.fullmatch(r"/api/integrations/apps/[^/]+/builds", path)))
        content_type = next((v.lower() for k, v in scope.get("headers", [])
                             if k.lower() == b"content-type"), b"")
        if is_upload and content_type.split(b";", 1)[0].strip() == b"multipart/form-data":
            return self.max_request_bytes
        return self.max_json_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.limit_for(scope)
        headers = scope.get("headers", [])
        lengths = [v for k, v in headers if k.lower() == b"content-length"]
        has_transfer_encoding = any(k.lower() == b"transfer-encoding" for k, _ in headers)
        if lengths:
            if (len(lengths) != 1 or not re.fullmatch(rb"[0-9]{1,20}", lengths[0])
                    or has_transfer_encoding):
                return await JSONResponse({"detail": "Invalid Content-Length"}, 400)(scope, receive, send)
            if int(lengths[0]) > limit:
                return await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)

        consumed = 0
        exceeded = False
        response_started = False
        rejected = False

        async def limited_receive():
            nonlocal consumed, exceeded
            if exceeded:
                raise _BodyTooLarge("Request body too large")
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > limit:
                    exceeded = True
                    raise _BodyTooLarge("Request body too large")
            return message

        async def reject():
            nonlocal rejected
            if not rejected:
                rejected = True
                await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)

        async def limited_send(message):
            nonlocal response_started
            if exceeded and not response_started:
                # Body parsers may translate the exception to 400; retain 413.
                return await reject()
            if rejected:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await reject()
