from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from utils.logger import app_log


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


async def safe_http_exception(request: Request, exc: StarletteHTTPException):
    detail = exc.detail if exc.status_code < 500 else "INTERNAL_SERVER_ERROR"
    body = {"detail": detail}
    request_id = _request_id(request)
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)


async def safe_validation_exception(request: Request, exc: RequestValidationError):
    # Pydantic error objects normally contain the rejected input. That input may
    # be a password, API key, license, or other credential, so never echo it.
    errors = [
        {"type": item.get("type", "value_error"),
         "loc": list(item.get("loc", ())),
         "msg": item.get("msg", "Invalid value")}
        for item in exc.errors()
    ]
    body = {"detail": errors}
    request_id = _request_id(request)
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(body, status_code=422)


async def safe_unhandled_exception(request: Request, exc: Exception):
    request_id = _request_id(request)
    app_log.error(
        "Unhandled API failure request_id=%s method=%s path=%s error_type=%s",
        request_id or "unknown",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    body = {"detail": "INTERNAL_SERVER_ERROR"}
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(body, status_code=500)
