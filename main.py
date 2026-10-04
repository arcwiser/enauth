import os
import sys
import secrets
import string
import asyncio
import contextlib
from contextlib import asynccontextmanager
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

sys.path.insert(0, str(Path(__file__).parent))

from database import init_db, get_db, DB_PATH
from routes.client import router as client_router, limiter
from routes.admin  import router as admin_router, cleanup_runtime_state
from routes.integrations import router as integrations_router
from routes.status import router as status_router
from utils.crypto  import generate_uid, hash_password, generate_app_secret
from utils.logger import app_log
from utils.response_signing import ensure_response_signing_key, response_public_key_hex

# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_startup_configuration(debug_mode)
    ensure_response_signing_key()
    app_log.info("Response-signing public key: %s", response_public_key_hex())
    await init_db()
    await ensure_default_admin()
    cleanup_task = asyncio.create_task(_maintenance_loop())
    yield
    cleanup_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await cleanup_task
    app_log.info("EnAuth server shutdown complete")


def validate_startup_configuration(debug_mode: bool):
    """Emit operator-friendly warnings for common self-hosting misconfigurations."""
    if not os.getenv("ADMIN_PASSWORD"):
        app_log.warning("ADMIN_PASSWORD is not set; a random password will be generated if no admin user exists.")
    license_pepper = os.getenv("LICENSE_KEY_PEPPER", "")
    if len(license_pepper) < 32:
        print("CRITICAL ERROR: LICENSE_KEY_PEPPER must contain at least 32 characters.")
        sys.exit(1)
    if not debug_mode and os.getenv("COOKIE_SECURE", "true").lower() != "true":
        print("CRITICAL ERROR: COOKIE_SECURE must be true in production mode.")
        print("Use DEBUG=true only for intentional local HTTP development.")
        sys.exit(1)
    if os.getenv("CORS_ORIGINS", "*") == "*":
        if not debug_mode:
            print("\n" + "="*80)
            print("CRITICAL ERROR: CORS_ORIGINS is set to '*' in production mode (DEBUG=false).")
            print("This is extremely unsafe and can allow any website to make cross-origin requests to your server.")
            print("Please set CORS_ORIGINS to a specific domain (e.g., CORS_ORIGINS=https://yourdomain.com)")
            print("or run the server in debug mode (DEBUG=true) for local development.")
            print("="*80 + "\n")
            sys.exit(1)
        else:
            app_log.warning("CORS_ORIGINS is set to '*'. That is convenient for local use, but tighter origins are safer in production.")


async def _maintenance_loop():
    """Periodically prune expired sessions and stale runtime state."""
    import aiosqlite
    while True:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                await cleanup_runtime_state(db)
        except Exception as exc:
            app_log.error(f"[maintenance] cleanup failed: {exc}")
        await asyncio.sleep(600)


# ─── App ─────────────────────────────────────────────────────────────────────

debug_mode = os.getenv("DEBUG", "false").lower() == "true"
app = FastAPI(title="EnAuth", version="1.1.0",
              docs_url="/docs" if debug_mode else None,
              redoc_url="/redoc" if debug_mode else None,
              lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = os.getenv("CORS_ORIGINS", "*")
if cors_origins != "*":
    cors_origins = [origin.strip() for origin in cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins != "*" else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.include_router(client_router)
app.include_router(admin_router)
app.include_router(integrations_router)
app.include_router(status_router)

# Serve admin panel static files
PUBLIC = Path(__file__).parent / "public"
app.mount("/panel", StaticFiles(directory=str(PUBLIC), html=True), name="panel")

@app.get("/")
async def root():
    return RedirectResponse("/panel/")


@app.get("/health")
async def health():
    """Health check endpoint for monitoring and load balancers."""
    return {"status": "healthy", "service": "enauth"}


async def ensure_default_admin():
    """Create the default owner account if no admin users exist."""
    import aiosqlite
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM admin_users") as cur:
            count = (await cur.fetchone())[0]
        if count == 0:
            if not password:
                charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
                password = "".join(secrets.choice(charset) for _ in range(18))
            await db.execute(
                "INSERT INTO admin_users (id, username, password_hash, role) VALUES (?,?,?,?)",
                (generate_uid(), username, hash_password(password), "owner"),
            )
            await db.commit()
            
            # Print the generated password prominently to the console, NOT to the log file.
            print("\n" + "!"*80)
            print(f"!!! DEFAULT ADMIN ACCOUNT CREATED !!!")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"WARNING: PLEASE CHANGE THIS PASSWORD IMMEDIATELY UPON LOGIN!")
            print("!"*80 + "\n")
            app_log.info(f"Default admin account created for username '{username}'. Check terminal output for password.")


if __name__ == "__main__":
    import uvicorn
    host  = os.getenv("HOST", "0.0.0.0")
    port  = int(os.getenv("PORT", "8080"))
    debug = os.getenv("DEBUG", "false").lower() == "true"

    ssl_cert = os.getenv("SSL_CERT")
    ssl_key  = os.getenv("SSL_KEY")
    scheme = "https" if ssl_cert and ssl_key and Path(ssl_cert).exists() and Path(ssl_key).exists() else "http"

    app_log.info(f"EnAuth Server starting on {scheme}://{host}:{port}")
    app_log.info(f"Admin panel -> {scheme}://localhost:{port}/panel/")

    uvicorn_kwargs = {
        "app":      "main:app",
        "host":     host,
        "port":     port,
        "reload":   debug,
        "log_level": "info",
    }

    if ssl_cert and ssl_key and Path(ssl_cert).exists() and Path(ssl_key).exists():
        uvicorn_kwargs["ssl_certfile"] = ssl_cert
        uvicorn_kwargs["ssl_keyfile"]  = ssl_key
        app_log.info(f"SSL enabled using: {ssl_cert}")
    elif ssl_cert or ssl_key:
        app_log.warning("SSL certificate or key specified but file not found. Running without SSL.")

    uvicorn.run(**uvicorn_kwargs)
