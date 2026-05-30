import os
import sys
import secrets
import string
import asyncio
import contextlib
import signal
from contextlib import asynccontextmanager
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI
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
from utils.crypto  import generate_uid, hash_password, generate_app_secret
from utils.logger import app_log

# ─── Lifespan ────────────────────────────────────────────────────────────────

shutdown_event = asyncio.Event()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await ensure_default_admin()
    cleanup_task = asyncio.create_task(_maintenance_loop())
    yield
    shutdown_event.set()
    cleanup_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await cleanup_task
    app_log.info("EnAuth server shutdown complete")


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
app = FastAPI(title="EnAuth", version="1.0.0",
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

app.include_router(client_router)
app.include_router(admin_router)

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
            app_log.info(f"Default admin account created - Username: {username}, Password: {password}")


# ─── Entry point ─────────────────────────────────────────────────────────────

def handle_signal(signum, frame):
    """Handle shutdown signals gracefully."""
    app_log.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()

if __name__ == "__main__":
    import uvicorn
    host  = os.getenv("HOST", "0.0.0.0")
    port  = int(os.getenv("PORT", "8080"))
    debug = os.getenv("DEBUG", "false").lower() == "true"

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    app_log.info(f"EnAuth Server starting on https://{host}:{port}")
    app_log.info(f"Admin panel -> https://localhost:{port}/panel/")

    ssl_cert = os.getenv("SSL_CERT")
    ssl_key  = os.getenv("SSL_KEY")

    uvicorn_kwargs = {
        "app":      "main:app",
        "host":     host,
        "port":     port,
        "reload":   debug,
        "log_level": "info",
    }

    if ssl_cert and ssl_key:
        uvicorn_kwargs["ssl_certfile"] = ssl_cert
        uvicorn_kwargs["ssl_keyfile"]  = ssl_key
        app_log.info(f"SSL enabled using: {ssl_cert}")

    uvicorn.run(**uvicorn_kwargs)
