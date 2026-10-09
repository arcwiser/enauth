import asyncio
import csv
from pydantic import field_validator, model_validator
import io
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, File, UploadFile, Form, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import Literal, Optional
import aiosqlite
import re
import secrets
import hashlib
import ipaddress
import shutil
import pyotp

from database import DB_PATH, get_db
from routes.client import limiter
from utils.crypto import (
    generate_license_key, generate_app_secret,
    generate_session_token, generate_uid,
    hash_password, verify_password,
    hash_license_key, mask_license_key, encrypt_license_key, display_license_key, encrypt_bytes,
)
from utils.logger import app_log, log_action
from utils.response_signing import KEY_PATH as RESPONSE_SIGNING_KEY_PATH, response_public_key_hex, sign_response
from utils.runtime_metrics import snapshot as runtime_metrics_snapshot
from utils.uploads import read_build_upload, validate_release_name, validate_release_version

router = APIRouter(prefix="/api/admin", tags=["admin"])
ADMIN_SESSION_HOURS = int(os.getenv("ADMIN_SESSION_HOURS", "8"))
MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "200"))
TEMP_2FA_TTL_MINUTES = int(os.getenv("TEMP_2FA_TTL_MINUTES", "5"))
TEMP_2FA_SWEEP_SECONDS = int(os.getenv("TEMP_2FA_SWEEP_SECONDS", "60"))
ADMIN_COOKIE_NAME = "enauth_admin_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
SERVER_STARTED_MONOTONIC = time.monotonic()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(Path(__file__).resolve().parent.parent / "backups"))).resolve()
BACKUP_RETENTION = max(1, min(int(os.getenv("BACKUP_RETENTION", "14")), 100))
BACKUP_ENCRYPTION_KEY = os.getenv("BACKUP_ENCRYPTION_KEY", "")


class SessionRevokeFilterBody(BaseModel):
    app_id: str = Field(min_length=1, max_length=128)
    product_id: Optional[str] = Field(default=None, max_length=128)
    license_id: Optional[str] = Field(default=None, max_length=128)
    reason: str = Field(default="Administrative revocation", min_length=3, max_length=300)


class EmergencyLockdownBody(BaseModel):
    reason: str = Field(min_length=3, max_length=300)
    confirmation: str = Field(min_length=1, max_length=200)


class SdkCompatibilityBody(BaseModel):
    minimum_version: Optional[str] = Field(default=None, max_length=64)
    recommended_version: Optional[str] = Field(default=None, max_length=64)
    enforce_minimum: bool = False
    upgrade_message: Optional[str] = Field(default=None, max_length=500)


class PortalDeviceNameBody(BaseModel):
    name: str = Field(min_length=1, max_length=60)


class PortalHwidResetRequestBody(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def future_hours(h: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S")

def future_minutes(m: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S")

def row_to_dict(row) -> dict:
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows) -> list:
    return [dict(r) for r in rows]


def clamp_limit(limit: Optional[int], default: int = 100) -> int:
    value = default if limit is None else limit
    return max(1, min(int(value), MAX_PAGE_SIZE))


def clamp_offset(offset: Optional[int]) -> int:
    return max(0, int(offset or 0))


def _utcnow_dt() -> datetime:
    return datetime.now(timezone.utc)


async def cleanup_runtime_state(db: aiosqlite.Connection):
    """Prune expired auth/session records and stale temp 2FA challenges."""
    now = utcnow()

    await db.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM reseller_sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM portal_sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM sessions WHERE expires_at <= ? OR COALESCE(token_expires_at, expires_at) <= ?", (now, now))
    await db.execute("DELETE FROM temp_2fa_sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM download_tickets WHERE expires_at <= ? OR consumed_at IS NOT NULL", (now,))
    await db.execute("DELETE FROM logs WHERE timestamp < datetime(?, '-30 days')", (now,))
    await db.commit()

def validate_password_policy(password: str):
    if len(password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    if not re.search(r"[A-Za-z]", password):
        raise HTTPException(400, "Password must include at least one letter")
    if not re.search(r"\d", password):
        raise HTTPException(400, "Password must include at least one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(400, "Password must include at least one special character")


async def require_admin(request: Request,
                        authorization: Optional[str] = Header(None),
                        db: aiosqlite.Connection = Depends(get_db)):
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    if not token:
        raise HTTPException(401, "Unauthorized")

    async with db.execute(
        """SELECT au.* FROM admin_sessions s
           JOIN admin_users au ON au.id = s.user_id
           WHERE s.token = ? AND s.expires_at > ?""",
        (token, utcnow()),
    ) as cur:
        user = await cur.fetchone()
    if user:
        u = dict(user)
        u["_source"] = "admin_users"
        return u

    async with db.execute(
        """SELECT u.* FROM auth_sessions s
           JOIN auth_users u ON u.id = s.user_id
           WHERE s.token = ? AND s.expires_at > ?""",
        (token, utcnow()),
    ) as cur:
        user = await cur.fetchone()

    if not user:
        raise HTTPException(401, "Invalid or expired session")
    u = dict(user)
    u["_source"] = "auth_users"
    return u


async def require_owner(user=Depends(require_admin)):
    require_panel_owner(user)
    return user


def _backup_path(name: str) -> Path:
    if not re.fullmatch(r"enauth-\d{8}-\d{6}(?:-\d+)?\.db", name):
        raise HTTPException(400, "Invalid backup name")
    path = (BACKUP_DIR / name).resolve()
    if path.parent != BACKUP_DIR:
        raise HTTPException(400, "Invalid backup path")
    return path


def _backup_info(path: Path) -> dict:
    stat = path.stat()
    return {
        "name": path.name,
        "size_bytes": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/backups")
async def list_backups(user=Depends(require_owner)):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(BACKUP_DIR.glob("enauth-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {"backups": [_backup_info(p) for p in files]}


@router.post("/backups")
async def create_backup(user=Depends(require_owner), db: aiosqlite.Connection = Depends(get_db)):
    return await create_verified_backup(db, "manual")


async def create_verified_backup(db: aiosqlite.Connection, source: str = "automatic") -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    destination = BACKUP_DIR / f"enauth-{stamp}.db"
    suffix = 1
    while destination.exists():
        destination = BACKUP_DIR / f"enauth-{stamp}-{suffix}.db"
        suffix += 1
    async with aiosqlite.connect(destination) as target:
        await db.backup(target)
        async with target.execute("PRAGMA integrity_check") as cur:
            check = await cur.fetchone()
    if not check or check[0] != "ok":
        destination.unlink(missing_ok=True)
        raise HTTPException(500, "Backup integrity verification failed")
    if BACKUP_ENCRYPTION_KEY and RESPONSE_SIGNING_KEY_PATH.is_file():
        encrypted_key = encrypt_bytes(RESPONSE_SIGNING_KEY_PATH.read_bytes(), BACKUP_ENCRYPTION_KEY)
        key_backup = destination.with_suffix(".signing-key.enc")
        key_backup.write_text(encrypted_key, encoding="ascii")
        try:
            key_backup.chmod(0o600)
        except OSError:
            pass
    files = sorted(BACKUP_DIR.glob("enauth-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for expired in files[BACKUP_RETENTION:]:
        expired.unlink(missing_ok=True)
        expired.with_suffix(".signing-key.enc").unlink(missing_ok=True)
    await log_action(db, "backup_created", details=f"{destination.name}; source={source}; signing_key={bool(BACKUP_ENCRYPTION_KEY)}")
    await db.commit()
    return _backup_info(destination)


@router.get("/backups/{name}")
async def download_backup(name: str, user=Depends(require_owner)):
    path = _backup_path(name)
    if not path.is_file():
        raise HTTPException(404, "Backup not found")
    return FileResponse(path, media_type="application/vnd.sqlite3", filename=path.name)


@router.delete("/backups/{name}")
async def delete_backup(name: str, user=Depends(require_owner), db: aiosqlite.Connection = Depends(get_db)):
    path = _backup_path(name)
    if not path.is_file():
        raise HTTPException(404, "Backup not found")
    path.unlink()
    await log_action(db, "backup_deleted", details=name)
    await db.commit()
    return {"ok": True}


async def require_api_key(x_api_key: Optional[str] = Header(None),
                         db: aiosqlite.Connection = Depends(get_db)):
    """Dependency that ensures a valid API key exists.

    Security: We use a fast SHA-256 prefix hash to narrow to one candidate key
    before doing the expensive bcrypt comparison. This prevents an O(n*bcrypt)
    DoS attack where an attacker could force the server to run bcrypt against
    every API key on every request.
    """
    import hashlib
    if not x_api_key:
        raise HTTPException(401, "Missing API key")

    if len(x_api_key) < 32 or not x_api_key.startswith("enauth_"):
        raise HTTPException(401, "Invalid API key")
    key_prefix = x_api_key[:20]
    deterministic_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()

    async with db.execute(
        """SELECT ak.*, au.username, au.role
           FROM api_keys ak
           JOIN admin_users au ON ak.user_id = au.id
           WHERE ak.is_active = 1 AND (ak.key_prefix = ? OR ak.key_prefix IS NULL)
           ORDER BY ak.created_at DESC""",
        (key_prefix,),
    ) as cur:
        keys = await cur.fetchall()

    key = None
    for row in keys:
        stored_hash = row["key_hash"]
        if secrets.compare_digest(stored_hash, deterministic_hash):
            key = row
            break
        # Backward-compatible verification for keys created before deterministic
        # hashes and prefixes were introduced. Successful use upgrades the row.
        if stored_hash.startswith("$2") and verify_password(x_api_key, stored_hash):
            key = row
            await db.execute(
                "UPDATE api_keys SET key_hash = ?, key_prefix = ? WHERE id = ?",
                (deterministic_hash, key_prefix, row["id"]),
            )
            break

    if not key:
        raise HTTPException(401, "Invalid API key")

    # Check expiration
    if key["expires_at"] and datetime.now(timezone.utc) > datetime.strptime(key["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc):
        raise HTTPException(401, "API key expired")

    # Update last used
    await db.execute("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?", (key["id"],))
    await db.commit()

    return dict(key)


def is_auth_panel_user(user: dict) -> bool:
    # Users from auth_users (tenants/resellers) always have an owner_user_id or role in that table.
    # The most reliable way is to check if the user dict has the expected admin_users fields.
    # For now, we'll assume any user with a role other than 'user' who is NOT in admin_users 
    # (checked in require_admin) is an auth_panel_user.
    # Actually, require_admin returns the dict directly. We can add a source field.
    return user.get("_source") == "auth_users"


def auth_owner_id(user: dict) -> Optional[str]:
    return user["id"] if is_auth_panel_user(user) else None


def require_panel_owner(user: dict) -> None:
    """Raise 403 unless the caller is a true panel owner (admin_users.role=='owner').
    Used to protect global, non-tenanted resources like banned HWIDs, variables,
    news, and the panel users list from regular auth_users."""
    if user.get("_source") != "admin_users" or user.get("role") != "owner":
        raise HTTPException(403, "Owner role required")


async def create_temp_2fa_session(db: aiosqlite.Connection, user_id: str, role: str) -> str:
    token = secrets.token_hex(32)
    await db.execute(
        "INSERT INTO temp_2fa_sessions (id, user_id, role, token, expires_at) VALUES (?, ?, ?, ?, ?)",
        (generate_uid(), user_id, role, token, future_minutes(TEMP_2FA_TTL_MINUTES)),
    )
    await db.commit()
    return token


# ─── Auth ─────────────────────────────────────────────────────────────────────

class LoginBody(BaseModel):
    username: str
    password: str


def set_admin_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        token,
        max_age=ADMIN_SESSION_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )

@router.post("/auth/login")
@limiter.limit("8/minute")
async def admin_login(response: Response, request: Request = None, body: LoginBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    async with db.execute("SELECT * FROM admin_users WHERE username = ?", (body.username,)) as cur:
        user = await cur.fetchone()
    # Security: use a constant-time generic error to prevent username enumeration.
    # An attacker must not be able to tell whether the username or password was wrong.
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    # 2FA Check
    if user["two_factor_enabled"] == 1:
        temp_token = await create_temp_2fa_session(db, user["id"], user["role"])
        return {
            "two_factor_required": True,
            "temp_token": temp_token,
            "username": user["username"]
        }

    token = generate_session_token()
    await db.execute(
        "INSERT INTO admin_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
        (generate_uid(), user["id"], token, future_hours(ADMIN_SESSION_HOURS)),
    )
    await db.commit()
    set_admin_cookie(response, token)
    return {"username": user["username"], "role": user["role"]}


@router.post("/auth/logout")
async def admin_logout(response: Response, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user["id"],))
    await db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user["id"],))
    await db.commit()
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/", secure=COOKIE_SECURE, samesite="strict")
    return {"ok": True}


@router.get("/auth/me")
async def admin_me(user=Depends(require_admin)):
    """Return the current authenticated user's profile."""
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user.get("role", "user"),
        "two_factor_enabled": user.get("two_factor_enabled", 0),
        "theme": user.get("theme", "dark"),
    }


# ─── Two-Factor Authentication (TOTP) Endpoints ─────────────────────────────

class TwoFactorVerifyBody(BaseModel):
    temp_token: str
    code: str

@router.post("/auth/2fa/setup")
@limiter.limit("10/minute")
async def setup_two_factor(request: Request = None, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    # Only admin_users supports 2FA currently
    if user.get("_source") != "admin_users":
        raise HTTPException(400, "Two-factor authentication is only available for administrative users.")

    # Generate a fresh TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    # Generate provisioning URI
    provisioning_url = totp.provisioning_uri(name=user["username"], issuer_name="EnAuth Admin")

    # Store it as a temporary/pending secret in db (do not enable yet)
    cursor = await db.execute(
        "UPDATE admin_users SET two_factor_secret = ? WHERE id = ? AND COALESCE(two_factor_enabled, 0) = 0",
        (secret, user["id"]),
    )
    if cursor.rowcount != 1:
        await db.rollback()
        raise HTTPException(409, "Disable existing two-factor authentication with its current code before replacing it.")
    await db.commit()

    return {"secret": secret, "provisioning_uri": provisioning_url}


class TwoFactorEnableBody(BaseModel):
    code: str

@router.post("/auth/2fa/enable")
@limiter.limit("10/minute")
async def enable_two_factor(request: Request = None, body: TwoFactorEnableBody = None, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    if user.get("_source") != "admin_users":
        raise HTTPException(400, "Two-factor authentication is only available for administrative users.")

    async with db.execute("SELECT two_factor_secret FROM admin_users WHERE id = ?", (user["id"],)) as cur:
        row = await cur.fetchone()
    
    if not row or not row["two_factor_secret"]:
        raise HTTPException(400, "2FA setup has not been initiated.")

    totp = pyotp.TOTP(row["two_factor_secret"])
    if not totp.verify(body.code.strip()):
        raise HTTPException(400, "Invalid verification code.")

    # Mark as enabled
    await db.execute("UPDATE admin_users SET two_factor_enabled = 1 WHERE id = ?", (user["id"],))
    await log_action(db, "2fa_enable", details=f"Enabled 2FA for administrative user {user['username']}")
    await db.commit()
    return {"ok": True}


@router.post("/auth/2fa/disable")
@limiter.limit("10/minute")
async def disable_two_factor(request: Request = None, body: TwoFactorEnableBody = None, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    if user.get("_source") != "admin_users":
        raise HTTPException(400, "Two-factor authentication is only available for administrative users.")

    async with db.execute("SELECT two_factor_secret FROM admin_users WHERE id = ?", (user["id"],)) as cur:
        row = await cur.fetchone()
    
    if not row or not row["two_factor_secret"]:
        raise HTTPException(400, "2FA has not been configured.")

    totp = pyotp.TOTP(row["two_factor_secret"])
    if not totp.verify(body.code.strip()):
        raise HTTPException(400, "Invalid verification code.")

    # Mark as disabled
    await db.execute("UPDATE admin_users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?", (user["id"],))
    await log_action(db, "2fa_disable", details=f"Disabled 2FA for administrative user {user['username']}")
    await db.commit()
    return {"ok": True}


@router.post("/auth/2fa/verify")
@limiter.limit("10/minute")
async def verify_two_factor(response: Response, request: Request = None, body: TwoFactorVerifyBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    async with db.execute(
        "SELECT * FROM temp_2fa_sessions WHERE token = ?",
        (body.temp_token,),
    ) as cur:
        sess = await cur.fetchone()

    if not sess:
        raise HTTPException(401, "Invalid or expired temporary session.")

    if sess["expires_at"] <= utcnow():
        await db.execute("DELETE FROM temp_2fa_sessions WHERE token = ?", (body.temp_token,))
        await db.commit()
        raise HTTPException(401, "Temporary login session expired.")

    # Load administrative user secret
    async with db.execute("SELECT * FROM admin_users WHERE id = ?", (sess["user_id"],)) as cur:
        user = await cur.fetchone()

    if not user:
        raise HTTPException(401, "User not found.")

    totp = pyotp.TOTP(user["two_factor_secret"])
    if not totp.verify(body.code.strip()):
        raise HTTPException(401, "Invalid verification code.")

    # Consume the challenge atomically before creating a session. Concurrent
    # submissions of the same code/challenge must not create multiple sessions.
    consumed = await db.execute(
        "DELETE FROM temp_2fa_sessions WHERE token = ? AND expires_at > ?",
        (body.temp_token, utcnow()),
    )
    if consumed.rowcount != 1:
        await db.rollback()
        raise HTTPException(401, "Invalid or expired temporary session.")
    token = generate_session_token()
    await db.execute(
        "INSERT INTO admin_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
        (generate_uid(), user["id"], token, future_hours(ADMIN_SESSION_HOURS)),
    )
    await db.commit()
    set_admin_cookie(response, token)
    return {"username": user["username"], "role": user["role"]}


# ─── Product Levels & Pricing ────────────────────────────────────────────────

class CreateProductBody(BaseModel):
    app_id: str
    name: str
    level: str


class UpdateProductBody(BaseModel):
    name: Optional[str] = None
    level: Optional[str] = None
    is_active: Optional[bool] = None
    service_status: Optional[str] = None
    status_message: Optional[str] = Field(default=None, max_length=500)
    status_color: Optional[str] = None
    required_client_version: Optional[str] = Field(default=None, max_length=64)
    blocked_client_versions: Optional[list[str]] = Field(default=None, max_length=100)
    version_kill_switch: Optional[bool] = None

    @field_validator("required_client_version")
    @classmethod
    def validate_required_client_version(cls, value):
        if value is None or not value.strip():
            return value
        if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+\-]{0,63}", value.strip()):
            raise ValueError("Invalid client version")
        return value.strip()

    @field_validator("blocked_client_versions")
    @classmethod
    def validate_blocked_client_versions(cls, values):
        if values is None:
            return values
        for value in values:
            if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+\-]{0,63}", value.strip()):
                raise ValueError("Invalid blocked client version")
        return values

    @field_validator("service_status")
    @classmethod
    def validate_service_status(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _/\-]{0,39}", value):
            raise ValueError("Status must be 1-40 letters, numbers, spaces, /, _ or -")
        return value

    @field_validator("status_color")
    @classmethod
    def validate_status_color(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
            raise ValueError("Status color must be a six-digit hex color such as #22c55e")
        return value.lower()


class ProductPricingBody(BaseModel):
    days: int
    price: float


class PauseBody(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class ResumeBody(BaseModel):
    compensation_hours: float = Field(default=0, ge=0, le=876000)


async def _owned_product(product_id: str, owner_id: Optional[str], db):
    sql = """SELECT p.*, a.owner_user_id FROM products p
             JOIN applications a ON a.id = p.app_id WHERE p.id = ?"""
    args = [product_id]
    if owner_id:
        sql += " AND a.owner_user_id = ?"
        args.append(owner_id)
    async with db.execute(sql, args) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Product not found")
    return row


def _paused_seconds(paused_at: str) -> int:
    started = datetime.strptime(paused_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return max(0, int((_utcnow_dt() - started).total_seconds()))


@router.get("/products")
async def list_products(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT p.*, a.name as app_name,
           (SELECT COUNT(*) FROM product_pricing_points pp WHERE pp.product_id = p.id) as pricing_count
           FROM products p
           JOIN applications a ON a.id = p.app_id"""
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
    sql += " ORDER BY p.created_at DESC"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/products")
async def create_product(body: CreateProductBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (body.app_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "App not found")
    pid = generate_uid()
    try:
        await db.execute(
            "INSERT INTO products (id, app_id, name, level) VALUES (?,?,?,?)",
            (pid, body.app_id, body.name.strip(), body.level.strip().lower()),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Product level already exists for this app")
    return {"id": pid}


@router.put("/products/{product_id}")
async def update_product(product_id: str, body: UpdateProductBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    product = await _owned_product(product_id, owner_id, db)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM products p
               JOIN applications a ON a.id = p.app_id
               WHERE p.id = ? AND a.owner_user_id = ?""",
            (product_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found")
    updates, args = [], []
    if body.name is not None:
        updates.append("name = ?"); args.append(body.name.strip())
    if body.level is not None:
        updates.append("level = ?"); args.append(body.level.strip().lower())
    if body.is_active is not None:
        updates.append("is_active = ?"); args.append(1 if body.is_active else 0)
    if body.service_status is not None:
        updates.append("service_status = ?"); args.append(body.service_status)
    if body.status_message is not None:
        updates.append("status_message = ?"); args.append(body.status_message.strip() or None)
    if body.status_color is not None:
        updates.append("status_color = ?"); args.append(body.status_color)
    if body.required_client_version is not None:
        updates.append("required_client_version = ?"); args.append(body.required_client_version.strip() or None)
    if body.blocked_client_versions is not None:
        cleaned = sorted({v.strip() for v in body.blocked_client_versions if v.strip()})
        updates.append("blocked_client_versions = ?"); args.append(json.dumps(cleaned))
    if body.version_kill_switch is not None:
        updates.append("version_kill_switch = ?"); args.append(1 if body.version_kill_switch else 0)
    if not updates:
        raise HTTPException(400, "Nothing to update")
    args.append(product_id)
    try:
        await db.execute(f"UPDATE products SET {', '.join(updates)} WHERE id = ?", args)
        if body.service_status is not None:
            await db.execute(
                """INSERT INTO outage_events(id,app_id,product_id,event_type,service_status,status_color,public_message)
                   VALUES(?,?,?,?,?,?,?)""",
                (generate_uid(), product["app_id"], product_id, "status_update",
                 body.service_status, body.status_color or product["status_color"],
                 (body.status_message or "").strip() or None),
            )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Product level already exists for this app")
    return {"ok": True}


@router.delete("/products/{product_id}")
async def delete_product(product_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM products WHERE id = ? AND app_id IN
               (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (product_id, owner_id),
        )
    else:
        await db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    await db.commit()
    return {"ok": True}


@router.post("/products/{product_id}/pause")
async def pause_product(product_id: str, body: PauseBody, user=Depends(require_admin),
                        db: aiosqlite.Connection = Depends(get_db)):
    product = await _owned_product(product_id, auth_owner_id(user), db)
    if product["is_paused"]:
        return {"ok": True, "already_paused": True, "paused_at": product["paused_at"]}
    now = utcnow()
    reason = (body.reason or "Product outage").strip()
    await db.execute(
        "UPDATE products SET is_paused=1, paused_at=?, pause_reason=? WHERE id=?",
        (now, reason, product_id),
    )
    async with db.execute("SELECT COUNT(*) FROM license_products WHERE product_id=?", (product_id,)) as cur:
        affected = (await cur.fetchone())[0]
    await db.execute(
        """INSERT INTO outage_events(id,app_id,product_id,event_type,service_status,status_color,public_message,started_at,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (generate_uid(), product["app_id"], product_id, "started", "offline", "#ef4444", reason, now, affected),
    )
    await db.execute("UPDATE products SET service_status='offline', status_color='#ef4444', status_message=? WHERE id=?", (reason, product_id))
    await db.execute("DELETE FROM sessions WHERE product_id=?", (product_id,))
    await log_action(db, "product_paused", app_id=product["app_id"], details=f"{product['level']}: {reason}")
    await db.commit()
    return {"ok": True, "paused_at": now}


@router.post("/products/{product_id}/resume")
async def resume_product(product_id: str, body: ResumeBody, user=Depends(require_admin),
                         db: aiosqlite.Connection = Depends(get_db)):
    product = await _owned_product(product_id, auth_owner_id(user), db)
    if not product["is_paused"] or not product["paused_at"]:
        raise HTTPException(409, "Product is not paused")
    downtime = _paused_seconds(product["paused_at"])
    compensation = int(body.compensation_hours * 3600)
    extension = downtime + compensation
    async with db.execute("SELECT COUNT(*) FROM license_products WHERE product_id=?", (product_id,)) as cur:
        affected = (await cur.fetchone())[0]
    await db.execute(
        """UPDATE license_products SET expires_at=datetime(expires_at, ?),
           total_compensation_seconds=total_compensation_seconds+? WHERE product_id=? AND expires_at IS NOT NULL""",
        (f"+{extension} seconds", compensation, product_id),
    )
    await db.execute(
        """UPDATE products SET is_paused=0, paused_at=NULL, pause_reason=NULL,
           service_status='operational', status_color='#22c55e', status_message=NULL WHERE id=?""", (product_id,)
    )
    await db.execute(
        """INSERT INTO outage_events(id,app_id,product_id,event_type,service_status,public_message,started_at,ended_at,downtime_seconds,compensation_seconds,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (generate_uid(), product["app_id"], product_id, "resolved", "operational",
         "Service restored", product["paused_at"], utcnow(), downtime, compensation, affected),
    )
    await log_action(db, "product_resumed", app_id=product["app_id"],
                     details=f"{product['level']}: extended {extension}s ({compensation}s compensation)")
    await db.commit()
    return {"ok": True, "downtime_seconds": downtime, "compensation_seconds": compensation,
            "extended_by_seconds": extension}


@router.get("/products/{product_id}/resume-preview")
async def preview_product_resume(product_id: str, compensation_hours: float = 0,
                                 user=Depends(require_admin), db=Depends(get_db)):
    if compensation_hours < 0 or compensation_hours > 876000:
        raise HTTPException(400, "Invalid compensation")
    product = await _owned_product(product_id, auth_owner_id(user), db)
    if not product["is_paused"] or not product["paused_at"]:
        raise HTTPException(409, "Product is not paused")
    downtime = _paused_seconds(product["paused_at"])
    extra = int(compensation_hours * 3600)
    async with db.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN expires_at IS NOT NULL THEN 1 ELSE 0 END) AS expiring
           FROM license_products WHERE product_id=?""", (product_id,)
    ) as cur:
        counts = await cur.fetchone()
    return {"affected_licenses": counts["total"], "expiring_licenses": counts["expiring"] or 0,
            "lifetime_licenses": counts["total"] - (counts["expiring"] or 0),
            "downtime_seconds": downtime, "compensation_seconds": extra,
            "extended_by_seconds": downtime + extra}


@router.get("/products/{product_id}/pricing")
async def list_product_pricing(product_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM products p
               JOIN applications a ON a.id = p.app_id
               WHERE p.id = ? AND a.owner_user_id = ?""",
            (product_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found")
    async with db.execute(
        "SELECT * FROM product_pricing_points WHERE product_id = ? ORDER BY days ASC, price ASC",
        (product_id,),
    ) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/products/{product_id}/pricing")
async def add_product_pricing(product_id: str, body: ProductPricingBody, user=Depends(require_admin),
                              db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM products p
               JOIN applications a ON a.id = p.app_id
               WHERE p.id = ? AND a.owner_user_id = ?""",
            (product_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found")
    if body.days <= 0 or body.price <= 0:
        raise HTTPException(400, "days and price must be greater than zero")
    async with db.execute("SELECT COUNT(*) FROM product_pricing_points WHERE product_id = ?", (product_id,)) as cur:
        count = (await cur.fetchone())[0]
    if count >= 6:
        raise HTTPException(400, "Maximum 6 pricing points per product")
    pricing_id = generate_uid()
    await db.execute(
        "INSERT INTO product_pricing_points (id, product_id, days, price) VALUES (?, ?, ?, ?)",
        (pricing_id, product_id, body.days, body.price),
    )
    await db.commit()
    return {"id": pricing_id}


@router.delete("/products/{product_id}/pricing/{pricing_id}")
async def delete_product_pricing(product_id: str, pricing_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM product_pricing_points
               WHERE id = ? AND product_id = ? AND product_id IN (
                 SELECT p.id FROM products p
                 JOIN applications a ON a.id = p.app_id
                 WHERE a.owner_user_id = ?
               )""",
            (pricing_id, product_id, owner_id),
        )
    else:
        await db.execute("DELETE FROM product_pricing_points WHERE id = ? AND product_id = ?", (pricing_id, product_id))
    await db.commit()
    return {"ok": True}


# ─── Resellers ────────────────────────────────────────────────────────────────

class CreateResellerBody(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    product_ids: list[str] = []
    pricing_point_ids: list[str] = []


class CreditResellerBody(BaseModel):
    amount: float
    reason: Optional[str] = None


class ResellerProductBody(BaseModel):
    product_id: str
    monthly_quota: Optional[int] = Field(default=None, ge=1, le=1000000)


class ResellerPricingBody(BaseModel):
    pricing_point_id: str


class SearchQueryBody(BaseModel):
    query: str
    category: Optional[str] = None
    limit: int = 20
    offset: int = 0


class BulkIdsBody(BaseModel):
    ids: list[str] = Field(..., max_length=500)


@router.get("/resellers")
async def list_resellers(search: Optional[str] = None,
                         limit: int = 50, offset: int = 0,
                         user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT id, username, balance, is_active, created_at FROM resellers"
    args = []
    if owner_id:
        sql += " WHERE owner_user_id = ?"
        args.append(owner_id)
        if search:
            sql += " AND (username LIKE ? OR id LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%"])
    elif search:
        sql += " WHERE (username LIKE ? OR id LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 50), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.get("/resellers/{reseller_id}/analytics")
async def get_reseller_analytics(reseller_id: str,
                                  user=Depends(require_admin),
                                  db: aiosqlite.Connection = Depends(get_db)):
    """Get sales analytics for a specific reseller."""
    owner_id = auth_owner_id(user)

    # Verify reseller access
    if owner_id:
        async with db.execute("SELECT owner_user_id FROM resellers WHERE id = ?", (reseller_id,)) as cur:
            reseller = await cur.fetchone()
        if not reseller or reseller["owner_user_id"] != owner_id:
            raise HTTPException(403, "Access denied")

    # Get total sales (licenses sold)
    async with db.execute(
        """SELECT COUNT(*) as total, COALESCE(SUM(ko.amount_paid), 0) as revenue
           FROM key_orders ko
           WHERE ko.reseller_id = ?""",
        (reseller_id,)
    ) as cur:
        sales = await cur.fetchone()

    # Get sales by date (last 30 days)
    async with db.execute(
        """SELECT DATE(ko.created_at) as date, COUNT(*) as count
           FROM licenses l
           JOIN key_orders ko ON l.id = ko.license_id
           WHERE ko.reseller_id = ? AND ko.created_at >= datetime('now', '-30 days')
           GROUP BY DATE(ko.created_at)
           ORDER BY date DESC""",
        (reseller_id,)
    ) as cur:
        sales_by_date = rows_to_list(await cur.fetchall())

    # Get top selling products
    async with db.execute(
        """SELECT lp.product_id, p.name, COUNT(*) as count
           FROM licenses l
           JOIN key_orders ko ON l.id = ko.license_id
           JOIN license_products lp ON l.id = lp.license_id
           JOIN products p ON lp.product_id = p.id
           WHERE ko.reseller_id = ?
           GROUP BY lp.product_id
           ORDER BY count DESC
           LIMIT 10""",
        (reseller_id,)
    ) as cur:
        top_products = rows_to_list(await cur.fetchall())

    return {
        "total_sales": sales["total"] or 0,
        "total_revenue": float(sales["revenue"] or 0),
        "sales_by_date": sales_by_date,
        "top_products": top_products,
    }


@router.post("/resellers")
async def create_reseller(body: CreateResellerBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    username = (body.username or f"reseller_{generate_uid()[:8]}").strip().lower()
    password = body.password or f"{generate_uid()[:8]}!Aa1"
    validate_password_policy(password)
    rid = generate_uid()
    try:
        await db.execute(
            "INSERT INTO resellers (id, username, password_hash, owner_user_id) VALUES (?, ?, ?, ?)",
            (rid, username, hash_password(password), owner_id),
        )
        for product_id in body.product_ids:
            await db.execute(
                "INSERT OR IGNORE INTO reseller_product_access (id, reseller_id, product_id) VALUES (?, ?, ?)",
                (generate_uid(), rid, product_id),
            )
        for pricing_id in body.pricing_point_ids:
            await db.execute(
                "INSERT OR IGNORE INTO reseller_pricing_access (id, reseller_id, pricing_point_id) VALUES (?, ?, ?)",
                (generate_uid(), rid, pricing_id),
            )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Reseller username already exists")
    return {"id": rid, "username": username, "password": password}


@router.post("/resellers/{reseller_id}/credit")
async def credit_reseller(reseller_id: str, body: CreditResellerBody, caller=Depends(require_admin),
                          db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(caller)
    if body.amount == 0:
        raise HTTPException(400, "Amount cannot be zero")
    if owner_id:
        await db.execute("UPDATE resellers SET balance = balance + ? WHERE id = ? AND owner_user_id = ?", (body.amount, reseller_id, owner_id))
    else:
        await db.execute("UPDATE resellers SET balance = balance + ? WHERE id = ?", (body.amount, reseller_id))
    await db.execute(
        "INSERT INTO reseller_balance_ledger (id, reseller_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?)",
        (generate_uid(), reseller_id, body.amount, body.reason or "Manual balance update", caller["username"]),
    )
    await db.commit()
    return {"ok": True}


@router.delete("/resellers/{reseller_id}")
async def delete_reseller(reseller_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM resellers WHERE id = ? AND owner_user_id = ?", (reseller_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Reseller not found")
    await db.execute("BEGIN IMMEDIATE")
    try:
        # Delete keys generated by this reseller BEFORE deleting reseller (key_orders would cascade otherwise).
        if owner_id:
            await db.execute(
                """DELETE FROM licenses
                   WHERE id IN (SELECT license_id FROM key_orders WHERE reseller_id = ?)
                   AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
                (reseller_id, owner_id),
            )
            await db.execute("DELETE FROM resellers WHERE id = ? AND owner_user_id = ?", (reseller_id, owner_id))
        else:
            await db.execute("DELETE FROM licenses WHERE id IN (SELECT license_id FROM key_orders WHERE reseller_id = ?)", (reseller_id,))
            await db.execute("DELETE FROM resellers WHERE id = ?", (reseller_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(500, "Failed to delete reseller")
    return {"ok": True}


@router.post("/resellers/bulk-delete")
async def bulk_delete_resellers(body: BulkIdsBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No reseller IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"DELETE FROM resellers WHERE id IN ({qmarks}) AND owner_user_id = ?",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM resellers WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


@router.post("/resellers/bulk-status")
async def bulk_reseller_status(body: dict, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    ids = body.get("ids") or []
    if not ids:
        raise HTTPException(400, "No reseller IDs provided")
    is_active = 1 if body.get("is_active", True) else 0
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(ids))
    if owner_id:
        await db.execute(
            f"UPDATE resellers SET is_active = ? WHERE id IN ({qmarks}) AND owner_user_id = ?",
            (is_active, *ids, owner_id),
        )
    else:
        await db.execute(f"UPDATE resellers SET is_active = ? WHERE id IN ({qmarks})", (is_active, *ids))
    await db.commit()
    return {"ok": True}


@router.get("/resellers/{reseller_id}/ledger")
async def reseller_ledger(reseller_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT l.* FROM reseller_balance_ledger l JOIN resellers r ON r.id = l.reseller_id WHERE l.reseller_id = ?"
    args = [reseller_id]
    if owner_id:
        sql += " AND r.owner_user_id = ?"
        args.append(owner_id)
    sql += " ORDER BY l.created_at DESC"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.get("/resellers/{reseller_id}/products")
async def reseller_products(reseller_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT p.*, rpa.id as access_id,rpa.monthly_quota,rpa.monthly_used,rpa.quota_reset_at
           FROM reseller_product_access rpa
           JOIN products p ON p.id = rpa.product_id
           JOIN applications a ON a.id = p.app_id
           WHERE rpa.reseller_id = ?"""
    args = [reseller_id]
    if owner_id:
        sql += " AND a.owner_user_id = ?"
        args.append(owner_id)
    sql += " ORDER BY p.name, p.level"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.get("/resellers/{reseller_id}/pricing")
async def reseller_pricing(reseller_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT p.name, p.level, pp.id as pricing_point_id, pp.days, pp.price
             FROM reseller_pricing_access rpa
             JOIN product_pricing_points pp ON pp.id = rpa.pricing_point_id
             JOIN products p ON p.id = pp.product_id
             JOIN applications a ON a.id = p.app_id
             WHERE rpa.reseller_id = ?"""
    args = [reseller_id]
    if owner_id:
        sql += " AND a.owner_user_id = ?"
        args.append(owner_id)
    sql += " ORDER BY p.name, p.level, pp.days"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/resellers/{reseller_id}/products")
async def grant_reseller_product(reseller_id: str, body: ResellerProductBody, user=Depends(require_admin),
                                 db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM resellers WHERE id = ? AND owner_user_id = ?", (reseller_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Reseller not found")
        async with db.execute(
            """SELECT 1 FROM products p
               JOIN applications a ON a.id = p.app_id
               WHERE p.id = ? AND a.owner_user_id = ?""",
            (body.product_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found")
    try:
        await db.execute(
            "INSERT INTO reseller_product_access (id, reseller_id, product_id, monthly_quota, quota_reset_at) VALUES (?, ?, ?, ?, datetime('now','start of month','+1 month'))",
            (generate_uid(), reseller_id, body.product_id, body.monthly_quota),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Product already granted to reseller")
    return {"ok": True}


@router.put("/resellers/{reseller_id}/products/{product_id}/quota")
async def set_reseller_product_quota(reseller_id: str, product_id: str, body: ResellerProductBody,
                                     user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if body.product_id != product_id:
        raise HTTPException(400, "Product mismatch")
    owner_id = auth_owner_id(user)
    sql = """UPDATE reseller_product_access SET monthly_quota=?
             WHERE reseller_id=? AND product_id=?"""
    args = [body.monthly_quota, reseller_id, product_id]
    if owner_id:
        sql += " AND reseller_id IN (SELECT id FROM resellers WHERE owner_user_id=?)"
        args.append(owner_id)
    cur = await db.execute(sql, args)
    if cur.rowcount != 1:
        raise HTTPException(404, "Reseller product access not found")
    await db.commit()
    return {"ok": True}


@router.post("/resellers/{reseller_id}/pricing")
async def grant_reseller_pricing(reseller_id: str, body: ResellerPricingBody, user=Depends(require_admin),
                                 db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM resellers WHERE id = ? AND owner_user_id = ?", (reseller_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Reseller not found")
        async with db.execute(
            """SELECT 1 FROM product_pricing_points pp
               JOIN products p ON p.id = pp.product_id
               JOIN applications a ON a.id = p.app_id
               WHERE pp.id = ? AND a.owner_user_id = ?""",
            (body.pricing_point_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Pricing point not found")
    try:
        await db.execute(
            "INSERT INTO reseller_pricing_access (id, reseller_id, pricing_point_id) VALUES (?, ?, ?)",
            (generate_uid(), reseller_id, body.pricing_point_id),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Pricing point already granted to reseller")
    return {"ok": True}


@router.delete("/resellers/{reseller_id}/products/{product_id}")
async def revoke_reseller_product(reseller_id: str, product_id: str, user=Depends(require_admin),
                                  db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM reseller_product_access
               WHERE reseller_id = ? AND product_id = ?
               AND reseller_id IN (SELECT id FROM resellers WHERE owner_user_id = ?)""",
            (reseller_id, product_id, owner_id),
        )
    else:
        await db.execute(
            "DELETE FROM reseller_product_access WHERE reseller_id = ? AND product_id = ?",
            (reseller_id, product_id),
        )
    await db.commit()
    return {"ok": True}


@router.delete("/resellers/{reseller_id}/pricing/{pricing_point_id}")
async def revoke_reseller_pricing(reseller_id: str, pricing_point_id: str, user=Depends(require_admin),
                                  db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM reseller_pricing_access
               WHERE reseller_id = ? AND pricing_point_id = ?
               AND reseller_id IN (SELECT id FROM resellers WHERE owner_user_id = ?)""",
            (reseller_id, pricing_point_id, owner_id),
        )
    else:
        await db.execute(
            "DELETE FROM reseller_pricing_access WHERE reseller_id = ? AND pricing_point_id = ?",
            (reseller_id, pricing_point_id),
        )
    await db.commit()
    return {"ok": True}


@router.post("/reseller/auth/signin")
@limiter.limit("8/minute")
async def reseller_signin(request: Request, body: LoginBody, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM resellers WHERE username = ? AND is_active = 1", (body.username,)) as cur:
        reseller = await cur.fetchone()
    if not reseller or not verify_password(body.password, reseller["password_hash"]):
        raise HTTPException(401, "Invalid reseller credentials")
    token = generate_session_token()
    await db.execute(
        "INSERT INTO reseller_sessions (id, reseller_id, token, expires_at) VALUES (?, ?, ?, ?)",
        (generate_uid(), reseller["id"], token, future_hours(ADMIN_SESSION_HOURS)),
    )
    await db.commit()
    return {"token": token, "reseller_id": reseller["id"], "username": reseller["username"], "balance": reseller["balance"]}


async def require_reseller(authorization: Optional[str] = Header(None),
                           db: aiosqlite.Connection = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization[7:]
    async with db.execute(
        """SELECT r.* FROM reseller_sessions rs
           JOIN resellers r ON r.id = rs.reseller_id
           WHERE rs.token = ? AND rs.expires_at > ? AND r.is_active = 1""",
        (token, utcnow()),
    ) as cur:
        reseller = await cur.fetchone()
    if not reseller:
        raise HTTPException(401, "Invalid or expired reseller session")
    return dict(reseller)


@router.get("/reseller/products")
async def list_my_products(reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT p.id, p.name, p.level, p.app_id,rpa.monthly_quota,rpa.monthly_used,rpa.quota_reset_at
           FROM reseller_product_access rpa
           JOIN products p ON p.id = rpa.product_id
           WHERE rpa.reseller_id = ? AND p.is_active = 1
           ORDER BY p.name, p.level""",
        (reseller["id"],),
    ) as cur:
        products = rows_to_list(await cur.fetchall())
    for p in products:
        async with db.execute(
            """SELECT pp.id, pp.days, pp.price
               FROM product_pricing_points pp
               JOIN reseller_pricing_access rpa ON rpa.pricing_point_id = pp.id
               WHERE pp.product_id = ? AND rpa.reseller_id = ?
               ORDER BY pp.days, pp.price""",
            (p["id"], reseller["id"]),
        ) as cur:
            p["pricing_points"] = rows_to_list(await cur.fetchall())
    return {"balance": reseller["balance"], "products": products}


@router.get("/reseller/overview")
async def reseller_overview(reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    """Reseller-scoped dashboard metrics, recent ledger activity, and sales trends."""
    async with db.execute(
        """SELECT COUNT(*) AS total_sales,
                  COALESCE(SUM(o.amount_paid), 0) AS total_spent,
                  SUM(CASE WHEN l.status='active' THEN 1 ELSE 0 END) AS active_keys,
                  SUM(CASE WHEN l.status='banned' THEN 1 ELSE 0 END) AS banned_keys,
                  SUM(CASE WHEN l.status='active' AND l.expires_at IS NOT NULL
                                AND l.expires_at <= datetime('now', '+7 days') THEN 1 ELSE 0 END) AS expiring_soon
           FROM key_orders o JOIN licenses l ON l.id=o.license_id
           WHERE o.reseller_id=?""",
        (reseller["id"],),
    ) as cur:
        totals = dict(await cur.fetchone())

    async with db.execute(
        """SELECT DATE(created_at) AS date, COUNT(*) AS count,
                  COALESCE(SUM(amount_paid), 0) AS amount
           FROM key_orders
           WHERE reseller_id=? AND created_at >= datetime('now', '-29 days')
           GROUP BY DATE(created_at) ORDER BY date""",
        (reseller["id"],),
    ) as cur:
        sales_by_date = rows_to_list(await cur.fetchall())

    async with db.execute(
        """SELECT p.id, p.name, p.level, COUNT(*) AS count,
                  COALESCE(SUM(o.amount_paid), 0) AS amount
           FROM key_orders o JOIN products p ON p.id=o.product_id
           WHERE o.reseller_id=? GROUP BY p.id, p.name, p.level
           ORDER BY count DESC, p.name LIMIT 8""",
        (reseller["id"],),
    ) as cur:
        top_products = rows_to_list(await cur.fetchall())

    async with db.execute(
        """SELECT amount, reason, created_by, created_at
           FROM reseller_balance_ledger WHERE reseller_id=?
           ORDER BY created_at DESC LIMIT 20""",
        (reseller["id"],),
    ) as cur:
        ledger = rows_to_list(await cur.fetchall())
    running_balance = float(reseller["balance"] or 0)
    recent_ledger = []
    for entry in ledger:
        recent_ledger.append({
            **entry,
            "type": "credit" if entry["amount"] >= 0 else "purchase",
            "description": entry["reason"],
            "balance_after": running_balance,
        })
        running_balance -= float(entry["amount"])

    return {
        "username": reseller["username"],
        "balance": reseller["balance"],
        **totals,
        "sales_by_date": sales_by_date,
        "top_products": top_products,
        "recent_ledger": recent_ledger,
    }


class ResellerBuyBody(BaseModel):
    product_id: str
    pricing_point_id: str


@router.post("/reseller/buy-key")
async def reseller_buy_key(body: ResellerBuyBody, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("BEGIN IMMEDIATE")
    try:
        async with db.execute(
            """SELECT monthly_quota,monthly_used,quota_reset_at FROM reseller_product_access
               WHERE reseller_id = ? AND product_id = ?""",
            (reseller["id"], body.product_id),
        ) as cur:
            allowed = await cur.fetchone()
        if not allowed:
            raise HTTPException(403, "Reseller is not allowed to buy this product")
        if allowed["quota_reset_at"] is None or allowed["quota_reset_at"] <= utcnow():
            await db.execute(
                """UPDATE reseller_product_access SET monthly_used=0,
                   quota_reset_at=datetime('now','start of month','+1 month')
                   WHERE reseller_id=? AND product_id=?""", (reseller["id"], body.product_id),
            )
            used = 0
        else:
            used = int(allowed["monthly_used"] or 0)
        if allowed["monthly_quota"] is not None and used >= int(allowed["monthly_quota"]):
            raise HTTPException(409, "Monthly product quota reached")

        async with db.execute(
            "SELECT 1 FROM reseller_pricing_access WHERE reseller_id = ? AND pricing_point_id = ?",
            (reseller["id"], body.pricing_point_id),
        ) as cur:
            pricing_allowed = await cur.fetchone()
        if not pricing_allowed:
            raise HTTPException(403, "Reseller is not allowed to buy this pricing point")

        async with db.execute(
            """SELECT p.id as product_id, p.app_id, pp.id as pricing_id, pp.days, pp.price
               FROM products p
               JOIN product_pricing_points pp ON pp.product_id = p.id
               WHERE p.id = ? AND pp.id = ? AND p.is_active = 1""",
            (body.product_id, body.pricing_point_id),
        ) as cur:
            target = await cur.fetchone()
        if not target:
            raise HTTPException(404, "Product/pricing not found")

        async with db.execute("SELECT balance FROM resellers WHERE id = ?", (reseller["id"],)) as cur:
            bal_row = await cur.fetchone()
        current_balance = bal_row["balance"] if bal_row else 0
        if current_balance < target["price"]:
            raise HTTPException(400, "Insufficient reseller balance")

        expires = (datetime.now(timezone.utc) + timedelta(days=target["days"])).strftime("%Y-%m-%d %H:%M:%S")
        license_id = generate_uid()
        license_key = generate_license_key()
        await db.execute(
            """INSERT INTO licenses (id, key, key_hash, key_ciphertext, app_id, max_hwids, expires_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (license_id, mask_license_key(license_key), hash_license_key(license_key),
             encrypt_license_key(license_key), target["app_id"], 1, expires, f"product_id={target['product_id']}"),
        )
        await db.execute(
            "INSERT OR IGNORE INTO license_products (id, license_id, product_id, expires_at) VALUES (?, ?, ?, ?)",
            (generate_uid(), license_id, target["product_id"], expires),
        )
        await db.execute("UPDATE resellers SET balance = balance - ? WHERE id = ?", (target["price"], reseller["id"]))
        await db.execute(
            "UPDATE reseller_product_access SET monthly_used=monthly_used+1 WHERE reseller_id=? AND product_id=?",
            (reseller["id"], body.product_id),
        )
        await db.execute(
            "INSERT INTO reseller_balance_ledger (id, reseller_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?)",
            (generate_uid(), reseller["id"], -target["price"], f"Bought key for {target['days']} days", reseller["username"]),
        )
        await db.execute(
            """INSERT INTO key_orders (id, reseller_id, license_id, product_id, pricing_point_id, amount_paid)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (generate_uid(), reseller["id"], license_id, target["product_id"], target["pricing_id"], target["price"]),
        )
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(500, "Failed to process reseller order")
    return {
        "license_id": license_id,
        "license_key": license_key,
        "days": target["days"],
        "price_paid": target["price"],
        "expires_at": expires,
    }


@router.get("/reseller/keys")
async def reseller_list_keys(reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT l.*, p.level as product_level, p.name as product_name, pp.days as pricing_days, pp.price as pricing_price
           FROM key_orders o
           JOIN licenses l ON l.id = o.license_id
           JOIN products p ON p.id = o.product_id
           JOIN product_pricing_points pp ON pp.id = o.pricing_point_id
           WHERE o.reseller_id = ?
           ORDER BY l.created_at DESC""",
        (reseller["id"],),
    ) as cur:
        rows = rows_to_list(await cur.fetchall())
    for row in rows:
        row["key"] = display_license_key(row["key"], row.get("key_ciphertext"))
        row.pop("key_ciphertext", None)
    return {"keys": rows}


async def _require_reseller_license(reseller_id: str, license_id: str, db: aiosqlite.Connection):
    async with db.execute(
        "SELECT 1 FROM key_orders WHERE reseller_id = ? AND license_id = ?",
        (reseller_id, license_id),
    ) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Key not found")


@router.post("/reseller/keys/{license_id}/ban")
async def reseller_ban_key(license_id: str, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await _require_reseller_license(reseller["id"], license_id, db)
    await db.execute("UPDATE licenses SET status='banned' WHERE id=?", (license_id,))
    await db.execute("DELETE FROM sessions WHERE license_id=?", (license_id,))
    await db.commit()
    return {"ok": True}


@router.post("/reseller/keys/{license_id}/unban")
async def reseller_unban_key(license_id: str, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await _require_reseller_license(reseller["id"], license_id, db)
    await db.execute("UPDATE licenses SET status='active' WHERE id=?", (license_id,))
    await db.commit()
    return {"ok": True}


@router.delete("/reseller/keys/{license_id}")
async def reseller_delete_key(license_id: str, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await _require_reseller_license(reseller["id"], license_id, db)
    await db.execute("DELETE FROM licenses WHERE id=?", (license_id,))
    await db.commit()
    return {"ok": True}


class ResellerBulkKeysBody(BaseModel):
    license_ids: list[str]


def _qmarks(n: int) -> str:
    return ",".join(["?"] * n)


async def _valid_reseller_license_ids(reseller_id: str, license_ids: list[str], db: aiosqlite.Connection) -> list[str]:
    if not license_ids:
        return []
    uniq = list(dict.fromkeys([str(x) for x in license_ids]))
    q = _qmarks(len(uniq))
    async with db.execute(
        f"SELECT license_id FROM key_orders WHERE reseller_id = ? AND license_id IN ({q})",
        [reseller_id, *uniq],
    ) as cur:
        rows = await cur.fetchall()
    return [r[0] for r in rows]


@router.post("/reseller/keys/bulk-ban")
async def reseller_bulk_ban(body: ResellerBulkKeysBody, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("BEGIN IMMEDIATE")
    try:
        valid_ids = await _valid_reseller_license_ids(reseller["id"], body.license_ids, db)
        if not valid_ids:
            return {"ok": True, "deleted": 0}
        q = _qmarks(len(valid_ids))
        await db.execute(f"UPDATE licenses SET status='banned' WHERE id IN ({q})", valid_ids)
        await db.execute(f"DELETE FROM sessions WHERE license_id IN ({q})", valid_ids)
        await db.commit()
        return {"ok": True, "updated": len(valid_ids)}
    except Exception:
        await db.rollback()
        raise HTTPException(500, "Failed to bulk ban keys")


@router.post("/reseller/keys/bulk-unban")
async def reseller_bulk_unban(body: ResellerBulkKeysBody, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("BEGIN IMMEDIATE")
    try:
        valid_ids = await _valid_reseller_license_ids(reseller["id"], body.license_ids, db)
        if not valid_ids:
            return {"ok": True, "updated": 0}
        q = _qmarks(len(valid_ids))
        await db.execute(f"UPDATE licenses SET status='active' WHERE id IN ({q})", valid_ids)
        await db.commit()
        return {"ok": True, "updated": len(valid_ids)}
    except Exception:
        await db.rollback()
        raise HTTPException(500, "Failed to bulk unban keys")


@router.post("/reseller/keys/bulk-delete")
async def reseller_bulk_delete(body: ResellerBulkKeysBody, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("BEGIN IMMEDIATE")
    try:
        valid_ids = await _valid_reseller_license_ids(reseller["id"], body.license_ids, db)
        if not valid_ids:
            return {"ok": True, "deleted": 0}
        q = _qmarks(len(valid_ids))
        await db.execute(f"DELETE FROM licenses WHERE id IN ({q})", valid_ids)
        await db.commit()
        return {"ok": True, "deleted": len(valid_ids)}
    except Exception:
        await db.rollback()
        raise HTTPException(500, "Failed to bulk delete keys")


# ─── Dashboard ───────────────────────────────────────────────────────────────

@router.get("/dashboard")
async def dashboard(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)

    async def scalar(sql, *args):
        async with db.execute(sql, args) as cur:
            r = await cur.fetchone()
            return r[0] if r else 0

    if owner_id:
        total_licenses = await scalar(
            """SELECT COUNT(*) FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE a.owner_user_id = ?""",
            owner_id,
        )
        active_licenses = await scalar(
            """SELECT COUNT(*) FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE l.status='active' AND a.owner_user_id = ?""",
            owner_id,
        )
        banned_licenses = await scalar(
            """SELECT COUNT(*) FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE l.status='banned' AND a.owner_user_id = ?""",
            owner_id,
        )
        active_sessions = await scalar(
            """SELECT COUNT(*) FROM sessions s
               JOIN applications a ON a.id = s.app_id
               WHERE s.expires_at > ? AND a.owner_user_id = ?""",
            utcnow(), owner_id,
        )
        total_apps = await scalar("SELECT COUNT(*) FROM applications WHERE owner_user_id = ?", owner_id)
        paused_apps = await scalar("SELECT COUNT(*) FROM applications WHERE is_paused=1 AND owner_user_id=?", owner_id)
        paused_products = await scalar(
            """SELECT COUNT(*) FROM products p JOIN applications a ON a.id=p.app_id
               WHERE p.is_paused=1 AND a.owner_user_id=?""", owner_id)
        failed_logins = await scalar(
            """SELECT COUNT(*) FROM logs lg JOIN applications a ON a.id=lg.app_id
               WHERE lg.action LIKE '%fail%' AND lg.timestamp >= datetime('now','-1 hour')
               AND a.owner_user_id=?""", owner_id)
    else:
        total_licenses  = await scalar("SELECT COUNT(*) FROM licenses")
        active_licenses = await scalar("SELECT COUNT(*) FROM licenses WHERE status='active'")
        banned_licenses = await scalar("SELECT COUNT(*) FROM licenses WHERE status='banned'")
        active_sessions = await scalar("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", utcnow())
        total_apps      = await scalar("SELECT COUNT(*) FROM applications")
        paused_apps = await scalar("SELECT COUNT(*) FROM applications WHERE is_paused=1")
        paused_products = await scalar("SELECT COUNT(*) FROM products WHERE is_paused=1")
        failed_logins = await scalar(
            "SELECT COUNT(*) FROM logs WHERE action LIKE '%fail%' AND timestamp >= datetime('now','-1 hour')")
    today           = utcnow()[:10]
    if owner_id:
        logins_today = await scalar(
            """SELECT COUNT(*) FROM logs lg
               JOIN applications a ON a.id = lg.app_id
               WHERE lg.action='login' AND lg.timestamp >= ? AND a.owner_user_id = ?""",
            today, owner_id,
        )
        async with db.execute(
            """SELECT lg.* FROM logs lg
               JOIN applications a ON a.id = lg.app_id
               WHERE a.owner_user_id = ?
               ORDER BY lg.timestamp DESC LIMIT 10""",
            (owner_id,),
        ) as cur:
            recent_logs = rows_to_list(await cur.fetchall())
        async with db.execute(
            """SELECT strftime('%H', lg.timestamp) AS hour,
                      SUM(CASE WHEN lg.action = 'login' THEN 1 ELSE 0 END) AS success,
                      SUM(CASE WHEN lg.action LIKE '%fail%' THEN 1 ELSE 0 END) AS failed
               FROM logs lg JOIN applications a ON a.id = lg.app_id
               WHERE lg.timestamp >= datetime('now', '-23 hours') AND a.owner_user_id = ?
               GROUP BY strftime('%Y-%m-%d %H', lg.timestamp)
               ORDER BY lg.timestamp""",
            (owner_id,),
        ) as cur:
            traffic = rows_to_list(await cur.fetchall())
    else:
        logins_today = await scalar("SELECT COUNT(*) FROM logs WHERE action='login' AND timestamp >= ?", today)
        async with db.execute(
            "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10"
        ) as cur:
            recent_logs = rows_to_list(await cur.fetchall())
        async with db.execute(
            """SELECT strftime('%H', timestamp) AS hour,
                      SUM(CASE WHEN action = 'login' THEN 1 ELSE 0 END) AS success,
                      SUM(CASE WHEN action LIKE '%fail%' THEN 1 ELSE 0 END) AS failed
               FROM logs WHERE timestamp >= datetime('now', '-23 hours')
               GROUP BY strftime('%Y-%m-%d %H', timestamp)
               ORDER BY timestamp"""
        ) as cur:
            traffic = rows_to_list(await cur.fetchall())

    async with db.execute("PRAGMA quick_check") as cur:
        integrity_row = await cur.fetchone()
    security_where = ""
    security_args = []
    if owner_id:
        security_where = " AND app_id IN (SELECT id FROM applications WHERE owner_user_id=?)"
        security_args = [owner_id]
    security_counts = {}
    for label, condition in {
        "suspicious_ip_changes": "action='suspicious_login'",
        "invalid_key_attempts": "action='login_fail' AND details='Key not found'",
        "hwid_limit_violations": "action='login_hwid_limit'",
        "replay_attempts": "action='login_fail' AND LOWER(details) LIKE '%replay%'",
    }.items():
        async with db.execute(
            f"SELECT COUNT(*) FROM logs WHERE timestamp>=datetime('now','-24 hours') AND {condition}{security_where}",
            security_args,
        ) as cur:
            security_counts[label] = (await cur.fetchone())[0]
    top_sql = """SELECT a.name,COUNT(*) AS attempts FROM logs lg JOIN applications a ON a.id=lg.app_id
                 WHERE lg.timestamp>=datetime('now','-24 hours') AND lg.action LIKE '%fail%'"""
    top_args = []
    if owner_id:
        top_sql += " AND a.owner_user_id=?"; top_args.append(owner_id)
    top_sql += " GROUP BY lg.app_id ORDER BY attempts DESC LIMIT 5"
    async with db.execute(top_sql, top_args) as cur:
        top_targets = rows_to_list(await cur.fetchall())
    db_file = Path(DB_PATH)
    configuration = {
        "secure_cookies": COOKIE_SECURE,
        "restricted_cors": os.getenv("CORS_ORIGINS", "*").strip() != "*",
        "license_pepper_set": bool(os.getenv("LICENSE_KEY_PEPPER", "").strip()),
        "debug_disabled": os.getenv("DEBUG", "false").lower() != "true",
    }
    return {
        "total_licenses":  total_licenses,
        "active_licenses": active_licenses,
        "banned_licenses": banned_licenses,
        "active_sessions": active_sessions,
        "total_apps":      total_apps,
        "logins_today":    logins_today,
        "recent_logs":     recent_logs,
        "traffic":         traffic,
        "monitoring": {
            "database_ok": bool(integrity_row and integrity_row[0] == "ok"),
            "database_size_bytes": db_file.stat().st_size if db_file.exists() else 0,
            "uptime_seconds": int(time.monotonic() - SERVER_STARTED_MONOTONIC),
            "paused_apps": paused_apps,
            "paused_products": paused_products,
            "failed_logins_last_hour": failed_logins,
            "configuration": configuration,
            "security_events": {**security_counts, "most_targeted_apps": top_targets},
        },
    }


@router.get("/security/control-center")
async def security_control_center(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    """Operational and security state without returning secrets or raw session tokens."""
    owner_id = auth_owner_id(user)
    ownership_sql = "WHERE a.owner_user_id = ?" if owner_id else ""
    ownership_args = [owner_id] if owner_id else []
    async with db.execute(
        f"""SELECT a.id,a.name,a.version,a.is_paused,a.pause_reason,
                   CASE WHEN a.is_paused=1 THEN 'offline' ELSE 'operational' END AS service_status,
                   (SELECT COUNT(*) FROM licenses l WHERE l.app_id=a.id) AS licenses,
                   (SELECT COUNT(*) FROM sessions s WHERE s.app_id=a.id
                    AND s.expires_at>datetime('now')) AS active_sessions,
                   (SELECT COUNT(*) FROM app_files f WHERE f.app_id=a.id
                    AND f.is_revoked=1) AS revoked_builds
            FROM applications a
            {ownership_sql}
            ORDER BY a.name""",
        ownership_args,
    ) as cur:
        apps = rows_to_list(await cur.fetchall())

    app_ids = [app["id"] for app in apps]
    event_counts = {"failed_auth": 0, "replay": 0, "hwid_limit": 0, "suspicious": 0}
    recent_events = []
    outstanding_tickets = 0
    if app_ids:
        marks = _qmarks(len(app_ids))
        async with db.execute(
            f"""SELECT
                SUM(CASE WHEN action LIKE '%fail%' THEN 1 ELSE 0 END) failed_auth,
                SUM(CASE WHEN LOWER(COALESCE(details,'')) LIKE '%replay%' THEN 1 ELSE 0 END) replay,
                SUM(CASE WHEN action='login_hwid_limit' THEN 1 ELSE 0 END) hwid_limit,
                SUM(CASE WHEN action='suspicious_login' THEN 1 ELSE 0 END) suspicious
                FROM logs WHERE timestamp>=datetime('now','-24 hours') AND app_id IN ({marks})""",
            app_ids,
        ) as cur:
            row = await cur.fetchone()
            if row:
                event_counts = {key: int(row[key] or 0) for key in event_counts}
        async with db.execute(
            f"""SELECT id,app_id,action,ip,details,timestamp FROM logs
                WHERE app_id IN ({marks}) AND
                (action LIKE '%fail%' OR action IN ('suspicious_login','login_hwid_limit','build_revoked','emergency_lockdown'))
                ORDER BY timestamp DESC LIMIT 30""",
            app_ids,
        ) as cur:
            recent_events = rows_to_list(await cur.fetchall())
        async with db.execute(
            f"""SELECT COUNT(*) FROM download_tickets
                WHERE app_id IN ({marks}) AND consumed_at IS NULL AND expires_at>datetime('now')""",
            app_ids,
        ) as cur:
            outstanding_tickets = int((await cur.fetchone())[0])

    settings = {
        "secure_cookies": COOKIE_SECURE,
        "cors_restricted": os.getenv("CORS_ORIGINS", "*").strip() != "*",
        "debug_disabled": os.getenv("DEBUG", "false").lower() != "true",
        "license_pepper_configured": bool(os.getenv("LICENSE_KEY_PEPPER", "").strip()),
        "legacy_protocol_disabled": os.getenv("ALLOW_LEGACY_PROTOCOL", "true").lower() != "true",
        "backup_encryption_configured": bool(BACKUP_ENCRYPTION_KEY),
        "automatic_backups_enabled": int(os.getenv("AUTO_BACKUP_HOURS", "0")) > 0,
    }
    return {
        "generated_at": utcnow(),
        "applications": apps,
        "events_24h": event_counts,
        "recent_security_events": recent_events,
        "outstanding_download_tickets": outstanding_tickets,
        "security_settings": settings,
        "security_score": round(100 * sum(bool(v) for v in settings.values()) / len(settings)),
    }


@router.get("/operations/health")
async def operations_health(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    started = time.perf_counter()
    async with db.execute("SELECT 1") as cur:
        await cur.fetchone()
    database_latency = round((time.perf_counter() - started) * 1000, 2)
    disk = shutil.disk_usage(Path(DB_PATH).resolve().parent)
    backups = sorted(BACKUP_DIR.glob("enauth-*.db"), key=lambda p: p.stat().st_mtime, reverse=True) if BACKUP_DIR.exists() else []
    backup_age = int(time.time() - backups[0].stat().st_mtime) if backups else None
    async with db.execute("SELECT MAX(last_used) FROM discord_integrations WHERE is_active=1") as cur:
        bot_last_seen = (await cur.fetchone())[0]
    signing = {"available": RESPONSE_SIGNING_KEY_PATH.is_file(), "public_key": None, "permissions_restricted": None}
    if signing["available"]:
        signing["public_key"] = response_public_key_hex()
        signing["permissions_restricted"] = ((RESPONSE_SIGNING_KEY_PATH.stat().st_mode & 0o077) == 0
                                              if os.name != "nt" else True)
    certificate = {"configured": False, "expires_at": None, "days_remaining": None, "healthy": None, "status": "not configured"}
    certificate_path = os.getenv("TLS_CERTIFICATE_PATH", "").strip()
    if certificate_path and Path(certificate_path).is_file():
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(Path(certificate_path).read_bytes())
            expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
            days = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
            certificate = {"configured": True, "expires_at": expiry.isoformat(),
                           "days_remaining": days, "healthy": days >= 14,
                           "status": "healthy" if days >= 14 else "expiring"}
        except Exception:
            certificate = {"configured": True, "expires_at": None, "days_remaining": None,
                           "healthy": False, "status": "invalid certificate"}
    disk_percent = round(100 * disk.used / max(disk.total, 1), 1)
    backup_hours = round(backup_age / 3600, 1) if backup_age is not None else None
    bot_status = "offline"
    if bot_last_seen:
        try:
            last_bot = datetime.strptime(bot_last_seen, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            bot_status = "healthy" if (_utcnow_dt() - last_bot).total_seconds() <= 180 else "stale"
        except (TypeError, ValueError):
            bot_status = "unknown"
    signing["status"] = "healthy" if signing["available"] and signing["permissions_restricted"] else "unhealthy"
    signing["key_id"] = (signing["public_key"] or "")[:16]
    return {"generated_at": utcnow(), "runtime": runtime_metrics_snapshot(),
            "database": {"latency_ms": database_latency, "healthy": database_latency < 250},
            "disk": {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free,
                     "free_gb": round(disk.free / 1073741824, 1), "percent_used": disk_percent,
                     "healthy": disk.free / max(disk.total, 1) > .1},
            "backups": {"latest_age_seconds": backup_age, "latest_age_hours": backup_hours, "count": len(backups),
                        "healthy": backup_age is not None and backup_age < 172800},
            "discord_bot": {"last_seen": bot_last_seen, "healthy": bot_status == "healthy", "status": bot_status},
            "signing_key": signing, "certificate": certificate}


@router.get("/sdk/releases")
async def list_sdk_releases(user=Depends(require_admin), db=Depends(get_db)):
    async with db.execute(
        """SELECT id,version,channel,status,package_name,package_size,sha256,signature,
                  release_notes,created_at FROM sdk_releases ORDER BY created_at DESC"""
    ) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/sdk/releases")
async def publish_sdk_release(version: str = Form(...), channel: str = Form("stable"),
                              status: str = Form("supported"), release_notes: str = Form(""),
                              file: UploadFile = File(...), user=Depends(require_owner), db=Depends(get_db)):
    version = validate_release_version(version)
    if channel not in {"stable", "beta", "preview", "legacy"} or status not in {"supported", "deprecated", "blocked"}:
        raise HTTPException(400, "Invalid SDK channel or status")
    content = await read_build_upload(file)
    package_name = validate_release_name(Path(file.filename or f"enauth-sdk-{version}.zip").name)
    digest = hashlib.sha256(content).hexdigest()
    release_id, created_at = generate_uid(), utcnow()
    signature = sign_response(f"sdk-package|{release_id}|{version}|{digest}|{created_at}")
    try:
        await db.execute(
            """INSERT INTO sdk_releases(id,version,channel,status,package_name,package,package_size,
               sha256,signature,release_notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (release_id, version, channel, status, package_name,
             content, len(content), digest, signature, release_notes.strip() or None, created_at),
        )
        await log_action(db, "sdk_release_published", details=f"version={version}; channel={channel}; sha256={digest}")
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "SDK version already exists")
    return {"id": release_id, "version": version, "sha256": digest, "signature": signature}


@router.get("/sdk/releases/{release_id}/download")
async def download_sdk_release(release_id: str, user=Depends(require_admin), db=Depends(get_db)):
    async with db.execute("SELECT * FROM sdk_releases WHERE id=?", (release_id,)) as cur:
        release = await cur.fetchone()
    if not release:
        raise HTTPException(404, "SDK release not found")
    return Response(content=release["package"], media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{validate_release_name(release["package_name"])}"',
        "X-EnAuth-SHA256": release["sha256"], "X-EnAuth-Signature": release["signature"],
    })


@router.get("/sdk/documentation")
async def sdk_documentation(user=Depends(require_admin)):
    path = Path(__file__).resolve().parent.parent / "sdk" / "README.md"
    return FileResponse(path, media_type="text/markdown", filename="EnAuth-SDK-README.md")


@router.get("/sdk/compatibility")
async def sdk_compatibility(user=Depends(require_admin), db=Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT a.id AS app_id,a.name,c.minimum_version,c.recommended_version,
                    COALESCE(c.enforce_minimum,0) enforce_minimum,c.upgrade_message,c.updated_at
             FROM applications a LEFT JOIN sdk_compatibility c ON c.app_id=a.id"""
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id=?"; args.append(owner_id)
    sql += " ORDER BY a.name"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.put("/sdk/compatibility/{app_id}")
async def update_sdk_compatibility(app_id: str, body: SdkCompatibilityBody,
                                   user=Depends(require_admin), db=Depends(get_db)):
    await _owned_app(app_id, auth_owner_id(user), db)
    for value in (body.minimum_version, body.recommended_version):
        if value:
            validate_release_version(value)
    await db.execute(
        """INSERT INTO sdk_compatibility(app_id,minimum_version,recommended_version,enforce_minimum,upgrade_message,updated_at)
           VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(app_id) DO UPDATE SET
           minimum_version=excluded.minimum_version,recommended_version=excluded.recommended_version,
           enforce_minimum=excluded.enforce_minimum,upgrade_message=excluded.upgrade_message,
           updated_at=CURRENT_TIMESTAMP""",
        (app_id, body.minimum_version, body.recommended_version, int(body.enforce_minimum),
         (body.upgrade_message or "").strip() or None),
    )
    await log_action(db, "sdk_compatibility_updated", app_id=app_id,
                     details=f"minimum={body.minimum_version}; recommended={body.recommended_version}; enforce={body.enforce_minimum}")
    await db.commit()
    return {"ok": True}


@router.post("/security/sessions/revoke")
async def revoke_filtered_sessions(body: SessionRevokeFilterBody, user=Depends(require_admin),
                                   db: aiosqlite.Connection = Depends(get_db)):
    await _owned_app(body.app_id, auth_owner_id(user), db)
    conditions = ["app_id=?"]
    args = [body.app_id]
    if body.product_id:
        product = await _owned_product(body.product_id, auth_owner_id(user), db)
        if product["app_id"] != body.app_id:
            raise HTTPException(400, "Product does not belong to the application")
        conditions.append("product_id=?"); args.append(body.product_id)
    if body.license_id:
        async with db.execute("SELECT app_id FROM licenses WHERE id=?", (body.license_id,)) as cur:
            license_row = await cur.fetchone()
        if not license_row or license_row["app_id"] != body.app_id:
            raise HTTPException(404, "License not found for this application")
        conditions.append("license_id=?"); args.append(body.license_id)
    where = " AND ".join(conditions)
    await db.execute("BEGIN IMMEDIATE")
    try:
        async with db.execute(f"SELECT COUNT(*) FROM sessions WHERE {where}", args) as cur:
            count = int((await cur.fetchone())[0])
        await db.execute(f"DELETE FROM sessions WHERE {where}", args)
        await db.execute(f"DELETE FROM download_tickets WHERE {where}", args)
        await log_action(db, "sessions_revoked", app_id=body.app_id,
                         details=f"count={count}; reason={body.reason.strip()}")
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return {"ok": True, "revoked_sessions": count}


@router.get("/security/sessions/revoke-preview")
async def preview_filtered_session_revoke(app_id: str, product_id: Optional[str] = None,
                                          license_id: Optional[str] = None,
                                          user=Depends(require_admin), db=Depends(get_db)):
    await _owned_app(app_id, auth_owner_id(user), db)
    conditions, args = ["app_id=?"], [app_id]
    if product_id:
        product = await _owned_product(product_id, auth_owner_id(user), db)
        if product["app_id"] != app_id:
            raise HTTPException(400, "Product does not belong to the application")
        conditions.append("product_id=?"); args.append(product_id)
    if license_id:
        async with db.execute("SELECT app_id FROM licenses WHERE id=?", (license_id,)) as cur:
            license_row = await cur.fetchone()
        if not license_row or license_row["app_id"] != app_id:
            raise HTTPException(404, "License not found for this application")
        conditions.append("license_id=?"); args.append(license_id)
    where = " AND ".join(conditions)
    async with db.execute(
        f"""SELECT COUNT(*) AS sessions,COUNT(DISTINCT license_id) AS licenses,
            COUNT(DISTINCT hwid) AS devices FROM sessions WHERE {where}""", args
    ) as cur:
        counts = dict(await cur.fetchone())
    async with db.execute(
        f"""SELECT COUNT(*) FROM download_tickets WHERE consumed_at IS NULL
            AND expires_at>CURRENT_TIMESTAMP AND {where}""", args
    ) as cur:
        counts["download_tickets"] = int((await cur.fetchone())[0])
    return counts


@router.get("/security/events")
async def list_security_events(app_id: Optional[str] = None, severity: Optional[str] = None,
                               search: Optional[str] = None, limit: int = 50, offset: int = 0,
                               user=Depends(require_admin), db=Depends(get_db)):
    owner_id = auth_owner_id(user)
    conditions = ["(lg.action LIKE '%fail%' OR lg.action IN ('suspicious_login','login_hwid_limit','build_revoked','emergency_lockdown','sessions_revoked','session_authorization_revoked'))"]
    args = []
    if owner_id:
        conditions.append("a.owner_user_id=?"); args.append(owner_id)
    if app_id:
        await _owned_app(app_id, owner_id, db)
        conditions.append("lg.app_id=?"); args.append(app_id)
    if severity:
        if severity not in {"critical", "warning", "info"}:
            raise HTTPException(400, "Invalid severity")
        severity_sql = {
            "critical": "lg.action IN ('emergency_lockdown','build_revoked','suspicious_login')",
            "warning": "(lg.action LIKE '%fail%' OR lg.action IN ('login_hwid_limit','session_authorization_revoked'))",
            "info": "lg.action='sessions_revoked'",
        }[severity]
        conditions.append(severity_sql)
    if search:
        conditions.append("(lg.action LIKE ? OR lg.ip LIKE ? OR lg.details LIKE ?)")
        term = f"%{search[:200]}%"; args.extend([term, term, term])
    where = " AND ".join(conditions)
    async with db.execute(f"SELECT COUNT(*) FROM logs lg LEFT JOIN applications a ON a.id=lg.app_id WHERE {where}", args) as cur:
        total = int((await cur.fetchone())[0])
    async with db.execute(
        f"""SELECT lg.id,lg.app_id,a.name AS app_name,lg.action,lg.ip,lg.details,lg.timestamp,
            CASE WHEN lg.action IN ('emergency_lockdown','build_revoked','suspicious_login') THEN 'critical'
                 WHEN lg.action LIKE '%fail%' OR lg.action IN ('login_hwid_limit','session_authorization_revoked') THEN 'warning'
                 ELSE 'info' END AS severity
            FROM logs lg LEFT JOIN applications a ON a.id=lg.app_id WHERE {where}
            ORDER BY lg.timestamp DESC LIMIT ? OFFSET ?""",
        [*args, clamp_limit(limit, 50), clamp_offset(offset)],
    ) as cur:
        items = rows_to_list(await cur.fetchall())
    return {"items": items, "total": total, "limit": clamp_limit(limit, 50), "offset": clamp_offset(offset)}


@router.post("/security/apps/{app_id}/lockdown")
async def emergency_app_lockdown(app_id: str, body: EmergencyLockdownBody,
                                 user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    app = await _owned_app(app_id, auth_owner_id(user), db)
    if not secrets.compare_digest(body.confirmation, f"LOCK {app_id}"):
        raise HTTPException(400, f"Type LOCK {app_id} to confirm")
    await db.execute("BEGIN IMMEDIATE")
    try:
        async with db.execute("SELECT COUNT(*) FROM sessions WHERE app_id=?", (app_id,)) as cur:
            session_count = int((await cur.fetchone())[0])
        now = utcnow()
        await db.execute(
            "UPDATE applications SET is_paused=1,paused_at=?,pause_reason=? WHERE id=?",
            (now, body.reason.strip(), app_id),
        )
        async with db.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)) as cur:
            affected = int((await cur.fetchone())[0])
        await db.execute(
            """INSERT INTO outage_events(id,app_id,event_type,service_status,status_color,
               public_message,started_at,affected_licenses) VALUES(?,?,?,?,?,?,?,?)""",
            (generate_uid(), app_id, "emergency_lockdown", "offline", "#ef4444",
             body.reason.strip(), now, affected),
        )
        await db.execute("DELETE FROM sessions WHERE app_id=?", (app_id,))
        await db.execute("DELETE FROM download_tickets WHERE app_id=?", (app_id,))
        await log_action(db, "emergency_lockdown", app_id=app_id,
                         details=f"{app['name']}; sessions={session_count}; reason={body.reason.strip()}")
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return {"ok": True, "app_id": app_id, "revoked_sessions": session_count,
            "downloads_invalidated": True, "authentication_paused": True}


# ─── Discord integrations ────────────────────────────────────────────────────

class CreateDiscordIntegrationBody(BaseModel):
    app_id: str = Field(min_length=1, max_length=128)


@router.get("/discord-integrations")
async def list_discord_integrations(user=Depends(require_owner), db=Depends(get_db)):
    async with db.execute(
        """SELECT di.id,di.app_id,di.key_prefix,di.is_active,di.last_used,di.created_at,a.name AS app_name
           FROM discord_integrations di JOIN applications a ON a.id=di.app_id
           ORDER BY di.created_at DESC"""
    ) as cur:
        integrations = rows_to_list(await cur.fetchall())
    client_id = os.getenv("DISCORD_CLIENT_ID", "").strip()
    invite_url = (
        f"https://discord.com/oauth2/authorize?client_id={client_id}&permissions=0&scope=bot%20applications.commands"
        if client_id.isdigit() else None
    )
    return {"integrations": integrations, "client_id": client_id or None, "invite_url": invite_url}


@router.get("/response-signing-public-key")
async def get_response_signing_public_key(user=Depends(require_owner)):
    return {"algorithm": "ECDSA-P256-SHA256", "public_key_hex": response_public_key_hex()}


@router.get("/developer/overview")
async def developer_overview(request: Request, user=Depends(require_admin),
                             db: aiosqlite.Connection = Depends(get_db)):
    """Non-secret integration inventory for the Developer Center."""
    async with db.execute(
        """SELECT ak.id,ak.name,ak.key_prefix,ak.scopes,ak.is_active,ak.last_used,ak.expires_at,
                  ak.usage_count,ak.last_ip,ak.app_id,a.name AS app_name,ak.allowed_ips
           FROM api_keys ak LEFT JOIN applications a ON a.id=ak.app_id
           WHERE ak.user_id=? ORDER BY ak.last_used DESC,ak.created_at DESC""", (user["id"],),
    ) as cur:
        keys = rows_to_list(await cur.fetchall())
    async with db.execute(
        "SELECT COUNT(*) FROM applications WHERE (? IS NULL OR owner_user_id=?)",
        (auth_owner_id(user), auth_owner_id(user)),
    ) as cur:
        application_count = (await cur.fetchone())[0]
    scopes = [
        {"name": "apps.read", "description": "Read application and product metadata"},
        {"name": "apps.modify", "description": "Pause apps and change product status"},
        {"name": "licenses.read", "description": "List licenses and customer requests"},
        {"name": "licenses.generate", "description": "Generate new licenses"},
        {"name": "licenses.modify", "description": "Ban, extend, reset, or update licenses"},
        {"name": "licenses.reveal", "description": "Reveal stored plaintext license keys"},
        {"name": "licenses.delete", "description": "Permanently delete licenses"},
        {"name": "logs.read", "description": "Read application security events"},
        {"name": "builds.read", "description": "List protected releases"},
        {"name": "builds.upload", "description": "Publish or replace protected releases"},
        {"name": "builds.delete", "description": "Delete protected releases"},
    ]
    return {
        "api_base": str(request.base_url).rstrip("/") + "/api/integrations",
        "openapi_url": "/api/admin/developer/openapi",
        "interactive_docs_url": "/docs",
        "response_signing": {"algorithm": "ECDSA-P256-SHA256", "public_key_hex": response_public_key_hex()},
        "protocol": {"current": 2, "legacy_allowed": os.getenv("ALLOW_LEGACY_PROTOCOL", "true").lower() == "true"},
        "limits": {"max_json_bytes": int(os.getenv("MAX_JSON_BYTES", str(2 * 1024 * 1024))),
                   "max_upload_bytes": int(os.getenv("MAX_BUILD_UPLOAD_BYTES", str(100 * 1024 * 1024))),
                   "session_token_seconds": int(os.getenv("SESSION_TOKEN_SECONDS", "300"))},
        "application_count": application_count, "keys": keys, "scopes": scopes,
    }


@router.get("/developer/openapi")
async def download_openapi(request: Request, user=Depends(require_admin)):
    schema = request.app.openapi()
    return JSONResponse(schema, headers={"Content-Disposition": 'attachment; filename="enauth-openapi.json"'})


@router.post("/discord-integrations")
async def create_discord_integration(body: CreateDiscordIntegrationBody,
                                     user=Depends(require_owner), db=Depends(get_db)):
    async with db.execute("SELECT id,name FROM applications WHERE id=?", (body.app_id,)) as cur:
        app = await cur.fetchone()
    if not app:
        raise HTTPException(404, "Application not found")
    raw_key = "enauth_discord_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    key_prefix = raw_key[:24]
    integration_id = generate_uid()
    await db.execute("UPDATE discord_integrations SET is_active=0 WHERE app_id=?", (body.app_id,))
    await db.execute(
        """INSERT INTO discord_integrations(id,app_id,key_hash,key_prefix,created_by)
           VALUES(?,?,?,?,?)""",
        (integration_id, body.app_id, key_hash, key_prefix, user["id"]),
    )
    await log_action(db, "discord_integration_created", app_id=body.app_id,
                     details=f"integration={integration_id}")
    await db.commit()
    return {
        "id": integration_id, "app_id": body.app_id, "app_name": app["name"],
        "key": raw_key, "key_prefix": key_prefix,
        "warning": "This key is shown once. Store it in the Discord bot configuration.",
    }


@router.delete("/discord-integrations/{integration_id}")
async def revoke_discord_integration(integration_id: str, user=Depends(require_owner), db=Depends(get_db)):
    async with db.execute("SELECT app_id FROM discord_integrations WHERE id=?", (integration_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Discord integration not found")
    await db.execute("UPDATE discord_integrations SET is_active=0 WHERE id=?", (integration_id,))
    await log_action(db, "discord_integration_revoked", app_id=row["app_id"], details=integration_id)
    await db.commit()
    return {"ok": True}


# ─── Licenses ────────────────────────────────────────────────────────────────

class CreateLicenseBody(BaseModel):
    app_id:    str
    product_ids: list[str] = []
    max_hwids: int = 1
    expires_days: Optional[float] = None  # None = lifetime
    expires_hours: Optional[float] = None  # None = lifetime
    notes:     Optional[str] = None
    count:     int = 1  # how many keys to generate at once
    prefix:    Optional[str] = None  # custom prefix for keys
    metadata:  Optional[str] = None

class UpdateLicenseBody(BaseModel):
    status:    Optional[str] = None
    max_hwids: Optional[int] = None
    expires_at: Optional[str] = None
    notes:    Optional[str] = None


class BulkIdsBody(BaseModel):
    ids: list[str]


class LicenseTemplateBody(BaseModel):
    app_id: str
    name: str = Field(min_length=1, max_length=80)
    product_ids: list[str]
    duration_hours: Optional[float] = Field(default=None, gt=0, le=876000)
    max_hwids: int = Field(default=1, ge=1, le=100)
    key_prefix: Optional[str] = Field(default=None, max_length=10)
    notes: Optional[str] = Field(default=None, max_length=500)
    metadata: Optional[str] = Field(default=None, max_length=2000)


@router.get("/license-templates")
async def list_license_templates(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT t.*,a.name AS app_name FROM license_templates t
             JOIN applications a ON a.id=t.app_id"""
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id=?"; args.append(owner_id)
    sql += " ORDER BY t.name"
    async with db.execute(sql, args) as cur:
        rows = rows_to_list(await cur.fetchall())
    for row in rows:
        row["product_ids"] = json.loads(row["product_ids"])
    return rows


@router.post("/license-templates")
async def save_license_template(body: LicenseTemplateBody, user=Depends(require_admin),
                                db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    app_sql, args = "SELECT id FROM applications WHERE id=?", [body.app_id]
    if owner_id:
        app_sql += " AND owner_user_id=?"; args.append(owner_id)
    async with db.execute(app_sql, args) as cur:
        if not await cur.fetchone(): raise HTTPException(404, "Application not found")
    unique_products = list(dict.fromkeys(body.product_ids))
    if not unique_products: raise HTTPException(400, "Select at least one product")
    marks = ",".join("?" for _ in unique_products)
    async with db.execute(f"SELECT COUNT(*) FROM products WHERE app_id=? AND id IN ({marks})",
                          [body.app_id, *unique_products]) as cur:
        if (await cur.fetchone())[0] != len(unique_products): raise HTTPException(400, "Invalid product selection")
    template_id = generate_uid()
    try:
        await db.execute(
            """INSERT INTO license_templates
               (id,app_id,name,product_ids,duration_hours,max_hwids,key_prefix,notes,metadata)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (template_id, body.app_id, body.name.strip(), json.dumps(unique_products), body.duration_hours,
             body.max_hwids, (body.key_prefix or "").strip().upper() or None, body.notes, body.metadata),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "A template with this name already exists for the application")
    return {"id": template_id, "name": body.name.strip()}


@router.delete("/license-templates/{template_id}")
async def delete_license_template(template_id: str, user=Depends(require_admin),
                                  db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "DELETE FROM license_templates WHERE id=?"
    args = [template_id]
    if owner_id:
        sql += " AND app_id IN (SELECT id FROM applications WHERE owner_user_id=?)"; args.append(owner_id)
    cursor = await db.execute(sql, args); await db.commit()
    if cursor.rowcount != 1: raise HTTPException(404, "Template not found")
    return {"ok": True}


@router.get("/licenses")
async def list_licenses(app_id: Optional[str] = None,
                        status: Optional[str] = None,
                        search: Optional[str] = None,
                        product_id: Optional[str] = None,
                        expired: Optional[bool] = None,
                        metadata: Optional[str] = None,
                        limit: int = 100, offset: int = 0,
                        user=Depends(require_admin),
                        db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT l.*, a.name as app_name,
             (SELECT COUNT(*) FROM hwids WHERE license_id = l.id) as hwid_count
             FROM licenses l JOIN applications a ON a.id = l.app_id WHERE 1=1"""
    args = []
    if owner_id:
        sql += " AND a.owner_user_id = ?"; args.append(owner_id)
    if app_id:
        sql += " AND l.app_id = ?"; args.append(app_id)
    if status:
        sql += " AND l.status = ?"; args.append(status)
    if search:
        sql += " AND (l.key LIKE ? OR l.notes LIKE ? OR l.metadata LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if product_id:
        sql += " AND l.id IN (SELECT license_id FROM license_products WHERE product_id = ?)"; args.append(product_id)
    if expired is True:
        sql += " AND l.expires_at < ?"; args.append(utcnow())
    elif expired is False:
        sql += " AND (l.expires_at IS NULL OR l.expires_at >= ?)"; args.append(utcnow())
    if metadata:
        sql += " AND l.metadata LIKE ?"; args.append(f"%{metadata}%")
    sql += " ORDER BY l.created_at DESC LIMIT ? OFFSET ?"
    args += [clamp_limit(limit, 100), clamp_offset(offset)]

    async with db.execute(sql, args) as cur:
        rows = rows_to_list(await cur.fetchall())
    for row in rows:
        row["key"] = display_license_key(row["key"], row.get("key_ciphertext"))
        row.pop("key_ciphertext", None)

    if rows:
        ids = [r["id"] for r in rows]
        qmarks = ",".join(["?"] * len(ids))
        async with db.execute(
            f"""SELECT lp.license_id, p.id as product_id, p.level, p.name,
                       lp.expires_at, lp.is_paused, lp.paused_at, lp.pause_reason,
                       lp.total_compensation_seconds
                FROM license_products lp
                JOIN products p ON p.id = lp.product_id
                WHERE lp.license_id IN ({qmarks})""",
            ids,
        ) as cur:
            attach_rows = rows_to_list(await cur.fetchall())
        by_lic: dict = {}
        for ar in attach_rows:
            by_lic.setdefault(ar["license_id"], []).append({
                "product_id": ar["product_id"],
                "level": ar["level"],
                "name":  ar["name"],
                "expires_at": ar["expires_at"],
                "is_paused": ar["is_paused"],
                "paused_at": ar["paused_at"],
                "pause_reason": ar["pause_reason"],
                "total_compensation_seconds": ar["total_compensation_seconds"],
            })
        for r in rows:
            r["products"] = by_lic.get(r["id"], [])
    return rows


def csv_safe(value) -> str:
    """Prevent spreadsheet formula execution when an exported CSV is opened."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


@router.get("/licenses/export.csv")
async def export_licenses_csv(app_id: Optional[str] = None,
                              status: Optional[str] = None,
                              search: Optional[str] = None,
                              product_id: Optional[str] = None,
                              expired: Optional[bool] = None,
                              user=Depends(require_admin),
                              db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT l.*, a.name AS app_name,
             (SELECT COUNT(*) FROM hwids WHERE license_id=l.id) AS hwid_count,
             (SELECT GROUP_CONCAT(p.level || ' (' || p.name || ')', '; ')
                FROM license_products lp JOIN products p ON p.id=lp.product_id
               WHERE lp.license_id=l.id) AS products,
             (SELECT GROUP_CONCAT(lp.product_id, ';') FROM license_products lp
               WHERE lp.license_id=l.id) AS product_ids
             FROM licenses l JOIN applications a ON a.id=l.app_id WHERE 1=1"""
    args = []
    if owner_id:
        sql += " AND a.owner_user_id=?"; args.append(owner_id)
    if app_id:
        sql += " AND l.app_id=?"; args.append(app_id)
    if status:
        sql += " AND l.status=?"; args.append(status)
    if search:
        sql += " AND (l.key LIKE ? OR l.notes LIKE ? OR l.metadata LIKE ?)"
        args.extend([f"%{search}%"] * 3)
    if product_id:
        sql += " AND l.id IN (SELECT license_id FROM license_products WHERE product_id=?)"
        args.append(product_id)
    if expired is True:
        sql += " AND l.expires_at < ?"; args.append(utcnow())
    elif expired is False:
        sql += " AND (l.expires_at IS NULL OR l.expires_at >= ?)"; args.append(utcnow())
    sql += " ORDER BY l.created_at DESC LIMIT 50000"
    async with db.execute(sql, args) as cur:
        rows = rows_to_list(await cur.fetchall())

    fields = ["license_key", "application", "app_id", "products", "product_ids", "status", "expires",
              "hwids_used", "max_hwids", "notes", "metadata", "created_at"]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "license_key": csv_safe(display_license_key(row["key"], row.get("key_ciphertext"))),
            "application": csv_safe(row["app_name"]),
            "app_id": csv_safe(row["app_id"]),
            "products": csv_safe(row.get("products") or "Any"),
            "product_ids": csv_safe(row.get("product_ids") or ""),
            "status": csv_safe(row["status"]),
            "expires": csv_safe(row["expires_at"] or "Lifetime"),
            "hwids_used": row["hwid_count"],
            "max_hwids": row["max_hwids"],
            "notes": csv_safe(row.get("notes")),
            "metadata": csv_safe(row.get("metadata")),
            "created_at": csv_safe(row["created_at"]),
        })
    filename = f"enauth-licenses-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        io.BytesIO(buffer.getvalue().encode("utf-8-sig")), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store, private"},
    )


async def parse_license_import(file: UploadFile, owner_id: Optional[str], db) -> tuple[list[dict], list[dict]]:
    raw = await file.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "CSV exceeds 5 MB")
    try:
        text = raw.decode("utf-8-sig")
        source = csv.DictReader(io.StringIO(text))
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must use UTF-8 encoding")
    required = {"license_key", "app_id"}
    if not source.fieldnames or not required.issubset(set(source.fieldnames)):
        raise HTTPException(400, "CSV requires license_key and app_id columns")
    input_rows = list(source)
    if not input_rows or len(input_rows) > 5000:
        raise HTTPException(400, "CSV must contain between 1 and 5000 rows")

    app_sql = "SELECT id FROM applications"
    app_args = []
    if owner_id:
        app_sql += " WHERE owner_user_id=?"; app_args.append(owner_id)
    async with db.execute(app_sql, app_args) as cur:
        allowed_apps = {row["id"] for row in await cur.fetchall()}
    async with db.execute("SELECT id,app_id FROM products") as cur:
        product_apps = {row["id"]: row["app_id"] for row in await cur.fetchall()}
    async with db.execute("SELECT key_hash FROM licenses WHERE key_hash IS NOT NULL") as cur:
        existing_hashes = {row["key_hash"] for row in await cur.fetchall()}

    valid, errors, seen = [], [], set()
    for number, row in enumerate(input_rows, 2):
        key = (row.get("license_key") or "").strip()
        app_id = (row.get("app_id") or "").strip()
        key_hash = hash_license_key(key) if key else ""
        row_errors = []
        if len(key) < 8 or len(key) > 255:
            row_errors.append("license_key must be 8-255 characters")
        if app_id not in allowed_apps:
            row_errors.append("application is missing or outside your account")
        if key_hash in existing_hashes or key_hash in seen:
            row_errors.append("duplicate license key")
        status_value = (row.get("status") or "active").strip().lower()
        if status_value not in {"active", "banned"}:
            row_errors.append("status must be active or banned")
        try:
            max_hwids = int((row.get("max_hwids") or "1").strip())
            if not 1 <= max_hwids <= 100: raise ValueError
        except ValueError:
            row_errors.append("max_hwids must be between 1 and 100"); max_hwids = 1
        expiry_raw = (row.get("expires") or row.get("expires_at") or "").strip()
        expires_at = None
        if expiry_raw and expiry_raw.lower() not in {"lifetime", "never"}:
            try:
                expires_at = datetime.fromisoformat(expiry_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                row_errors.append("expires must be Lifetime or an ISO date")
        product_ids = [x.strip() for x in (row.get("product_ids") or "").split(";") if x.strip()]
        if not product_ids:
            row_errors.append("at least one product_id is required")
        elif any(product_apps.get(pid) != app_id for pid in product_ids):
            row_errors.append("one or more product_ids do not belong to the application")
        if row_errors:
            errors.append({"row": number, "errors": row_errors})
            continue
        seen.add(key_hash)
        valid.append({"key": key, "key_hash": key_hash, "app_id": app_id, "status": status_value,
                      "max_hwids": max_hwids, "expires_at": expires_at,
                      "notes": (row.get("notes") or "").strip() or None,
                      "metadata": (row.get("metadata") or "").strip() or None,
                      "product_ids": list(dict.fromkeys(product_ids))})
    return valid, errors


@router.post("/licenses/import/preview")
async def preview_license_import(file: UploadFile = File(...), user=Depends(require_admin),
                                 db: aiosqlite.Connection = Depends(get_db)):
    valid, errors = await parse_license_import(file, auth_owner_id(user), db)
    return {"valid_count": len(valid), "error_count": len(errors), "errors": errors[:100]}


@router.post("/licenses/import")
async def import_licenses_csv(confirm: bool = Form(False), file: UploadFile = File(...),
                              user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if not confirm:
        raise HTTPException(400, "Import confirmation is required")
    valid, errors = await parse_license_import(file, auth_owner_id(user), db)
    if errors:
        raise HTTPException(400, {"message": "Fix CSV errors before importing", "errors": errors[:100]})
    for row in valid:
        license_id = generate_uid()
        await db.execute(
            """INSERT INTO licenses
               (id,key,key_hash,key_ciphertext,app_id,status,max_hwids,expires_at,notes,metadata)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (license_id, mask_license_key(row["key"]), row["key_hash"], encrypt_license_key(row["key"]),
             row["app_id"], row["status"], row["max_hwids"], row["expires_at"], row["notes"], row["metadata"]),
        )
        for product_id in row["product_ids"]:
            await db.execute(
                "INSERT INTO license_products(id,license_id,product_id,expires_at) VALUES(?,?,?,?)",
                (generate_uid(), license_id, product_id, row["expires_at"]),
            )
    await log_action(db, "licenses_csv_imported", details=f"count={len(valid)}")
    await db.commit()
    return {"imported": len(valid)}


@router.post("/licenses")
async def create_license(body: CreateLicenseBody,
                          user=Depends(require_admin),
                          db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    app_sql = "SELECT id FROM applications WHERE id = ?"
    app_args = [body.app_id]
    if owner_id:
        app_sql += " AND owner_user_id = ?"
        app_args.append(owner_id)
    async with db.execute(app_sql, app_args) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "App not found")

    if not body.product_ids:
        raise HTTPException(400, "Level selection is required")

    qmarks = ",".join(["?"] * len(body.product_ids))
    product_sql = f"SELECT COUNT(*) FROM products WHERE app_id = ? AND id IN ({qmarks})"
    product_args = [body.app_id] + body.product_ids
    if owner_id:
        product_sql = f"""SELECT COUNT(*) FROM products p
                          JOIN applications a ON a.id = p.app_id
                          WHERE p.app_id = ? AND p.id IN ({qmarks}) AND a.owner_user_id = ?"""
        product_args = [body.app_id] + body.product_ids + [owner_id]
    async with db.execute(product_sql, product_args) as cur:
        found = (await cur.fetchone())[0]
    if found != len(set(body.product_ids)):
        raise HTTPException(404, "One or more selected levels not found for this app")

    unique_pids = list(set(body.product_ids))
    pid_qmarks  = ",".join(["?"] * len(unique_pids))
    async with db.execute(
        f"SELECT id, level, name FROM products WHERE id IN ({pid_qmarks})",
        unique_pids,
    ) as cur:
        product_rows = rows_to_list(await cur.fetchall())

    expires = None
    if body.expires_hours is not None:
        expires = (datetime.now(timezone.utc) + timedelta(hours=body.expires_hours)).strftime("%Y-%m-%d %H:%M:%S")
    elif body.expires_days is not None:
        expires = (datetime.now(timezone.utc) + timedelta(days=body.expires_days)).strftime("%Y-%m-%d %H:%M:%S")

    created = []
    for _ in range(min(body.count, 100)):
        key = generate_license_key()
        if body.prefix:
            key = f"{body.prefix.upper()}-{key}"
        lid = generate_uid()
        notes = body.notes
        await db.execute(
            """INSERT INTO licenses (id, key, key_hash, key_ciphertext, app_id, max_hwids, expires_at, notes, metadata)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (lid, mask_license_key(key), hash_license_key(key), encrypt_license_key(key),
             body.app_id, body.max_hwids, expires, notes, body.metadata),
        )
        for pid in unique_pids:
            await db.execute(
                "INSERT OR IGNORE INTO license_products (id, license_id, product_id, expires_at) VALUES (?, ?, ?, ?)",
                (generate_uid(), lid, pid, expires),
            )
        created.append({"id": lid, "key": key, "products": product_rows})

    await db.commit()
    return {"created": created, "products": product_rows}


@router.get("/licenses/{license_id}")
async def get_license(license_id: str, user=Depends(require_admin),
                      db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT l.* FROM licenses l JOIN applications a ON a.id = l.app_id WHERE l.id = ?"
    args = [license_id]
    if owner_id:
        sql += " AND a.owner_user_id = ?"
        args.append(owner_id)
    async with db.execute(sql, args) as cur:
        lic = await cur.fetchone()
    if not lic:
        raise HTTPException(404, "License not found")
    lic = dict(lic)
    lic["key"] = display_license_key(lic["key"], lic.get("key_ciphertext"))
    lic.pop("key_ciphertext", None)
    async with db.execute("SELECT * FROM hwids WHERE license_id = ?", (license_id,)) as cur:
        lic["hwids"] = rows_to_list(await cur.fetchall())
    async with db.execute(
        """SELECT lp.product_id, p.name, p.level, lp.expires_at, lp.is_paused,
                  lp.paused_at, lp.pause_reason, lp.total_compensation_seconds
           FROM license_products lp JOIN products p ON p.id=lp.product_id
           WHERE lp.license_id=? ORDER BY p.name""", (license_id,)
    ) as cur:
        lic["products"] = rows_to_list(await cur.fetchall())
    return lic


class EntitlementAddBody(BaseModel):
    product_id: str
    expires_at: Optional[str] = None


class EntitlementExtendBody(BaseModel):
    hours: float = Field(gt=0, le=876000)


async def _owned_license(license_id: str, owner_id: Optional[str], db):
    sql = "SELECT l.* FROM licenses l JOIN applications a ON a.id=l.app_id WHERE l.id=?"
    args = [license_id]
    if owner_id:
        sql += " AND a.owner_user_id=?"
        args.append(owner_id)
    async with db.execute(sql, args) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "License not found")
    return row


@router.post("/licenses/{license_id}/products")
async def add_license_product(license_id: str, body: EntitlementAddBody,
                              user=Depends(require_admin), db=Depends(get_db)):
    lic = await _owned_license(license_id, auth_owner_id(user), db)
    async with db.execute("SELECT 1 FROM products WHERE id=? AND app_id=?", (body.product_id, lic["app_id"])) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Product not found for this application")
    try:
        await db.execute(
            "INSERT INTO license_products(id,license_id,product_id,expires_at) VALUES(?,?,?,?)",
            (generate_uid(), license_id, body.product_id, body.expires_at),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "License already owns this product")
    await log_action(db, "entitlement_added", license_key=lic["key"], app_id=lic["app_id"], details=body.product_id)
    await db.commit()
    return {"ok": True}


@router.delete("/licenses/{license_id}/products/{product_id}")
async def remove_license_product(license_id: str, product_id: str,
                                 user=Depends(require_admin), db=Depends(get_db)):
    lic = await _owned_license(license_id, auth_owner_id(user), db)
    cursor = await db.execute("DELETE FROM license_products WHERE license_id=? AND product_id=?", (license_id, product_id))
    await db.execute("DELETE FROM sessions WHERE license_id=? AND product_id=?", (license_id, product_id))
    if cursor.rowcount == 0:
        raise HTTPException(404, "Entitlement not found")
    await log_action(db, "entitlement_removed", license_key=lic["key"], app_id=lic["app_id"], details=product_id)
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/products/{product_id}/pause")
async def pause_license_product(license_id: str, product_id: str, body: PauseBody,
                                user=Depends(require_admin), db=Depends(get_db)):
    lic = await _owned_license(license_id, auth_owner_id(user), db)
    cursor = await db.execute(
        """UPDATE license_products SET is_paused=1, paused_at=?, pause_reason=?
           WHERE license_id=? AND product_id=? AND is_paused=0""",
        (utcnow(), (body.reason or "License entitlement paused").strip(), license_id, product_id),
    )
    if cursor.rowcount == 0:
        raise HTTPException(409, "Entitlement not found or already paused")
    await db.execute("DELETE FROM sessions WHERE license_id=? AND product_id=?", (license_id, product_id))
    await log_action(db, "entitlement_paused", license_key=lic["key"], app_id=lic["app_id"], details=product_id)
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/products/{product_id}/resume")
async def resume_license_product(license_id: str, product_id: str, body: ResumeBody,
                                 user=Depends(require_admin), db=Depends(get_db)):
    lic = await _owned_license(license_id, auth_owner_id(user), db)
    async with db.execute(
        "SELECT * FROM license_products WHERE license_id=? AND product_id=?", (license_id, product_id)
    ) as cur:
        ent = await cur.fetchone()
    if not ent or not ent["is_paused"] or not ent["paused_at"]:
        raise HTTPException(409, "Entitlement is not paused")
    downtime = _paused_seconds(ent["paused_at"])
    extra = int(body.compensation_hours * 3600)
    total = downtime + extra
    await db.execute(
        """UPDATE license_products SET is_paused=0,paused_at=NULL,pause_reason=NULL,
           expires_at=CASE WHEN expires_at IS NULL THEN NULL ELSE datetime(expires_at, ?) END,
           total_compensation_seconds=total_compensation_seconds+?
           WHERE license_id=? AND product_id=?""",
        (f"+{total} seconds", extra, license_id, product_id),
    )
    await log_action(db, "entitlement_resumed", license_key=lic["key"], app_id=lic["app_id"],
                     details=f"{product_id}; restored={downtime}s; compensation={extra}s")
    await db.commit()
    return {"ok": True, "downtime_seconds": downtime, "compensation_seconds": extra,
            "extended_by_seconds": total}


@router.post("/licenses/{license_id}/products/{product_id}/extend")
async def extend_license_product(license_id: str, product_id: str, body: EntitlementExtendBody,
                                 user=Depends(require_admin), db=Depends(get_db)):
    lic = await _owned_license(license_id, auth_owner_id(user), db)
    seconds = int(body.hours * 3600)
    cursor = await db.execute(
        """UPDATE license_products SET expires_at=datetime(CASE
             WHEN expires_at < CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP ELSE expires_at END, ?)
           WHERE license_id=? AND product_id=? AND expires_at IS NOT NULL""",
        (f"+{seconds} seconds", license_id, product_id),
    )
    if cursor.rowcount == 0:
        raise HTTPException(409, "Entitlement not found or is lifetime")
    await log_action(db, "entitlement_extended", license_key=lic["key"], app_id=lic["app_id"],
                     details=f"{product_id}; extended={seconds}s")
    await db.commit()
    return {"ok": True}


@router.put("/licenses/{license_id}")
async def update_license(license_id: str, body: UpdateLicenseBody,
                         user=Depends(require_admin),
                         db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE l.id = ? AND a.owner_user_id = ?""",
            (license_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "License not found")
    updates, args = [], []
    if body.status is not None:
        updates.append("status = ?"); args.append(body.status)
    if body.max_hwids is not None:
        updates.append("max_hwids = ?"); args.append(body.max_hwids)
    if body.expires_at is not None:
        updates.append("expires_at = ?"); args.append(body.expires_at or None)
    if body.notes is not None:
        updates.append("notes = ?"); args.append(body.notes)
    if not updates:
        raise HTTPException(400, "Nothing to update")
    args.append(license_id)
    await db.execute(f"UPDATE licenses SET {', '.join(updates)} WHERE id = ?", args)
    if body.expires_at is not None:
        await db.execute("UPDATE license_products SET expires_at=? WHERE license_id=?",
                         (body.expires_at or None, license_id))
    await db.commit()
    return {"ok": True}


@router.delete("/licenses/{license_id}")
async def delete_license(license_id: str, user=Depends(require_admin),
                         db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM licenses
               WHERE id = ? AND app_id IN (
                 SELECT id FROM applications WHERE owner_user_id = ?
               )""",
            (license_id, owner_id),
        )
    else:
        await db.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
    await db.commit()
    return {"ok": True}


@router.post("/licenses/bulk-delete")
async def bulk_delete_licenses(body: BulkIdsBody, user=Depends(require_admin),
                               db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No license IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"""DELETE FROM licenses
                WHERE id IN ({qmarks})
                AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM licenses WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


@router.post("/licenses/bulk-ban")
async def bulk_ban_licenses(body: BulkIdsBody, user=Depends(require_admin),
                            db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No license IDs provided")
    for license_id in body.ids:
        await ban_license(license_id, user=user, db=db)
    return {"ok": True}


@router.post("/licenses/bulk-unban")
async def bulk_unban_licenses(body: BulkIdsBody, user=Depends(require_admin),
                              db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No license IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"""UPDATE licenses SET status='active'
                WHERE id IN ({qmarks})
                AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"UPDATE licenses SET status='active' WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/ban")
async def ban_license(license_id: str, user=Depends(require_admin),
                      db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE l.id = ? AND a.owner_user_id = ?""",
            (license_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "License not found")
    # Auto-ban associated HWIDs for this app
    async with db.execute("SELECT hwid_hash, app_id FROM hwids JOIN licenses l ON l.id = hwids.license_id WHERE l.id=?", (license_id,)) as cur:
        hwids = await cur.fetchall()
    
    for row in hwids:
        # INSERT OR REPLACE in case it was already banned
        await db.execute("INSERT OR REPLACE INTO banned_hwids (hwid, app_id, reason) VALUES (?, ?, ?)", 
                         (row["hwid_hash"], row["app_id"], f"Auto-banned from license {license_id}"))

    await db.execute("UPDATE licenses SET status='banned' WHERE id=?", (license_id,))
    await db.execute("DELETE FROM sessions WHERE license_id=?", (license_id,))
    await db.commit()
    async with db.execute("SELECT key FROM licenses WHERE id=?", (license_id,)) as cur:
        lic = await cur.fetchone()
    await log_action(db, "ban", license_key=lic["key"] if lic else None,
                     details=f"Banned and HWIDs locked by {user['username']}")
    return {"ok": True}


@router.post("/licenses/{license_id}/unban")
async def unban_license(license_id: str, user=Depends(require_admin),
                        db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """UPDATE licenses SET status='active'
               WHERE id=? AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (license_id, owner_id),
        )
    else:
        await db.execute("UPDATE licenses SET status='active' WHERE id=?", (license_id,))
    await db.commit()
    return {"ok": True}


@router.post("/licenses/{license_id}/reset-hwid")
async def reset_hwid(license_id: str, user=Depends(require_admin),
                     db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute(
            """SELECT 1 FROM licenses l
               JOIN applications a ON a.id = l.app_id
               WHERE l.id = ? AND a.owner_user_id = ?""",
            (license_id, owner_id),
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "License not found")
    await db.execute("DELETE FROM hwids WHERE license_id=?", (license_id,))
    await db.execute("UPDATE licenses SET hwid_reset_at=? WHERE id=?", (utcnow(), license_id))
    await db.commit()
    return {"ok": True}


class ExtendLicenseBody(BaseModel):
    days: Optional[float] = None
    hours: Optional[float] = None
    license_id: Optional[str] = None  # None = extend all active with expiration

@router.post("/licenses/extend")
async def extend_license(body: ExtendLicenseBody, user=Depends(require_admin),
                         db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    # Security: clamp values to prevent absurdly large/negative modifiers from
    # silently producing NULL dates or epoch-overflowed dates in SQLite.
    MAX_DAYS = 36500   # 100 years
    MAX_HOURS = MAX_DAYS * 24
    if body.hours is not None:
        hours_val = float(body.hours)
        if not (0 < hours_val <= MAX_HOURS):
            raise HTTPException(400, f"hours must be between 0 and {MAX_HOURS}")
        minutes = int(hours_val * 60)
        modifier = f"+{minutes} minutes"
    elif body.days is not None:
        days_val = float(body.days)
        if not (0 < days_val <= MAX_DAYS):
            raise HTTPException(400, f"days must be between 0 and {MAX_DAYS}")
        if days_val % 1 != 0:
            minutes = int(days_val * 1440)
            modifier = f"+{minutes} minutes"
        else:
            modifier = f"+{int(days_val)} days"
    else:
        raise HTTPException(400, "Must provide either 'days' or 'hours'")

    # Final safety check: modifier must only contain digits, spaces, and known keywords
    import re as _re
    if not _re.fullmatch(r"[+\-]\d+ (days|hours|minutes|seconds)", modifier):
        raise HTTPException(400, "Invalid time modifier")

    if body.license_id:
        if owner_id:
            await db.execute(
                """UPDATE licenses SET expires_at = datetime(expires_at, ?)
                   WHERE id = ? AND expires_at IS NOT NULL
                   AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
                (modifier, body.license_id, owner_id),
            )
        else:
            await db.execute("UPDATE licenses SET expires_at = datetime(expires_at, ?) WHERE id = ? AND expires_at IS NOT NULL", (modifier, body.license_id))
        if owner_id:
            await db.execute(
                """UPDATE license_products SET expires_at=datetime(expires_at, ?)
                   WHERE license_id=? AND expires_at IS NOT NULL AND license_id IN
                   (SELECT l.id FROM licenses l JOIN applications a ON a.id=l.app_id WHERE a.owner_user_id=?)""",
                (modifier, body.license_id, owner_id),
            )
        else:
            await db.execute(
                "UPDATE license_products SET expires_at=datetime(expires_at, ?) WHERE license_id=? AND expires_at IS NOT NULL",
                (modifier, body.license_id),
            )
    else:
        if owner_id:
            await db.execute(
                """UPDATE licenses SET expires_at = datetime(expires_at, ?)
                   WHERE expires_at IS NOT NULL AND status='active'
                   AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
                (modifier, owner_id),
            )
        else:
            await db.execute("UPDATE licenses SET expires_at = datetime(expires_at, ?) WHERE expires_at IS NOT NULL AND status='active'", (modifier,))
        if owner_id:
            await db.execute(
                """UPDATE license_products SET expires_at=datetime(expires_at, ?)
                   WHERE expires_at IS NOT NULL AND license_id IN
                   (SELECT l.id FROM licenses l JOIN applications a ON a.id=l.app_id
                    WHERE l.status='active' AND a.owner_user_id=?)""", (modifier, owner_id))
        else:
            await db.execute(
                """UPDATE license_products SET expires_at=datetime(expires_at, ?)
                   WHERE expires_at IS NOT NULL AND license_id IN
                   (SELECT id FROM licenses WHERE status='active')""", (modifier,))
    await db.commit()
    return {"ok": True}


# ─── Banned HWIDs ────────────────────────────────────────────────────────────

@router.get("/banned-hwids")
async def list_banned_hwids(app_id: Optional[str] = None, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT b.hwid, b.reason, b.banned_at, a.name as app_name, b.app_id FROM banned_hwids b JOIN applications a ON a.id = b.app_id"
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
        if app_id:
            sql += " AND b.app_id = ?"
            args.append(app_id)
    elif app_id:
        sql += " WHERE b.app_id = ?"
        args.append(app_id)
    sql += " ORDER BY b.banned_at DESC"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())

class BanHwidBody(BaseModel):
    hwid: str
    app_id: str
    reason: Optional[str] = None

@router.post("/banned-hwids")
async def ban_hwid(body: BanHwidBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (body.app_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "App not found")
    await db.execute("INSERT OR REPLACE INTO banned_hwids (hwid, app_id, reason) VALUES (?, ?, ?)",
                     (body.hwid, body.app_id, body.reason or "Manually banned by admin"))
    await log_action(db, "ban_hwid", hwid=body.hwid, details=f"Banned for app {body.app_id} by {user['username']}")
    await db.commit()
    return {"ok": True}

@router.delete("/banned-hwids/{app_id}/{hwid}")
async def unban_hwid(app_id: str, hwid: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM banned_hwids 
               WHERE hwid=? AND app_id=? 
               AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (hwid, app_id, owner_id)
        )
    else:
        await db.execute("DELETE FROM banned_hwids WHERE hwid=? AND app_id=?", (hwid, app_id))
    await log_action(db, "unban_hwid", hwid=hwid, details=f"Unbanned for app {app_id} by {user['username']}")
    await db.commit()
    return {"ok": True}


# ─── Sessions ────────────────────────────────────────────────────────────────

@router.get("/sessions")
async def list_sessions(search: Optional[str] = None, app_id: Optional[str] = None,
                        limit: int = 100, offset: int = 0,
                        user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT s.*, l.key as license_key, a.name as app_name, p.name as product_name
           FROM sessions s
           JOIN licenses l ON l.id = s.license_id
           JOIN applications a ON a.id = s.app_id
           LEFT JOIN products p ON p.id = s.product_id
           WHERE s.expires_at > ? AND COALESCE(s.token_expires_at, s.expires_at) > CURRENT_TIMESTAMP"""
    args = [utcnow()]
    if owner_id:
        sql += " AND a.owner_user_id = ?"
        args.append(owner_id)
    if app_id:
        sql += " AND s.app_id = ?"
        args.append(app_id)
    if search:
        sql += " AND (l.key LIKE ? OR s.hwid LIKE ? OR s.ip LIKE ? OR a.name LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])
    sql += " ORDER BY s.started_at DESC LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 100), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.delete("/sessions/{session_id}")
async def kill_session(session_id: str, user=Depends(require_admin),
                       db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            """DELETE FROM sessions
               WHERE id = ? AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (session_id, owner_id),
        )
    else:
        await db.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    await db.commit()
    return {"ok": True}


@router.post("/sessions/bulk-kill")
async def bulk_kill_sessions(body: BulkIdsBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No session IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"DELETE FROM sessions WHERE id IN ({qmarks}) AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM sessions WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


@router.delete("/sessions")
async def kill_all_sessions(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute("DELETE FROM sessions WHERE app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)", (owner_id,))
    else:
        await db.execute("DELETE FROM sessions")
    await db.commit()
    return {"ok": True}


# ─── Logs ────────────────────────────────────────────────────────────────────

@router.get("/logs")
async def list_logs(action: Optional[str] = None,
                    license_key: Optional[str] = None,
                    app_id: Optional[str] = None,
                    search: Optional[str] = None,
                    date_from: Optional[str] = None,
                    date_to: Optional[str] = None,
                    limit: int = 200, offset: int = 0,
                    user=Depends(require_admin),
                    db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        sql = "SELECT lg.* FROM logs lg JOIN applications a ON a.id = lg.app_id WHERE a.owner_user_id = ?"
        args = [owner_id]
    else:
        sql = "SELECT * FROM logs WHERE 1=1"
        args = []
    if action:
        sql += " AND action = ?"; args.append(action)
    if license_key:
        sql += " AND license_key LIKE ?"; args.append(f"%{license_key}%")
    if app_id:
        sql += " AND app_id = ?"; args.append(app_id)
    if search:
        sql += " AND (license_key LIKE ? OR ip LIKE ? OR hwid LIKE ? OR details LIKE ? OR action LIKE ?)"
        args.extend([f"%{search}%"] * 5)
    if date_from:
        sql += " AND timestamp >= ?"; args.append(date_from)
    if date_to:
        sql += " AND timestamp <= ?"; args.append(date_to)
    sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    args += [clamp_limit(limit, 200), clamp_offset(offset)]
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.delete("/logs")
async def clear_all_logs(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute("DELETE FROM logs WHERE app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)", (owner_id,))
    else:
        await db.execute("DELETE FROM logs")
    await db.commit()
    return {"ok": True}


@router.get("/logs/export")
async def export_logs(action: Optional[str] = None,
                      license_key: Optional[str] = None,
                      app_id: Optional[str] = None,
                      search: Optional[str] = None,
                      date_from: Optional[str] = None,
                      date_to: Optional[str] = None,
                      user=Depends(require_admin),
                      db: aiosqlite.Connection = Depends(get_db)):
    rows = await list_logs(
        action=action,
        license_key=license_key,
        app_id=app_id,
        search=search,
        date_from=date_from,
        date_to=date_to,
        limit=5000,
        offset=0,
        user=user,
        db=db,
    )
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["id", "license_key", "app_id", "action", "ip", "hwid", "details", "timestamp"])
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
    return StreamingResponse(io.BytesIO(buffer.getvalue().encode("utf-8")), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=logs.csv"})


@router.get("/search")
async def global_search(query: str,
                        category: Optional[str] = None,
                        limit: int = 20,
                        offset: int = 0,
                        user=Depends(require_admin),
                        db: aiosqlite.Connection = Depends(get_db)):
    q = f"%{query.strip()}%"
    if not query.strip():
        return {"items": [], "total": 0, "limit": clamp_limit(limit, 20), "offset": clamp_offset(offset)}

    owner_id = auth_owner_id(user)
    max_bucket = clamp_limit(limit, 20) * 3
    items: list[dict] = []

    async def fetch(sql: str, params: tuple):
        async with db.execute(sql, params) as cur:
            return rows_to_list(await cur.fetchall())

    if category in (None, "apps"):
        sql = """SELECT a.id as entity_id, a.name as title, a.version as subtitle, a.created_at,
                        a.name as app_name, 'app' as entity_type,
                        CAST((SELECT COUNT(*) FROM licenses WHERE app_id = a.id) AS TEXT) as details,
                        NULL as status
                 FROM applications a
                 WHERE (a.name LIKE ? OR a.id LIKE ?)"""
        params = [q, q]
        if owner_id:
            sql += " AND a.owner_user_id = ?"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY a.created_at DESC LIMIT ?", tuple(params + [max_bucket])))

    if category in (None, "licenses"):
        sql = """SELECT l.id as entity_id, l.key as title, a.name as subtitle, l.created_at,
                        a.name as app_name, 'license' as entity_type,
                        COALESCE(l.notes, l.metadata, '') as details,
                        l.status as status
                 FROM licenses l
                 JOIN applications a ON a.id = l.app_id
                 WHERE (l.key LIKE ? OR l.notes LIKE ? OR l.metadata LIKE ? OR a.name LIKE ?)"""
        params = [q, q, q, q]
        if owner_id:
            sql += " AND a.owner_user_id = ?"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY l.created_at DESC LIMIT ?", tuple(params + [max_bucket])))

    if category in (None, "users"):
        sql = """SELECT u.id as entity_id, u.username as title, u.role as subtitle, u.created_at,
                        NULL as app_name, 'user' as entity_type,
                        u.role as details,
                        u.role as status
                 FROM admin_users u
                 WHERE (u.username LIKE ? OR u.role LIKE ?)"""
        items.extend(await fetch(sql + " ORDER BY u.created_at DESC LIMIT ?", (q, q, max_bucket)))

    if category in (None, "resellers"):
        sql = """SELECT r.id as entity_id, r.username as title, CAST(r.balance AS TEXT) as subtitle, r.created_at,
                        NULL as app_name, 'reseller' as entity_type,
                        CASE WHEN r.is_active = 1 THEN 'active' ELSE 'disabled' END as details,
                        CASE WHEN r.is_active = 1 THEN 'active' ELSE 'disabled' END as status
                 FROM resellers r
                 WHERE (r.username LIKE ? OR r.id LIKE ?)"""
        params = [q, q]
        if owner_id:
            sql += " AND r.owner_user_id = ?"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY r.created_at DESC LIMIT ?", tuple(params + [max_bucket])))

    if category in (None, "sessions"):
        sql = """SELECT s.id as entity_id, l.key as title, a.name as subtitle, s.started_at as created_at,
                        a.name as app_name, 'session' as entity_type,
                        s.ip || ' | ' || s.hwid as details,
                        'active' as status
                 FROM sessions s
                 JOIN licenses l ON l.id = s.license_id
                 JOIN applications a ON a.id = s.app_id
                 WHERE (l.key LIKE ? OR s.hwid LIKE ? OR s.ip LIKE ? OR a.name LIKE ?)"""
        params = [q, q, q, q]
        if owner_id:
            sql += " AND a.owner_user_id = ?"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY s.started_at DESC LIMIT ?", tuple(params + [max_bucket])))

    if category in (None, "logs"):
        sql = """SELECT CAST(lg.id AS TEXT) as entity_id, lg.action as title, COALESCE(lg.license_key, lg.app_id, '') as subtitle,
                        lg.timestamp as created_at, a.name as app_name, 'log' as entity_type,
                        COALESCE(lg.details, '') as details, lg.action as status
                 FROM logs lg
                 LEFT JOIN applications a ON a.id = lg.app_id
                 WHERE (lg.action LIKE ? OR lg.license_key LIKE ? OR lg.ip LIKE ? OR lg.hwid LIKE ? OR lg.details LIKE ?)"""
        params = [q, q, q, q, q]
        if owner_id:
            sql += " AND lg.app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY lg.timestamp DESC LIMIT ?", tuple(params + [max_bucket])))

    if category in (None, "files"):
        sql = """SELECT f.id as entity_id, f.name as title, a.name as subtitle, f.created_at,
                        a.name as app_name, 'file' as entity_type,
                        CASE WHEN f.is_secret = 1 THEN 'secret' ELSE 'public' END as details,
                        CASE WHEN f.is_secret = 1 THEN 'secret' ELSE 'public' END as status
                 FROM app_files f
                 JOIN applications a ON a.id = f.app_id
                 WHERE (f.name LIKE ? OR a.name LIKE ?)"""
        params = [q, q]
        if owner_id:
            sql += " AND a.owner_user_id = ?"
            params.append(owner_id)
        items.extend(await fetch(sql + " ORDER BY f.created_at DESC LIMIT ?", tuple(params + [max_bucket])))

    items.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    total = len(items)
    start = clamp_offset(offset)
    end = start + clamp_limit(limit, 20)
    return {
        "items": items[start:end],
        "total": total,
        "limit": clamp_limit(limit, 20),
        "offset": start,
    }


@router.get("/activity/{entity_type}/{entity_id}")
async def activity_timeline(entity_type: str, entity_id: str,
                            limit: int = 25, offset: int = 0,
                            user=Depends(require_admin),
                            db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    limit = clamp_limit(limit, 25)
    offset = clamp_offset(offset)

    if entity_type == "app":
        sql = """SELECT lg.* FROM logs lg
                 JOIN applications a ON a.id = lg.app_id
                 WHERE lg.app_id = ?"""
        args = [entity_id]
        if owner_id:
            sql += " AND a.owner_user_id = ?"
            args.append(owner_id)
        sql += " ORDER BY lg.timestamp DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        async with db.execute(sql, args) as cur:
            return {"items": rows_to_list(await cur.fetchall()), "entity_type": entity_type, "entity_id": entity_id}

    if entity_type == "license":
        async with db.execute("SELECT key, app_id FROM licenses WHERE id = ?", (entity_id,)) as cur:
            lic = await cur.fetchone()
        if not lic:
            raise HTTPException(404, "License not found")
        if owner_id:
            async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (lic["app_id"], owner_id)) as cur:
                if not await cur.fetchone():
                    raise HTTPException(404, "License not found")
        sql = """SELECT * FROM logs WHERE license_key = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?"""
        async with db.execute(sql, (lic["key"], limit, offset)) as cur:
            return {"items": rows_to_list(await cur.fetchall()), "entity_type": entity_type, "entity_id": entity_id}

    if entity_type == "reseller":
        sql = """SELECT l.* FROM reseller_balance_ledger l
                 JOIN resellers r ON r.id = l.reseller_id
                 WHERE l.reseller_id = ?"""
        args = [entity_id]
        if owner_id:
            sql += " AND r.owner_user_id = ?"
            args.append(owner_id)
        sql += " ORDER BY l.created_at DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        async with db.execute(sql, args) as cur:
            return {"items": rows_to_list(await cur.fetchall()), "entity_type": entity_type, "entity_id": entity_id}

    if entity_type == "user":
        sql = """SELECT lg.* FROM logs lg
                 WHERE lg.details LIKE ? OR lg.details LIKE ?"""
        async with db.execute(sql + " ORDER BY timestamp DESC LIMIT ? OFFSET ?", (f"%{entity_id}%", f"%{entity_id}%", limit, offset)) as cur:
            return {"items": rows_to_list(await cur.fetchall()), "entity_type": entity_type, "entity_id": entity_id}

    raise HTTPException(400, "Unsupported entity type")


# ─── Applications ─────────────────────────────────────────────────────────────

class CreateAppBody(BaseModel):
    name:    str
    version: str = "1.0.0"

class UpdateAppBody(BaseModel):
    name:    Optional[str] = None
    version: Optional[str] = None
    download_violation_action: Optional[str] = None
    download_violation_limit: Optional[int] = None


async def _owned_app(app_id: str, owner_id: Optional[str], db):
    sql = "SELECT * FROM applications WHERE id = ?"
    args = [app_id]
    if owner_id:
        sql += " AND owner_user_id = ?"
        args.append(owner_id)
    async with db.execute(sql, args) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "App not found")
    return row

@router.get("/apps")
async def list_apps(search: Optional[str] = None,
                    limit: int = 100, offset: int = 0,
                    user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT a.*,
           (SELECT COUNT(*) FROM licenses WHERE app_id=a.id) as license_count
           FROM applications a"""
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
        if search:
            sql += " AND (a.name LIKE ? OR a.id LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%"])
    elif search:
        sql += " WHERE (a.name LIKE ? OR a.id LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 100), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/apps")
async def create_app(body: CreateAppBody, user=Depends(require_admin),
                     db: aiosqlite.Connection = Depends(get_db)):
    app_id = generate_uid()
    secret = generate_app_secret()
    owner_id = auth_owner_id(user)
    await db.execute(
        "INSERT INTO applications (id, name, secret_key, version, owner_user_id) VALUES (?,?,?,?,?)",
        (app_id, body.name, secret, body.version, owner_id),
    )
    await db.commit()
    return {"id": app_id, "name": body.name, "secret_key": secret, "version": body.version}


@router.put("/apps/{app_id}")
async def update_app(app_id: str, body: UpdateAppBody, user=Depends(require_admin),
                     db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    updates, args = [], []
    if body.name is not None:
        updates.append("name = ?"); args.append(body.name)
    if body.version is not None:
        updates.append("version = ?"); args.append(body.version)
    if body.download_violation_action is not None:
        if body.download_violation_action not in {"deny", "warn_ban", "ban"}:
            raise HTTPException(400, "Invalid download violation action")
        updates.append("download_violation_action = ?"); args.append(body.download_violation_action)
    if body.download_violation_limit is not None:
        if not 1 <= body.download_violation_limit <= 20:
            raise HTTPException(400, "Warning limit must be between 1 and 20")
        updates.append("download_violation_limit = ?"); args.append(body.download_violation_limit)
    if not updates:
        raise HTTPException(400, "Nothing to update")
    args.append(app_id)
    sql = f"UPDATE applications SET {', '.join(updates)} WHERE id = ?"
    if owner_id:
        sql += " AND owner_user_id = ?"
        args.append(owner_id)
    await db.execute(sql, args)
    await db.commit()
    return {"ok": True}


@router.delete("/apps/{app_id}")
async def delete_app(app_id: str, user=Depends(require_admin),
                     db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute("DELETE FROM applications WHERE id=? AND owner_user_id = ?", (app_id, owner_id))
    else:
        await db.execute("DELETE FROM applications WHERE id=?", (app_id,))
    await db.commit()
    return {"ok": True}


@router.post("/apps/bulk-delete")
async def bulk_delete_apps(body: BulkIdsBody, user=Depends(require_admin),
                           db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No app IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"DELETE FROM applications WHERE id IN ({qmarks}) AND owner_user_id = ?",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM applications WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


@router.post("/apps/{app_id}/regenerate-secret")
async def regen_secret(app_id: str, user=Depends(require_admin),
                       db: aiosqlite.Connection = Depends(get_db)):
    new_secret = generate_app_secret()
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute("UPDATE applications SET secret_key=? WHERE id=? AND owner_user_id = ?", (new_secret, app_id, owner_id))
    else:
        await db.execute("UPDATE applications SET secret_key=? WHERE id=?", (new_secret, app_id))
    await db.commit()
    return {"secret_key": new_secret}


@router.post("/apps/{app_id}/pause")
async def pause_app(app_id: str, body: PauseBody, user=Depends(require_admin),
                    db: aiosqlite.Connection = Depends(get_db)):
    app = await _owned_app(app_id, auth_owner_id(user), db)
    if app["is_paused"]:
        return {"ok": True, "already_paused": True, "paused_at": app["paused_at"]}
    now = utcnow()
    reason = (body.reason or "Application outage").strip()
    await db.execute(
        "UPDATE applications SET is_paused=1, paused_at=?, pause_reason=? WHERE id=?",
        (now, reason, app_id),
    )
    async with db.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)) as cur:
        affected = (await cur.fetchone())[0]
    await db.execute(
        """INSERT INTO outage_events(id,app_id,event_type,service_status,status_color,public_message,started_at,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?)""", (generate_uid(), app_id, "started", "offline", "#ef4444", reason, now, affected)
    )
    await db.execute("DELETE FROM sessions WHERE app_id=?", (app_id,))
    await log_action(db, "app_paused", app_id=app_id, details=reason)
    await db.commit()
    return {"ok": True, "paused_at": now}


@router.post("/apps/{app_id}/resume")
async def resume_app(app_id: str, body: ResumeBody, user=Depends(require_admin),
                     db: aiosqlite.Connection = Depends(get_db)):
    app = await _owned_app(app_id, auth_owner_id(user), db)
    if not app["is_paused"] or not app["paused_at"]:
        raise HTTPException(409, "Application is not paused")
    downtime = _paused_seconds(app["paused_at"])
    compensation = int(body.compensation_hours * 3600)
    extension = downtime + compensation
    async with db.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)) as cur:
        affected = (await cur.fetchone())[0]
    await db.execute(
        "UPDATE licenses SET expires_at=datetime(expires_at, ?) WHERE app_id=? AND expires_at IS NOT NULL",
        (f"+{extension} seconds", app_id),
    )
    await db.execute(
        """UPDATE license_products SET expires_at=datetime(expires_at, ?),
           total_compensation_seconds=total_compensation_seconds+?
           WHERE expires_at IS NOT NULL AND product_id IN (SELECT id FROM products WHERE app_id=?)""",
        (f"+{extension} seconds", compensation, app_id),
    )
    await db.execute(
        "UPDATE applications SET is_paused=0, paused_at=NULL, pause_reason=NULL WHERE id=?", (app_id,)
    )
    await db.execute(
        """INSERT INTO outage_events(id,app_id,event_type,service_status,public_message,started_at,ended_at,downtime_seconds,compensation_seconds,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (generate_uid(), app_id, "resolved", "operational", "Service restored", app["paused_at"],
         utcnow(), downtime, compensation, affected),
    )
    await log_action(db, "app_resumed", app_id=app_id,
                     details=f"Extended {extension}s ({compensation}s compensation)")
    await db.commit()
    return {"ok": True, "downtime_seconds": downtime, "compensation_seconds": compensation,
            "extended_by_seconds": extension}


@router.get("/apps/{app_id}/resume-preview")
async def preview_app_resume(app_id: str, compensation_hours: float = 0,
                             user=Depends(require_admin), db=Depends(get_db)):
    if compensation_hours < 0 or compensation_hours > 876000:
        raise HTTPException(400, "Invalid compensation")
    app = await _owned_app(app_id, auth_owner_id(user), db)
    if not app["is_paused"] or not app["paused_at"]:
        raise HTTPException(409, "Application is not paused")
    downtime = _paused_seconds(app["paused_at"])
    extra = int(compensation_hours * 3600)
    async with db.execute(
        """SELECT COUNT(DISTINCT l.id) AS total,
                  COUNT(DISTINCT CASE WHEN lp.expires_at IS NOT NULL THEN l.id END) AS expiring
           FROM licenses l LEFT JOIN license_products lp ON lp.license_id=l.id WHERE l.app_id=?""", (app_id,)
    ) as cur:
        counts = await cur.fetchone()
    return {"affected_licenses": counts["total"], "expiring_licenses": counts["expiring"],
            "lifetime_licenses": counts["total"] - counts["expiring"],
            "downtime_seconds": downtime, "compensation_seconds": extra,
            "extended_by_seconds": downtime + extra}


# ─── Admin Users ──────────────────────────────────────────────────────────────

class CreateUserBody(BaseModel):
    username: str
    password: str
    role:     str = "admin"

class UpdateUserBody(BaseModel):
    password: Optional[str] = None
    role:     Optional[str] = None
    theme:    Optional[str] = None


class PasswordResetRequestBody(BaseModel):
    username: str


class PasswordResetVerifyBody(BaseModel):
    token: str
    new_password: str


class CreateApiKeyBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: str = Field(default="read", min_length=1, max_length=1000)
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)
    app_id: Optional[str] = Field(default=None, max_length=128)
    allowed_ips: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values):
        normalized = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_network(value.strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f"Invalid IP address or CIDR: {value}") from exc
        return sorted(set(normalized))


class UpdateApiKeyBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    scopes: Optional[str] = Field(default=None, min_length=1, max_length=1000)
    is_active: Optional[bool] = None
    app_id: Optional[str] = Field(default=None, max_length=128)
    allowed_ips: Optional[list[str]] = Field(default=None, max_length=50)

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values):
        if values is None:
            return values
        return CreateApiKeyBody.validate_allowed_ips(values)


@router.get("/users")
async def list_users(search: Optional[str] = None,
                     limit: int = 100, offset: int = 0,
                     user=Depends(require_owner), db: aiosqlite.Connection = Depends(get_db)):
    sql = "SELECT id, username, role, two_factor_enabled, created_at FROM admin_users"
    args = []
    if search:
        sql += " WHERE username LIKE ? OR role LIKE ?"
        args.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY created_at LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 100), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/users")
async def create_user(body: CreateUserBody, user=Depends(require_owner),
                      db: aiosqlite.Connection = Depends(get_db)):
    validate_password_policy(body.password)
    async with db.execute("SELECT 1 FROM admin_users WHERE username = ?", (body.username,)) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "Username already taken")
    uid = generate_uid()
    try:
        await db.execute(
            "INSERT INTO admin_users (id, username, password_hash, role) VALUES (?,?,?,?)",
            (uid, body.username, hash_password(body.password), body.role),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Username already taken")
    return {"id": uid, "username": body.username, "role": body.role}


@router.put("/users/{user_id}")
async def update_user(user_id: str, body: UpdateUserBody,
                      caller=Depends(require_admin),
                      db: aiosqlite.Connection = Depends(get_db)):
    if caller.get("_source") != "admin_users":
        raise HTTPException(403, "Administrative account required")
    # Non-owners can only update themselves
    if caller["role"] != "owner" and caller["id"] != user_id:
        raise HTTPException(403, "Forbidden")
    updates, args = [], []
    if body.password:
        validate_password_policy(body.password)
        updates.append("password_hash = ?"); args.append(hash_password(body.password))
    if body.role and caller["role"] == "owner":
        updates.append("role = ?"); args.append(body.role)
    if body.theme is not None:
        if body.theme not in ("dark", "light"):
            raise HTTPException(400, "Theme must be 'dark' or 'light'")
        updates.append("theme = ?"); args.append(body.theme)
    if not updates:
        raise HTTPException(400, "Nothing to update")
    args.append(user_id)
    await db.execute(f"UPDATE admin_users SET {', '.join(updates)} WHERE id = ?", args)
    if body.password:
        await db.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM temp_2fa_sessions WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
    await db.commit()
    return {"ok": True}


@router.post("/auth/password-reset/request")
@limiter.limit("5/minute")
async def request_password_reset(request: Request = None, body: PasswordResetRequestBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    """Request a password reset token for a username."""
    async with db.execute("SELECT id FROM admin_users WHERE username = ?", (body.username,)) as cur:
        user = await cur.fetchone()
    if not user:
        # Don't reveal if user exists for security
        return {"ok": True, "message": "If the username exists, a reset token has been generated"}

    user_id = user["id"]
    token = generate_session_token()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = future_hours(1)  # Token valid for 1 hour

    await db.execute(
        "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES (?,?,?,?)",
        (generate_uid(), user_id, token_hash, expires_at)
    )
    await db.commit()

    # Do not log the reset token itself; it should only be delivered through the intended recovery channel.
    app_log.info(f"Password reset requested for {body.username}")

    return {"ok": True, "message": "If the username exists, a reset token has been generated", "token": token if os.getenv("DEBUG") == "true" else None}


@router.post("/auth/password-reset/verify")
@limiter.limit("5/minute")
async def verify_password_reset(request: Request = None, body: PasswordResetVerifyBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    """Verify a password reset token and set new password."""
    validate_password_policy(body.new_password)

    async with db.execute(
        "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token = ?",
        (hashlib.sha256(body.token.encode("utf-8")).hexdigest(),)
    ) as cur:
        reset_token = await cur.fetchone()

    if not reset_token:
        raise HTTPException(400, "Invalid reset token")

    if reset_token["used_at"]:
        raise HTTPException(400, "Reset token already used")

    expires_at = datetime.strptime(reset_token["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(400, "Reset token expired")

    # Only one concurrent request may redeem a reset token.
    consumed = await db.execute(
        "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
        (utcnow(), reset_token["id"], utcnow()),
    )
    if consumed.rowcount != 1:
        await db.rollback()
        raise HTTPException(400, "Invalid or expired reset token")

    # Update password
    await db.execute(
        "UPDATE admin_users SET password_hash = ? WHERE id = ?",
        (hash_password(body.new_password), reset_token["user_id"])
    )
    await db.execute("DELETE FROM admin_sessions WHERE user_id = ?", (reset_token["user_id"],))
    await db.execute("DELETE FROM temp_2fa_sessions WHERE user_id = ?", (reset_token["user_id"],))
    await db.execute(
        "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
        (utcnow(), reset_token["user_id"]),
    )
    await log_action(db, "password_reset", details=f"Password reset for user_id: {reset_token['user_id']}")
    await db.commit()

    return {"ok": True, "message": "Password reset successfully"}


# ─── API Keys ────────────────────────────────────────────────────────────────

@router.get("/api-keys", tags=["API Keys"])
async def list_api_keys(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    """
    List all API keys for the current authenticated user.
    
    Returns a list of API keys with their metadata including name, scopes, status, last used time, and expiration.
    
    **Authentication**: Requires Bearer token from admin session.
    """
    async with db.execute(
        """SELECT ak.id,ak.name,ak.scopes,ak.is_active,ak.last_used,ak.expires_at,ak.created_at,
                  ak.app_id,ak.allowed_ips,ak.usage_count,ak.last_ip,a.name AS app_name
           FROM api_keys ak LEFT JOIN applications a ON a.id=ak.app_id
           WHERE ak.user_id = ? ORDER BY ak.created_at DESC""",
        (user["id"],)
    ) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/api-keys", tags=["API Keys"])
async def create_api_key(body: CreateApiKeyBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    """
    Create a new API key for external integrations.
    
    The API key is returned only once in the response. Store it securely as it cannot be retrieved again.
    
    - **name**: A descriptive name for the API key (e.g., "Production App", "Testing Script")
    - **scopes**: Permission level - "read" (read-only), "write" (read & write), or "admin" (full access)
    - **expires_days**: Optional expiration in days. If not provided, the key never expires.
    
    **Example request**:
    ```json
    {
        "name": "Production App",
        "scopes": "write",
        "expires_days": 365
    }
    ```
    
    **Authentication**: Requires Bearer token from admin session.
    """
    import secrets
    # Generate a secure random key
    api_key = f"enauth_{secrets.token_urlsafe(32)}"
    import hashlib
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    key_prefix = api_key[:20]

    expires_at = None
    if body.expires_days:
        expires_at = future_hours(body.expires_days * 24)

    key_id = generate_uid()
    if body.app_id:
        await _owned_app(body.app_id, auth_owner_id(user), db)
    await db.execute(
        """INSERT INTO api_keys
           (id,user_id,key_hash,key_prefix,name,scopes,expires_at,app_id,allowed_ips)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (key_id, user["id"], key_hash, key_prefix, body.name, body.scopes, expires_at,
         body.app_id, json.dumps(body.allowed_ips) if body.allowed_ips else None)
    )
    await log_action(db, "api_key_created", details=f"API key created: {body.name}")
    await db.commit()

    # Return the key only once
    return {"id": key_id, "key": api_key, "name": body.name, "scopes": body.scopes,
            "expires_at": expires_at, "app_id": body.app_id, "allowed_ips": body.allowed_ips}


@router.put("/api-keys/{key_id}", tags=["API Keys"])
async def update_api_key(key_id: str, body: UpdateApiKeyBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    """
    Update an existing API key.
    
    You can update the name, scopes, or active status of an API key.
    
    **Example request**:
    ```json
    {
        "name": "Updated Name",
        "is_active": false
    }
    ```
    
    **Authentication**: Requires Bearer token from admin session.
    """
    # Verify ownership
    async with db.execute("SELECT user_id FROM api_keys WHERE id = ?", (key_id,)) as cur:
        key = await cur.fetchone()
    if not key or key["user_id"] != user["id"]:
        raise HTTPException(404, "API key not found")

    updates, args = [], []
    if body.name:
        updates.append("name = ?")
        args.append(body.name)
    if body.scopes:
        updates.append("scopes = ?")
        args.append(body.scopes)
    if body.is_active is not None:
        updates.append("is_active = ?")
        args.append(1 if body.is_active else 0)
    if "app_id" in body.model_fields_set:
        if body.app_id:
            await _owned_app(body.app_id, auth_owner_id(user), db)
        updates.append("app_id = ?"); args.append(body.app_id)
    if body.allowed_ips is not None:
        updates.append("allowed_ips = ?")
        args.append(json.dumps(body.allowed_ips) if body.allowed_ips else None)

    if not updates:
        raise HTTPException(400, "Nothing to update")

    args.append(key_id)
    await db.execute(f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?", args)
    await log_action(db, "api_key_updated", details=f"API key updated: {key_id}")
    await db.commit()

    return {"ok": True}


@router.post("/api-keys/{key_id}/rotate", tags=["API Keys"])
async def rotate_api_key(key_id: str, user=Depends(require_admin),
                         db: aiosqlite.Connection = Depends(get_db)):
    """Replace an API credential atomically and reveal the replacement once."""
    async with db.execute(
        "SELECT id,name,scopes,expires_at FROM api_keys WHERE id=? AND user_id=?",
        (key_id, user["id"]),
    ) as cur:
        key = await cur.fetchone()
    if not key:
        raise HTTPException(404, "API key not found")
    replacement = f"enauth_{secrets.token_urlsafe(32)}"
    replacement_hash = hashlib.sha256(replacement.encode("utf-8")).hexdigest()
    cursor = await db.execute(
        """UPDATE api_keys SET key_hash=?,key_prefix=?,is_active=1,last_used=NULL
           WHERE id=? AND user_id=?""",
        (replacement_hash, replacement[:20], key_id, user["id"]),
    )
    if cursor.rowcount != 1:
        await db.rollback()
        raise HTTPException(409, "API key changed during rotation")
    await log_action(db, "api_key_rotated", details=f"API key rotated: {key_id}")
    await db.commit()
    return {"id": key_id, "key": replacement, "name": key["name"],
            "scopes": key["scopes"], "expires_at": key["expires_at"]}


@router.delete("/api-keys/{key_id}", tags=["API Keys"])
async def delete_api_key(key_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    """
    Delete an API key permanently.
    
    This action cannot be undone. Any applications using this key will immediately lose access.
    
    **Authentication**: Requires Bearer token from admin session.
    """
    # Verify ownership
    async with db.execute("SELECT user_id FROM api_keys WHERE id = ?", (key_id,)) as cur:
        key = await cur.fetchone()
    if not key or key["user_id"] != user["id"]:
        raise HTTPException(404, "API key not found")

    await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    await log_action(db, "api_key_deleted", details=f"API key deleted: {key_id}")
    await db.commit()

    return {"ok": True}


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, caller=Depends(require_owner),
                      db: aiosqlite.Connection = Depends(get_db)):
    if caller["id"] == user_id:
        raise HTTPException(400, "Cannot delete yourself")
    await db.execute("DELETE FROM admin_users WHERE id=?", (user_id,))
    await db.commit()
    return {"ok": True}


@router.post("/users/bulk-delete")
async def bulk_delete_users(body: BulkIdsBody, caller=Depends(require_owner),
                            db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No user IDs provided")
    if caller["id"] in body.ids:
        raise HTTPException(400, "Cannot delete yourself")
    qmarks = ",".join(["?"] * len(body.ids))
    await db.execute(f"DELETE FROM admin_users WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


# ─── Variables ───────────────────────────────────────────────────────────────

class VariableBody(BaseModel):
    name: str
    value: str
    is_secret: bool = False

@router.get("/variables")
async def list_variables(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    require_panel_owner(user)
    async with db.execute("SELECT * FROM variables ORDER BY created_at") as cur:
        return rows_to_list(await cur.fetchall())

@router.post("/variables")
async def set_variable(body: VariableBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    require_panel_owner(user)
    uid = generate_uid()
    await db.execute(
        "INSERT INTO variables (id, name, value, is_secret) VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value, is_secret=excluded.is_secret",
        (uid, body.name, body.value, body.is_secret)
    )
    await db.commit()
    return {"ok": True}

@router.delete("/variables/{name}")
async def delete_variable(name: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    require_panel_owner(user)
    await db.execute("DELETE FROM variables WHERE name=?", (name,))
    await db.commit()
    return {"ok": True}


# ─── News ────────────────────────────────────────────────────────────────────

class NewsBody(BaseModel):
    app_id:  str
    title:   str
    content: str
    color:   str = "white"

@router.get("/news")
async def list_news(app_id: Optional[str] = None, search: Optional[str] = None,
                    limit: int = 100, offset: int = 0,
                    user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT n.*, a.name as app_name FROM news n JOIN applications a ON a.id = n.app_id"
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
        if app_id:
            sql += " AND n.app_id = ?"
            args.append(app_id)
        if search:
            sql += " AND (n.title LIKE ? OR n.content LIKE ? OR a.name LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    elif app_id:
        sql += " WHERE n.app_id = ?"
        args.append(app_id)
        if search:
            sql += " AND (n.title LIKE ? OR n.content LIKE ? OR a.name LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    elif search:
        sql += " WHERE (n.title LIKE ? OR n.content LIKE ? OR a.name LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    sql += " ORDER BY n.created_at DESC LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 100), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())

@router.post("/news")
async def add_news(body: NewsBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (body.app_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "App not found")
    uid = generate_uid()
    await db.execute(
        "INSERT INTO news (id, app_id, title, content, color) VALUES (?,?,?,?,?)",
        (uid, body.app_id, body.title, body.content, body.color)
    )
    await db.commit()
    return {"id": uid}

@router.delete("/news/{news_id}")
async def delete_news(news_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            "DELETE FROM news WHERE id=? AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)",
            (news_id, owner_id)
        )
    else:
        await db.execute("DELETE FROM news WHERE id=?", (news_id,))
    await log_action(db, "delete_news", details=f"News {news_id} deleted by {user['username']}")
    await db.commit()
    return {"ok": True}


@router.post("/news/bulk-delete")
async def bulk_delete_news(body: BulkIdsBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No news IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"""DELETE FROM news WHERE id IN ({qmarks})
                AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM news WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}

# ─── App Files ───────────────────────────────────────────────────────────────

@router.get("/loaders")
async def list_loader_releases(app_id: Optional[str] = None, user=Depends(require_admin),
                               db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT f.id,f.app_id,f.name,f.release_version,f.file_size,f.file_sha256,
                    f.release_notes,f.is_active,f.is_archived,f.is_revoked,f.created_at,
                    a.name AS app_name
             FROM app_files f JOIN applications a ON a.id=f.app_id
             WHERE f.file_type='loader'"""
    args = []
    if owner_id:
        sql += " AND a.owner_user_id=?"; args.append(owner_id)
    if app_id:
        sql += " AND f.app_id=?"; args.append(app_id)
    sql += " ORDER BY f.created_at DESC LIMIT 200"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/loaders")
async def upload_loader_release(app_id: str = Form(...), version: str = Form(...),
                                logical_name: str = Form("loader.exe"),
                                release_notes: Optional[str] = Form(None),
                                file: UploadFile = File(...), user=Depends(require_admin),
                                db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    async with db.execute(
        "SELECT id FROM applications WHERE id=?" + (" AND owner_user_id=?" if owner_id else ""),
        (app_id, owner_id) if owner_id else (app_id,),
    ) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Application not found")
    safe_name = validate_release_name(logical_name)
    if not safe_name.lower().endswith(".exe"):
        raise HTTPException(400, "Loader name must be a plain .exe filename")
    clean_version = validate_release_version(version)
    archive_prefix = f"{safe_name}.archived."
    async with db.execute(
        """SELECT 1 FROM app_files WHERE app_id=? AND file_type='loader' AND release_version=?
           AND (name=? OR substr(name,1,?)=?)""",
        (app_id, clean_version, safe_name, len(archive_prefix), archive_prefix),
    ) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "This loader version already exists; publish a new version")
    content = await read_build_upload(file)
    if not content.startswith(b"MZ"):
        raise HTTPException(400, "Loader must be a Windows executable")
    async with db.execute(
        "SELECT id,file_type FROM app_files WHERE app_id=? AND name=?",
        (app_id, safe_name),
    ) as cur:
        previous = await cur.fetchone()
    if previous:
        if previous["file_type"] != "loader":
            raise HTTPException(409, "This filename belongs to a different file type")
        await db.execute(
            "UPDATE app_files SET name=?,is_active=0,is_archived=1 WHERE id=?",
            (f"{safe_name}.archived.{previous['id']}", previous["id"]),
        )
    file_id = generate_uid()
    digest = hashlib.sha256(content).hexdigest()
    await db.execute(
        """INSERT INTO app_files
           (id,app_id,name,content,file_sha256,is_secret,portal_visible,release_version,
            channel,file_type,platform,architecture,release_notes,mime_type,file_size,
            is_active,is_archived,is_mandatory,replaced_file_id)
           VALUES(?,?,?,?,?,0,0,?,'stable','loader','windows','x64',?,'application/vnd.microsoft.portable-executable',?,1,0,1,?)""",
        (file_id, app_id, safe_name, content, digest, clean_version,
         (release_notes or "").strip() or None, len(content), previous["id"] if previous else None),
    )
    await log_action(db, "loader_release_published", app_id=app_id,
                     details=f"name={safe_name}; version={clean_version}; sha256={digest}")
    await db.commit()
    return {"id": file_id, "name": safe_name, "version": clean_version, "sha256": digest,
            "size": len(content), "replaced_file_id": previous["id"] if previous else None}

@router.get("/files")
async def list_files(app_id: Optional[str] = None, search: Optional[str] = None,
                     limit: int = 100, offset: int = 0,
                     user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT f.id, f.app_id, f.name, f.is_secret, f.portal_visible, f.product_id,
                    f.created_at, f.release_version, f.is_revoked, f.revoked_at, f.revoke_reason,
                    a.name as app_name, p.name as product_name
             FROM app_files f 
             JOIN applications a ON a.id = f.app_id
             LEFT JOIN products p ON p.id=f.product_id"""
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
        if app_id:
            sql += " AND f.app_id = ?"
            args.append(app_id)
        if search:
            sql += " AND (f.name LIKE ? OR a.name LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%"])
    elif app_id:
        sql += " WHERE f.app_id = ?"
        args.append(app_id)
        if search:
            sql += " AND (f.name LIKE ? OR a.name LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%"])
    elif search:
        sql += " WHERE (f.name LIKE ? OR a.name LIKE ?)"
        args.extend([f"%{search}%", f"%{search}%"])
        
    sql += " ORDER BY f.created_at DESC LIMIT ? OFFSET ?"
    args.extend([clamp_limit(limit, 100), clamp_offset(offset)])
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())

@router.post("/files")
async def upload_file(
    app_id: str = Form(...),
    name: str = Form(...),
    is_secret: bool = Form(False),
    portal_visible: bool = Form(False),
    product_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
    user=Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db)
):
    owner_id = auth_owner_id(user)
    async with db.execute(
        "SELECT 1 FROM applications WHERE id=?" + (" AND owner_user_id=?" if owner_id else ""),
        (app_id, owner_id) if owner_id else (app_id,),
    ) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "App not found")
    safe_name = validate_release_name(name)
    if product_id:
        async with db.execute("SELECT 1 FROM products WHERE id=? AND app_id=?", (product_id, app_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found for this app")
    
    # Release rows are immutable. An in-place overwrite would preserve old
    # tickets, hashes, versions and revocation flags for entirely new bytes.
    async with db.execute("SELECT 1 FROM app_files WHERE app_id=? AND name=?", (app_id, safe_name)) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "A file with this name exists; publish a new release or remove the old file first")
    content = await read_build_upload(file)
    digest = hashlib.sha256(content).hexdigest()
        
    fid = generate_uid()
    try:
        await db.execute(
            """INSERT INTO app_files
               (id,app_id,name,content,is_secret,portal_visible,product_id,file_sha256,file_size,mime_type)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (fid, app_id, safe_name, content, 1 if is_secret else 0,
             1 if portal_visible else 0, product_id or None, digest, len(content), file.content_type)
        )
        if product_id:
            await db.execute("INSERT INTO app_file_products(file_id,product_id) VALUES(?,?)", (fid, product_id))
        await log_action(db, "file_uploaded", app_id=app_id,
                         details=f"name={safe_name}; sha256={digest}; size={len(content)}")
        await db.commit()
    except aiosqlite.IntegrityError:
        await db.rollback()
        raise HTTPException(409, "A file with this name already exists") from None
        
    return {"id": fid, "name": safe_name, "sha256": digest, "size": len(content)}


class FileVisibilityBody(BaseModel):
    portal_visible: bool
    product_id: Optional[str] = None


class RevokeBuildBody(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    block_client_version: bool = True


@router.put("/files/{file_id}/visibility")
async def update_file_visibility(file_id: str, body: FileVisibilityBody,
                                 user=Depends(require_admin), db=Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT f.app_id FROM app_files f JOIN applications a ON a.id=f.app_id WHERE f.id=?"""
    args = [file_id]
    if owner_id:
        sql += " AND a.owner_user_id=?"; args.append(owner_id)
    async with db.execute(sql, args) as cur:
        file_row = await cur.fetchone()
    if not file_row:
        raise HTTPException(404, "File not found")
    if body.product_id:
        async with db.execute("SELECT 1 FROM products WHERE id=? AND app_id=?", (body.product_id, file_row["app_id"])) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Product not found for this app")
    await db.execute("UPDATE app_files SET portal_visible=?, product_id=? WHERE id=?",
                     (1 if body.portal_visible else 0, body.product_id, file_id))
    await db.commit()
    return {"ok": True}


@router.post("/files/{file_id}/revoke")
async def revoke_file_build(file_id: str, body: RevokeBuildBody,
                            user=Depends(require_admin), db=Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT f.* FROM app_files f JOIN applications a ON a.id=f.app_id WHERE f.id=?"""
    args = [file_id]
    if owner_id:
        sql += " AND a.owner_user_id=?"; args.append(owner_id)
    async with db.execute(sql, args) as cur:
        file_row = await cur.fetchone()
    if not file_row:
        raise HTTPException(404, "File not found")
    await db.execute(
        """UPDATE app_files SET is_revoked=1,is_active=0,revoked_at=CURRENT_TIMESTAMP,revoke_reason=?
           WHERE id=?""", (body.reason.strip(), file_id),
    )
    if body.block_client_version and file_row["release_version"]:
        async with db.execute(
            """SELECT product_id FROM app_file_products WHERE file_id=?
               UNION SELECT product_id FROM app_files WHERE id=? AND product_id IS NOT NULL""",
            (file_id, file_id),
        ) as cur:
            product_ids = [row[0] for row in await cur.fetchall()]
        for product_id in product_ids:
            async with db.execute("SELECT blocked_client_versions FROM products WHERE id=?", (product_id,)) as cur:
                product = await cur.fetchone()
            versions = set(json.loads(product[0] or "[]")) if product else set()
            versions.add(file_row["release_version"])
            await db.execute("UPDATE products SET blocked_client_versions=? WHERE id=?",
                             (json.dumps(sorted(versions)), product_id))
            await db.execute("DELETE FROM sessions WHERE product_id=? AND client_version=?",
                             (product_id, file_row["release_version"]))
    await log_action(db, "build_revoked", app_id=file_row["app_id"],
                     details=f"file={file_id}; version={file_row['release_version']}; reason={body.reason.strip()}")
    await db.commit()
    return {"ok": True}


@router.post("/files/{file_id}/restore")
async def restore_file_build(file_id: str, user=Depends(require_admin), db=Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """UPDATE app_files SET is_revoked=0,is_active=1,revoked_at=NULL,revoke_reason=NULL
             WHERE id=?"""
    args = [file_id]
    if owner_id:
        sql += " AND app_id IN (SELECT id FROM applications WHERE owner_user_id=?)"
        args.append(owner_id)
    cursor = await db.execute(sql, args)
    if cursor.rowcount != 1:
        raise HTTPException(404, "File not found")
    await log_action(db, "build_restored", details=f"file={file_id}; blocked versions unchanged")
    await db.commit()
    return {"ok": True, "note": "Remove the version from the product block list separately when safe."}

@router.delete("/files/{file_id}")
async def delete_file(file_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            "DELETE FROM app_files WHERE id = ? AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)",
            (file_id, owner_id)
        )
    else:
        await db.execute("DELETE FROM app_files WHERE id = ?", (file_id,))
    await db.commit()
    return {"ok": True}


@router.post("/files/bulk-delete")
async def bulk_delete_files(body: BulkIdsBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    if not body.ids:
        raise HTTPException(400, "No file IDs provided")
    owner_id = auth_owner_id(user)
    qmarks = ",".join(["?"] * len(body.ids))
    if owner_id:
        await db.execute(
            f"""DELETE FROM app_files WHERE id IN ({qmarks})
                AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)""",
            (*body.ids, owner_id),
        )
    else:
        await db.execute(f"DELETE FROM app_files WHERE id IN ({qmarks})", body.ids)
    await db.commit()
    return {"ok": True}


# ─── Panels ──────────────────────────────────────────────────────────────────

class CreatePanelBody(BaseModel):
    name: str
    app_id: str

@router.get("/panels")
async def list_panels(user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = "SELECT p.*, a.name as app_name FROM panels p JOIN applications a ON a.id = p.app_id"
    args = []
    if owner_id:
        sql += " WHERE a.owner_user_id = ?"
        args.append(owner_id)
    sql += " ORDER BY p.created_at DESC"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())

@router.post("/panels")
async def create_panel(body: CreatePanelBody, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (body.app_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "App not found")
    pid = generate_uid()
    await db.execute("INSERT INTO panels (id, name, app_id) VALUES (?, ?, ?)", (pid, body.name.strip(), body.app_id))
    await db.commit()
    return {"id": pid, "name": body.name, "app_id": body.app_id}

@router.delete("/panels/{panel_id}")
async def delete_panel(panel_id: str, user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    if owner_id:
        await db.execute(
            "DELETE FROM panels WHERE id = ? AND app_id IN (SELECT id FROM applications WHERE owner_user_id = ?)",
            (panel_id, owner_id),
        )
    else:
        await db.execute("DELETE FROM panels WHERE id = ?", (panel_id,))
    await db.commit()
    return {"ok": True}


# ─── End-User Portal (Public & Authenticated) ────────────────────────────────

async def _portal_has_valid_entitlement(db, license_id: str) -> bool:
    async with db.execute(
        """SELECT 1 FROM license_products
           WHERE license_id=? AND is_paused=0 AND (expires_at IS NULL OR expires_at>=?) LIMIT 1""",
        (license_id, utcnow()),
    ) as cur:
        return bool(await cur.fetchone())

@router.get("/portal/panel/{panel_id}")
async def get_portal_panel(panel_id: str, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT p.id, p.name as panel_name, a.name as app_name, a.id as app_id FROM panels p JOIN applications a ON a.id = p.app_id WHERE p.id = ?",
        (panel_id,),
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Panel not found")
    return dict(row)

class PortalRegisterBody(BaseModel):
    panel_id: str
    username: str
    password: str
    license_key: str

@router.post("/portal/register")
@limiter.limit("5/minute")
async def portal_register(request: Request = None, body: PortalRegisterBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    async with db.execute("SELECT app_id FROM panels WHERE id = ?", (body.panel_id,)) as cur:
        panel = await cur.fetchone()
    if not panel:
        raise HTTPException(404, "Panel not found")
    app_id = panel["app_id"]

    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(400, "Username too short")
    validate_password_policy(body.password)

    async with db.execute(
        "SELECT 1 FROM licenses WHERE app_id = ? AND client_username = ?",
        (app_id, username),
    ) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "Username already taken for this application")

    license_key = body.license_key.strip().upper()
    async with db.execute(
        "SELECT * FROM licenses WHERE key_hash = ? AND app_id = ?",
        (hash_license_key(license_key), app_id),
    ) as cur:
        lic = await cur.fetchone()
    if not lic:
        raise HTTPException(404, "License key not found or invalid for this application")
    if lic["status"] != "active":
        raise HTTPException(400, "This license key is not active")
    if not await _portal_has_valid_entitlement(db, lic["id"]):
        raise HTTPException(400, "This license key has expired")
    if lic["client_username"]:
        raise HTTPException(400, "This license key is already registered to a user account")

    await db.execute(
        "UPDATE licenses SET client_username = ?, client_password_hash = ? WHERE id = ?",
        (username, hash_password(body.password), lic["id"]),
    )
    await db.commit()
    return {"ok": True}

class PortalLoginBody(BaseModel):
    panel_id: str
    username: str
    password: str

@router.post("/portal/login")
@limiter.limit("8/minute")
async def portal_login(request: Request = None, body: PortalLoginBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    async with db.execute("SELECT app_id FROM panels WHERE id = ?", (body.panel_id,)) as cur:
        panel = await cur.fetchone()
    if not panel:
        raise HTTPException(404, "Panel not found")
    app_id = panel["app_id"]

    username = body.username.strip()
    async with db.execute(
        "SELECT * FROM licenses WHERE app_id = ? AND client_username = ?",
        (app_id, username),
    ) as cur:
        lic = await cur.fetchone()

    # Security: use a generic error to prevent username enumeration via portal.
    if not lic:
        raise HTTPException(401, "Invalid credentials")

    # Security: enforce strike-based lockout against distributed brute force.
    # IP rate limiting alone is insufficient if the attacker rotates IPs.
    if lic["login_strikes"] >= MAX_LOGIN_STRIKES:
        raise HTTPException(403, "Account locked due to too many failed attempts")

    if not verify_password(body.password, lic["client_password_hash"]):
        await db.execute("UPDATE licenses SET login_strikes = login_strikes + 1 WHERE id = ?", (lic["id"],))
        await db.commit()
        raise HTTPException(401, "Invalid credentials")

    if lic["status"] != "active":
        raise HTTPException(400, "This license key is not active")
    if not await _portal_has_valid_entitlement(db, lic["id"]):
        raise HTTPException(400, "This license key has expired")

    token = generate_session_token()
    await db.execute(
        "INSERT INTO portal_sessions (id, license_id, token, expires_at) VALUES (?, ?, ?, ?)",
        (generate_uid(), lic["id"], token, future_hours(8)),
    )
    # Reset strikes on successful login
    await db.execute("UPDATE licenses SET login_strikes = 0 WHERE id = ?", (lic["id"],))
    await db.commit()
    return {"token": token, "username": username}

async def require_portal_user(authorization: Optional[str] = Header(None),
                              db: aiosqlite.Connection = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    token = authorization[7:]
    async with db.execute(
        """SELECT l.*, a.name as app_name, ps.token as session_token FROM portal_sessions ps
           JOIN licenses l ON l.id = ps.license_id
           JOIN applications a ON a.id = l.app_id
           WHERE ps.token = ? AND ps.expires_at > ?""",
         (token, utcnow()),
    ) as cur:
        lic = await cur.fetchone()
    if not lic:
        raise HTTPException(401, "Invalid or expired session")
    
    if lic["status"] != "active":
        raise HTTPException(400, "Your license is no longer active")
    if not await _portal_has_valid_entitlement(db, lic["id"]):
        raise HTTPException(400, "Your license has expired")
    
    return dict(lic)

@router.get("/portal/license")
async def get_portal_license(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT COUNT(*) FROM hwids WHERE license_id = ?", (lic["id"],)) as cur:
        hwid_count = (await cur.fetchone())[0]
    async with db.execute(
        """SELECT p.id AS product_id,p.name,p.level,p.service_status,p.status_color,p.status_message,
                  lp.expires_at,lp.is_paused,lp.pause_reason,lp.total_compensation_seconds
           FROM license_products lp JOIN products p ON p.id=lp.product_id
           WHERE lp.license_id=? ORDER BY p.name""", (lic["id"],)
    ) as cur:
        products = rows_to_list(await cur.fetchall())
    cooldown_hours = 24
    async with db.execute("SELECT value FROM variables WHERE name='HWID_RESET_COOLDOWN_HOURS'") as cur:
        cooldown_row = await cur.fetchone()
    if cooldown_row:
        try:
            cooldown_hours = max(0, int(cooldown_row[0]))
        except (TypeError, ValueError):
            pass
    
    return {
        "app_name": lic["app_name"],
        "key": display_license_key(lic["key"], lic.get("key_ciphertext")),
        "status": lic["status"],
        "expires_at": lic["expires_at"],
        "max_hwids": lic["max_hwids"],
        "hwid_count": hwid_count,
        "client_username": lic["client_username"],
        "hwid_reset_at": lic["hwid_reset_at"],
        "products": products,
        "total_compensation_seconds": sum(p["total_compensation_seconds"] or 0 for p in products),
        "hwid_reset_cooldown_hours": cooldown_hours,
    }

@router.post("/portal/reset-hwid")
async def portal_reset_hwid(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    if lic["hwid_reset_at"]:
        try:
            # Parse last reset datetime
            last_reset = datetime.strptime(lic["hwid_reset_at"], "%Y-%m-%d %H:%M:%S")
            last_reset = last_reset.replace(tzinfo=timezone.utc)
            
            # Fetch custom cooldown from variables, default to 24
            cooldown_hours = 24
            async with db.execute("SELECT value FROM variables WHERE name = 'HWID_RESET_COOLDOWN_HOURS'") as cur:
                var_row = await cur.fetchone()
                if var_row:
                    try:
                        cooldown_hours = int(var_row[0])
                    except ValueError:
                        pass
            
            if cooldown_hours > 0:
                now_dt = datetime.now(timezone.utc)
                elapsed = now_dt - last_reset
                cooldown_seconds = cooldown_hours * 3600
                if elapsed.total_seconds() < cooldown_seconds:
                    remaining_seconds = int(cooldown_seconds - elapsed.total_seconds())
                    hours = remaining_seconds // 3600
                    minutes = (remaining_seconds % 3600) // 60
                    raise HTTPException(400, f"HWID reset is on cooldown. Please wait {hours}h {minutes}m before resetting again.")
        except HTTPException:
            raise
        except Exception:
            pass

    await db.execute("DELETE FROM hwids WHERE license_id=?", (lic["id"],))
    await db.execute("UPDATE licenses SET hwid_reset_at=? WHERE id=?", (utcnow(), lic["id"]))
    await log_action(db, "portal_hwid_reset", license_key=lic["key"], app_id=lic["app_id"], details="HWID reset via user portal")
    await db.commit()
    return {"ok": True}


@router.get("/portal/devices")
async def portal_devices(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT d.id,COALESCE(n.display_name,'Unnamed device') AS name,d.last_seen,d.is_suspicious
           FROM device_fingerprints d LEFT JOIN portal_device_names n
             ON n.license_id=d.license_id AND n.fingerprint_id=d.id
           WHERE d.license_id=? ORDER BY d.last_seen DESC""", (lic["id"],)
    ) as cur:
        return rows_to_list(await cur.fetchall())


@router.put("/portal/devices/{device_id}")
async def portal_name_device(device_id: str, body: PortalDeviceNameBody,
                             lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT 1 FROM device_fingerprints WHERE id=? AND license_id=?", (device_id, lic["id"])) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Device not found")
    await db.execute(
        """INSERT INTO portal_device_names(license_id,fingerprint_id,display_name,updated_at)
           VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(license_id,fingerprint_id) DO UPDATE SET
           display_name=excluded.display_name,updated_at=CURRENT_TIMESTAMP""",
        (lic["id"], device_id, body.name.strip()),
    )
    await db.commit()
    return {"ok": True}


@router.get("/portal/hwid-reset-requests")
async def portal_reset_requests(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT id,reason,status,created_at,reviewed_at FROM hwid_reset_requests WHERE license_id=? ORDER BY created_at DESC LIMIT 20",
        (lic["id"],),
    ) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/portal/hwid-reset-requests")
async def portal_request_reset(body: PortalHwidResetRequestBody, lic=Depends(require_portal_user),
                               db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT 1 FROM hwid_reset_requests WHERE license_id=? AND status='pending'", (lic["id"],)
    ) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "A reset request is already pending")
    request_id = generate_uid()
    await db.execute("INSERT INTO hwid_reset_requests(id,license_id,reason) VALUES(?,?,?)",
                     (request_id, lic["id"], (body.reason or "").strip() or None))
    await log_action(db, "portal_hwid_reset_requested", license_key=lic["key"], app_id=lic["app_id"],
                     details="Customer requested an HWID reset")
    await db.commit()
    return {"id": request_id, "status": "pending"}


@router.get("/portal/history")
async def portal_history(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT e.downloaded_at AS timestamp,'download' AS type,f.name AS description
           FROM file_download_events e JOIN app_files f ON f.id=e.file_id
           WHERE e.license_id=? ORDER BY e.downloaded_at DESC LIMIT 50""", (lic["id"],)
    ) as cur:
        downloads = rows_to_list(await cur.fetchall())
    async with db.execute(
        """SELECT created_at AS timestamp,'entitlement' AS type,
                  p.name || ' (' || p.level || ')' AS description
           FROM license_products lp JOIN products p ON p.id=lp.product_id
           WHERE lp.license_id=? ORDER BY lp.created_at DESC""", (lic["id"],)
    ) as cur:
        entitlements = rows_to_list(await cur.fetchall())
    return sorted(downloads + entitlements, key=lambda item: item["timestamp"] or "", reverse=True)[:100]


@router.get("/hwid-reset-requests")
async def admin_reset_requests(status: str = "pending", user=Depends(require_admin),
                               db: aiosqlite.Connection = Depends(get_db)):
    if status not in {"pending", "approved", "rejected", "all"}:
        raise HTTPException(400, "Invalid request status")
    owner_id = auth_owner_id(user)
    sql = """SELECT r.id,r.reason,r.status,r.created_at,r.reviewed_at,l.key,l.client_username,a.name AS app_name
             FROM hwid_reset_requests r JOIN licenses l ON l.id=r.license_id
             JOIN applications a ON a.id=l.app_id WHERE 1=1"""
    args = []
    if status != "all": sql += " AND r.status=?"; args.append(status)
    if owner_id: sql += " AND a.owner_user_id=?"; args.append(owner_id)
    sql += " ORDER BY r.created_at DESC LIMIT 200"
    async with db.execute(sql, args) as cur:
        return rows_to_list(await cur.fetchall())


@router.post("/hwid-reset-requests/{request_id}/{decision}")
async def review_reset_request(request_id: str, decision: str, user=Depends(require_admin),
                               db: aiosqlite.Connection = Depends(get_db)):
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "Decision must be approve or reject")
    owner_id = auth_owner_id(user)
    sql = """SELECT r.license_id,l.app_id FROM hwid_reset_requests r JOIN licenses l ON l.id=r.license_id
             JOIN applications a ON a.id=l.app_id WHERE r.id=? AND r.status='pending'"""
    args = [request_id]
    if owner_id: sql += " AND a.owner_user_id=?"; args.append(owner_id)
    async with db.execute(sql, args) as cur:
        row = await cur.fetchone()
    if not row: raise HTTPException(404, "Pending reset request not found")
    await db.execute("BEGIN IMMEDIATE")
    try:
        if decision == "approve":
            await db.execute("DELETE FROM hwids WHERE license_id=?", (row["license_id"],))
            await db.execute("DELETE FROM device_fingerprints WHERE license_id=?", (row["license_id"],))
            await db.execute("UPDATE licenses SET hwid_reset_at=? WHERE id=?", (utcnow(), row["license_id"]))
        await db.execute("UPDATE hwid_reset_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",
                         ("approved" if decision == "approve" else "rejected", user["username"], request_id))
        await log_action(db, f"hwid_reset_request_{decision}d", app_id=row["app_id"], details=f"request={request_id}")
        await db.commit()
    except Exception:
        await db.rollback(); raise
    return {"ok": True}


# ─── End-User Portal Files ──────────────────────────────────────────────────

@router.get("/portal/files")
async def portal_list_files(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    sql = """SELECT id, name, created_at, product_id
             FROM app_files
             WHERE app_id = ? AND portal_visible = 1
               AND (product_id IS NULL OR product_id IN
                    (SELECT product_id FROM license_products WHERE license_id=?))
             ORDER BY created_at DESC"""
    async with db.execute(sql, (lic["app_id"], lic["id"])) as cur:
        return rows_to_list(await cur.fetchall())


@router.get("/portal/files/{file_id}/download")
async def portal_download_file(file_id: str, lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT name, content FROM app_files WHERE id = ? AND app_id = ? AND portal_visible=1
           AND (product_id IS NULL OR product_id IN
                (SELECT product_id FROM license_products WHERE license_id=?))""",
        (file_id, lic["app_id"], lic["id"]),
    ) as cur:
        row = await cur.fetchone()

    if not row:
        raise HTTPException(404, "File not found or access denied.")

    content = row["content"]
    filename = row["name"]

    # Security: sanitize filename to prevent HTTP header injection via
    # Content-Disposition. Strip any characters outside safe ASCII printable
    # range, then use RFC 5987 percent-encoding for the filename parameter.
    safe_filename = re.sub(r'[^\w\-. ]', '_', filename)
    from urllib.parse import quote
    encoded_filename = quote(filename, safe=" !#$&'()*+,/:;=?@[]~")

    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{safe_filename}\"; "
                f"filename*=UTF-8''{encoded_filename}"
            )
        }
    )
