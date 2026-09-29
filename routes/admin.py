import asyncio
import csv
from pydantic import field_validator, model_validator
import io
import os
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Header, File, UploadFile, Form, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional
import aiosqlite
import re
import secrets
import hashlib
import pyotp

from database import get_db
from routes.client import limiter
from utils.crypto import (
    generate_license_key, generate_app_secret,
    generate_session_token, generate_uid,
    hash_password, verify_password,
    hash_license_key, mask_license_key,
)
from utils.logger import app_log, log_action

router = APIRouter(prefix="/api/admin", tags=["admin"])
ADMIN_SESSION_HOURS = int(os.getenv("ADMIN_SESSION_HOURS", "8"))
MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "200"))
TEMP_2FA_TTL_MINUTES = int(os.getenv("TEMP_2FA_TTL_MINUTES", "5"))
TEMP_2FA_SWEEP_SECONDS = int(os.getenv("TEMP_2FA_SWEEP_SECONDS", "60"))
ADMIN_COOKIE_NAME = "enauth_admin_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


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
    await db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    await db.execute("DELETE FROM temp_2fa_sessions WHERE expires_at <= ?", (now,))
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
    if user["role"] != "owner":
        raise HTTPException(403, "Owner role required")
    return user


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

class SignupBody(BaseModel):
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


@router.post("/auth/signup")
@limiter.limit("5/minute")
async def auth_signup(request: Request = None, body: SignupBody = None, db: aiosqlite.Connection = Depends(get_db)):
    if body is None:
        raise HTTPException(400, "Invalid request")
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(400, "Username too short")
    validate_password_policy(body.password)

    # Check both tables for uniqueness
    async with db.execute("SELECT 1 FROM admin_users WHERE username = ?", (username,)) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "Username already taken")
    async with db.execute("SELECT 1 FROM auth_users WHERE username = ?", (username,)) as cur:
        if await cur.fetchone():
            raise HTTPException(409, "Username already taken")

    uid = generate_uid()
    try:
        await db.execute(
            "INSERT INTO auth_users (id, username, password_hash, role) VALUES (?,?,?,?)",
            (uid, username, hash_password(body.password), "user"),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Username already taken")
    return {"id": uid, "username": username}


@router.post("/auth/signin")
@limiter.limit("8/minute")
async def auth_signin(response: Response, request: Request, body: LoginBody, db: aiosqlite.Connection = Depends(get_db)):
    # Security: check both user tables but always return a generic 401 to prevent
    # username enumeration. Never reveal which table or field was wrong.
    async with db.execute("SELECT * FROM auth_users WHERE username = ?", (body.username,)) as cur:
        auth_user = await cur.fetchone()
    if auth_user and verify_password(body.password, auth_user["password_hash"]):
        token = generate_session_token()
        await db.execute(
            "INSERT INTO auth_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
            (generate_uid(), auth_user["id"], token, future_hours(ADMIN_SESSION_HOURS)),
        )
        await db.commit()
        set_admin_cookie(response, token)
        return {"username": auth_user["username"], "role": auth_user["role"]}

    async with db.execute("SELECT * FROM admin_users WHERE username = ?", (body.username,)) as cur:
        admin_user = await cur.fetchone()
    if admin_user and verify_password(body.password, admin_user["password_hash"]):
        # 2FA Check
        if admin_user["two_factor_enabled"] == 1:
            temp_token = await create_temp_2fa_session(db, admin_user["id"], admin_user["role"])
            return {
                "two_factor_required": True,
                "temp_token": temp_token,
                "username": admin_user["username"]
            }

        token = generate_session_token()
        await db.execute(
            "INSERT INTO admin_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
            (generate_uid(), admin_user["id"], token, future_hours(ADMIN_SESSION_HOURS)),
        )
        await db.commit()
        set_admin_cookie(response, token)
        return {"username": admin_user["username"], "role": admin_user["role"]}

    raise HTTPException(401, "Invalid credentials")


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
    await db.execute("UPDATE admin_users SET two_factor_secret = ? WHERE id = ?", (secret, user["id"]))
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

    # Successful verification! Create active admin session token
    token = generate_session_token()
    await db.execute(
        "INSERT INTO admin_sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)",
        (generate_uid(), user["id"], token, future_hours(ADMIN_SESSION_HOURS)),
    )
    await db.execute("DELETE FROM temp_2fa_sessions WHERE token = ?", (body.temp_token,))
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


class ProductPricingBody(BaseModel):
    days: int
    price: float


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
    if not updates:
        raise HTTPException(400, "Nothing to update")
    args.append(product_id)
    try:
        await db.execute(f"UPDATE products SET {', '.join(updates)} WHERE id = ?", args)
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
        """SELECT COUNT(*) as total, SUM(CAST(l.metadata AS REAL)) as revenue
           FROM licenses l
           JOIN key_orders ko ON l.id = ko.license_id
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
    sql = """SELECT p.*, rpa.id as access_id
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
            "INSERT INTO reseller_product_access (id, reseller_id, product_id) VALUES (?, ?, ?)",
            (generate_uid(), reseller_id, body.product_id),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Product already granted to reseller")
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
async def reseller_signin(body: LoginBody, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM resellers WHERE username = ? AND is_active = 1", (body.username,)) as cur:
        reseller = await cur.fetchone()
    if not reseller:
        raise HTTPException(404, "Username not found")
    if not verify_password(body.password, reseller["password_hash"]):
        raise HTTPException(401, "Wrong password")
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
        """SELECT p.id, p.name, p.level, p.app_id
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


class ResellerBuyBody(BaseModel):
    product_id: str
    pricing_point_id: str


@router.post("/reseller/buy-key")
async def reseller_buy_key(body: ResellerBuyBody, reseller=Depends(require_reseller), db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("BEGIN IMMEDIATE")
    try:
        async with db.execute(
            "SELECT 1 FROM reseller_product_access WHERE reseller_id = ? AND product_id = ?",
            (reseller["id"], body.product_id),
        ) as cur:
            allowed = await cur.fetchone()
        if not allowed:
            raise HTTPException(403, "Reseller is not allowed to buy this product")

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
            "INSERT INTO licenses (id, key, key_hash, app_id, max_hwids, expires_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (license_id, mask_license_key(license_key), hash_license_key(license_key), target["app_id"], 1, expires, f"product_id={target['product_id']}"),
        )
        await db.execute(
            "INSERT OR IGNORE INTO license_products (id, license_id, product_id) VALUES (?, ?, ?)",
            (generate_uid(), license_id, target["product_id"]),
        )
        await db.execute("UPDATE resellers SET balance = balance - ? WHERE id = ?", (target["price"], reseller["id"]))
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
    else:
        total_licenses  = await scalar("SELECT COUNT(*) FROM licenses")
        active_licenses = await scalar("SELECT COUNT(*) FROM licenses WHERE status='active'")
        banned_licenses = await scalar("SELECT COUNT(*) FROM licenses WHERE status='banned'")
        active_sessions = await scalar("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", utcnow())
        total_apps      = await scalar("SELECT COUNT(*) FROM applications")
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

    return {
        "total_licenses":  total_licenses,
        "active_licenses": active_licenses,
        "banned_licenses": banned_licenses,
        "active_sessions": active_sessions,
        "total_apps":      total_apps,
        "logins_today":    logins_today,
        "recent_logs":     recent_logs,
        "traffic":         traffic,
    }


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

    if rows:
        ids = [r["id"] for r in rows]
        qmarks = ",".join(["?"] * len(ids))
        async with db.execute(
            f"""SELECT lp.license_id, p.id as product_id, p.level, p.name
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
            })
        for r in rows:
            r["products"] = by_lic.get(r["id"], [])
    return rows


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
            "INSERT INTO licenses (id, key, key_hash, app_id, max_hwids, expires_at, notes, metadata) VALUES (?,?,?,?,?,?,?,?)",
            (lid, mask_license_key(key), hash_license_key(key), body.app_id, body.max_hwids, expires, notes, body.metadata),
        )
        for pid in unique_pids:
            await db.execute(
                "INSERT OR IGNORE INTO license_products (id, license_id, product_id) VALUES (?, ?, ?)",
                (generate_uid(), lid, pid),
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
    async with db.execute("SELECT * FROM hwids WHERE license_id = ?", (license_id,)) as cur:
        lic["hwids"] = rows_to_list(await cur.fetchall())
    return lic


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
    sql = """SELECT s.*, l.key as license_key, a.name as app_name
           FROM sessions s
           JOIN licenses l ON l.id = s.license_id
           JOIN applications a ON a.id = s.app_id
           WHERE s.expires_at > ?"""
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
    name: str
    scopes: str = "read"
    expires_days: Optional[int] = None


class UpdateApiKeyBody(BaseModel):
    name: Optional[str] = None
    scopes: Optional[str] = None
    is_active: Optional[bool] = None


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

    # Mark token as used
    await db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?", (utcnow(), reset_token["id"]))

    # Update password
    await db.execute(
        "UPDATE admin_users SET password_hash = ? WHERE id = ?",
        (hash_password(body.new_password), reset_token["user_id"])
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
        """SELECT id, name, scopes, is_active, last_used, expires_at, created_at
           FROM api_keys WHERE user_id = ? ORDER BY created_at DESC""",
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
    await db.execute(
        """INSERT INTO api_keys (id, user_id, key_hash, key_prefix, name, scopes, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (key_id, user["id"], key_hash, key_prefix, body.name, body.scopes, expires_at)
    )
    await log_action(db, "api_key_created", details=f"API key created: {body.name}")
    await db.commit()

    # Return the key only once
    return {"id": key_id, "key": api_key, "name": body.name, "scopes": body.scopes, "expires_at": expires_at}


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

    if not updates:
        raise HTTPException(400, "Nothing to update")

    args.append(key_id)
    await db.execute(f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?", args)
    await log_action(db, "api_key_updated", details=f"API key updated: {key_id}")
    await db.commit()

    return {"ok": True}


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

@router.get("/files")
async def list_files(app_id: Optional[str] = None, search: Optional[str] = None,
                     limit: int = 100, offset: int = 0,
                     user=Depends(require_admin), db: aiosqlite.Connection = Depends(get_db)):
    owner_id = auth_owner_id(user)
    sql = """SELECT f.id, f.app_id, f.name, f.is_secret, f.created_at, a.name as app_name 
             FROM app_files f 
             JOIN applications a ON a.id = f.app_id"""
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
    file: UploadFile = File(...),
    user=Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db)
):
    owner_id = auth_owner_id(user)
    if owner_id:
        async with db.execute("SELECT 1 FROM applications WHERE id = ? AND owner_user_id = ?", (app_id, owner_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "App not found")
    
    content = await file.read()
    if len(content) > 5 * 1024 * 1024: # 5MB limit
        raise HTTPException(400, "File too large (max 5MB)")
        
    fid = generate_uid()
    try:
        await db.execute(
            "INSERT INTO app_files (id, app_id, name, content, is_secret) VALUES (?,?,?,?,?) ON CONFLICT(app_id, name) DO UPDATE SET content=excluded.content, is_secret=excluded.is_secret",
            (fid, app_id, name.strip(), content, 1 if is_secret else 0)
        )
        await db.commit()
    except Exception as e:
        raise HTTPException(500, f"Upload failed: {str(e)}")
        
    return {"id": fid, "name": name}

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
    if lic["expires_at"] and lic["expires_at"] < utcnow():
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
    if lic["expires_at"] and lic["expires_at"] < utcnow():
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
    if lic["expires_at"] and lic["expires_at"] < utcnow():
        raise HTTPException(400, "Your license has expired")
    
    return dict(lic)

@router.get("/portal/license")
async def get_portal_license(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT COUNT(*) FROM hwids WHERE license_id = ?", (lic["id"],)) as cur:
        hwid_count = (await cur.fetchone())[0]
    
    return {
        "app_name": lic["app_name"],
        "key": lic["key"],
        "status": lic["status"],
        "expires_at": lic["expires_at"],
        "max_hwids": lic["max_hwids"],
        "hwid_count": hwid_count,
        "client_username": lic["client_username"],
        "hwid_reset_at": lic["hwid_reset_at"]
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


# ─── End-User Portal Files ──────────────────────────────────────────────────

@router.get("/portal/files")
async def portal_list_files(lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    # Retrieve files associated with the active application, excluding secret files
    sql = """SELECT id, name, created_at 
             FROM app_files 
             WHERE app_id = ? AND is_secret = 0 
             ORDER BY created_at DESC"""
    async with db.execute(sql, (lic["app_id"],)) as cur:
        return rows_to_list(await cur.fetchall())


@router.get("/portal/files/{file_id}/download")
async def portal_download_file(file_id: str, lic=Depends(require_portal_user), db: aiosqlite.Connection = Depends(get_db)):
    # Verify the file belongs to the application and is not secret
    async with db.execute(
        "SELECT name, content, is_secret FROM app_files WHERE id = ? AND app_id = ?",
        (file_id, lic["app_id"]),
    ) as cur:
        row = await cur.fetchone()

    if not row:
        raise HTTPException(404, "File not found or access denied.")

    if row["is_secret"] == 1:
        raise HTTPException(403, "Access to secret files is restricted.")

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
