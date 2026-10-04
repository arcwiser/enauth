import time
import hashlib
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import json
import aiosqlite
from slowapi import Limiter
from slowapi.util import get_remote_address

from database import get_db
from utils.crypto import (
    encrypt_payload, decrypt_payload,
    verify_signature, compute_signature,
    generate_session_token, generate_uid,
    is_valid_hwid, hash_license_key, mask_license_key,
    encrypt_bytes, derive_session_download_secret,
)
from utils.response_signing import sign_response
from utils.logger import log_action

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/client", tags=["client"])

# ─── Security Constants ───────────────────────────────────────────────────────
import os
TIMESTAMP_TOLERANCE  = int(os.getenv("TIMESTAMP_TOLERANCE", "60"))      # ±60 seconds — tight replay window
SESSION_DURATION     = int(os.getenv("SESSION_DURATION", "86400"))       # 24 hours
MAX_LOGIN_STRIKES    = int(os.getenv("MAX_LOGIN_STRIKES", "5"))          # lock key after 5 bad attempts (down from 10)
NONCE_CACHE_SIZE     = int(os.getenv("NONCE_CACHE_SIZE", "10000"))      # max unique nonces to remember
NONCE_TTL            = int(os.getenv("NONCE_TTL", "120"))                # seconds to keep a nonce (2× tolerance)
REQUIRE_SESSION_HWID = os.getenv("REQUIRE_SESSION_HWID", "true").lower() == "true"


async def enforce_session_identity(db, payload: dict, sess, app_id: str, ip: str) -> bool:
    supplied_hwid = (payload.get("hwid") or "").strip()
    if (REQUIRE_SESSION_HWID and not supplied_hwid) or (supplied_hwid and supplied_hwid != sess["hwid"]):
        await db.execute("DELETE FROM sessions WHERE token=?", (sess["token"],))
        await log_action(db, "session_identity_mismatch", app_id=app_id, ip=ip,
                         hwid=supplied_hwid[:128] or None, details="Session revoked")
        await db.commit()
        return False
    return True

async def _check_and_store_nonce(db: aiosqlite.Connection, nonce: str, now: float) -> bool:
    """Atomically persist a nonce so replay checks survive restarts and workers."""
    nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    await db.execute("DELETE FROM request_nonces WHERE expires_at <= ?", (int(now),))
    try:
        await db.execute(
            "INSERT INTO request_nonces(nonce_hash, expires_at) VALUES (?, ?)",
            (nonce_hash, int(now) + NONCE_TTL),
        )
        await db.commit()
        return True
    except aiosqlite.IntegrityError:
        await db.rollback()
        return False


# ─── Helpers ─────────────────────────────────────────────────────────────────

class EncryptedRequest(BaseModel):
    app_id: str = Field(min_length=1, max_length=128)
    data:   str = Field(min_length=1, max_length=6_000_000)
    sig:    str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")
    ts:     int
    nonce:  str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-fA-F]{32}$")


def get_ip(request: Request) -> str:
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def generate_device_fingerprint(request: Request, hwid: str) -> str:
    """Generate a device fingerprint from request data and HWID."""
    user_agent = request.headers.get("User-Agent", "")
    ip = get_ip(request)
    fingerprint_data = f"{hwid}:{user_agent}:{ip}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


async def check_fingerprint_consistency(db: aiosqlite.Connection, license_id: str, fingerprint: str, ip: str, user_agent: str) -> bool:
    """Check if the fingerprint is consistent with previous logins."""
    # Check if this fingerprint has been seen before for this user
    async with db.execute(
        """SELECT id, is_suspicious FROM device_fingerprints
           WHERE license_id = ? AND fingerprint = ?""",
        (license_id, fingerprint)
    ) as cur:
        existing = await cur.fetchone()
    
    if existing:
        # Fingerprint seen before, update last_seen
        await db.execute(
            """UPDATE device_fingerprints
               SET last_seen = CURRENT_TIMESTAMP, ip_address = ?, user_agent = ?
               WHERE id = ?""",
            (ip, user_agent, existing["id"])
        )
        return True
    
    # New fingerprint - check if it's suspicious (too many different fingerprints)
    async with db.execute(
        """SELECT COUNT(*) as count FROM device_fingerprints
           WHERE license_id = ? AND last_seen > datetime('now', '-7 days')""",
        (license_id,)
    ) as cur:
        recent_count = (await cur.fetchone())["count"]
    
    is_suspicious = recent_count >= 5  # More than 5 different devices in 7 days is suspicious
    
    # Store the new fingerprint
    await db.execute(
        """INSERT INTO device_fingerprints (id, license_id, fingerprint, user_agent, ip_address, is_suspicious)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (generate_uid(), license_id, fingerprint, user_agent, ip, 1 if is_suspicious else 0)
    )
    
    return not is_suspicious


def enc_resp(data: dict, secret: str, app_id: str = "") -> JSONResponse:
    ts  = int(time.time())
    enc = encrypt_payload(data, secret)
    sig = compute_signature(secret, enc, ts, app_id)
    signed_message = f"{app_id}|{ts}|{enc}"
    return JSONResponse({"data": enc, "sig": sig, "server_sig": sign_response(signed_message), "ts": ts})


async def parse_request(req: EncryptedRequest, db) -> tuple[dict, dict]:
    """
    Full validation pipeline:
      1. Timestamp within ±60 s
      2. Nonce not seen before (replay protection)
      3. App exists
      4. HMAC-SHA256 signature valid (covers app_id + ts + data)
      5. AES-256-GCM decrypt (authenticated — rejects tampered ciphertext)
    """
    now = time.time()

    # 1. Timestamp check
    if abs(now - req.ts) > TIMESTAMP_TOLERANCE:
        raise HTTPException(400, "REPLAY_ATTACK")

    # 2. App lookup
    async with db.execute("SELECT * FROM applications WHERE id = ?", (req.app_id,)) as cur:
        app = await cur.fetchone()
    if not app:
        raise HTTPException(401, "INVALID_APP")

    secret = app["secret_key"]

    # 3. Authenticate before touching the replay cache. This prevents invalid
    # requests from filling the persistent nonce table.
    if not verify_signature(secret, req.data, req.ts, req.sig, req.app_id):
        raise HTTPException(401, "INVALID_SIGNATURE")

    # 4. Store the authenticated nonce atomically.
    if not await _check_and_store_nonce(db, req.nonce, now):
        raise HTTPException(400, "REPLAY_ATTACK")

    # 5. Authenticated decryption (GCM tag validates integrity)
    try:
        payload = decrypt_payload(req.data, secret)
    except Exception:
        raise HTTPException(400, "DECRYPT_FAILED")

    return payload, dict(app)


async def get_app_session(db, token: str, app_id: str):
    """Resolve a session only inside the application that issued it."""
    async with db.execute(
        "SELECT * FROM sessions WHERE token = ? AND app_id = ?", (token, app_id)
    ) as cur:
        return await cur.fetchone()


async def enforce_active_authorization(db, sess, app, ip: str) -> str | None:
    """Re-check mutable license and product authorization on protected calls."""
    async with db.execute(
        "SELECT status, expires_at FROM licenses WHERE id=? AND app_id=?",
        (sess["license_id"], app["id"]),
    ) as cur:
        lic = await cur.fetchone()

    failure = None
    if not lic or lic["status"] != "active":
        failure = "EXPIRED_KEY" if lic and lic["status"] == "expired" else "BANNED_KEY"
    elif lic["expires_at"] and lic["expires_at"] < utcnow():
        failure = "EXPIRED_KEY"
    elif app["is_paused"]:
        failure = "APP_PAUSED"

    if not failure and sess["product_id"]:
        async with db.execute(
            """SELECT p.is_paused AS product_paused,
                      lp.is_paused AS entitlement_paused, lp.expires_at
               FROM products p
               JOIN license_products lp ON lp.product_id=p.id AND lp.license_id=?
               WHERE p.id=? AND p.app_id=?""",
            (sess["license_id"], sess["product_id"], app["id"]),
        ) as cur:
            entitlement = await cur.fetchone()
        if not entitlement:
            failure = "LEVEL_NOT_ALLOWED"
        elif entitlement["product_paused"]:
            failure = "PRODUCT_PAUSED"
        elif entitlement["entitlement_paused"]:
            failure = "ENTITLEMENT_PAUSED"
        elif entitlement["expires_at"] and entitlement["expires_at"] < utcnow():
            failure = "EXPIRED_KEY"

    if failure:
        await db.execute("DELETE FROM sessions WHERE token=?", (sess["token"],))
        await log_action(db, "session_authorization_revoked", app_id=app["id"], ip=ip,
                         hwid=sess["hwid"], details=failure)
        await db.commit()
    return failure


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")


# ─── /init ───────────────────────────────────────────────────────────────────

@router.post("/init")
@limiter.limit("20/minute")
async def client_init(request: Request, req: EncryptedRequest,
                      db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException as e:
        await log_action(db, "init_fail", app_id=req.app_id, ip=ip, details=e.detail)
        raise

    version = payload.get("version", "")
    secret  = app["secret_key"]

    if version != app["version"]:
        await log_action(db, "init_outdated", app_id=req.app_id, ip=ip,
                         details=f"client={version} required={app['version']}")
        return enc_resp({"success": False, "message": "OUTDATED_VERSION",
                         "required_version": app["version"]}, secret, req.app_id)

    await log_action(db, "init", app_id=req.app_id, ip=ip, details=f"v{version}")
    return enc_resp({"success": True, "message": "OK",
                     "server_time": utcnow()}, secret, req.app_id)


# ─── /news ───────────────────────────────────────────────────────────────────

@router.post("/news")
@limiter.limit("15/minute")
async def client_news(request: Request, req: EncryptedRequest,
                      db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException:
        raise

    secret = app["secret_key"]
    async with db.execute(
        "SELECT id, title, content, color, created_at FROM news WHERE app_id = ? ORDER BY created_at DESC LIMIT 10",
        (app["id"],),
    ) as cur:
        rows = await cur.fetchall()

    news_items = [
        {"id": r["id"], "title": r["title"], "content": r["content"],
         "color": r["color"], "created_at": r["created_at"]}
        for r in rows
    ]
    return enc_resp({"success": True, "message": "OK", "news": news_items}, secret, req.app_id)


# ─── /login ──────────────────────────────────────────────────────────────────

@router.post("/login")
@limiter.limit("8/minute")
async def client_login(request: Request, req: EncryptedRequest,
                       db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException as e:
        await log_action(db, "login_fail", app_id=req.app_id, ip=ip, details=e.detail)
        raise

    secret      = app["secret_key"]
    license_key = payload.get("license_key", "").strip().upper()
    hwid        = payload.get("hwid", "").strip()
    product_id  = (payload.get("product_id") or "").strip()
    level       = (payload.get("level") or "").strip().lower()

    if not license_key or not hwid:
        return enc_resp({"success": False, "message": "MISSING_FIELDS"}, secret, req.app_id)

    if app["is_paused"]:
        return enc_resp({"success": False, "message": "APP_PAUSED",
                         "reason": app["pause_reason"] or "Temporarily unavailable"}, secret, req.app_id)

    # ── HWID format validation ──
    # Clients must send a SHA-256 or SHA-512 hex digest — no raw strings
    if not is_valid_hwid(hwid):
        await log_action(db, "login_fail", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid[:32], details="Invalid HWID format")
        return enc_resp({"success": False, "message": "INVALID_HWID_FORMAT"}, secret, req.app_id)

    # ── Fetch license ──
    async with db.execute(
        "SELECT * FROM licenses WHERE key_hash = ? AND app_id = ?", (hash_license_key(license_key), app["id"])
    ) as cur:
        lic = await cur.fetchone()

    if not lic:
        # Increment IP-level strike counter to slow down key enumeration
        await log_action(db, "login_fail", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid, details="Key not found")
        return enc_resp({"success": False, "message": "INVALID_KEY"}, secret, req.app_id)

    # ── Brute force lockout (5 strikes) ──
    if lic["login_strikes"] >= MAX_LOGIN_STRIKES:
        await log_action(db, "login_locked", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid, details=f"Locked after {MAX_LOGIN_STRIKES} strikes")
        return enc_resp({"success": False, "message": "KEY_LOCKED_STRIKES"}, secret, req.app_id)

    # ── Level enforcement ──
    entitlement = None
    if product_id:
        async with db.execute(
            """SELECT lp.expires_at, lp.is_paused AS entitlement_paused,
                      lp.pause_reason AS entitlement_pause_reason,
                      p.id AS product_id, p.is_paused, p.pause_reason
               FROM license_products lp JOIN products p ON p.id=lp.product_id
               WHERE lp.license_id = ? AND lp.product_id = ? AND p.app_id = ?""",
            (lic["id"], product_id, app["id"]),
        ) as cur:
            entitlement = await cur.fetchone()
            if not entitlement:
                await db.execute("UPDATE licenses SET login_strikes = login_strikes + 1 WHERE id = ?", (lic["id"],))
                await db.commit()
                return enc_resp({"success": False, "message": "LEVEL_NOT_ALLOWED"}, secret, req.app_id)
    elif level:
        async with db.execute(
            """SELECT lp.expires_at, lp.is_paused AS entitlement_paused,
                      lp.pause_reason AS entitlement_pause_reason,
                      p.id AS product_id, p.is_paused, p.pause_reason FROM license_products lp
               JOIN products p ON lp.product_id = p.id
               WHERE lp.license_id = ? AND LOWER(p.level) = ? AND p.app_id = ?""",
            (lic["id"], level, app["id"]),
        ) as cur:
            entitlement = await cur.fetchone()
            if not entitlement:
                await db.execute("UPDATE licenses SET login_strikes = login_strikes + 1 WHERE id = ?", (lic["id"],))
                await db.commit()
                return enc_resp({"success": False, "message": "LEVEL_NOT_ALLOWED"}, secret, req.app_id)

    if entitlement and entitlement["is_paused"]:
        return enc_resp({"success": False, "message": "PRODUCT_PAUSED",
                         "reason": entitlement["pause_reason"] or "Temporarily unavailable"}, secret, req.app_id)
    if entitlement and entitlement["entitlement_paused"]:
        return enc_resp({"success": False, "message": "ENTITLEMENT_PAUSED",
                         "reason": entitlement["entitlement_pause_reason"] or "License temporarily paused"}, secret, req.app_id)

    # ── App-specific HWID ban check ──
    async with db.execute(
        "SELECT reason FROM banned_hwids WHERE hwid = ? AND app_id = ?", (hwid, app["id"])
    ) as cur:
        ban_row = await cur.fetchone()
    if ban_row:
        # Auto-ban the key linked to this banned hardware
        await db.execute("UPDATE licenses SET status = 'banned' WHERE id = ?", (lic["id"],))
        await db.commit()
        await log_action(db, "auto_ban", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid,
                         details=f"Auto-banned: linked to banned HWID ({ban_row['reason']})")
        return enc_resp({"success": False, "message": "BANNED_HWID"}, secret, req.app_id)

    # ── Status checks ──
    if lic["status"] == "banned":
        await log_action(db, "login_banned", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid)
        return enc_resp({"success": False, "message": "BANNED_KEY"}, secret, req.app_id)

    effective_expiry = entitlement["expires_at"] if entitlement else lic["expires_at"]
    if lic["status"] == "expired" or (effective_expiry and effective_expiry < utcnow()):
        await log_action(db, "login_expired", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid)
        return enc_resp({"success": False, "message": "EXPIRED_KEY"}, secret, req.app_id)

    # ── IP change detection ──
    suspicious = False
    if lic["last_ip"] and lic["last_ip"] != ip:
        suspicious = True
        await log_action(db, "suspicious_login", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid, details=f"IP changed from {lic['last_ip']}")

    # ── HWID check ──
    async with db.execute("SELECT hwid_hash FROM hwids WHERE license_id = ?", (lic["id"],)) as cur:
        hwid_rows = await cur.fetchall()

    known_hashes = [r["hwid_hash"] for r in hwid_rows]

    if hwid not in known_hashes:
        if len(known_hashes) >= lic["max_hwids"]:
            await log_action(db, "login_hwid_limit", license_key=mask_license_key(license_key),
                             app_id=app["id"], ip=ip, hwid=hwid)
            return enc_resp({"success": False, "message": "MAX_HWIDS"}, secret, req.app_id)
        await db.execute(
            "INSERT INTO hwids (license_id, hwid_hash) VALUES (?, ?)", (lic["id"], hwid)
        )
    else:
        await db.execute(
            "UPDATE hwids SET last_seen = ? WHERE license_id = ? AND hwid_hash = ?",
            (utcnow(), lic["id"], hwid),
        )

    # ── Device fingerprint consistency check ──
    fingerprint = generate_device_fingerprint(request, hwid)
    user_agent = request.headers.get("User-Agent", "")
    # Use license ID for fingerprint tracking
    fingerprint_ok = await check_fingerprint_consistency(db, lic["id"], fingerprint, ip, user_agent)
    if not fingerprint_ok:
        await log_action(db, "suspicious_fingerprint", license_key=mask_license_key(license_key), app_id=app["id"],
                         ip=ip, hwid=hwid, details="New device fingerprint detected (multiple devices in short period)")
        # Don't block login, just log it for security monitoring

    # ── Kill only the existing session for this license/product pair ──
    selected_product_id = entitlement["product_id"] if entitlement else None
    if selected_product_id:
        await db.execute("DELETE FROM sessions WHERE license_id = ? AND product_id = ?",
                         (lic["id"], selected_product_id))
    else:
        await db.execute("DELETE FROM sessions WHERE license_id = ? AND product_id IS NULL", (lic["id"],))

    # ── Create session ──
    token      = generate_session_token()
    session_id = generate_uid()
    expires    = future(SESSION_DURATION)

    await db.execute(
        "INSERT INTO sessions (id, token, license_id, hwid, ip, app_id, product_id, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (session_id, token, lic["id"], hwid, ip, app["id"], selected_product_id, expires),
    )

    # ── Reset strikes on successful login ──
    await db.execute(
        "UPDATE licenses SET last_ip = ?, login_strikes = 0 WHERE id = ?",
        (ip, lic["id"]),
    )
    await db.commit()

    await log_action(db, "login", license_key=mask_license_key(license_key), app_id=app["id"],
                     ip=ip, hwid=hwid, details="Success")

    # ── Fetch non-secret variables only ──
    async with db.execute("SELECT name, value FROM variables WHERE is_secret = 0") as cur:
        var_rows = await cur.fetchall()
    variables = {r["name"]: r["value"] for r in var_rows}

    return enc_resp({
        "success":     True,
        "message":     "SUSPICIOUS_LOGIN" if suspicious else "OK",
        "token":       token,
        "expires_at":  expires,
        "license_key": license_key,
        "variables":   json.dumps(variables),
    }, secret, req.app_id)


# ─── /heartbeat ──────────────────────────────────────────────────────────────

@router.post("/heartbeat")
@limiter.limit("60/minute")
async def client_heartbeat(request: Request, req: EncryptedRequest,
                           db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException as e:
        await log_action(db, "heartbeat_fail", app_id=req.app_id, ip=ip, details=e.detail)
        raise

    secret = app["secret_key"]
    token  = payload.get("token", "")

    sess = await get_app_session(db, token, app["id"])

    if not sess or sess["expires_at"] < utcnow():
        if sess:
            await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            await db.commit()
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)
    if not await enforce_session_identity(db, payload, sess, app["id"], ip):
        return enc_resp({"success": False, "message": "SESSION_IDENTITY_MISMATCH"}, secret, req.app_id)
    authorization_failure = await enforce_active_authorization(db, sess, app, ip)
    if authorization_failure:
        return enc_resp({"success": False, "message": authorization_failure}, secret, req.app_id)

    # ── Per-app HWID ban check ──
    async with db.execute(
        "SELECT 1 FROM banned_hwids WHERE hwid = ? AND app_id = ?",
        (sess["hwid"], sess["app_id"]),
    ) as cur:
        if await cur.fetchone():
            await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            await db.commit()
            await log_action(db, "heartbeat_hwid_banned", app_id=req.app_id,
                             ip=ip, hwid=sess["hwid"])
            return enc_resp({"success": False, "message": "BANNED_HWID"}, secret, req.app_id)

    await db.execute(
        "UPDATE sessions SET last_heartbeat = ?, ip = ? WHERE token = ?",
        (utcnow(), ip, token),
    )
    await db.commit()
    return enc_resp({"success": True, "message": "OK"}, secret, req.app_id)


# ─── /logout ─────────────────────────────────────────────────────────────────

@router.post("/logout")
@limiter.limit("20/minute")
async def client_logout(request: Request, req: EncryptedRequest,
                        db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException as e:
        await log_action(db, "logout_fail", app_id=req.app_id, ip=ip, details=e.detail)
        raise

    secret = app["secret_key"]
    token  = payload.get("token", "")

    sess = await get_app_session(db, token, app["id"])

    if sess:
        if not await enforce_session_identity(db, payload, sess, app["id"], ip):
            return enc_resp({"success": False, "message": "SESSION_IDENTITY_MISMATCH"}, secret, req.app_id)
        await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await db.commit()
        async with db.execute("SELECT key FROM licenses WHERE id = ?", (sess["license_id"],)) as c:
            lic = await c.fetchone()
        await log_action(db, "logout", license_key=lic["key"] if lic else None,
                         app_id=app["id"], ip=ip)

    return enc_resp({"success": True, "message": "OK"}, secret, req.app_id)


# ─── /validate ───────────────────────────────────────────────────────────────

@router.post("/validate")
@limiter.limit("30/minute")
async def client_validate(request: Request, req: EncryptedRequest,
                          db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException:
        raise

    secret = app["secret_key"]
    token  = payload.get("token", "")

    sess = await get_app_session(db, token, app["id"])

    if not sess or sess["expires_at"] < utcnow():
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)
    if not await enforce_session_identity(db, payload, sess, app["id"], ip):
        return enc_resp({"success": False, "message": "SESSION_IDENTITY_MISMATCH"}, secret, req.app_id)
    authorization_failure = await enforce_active_authorization(db, sess, app, ip)
    if authorization_failure:
        return enc_resp({"success": False, "message": authorization_failure}, secret, req.app_id)

    return enc_resp({"success": True, "message": "OK",
                     "expires_at": sess["expires_at"]}, secret, req.app_id)


# ─── /download ───────────────────────────────────────────────────────────────

@router.post("/download")
@limiter.limit("10/minute")
async def client_download(request: Request, req: EncryptedRequest,
                          db: aiosqlite.Connection = Depends(get_db)):
    ip = get_ip(request)
    try:
        payload, app = await parse_request(req, db)
    except HTTPException as e:
        await log_action(db, "download_fail", app_id=req.app_id, ip=ip, details=e.detail)
        raise

    secret = app["secret_key"]
    token  = payload.get("token", "")
    name   = payload.get("name", "").strip()

    if not name:
        return enc_resp({"success": False, "message": "MISSING_FIELDS"}, secret, req.app_id)

    sess = await get_app_session(db, token, app["id"])

    if not sess or sess["expires_at"] < utcnow():
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)
    if not await enforce_session_identity(db, payload, sess, app["id"], ip):
        return enc_resp({"success": False, "message": "SESSION_IDENTITY_MISMATCH"}, secret, req.app_id)
    authorization_failure = await enforce_active_authorization(db, sess, app, ip)
    if authorization_failure:
        return enc_resp({"success": False, "message": authorization_failure}, secret, req.app_id)

    # Select only an active, currently available release for this application.
    async with db.execute(
        """SELECT f.* FROM app_files f
           WHERE f.app_id=? AND f.name=? AND f.is_active=1 AND f.is_archived=0
             AND (f.available_from IS NULL OR f.available_from<=CURRENT_TIMESTAMP)
             AND (f.available_until IS NULL OR f.available_until>CURRENT_TIMESTAMP)""",
        (app["id"], name),
    ) as cur:
        row = await cur.fetchone()

    if not row:
        return enc_resp({"success": False, "message": "FILE_NOT_FOUND"}, secret, req.app_id)

    async with db.execute("SELECT product_id FROM app_file_products WHERE file_id=?", (row["id"],)) as cur:
        allowed_products = {item["product_id"] for item in await cur.fetchall()}
    if allowed_products and sess["product_id"] not in allowed_products:
        await log_action(db, "download_denied", app_id=app["id"], ip=ip,
                         details=f"file={name}; product={sess['product_id']}")
        await db.commit()
        return enc_resp({"success": False, "message": "PRODUCT_NOT_AUTHORIZED"}, secret, req.app_id)
    if row["download_limit"]:
        async with db.execute(
            "SELECT COUNT(*) FROM file_download_events WHERE file_id=? AND license_id=?",
            (row["id"], sess["license_id"]),
        ) as cur:
            downloads = (await cur.fetchone())[0]
        if downloads >= row["download_limit"]:
            return enc_resp({"success": False, "message": "DOWNLOAD_LIMIT_REACHED"}, secret, req.app_id)

    download_secret = derive_session_download_secret(
        secret, token, sess["hwid"], row["id"]
    )
    content_b64 = encrypt_bytes(row["content"], download_secret)
    content_sha256 = row["file_sha256"] or hashlib.sha256(row["content"]).hexdigest()
    if not row["file_sha256"]:
        await db.execute("UPDATE app_files SET file_sha256=? WHERE id=?", (content_sha256, row["id"]))

    await db.execute(
        "INSERT INTO file_download_events(file_id,license_id,source,ip) VALUES(?,?,?,?)",
        (row["id"], sess["license_id"], "sdk", ip),
    )
    await db.commit()

    return enc_resp({
        "success": True,
        "message": "OK",
        "name":    name,
        "file_id": row["id"],
        "data":    content_b64,
        "encryption": "AES-256-GCM-SESSION-v1",
        "sha256":  content_sha256,
        "version": row["release_version"],
        "channel": row["channel"],
        "file_type": row["file_type"],
        "mandatory": bool(row["is_mandatory"]),
    }, secret, req.app_id)
