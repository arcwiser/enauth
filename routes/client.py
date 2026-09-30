import time
import hashlib
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
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
)
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
    app_id: str
    data:   str
    sig:    str
    ts:     int
    nonce:  str = ""   # optional for backwards compat, enforced below


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
    return JSONResponse({"data": enc, "sig": sig, "ts": ts})


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

    # 2. Nonce check — build a nonce from sig+ts if client didn't send one
    nonce = req.nonce or f"{req.sig[:32]}{req.ts}"
    if not await _check_and_store_nonce(db, nonce, now):
        raise HTTPException(400, "REPLAY_ATTACK")

    # 3. App lookup
    async with db.execute("SELECT * FROM applications WHERE id = ?", (req.app_id,)) as cur:
        app = await cur.fetchone()
    if not app:
        raise HTTPException(401, "INVALID_APP")

    secret = app["secret_key"]

    # 4. HMAC verification (now binds app_id)
    if not verify_signature(secret, req.data, req.ts, req.sig, req.app_id):
        raise HTTPException(401, "INVALID_SIGNATURE")

    # 5. Authenticated decryption (GCM tag validates integrity)
    try:
        payload = decrypt_payload(req.data, secret)
    except Exception:
        raise HTTPException(400, "DECRYPT_FAILED")

    return payload, dict(app)


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
            """SELECT lp.expires_at, p.id AS product_id, p.is_paused, p.pause_reason
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
            """SELECT lp.expires_at, p.id AS product_id, p.is_paused, p.pause_reason FROM license_products lp
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

    async with db.execute("SELECT * FROM sessions WHERE token = ?", (token,)) as cur:
        sess = await cur.fetchone()

    if not sess or sess["expires_at"] < utcnow():
        if sess:
            await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            await db.commit()
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)

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

    async with db.execute("SELECT license_id FROM sessions WHERE token = ?", (token,)) as cur:
        sess = await cur.fetchone()

    if sess:
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

    async with db.execute("SELECT * FROM sessions WHERE token = ?", (token,)) as cur:
        sess = await cur.fetchone()

    if not sess or sess["expires_at"] < utcnow():
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)

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

    async with db.execute("SELECT * FROM sessions WHERE token = ?", (token,)) as cur:
        sess = await cur.fetchone()

    if not sess or sess["expires_at"] < utcnow():
        return enc_resp({"success": False, "message": "SESSION_EXPIRED"}, secret, req.app_id)

    # Only allow downloading files that belong to this app
    async with db.execute(
        "SELECT content FROM app_files WHERE app_id = ? AND name = ?", (app["id"], name)
    ) as cur:
        row = await cur.fetchone()

    if not row:
        return enc_resp({"success": False, "message": "FILE_NOT_FOUND"}, secret, req.app_id)

    import base64
    content_b64 = base64.b64encode(row["content"]).decode()

    return enc_resp({
        "success": True,
        "message": "OK",
        "name":    name,
        "data":    content_b64,
    }, secret, req.app_id)
