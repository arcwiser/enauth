import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from database import get_db
from routes.admin import require_api_key
from utils.crypto import (generate_license_key, generate_uid, hash_license_key,
                          mask_license_key, encrypt_license_key, display_license_key)
from utils.logger import log_action
from utils.uploads import read_build_upload, validate_release_name, validate_release_version
from utils.request_security import resolve_client_ip

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def has_scope(key: dict, required: str) -> bool:
    """Evaluate both explicit permissions and the documented legacy scopes."""
    ranks = {"read": 1, "write": 2, "admin": 3}
    configured = {item.strip().lower() for item in str(key.get("scopes") or "read").split(",") if item.strip()}
    if configured & {"*", "admin"}:
        return True
    if required in ranks:
        return max((ranks.get(item, 0) for item in configured), default=0) >= ranks[required]
    resource, _, action = required.partition(".")
    if required in configured or f"{resource}.*" in configured:
        return True
    if action in {"read", "list"}:
        return bool(configured & {"read", "write"})
    # Revealing existing credentials always requires an explicit permission.
    return action != "reveal" and "write" in configured


def require_scope(required: str):

    async def dependency(request: Request,
                         x_api_key: Optional[str] = Header(None),
                         x_discord_key: Optional[str] = Header(None),
                         db: aiosqlite.Connection = Depends(get_db)):
        if x_discord_key:
            if len(x_discord_key) < 40 or not x_discord_key.startswith("enauth_discord_"):
                raise HTTPException(401, "Invalid Discord integration key")
            digest = hashlib.sha256(x_discord_key.encode("utf-8")).hexdigest()
            async with db.execute(
                """SELECT id,app_id FROM discord_integrations
                   WHERE key_hash=? AND is_active=1 LIMIT 1""", (digest,)
            ) as cur:
                row = await cur.fetchone()
            if not row:
                raise HTTPException(401, "Invalid or revoked Discord integration key")
            requested_app = request.path_params.get("app_id")
            if requested_app and requested_app != row["app_id"]:
                raise HTTPException(403, "Discord integration key is bound to another application")
            if not requested_app and not (
                request.method == "GET" and request.url.path.rstrip("/") == "/api/integrations/apps"
            ):
                raise HTTPException(403, "Discord integrations cannot access global resources")
            await db.execute("UPDATE discord_integrations SET last_used=CURRENT_TIMESTAMP WHERE id=?", (row["id"],))
            await db.commit()
            return {"id": row["id"], "role": "owner", "scopes": "*", "app_id": row["app_id"], "kind": "discord"}
        key = await require_api_key(x_api_key, db)
        if key.get("role") != "owner":
            raise HTTPException(403, "Owner API key required")
        requested_app = request.path_params.get("app_id")
        bound_app = key.get("app_id")
        if bound_app and requested_app and requested_app != bound_app:
            raise HTTPException(403, "API key is bound to another application")
        if bound_app and not requested_app and not (
            request.method == "GET" and request.url.path.rstrip("/") == "/api/integrations/apps"
        ):
            raise HTTPException(403, "App-bound API keys cannot access global resources")
        source_ip = resolve_client_ip(request.client.host if request.client else "unknown",
                                      request.headers.get("X-Forwarded-For"))
        if key.get("allowed_ips"):
            try:
                configured_networks = json.loads(key["allowed_ips"])
                source = ipaddress.ip_address(source_ip)
                if not isinstance(configured_networks, list) or not any(
                    source in ipaddress.ip_network(network, strict=False) for network in configured_networks
                ):
                    raise HTTPException(403, "API key is not allowed from this IP address")
            except HTTPException:
                raise
            except (ValueError, TypeError, json.JSONDecodeError):
                raise HTTPException(403, "API key IP policy is invalid")
        if not has_scope(key, required):
            raise HTTPException(403, f"API key requires {required} scope")
        await db.execute(
            "UPDATE api_keys SET usage_count=usage_count+1,last_ip=? WHERE id=?",
            (source_ip, key["id"]),
        )
        await db.commit()
        return key

    return dependency


async def require_app(db: aiosqlite.Connection, app_id: str):
    async with db.execute(
        "SELECT id, name, version, is_paused, pause_reason FROM applications WHERE id = ?", (app_id,)
    ) as cur:
        app = await cur.fetchone()
    if not app:
        raise HTTPException(404, "Application not found")
    return dict(app)


async def find_license(db: aiosqlite.Connection, app_id: str, identifier: str):
    identifier = identifier.strip()
    digest = hash_license_key(identifier)
    async with db.execute(
        """SELECT * FROM licenses
           WHERE app_id = ? AND (id = ? OR key_hash = ?)
           LIMIT 1""",
        (app_id, identifier, digest),
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "License not found")
    result = dict(row)
    result["key"] = display_license_key(result["key"], result.get("key_ciphertext"))
    result.pop("key_ciphertext", None)
    return result


class GenerateBody(BaseModel):
    product_level: str = Field(min_length=1, max_length=64)
    duration_hours: Optional[float] = Field(default=None, gt=0, le=876000)
    notes: Optional[str] = Field(default=None, max_length=500)
    count: int = Field(default=1, ge=1, le=500)
    max_hwids: int = Field(default=1, ge=1, le=100)


class ExtendBody(BaseModel):
    hours: float = Field(gt=0, le=876000)


class PauseBody(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class ResumeBody(BaseModel):
    compensation_hours: float = Field(default=0, ge=0, le=876000)


class EntitlementAddBody(BaseModel):
    product_id: str = Field(min_length=1, max_length=100)
    duration_hours: Optional[float] = Field(default=None, gt=0, le=876000)


class CreditResellerBody(BaseModel):
    amount: float = Field(gt=0, le=100000000)
    reason: Optional[str] = Field(default=None, max_length=500)


class NamedValueBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    value: str = Field(max_length=4000)
    is_secret: bool = False


class NewsBody(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=4000)


class HwidBody(BaseModel):
    hwid: str = Field(min_length=32, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=500)


class ProductStatusBody(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    color: str = Field(pattern=r"^#[0-9A-Fa-f]{6}$")
    message: Optional[str] = Field(default=None, max_length=300)


@router.get("/apps")
async def apps(_key=Depends(require_scope("apps.read")), db=Depends(get_db)):
    async with db.execute(
        "SELECT id, name, version FROM applications WHERE (? IS NULL OR id=?) ORDER BY name LIMIT 200",
        (_key.get("app_id"), _key.get("app_id")),
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.get("/apps/{app_id}")
async def app_details(app_id: str, _key=Depends(require_scope("apps.read")), db=Depends(get_db)):
    app = await require_app(db, app_id)
    async with db.execute(
        """SELECT id, name, level, is_active, service_status, status_color, status_message,
                  is_paused, paused_at, pause_reason
           FROM products WHERE app_id = ? ORDER BY name""",
        (app_id,),
    ) as cur:
        app["products"] = [dict(row) for row in await cur.fetchall()]
    return app


@router.get("/apps/{app_id}/capabilities")
async def integration_capabilities(app_id: str, key=Depends(require_scope("apps.read")), db=Depends(get_db)):
    """Describe what the presented credential may do without exposing the credential itself."""
    await require_app(db, app_id)
    known = ["apps.read", "apps.modify", "licenses.read", "licenses.generate", "licenses.modify",
             "licenses.reveal", "licenses.delete", "logs.read", "builds.read", "builds.upload", "builds.delete"]
    return {
        "app_id": app_id,
        "credential_kind": key.get("kind", "api_key"),
        "configured_scopes": [item.strip() for item in str(key.get("scopes") or "read").split(",") if item.strip()],
        "capabilities": {scope: has_scope(key, scope) for scope in known},
        "limits": {"max_list_size": 50, "max_bulk_generation": 500,
                   "max_upload_bytes": int(os.getenv("MAX_BUILD_UPLOAD_BYTES", str(100 * 1024 * 1024)))},
    }


@router.get("/apps/{app_id}/operations")
async def app_operations(app_id: str, _key=Depends(require_scope("apps.read")), db=Depends(get_db)):
    """A secret-free operational snapshot suitable for Discord and monitoring integrations."""
    app = await require_app(db, app_id)
    async with db.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
                  SUM(CASE WHEN status='banned' THEN 1 ELSE 0 END) AS banned,
                  SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) AS expired
           FROM licenses WHERE app_id=?""", (app_id,),
    ) as cur:
        licenses = dict(await cur.fetchone())
    async with db.execute(
        """SELECT COUNT(*) AS active_sessions,COUNT(DISTINCT license_id) AS active_users
           FROM sessions WHERE app_id=? AND expires_at>CURRENT_TIMESTAMP""", (app_id,),
    ) as cur:
        sessions = dict(await cur.fetchone())
    async with db.execute(
        """SELECT COUNT(*) AS authentications,
                  SUM(CASE WHEN action LIKE '%fail%' OR action LIKE '%blocked%' THEN 1 ELSE 0 END) AS failures
           FROM logs WHERE app_id=? AND timestamp>=datetime('now','-24 hours')""", (app_id,),
    ) as cur:
        activity = dict(await cur.fetchone())
    async with db.execute(
        """SELECT sdk_version,COUNT(*) AS sessions FROM sessions
           WHERE app_id=? AND expires_at>CURRENT_TIMESTAMP
           GROUP BY sdk_version ORDER BY sessions DESC LIMIT 10""", (app_id,),
    ) as cur:
        sdk_usage = [dict(row) for row in await cur.fetchall()]
    async with db.execute("SELECT * FROM sdk_compatibility WHERE app_id=?", (app_id,)) as cur:
        compatibility = await cur.fetchone()
    return {"app": app, "licenses": licenses, "sessions": sessions, "activity_24h": activity,
            "sdk_usage": sdk_usage, "sdk_policy": dict(compatibility) if compatibility else None}


@router.get("/apps/{app_id}/expiring")
async def app_expiring(app_id: str, days: int = 7, limit: int = 25,
                       _key=Depends(require_scope("licenses.read")), db=Depends(get_db)):
    await require_app(db, app_id)
    days, limit = max(1, min(days, 365)), max(1, min(limit, 50))
    async with db.execute(
        """SELECT l.id AS license_id,l.key,l.client_username,p.name AS product,p.level,lp.expires_at
           FROM license_products lp JOIN licenses l ON l.id=lp.license_id
           JOIN products p ON p.id=lp.product_id
           WHERE l.app_id=? AND l.status='active' AND lp.expires_at IS NOT NULL
             AND lp.expires_at>CURRENT_TIMESTAMP AND lp.expires_at<=datetime('now', ?)
           ORDER BY lp.expires_at LIMIT ?""", (app_id, f"+{days} days", limit),
    ) as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    for row in rows:
        row["key"] = mask_license_key(row["key"])
    return {"days": days, "items": rows}


@router.get("/apps/{app_id}/security-summary")
async def app_security_summary(app_id: str, _key=Depends(require_scope("logs.read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        """SELECT action,COUNT(*) AS count FROM logs WHERE app_id=?
           AND timestamp>=datetime('now','-24 hours')
           AND (action LIKE '%fail%' OR action LIKE '%blocked%' OR action LIKE '%replay%' OR action LIKE '%ban%')
           GROUP BY action ORDER BY count DESC LIMIT 10""", (app_id,),
    ) as cur:
        events = [dict(row) for row in await cur.fetchall()]
    async with db.execute(
        """SELECT COUNT(*) FROM device_fingerprints d JOIN licenses l ON l.id=d.license_id
           WHERE l.app_id=? AND d.is_suspicious=1""", (app_id,),
    ) as cur:
        suspicious_devices = (await cur.fetchone())[0]
    async with db.execute("SELECT COUNT(*) FROM banned_hwids WHERE app_id=?", (app_id,)) as cur:
        banned_hwids = (await cur.fetchone())[0]
    return {"window_hours": 24, "events": events, "suspicious_devices": suspicious_devices,
            "banned_hwids": banned_hwids}


@router.put("/apps/{app_id}/products/{product_id}/status")
async def integration_product_status(app_id: str, product_id: str, body: ProductStatusBody,
                                     key=Depends(require_scope("apps.modify")), db=Depends(get_db)):
    async with db.execute("SELECT name FROM products WHERE id=? AND app_id=?", (product_id, app_id)) as cur:
        product = await cur.fetchone()
    if not product:
        raise HTTPException(404, "Product not found for this application")
    status = body.status.strip().lower().replace(" ", "-")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", status):
        raise HTTPException(400, "Status may contain letters, numbers, dashes, and underscores")
    await db.execute(
        "UPDATE products SET service_status=?,status_color=?,status_message=? WHERE id=? AND app_id=?",
        (status, body.color.lower(), (body.message or "").strip() or None, product_id, app_id),
    )
    await log_action(db, "integration_product_status", app_id=app_id,
                     details=f"product={product_id}; status={status}; integration={key['id']}")
    await db.commit()
    return {"ok": True, "product": product["name"], "status": status, "color": body.color.lower()}


@router.get("/apps/{app_id}/hwid-reset-requests")
async def integration_reset_requests(app_id: str, status: str = "pending",
                                     _key=Depends(require_scope("licenses.read")), db=Depends(get_db)):
    await require_app(db, app_id)
    if status not in {"pending", "approved", "rejected", "all"}:
        raise HTTPException(400, "Invalid request status")
    sql = """SELECT r.id,r.reason,r.status,r.created_at,r.reviewed_at,
                    l.id AS license_id,l.key,l.client_username
             FROM hwid_reset_requests r JOIN licenses l ON l.id=r.license_id
             WHERE l.app_id=?"""
    args = [app_id]
    if status != "all":
        sql += " AND r.status=?"; args.append(status)
    sql += " ORDER BY r.created_at DESC LIMIT 50"
    async with db.execute(sql, args) as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    for row in rows:
        row["key"] = mask_license_key(row["key"])
    return rows


@router.post("/apps/{app_id}/hwid-reset-requests/{request_id}/{decision}")
async def integration_review_reset(app_id: str, request_id: str, decision: str,
                                   key=Depends(require_scope("licenses.modify")), db=Depends(get_db)):
    await require_app(db, app_id)
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "Decision must be approve or reject")
    async with db.execute(
        """SELECT r.license_id FROM hwid_reset_requests r JOIN licenses l ON l.id=r.license_id
           WHERE r.id=? AND r.status='pending' AND l.app_id=?""", (request_id, app_id),
    ) as cur:
        request_row = await cur.fetchone()
    if not request_row:
        raise HTTPException(404, "Pending reset request not found")
    await db.execute("BEGIN IMMEDIATE")
    try:
        if decision == "approve":
            await db.execute("DELETE FROM hwids WHERE license_id=?", (request_row["license_id"],))
            await db.execute("DELETE FROM device_fingerprints WHERE license_id=?", (request_row["license_id"],))
            await db.execute("DELETE FROM sessions WHERE license_id=?", (request_row["license_id"],))
            await db.execute("UPDATE licenses SET hwid_reset_at=CURRENT_TIMESTAMP WHERE id=?", (request_row["license_id"],))
        await db.execute(
            """UPDATE hwid_reset_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP
               WHERE id=? AND status='pending'""",
            ("approved" if decision == "approve" else "rejected", f"integration:{key['id']}", request_id),
        )
        await log_action(db, f"integration_hwid_request_{decision}d", app_id=app_id,
                         details=f"request={request_id}; integration={key['id']}")
        await db.commit()
    except Exception:
        await db.rollback(); raise
    return {"ok": True, "status": "approved" if decision == "approve" else "rejected"}


@router.get("/apps/{app_id}/licenses")
async def licenses(app_id: str, search: Optional[str] = None, limit: int = 25,
                   _key=Depends(require_scope("licenses.read")), db=Depends(get_db)):
    await require_app(db, app_id)
    limit = max(1, min(limit, 50))
    sql = "SELECT id, key, key_ciphertext, status, expires_at, max_hwids, notes, created_at FROM licenses WHERE app_id = ?"
    args = [app_id]
    if search:
        sql += " AND (id = ? OR key_hash = ? OR notes LIKE ?)"
        args.extend([search, hash_license_key(search), f"%{search}%"])
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    async with db.execute(sql, args) as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    for row in rows:
        row["key"] = (display_license_key(row["key"], row.get("key_ciphertext"))
                      if has_scope(_key, "licenses.reveal") else mask_license_key(row["key"]))
        row.pop("key_ciphertext", None)
    return rows


@router.post("/apps/{app_id}/licenses")
async def generate(app_id: str, body: GenerateBody, key=Depends(require_scope("licenses.generate")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        "SELECT id, name, level FROM products WHERE app_id = ? AND level = ? AND is_active = 1",
        (app_id, body.product_level),
    ) as cur:
        product = await cur.fetchone()
    if not product:
        raise HTTPException(404, "Active product level not found")

    expires_at = None
    if body.duration_hours is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=body.duration_hours)).strftime("%Y-%m-%d %H:%M:%S")

    created = []
    for _ in range(body.count):
        raw_key = generate_license_key()
        license_id = generate_uid()
        await db.execute(
            """INSERT INTO licenses
               (id, key, key_hash, key_ciphertext, app_id, max_hwids, expires_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (license_id, mask_license_key(raw_key), hash_license_key(raw_key), encrypt_license_key(raw_key), app_id,
             body.max_hwids, expires_at, body.notes),
        )
        await db.execute(
            "INSERT INTO license_products (id, license_id, product_id, expires_at) VALUES (?, ?, ?, ?)",
            (generate_uid(), license_id, product["id"], expires_at),
        )
        await log_action(db, "integration_generated", app_id=app_id,
                         license_key=mask_license_key(raw_key),
                         details=f"Level {product['level']}; API key {key['id']}")
        created.append({"id": license_id, "key": raw_key, "expires_at": expires_at})
    await log_action(db, "integration_generate", app_id=app_id,
                     details=f"Generated {body.count} key(s) through API key {key['id']}")
    await db.commit()
    return {"created": created, "level": product["level"]}


async def set_license_state(app_id: str, identifier: str, state: str, key: dict, db):
    license_row = await find_license(db, app_id, identifier)
    await db.execute("UPDATE licenses SET status = ? WHERE id = ?", (state, license_row["id"]))
    if state == "banned":
        await db.execute("DELETE FROM sessions WHERE license_id = ?", (license_row["id"],))
    await log_action(db, f"integration_{state}", app_id=app_id,
                     license_key=mask_license_key(license_row["key"]), details=f"API key {key['id']}")
    await db.commit()
    return {"ok": True, "id": license_row["id"], "status": state}


@router.post("/apps/{app_id}/licenses/{identifier}/ban")
async def ban(app_id: str, identifier: str, key=Depends(require_scope("write")), db=Depends(get_db)):
    return await set_license_state(app_id, identifier, "banned", key, db)


@router.post("/apps/{app_id}/licenses/{identifier}/unban")
async def unban(app_id: str, identifier: str, key=Depends(require_scope("write")), db=Depends(get_db)):
    return await set_license_state(app_id, identifier, "active", key, db)


@router.post("/apps/{app_id}/licenses/{identifier}/reset-hwid")
async def reset_hwid(app_id: str, identifier: str, key=Depends(require_scope("write")), db=Depends(get_db)):
    license_row = await find_license(db, app_id, identifier)
    await db.execute("DELETE FROM hwids WHERE license_id = ?", (license_row["id"],))
    await db.execute("DELETE FROM sessions WHERE license_id = ?", (license_row["id"],))
    await db.execute("UPDATE licenses SET hwid_reset_at = CURRENT_TIMESTAMP WHERE id = ?", (license_row["id"],))
    await log_action(db, "integration_reset_hwid", app_id=app_id,
                     license_key=mask_license_key(license_row["key"]), details=f"API key {key['id']}")
    await db.commit()
    return {"ok": True, "id": license_row["id"]}


@router.get("/apps/{app_id}/logs")
async def logs(app_id: str, limit: int = 20, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        """SELECT action, license_key, ip, details, timestamp FROM logs
           WHERE app_id = ? ORDER BY timestamp DESC LIMIT ?""",
        (app_id, max(1, min(limit, 50))),
    ) as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    if not has_scope(_key, "licenses.reveal"):
        for row in rows:
            if row["license_key"]:
                row["license_key"] = mask_license_key(row["license_key"])
    return rows


@router.post("/apps/{app_id}/builds")
async def upload_build(app_id: str, name: str = Form(...), file: UploadFile = File(...),
                       product_ids: Optional[str] = Form(None),
                       release_version: str = Form("1.0.0"),
                       channel: str = Form("stable"), file_type: str = Form("payload"),
                       platform: str = Form("windows"), architecture: str = Form("x64"),
                       release_notes: Optional[str] = Form(None), portal_visible: bool = Form(False),
                       is_mandatory: bool = Form(False), auto_replace: bool = Form(False),
                       key=Depends(require_scope("builds.upload")), db=Depends(get_db)):
    await require_app(db, app_id)
    safe_name = validate_release_name(name)
    release_version = validate_release_version(release_version)
    allowed_channels = {"stable", "beta", "nightly", "private"}
    allowed_types = {"loader", "payload", "update", "config", "symbols", "documentation"}
    allowed_platforms = {"windows", "linux", "macos", "any"}
    allowed_architectures = {"x64", "x86", "arm64", "any"}
    if channel not in allowed_channels or file_type not in allowed_types:
        raise HTTPException(400, "Invalid release channel or file type")
    if platform not in allowed_platforms or architecture not in allowed_architectures:
        raise HTTPException(400, "Invalid platform or architecture")
    selected_products = list(dict.fromkeys(x.strip() for x in (product_ids or "").split(",") if x.strip()))
    if len(selected_products) > 25:
        raise HTTPException(400, "A release can target at most 25 products")
    for product_id in selected_products:
        async with db.execute("SELECT 1 FROM products WHERE id=? AND app_id=?", (product_id, app_id)) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, f"Product not found for this application: {product_id}")
    content = await read_build_upload(file)
    if file_type == "loader" and platform == "windows":
        if not safe_name.lower().endswith(".exe") or not content.startswith(b"MZ"):
            raise HTTPException(400, "Windows loaders must be .exe files")
    file_id = generate_uid()
    digest = hashlib.sha256(content).hexdigest()
    async with db.execute(
        "SELECT id,file_type,release_version FROM app_files WHERE app_id=? AND name=?", (app_id, safe_name)
    ) as cur:
        previous = await cur.fetchone()
    if previous and not auto_replace:
        raise HTTPException(409, "An active build with this name exists; enable auto replace")
    if previous:
        if previous["file_type"] != file_type:
            raise HTTPException(409, "Cannot replace a different file type")
        if previous["release_version"] == release_version:
            raise HTTPException(409, "Publish a new version when replacing a build")
        archived_name = f"{safe_name}.archived.{previous['id']}"
        await db.execute(
            "UPDATE app_files SET name=?, is_active=0, is_archived=1 WHERE id=?",
            (archived_name, previous["id"]),
        )
    await db.execute(
        """INSERT INTO app_files
           (id,app_id,name,content,file_sha256,is_secret,portal_visible,product_id,
            release_version,channel,file_type,platform,architecture,release_notes,mime_type,file_size,
            is_active,is_archived,is_mandatory,replaced_file_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?,?)""",
        (file_id, app_id, safe_name, content, digest, 1 if file_type == "payload" else 0,
         1 if portal_visible else 0, selected_products[0] if len(selected_products) == 1 else None,
         release_version.strip(), channel, file_type, platform, architecture,
         (release_notes or "").strip() or None, file.content_type, len(content),
         1 if is_mandatory else 0, previous["id"] if previous else None),
    )
    for product_id in selected_products:
        await db.execute("INSERT INTO app_file_products(file_id,product_id) VALUES(?,?)", (file_id, product_id))
    await log_action(db, "integration_upload_build", app_id=app_id,
                     details=f"Uploaded {safe_name} ({digest[:16]}) via API key {key['id']}")
    await db.commit()
    async with db.execute("SELECT id FROM app_files WHERE app_id = ? AND name = ?", (app_id, safe_name)) as cur:
        stored = await cur.fetchone()
    return {"ok": True, "id": stored["id"], "name": safe_name, "size": len(content),
            "sha256": digest, "version": release_version, "channel": channel,
            "file_type": file_type, "products": selected_products,
            "replaced_file_id": previous["id"] if previous else None}


@router.get("/apps/{app_id}/stats")
async def stats(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    result = {}
    for name, sql in {
        "licenses": "SELECT COUNT(*) FROM licenses WHERE app_id = ?",
        "active_licenses": "SELECT COUNT(*) FROM licenses WHERE app_id = ? AND status = 'active'",
        "active_sessions": "SELECT COUNT(*) FROM sessions WHERE app_id = ? AND expires_at > CURRENT_TIMESTAMP",
        "banned_hwids": "SELECT COUNT(*) FROM banned_hwids WHERE app_id = ?",
        "builds": "SELECT COUNT(*) FROM app_files WHERE app_id = ?",
    }.items():
        async with db.execute(sql, (app_id,)) as cur:
            result[name] = (await cur.fetchone())[0]
    return result


@router.get("/apps/{app_id}/licenses/{identifier}")
async def license_details(app_id: str, identifier: str, _key=Depends(require_scope("licenses.reveal")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    item.pop("key_hash", None)
    async with db.execute("SELECT hwid_hash, first_seen, last_seen FROM hwids WHERE license_id = ?", (item["id"],)) as cur:
        item["hwids"] = [dict(row) for row in await cur.fetchall()]
    async with db.execute(
        """SELECT lp.product_id, p.name, p.level, lp.expires_at, lp.is_paused,
                  lp.paused_at, lp.pause_reason, lp.total_compensation_seconds
           FROM license_products lp JOIN products p ON p.id = lp.product_id
           WHERE lp.license_id = ? ORDER BY p.name""",
        (item["id"],),
    ) as cur:
        item["products"] = [dict(row) for row in await cur.fetchall()]
    return item


@router.get("/apps/{app_id}/licenses/{identifier}/history")
async def license_history(app_id: str, identifier: str, limit: int = 50,
                          _key=Depends(require_scope("licenses.read")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    async with db.execute(
        """SELECT action, ip, hwid, details, timestamp FROM logs
           WHERE app_id = ? AND license_key IN (?, ?)
           ORDER BY timestamp DESC LIMIT ?""",
        (app_id, item["key"], mask_license_key(item["key"]), max(1, min(limit, 100))),
    ) as cur:
        events = [dict(row) for row in await cur.fetchall()]
    visible_key = item["key"] if has_scope(_key, "licenses.reveal") else mask_license_key(item["key"])
    return {"license_id": item["id"], "key": visible_key, "events": events}


@router.post("/apps/{app_id}/licenses/{identifier}/products")
async def add_license_product(app_id: str, identifier: str, body: EntitlementAddBody,
                              key=Depends(require_scope("admin")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    async with db.execute(
        "SELECT id, name, level FROM products WHERE id = ? AND app_id = ? AND is_active = 1",
        (body.product_id, app_id),
    ) as cur:
        product = await cur.fetchone()
    if not product:
        raise HTTPException(404, "Active product not found for this application")
    expires_at = None
    if body.duration_hours is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=body.duration_hours)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        await db.execute(
            "INSERT INTO license_products(id, license_id, product_id, expires_at) VALUES(?, ?, ?, ?)",
            (generate_uid(), item["id"], body.product_id, expires_at),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "License already owns this product")
    await log_action(db, "integration_entitlement_added", app_id=app_id, license_key=mask_license_key(item["key"]),
                     details=f"{product['level']} via API key {key['id']}")
    await db.commit()
    return {"ok": True, "license_id": item["id"], "product_id": product["id"],
            "product": product["name"], "expires_at": expires_at}


@router.post("/apps/{app_id}/products/{product_id}/licenses/{identifier}/extend")
async def extend_product_license(app_id: str, product_id: str, identifier: str, body: ExtendBody,
                                 key=Depends(require_scope("admin")), db=Depends(get_db)):
    async with db.execute("SELECT id, name, level FROM products WHERE id = ? AND app_id = ?", (product_id, app_id)) as cur:
        product = await cur.fetchone()
    if not product:
        raise HTTPException(404, "Product not found for this application")
    seconds = int(body.hours * 3600)
    if identifier.lower() == "all":
        cursor = await db.execute(
            """UPDATE license_products SET expires_at=datetime(
                   CASE WHEN expires_at < CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP ELSE expires_at END, ?)
               WHERE product_id = ? AND expires_at IS NOT NULL""",
            (f"+{seconds} seconds", product_id),
        )
        affected = cursor.rowcount
        async with db.execute(
            """SELECT l.key FROM licenses l JOIN license_products lp ON lp.license_id=l.id
               WHERE lp.product_id=? AND lp.expires_at IS NOT NULL""", (product_id,)
        ) as cur:
            extended_licenses = await cur.fetchall()
        for row in extended_licenses:
            await log_action(db, "integration_product_extended", app_id=app_id,
                             license_key=row["key"],
                             details=f"{product['level']}; extended={seconds}s; bulk; API key {key['id']}")
        await db.commit()
        return {"ok": True, "affected": affected, "product": product["name"]}
    item = await find_license(db, app_id, identifier)
    cursor = await db.execute(
        """UPDATE license_products SET expires_at=datetime(
               CASE WHEN expires_at < CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP ELSE expires_at END, ?)
           WHERE license_id = ? AND product_id = ? AND expires_at IS NOT NULL""",
        (f"+{seconds} seconds", item["id"], product_id),
    )
    if cursor.rowcount == 0:
        raise HTTPException(409, "Entitlement not found or is lifetime")
    await log_action(db, "integration_entitlement_extended", app_id=app_id, license_key=mask_license_key(item["key"]),
                     details=f"{product['level']}; extended={seconds}s; API key {key['id']}")
    await db.commit()
    return {"ok": True, "affected": 1, "product": product["name"]}


@router.post("/apps/{app_id}/licenses/{identifier}/extend")
async def extend(app_id: str, identifier: str, body: ExtendBody,
                 key=Depends(require_scope("write")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    base = datetime.now(timezone.utc)
    if item["expires_at"]:
        current = datetime.strptime(item["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        base = max(base, current)
    expires_at = (base + timedelta(hours=body.hours)).strftime("%Y-%m-%d %H:%M:%S")
    await db.execute("UPDATE licenses SET expires_at = ? WHERE id = ?", (expires_at, item["id"]))
    await db.execute("UPDATE license_products SET expires_at = ? WHERE license_id = ?",
                     (expires_at, item["id"]))
    await log_action(db, "integration_extend", app_id=app_id, license_key=mask_license_key(item["key"]),
                     details=f"Extended through API key {key['id']}")
    await db.commit()
    return {"ok": True, "expires_at": expires_at}


@router.delete("/apps/{app_id}/licenses/{identifier}")
async def delete_license(app_id: str, identifier: str, _key=Depends(require_scope("licenses.delete")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    await log_action(db, "integration_deleted", app_id=app_id,
                     license_key=mask_license_key(item["key"]), details=f"License {item['id']} deleted")
    await db.execute("DELETE FROM licenses WHERE id = ?", (item["id"],))
    await db.commit()
    return {"ok": True}


@router.get("/apps/{app_id}/sessions")
async def sessions(app_id: str, limit: int = 25, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        """SELECT s.id, s.ip, s.hwid, s.last_heartbeat, s.expires_at, l.key AS license_key
           FROM sessions s JOIN licenses l ON l.id = s.license_id
           WHERE s.app_id = ? ORDER BY s.last_heartbeat DESC LIMIT ?""",
        (app_id, max(1, min(limit, 50))),
    ) as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    if not has_scope(_key, "licenses.reveal"):
        for row in rows:
            row["license_key"] = mask_license_key(row["license_key"])
    return rows


@router.delete("/apps/{app_id}/sessions/{session_id}")
async def kill_session(app_id: str, session_id: str, _key=Depends(require_scope("write")), db=Depends(get_db)):
    cursor = await db.execute("DELETE FROM sessions WHERE id = ? AND app_id = ?", (session_id, app_id))
    await db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(404, "Session not found")
    return {"ok": True}


@router.delete("/apps/{app_id}/sessions")
async def kill_all_sessions(app_id: str, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    await require_app(db, app_id)
    cursor = await db.execute("DELETE FROM sessions WHERE app_id = ?", (app_id,))
    await db.commit()
    return {"ok": True, "deleted": cursor.rowcount}


@router.post("/apps/{app_id}/pause")
async def pause_app(app_id: str, body: PauseBody, key=Depends(require_scope("apps.modify")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute("SELECT is_paused, paused_at FROM applications WHERE id = ?", (app_id,)) as cur:
        state = await cur.fetchone()
    if state["is_paused"]:
        return {"ok": True, "already_paused": True, "paused_at": state["paused_at"]}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    reason = (body.reason or "Application outage").strip()
    async with db.execute("SELECT COUNT(*) FROM licenses WHERE app_id=?", (app_id,)) as cur:
        affected = (await cur.fetchone())[0]
    await db.execute("UPDATE applications SET is_paused=1, paused_at=?, pause_reason=? WHERE id=?", (now, reason, app_id))
    await db.execute(
        """INSERT INTO outage_events(id,app_id,event_type,service_status,status_color,public_message,started_at,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?)""",
        (generate_uid(), app_id, "started", "offline", "#ef4444", reason, now, affected),
    )
    await db.execute("DELETE FROM sessions WHERE app_id=?", (app_id,))
    await log_action(db, "integration_app_paused", app_id=app_id,
                     details=f"{reason}; API key {key['id']}")
    await db.commit()
    return {"ok": True, "paused_at": now}


@router.get("/apps/{app_id}/resume-preview")
async def resume_app_preview(app_id: str, compensation_hours: float = 0,
                             _key=Depends(require_scope("admin")), db=Depends(get_db)):
    if compensation_hours < 0 or compensation_hours > 876000:
        raise HTTPException(400, "Invalid compensation")
    async with db.execute("SELECT is_paused, paused_at FROM applications WHERE id = ?", (app_id,)) as cur:
        state = await cur.fetchone()
    if not state or not state["is_paused"] or not state["paused_at"]:
        raise HTTPException(409, "Application is not paused")
    paused_at = datetime.strptime(state["paused_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    downtime = max(0, int((datetime.now(timezone.utc) - paused_at).total_seconds()))
    async with db.execute(
        """SELECT COUNT(DISTINCT l.id) total,
                  COUNT(DISTINCT CASE WHEN lp.expires_at IS NOT NULL THEN l.id END) expiring
           FROM licenses l LEFT JOIN license_products lp ON lp.license_id=l.id WHERE l.app_id=?""",
        (app_id,),
    ) as cur:
        counts = await cur.fetchone()
    extra = int(compensation_hours * 3600)
    return {"affected_licenses": counts["total"], "expiring_licenses": counts["expiring"],
            "downtime_seconds": downtime, "compensation_seconds": extra,
            "extended_by_seconds": downtime + extra}


@router.post("/apps/{app_id}/resume")
async def resume_app(app_id: str, body: ResumeBody, key=Depends(require_scope("admin")), db=Depends(get_db)):
    preview = await resume_app_preview(app_id, body.compensation_hours, key, db)
    async with db.execute("SELECT paused_at FROM applications WHERE id=?", (app_id,)) as cur:
        paused_at = (await cur.fetchone())["paused_at"]
    seconds = preview["extended_by_seconds"]
    await db.execute(
        "UPDATE licenses SET expires_at=datetime(expires_at, ?) WHERE app_id=? AND expires_at IS NOT NULL",
        (f"+{seconds} seconds", app_id),
    )
    await db.execute(
        """UPDATE license_products SET expires_at=datetime(expires_at, ?),
                  total_compensation_seconds=total_compensation_seconds+?
           WHERE expires_at IS NOT NULL AND product_id IN (SELECT id FROM products WHERE app_id=?)""",
        (f"+{seconds} seconds", preview["compensation_seconds"], app_id),
    )
    await db.execute("UPDATE applications SET is_paused=0, paused_at=NULL, pause_reason=NULL WHERE id=?", (app_id,))
    await db.execute(
        """INSERT INTO outage_events(id,app_id,event_type,service_status,public_message,started_at,ended_at,
                  downtime_seconds,compensation_seconds,affected_licenses)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (generate_uid(), app_id, "resolved", "operational", "Service restored", paused_at,
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), preview["downtime_seconds"],
         preview["compensation_seconds"], preview["affected_licenses"]),
    )
    async with db.execute("SELECT key FROM licenses WHERE app_id=?", (app_id,)) as cur:
        compensated_licenses = await cur.fetchall()
    for row in compensated_licenses:
        await log_action(db, "integration_compensation", app_id=app_id, license_key=row["key"],
                         details=f"downtime={preview['downtime_seconds']}s; extra={preview['compensation_seconds']}s")
    await log_action(db, "integration_app_resumed", app_id=app_id,
                     details=f"affected={preview['affected_licenses']}; extended={seconds}s; API key {key['id']}")
    await db.commit()
    return {"ok": True, **preview}


@router.get("/resellers")
async def resellers(key=Depends(require_scope("resellers.read")), db=Depends(get_db)):
    if key.get("kind") == "discord":
        raise HTTPException(403, "Discord integrations cannot access reseller accounts")
    async with db.execute(
        "SELECT id, username, balance, is_active, created_at FROM resellers ORDER BY username LIMIT 200"
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.post("/resellers/{reseller_id}/credit")
async def credit_reseller(reseller_id: str, body: CreditResellerBody,
                          key=Depends(require_scope("resellers.credit")), db=Depends(get_db)):
    if key.get("kind") == "discord":
        raise HTTPException(403, "Discord integrations cannot access reseller accounts")
    cursor = await db.execute("UPDATE resellers SET balance=balance+? WHERE id=?", (body.amount, reseller_id))
    if cursor.rowcount == 0:
        raise HTTPException(404, "Reseller not found")
    reason = (body.reason or "Discord bot credit").strip()
    await db.execute(
        "INSERT INTO reseller_balance_ledger(id, reseller_id, amount, reason, created_by) VALUES(?, ?, ?, ?, ?)",
        (generate_uid(), reseller_id, body.amount, reason, f"api:{key['id']}"),
    )
    async with db.execute("SELECT balance FROM resellers WHERE id=?", (reseller_id,)) as cur:
        balance = (await cur.fetchone())["balance"]
    await log_action(db, "integration_reseller_credit",
                     details=f"reseller={reseller_id}; amount={body.amount}; API key {key['id']}")
    await db.commit()
    return {"ok": True, "balance": balance}


@router.get("/apps/{app_id}/builds")
async def builds(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        """SELECT id,name,release_version,channel,file_type,platform,architecture,file_size,file_sha256,
                  is_active,is_archived,portal_visible,created_at
           FROM app_files WHERE app_id = ? ORDER BY created_at DESC""",
        (app_id,),
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.delete("/apps/{app_id}/builds/{file_id}")
async def delete_build(app_id: str, file_id: str, _key=Depends(require_scope("builds.delete")), db=Depends(get_db)):
    cursor = await db.execute("DELETE FROM app_files WHERE id = ? AND app_id = ?", (file_id, app_id))
    await db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(404, "Build not found")
    return {"ok": True}


@router.get("/apps/{app_id}/news")
async def news(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute("SELECT * FROM news WHERE app_id = ? ORDER BY created_at DESC LIMIT 25", (app_id,)) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.post("/apps/{app_id}/news")
async def add_news(app_id: str, body: NewsBody, _key=Depends(require_scope("write")), db=Depends(get_db)):
    await require_app(db, app_id)
    item_id = generate_uid()
    await db.execute("INSERT INTO news (id, app_id, title, content) VALUES (?, ?, ?, ?)",
                     (item_id, app_id, body.title, body.content))
    await db.commit()
    return {"ok": True, "id": item_id}


@router.delete("/apps/{app_id}/news/{news_id}")
async def delete_news(app_id: str, news_id: str, _key=Depends(require_scope("write")), db=Depends(get_db)):
    cursor = await db.execute("DELETE FROM news WHERE id = ? AND app_id = ?", (news_id, app_id))
    await db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(404, "News item not found")
    return {"ok": True}


@router.get("/variables")
async def variables(_key=Depends(require_scope("read")), db=Depends(get_db)):
    async with db.execute("SELECT name, value, is_secret, created_at FROM variables ORDER BY name") as cur:
        rows = [dict(row) for row in await cur.fetchall()]
    for row in rows:
        if row["is_secret"]:
            row["value"] = "<secret>"
    return rows


@router.put("/variables")
async def set_variable(body: NamedValueBody, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    await db.execute(
        """INSERT INTO variables (id, name, value, is_secret) VALUES (?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET value=excluded.value, is_secret=excluded.is_secret""",
        (generate_uid(), body.name, body.value, 1 if body.is_secret else 0),
    )
    await db.commit()
    return {"ok": True}


@router.delete("/variables/{name}")
async def delete_variable(name: str, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    await db.execute("DELETE FROM variables WHERE name = ?", (name,))
    await db.commit()
    return {"ok": True}


@router.get("/apps/{app_id}/banned-hwids")
async def banned_hwids(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute("SELECT hwid, reason, banned_at FROM banned_hwids WHERE app_id = ?", (app_id,)) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.post("/apps/{app_id}/banned-hwids")
async def ban_hwid(app_id: str, body: HwidBody, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    await require_app(db, app_id)
    await db.execute("INSERT OR REPLACE INTO banned_hwids (hwid, app_id, reason) VALUES (?, ?, ?)",
                     (body.hwid.lower(), app_id, body.reason))
    await db.commit()
    return {"ok": True}


@router.delete("/apps/{app_id}/banned-hwids/{hwid}")
async def unban_hwid(app_id: str, hwid: str, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    await db.execute("DELETE FROM banned_hwids WHERE app_id = ? AND hwid = ?", (app_id, hwid.lower()))
    await db.commit()
    return {"ok": True}
