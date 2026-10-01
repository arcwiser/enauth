import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from database import get_db
from routes.admin import require_api_key
from utils.crypto import (generate_license_key, generate_uid, hash_license_key,
                          mask_license_key, encrypt_license_key, display_license_key)
from utils.logger import log_action

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def require_scope(required: str):
    ranks = {"read": 1, "write": 2, "admin": 3}

    async def dependency(key=Depends(require_api_key)):
        if key.get("role") != "owner":
            raise HTTPException(403, "Owner API key required")
        configured = str(key.get("scopes") or "read").lower()
        granted = max((ranks.get(item.strip(), 0) for item in configured.split(",")), default=0)
        if granted < ranks[required]:
            raise HTTPException(403, f"API key requires {required} scope")
        return key

    return dependency


async def require_app(db: aiosqlite.Connection, app_id: str):
    async with db.execute("SELECT id, name, version FROM applications WHERE id = ?", (app_id,)) as cur:
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
    count: int = Field(default=1, ge=1, le=50)
    max_hwids: int = Field(default=1, ge=1, le=100)


class ExtendBody(BaseModel):
    hours: float = Field(gt=0, le=876000)


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


@router.get("/apps")
async def apps(_key=Depends(require_scope("read")), db=Depends(get_db)):
    async with db.execute(
        "SELECT id, name, version FROM applications ORDER BY name LIMIT 200"
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.get("/apps/{app_id}")
async def app_details(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    app = await require_app(db, app_id)
    async with db.execute(
        """SELECT id, name, level, is_active, service_status, status_color, status_message,
                  is_paused, paused_at, pause_reason
           FROM products WHERE app_id = ? ORDER BY name""",
        (app_id,),
    ) as cur:
        app["products"] = [dict(row) for row in await cur.fetchall()]
    return app


@router.get("/apps/{app_id}/licenses")
async def licenses(app_id: str, search: Optional[str] = None, limit: int = 25,
                   _key=Depends(require_scope("read")), db=Depends(get_db)):
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
        row["key"] = display_license_key(row["key"], row.get("key_ciphertext"))
        row.pop("key_ciphertext", None)
    return rows


@router.post("/apps/{app_id}/licenses")
async def generate(app_id: str, body: GenerateBody, key=Depends(require_scope("write")), db=Depends(get_db)):
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
                     license_key=license_row["key"], details=f"API key {key['id']}")
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
                     license_key=license_row["key"], details=f"API key {key['id']}")
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
        return [dict(row) for row in await cur.fetchall()]


@router.post("/apps/{app_id}/builds")
async def upload_build(app_id: str, name: str = Form(...), file: UploadFile = File(...),
                       key=Depends(require_scope("admin")), db=Depends(get_db)):
    await require_app(db, app_id)
    safe_name = Path(name).name.strip()
    if not safe_name or safe_name != name.strip():
        raise HTTPException(400, "Invalid build name")
    content = await file.read(5 * 1024 * 1024 + 1)
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Build exceeds 5 MiB")
    file_id = generate_uid()
    digest = hashlib.sha256(content).hexdigest()
    await db.execute(
        """INSERT INTO app_files (id, app_id, name, content, file_sha256, is_secret)
           VALUES (?, ?, ?, ?, ?, 1)
           ON CONFLICT(app_id, name) DO UPDATE SET content=excluded.content,
           file_sha256=excluded.file_sha256, is_secret=1""",
        (file_id, app_id, safe_name, content, digest),
    )
    await log_action(db, "integration_upload_build", app_id=app_id,
                     details=f"Uploaded {safe_name} ({digest[:16]}) via API key {key['id']}")
    await db.commit()
    async with db.execute("SELECT id FROM app_files WHERE app_id = ? AND name = ?", (app_id, safe_name)) as cur:
        stored = await cur.fetchone()
    return {"ok": True, "id": stored["id"], "name": safe_name, "size": len(content), "sha256": digest}


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
async def license_details(app_id: str, identifier: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
    item.pop("key_hash", None)
    async with db.execute("SELECT hwid_hash, first_seen, last_seen FROM hwids WHERE license_id = ?", (item["id"],)) as cur:
        item["hwids"] = [dict(row) for row in await cur.fetchall()]
    return item


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
    await log_action(db, "integration_extend", app_id=app_id, license_key=item["key"],
                     details=f"Extended through API key {key['id']}")
    await db.commit()
    return {"ok": True, "expires_at": expires_at}


@router.delete("/apps/{app_id}/licenses/{identifier}")
async def delete_license(app_id: str, identifier: str, _key=Depends(require_scope("admin")), db=Depends(get_db)):
    item = await find_license(db, app_id, identifier)
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
        return [dict(row) for row in await cur.fetchall()]


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


@router.get("/apps/{app_id}/builds")
async def builds(app_id: str, _key=Depends(require_scope("read")), db=Depends(get_db)):
    await require_app(db, app_id)
    async with db.execute(
        "SELECT id, name, created_at FROM app_files WHERE app_id = ? ORDER BY created_at DESC",
        (app_id,),
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


@router.delete("/apps/{app_id}/builds/{file_id}")
async def delete_build(app_id: str, file_id: str, _key=Depends(require_scope("admin")), db=Depends(get_db)):
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
