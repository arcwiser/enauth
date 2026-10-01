from fastapi import APIRouter, Depends, HTTPException
import aiosqlite

from database import get_db

router = APIRouter(prefix="/api/status", tags=["public-status"])


@router.get("/{app_id}")
async def public_status(app_id: str, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id,name,is_paused,pause_reason FROM applications WHERE id=?", (app_id,)) as cur:
        app = await cur.fetchone()
    if not app:
        raise HTTPException(404, "Status page not found")
    async with db.execute(
        """SELECT id,name,level,service_status,status_color,status_message,is_paused,paused_at
           FROM products WHERE app_id=? AND is_active=1 ORDER BY name""", (app_id,)
    ) as cur:
        products = [dict(row) for row in await cur.fetchall()]
    async with db.execute(
        """SELECT oe.event_type,oe.service_status,oe.status_color,oe.public_message,oe.started_at,oe.ended_at,
                  oe.downtime_seconds,oe.created_at,p.name AS product_name,p.level
           FROM outage_events oe LEFT JOIN products p ON p.id=oe.product_id
           WHERE oe.app_id=? ORDER BY oe.created_at DESC LIMIT 50""", (app_id,)
    ) as cur:
        history = [dict(row) for row in await cur.fetchall()]
    rank = {"operational": 0, "degraded": 1, "maintenance": 2, "offline": 3}
    worst = max(products, key=lambda p: rank.get(p["service_status"].lower(), 1), default=None)
    overall = "offline" if app["is_paused"] else (worst["service_status"] if worst else "operational")
    overall_color = "#ef4444" if app["is_paused"] else (worst["status_color"] if worst else "#22c55e")
    return {"app": {"id": app["id"], "name": app["name"]}, "overall_status": overall,
            "overall_color": overall_color,
            "message": app["pause_reason"] if app["is_paused"] else None,
            "products": products, "history": history}
