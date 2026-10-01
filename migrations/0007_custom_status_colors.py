VERSION = 7


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    if "status_color" not in await _columns(db, "products"):
        await db.execute("ALTER TABLE products ADD COLUMN status_color TEXT NOT NULL DEFAULT '#22c55e'")
    if "status_color" not in await _columns(db, "outage_events"):
        await db.execute("ALTER TABLE outage_events ADD COLUMN status_color TEXT NOT NULL DEFAULT '#22c55e'")
