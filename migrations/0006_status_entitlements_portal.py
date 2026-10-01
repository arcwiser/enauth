VERSION = 6


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    product_columns = await _columns(db, "products")
    for name, definition in (
        ("service_status", "TEXT NOT NULL DEFAULT 'operational'"),
        ("status_message", "TEXT"),
    ):
        if name not in product_columns:
            await db.execute(f"ALTER TABLE products ADD COLUMN {name} {definition}")

    entitlement_columns = await _columns(db, "license_products")
    for name, definition in (
        ("is_paused", "INTEGER NOT NULL DEFAULT 0"),
        ("paused_at", "DATETIME"),
        ("pause_reason", "TEXT"),
        ("total_compensation_seconds", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in entitlement_columns:
            await db.execute(f"ALTER TABLE license_products ADD COLUMN {name} {definition}")

    file_columns = await _columns(db, "app_files")
    if "portal_visible" not in file_columns:
        await db.execute("ALTER TABLE app_files ADD COLUMN portal_visible INTEGER NOT NULL DEFAULT 0")
    if "product_id" not in file_columns:
        await db.execute("ALTER TABLE app_files ADD COLUMN product_id TEXT")

    await db.execute(
        """CREATE TABLE IF NOT EXISTS outage_events (
               id TEXT PRIMARY KEY,
               app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
               product_id TEXT REFERENCES products(id) ON DELETE CASCADE,
               event_type TEXT NOT NULL,
               service_status TEXT NOT NULL,
               public_message TEXT,
               started_at DATETIME,
               ended_at DATETIME,
               downtime_seconds INTEGER NOT NULL DEFAULT 0,
               compensation_seconds INTEGER NOT NULL DEFAULT 0,
               affected_licenses INTEGER NOT NULL DEFAULT 0,
               created_at DATETIME DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_outages_app_created ON outage_events(app_id, created_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_outages_product_created ON outage_events(product_id, created_at)")
