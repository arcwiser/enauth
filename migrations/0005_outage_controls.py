VERSION = 5


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    app_columns = await _columns(db, "applications")
    for name, definition in (
        ("is_paused", "INTEGER NOT NULL DEFAULT 0"),
        ("paused_at", "DATETIME"),
        ("pause_reason", "TEXT"),
    ):
        if name not in app_columns:
            await db.execute(f"ALTER TABLE applications ADD COLUMN {name} {definition}")

    product_columns = await _columns(db, "products")
    for name, definition in (
        ("is_paused", "INTEGER NOT NULL DEFAULT 0"),
        ("paused_at", "DATETIME"),
        ("pause_reason", "TEXT"),
    ):
        if name not in product_columns:
            await db.execute(f"ALTER TABLE products ADD COLUMN {name} {definition}")

    entitlement_columns = await _columns(db, "license_products")
    if "expires_at" not in entitlement_columns:
        await db.execute("ALTER TABLE license_products ADD COLUMN expires_at DATETIME")
        await db.execute(
            """UPDATE license_products
               SET expires_at = (SELECT expires_at FROM licenses WHERE licenses.id = license_products.license_id)"""
        )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_license_products_expiry ON license_products(expires_at)"
    )

    session_columns = await _columns(db, "sessions")
    if "product_id" not in session_columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN product_id TEXT")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_product ON sessions(product_id)")
