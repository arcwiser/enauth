VERSION = 14


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    await db.execute("""CREATE TABLE IF NOT EXISTS sdk_releases (
        id TEXT PRIMARY KEY, version TEXT NOT NULL UNIQUE, channel TEXT NOT NULL DEFAULT 'stable',
        status TEXT NOT NULL DEFAULT 'supported', package_name TEXT NOT NULL,
        package BLOB NOT NULL, package_size INTEGER NOT NULL, sha256 TEXT NOT NULL,
        signature TEXT NOT NULL, release_notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    await db.execute("""CREATE TABLE IF NOT EXISTS sdk_compatibility (
        app_id TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
        minimum_version TEXT, recommended_version TEXT, enforce_minimum INTEGER NOT NULL DEFAULT 0,
        upgrade_message TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    session_columns = await _columns(db, "sessions")
    if "sdk_version" not in session_columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN sdk_version TEXT")
    access_columns = await _columns(db, "reseller_product_access")
    for name, definition in (("monthly_quota", "INTEGER"), ("monthly_used", "INTEGER NOT NULL DEFAULT 0"),
                             ("quota_reset_at", "DATETIME")):
        if name not in access_columns:
            await db.execute(f"ALTER TABLE reseller_product_access ADD COLUMN {name} {definition}")
    await db.execute("""CREATE TABLE IF NOT EXISTS portal_device_names (
        license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
        fingerprint_id TEXT NOT NULL REFERENCES device_fingerprints(id) ON DELETE CASCADE,
        display_name TEXT NOT NULL, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(license_id,fingerprint_id))""")
    await db.execute("""CREATE TABLE IF NOT EXISTS hwid_reset_requests (
        id TEXT PRIMARY KEY, license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
        reason TEXT, status TEXT NOT NULL DEFAULT 'pending', reviewed_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, reviewed_at DATETIME)""")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_sdk_release_channel ON sdk_releases(channel,status,created_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_hwid_requests_status ON hwid_reset_requests(status,created_at)")
