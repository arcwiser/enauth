VERSION = 15


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    columns = await _columns(db, "applications")
    if "download_violation_action" not in columns:
        await db.execute(
            "ALTER TABLE applications ADD COLUMN download_violation_action TEXT NOT NULL DEFAULT 'deny'"
        )
    if "download_violation_limit" not in columns:
        await db.execute(
            "ALTER TABLE applications ADD COLUMN download_violation_limit INTEGER NOT NULL DEFAULT 3"
        )
    await db.execute("""CREATE TABLE IF NOT EXISTS download_violations (
        app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
        license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
        hwid TEXT NOT NULL,
        warning_count INTEGER NOT NULL DEFAULT 0,
        last_reason TEXT,
        last_ip TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(app_id, license_id, hwid)
    )""")
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_download_violations_license ON download_violations(license_id,updated_at)"
    )
