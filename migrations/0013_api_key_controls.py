VERSION = 13


async def apply(db):
    async with db.execute("PRAGMA table_info(api_keys)") as cur:
        columns = {row[1] for row in await cur.fetchall()}
    for name, definition in (
        ("app_id", "TEXT REFERENCES applications(id) ON DELETE CASCADE"),
        ("allowed_ips", "TEXT"),
        ("usage_count", "INTEGER NOT NULL DEFAULT 0"),
        ("last_ip", "TEXT"),
    ):
        if name not in columns:
            await db.execute(f"ALTER TABLE api_keys ADD COLUMN {name} {definition}")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_app ON api_keys(app_id)")
