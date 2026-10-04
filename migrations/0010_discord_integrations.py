VERSION = 10


async def apply(db):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS discord_integrations (
            id          TEXT PRIMARY KEY,
            app_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            key_hash    TEXT NOT NULL UNIQUE,
            key_prefix  TEXT NOT NULL,
            created_by  TEXT,
            is_active   INTEGER NOT NULL DEFAULT 1,
            last_used   DATETIME,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_discord_integrations_app ON discord_integrations(app_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_discord_integrations_prefix ON discord_integrations(key_prefix)")
