VERSION = 11


async def _columns(db, table: str) -> set[str]:
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    session_columns = await _columns(db, "sessions")
    for name, definition in (
        ("client_version", "TEXT"),
        ("token_expires_at", "DATETIME"),
        ("rotated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"),
        ("token_generation", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in session_columns:
            await db.execute(f"ALTER TABLE sessions ADD COLUMN {name} {definition}")
    await db.execute("UPDATE sessions SET token_expires_at=expires_at WHERE token_expires_at IS NULL")

    product_columns = await _columns(db, "products")
    for name, definition in (
        ("required_client_version", "TEXT"),
        ("blocked_client_versions", "TEXT NOT NULL DEFAULT '[]'"),
        ("version_kill_switch", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in product_columns:
            await db.execute(f"ALTER TABLE products ADD COLUMN {name} {definition}")

    file_columns = await _columns(db, "app_files")
    for name, definition in (
        ("is_revoked", "INTEGER NOT NULL DEFAULT 0"),
        ("revoked_at", "DATETIME"),
        ("revoke_reason", "TEXT"),
    ):
        if name not in file_columns:
            await db.execute(f"ALTER TABLE app_files ADD COLUMN {name} {definition}")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS download_tickets (
            id TEXT PRIMARY KEY,
            ticket_hash TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            product_id TEXT,
            file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
            hwid TEXT NOT NULL,
            client_version TEXT,
            expires_at DATETIME NOT NULL,
            consumed_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_download_tickets_hash ON download_tickets(ticket_hash)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token_expiry ON sessions(token_expires_at)")
