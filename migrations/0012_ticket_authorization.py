VERSION = 12


async def apply(db):
    async with db.execute("PRAGMA table_info(sessions)") as cur:
        columns = {row[1] for row in await cur.fetchall()}
    if "protocol" not in columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1")
        # Existing rotating sessions must never fall back to a legacy envelope.
        await db.execute("""UPDATE sessions SET protocol=2
                            WHERE token_generation>0 OR token_expires_at<expires_at""")

    async with db.execute("PRAGMA foreign_key_list(download_tickets)") as cur:
        ticket_foreign_keys = await cur.fetchall()
    if any(row[2] == "app_files_current" for row in ticket_foreign_keys):
        # Some historical v8 repair paths renamed app_files and left this
        # short-lived table pointing at the temporary table name.
        await db.execute("DROP TABLE download_tickets")
        await db.execute("""CREATE TABLE download_tickets (
            id TEXT PRIMARY KEY, ticket_hash TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            product_id TEXT, file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
            hwid TEXT NOT NULL, client_version TEXT, file_sha256 TEXT, file_version TEXT,
            expires_at DATETIME NOT NULL, consumed_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")

    async with db.execute("PRAGMA table_info(download_tickets)") as cur:
        columns = {row[1] for row in await cur.fetchall()}
    for name in ("file_sha256", "file_version"):
        if name not in columns:
            await db.execute(f"ALTER TABLE download_tickets ADD COLUMN {name} TEXT")
    # Old tickets did not bind immutable content. They last at most five minutes;
    # clients can obtain a fresh ticket after this upgrade.
    await db.execute("DELETE FROM download_tickets WHERE file_sha256 IS NULL OR file_version IS NULL")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_download_tickets_expiry ON download_tickets(expires_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_download_tickets_hash ON download_tickets(ticket_hash)")
