VERSION = 7


async def _columns(db, table):
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def apply(db):
    columns = await _columns(db, "app_files")
    additions = (
        ("release_version", "TEXT NOT NULL DEFAULT '1.0.0'"),
        ("channel", "TEXT NOT NULL DEFAULT 'stable'"),
        ("file_type", "TEXT NOT NULL DEFAULT 'payload'"),
        ("platform", "TEXT NOT NULL DEFAULT 'windows'"),
        ("architecture", "TEXT NOT NULL DEFAULT 'x64'"),
        ("min_client_version", "TEXT"),
        ("max_client_version", "TEXT"),
        ("release_notes", "TEXT"),
        ("mime_type", "TEXT"),
        ("file_size", "INTEGER NOT NULL DEFAULT 0"),
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
        ("is_archived", "INTEGER NOT NULL DEFAULT 0"),
        ("is_mandatory", "INTEGER NOT NULL DEFAULT 0"),
        ("download_limit", "INTEGER"),
        ("available_from", "DATETIME"),
        ("available_until", "DATETIME"),
        ("storage_provider", "TEXT NOT NULL DEFAULT 'database'"),
        ("storage_key", "TEXT"),
        ("replaced_file_id", "TEXT"),
    )
    for name, definition in additions:
        if name not in columns:
            await db.execute(f"ALTER TABLE app_files ADD COLUMN {name} {definition}")
    await db.execute(
        """CREATE TABLE IF NOT EXISTS app_file_products (
               file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
               product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
               PRIMARY KEY(file_id, product_id)
           )"""
    )
    await db.execute(
        """INSERT OR IGNORE INTO app_file_products(file_id, product_id)
           SELECT id, product_id FROM app_files WHERE product_id IS NOT NULL"""
    )
    await db.execute(
        """CREATE TABLE IF NOT EXISTS file_download_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
               license_id TEXT REFERENCES licenses(id) ON DELETE SET NULL,
               source TEXT NOT NULL,
               ip TEXT,
               downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_file_release_lookup ON app_files(app_id,name,channel,is_active,is_archived)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_file_products_product ON app_file_products(product_id,file_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_file_downloads_file ON file_download_events(file_id,downloaded_at)")
