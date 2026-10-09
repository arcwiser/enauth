VERSION = 16


async def apply(db):
    await db.execute("""CREATE TABLE IF NOT EXISTS license_templates (
        id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
        name TEXT NOT NULL, product_ids TEXT NOT NULL, duration_hours REAL,
        max_hwids INTEGER NOT NULL DEFAULT 1, key_prefix TEXT, notes TEXT, metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(app_id,name)
    )""")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_license_templates_app ON license_templates(app_id,name)")
