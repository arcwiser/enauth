VERSION = 18


async def apply(db):
    async with db.execute("PRAGMA table_info(api_keys)") as cur:
        columns = {row[1] for row in await cur.fetchall()}
    for name, definition in (
        ("rate_limit_per_minute", "INTEGER"),
        ("rate_window_minute", "INTEGER"),
        ("rate_window_count", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in columns:
            await db.execute(f"ALTER TABLE api_keys ADD COLUMN {name} {definition}")
