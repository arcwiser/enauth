VERSION = 8


async def apply(db):
    async with db.execute("PRAGMA table_info(licenses)") as cur:
        columns = {row[1] for row in await cur.fetchall()}
    if "key_ciphertext" not in columns:
        await db.execute("ALTER TABLE licenses ADD COLUMN key_ciphertext TEXT")
