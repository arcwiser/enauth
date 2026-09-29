from utils.crypto import hash_license_key, mask_license_key

VERSION = 4


async def apply(db):
    async with db.execute("PRAGMA table_info(licenses)") as cur:
        license_columns = [row[1] for row in await cur.fetchall()]
    if "key_hash" not in license_columns:
        await db.execute("ALTER TABLE licenses ADD COLUMN key_hash TEXT")

    async with db.execute("SELECT id, key FROM licenses WHERE key_hash IS NULL") as cur:
        legacy_licenses = await cur.fetchall()
    for license_row in legacy_licenses:
        license_id, plaintext_key = license_row[0], license_row[1]
        await db.execute(
            "UPDATE licenses SET key = ?, key_hash = ? WHERE id = ?",
            (mask_license_key(plaintext_key), hash_license_key(plaintext_key), license_id),
        )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash)")

    await db.execute(
        """CREATE TABLE IF NOT EXISTS request_nonces (
               nonce_hash TEXT PRIMARY KEY,
               expires_at INTEGER NOT NULL
           )"""
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_request_nonces_expires ON request_nonces(expires_at)"
    )

    async with db.execute("PRAGMA table_info(api_keys)") as cur:
        api_key_columns = [row[1] for row in await cur.fetchall()]
    if api_key_columns and "key_prefix" not in api_key_columns:
        await db.execute("ALTER TABLE api_keys ADD COLUMN key_prefix TEXT")
    if api_key_columns:
        await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)")
