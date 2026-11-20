VERSION = 19


async def apply(db):
    await db.execute(
        """CREATE TABLE IF NOT EXISTS api_idempotency_keys (
               credential_id TEXT NOT NULL,
               credential_kind TEXT NOT NULL,
               operation TEXT NOT NULL,
               idempotency_key_hash TEXT NOT NULL,
               request_hash TEXT NOT NULL,
               result_json TEXT,
               expires_at DATETIME NOT NULL,
               created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
               PRIMARY KEY(credential_id,credential_kind,operation,idempotency_key_hash)
           )"""
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_idempotency_expires ON api_idempotency_keys(expires_at)"
    )
