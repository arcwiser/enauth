VERSION = 20


async def apply(db):
    await db.execute(
        """CREATE INDEX IF NOT EXISTS idx_licenses_app_status_created
           ON licenses(app_id,status,created_at DESC,id DESC)"""
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_products_app_level ON products(app_id,level,id)"
    )
