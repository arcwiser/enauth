from database import _apply_schema_v2

VERSION = 2


async def apply(db):
    await _apply_schema_v2(db)
