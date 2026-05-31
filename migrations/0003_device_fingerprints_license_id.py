from database import _apply_schema_v3

VERSION = 3


async def apply(db):
    await _apply_schema_v3(db)
