from database import _apply_schema_v1

VERSION = 1


async def apply(db):
    await _apply_schema_v1(db)
