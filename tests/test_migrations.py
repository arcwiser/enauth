import importlib
import logging
import os
import shutil
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path


class DatabaseMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.workdir = Path(__file__).resolve().parent / f"_migrate-{uuid.uuid4().hex}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workdir / "enauth.db"

        os.environ["DB_PATH"] = str(self.db_path)

        sys.modules.pop("database", None)
        self.database = importlib.import_module("database")

    async def asyncTearDown(self):
        logger = logging.getLogger("root")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        shutil.rmtree(self.workdir, ignore_errors=True)

    async def test_init_db_sets_latest_version(self):
        await self.database.init_db()

        async with self.database.aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='temp_2fa_sessions'"
            ) as cur:
                temp_table = await cur.fetchone()

        self.assertEqual(version, self.database.LATEST_SCHEMA_VERSION)
        self.assertIsNotNone(temp_table)

    async def test_init_db_upgrades_version_1_database(self):
        async with self.database.aiosqlite.connect(self.db_path) as db:
            db.row_factory = self.database.aiosqlite.Row
            await self.database._apply_schema_v1(db)
            await db.execute("PRAGMA user_version = 1")
            await db.commit()

        await self.database.init_db()

        async with self.database.aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='temp_2fa_sessions'"
            ) as cur:
                temp_table = await cur.fetchone()

        self.assertEqual(version, self.database.LATEST_SCHEMA_VERSION)
        self.assertIsNotNone(temp_table)


if __name__ == "__main__":
    unittest.main()
