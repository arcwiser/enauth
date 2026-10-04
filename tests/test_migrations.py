import importlib
import logging
import os
import shutil
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path

import aiosqlite


class DatabaseMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.workdir = Path(__file__).resolve().parent / f"_migrate-{uuid.uuid4().hex}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workdir / "enauth.db"

        os.environ["DB_PATH"] = str(self.db_path)
        os.environ["LICENSE_KEY_PEPPER"] = "test-license-pepper-that-is-long-enough"

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

    async def test_security_migration_hashes_existing_license_keys(self):
        plaintext_key = "ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF-ABCDEF"
        async with self.database.aiosqlite.connect(self.db_path) as db:
            db.row_factory = self.database.aiosqlite.Row
            await self.database._apply_schema_v1(db)
            await self.database._apply_schema_v2(db)
            await self.database._apply_schema_v3(db)
            await db.execute(
                "INSERT INTO applications(id, name, secret_key, version) VALUES (?, ?, ?, ?)",
                ("app-1", "Test", "s" * 64, "1.0.0"),
            )
            await db.execute(
                "INSERT INTO licenses(id, key, key_hash, app_id) VALUES (?, ?, NULL, ?)",
                ("lic-1", plaintext_key, "app-1"),
            )
            await db.execute("PRAGMA user_version = 3")
            await db.commit()

        await self.database.init_db()

        async with self.database.aiosqlite.connect(self.db_path) as db:
            db.row_factory = self.database.aiosqlite.Row
            async with db.execute("SELECT key, key_hash FROM licenses WHERE id = 'lic-1'") as cur:
                license_row = await cur.fetchone()

        self.assertNotEqual(license_row["key"], plaintext_key)
        self.assertEqual(len(license_row["key_hash"]), 64)

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

    async def test_outage_schema_supports_per_product_expiration(self):
        await self.database.init_db()
        async with self.database.aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA table_info(applications)") as cur:
                app_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(products)") as cur:
                product_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(license_products)") as cur:
                entitlement_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(sessions)") as cur:
                session_columns = {row[1] for row in await cur.fetchall()}

        self.assertTrue({"is_paused", "paused_at", "pause_reason"} <= app_columns)
        self.assertTrue({"is_paused", "paused_at", "pause_reason"} <= product_columns)
        self.assertIn("expires_at", entitlement_columns)
        self.assertIn("product_id", session_columns)

    async def test_status_portal_and_entitlement_schema(self):
        await self.database.init_db()
        async with self.database.aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA table_info(products)") as cur:
                product_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(license_products)") as cur:
                entitlement_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(app_files)") as cur:
                file_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("PRAGMA table_info(licenses)") as cur:
                license_columns = {row[1] for row in await cur.fetchall()}
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='outage_events'") as cur:
                outage_table = await cur.fetchone()

        self.assertTrue({"service_status", "status_message", "status_color"} <= product_columns)
        self.assertTrue({"is_paused", "paused_at", "pause_reason", "total_compensation_seconds"} <= entitlement_columns)
        self.assertTrue({"portal_visible", "product_id"} <= file_columns)
        self.assertIn("key_ciphertext", license_columns)
        self.assertIsNotNone(outage_table)

    async def test_release_file_schema(self):
        await self.database.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA table_info(app_files)") as cur:
                columns = {row[1] for row in await cur.fetchall()}
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('app_file_products','file_download_events')"
            ) as cur:
                tables = {row[0] for row in await cur.fetchall()}
        self.assertTrue({"release_version", "channel", "file_type", "platform", "architecture",
                         "file_size", "is_active", "is_archived", "download_limit"} <= columns)
        self.assertEqual(tables, {"app_file_products", "file_download_events"})

    async def test_version_8_database_receives_release_repair(self):
        await self.database.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DROP TABLE file_download_events")
            await db.execute("DROP TABLE app_file_products")
            await db.execute("ALTER TABLE app_files RENAME TO app_files_current")
            await db.execute(
                """CREATE TABLE app_files (
                       id TEXT PRIMARY KEY, app_id TEXT NOT NULL, name TEXT NOT NULL,
                       content BLOB NOT NULL, file_sha256 TEXT, is_secret INTEGER DEFAULT 0,
                       portal_visible INTEGER NOT NULL DEFAULT 0, product_id TEXT,
                       created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(app_id,name)
                   )"""
            )
            await db.execute("DROP TABLE app_files_current")
            await db.execute("PRAGMA user_version=8")
            await db.commit()
        await self.database.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
            async with db.execute("PRAGMA table_info(app_files)") as cur:
                columns = {row[1] for row in await cur.fetchall()}
            self.assertEqual(version, 11)
        self.assertTrue({"release_version", "channel", "file_type", "is_archived"} <= columns)


if __name__ == "__main__":
    unittest.main()
