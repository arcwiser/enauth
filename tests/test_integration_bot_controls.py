import os
import unittest
from datetime import datetime, timedelta, timezone

import aiosqlite

os.environ.setdefault("LICENSE_KEY_PEPPER", "test-license-pepper-that-is-long-enough")

from database import SCHEMA
from routes import integrations
from utils.crypto import encrypt_license_key, hash_license_key, mask_license_key


class DiscordIntegrationControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = await aiosqlite.connect(":memory:")
        self.db.row_factory = aiosqlite.Row
        await self.db.executescript(SCHEMA)
        await self.db.execute(
            "INSERT INTO applications(id,name,secret_key) VALUES('app-1','Test','secret')"
        )
        await self.db.execute(
            "INSERT INTO products(id,app_id,name,level) VALUES('product-1','app-1','One','one')"
        )
        await self.db.execute(
            "INSERT INTO products(id,app_id,name,level) VALUES('product-2','app-1','Two','two')"
        )
        self.keys = [
            "AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF",
            "GGGGGG-HHHHHH-IIIIII-JJJJJJ-KKKKKK-LLLLLL",
        ]
        expiry = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        for index, raw_key in enumerate(self.keys, 1):
            license_id = f"license-{index}"
            await self.db.execute(
                """INSERT INTO licenses(id,key,key_hash,key_ciphertext,app_id,expires_at)
                   VALUES(?,?,?,?,?,?)""",
                (license_id, mask_license_key(raw_key), hash_license_key(raw_key),
                 encrypt_license_key(raw_key), "app-1", expiry),
            )
            await self.db.execute(
                "INSERT INTO license_products(id,license_id,product_id,expires_at) VALUES(?,?,?,?)",
                (f"entitlement-{index}", license_id, "product-1", expiry),
            )
        await self.db.commit()
        self.api_key = {"id": "api-1", "role": "owner", "scopes": "admin"}

    async def asyncTearDown(self):
        await self.db.close()

    async def test_add_product_and_reveal_it_in_license_details(self):
        result = await integrations.add_license_product(
            "app-1", self.keys[0], integrations.EntitlementAddBody(product_id="product-2", duration_hours=48),
            self.api_key, self.db,
        )
        self.assertEqual(result["product"], "Two")
        details = await integrations.license_details("app-1", self.keys[0], self.api_key, self.db)
        self.assertEqual({item["product_id"] for item in details["products"]}, {"product-1", "product-2"})

    async def test_extend_product_all_and_show_each_key_history(self):
        result = await integrations.extend_product_license(
            "app-1", "product-1", "all", integrations.ExtendBody(hours=24), self.api_key, self.db
        )
        self.assertEqual(result["affected"], 2)
        for raw_key in self.keys:
            history = await integrations.license_history("app-1", raw_key, 50, self.api_key, self.db)
            self.assertEqual(history["events"][0]["action"], "integration_product_extended")

    async def test_pause_preview_and_resume_with_compensation(self):
        await integrations.pause_app(
            "app-1", integrations.PauseBody(reason="Maintenance"), self.api_key, self.db
        )
        preview = await integrations.resume_app_preview("app-1", 48, self.api_key, self.db)
        self.assertEqual(preview["affected_licenses"], 2)
        self.assertEqual(preview["compensation_seconds"], 48 * 3600)
        result = await integrations.resume_app(
            "app-1", integrations.ResumeBody(compensation_hours=48), self.api_key, self.db
        )
        self.assertEqual(result["affected_licenses"], 2)
        history = await integrations.license_history("app-1", self.keys[0], 50, self.api_key, self.db)
        self.assertIn("integration_compensation", {event["action"] for event in history["events"]})


if __name__ == "__main__":
    unittest.main()
