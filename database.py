import aiosqlite
import importlib.util
import os
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "enauth.db")
MIGRATIONS_DIR = Path(__file__).parent / "migrations"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS applications (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    secret_key  TEXT NOT NULL UNIQUE,
    version     TEXT NOT NULL DEFAULT '1.0.0',
    owner_user_id TEXT REFERENCES auth_users(id) ON DELETE SET NULL,
    is_paused   INTEGER NOT NULL DEFAULT 0,
    paused_at   DATETIME,
    pause_reason TEXT,
    download_violation_action TEXT NOT NULL DEFAULT 'deny',
    download_violation_limit INTEGER NOT NULL DEFAULT 3,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS licenses (
    id           TEXT PRIMARY KEY,
    key          TEXT NOT NULL UNIQUE,
    key_hash     TEXT UNIQUE,
    key_hash_version TEXT NOT NULL DEFAULT 'legacy-v1',
    key_ciphertext TEXT,
    app_id       TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME,
    max_hwids    INTEGER NOT NULL DEFAULT 1,
    notes        TEXT,
    metadata     TEXT,
    hwid_reset_at DATETIME,
    last_ip      TEXT,
    login_strikes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS license_products (
    id          TEXT PRIMARY KEY,
    license_id  TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    product_id  TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    expires_at  DATETIME,
    is_paused   INTEGER NOT NULL DEFAULT 0,
    paused_at   DATETIME,
    pause_reason TEXT,
    total_compensation_seconds INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(license_id, product_id)
);

CREATE TABLE IF NOT EXISTS hwids (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id  TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    hwid_hash   TEXT NOT NULL,
    first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(license_id, hwid_hash)
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    token           TEXT NOT NULL UNIQUE,
    license_id      TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    hwid            TEXT NOT NULL,
    ip              TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    product_id      TEXT,
    started_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    client_version  TEXT,
    token_expires_at DATETIME,
    rotated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    token_generation INTEGER NOT NULL DEFAULT 0,
    protocol        INTEGER NOT NULL DEFAULT 1,
    sdk_version     TEXT
);

CREATE TABLE IF NOT EXISTS request_nonces (
    nonce_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_nonces_expires
    ON request_nonces(expires_at);

CREATE TABLE IF NOT EXISTS admin_users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email         TEXT,
    role          TEXT NOT NULL DEFAULT 'admin',
    theme         TEXT DEFAULT 'dark',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    app_id      TEXT,
    action      TEXT NOT NULL,
    ip          TEXT,
    hwid        TEXT,
    details     TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_licenses_key        ON licenses(key);
CREATE INDEX IF NOT EXISTS idx_licenses_app        ON licenses(app_id);
CREATE INDEX IF NOT EXISTS idx_license_products_license ON license_products(license_id);
CREATE INDEX IF NOT EXISTS idx_license_products_product ON license_products(product_id);
CREATE INDEX IF NOT EXISTS idx_hwids_license       ON hwids(license_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token      ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_license    ON sessions(license_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp      ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_license        ON logs(license_key);
CREATE INDEX IF NOT EXISTS idx_admin_sess_token    ON admin_sessions(token);

CREATE TABLE IF NOT EXISTS download_violations (
    app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    hwid TEXT NOT NULL,
    warning_count INTEGER NOT NULL DEFAULT 0,
    last_reason TEXT,
    last_ip TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(app_id, license_id, hwid)
);

CREATE TABLE IF NOT EXISTS banned_hwids (
    hwid        TEXT NOT NULL,
    app_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    reason      TEXT,
    banned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(hwid, app_id)
);

CREATE TABLE IF NOT EXISTS variables (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    value       TEXT NOT NULL,
    is_secret   BOOLEAN DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS news (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    color       TEXT DEFAULT 'white',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_flags (
    hwid        TEXT PRIMARY KEY,
    strikes     INTEGER DEFAULT 0,
    last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_files (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    content     BLOB NOT NULL,
    file_sha256 TEXT,
    is_secret   BOOLEAN DEFAULT 0,
    portal_visible INTEGER NOT NULL DEFAULT 0,
    product_id  TEXT REFERENCES products(id) ON DELETE SET NULL,
    release_version TEXT NOT NULL DEFAULT '1.0.0',
    channel TEXT NOT NULL DEFAULT 'stable',
    file_type TEXT NOT NULL DEFAULT 'payload',
    platform TEXT NOT NULL DEFAULT 'windows',
    architecture TEXT NOT NULL DEFAULT 'x64',
    min_client_version TEXT,
    max_client_version TEXT,
    release_notes TEXT,
    mime_type TEXT,
    file_size INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_archived INTEGER NOT NULL DEFAULT 0,
    is_mandatory INTEGER NOT NULL DEFAULT 0,
    download_limit INTEGER,
    available_from DATETIME,
    available_until DATETIME,
    storage_provider TEXT NOT NULL DEFAULT 'database',
    storage_key TEXT,
    replaced_file_id TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME,
    revoke_reason TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, name)
);

CREATE TABLE IF NOT EXISTS app_file_products (
    file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    PRIMARY KEY(file_id, product_id)
);

CREATE TABLE IF NOT EXISTS file_download_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
    license_id TEXT REFERENCES licenses(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    ip TEXT,
    downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    app_id       TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    level       TEXT NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1,
    is_paused   INTEGER NOT NULL DEFAULT 0,
    paused_at   DATETIME,
    pause_reason TEXT,
    service_status TEXT NOT NULL DEFAULT 'operational',
    status_message TEXT,
    status_color TEXT NOT NULL DEFAULT '#22c55e',
    required_client_version TEXT,
    blocked_client_versions TEXT NOT NULL DEFAULT '[]',
    version_kill_switch INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, level)
);

CREATE TABLE IF NOT EXISTS product_pricing_points (
    id            TEXT PRIMARY KEY,
    product_id    TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    days          INTEGER NOT NULL,
    price         REAL NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resellers (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    owner_user_id TEXT REFERENCES auth_users(id) ON DELETE CASCADE,
    balance       REAL NOT NULL DEFAULT 0,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reseller_sessions (
    id          TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS reseller_product_access (
    id            TEXT PRIMARY KEY,
    reseller_id   TEXT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    product_id    TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    monthly_quota INTEGER,
    monthly_used  INTEGER NOT NULL DEFAULT 0,
    quota_reset_at DATETIME,
    UNIQUE(reseller_id, product_id)
);

CREATE TABLE IF NOT EXISTS reseller_pricing_access (
    id               TEXT PRIMARY KEY,
    reseller_id      TEXT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    pricing_point_id TEXT NOT NULL REFERENCES product_pricing_points(id) ON DELETE CASCADE,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(reseller_id, pricing_point_id)
);

CREATE TABLE IF NOT EXISTS reseller_balance_ledger (
    id            TEXT PRIMARY KEY,
    reseller_id   TEXT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    amount        REAL NOT NULL,
    reason        TEXT NOT NULL,
    created_by    TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_orders (
    id                 TEXT PRIMARY KEY,
    reseller_id        TEXT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    license_id         TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    product_id         TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    pricing_point_id   TEXT NOT NULL REFERENCES product_pricing_points(id) ON DELETE CASCADE,
    amount_paid        REAL NOT NULL,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_users_username       ON auth_users(username);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token       ON auth_sessions(token);
CREATE INDEX IF NOT EXISTS idx_products_app              ON products(app_id);
CREATE INDEX IF NOT EXISTS idx_products_level            ON products(level);
CREATE INDEX IF NOT EXISTS idx_pricing_product           ON product_pricing_points(product_id);
CREATE INDEX IF NOT EXISTS idx_resellers_username        ON resellers(username);
CREATE INDEX IF NOT EXISTS idx_reseller_sessions_token   ON reseller_sessions(token);
CREATE INDEX IF NOT EXISTS idx_reseller_access_reseller  ON reseller_product_access(reseller_id);
CREATE INDEX IF NOT EXISTS idx_reseller_access_product   ON reseller_product_access(product_id);
CREATE INDEX IF NOT EXISTS idx_reseller_price_reseller   ON reseller_pricing_access(reseller_id);
CREATE INDEX IF NOT EXISTS idx_reseller_price_point      ON reseller_pricing_access(pricing_point_id);
CREATE INDEX IF NOT EXISTS idx_orders_reseller           ON key_orders(reseller_id);
CREATE INDEX IF NOT EXISTS idx_orders_license            ON key_orders(license_id);

CREATE TABLE IF NOT EXISTS outage_events (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    product_id TEXT REFERENCES products(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    service_status TEXT NOT NULL,
    status_color TEXT NOT NULL DEFAULT '#22c55e',
    public_message TEXT,
    started_at DATETIME,
    ended_at DATETIME,
    downtime_seconds INTEGER NOT NULL DEFAULT 0,
    compensation_seconds INTEGER NOT NULL DEFAULT 0,
    affected_licenses INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS panels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    app_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS portal_sessions (
    id         TEXT PRIMARY KEY,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
    id              TEXT PRIMARY KEY,
    license_id      TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,
    user_agent      TEXT,
    ip_address      TEXT,
    last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_suspicious   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    key_hash    TEXT NOT NULL UNIQUE,
    key_prefix  TEXT,
    name        TEXT NOT NULL,
    scopes      TEXT DEFAULT 'read',
    is_active   INTEGER DEFAULT 1,
    last_used   DATETIME,
    app_id      TEXT REFERENCES applications(id) ON DELETE CASCADE,
    allowed_ips TEXT,
    usage_count INTEGER NOT NULL DEFAULT 0,
    last_ip     TEXT,
    expires_at  DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS download_tickets (
    id TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    license_id TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    product_id TEXT,
    file_id TEXT NOT NULL REFERENCES app_files(id) ON DELETE CASCADE,
    hwid TEXT NOT NULL,
    client_version TEXT,
    file_sha256 TEXT,
    file_version TEXT,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

"""


async def _get_schema_version(db: aiosqlite.Connection) -> int:
    async with db.execute("PRAGMA user_version") as cur:
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def _set_schema_version(db: aiosqlite.Connection, version: int):
    await db.execute(f"PRAGMA user_version = {int(version)}")


def _discover_migration_files() -> list[tuple[int, Path]]:
    if not MIGRATIONS_DIR.exists():
        return []

    migrations = []
    for path in MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.py"):
        try:
            version = int(path.stem.split("_", 1)[0])
        except ValueError:
            continue
        migrations.append((version, path))
    return sorted(migrations, key=lambda item: item[0])


LATEST_SCHEMA_VERSION = max((version for version, _ in _discover_migration_files()), default=0)


async def _apply_schema_v1(db: aiosqlite.Connection):
    await db.executescript(SCHEMA)

    async with db.execute("PRAGMA table_info(applications)") as cur:
        app_cols = [r[1] for r in await cur.fetchall()]
    if "owner_user_id" not in app_cols:
        await db.execute("ALTER TABLE applications ADD COLUMN owner_user_id TEXT REFERENCES auth_users(id) ON DELETE SET NULL")

    async with db.execute("PRAGMA table_info(resellers)") as cur:
        reseller_cols = [r[1] for r in await cur.fetchall()]
    if "owner_user_id" not in reseller_cols:
        await db.execute("ALTER TABLE resellers ADD COLUMN owner_user_id TEXT REFERENCES auth_users(id) ON DELETE CASCADE")

    async with db.execute("PRAGMA table_info(licenses)") as cur:
        lic_cols = [r[1] for r in await cur.fetchall()]
    if "metadata" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN metadata TEXT")

    if "last_ip" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN last_ip TEXT")
    if "login_strikes" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN login_strikes INTEGER DEFAULT 0")
    if "client_username" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN client_username TEXT")
    if "client_password_hash" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN client_password_hash TEXT")
    if "key_hash" not in lic_cols:
        await db.execute("ALTER TABLE licenses ADD COLUMN key_hash TEXT")

    # One-way migration: existing plaintext keys become masked display values.
    # Operators must back up before upgrading, as documented in the README.
    from utils.crypto import hash_license_key, mask_license_key
    async with db.execute("SELECT id, key FROM licenses WHERE key_hash IS NULL") as cur:
        legacy_licenses = await cur.fetchall()
    for license_row in legacy_licenses:
        await db.execute(
            "UPDATE licenses SET key = ?, key_hash = ? WHERE id = ?",
            (mask_license_key(license_row["key"]), hash_license_key(license_row["key"]), license_row["id"]),
        )
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash)")

    async with db.execute("PRAGMA table_info(admin_users)") as cur:
        user_cols = [r[1] for r in await cur.fetchall()]
    if "theme" not in user_cols:
        await db.execute("ALTER TABLE admin_users ADD COLUMN theme TEXT DEFAULT 'dark'")

    async with db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'") as cur:
        api_keys_exists = await cur.fetchone()
    if not api_keys_exists:
        await db.execute("""
            CREATE TABLE api_keys (
                id          TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
                key_hash    TEXT NOT NULL UNIQUE,
                key_prefix  TEXT,
                name        TEXT NOT NULL,
                scopes      TEXT DEFAULT 'read',
                is_active   INTEGER DEFAULT 1,
                last_used   DATETIME,
                expires_at  DATETIME,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        async with db.execute("PRAGMA table_info(api_keys)") as cur:
            api_key_cols = [r[1] for r in await cur.fetchall()]
        if "key_prefix" not in api_key_cols:
            await db.execute("ALTER TABLE api_keys ADD COLUMN key_prefix TEXT")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)")

    async with db.execute("PRAGMA table_info(app_files)") as cur:
        file_cols = [r[1] for r in await cur.fetchall()]
    if "file_sha256" not in file_cols:
        await db.execute("ALTER TABLE app_files ADD COLUMN file_sha256 TEXT")

    async with db.execute("PRAGMA table_info(news)") as cur:
        news_cols = [r[1] for r in await cur.fetchall()]
    if "app_id" not in news_cols:
        await db.execute("ALTER TABLE news ADD COLUMN app_id TEXT REFERENCES applications(id) ON DELETE CASCADE")

    async with db.execute("PRAGMA table_info(banned_hwids)") as cur:
        ban_cols = [r[1] for r in await cur.fetchall()]
    if "app_id" not in ban_cols:
        await db.execute("ALTER TABLE banned_hwids ADD COLUMN app_id TEXT REFERENCES applications(id) ON DELETE CASCADE")

    async with db.execute("PRAGMA table_info(admin_users)") as cur:
        admin_cols = [r[1] for r in await cur.fetchall()]
    if "two_factor_enabled" not in admin_cols:
        await db.execute("ALTER TABLE admin_users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0")
    if "two_factor_secret" not in admin_cols:
        await db.execute("ALTER TABLE admin_users ADD COLUMN two_factor_secret TEXT")

    await db.execute("CREATE INDEX IF NOT EXISTS idx_apps_owner ON applications(owner_user_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_resellers_owner ON resellers(owner_user_id)")


async def _apply_schema_v2(db: aiosqlite.Connection):
    await db.execute("""
        CREATE TABLE IF NOT EXISTS temp_2fa_sessions (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
            role       TEXT NOT NULL,
            token      TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_temp_2fa_token ON temp_2fa_sessions(token)")


async def _apply_schema_v3(db: aiosqlite.Connection):
    await db.execute("DROP TABLE IF EXISTS device_fingerprints")
    await db.execute("""
        CREATE TABLE device_fingerprints (
            id              TEXT PRIMARY KEY,
            license_id      TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            fingerprint     TEXT NOT NULL,
            user_agent      TEXT,
            ip_address      TEXT,
            last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_suspicious   INTEGER DEFAULT 0
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_device_fingerprints_license ON device_fingerprints(license_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_device_fingerprints_fingerprint ON device_fingerprints(fingerprint)")


async def run_migrations(db: aiosqlite.Connection):
    current_version = await _get_schema_version(db)
    migrations = _discover_migration_files()

    for version, path in migrations:
        if version <= current_version:
            continue
        if version != current_version + 1:
            raise RuntimeError(
                f"Migration gap detected: expected version {current_version + 1} but found {version} at {path.name}"
            )

        module_name = f"_enauth_migration_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if not spec or not spec.loader:
            raise RuntimeError(f"Unable to load migration file: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        apply = getattr(module, "apply", None)
        if apply is None:
            raise RuntimeError(f"Migration file missing apply(db): {path}")

        await apply(db)
        current_version = version
        await _set_schema_version(db, current_version)
        await db.commit()

    # Best-effort compatibility for databases that predate this migration system.
    await db.execute("CREATE INDEX IF NOT EXISTS idx_apps_owner ON applications(owner_user_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_resellers_owner ON resellers(owner_user_id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_temp_2fa_token ON temp_2fa_sessions(token)")
    await db.commit()
async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
    finally:
        await db.close()


async def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await run_migrations(db)
