# EnAuth

A comprehensive authentication and licensing system with support for license keys, HWID binding, multi-level products, resellers, and a full admin panel.

## Features

- **License Management**: Create, manage, and revoke license keys with expiration dates
- **HWID Binding**: Secure hardware ID binding with configurable limits per license
- **Multi-Level Products**: Support for different product tiers and pricing
- **Reseller System**: Built-in reseller management with balance and pricing controls
- **Admin Panel**: Full-featured web interface for managing all aspects of the system
- **Two-Factor Authentication**: TOTP-based 2FA for admin accounts
- **Security**: Hashed license storage, secure dashboard cookies, rate limiting, durable replay protection, and audit logging
- **C++ SDK**: C++17 Windows SDK with strict TLS validation, timeouts, and response limits
- **Audit Logging**: Comprehensive logging of all actions

## Installation

### Prerequisites

- Python 3.12 or later
- pip package manager

### Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd server
```

2. Install dependencies:
```bash
# Windows
install_deps.bat

# Linux/Mac
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run the server:
```bash
# Windows
start_server.bat

# Linux/Mac
python main.py
```

5. Access the admin panel:
```
http://localhost:8080/panel/
```

## Self-Hosting Guide

This project is designed to be self-hosted. The sections below cover the common things operators usually need after the first launch.

### First Run Checklist

Before starting the server for the first time:

1. Copy `.env.example` to `.env`.
2. Set `HOST`, `PORT`, and `DB_PATH` if you want custom values.
3. Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` if you want a known initial admin login.
4. Generate different random values for `LICENSE_LOOKUP_KEY` and `LICENSE_ENCRYPTION_KEY`. Back both up separately; losing them makes existing keys unusable.
5. If you do not set `ADMIN_PASSWORD`, the server generates one on first startup and prints it once to the terminal.
6. Use HTTPS directly or place the service behind a trusted reverse proxy. Set `COOKIE_SECURE=true` when the public URL is HTTPS.
7. Keep `ALLOW_LEGACY_PROTOCOL=false` for new deployments. Enable it only temporarily when migrating pre-v2 clients.

### Local Development Run

If you just want to test the project locally:

```bash
python main.py
```

## Ubuntu VPS installation

On Ubuntu 22.04 or newer, clone the repository and run the included installer
from the repository root:

```bash
chmod +x deploy/install_ubuntu.sh
sudo ./deploy/install_ubuntu.sh
```

The installer adds Docker and Compose when missing, creates a locked-down
`.env`, generates a cryptographically random license-key pepper and admin
password, starts the service, and waits for the health check. The database and
logs remain in the persistent `data` directory.

The application listens on port 8080. Place Nginx, Caddy, or another HTTPS
reverse proxy in front of it before public use; an Nginx starting point is
provided at `deploy/nginx.conf.example`. Set `CORS_ORIGINS` to the exact public
HTTPS origin and keep `COOKIE_SECURE=true` in production.

## Discord management bot

The optional bot in `discord_bot/` provides private slash commands for
licenses, sessions, builds, news, variables, logs, and HWID bans. Create its
app-bound, separately revocable key from the owner-only **Discord bot** panel,
invite the bot from that same page, then use the key with `/setup`. The key is
shown once and encrypted at rest by the bot. See
`discord_bot/README.md` for installation instructions.

Then open:

```text
http://localhost:8080/panel/
```

### Docker Deployment

The repository includes Docker support if you want a reproducible deployment with persistent data.

#### Using Docker Compose

From the project root:

```bash
cp .env.example .env
# Set ADMIN_PASSWORD, LICENSE_LOOKUP_KEY, and LICENSE_ENCRYPTION_KEY first.
docker compose up -d --build
```

Compose refuses to start without those three secrets. Its default origin is
`http://localhost:8080`; set `CORS_ORIGINS` to the exact public dashboard
origin before deployment.

If your Docker installation still uses the older command, this also works:

```bash
docker-compose up -d --build
```

This starts the server on port `8080` and stores the SQLite database and logs in `./data` on the host machine.

To view logs:

```bash
docker compose logs -f
```

To stop the container:

```bash
docker compose down
```

#### Using Plain Docker

If you prefer to run the image manually:

```bash
docker build -t enauth .
docker run -d \
  --name enauth-server \
  -p 8080:8080 \
  -e HOST=0.0.0.0 \
  -e PORT=8080 \
  -e DB_PATH=/app/data/enauth.db \
  -v "$(pwd)/data:/app/data" \
  enauth
```

If you are on Windows PowerShell, the volume path syntax may need to be adjusted for your shell environment.

#### Docker Notes

1. Keep the `./data` folder or mounted volume if you want to preserve the SQLite database and logs.
2. Set `ADMIN_PASSWORD` before first startup if you want a known initial admin password.
3. Check `docker compose logs -f` if the container exits or the panel does not load.
4. If you expose the container to the internet, prefer a reverse proxy in front of it for TLS and header handling.

### Reverse Proxy Setup

For production, it is usually better to run the app behind a reverse proxy.

An example Nginx configuration is included in [`deploy/nginx.conf.example`](C:/Users/Weirdo/Desktop/enauth/.vscode/server/server/deploy/nginx.conf.example).

Recommended proxy responsibilities:

1. Terminate TLS.
2. Forward requests to the FastAPI server.
3. Preserve the original client IP.
4. Set trusted proxy headers only from your own proxy layer.

Important note:

- The app reads `X-Forwarded-For` for client IP detection, so only trust that header if your proxy is the only thing allowed to reach the app directly.

See the changelog section below for release notes and upgrade highlights.

### SSL / HTTPS

You can run the server with SSL directly by setting:

- `SSL_CERT`
- `SSL_KEY`

If both files exist, the server will start with HTTPS enabled. For most deployments, using a reverse proxy with TLS is still the easier long-term setup.

### Backups

Your main data lives in the SQLite database file defined by `DB_PATH`.

#### Backup steps

1. Stop the server.
2. Copy the database file somewhere safe.
3. Store a copy of your `.env` file separately.
4. If you store uploaded files or other assets outside the database, back those up too.

Example:

```bash
cp enauth.db enauth.db.backup
cp .env .env.backup
```

#### Restore steps

1. Stop the server.
2. Replace the database file with the backup copy.
3. Restore your `.env` file if needed.
4. Start the server again.

### Upgrading

When updating to a newer release:

1. Read the release notes or changelog first.
2. Back up `enauth.db`.
3. Update dependencies.
4. Start the server and check the logs for migration or startup warnings.

The database now uses versioned migrations, so schema changes should be applied automatically on startup. Keeping a backup before upgrading is still recommended.

### Admin Login

On first launch, the server creates a default admin account if no admin users exist.

- Default username: `admin` unless overridden by `ADMIN_USERNAME`
- Default password: `ADMIN_PASSWORD` if set, otherwise a generated password is logged on startup

If you lose the admin password, use the password reset flow or replace the database during recovery.

### Common Tasks

#### Create an application

Use the admin panel to create a new application, then note its `app_id` and `secret_key`. The client SDK needs both values.

#### Create a license

Licenses are tied to an application. After creating a license, you can:

- bind HWIDs
- set expiration dates
- assign products
- ban or unban the key

#### Add news

Use the admin panel to publish news items for a specific application. Clients can fetch them through the `/api/client/news` endpoint.

#### Upload files

Upload application files from the admin panel if you want clients to download signed or managed assets.

#### Manage resellers

Create reseller accounts from the admin panel, assign product access and pricing access, then let them sell keys from their own panel.

### Troubleshooting

#### The server will not start

Check the following:

1. Python version matches the requirements.
2. Dependencies are installed.
3. `DB_PATH` points to a writable location.
4. SSL certificate paths are valid if SSL is enabled.
5. The port is not already in use.

#### The admin panel loads but login fails

Try these checks:

1. Confirm you are using the correct username and password.
2. Check whether 2FA is enabled on the account.
3. Make sure the session token is being sent as a `Bearer` token if you are using the API directly.
4. Review the server logs for authentication errors.

#### Clients keep getting `REPLAY_ATTACK`

That usually means one of the following:

1. The request timestamp is too old or too far in the future.
2. The client is reusing a previous nonce or request payload.
3. The server and client clocks are out of sync.

#### Clients keep getting `INVALID_SIGNATURE`

Check that:

1. The client is using the correct app secret.
2. The `app_id` matches the application that owns the secret.
3. The request body was not modified before sending.

#### Clients keep getting `BANNED_HWID`

That means the HWID is present in the banned list for the application. Remove it from the admin panel if you want to allow it again.

#### Login works once, then the next login fails

This can happen if the key is already tied to a session or if the previous session was invalidated. Check the active sessions list in the admin panel.

#### The database seems corrupt or locked

SQLite can become locked if multiple processes are writing to the same file or if the process was interrupted. Make sure:

1. Only one server instance is writing to the same database file.
2. The database file is on a stable disk.
3. You are not restoring a backup while the server is still running.

#### Password reset token is not usable

Password reset tokens expire after a limited time. If you generated one in debug mode, check the logs or the response body depending on your configuration.

#### I cannot reach the API from another machine

Check:

1. `HOST` is set to `0.0.0.0` if you want external access.
2. Firewall rules allow inbound traffic on the chosen port.
3. Your reverse proxy is forwarding requests correctly.

### Operational Notes

- The server uses SQLite by default, so it is simple to deploy but not ideal for heavy concurrent writes.
- The maintenance loop clears expired sessions and stale runtime state automatically.
- Logs are written to `server.log` with rotation enabled.
- The app exposes `/health` for basic health monitoring.

### Product outage controls

- Open **Applications** and use **Pause All** when an entire application is unavailable.
- Open **Product levels** and use **Pause** when only one product/level is unavailable.
- Pausing immediately closes only the affected client sessions and blocks new affected logins.
- On resume, EnAuth automatically restores the exact paused duration. Enter optional extra
  compensation days when prompted (for example, enter `2` after a four-day outage to grant
  six days total).
- Lifetime entitlements remain lifetime. Other product levels keep running and their expiry
  dates are not changed during a product-level outage.
- The dashboard's **Operational Monitoring** panel checks database integrity, recent login
  failures, paused services, uptime, and important production configuration settings.
- Each application has a public status page at `/panel/status.html?app=YOUR_APP_ID` with
  current product health and sanitized incident history.
- Product status can use any short owner-defined label and a six-digit hex color from
  **Product levels → Set Status**. Common examples are Operational, Degraded,
  Maintenance, Updating, Delayed, or Offline.
- Use **Licenses → Products** to add, remove, extend, pause, or resume one product
  entitlement without changing the other products on that license.
- Files are private in the customer portal unless the owner explicitly enables
  **Allow customers to download this file**. Downloads may be restricted to licenses
  that own one selected product. Existing files remain private after upgrading.
- The customer portal displays owned products, separate expiration dates, service status,
  compensation received, and the configured HWID-reset cooldown.
- Resellers sign in from the main login page using **Reseller Sign In**.
- New license keys are stored as both a one-way lookup hash and AES-GCM authenticated
  ciphertext, allowing authorized admins, the issuing reseller, and the owning customer
  portal to copy them later without plaintext database storage. Keys created before this
  upgrade remain masked because their original values cannot be recovered retroactively.

## Configuration

Environment variables (see `.env.example`):

- `HOST`: Server host (default: 0.0.0.0)
- `PORT`: Server port (default: 8080)
- `DEBUG`: Enable debug mode (default: false)
- `DB_PATH`: Database file path (default: enauth.db)
- `ADMIN_USERNAME`: Default admin username
- `ADMIN_PASSWORD`: Default admin password (auto-generated if not set)
- `CORS_ORIGINS`: Comma-separated list of allowed origins
- `SSL_CERT`: Path to SSL certificate file
- `SSL_KEY`: Path to SSL key file

### Security Settings

- `TIMESTAMP_TOLERANCE`: Request timestamp tolerance in seconds (default: 60)
- `SESSION_DURATION`: Client session duration in seconds (default: 86400)
- `SESSION_TOKEN_SECONDS`: Protocol-v2 bearer-token lifetime before rotation (default: 300)
- `DOWNLOAD_TICKET_SECONDS`: One-use SDK download-ticket lifetime (default: 60)
- `MAX_BUILD_BYTES`: Maximum uploaded build/loader size, capped at 100 MiB
- `MAX_REQUEST_BYTES`: Multipart request limit for the three upload endpoints (default and ceiling: 105 MiB)
- `MAX_JSON_BYTES`: Limit for all other request bodies (default: 2 MiB); actual streamed bytes are counted even without Content-Length
- `AUTO_BACKUP_HOURS`: Verified scheduled-backup interval; `0` disables it
- `BACKUP_ENCRYPTION_KEY`: Encrypts signing-key copies stored beside scheduled database backups

Loader releases are managed from **Loader releases** in the panel. Publish each
new version under the same logical filename (for example `loader.exe`); EnAuth
archives the previous release automatically. SDK applications can call
`AutoUpdateLoader("loader.exe", "1.2.0")` after login and validation. A `true`
result means the signed and SHA-256-verified update was staged and the process
should exit immediately so the updater can replace and restart it.
- `MAX_LOGIN_STRIKES`: Maximum failed login attempts before lockout (default: 5)
- `NONCE_CACHE_SIZE`: Maximum nonces to remember for replay protection (default: 10000)
- `NONCE_TTL`: Nonce time-to-live in seconds (default: 120)

### Rate Limiting

- `RATE_LIMIT_INIT`: Init endpoint (default: 20/minute)
- `RATE_LIMIT_NEWS`: News endpoint (default: 15/minute)
- `RATE_LIMIT_LOGIN`: Login endpoint (default: 8/minute)
- `RATE_LIMIT_HEARTBEAT`: Heartbeat endpoint (default: 60/minute)
- `RATE_LIMIT_LOGOUT`: Logout endpoint (default: 20/minute)
- `RATE_LIMIT_VALIDATE`: Validate endpoint (default: 30/minute)
- `RATE_LIMIT_DOWNLOAD`: Download endpoint (default: 10/minute)

## API Documentation

When running in debug mode (`DEBUG=true`), API documentation is available at:
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

### Management API keys

Create an app-bound API key from **API Keys** in the owner panel and send it in
the `X-API-Key` header. Prefer the smallest required scopes and an IP/CIDR
allowlist. The management API is rooted at `/api/integrations`.

Only owner accounts may issue, rotate, update, or revoke management API keys.
Scope names are validated when a key is created or edited: unknown scopes and
unknown resource wildcards are rejected, duplicates are removed, and names are
stored in a canonical lowercase form.

Each key may also have its own requests-per-minute ceiling. The counter is
updated atomically in SQLite, so the limit is shared by all server workers and
survives ordinary process concurrency rather than existing only in memory.

Every `/api/integrations` response is marked `no-store, private`, varies on the
credential headers, and is excluded from indexing. Requests supplying both an
API key and Discord key are rejected instead of silently choosing the more
privileged credential.

Common license operations:

| Operation | Method and path | Required scope |
| --- | --- | --- |
| List keys, product names, and levels | `GET /apps/{app_id}/licenses` | `licenses.read` |
| Inspect one key's levels and metadata | `GET /apps/{app_id}/licenses/{id_or_key}` | `licenses.read` |
| Generate keys for a level | `POST /apps/{app_id}/licenses` | `licenses.generate` |
| Update status, expiry, HWID limit, notes, or metadata | `PATCH /apps/{app_id}/licenses/{id_or_key}` | `licenses.modify` |
| Ban/blacklist a key | `POST /apps/{app_id}/licenses/{id_or_key}/blacklist` | `licenses.modify` |
| Unblacklist a key | `POST /apps/{app_id}/licenses/{id_or_key}/unblacklist` | `licenses.modify` |
| Reset a key's HWID bindings | `POST /apps/{app_id}/licenses/{id_or_key}/reset-hwid` | `licenses.modify` |
| Add a level to a key | `POST /apps/{app_id}/licenses/{id_or_key}/products` | `licenses.modify` |
| Pause/resume one level | `POST /apps/{app_id}/licenses/{id_or_key}/products/{product_id}/pause` or `/resume` | `licenses.modify` |
| Remove a level from a key | `DELETE /apps/{app_id}/licenses/{id_or_key}/products/{product_id}` | `licenses.modify` |
| Permanently delete a key | `DELETE /apps/{app_id}/licenses/{id_or_key}` | `licenses.delete` |

Large inventories can use `GET /apps/{app_id}/licenses/page` for a structured
response containing `items` plus `total`, `limit`, `offset`, `next_offset`, and
`has_more`. Both the paginated endpoint and the backwards-compatible list route
accept `search`, `status`, `product_level`, `expires_before`, and
`expires_after` filters, with a stable `created_at,id` ordering.

Bulk license automation accepts up to 100 IDs or raw keys per request. Inputs
are fully resolved and deduplicated before the transaction starts, so an unknown
identifier cannot leave a partially modified batch.

| Bulk operation | Method and path | Required scope |
| --- | --- | --- |
| Blacklist keys | `POST /apps/{app_id}/licenses/bulk/blacklist` | `licenses.modify` |
| Unblacklist keys | `POST /apps/{app_id}/licenses/bulk/unblacklist` | `licenses.modify` |
| Reset HWIDs and device fingerprints | `POST /apps/{app_id}/licenses/bulk/reset-hwid` | `licenses.modify` |
| Permanently delete keys | `POST /apps/{app_id}/licenses/bulk/delete` | `licenses.delete` |

The delete body must include `"confirm":"DELETE"`. Bulk blacklisting and HWID
resets immediately revoke affected sessions.

Product-level administration is also available through API keys:

| Operation | Method and path | Required scope |
| --- | --- | --- |
| List levels and version policies | `GET /apps/{app_id}/products` | `products.read` |
| Create a level | `POST /apps/{app_id}/products` | `products.modify` |
| Rename, deactivate, or change version policy | `PATCH /apps/{app_id}/products/{product_id}` | `products.modify` |
| Pause/resume a level-wide outage | `POST /apps/{app_id}/products/{product_id}/pause` or `/resume` | `products.modify` |
| Preview outage restoration | `GET /apps/{app_id}/products/{product_id}/resume-preview` | `products.read` |
| Delete a level | `DELETE /apps/{app_id}/products/{product_id}?force=true` | `products.delete` |

Deleting a product with assigned licenses is rejected unless `force=true` is
explicitly supplied. Deactivation and client-version policy changes revoke that
product's current sessions so the new policy is enforced on the next login.

Unbound owner API keys can administer applications:

| Operation | Method and path | Required scope |
| --- | --- | --- |
| Create an application | `POST /apps` | `apps.create` |
| Update app name, version, or download-abuse policy | `PATCH /apps/{app_id}` | `apps.modify` |
| Rotate the legacy application secret | `POST /apps/{app_id}/rotate-secret` | `apps.secrets` |
| Delete an application | `DELETE /apps/{app_id}?force=true` | `apps.delete` |

Initial and rotated application secrets are returned only by their respective
calls. Secret rotation requires its own high-risk scope and is not granted by
the legacy `write` scope. App-bound keys cannot create or access other apps.

`licenses.read` returns a masked key plus `products` and `levels`. Add the
separate high-risk `licenses.reveal` scope only when the integration genuinely
needs stored plaintext keys. Newly generated keys are returned once by the
generation call regardless, so the caller can deliver them without retaining
ongoing reveal access. Destructive `*.delete` operations likewise require an
explicit delete scope; the legacy broad `write` scope does not grant them.

```bash
# Discover available product names and level identifiers.
curl -H "X-API-Key: $ENAUT_API_KEY" \
  "https://auth.example.com/api/integrations/apps/APP_ID"

# Generate two 30-day keys for level "pro".
curl -X POST -H "X-API-Key: $ENAUT_API_KEY" \
  -H "Idempotency-Key: order-2026-000042" \
  -H "Content-Type: application/json" \
  -d '{"product_level":"pro","duration_hours":720,"count":2,"max_hwids":1}' \
  "https://auth.example.com/api/integrations/apps/APP_ID/licenses"

# Read the product names and levels assigned to a key without revealing it.
curl -H "X-API-Key: $ENAUT_API_KEY" \
  "https://auth.example.com/api/integrations/apps/APP_ID/licenses/LICENSE_ID"
```

Use `GET /apps/{app_id}/capabilities` to verify what the presented credential
can do. An owner key with the `admin` scope can use every management operation,
but narrowly scoped, app-bound keys are recommended for production automation.

Any valid credential can call `GET /api/integrations/credential` or its bound
app's `/capabilities` route even when it does not have `apps.read`. The response
contains only its ID, kind, app binding, normalized scopes, effective
capabilities, IP/expiry/rate policy, and API limits—never its hash or secret.

Other least-privilege scopes include `logs.read`, `sessions.read`,
`sessions.modify`, `builds.read`, `builds.upload`, `builds.delete`, `news.read`,
`news.modify`, `news.delete`, `hwids.read`, and `hwids.modify`. Global variable
access is split between `variables.read`, `variables.modify`,
`variables.secrets`, and `variables.delete`; secret values stay masked unless
`variables.secrets` is present, and modifying or declassifying an existing
secret also requires that explicit high-risk scope.

Generation accepts an optional `Idempotency-Key` header containing 8-200 safe
ASCII characters. Repeating the same request with the same credential and key
within 24 hours returns the original generated licenses without creating more.
Reusing it with different parameters returns HTTP 409. Retry records contain
only license IDs and response metadata; full keys are reconstructed from their
existing AES-GCM encrypted storage rather than copied into a plaintext cache.

## Client SDK Integration

See `sdk/README.md` for detailed C++ SDK integration instructions.

Basic usage:
```cpp
#include "enauth.h"

enauth::Client client(
    "https://your-server.com",
    "your-app-id",
    "1.0.0",
    "YOUR_RESPONSE_SIGNING_PUBLIC_KEY"
);

auto result = client.Init();
if (result.success) {
    auto login = client.Login("YOUR-LICENSE-KEY");
    if (login.success) {
        // Application authenticated
    }
}
```

## Database Schema

The system uses SQLite with the following main tables:
- `applications`: Application definitions
- `licenses`: License keys and their properties
- `hwids`: Hardware ID bindings
- `sessions`: Active client sessions
- `admin_users`: Admin accounts
- `products`: Product tiers
- `resellers`: Reseller accounts
- `logs`: Audit log

## Security Considerations

- TLS is mandatory for non-local SDK connections; certificate errors are never ignored
- License keys are returned only when created and stored as server-peppered hashes
- Dashboard sessions use `HttpOnly`, `SameSite=Strict` cookies rather than browser storage
- Replay nonces are stored in SQLite so protection survives restarts and multiple workers
- Protocol 2 SDK builds contain no application secret; TLS protects client requests
- Every server response is asymmetrically signed and bound to the exact request context
- A client-side license check can be patched; keep high-value authorization decisions server-side
- Nonce-based replay protection
- Rate limiting on all endpoints
- HWID validation requires SHA-256/512 hashes
- Brute force protection with strike counting

## License

This project is provided as-is for authentication and licensing purposes.

## Support

For issues and questions, please refer to the project documentation or contact the maintainers.

## Changelog

### Unreleased

- Allowed `licenses.read` API keys to inspect assigned product names and levels
  without granting access to plaintext license credentials.
- Prevented internal lookup hashes, encrypted key material, and client password
  hashes from leaking through license-detail responses.
- Required explicit scopes for destructive API deletes instead of granting them
  to legacy broad `write` keys.
- Added explicit API aliases for blacklisting and unblacklisting license keys.
- Added API-key operations to add, pause, resume, compensate, and remove one
  product level on a license without disturbing its other levels.
- Added scoped license updates for status, expiration/lifetime, HWID limits,
  notes, and structured metadata, with bound-seat validation and session revocation.
- Added scoped product-level listing, creation, configuration, version-policy
  management, and guarded deletion through API keys.
- Added product outage pause/resume APIs with session revocation, downtime
  restoration, optional compensation, and a read-only impact preview.
- Added scoped application creation, updates, one-time secret rotation, and
  guarded deletion. Bound keys remain limited to their configured application.
- Restricted management API-key issuance and lifecycle operations to owners and
  added strict scope validation/canonicalization to prevent configuration drift.
- Added optional durable per-key rate limits with atomic shared counters and
  owner-panel controls to contain leaked or malfunctioning integrations.
- Added atomic bulk blacklist, unblacklist, HWID/device reset, and confirmed
  deletion operations for up to 100 license identifiers per API request.
- Added concurrency-safe, 24-hour idempotency for license generation so network
  retries cannot accidentally mint duplicate batches or duplicate plaintext keys.
- Replaced remaining broad integration permissions with resource-specific scopes
  for logs, sessions, builds, news, variables, and HWID bans while preserving
  documented legacy `read`/`write` compatibility for non-destructive operations.
- Marked all management API responses non-cacheable and rejected requests that
  ambiguously supply both supported integration credential types.
- Added stable license pagination, totals, offsets, and server-side filtering by
  status, product level, expiration window, identifier, key, or notes.
- Added scope-independent credential and capability introspection so narrowly
  scoped automation can safely discover its own effective permissions and limits.
- Added application-wide and per-product outage pause/resume controls.
- Added automatic downtime restoration plus optional compensation for affected entitlements.
- Added operational monitoring and production configuration checks to the dashboard.
- Added product-aware client sessions and SDK pause status values.

### 1.1.0

Release focus: self-hosting readiness, security hardening, and upgrade safety.

#### Added

- Versioned SQLite migrations with startup migration discovery
- Persistent temporary 2FA sessions stored in SQLite
- CI workflow for automated test runs on GitHub Actions
- Security and migration test coverage for admin and client flows
- Expanded self-hosting documentation in the README

#### Changed

- Tightened owner-only admin permission checks
- Added rate limiting to sensitive auth endpoints
- Removed plaintext password reset token logging
- Improved logger configuration for file path and rotation settings

#### Notes

- Back up `enauth.db` before upgrading.
- If you run behind a reverse proxy, only trust forwarded headers from your own proxy layer.

#### Quick Release Summary

- Better self-hosting docs
- Safer admin and client auth paths
- Versioned schema migrations
- CI and tests for the important flows

### 1.0.0

- Initial public release of the EnAuth server
