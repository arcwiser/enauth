# EnAuth C++ SDK

Windows C++17 client SDK for EnAuth authentication and licensing system. The
EnAuth server can run on an Ubuntu VPS; the Windows client connects to its
public HTTPS URL.

## Requirements

- Windows 7+
- C++17 or later
- Link: `winhttp.lib bcrypt.lib crypt32.lib`

## Integration

### 1. Copy SDK Files

Copy the following files to your project:
- `enauth.h`
- `enauth.cpp`
- `hwid.cpp`
- `crypto_win.cpp`
- `json.hpp`
- `string_obfuscation.h`

### 2. Link Libraries

Add to your project settings:
```
winhttp.lib bcrypt.lib crypt32.lib
```

### 3. Basic Usage

```cpp
#include "enauth.h"

// Initialize client
enauth::Client client(
    "https://your-server.com",  // Server URL
    "your-app-id",              // Application ID from admin panel
    "1.0.0",                   // Application version
    "your-128-char-response-signing-public-key"
);

// Validate version with server
auto init = client.Init();
if (!init.success) {
    // Handle error (check init.status)
    if (init.status == enauth::Status::OutdatedVersion) {
        // Update required
    }
    return;
}

// Login with license key
auto login = client.Login("YOUR-LICENSE-KEY");
if (!login.success) {
    // Handle error (check login.status)
    return;
}

// Access variables
std::string featureFlag = client.GetVariable("feature_enabled", "false");

// Send heartbeat periodically
auto hb = client.Heartbeat();
if (!hb.success) {
    // Session expired
}

// Logout when done
client.Logout();
```

### 4. Automatic Heartbeat

```cpp
// Start background heartbeat thread
client.StartHeartbeatThread(60, []() {
    // Called when session expires
    // Handle reconnection or shutdown
});

// ... your application logic ...

// Stop heartbeat before destruction
client.StopHeartbeatThread();
```

### 5. Download Files

```cpp
// Download a file from the server
std::vector<unsigned char> fileData = client.DownloadFile("config.json");
if (!fileData.empty()) {
    // Process file data
}
```

SDK 2.6 downloads are returned only in an authenticated AES-256-GCM envelope derived
from the one-use ticket, current rotating session token, device HWID, and exact
file ID. `DownloadFile` verifies the signed server response and SHA-256 digest,
requires the name, file ID, release version, file type, and digest to match the
one-use ticket, then returns the plaintext bytes in memory. The older plaintext
ticket-envelope fallback is rejected; the SDK does not save downloads to disk.

### 6. Get News

```cpp
// Fetch news items (no login required after Init)
auto news = client.GetNews();
if (news.success) {
    for (const auto& item : news.items) {
        std::cout << item.title << ": " << item.content << std::endl;
    }
}
```

## Status Codes

Check `Status` enum in `enauth.h` for all possible status codes:
- `Success` - Operation succeeded
- `InvalidApp` - Application ID not found
- `OutdatedVersion` - Client version mismatch
- `InvalidKey` - License key not found
- `ExpiredKey` - License expired
- `BannedKey` - License banned
- `BannedHwid` - Hardware ID banned
- `MaxHwids` - Maximum HWID limit reached
- `SessionExpired` - Session expired
- `NetworkError` - Network connection failed
- `ServerError` - Server error
- `DecryptError` - Decryption failed
- `ReplayAttack` - Replay attack detected
- `LevelRequired` - Product level required
- `LevelNotAllowed` - Product level not allowed
- `SuspiciousLogin` - IP change detected
- `Unknown` - Unknown error

## Security Features

The SDK includes:
- Strict operating-system TLS certificate validation
- HTTPS enforcement for every non-local server
- Network timeouts and a 4 MiB response limit
- TLS transport protection with server-side authorization on every protected operation
- Signed payload delivery bound to the exact application, endpoint, request nonce,
  timestamp, and short absolute response expiry
- ECDSA P-256 server response verification. Only the public key is embedded in
  the SDK; the signing private key stays on the server.
- Cryptographically random per-request replay nonces
- Fail-closed asymmetric server signature, request-context, and expiry validation
- Strict response schemas and size limits for session tokens, messages, variables,
  news, and release metadata. Successful authentication and token rotation fail
  closed when a required token is missing or malformed; raw responses and internal
  exception details are never copied into public error messages.
- Interruptible, single-owner heartbeat worker with bounded intervals. Starting it
  again safely replaces the previous worker, and any failed heartbeat invalidates
  the local session immediately before the expiry callback runs.
- Release builds enable CFG, CET shadow-stack compatibility, Spectre mitigations,
  ASLR, DEP, stack checks, and link-time optimization when built with MSVC
- Post-login requests include the device HWID so copied session tokens can be
  revoked. `REQUIRE_SESSION_HWID` defaults to `true`, so legacy token-only
  requests are rejected unless an operator explicitly opts out.
- The SDK's free local integrity checks are enabled by default by the example
  CMake project and can be disabled explicitly with
  `-DENAUTH_ENABLE_ANTI_DEBUG=OFF` for development troubleshooting.
- Replay attack protection
- Short-lived, one-use file tickets bound to the license, application, product,
  session, HWID, client version, file ID, file version, and file digest
- SDK 2.2 protected files use a fresh authenticated AES-256-GCM ticket envelope.
  The response is also sent with `no-store` cache controls to discourage browsers,
  proxies, and other intermediaries from retaining it.
- The SDK decrypts the file only after signature and ticket checks, verifies its
  SHA-256 digest, and keeps the result in memory unless the application chooses
  to write it elsewhere.
- Layered runtime secret storage using a per-process AES-256-GCM key plus a
  position-varying XOR transform (replacing the previous single-byte XOR-only storage)
- Local anti-debugging and integrity checks enabled by default in the example build
- HWID collection and validation

Protocol v2 contains no application secret. The SDK carries only the public
response-verification key. Do not rely on a local license check to protect
server-side privileges.

Loader builds can opt into verified automatic updates after authentication:

```cpp
if (client.AutoUpdateLoader("loader.exe", "1.2.0")) {
    return 0; // exit promptly; the staged updater replaces and restarts this executable
}
```

The loader release is delivered through a one-use download ticket, the signed
response is verified, and its SHA-256 digest is checked before replacement.
The updater also validates the PE structure, executable type, and target CPU,
rejects command-sensitive installation paths, and uses exclusive randomized
staging files with write-through flushes. The running process is never overwritten
in place.

### Protection boundary

These controls prevent ordinary link sharing, ticket replay, using a ticket on a
different device or session, undetected response modification, and casual theft
from HTTP caches or temporary download files. They cannot make extraction
impossible on a customer-controlled computer: executable plaintext must exist in
memory while it runs, so a sufficiently capable local attacker can still inspect
or dump that process. Keep valuable authorization and secrets on the server,
deliver only what the current entitlement needs, revoke compromised versions,
and prefer a small loader plus a protected payload over shipping permanent
credentials in the client.

## HWID Collection

SDK 2.4 builds a versioned device fingerprint from the SMBIOS system UUID,
physical-drive serial, Windows Machine GUID, system-volume serial, and CPU
signature. Known placeholder OEM values are discarded, and at least two strong
signals must be available before the v2 fingerprint is used. Computer names and
MAC addresses are deliberately excluded as primary identifiers because they are
easy to change and cause avoidable false device resets.

Raw hardware identifiers never leave the client: normalized values are combined
and SHA-256 hashed locally. It also generates a random 256-bit installation secret,
seals it with Windows DPAPI, and mixes it into the final fingerprint. Copying
serial strings or the encrypted registry value to another Windows account or
installation does not reproduce the same result. On the first SDK 2.4 login, the
client also submits its previous hashes for a one-time server-side binding upgrade. The old value must
already belong to that license, so existing customers do not consume another
HWID slot during migration. Subsequent session requests use only the v2 hash.

No user-mode HWID is impossible to spoof on a machine controlled by an attacker.
Treat it as a strong account-binding and risk signal, not as a hardware root of
trust; keep authorization, entitlements, and sensitive decisions on the server.

## Error Handling

Always check the `success` field of result structs and examine the `status` field for error details:

```cpp
auto result = client.Login(key);
if (!result.success) {
    switch (result.status) {
        case enauth::Status::InvalidKey:
            std::cerr << "Invalid license key" << std::endl;
            break;
        case enauth::Status::ExpiredKey:
            std::cerr << "License expired" << std::endl;
            break;
        // ... handle other statuses
        default:
            std::cerr << "Error: " << result.message << std::endl;
    }
}
```

## Thread Safety

The client is not thread-safe. Use synchronization if accessing from multiple threads, or create separate client instances per thread.

## Building

### Ready-to-run example

The `example` directory contains a console client and a Windows bootstrapper.
It detects CMake and the Visual Studio C++ Build Tools, installs either through
Windows Package Manager when missing, and builds the SDK example.

```powershell
cd sdk\example
.\build.bat
.\build\Release\enauth-example.exe
```

The example is preconfigured with the obfuscated production endpoint
`https://auth.olsoftwares.com`. Change that literal in `example/main.cpp` when
building for a different EnAuth deployment.

Before building, replace `REPLACE_WITH_APPLICATION_ID` and
`REPLACE_WITH_RESPONSE_SIGNING_PUBLIC_KEY` in `example/main.cpp`. Retrieve the
public signing key from the owner-only Discord integration page or
`GET /api/admin/response-signing-public-key`. The server creates its private
key on first startup at `RESPONSE_SIGNING_KEY_PATH`; back that file up and never
ship it with a client. Version, optional product/level enforcement, protected
download name, and heartbeat interval are compile-time settings in the same
configuration block. The end user only enters their license key; the example
does not read configuration from environment variables.

The example links every SDK implementation file. Its Release configuration
enables the SDK anti-debug path, control-flow guard, stack checks, ASLR, DEP,
and high-entropy ASLR. Layered in-memory field protection, HWID collection,
strict TLS validation, persistent replay protection, asymmetric response
verification, and encrypted session storage are performed automatically inside
the SDK rather than called separately by application code.

SDK 2.5 additionally enables TLS certificate-revocation checks, rejects redirects
and ambiguous base URLs, fails on partial HTTP reads, enforces response and input
size limits, requires successful initialization before login, and clears cached
session state whenever validation can no longer be proven.

SDK 2.5.1 checks every Windows CNG operation, automatically destroys provider,
hash, and key handles, wipes intermediate key material on every exit path, and
ships known-answer plus authenticated-ciphertext tamper tests.

### Protocol 2 migration for existing installations

New installations reject protocol 1 by default. For an existing installation
that still has old clients, use this controlled migration:

1. Explicitly deploy the server with `ALLOW_LEGACY_PROTOCOL=true`.
2. Copy the response-signing public key into each new SDK build and distribute it.
3. Require the new client version for every application.
4. Set `ALLOW_LEGACY_PROTOCOL=false` and restart the server.
5. Rotate the old application secret after all legacy clients are retired.

Never enable protocol 1 on a fresh installation. The compatibility flag restores
the extractable shared-secret protocol and exists only to prevent an abrupt
lockout while old clients are replaced.

New protocol 2 clients never receive or embed the application secret. TLS protects
requests in transit; licenses and short-lived, app-bound sessions remain the
actual authorization credentials. Every response is signed and bound to its app,
endpoint, request nonce, timestamp, and expiry.

### SDK releases and upgrade policy

The **SDK & documentation** tab lets an owner publish packages, assign stable,
beta, preview, or legacy channels, and mark a release supported, deprecated, or
blocked. EnAuth stores the package SHA-256 and an ECDSA signature generated by
the server response-signing key. Verify both values before distributing a
download; a hash alone detects corruption but does not prove who published it.

Each application can define a minimum and recommended SDK version. When minimum
enforcement is enabled, older clients receive `SDK_UPDATE_REQUIRED`. A release
marked blocked is rejected even when it would otherwise meet the application's
minimum version. `InitResult` and `LoginResult` expose `minimum_sdk_version`,
`recommended_sdk_version`, and `upgrade_message` so launchers can show a useful
upgrade notice instead of a generic network error.

Run `bootstrap.ps1 -SkipInstall` when dependency installation is managed by
your organization and the script should fail instead of installing tools.

### Using Visual Studio

1. Add SDK files to your project
2. Add linker dependencies
3. Set C++ language standard to C++17 or later
4. Build

### Using CMake

```cmake
add_executable(your_app main.cpp)
target_link_libraries(your_app winhttp bcrypt crypt32)
target_compile_features(your_app PRIVATE cxx_std_17)
```

## Troubleshooting

### Network Errors
- Check server URL is correct
- Ensure server is accessible
- Check firewall settings

### Version Mismatch
- Update client version to match server
- Or update server application version

### HWID Issues
- Ensure HWID is being collected correctly
- Check if HWID is banned in admin panel
- Verify HWID limit on license

### Session Expiration
- Implement automatic heartbeat
- Handle reconnection logic
- Check session duration settings

## Support

For issues or questions, refer to the main project documentation or contact maintainers.
