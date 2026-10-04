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
    "your-app-secret",          // 64-char hex secret from admin panel
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
- AES-256-GCM application-layer message protection
- Session-bound AES-256-GCM file envelopes derived from the session token,
  device HWID, application secret, and file identity. A payload captured from
  one session cannot be decrypted with a different session context.
- HMAC-SHA256 signature verification
- ECDSA P-256 server response verification. Only the public key is embedded in
  the SDK; the signing private key stays on the server.
- Cryptographically random per-request replay nonces
- Fail-closed server response HMAC and timestamp validation
- Release builds enable CFG, CET shadow-stack compatibility, Spectre mitigations,
  ASLR, DEP, stack checks, and link-time optimization when built with MSVC
- Post-login requests include the device HWID so copied session tokens can be
  revoked. `REQUIRE_SESSION_HWID` defaults to `true`, so legacy token-only
  requests are rejected unless an operator explicitly opts out.
- The SDK's free local integrity checks are enabled by default by the example
  CMake project and can be disabled explicitly with
  `-DENAUTH_ENABLE_ANTI_DEBUG=OFF` for development troubleshooting.
- Replay attack protection
- Layered runtime secret storage using a per-process AES-256-GCM key plus a
  position-varying XOR transform (replacing the previous single-byte XOR-only storage)
- Local anti-debugging and integrity checks enabled by default in the example build
- HWID collection and validation

Application secrets compiled into a desktop application can be recovered by a
determined attacker. Do not treat the SDK as a place to keep a master secret,
and do not rely on a local license check to protect server-side privileges.

## HWID Collection

The SDK automatically collects hardware ID using:
- CPU information
- Motherboard serial
- MAC address
- Disk serial

The HWID is hashed with SHA-256 before sending to the server.

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

Before building, replace `REPLACE_WITH_APPLICATION_ID`,
`REPLACE_WITH_APPLICATION_SECRET`, and
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
and high-entropy ASLR. XOR-protected in-memory credentials, HWID collection,
AES-256-GCM encryption, PBKDF2 derivation, HMAC signing, TLS validation, replay
protection, and encrypted session storage are performed automatically inside
the SDK rather than called separately by application code.

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
