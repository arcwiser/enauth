# EnAuth C++ SDK

Windows C++17 client SDK for EnAuth authentication and licensing system.

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
    "1.0.0"                    // Application version
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
- AES-256-GCM encryption for all communication
- HMAC-SHA256 signature verification
- Replay attack protection
- Runtime string obfuscation
- Anti-debugging checks
- HWID collection and validation

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
