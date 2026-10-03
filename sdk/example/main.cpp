#include "enauth.h"
#include "string_obfuscation.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <conio.h>
#include <iostream>
#include <string>
#include <thread>

namespace {

void ClearSensitive(std::string& value) {
    std::fill(value.begin(), value.end(), '\0');
    value.clear();
}

const char* StatusName(enauth::Status status) {
    switch (status) {
        case enauth::Status::Success: return "success";
        case enauth::Status::InvalidApp: return "invalid application";
        case enauth::Status::OutdatedVersion: return "outdated version";
        case enauth::Status::InvalidKey: return "invalid license";
        case enauth::Status::ExpiredKey: return "expired license";
        case enauth::Status::BannedKey: return "banned license";
        case enauth::Status::BannedHwid: return "banned hardware";
        case enauth::Status::MaxHwids: return "hardware limit reached";
        case enauth::Status::SessionExpired: return "session expired";
        case enauth::Status::NetworkError: return "network error";
        case enauth::Status::ServerError: return "server error";
        case enauth::Status::DecryptError: return "decryption error";
        case enauth::Status::ReplayAttack: return "replay rejected";
        case enauth::Status::LevelRequired: return "product level required";
        case enauth::Status::LevelNotAllowed: return "product level denied";
        case enauth::Status::SuspiciousLogin: return "suspicious login";
        default: return "unknown error";
    }
}

}  // namespace

int main() {
    // Compile-time application configuration. Replace the two placeholders
    // below with the values from your EnAuth admin panel before building.
    const std::string serverUrl = OBFUSCATE("https://auth.olsoftwares.com");
    const std::string appId = OBFUSCATE("REPLACE_WITH_APPLICATION_ID");
    std::string appSecret = OBFUSCATE("REPLACE_WITH_APPLICATION_SECRET");
    const std::string appVersion = OBFUSCATE("1.0.0");
    const std::string productId = OBFUSCATE("");
    const std::string productLevel = OBFUSCATE("");
    const std::string downloadName = OBFUSCATE("");
    constexpr int heartbeatSeconds = 30;

    if (appId == "REPLACE_WITH_APPLICATION_ID" ||
        appSecret == "REPLACE_WITH_APPLICATION_SECRET") {
        std::cerr << "Configure the application ID and secret in main.cpp before building.\n";
        return 2;
    }

    if (productId.empty() != productLevel.empty()) {
        std::cerr << "Set both ENAUTH_PRODUCT_ID and ENAUTH_PRODUCT_LEVEL, or neither.\n";
        ClearSensitive(appSecret);
        return 2;
    }

    std::string licenseKey;
    std::cout << "License key: ";
    std::getline(std::cin, licenseKey);

    if (licenseKey.empty()) {
        std::cerr << "A license key is required.\n";
        ClearSensitive(appSecret);
        return 2;
    }

    enauth::Client client(serverUrl, appId, appSecret, appVersion);
    ClearSensitive(appSecret);

    const auto init = client.Init();
    if (!init.success) {
        std::cerr << "Initialization failed (" << StatusName(init.status)
                  << "): " << init.message << '\n';
        if (!init.required_version.empty()) {
            std::cerr << "Required version: " << init.required_version << '\n';
        }
        ClearSensitive(licenseKey);
        return 1;
    }

    auto login = client.Login(licenseKey, productId, productLevel);
    ClearSensitive(licenseKey);
    if (!login.success) {
        ClearSensitive(login.token);
        std::cerr << "Login failed (" << StatusName(login.status)
                  << "): " << login.message << '\n';
        return 1;
    }

    ClearSensitive(login.token);

    std::cout << "Authenticated successfully.\n";
    if (!login.expires_at.empty()) {
        std::cout << "License expires: " << login.expires_at << '\n';
    }

    for (const auto& [name, value] : login.variables) {
        std::cout << "Variable " << name << " = " << value << '\n';
    }

    const auto news = client.GetNews();
    if (news.success && !news.items.empty()) {
        std::cout << "Latest news: " << news.items.front().title << '\n';
    }

    const auto validation = client.ValidateSession();
    if (!validation.success) {
        std::cerr << "Session validation failed (" << StatusName(validation.status)
                  << "): " << validation.message << '\n';
        client.Logout();
        return 1;
    }

    if (!downloadName.empty()) {
        auto fileData = client.DownloadFile(downloadName);
        if (fileData.empty()) {
            std::cerr << "Protected download failed or returned no data.\n";
        } else {
            std::cout << "Verified session-bound payload loaded in memory ("
                      << fileData.size() << " bytes).\n";
            // Consume the protected payload directly from memory here. Do not
            // write decrypted bytes to disk. Wipe them as soon as processing ends.
            SecureZeroMemory(fileData.data(), fileData.size());
        }
    }

    std::atomic<bool> sessionLost{false};
    client.StartHeartbeatThread(heartbeatSeconds, [&sessionLost]() {
        sessionLost = true;
    });

    std::cout << "Protected session active. Press Enter to log out.\n";
    while (!sessionLost) {
        if (_kbhit() && _getch() == '\r') break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    client.StopHeartbeatThread();
    if (sessionLost) {
        std::cerr << "Session protection stopped the application after heartbeat failures.\n";
        return 1;
    }

    client.Logout();
    std::cout << "Logged out securely.\n";
    return 0;
}
