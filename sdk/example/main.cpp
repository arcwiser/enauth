#include "enauth.h"
#include "string_obfuscation.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <conio.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::string ReadEnvironment(const char* name) {
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
        return {};
    }

    std::string result{value};
    std::fill(value, value + length, '\0');
    std::free(value);
    return result;
}

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

int ReadHeartbeatInterval() {
    const std::string configured = ReadEnvironment("ENAUTH_HEARTBEAT_SECONDS");
    if (configured.empty()) return 30;
    try {
        return std::clamp(std::stoi(configured), 10, 300);
    } catch (...) {
        return 30;
    }
}

}  // namespace

int main() {
    const std::string serverUrl = OBFUSCATE("https://auth.olsoftwares.com");
    const std::string appId = ReadEnvironment("ENAUTH_APP_ID");
    std::string appSecret = ReadEnvironment("ENAUTH_APP_SECRET");
    const std::string appVersion = ReadEnvironment("ENAUTH_APP_VERSION");
    const std::string productId = ReadEnvironment("ENAUTH_PRODUCT_ID");
    const std::string productLevel = ReadEnvironment("ENAUTH_PRODUCT_LEVEL");
    const std::string downloadName = ReadEnvironment("ENAUTH_DOWNLOAD_NAME");

    if (appId.empty() || appSecret.empty() || appVersion.empty()) {
        std::cerr
            << "Missing configuration. Set ENAUTH_APP_ID, ENAUTH_APP_SECRET, "
               "and ENAUTH_APP_VERSION before running.\n";
        return 2;
    }

    if (productId.empty() != productLevel.empty()) {
        std::cerr << "Set both ENAUTH_PRODUCT_ID and ENAUTH_PRODUCT_LEVEL, or neither.\n";
        ClearSensitive(appSecret);
        return 2;
    }

    std::string licenseKey = ReadEnvironment("ENAUTH_LICENSE_KEY");
    if (licenseKey.empty()) {
        std::cout << "License key: ";
        std::getline(std::cin, licenseKey);
    }

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
        const auto fileData = client.DownloadFile(downloadName);
        if (fileData.empty()) {
            std::cerr << "Protected download failed or returned no data.\n";
        } else {
            std::ofstream output(downloadName, std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char*>(fileData.data()),
                         static_cast<std::streamsize>(fileData.size()));
            if (!output) {
                std::cerr << "Could not save protected download.\n";
            } else {
                std::cout << "Verified download saved as " << downloadName << '\n';
            }
        }
    }

    std::atomic<bool> sessionLost{false};
    client.StartHeartbeatThread(ReadHeartbeatInterval(), [&sessionLost]() {
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
