#include "enauth.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>

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

}  // namespace

int main() {
    const std::string serverUrl = ReadEnvironment("ENAUTH_SERVER_URL");
    const std::string appId = ReadEnvironment("ENAUTH_APP_ID");
    std::string appSecret = ReadEnvironment("ENAUTH_APP_SECRET");
    const std::string appVersion = ReadEnvironment("ENAUTH_APP_VERSION");
    const std::string productId = ReadEnvironment("ENAUTH_PRODUCT_ID");
    const std::string productLevel = ReadEnvironment("ENAUTH_PRODUCT_LEVEL");

    if (serverUrl.empty() || appId.empty() || appSecret.empty() || appVersion.empty()) {
        std::cerr
            << "Missing configuration. Set ENAUTH_SERVER_URL, ENAUTH_APP_ID, "
               "ENAUTH_APP_SECRET, and ENAUTH_APP_VERSION before running.\n";
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
        std::cerr << "Initialization failed: " << init.message << '\n';
        ClearSensitive(licenseKey);
        return 1;
    }

    const auto login = client.Login(licenseKey, productId, productLevel);
    ClearSensitive(licenseKey);
    if (!login.success) {
        std::cerr << "Login failed: " << login.message << '\n';
        return 1;
    }

    std::cout << "Authenticated successfully.\n";

    const auto validation = client.ValidateSession();
    if (!validation.success) {
        std::cerr << "Session validation failed: " << validation.message << '\n';
        client.Logout();
        return 1;
    }

    std::cout << "Session is valid.\n";
    client.Logout();
    return 0;
}
