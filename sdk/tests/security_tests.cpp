#include "enauth.h"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

constexpr const char* kPublicKey =
    "f026855a9cc3270e8bbfedc2d5faae92c127a62e12ae6c1d558350ab0af1f9fc"
    "e9717ea9fa854e2d0ca6db7769941d01d528d261198377a5aaaa9f1d5f9ad839";
constexpr const char* kPayload = "eyJzdWNjZXNzIjp0cnVlLCJtZXNzYWdlIjoiT0sifQ==";
constexpr const char* kSignature =
    "YRPOf9cqEA3A5cdjK7LBMncLu+PxQIA1v4WkeM0vEFhhUMkuw9KhuyO0Yl/"
    "i1wlCJK9aZ9G+HUtnY0VIzi1wwg==";
constexpr const char* kNonce = "11111111111111111111111111111111";
constexpr const char* kEndpoint = "/api/client/init";

std::string Envelope(const std::string& payload = kPayload,
                     const std::string& signature = kSignature,
                     const std::string& nonce = kNonce,
                     const std::string& endpoint = kEndpoint,
                     long long timestamp = 2000000000,
                     long long validUntil = 2000000060) {
    return "{\"protocol\":2,\"app_id\":\"app-test\",\"endpoint\":\"" + endpoint +
        "\",\"request_nonce\":\"" + nonce + "\",\"ts\":" + std::to_string(timestamp) +
        ",\"valid_until\":" + std::to_string(validUntil) + ",\"payload\":\"" + payload +
        "\",\"server_sig\":\"" + signature + "\"}";
}

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void RequireThrows(const std::function<void()>& action, const char* message) {
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(message);
}

} // namespace

int main() {
    static_assert(enauth::RESOLVE_TIMEOUT_MS <= 10000, "DNS timeout must remain bounded");
    static_assert(enauth::CONNECT_TIMEOUT_MS <= 10000, "Connect timeout must remain bounded");
    static_assert(enauth::SEND_TIMEOUT_MS <= 10000, "Send timeout must remain bounded");
    static_assert(enauth::RECEIVE_TIMEOUT_MS <= 15000, "Receive timeout must remain bounded");

    try {
        RequireThrows([] {
            enauth::Client client("http://auth.example.com", "app-test", "1.0.0", kPublicKey);
        }, "Remote plaintext HTTP must be rejected");
        RequireThrows([] {
            enauth::Client client("https://auth.example.com", "app-test", "1.0.0", "not-a-key");
        }, "Invalid response-signing keys must be rejected");

        enauth::Client loopback("http://127.0.0.1:8080", "app-test", "1.0.0", kPublicKey);
        enauth::Client client("https://auth.example.com", "app-test", "1.0.0", kPublicKey);
        const std::string decoded = client.TestDecryptResponseAt(
            Envelope(), kEndpoint, kNonce, 2000000030);
        Require(decoded == "{\"success\":true,\"message\":\"OK\"}",
                "A valid signed response must verify");

        std::string tamperedPayload = kPayload;
        tamperedPayload[5] = tamperedPayload[5] == 'A' ? 'B' : 'A';
        RequireThrows([&] {
            client.TestDecryptResponseAt(Envelope(tamperedPayload), kEndpoint, kNonce, 2000000030);
        }, "Tampered response payload must fail closed");
        RequireThrows([&] {
            client.TestDecryptResponseAt(Envelope(kPayload, kSignature, std::string(32, '2')),
                                         kEndpoint, kNonce, 2000000030);
        }, "Mismatched request nonce must fail closed");
        RequireThrows([&] {
            client.TestDecryptResponseAt(Envelope(kPayload, kSignature, kNonce, "/api/client/login"),
                                         kEndpoint, kNonce, 2000000030);
        }, "Mismatched endpoint must fail closed");
        RequireThrows([&] {
            client.TestDecryptResponseAt(Envelope(), kEndpoint, kNonce, 2000000061);
        }, "Expired signed response must fail closed");
        RequireThrows([&] {
            client.TestDecryptResponseAt(Envelope(kPayload, ""), kEndpoint, kNonce, 2000000030);
        }, "Unsigned response must fail closed");
    } catch (const std::exception& error) {
        std::cerr << "SDK security test failed: " << error.what() << '\n';
        return 1;
    }

    std::cout << "All EnAuth SDK security tests passed.\n";
    return 0;
}
