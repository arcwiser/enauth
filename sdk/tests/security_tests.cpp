#include "enauth.h"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <vector>

std::string AES256CBCEncrypt(const std::string& plaintext, const std::string& app_secret);
std::string AES256CBCDecrypt(const std::string& b64, const std::string& app_secret);
std::string HmacSHA256Hex(const std::string& key, const std::string& msg);
std::string SHA256Hex(const std::string& data);
std::vector<unsigned char> Base64Decode(const std::string& b64);
std::string Base64Encode(const std::vector<unsigned char>& data);

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
    static_assert(enauth::MAX_API_RESPONSE_BYTES <= 4u * 1024u * 1024u,
                  "API responses must remain bounded");
    static_assert(enauth::MAX_DOWNLOAD_RESPONSE_BYTES <= 190u * 1024u * 1024u,
                  "Download envelopes must remain bounded");

    try {
        Require(SHA256Hex("abc") ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA-256 must match its known-answer test");
        Require(HmacSHA256Hex("key", "The quick brown fox jumps over the lazy dog") ==
                "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
                "HMAC-SHA256 must match its known-answer test");
        const std::string encrypted = AES256CBCEncrypt("authenticated plaintext", "test-secret-at-least-32-characters");
        Require(AES256CBCDecrypt(encrypted, "test-secret-at-least-32-characters") ==
                "authenticated plaintext", "AES-GCM round trip must succeed");
        auto tampered = Base64Decode(encrypted);
        tampered[tampered.size() / 2] ^= 0x01;
        const std::string tamperedEncoded = Base64Encode(tampered);
        RequireThrows([&] {
            AES256CBCDecrypt(tamperedEncoded, "test-secret-at-least-32-characters");
        }, "AES-GCM tampering must fail closed");
        RequireThrows([] { Base64Decode("not base64!!!"); },
                      "Malformed Base64 must be rejected");

        RequireThrows([] {
            enauth::Client client("http://auth.example.com", "app-test", "1.0.0", kPublicKey);
        }, "Remote plaintext HTTP must be rejected");
        RequireThrows([] {
            enauth::Client client("https://auth.example.com", "app-test", "1.0.0", "not-a-key");
        }, "Invalid response-signing keys must be rejected");
        RequireThrows([] {
            enauth::Client client("https://user:pass@auth.example.com", "app-test", "1.0.0", kPublicKey);
        }, "Credential-bearing server URLs must be rejected");
        RequireThrows([] {
            enauth::Client client("https://auth.example.com?redirect=evil", "app-test", "1.0.0", kPublicKey);
        }, "Ambiguous server URLs must be rejected");

        enauth::Client loopback("http://127.0.0.1:8080", "app-test", "1.0.0", kPublicKey);
        enauth::Client client("https://auth.example.com", "app-test", "1.0.0", kPublicKey);
        const auto invalidLogin = loopback.Login(std::string(enauth::MAX_LICENSE_KEY_BYTES + 1, 'A'));
        Require(!invalidLogin.success && invalidLogin.message == "INVALID_INPUT",
                "Oversized login input must be rejected before networking");
        const auto uninitializedLogin = loopback.Login("VALID-LENGTH-KEY");
        Require(!uninitializedLogin.success && uninitializedLogin.message == "NOT_INITIALIZED",
                "Login must fail closed until initialization succeeds");
        Require(!loopback.GetNews().success,
                "Public SDK operations must respect initialization state");
        Require(loopback.DownloadFile(std::string(enauth::MAX_RESOURCE_NAME_BYTES + 1, 'A')).empty(),
                "Oversized download names must be rejected before networking");
        Require(loopback.ValidateSession().status == enauth::Status::SessionExpired,
                "Session operations must fail closed before login");
        loopback.StartHeartbeatThread(0);
        loopback.StartHeartbeatThread(999999);
        loopback.StopHeartbeatThread();
        Require(!enauth::Client::TestValidatePortableExecutable({'M', 'Z'}),
                "An MZ prefix alone must not qualify as a loader update");
        std::vector<unsigned char> executable(512, 0);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        std::memcpy(executable.data(), &dos, sizeof(dos));
        const DWORD peSignature = IMAGE_NT_SIGNATURE;
        std::memcpy(executable.data() + 0x80, &peSignature, sizeof(peSignature));
        IMAGE_FILE_HEADER fileHeader{};
#if defined(_M_X64)
        fileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        const WORD optionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#elif defined(_M_IX86)
        fileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        const WORD optionalMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
#elif defined(_M_ARM64)
        fileHeader.Machine = IMAGE_FILE_MACHINE_ARM64;
        const WORD optionalMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#endif
        fileHeader.NumberOfSections = 1;
        fileHeader.SizeOfOptionalHeader = sizeof(WORD);
        fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
        std::memcpy(executable.data() + 0x80 + sizeof(DWORD), &fileHeader, sizeof(fileHeader));
        std::memcpy(executable.data() + 0x80 + sizeof(DWORD) + sizeof(fileHeader),
                    &optionalMagic, sizeof(optionalMagic));
        Require(enauth::Client::TestValidatePortableExecutable(executable),
                "A structurally valid same-architecture PE must qualify as an update");
        fileHeader.Characteristics |= IMAGE_FILE_DLL;
        std::memcpy(executable.data() + 0x80 + sizeof(DWORD), &fileHeader, sizeof(fileHeader));
        Require(!enauth::Client::TestValidatePortableExecutable(executable),
                "DLL payloads must not qualify as loader updates");
        Require(enauth::Client::TestAutoUpdatePathAllowed(L"C:\\Program Files\\Loader\\loader.exe"),
                "Normal quoted Windows paths must be allowed");
        Require(!enauth::Client::TestAutoUpdatePathAllowed(L"C:\\Loader&calc.exe"),
                "Command metacharacters must be rejected from updater paths");
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
