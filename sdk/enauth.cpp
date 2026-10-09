/*
 *  EnAuth C++ Client — Implementation
 *
 *  Link: winhttp.lib  bcrypt.lib  crypt32.lib
 */
#include "enauth.h"
#include "string_obfuscation.h"
#include "protocol_json.h"
#include <chrono>
#include <tlhelp32.h>
#include <vector>
#include <stdexcept>
#include <thread>
#include <winternl.h>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "ntdll.lib")

// NT API Typedefs
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif
#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif
#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger 0x11
#endif

// Declared in crypto_win.cpp
std::string AES256CBCEncrypt(const std::string& plaintext, const std::string& app_secret);
std::string AES256CBCDecrypt(const std::string& b64,       const std::string& app_secret);
std::string HmacSHA256Hex   (const std::string& key,       const std::string& msg);
std::string SHA256Hex        (const std::string& data);
std::string SecureRandomHex  (size_t byteCount);
std::vector<unsigned char> Base64Decode(const std::string& b64);
std::string Base64Encode(const std::vector<unsigned char>& data);
bool VerifyEcdsaP256Signature(const std::string& publicKeyHex,
                             const std::string& message,
                             const std::string& signatureB64);

// Declared in hwid.cpp
namespace enauth { namespace hwid { std::string Collect(); } }

namespace enauth {

// ─── JSON helpers (minimal, no external dep) ─────────────────────────────────

static std::string JsonStr(const std::string& k, const std::string& v) {
    return nlohmann::json(k).dump() + ":" + nlohmann::json(v).dump();
}
static std::string JsonInt(const std::string& k, long long v) {
    return "\"" + k + "\":" + std::to_string(v);
}

static std::string JsonGet(const std::string& json, const std::string& key) {
    const auto document = detail::ParseObject(json);
    if (!document.is_object()) throw std::runtime_error("Expected JSON object");
    auto field = document.find(key);
    if (field == document.end() || field->is_null()) return {};
    return field->is_string() ? field->get<std::string>() : field->dump();
}

static bool JsonBool(const std::string& json, const std::string& key) {
    const auto document = detail::ParseObject(json);
    return document.is_object() && document.contains(key) &&
        document[key].is_boolean() && document[key].get<bool>();
}

static long long UnixTime() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static unsigned char GenerateRuntimeKey() {
    int info[4];
    __cpuid(info, 0);
    unsigned __int64 tsc = __rdtsc();
    return static_cast<unsigned char>((tsc ^ info[0] ^ info[3]) & 0xFF);
}

static std::string WideToUtf8(const wchar_t* text) {
    if (!text || !*text) {
        return {};
    }

    const int required = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), required, nullptr, nullptr))
        throw std::runtime_error("UTF-8 conversion failed");
    result.resize(static_cast<size_t>(required - 1));
    return result;
}

// ─── WinHTTP POST ────────────────────────────────────────────────────────────

std::string Client::Post(const std::string& endpoint, const std::string& body) {
    URL_COMPONENTSW comps = {};
    comps.dwStructSize = sizeof(comps);
    wchar_t wHost[256] = {}, wPath[1024] = {};
    comps.lpszHostName    = wHost; comps.dwHostNameLength    = 256;
    comps.lpszUrlPath     = wPath; comps.dwUrlPathLength     = 1024;
    comps.nScheme         = INTERNET_SCHEME_HTTP;

    std::string srvUrl = GetServerUrl();
    std::wstring wUrl(srvUrl.begin(), srvUrl.end());
    std::wstring wEndpoint(endpoint.begin(), endpoint.end());
    std::wstring fullUrl = wUrl + wEndpoint;
    SecureZeroMemory(&srvUrl[0], srvUrl.size());

    if (!WinHttpCrackUrl(fullUrl.c_str(), 0, 0, &comps))
        throw std::runtime_error(OBFUSCATE("Invalid URL"));

    bool https = (comps.nScheme == INTERNET_SCHEME_HTTPS);
    std::wstring host(wHost, comps.dwHostNameLength);
    std::transform(host.begin(), host.end(), host.begin(), ::towlower);
    const bool localhost = host == L"localhost" || host == L"127.0.0.1" || host == L"::1";
    if (!https && !(localhost && comps.nScheme == INTERNET_SCHEME_HTTP))
        throw std::runtime_error(OBFUSCATE("HTTPS is required for non-local EnAuth servers"));

    HINTERNET hSession = WinHttpOpen(W_OBFUSCATE(L"EnAuth/1.0").c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) throw std::runtime_error(OBFUSCATE("WinHttpOpen failed"));

    WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 15000);

    HINTERNET hConnect = WinHttpConnect(hSession, wHost, comps.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error(OBFUSCATE("WinHttpConnect failed"));
    }
    HINTERNET hReq     = WinHttpOpenRequest(hConnect, W_OBFUSCATE(L"POST").c_str(), wPath,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error(OBFUSCATE("WinHttpOpenRequest failed"));
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redirectPolicy, sizeof(redirectPolicy))) {
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Cannot disable HTTP redirects");
    }

#ifdef ENAUTH_ENABLE_ANTI_DEBUG
    SecurityCheck();
#endif

    LPCWSTR hdrs = L"Content-Type: application/json";
    std::string response;
    bool requestOk = WinHttpSendRequest(hReq, hdrs, (DWORD)-1,
                           (LPVOID)body.c_str(), (DWORD)body.size(),
                           (DWORD)body.size(), 0) &&
        WinHttpReceiveResponse(hReq, nullptr);
    if (requestOk) {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
                            WINHTTP_NO_HEADER_INDEX);
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            // Download content is base64 inside a second base64 signed envelope.
            const size_t limit = endpoint == "/api/client/download" ?
                190u * 1024u * 1024u : 4u * 1024u * 1024u;
            if (avail > limit - response.size()) {
                WinHttpCloseHandle(hReq);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                throw std::runtime_error(OBFUSCATE("Server response exceeded size limit"));
            }
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(hReq, &chunk[0], avail, &read)) break;
            response.append(chunk.data(), read);
        }
        if (statusCode < 200 || statusCode >= 300) {
            response.clear();
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    if (!requestOk || response.empty())
        throw std::runtime_error(OBFUSCATE("EnAuth request failed"));
    return response;
}

std::string Client::BuildRequest(const std::string& json_payload, std::string& requestNonce) {
    const long long ts = UnixTime();
    std::string appId = GetAppId();
    requestNonce = SecureRandomHex(16);
    std::vector<unsigned char> bytes(json_payload.begin(), json_payload.end());
    std::string payload = Base64Encode(bytes);
    std::string res = std::string("{") +
        JsonInt(OBFUSCATE("protocol"), 2) + "," +
        JsonStr(OBFUSCATE("app_id"), appId) + "," +
        JsonStr(OBFUSCATE("payload"), payload) + "," +
        JsonInt(OBFUSCATE("ts"), ts) + "," +
        JsonStr(OBFUSCATE("nonce"), requestNonce) + "}";
    if (!appId.empty()) SecureZeroMemory(appId.data(), appId.size());
    if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size());
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    return res;
}

std::string Client::DecryptResponse(const std::string& json_response,
                                    const std::string& endpoint,
                                    const std::string& requestNonce) {
    const auto envelope = detail::ParseObject(json_response);
    if (!envelope.contains("protocol") || !envelope["protocol"].is_number_integer() ||
        envelope["protocol"] != 2) {
        throw std::runtime_error(OBFUSCATE("Protocol 2 response required"));
    }
    const std::string payload = detail::StringField(envelope, "payload");
    const std::string serverSig = detail::StringField(envelope, "server_sig");
    const long long responseTs = detail::TimeField(envelope, "ts");
    const long long validUntil = detail::TimeField(envelope, "valid_until");
    const std::string tsText = std::to_string(responseTs);
    const std::string validUntilText = std::to_string(validUntil);
    const std::string returnedNonce = detail::StringField(envelope, "request_nonce");
    const std::string returnedEndpoint = detail::StringField(envelope, "endpoint");
    const std::string returnedAppId = detail::StringField(envelope, "app_id");
    if (payload.empty() || serverSig.empty() || tsText.empty() || validUntilText.empty())
        throw std::runtime_error(OBFUSCATE("Unsigned server response"));
    const long long now = UnixTime();
    if (responseTs < 0 || responseTs > now + 60 || validUntil < now ||
        validUntil < responseTs || validUntil - responseTs > 120)
        throw std::runtime_error(OBFUSCATE("Stale server response"));

    std::string appId = GetAppId();
    if (returnedNonce != requestNonce || returnedEndpoint != endpoint || returnedAppId != appId) {
        if (!appId.empty()) SecureZeroMemory(appId.data(), appId.size());
        throw std::runtime_error(OBFUSCATE("Server response context mismatch"));
    }
    std::string responsePublicKey = GetResponsePublicKey();
    const std::string signedMessage = "v2|" + appId + "|" + endpoint + "|" + requestNonce +
        "|" + tsText + "|" + validUntilText + "|" + payload;
    if (serverSig.empty() || !VerifyEcdsaP256Signature(responsePublicKey, signedMessage, serverSig)) {
        if (!responsePublicKey.empty()) SecureZeroMemory(responsePublicKey.data(), responsePublicKey.size());
        if (!appId.empty()) SecureZeroMemory(appId.data(), appId.size());
        throw std::runtime_error(OBFUSCATE("Invalid asymmetric server signature"));
    }
    if (!responsePublicKey.empty()) SecureZeroMemory(responsePublicKey.data(), responsePublicKey.size());
    if (!appId.empty()) SecureZeroMemory(&appId[0], appId.size());
    const auto decoded = Base64Decode(payload);
    std::string result(decoded.begin(), decoded.end());
    const auto parsed = detail::ParseObject(result);
    if (!parsed.contains("success") || !parsed["success"].is_boolean())
        throw std::runtime_error("Invalid response success field");
    return result;
}

Status Client::MessageToStatus(const std::string& msg) {
    if (msg == OBFUSCATE("INVALID_APP"))        return Status::InvalidApp;
    if (msg == OBFUSCATE("OUTDATED_VERSION"))   return Status::OutdatedVersion;
    if (msg == OBFUSCATE("SDK_UPDATE_REQUIRED")) return Status::SdkUpdateRequired;
    if (msg == OBFUSCATE("INVALID_KEY"))        return Status::InvalidKey;
    if (msg == OBFUSCATE("EXPIRED_KEY"))        return Status::ExpiredKey;
    if (msg == OBFUSCATE("BANNED_KEY"))         return Status::BannedKey;
    if (msg == OBFUSCATE("BANNED_HWID"))        return Status::BannedHwid;
    if (msg == OBFUSCATE("MAX_HWIDS"))          return Status::MaxHwids;
    if (msg == OBFUSCATE("SESSION_EXPIRED"))    return Status::SessionExpired;
    if (msg == OBFUSCATE("SESSION_IDENTITY_MISMATCH")) return Status::SessionIdentityMismatch;
    if (msg == OBFUSCATE("LEVEL_REQUIRED"))     return Status::LevelRequired;
    if (msg == OBFUSCATE("LEVEL_NOT_ALLOWED"))  return Status::LevelNotAllowed;
    if (msg == OBFUSCATE("APP_PAUSED"))         return Status::AppPaused;
    if (msg == OBFUSCATE("PRODUCT_PAUSED"))     return Status::ProductPaused;
    if (msg == OBFUSCATE("ENTITLEMENT_PAUSED")) return Status::EntitlementPaused;
    if (msg == OBFUSCATE("OK"))                 return Status::Success;
    return Status::Unknown;
}

Client::Client(const std::string& server_url, const std::string& app_id,
               const std::string& version,
               const std::string& response_public_key_hex)
{
    m_xor_key = GenerateRuntimeKey();
    std::string memoryKey = SecureRandomHex(32);
    m_enc_memory_key.reserve(memoryKey.size());
    for (size_t i = 0; i < memoryKey.size(); ++i)
        m_enc_memory_key.push_back(static_cast<unsigned char>(memoryKey[i]) ^
            static_cast<unsigned char>(m_xor_key + (i * 29u)));
    SecureZeroMemory(memoryKey.data(), memoryKey.size());
    EncryptStore(m_enc_server_url, server_url);
    EncryptStore(m_enc_app_id,     app_id);
    EncryptStore(m_enc_version,    version);
    EncryptStore(m_enc_response_public_key, response_public_key_hex);
    
#ifdef ENAUTH_ENABLE_ANTI_DEBUG
    SecurityCheck();
    HideThread();
#endif
}

void Client::EncryptStore(std::vector<unsigned char>& target, const std::string& source) {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    std::string layered(source);
    for (size_t i = 0; i < layered.size(); ++i)
        layered[i] = static_cast<char>(static_cast<unsigned char>(layered[i]) ^
            static_cast<unsigned char>(m_xor_key + (i * 131u)));
    std::string memoryKey = GetMemoryKey();
    std::string encrypted = AES256CBCEncrypt(layered, memoryKey);
    target.assign(encrypted.begin(), encrypted.end());
    if (!layered.empty()) SecureZeroMemory(layered.data(), layered.size());
    if (!memoryKey.empty()) SecureZeroMemory(memoryKey.data(), memoryKey.size());
    if (!encrypted.empty()) SecureZeroMemory(encrypted.data(), encrypted.size());
}

std::string Client::DecryptField(const std::vector<unsigned char>& field) const {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    if (field.empty()) return {};
    std::string encrypted(field.begin(), field.end());
    std::string memoryKey = GetMemoryKey();
    std::string value = AES256CBCDecrypt(encrypted, memoryKey);
    for (size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<char>(static_cast<unsigned char>(value[i]) ^
            static_cast<unsigned char>(m_xor_key + (i * 131u)));
    SecureZeroMemory(encrypted.data(), encrypted.size());
    SecureZeroMemory(memoryKey.data(), memoryKey.size());
    return value;
}

std::string Client::GetMemoryKey() const {
    std::string key;
    key.reserve(m_enc_memory_key.size());
    for (size_t i = 0; i < m_enc_memory_key.size(); ++i)
        key.push_back(static_cast<char>(m_enc_memory_key[i] ^
            static_cast<unsigned char>(m_xor_key + (i * 29u))));
    return key;
}

std::string Client::GetServerUrl()  const { return DecryptField(m_enc_server_url); }
std::string Client::GetAppId()      const { return DecryptField(m_enc_app_id); }
std::string Client::GetVersion()    const { return DecryptField(m_enc_version); }
std::string Client::GetResponsePublicKey() const { return DecryptField(m_enc_response_public_key); }
std::string Client::GetSessionToken() const { return DecryptField(m_enc_token); }
std::string Client::GetLicenseKey()   const { return DecryptField(m_enc_license_key); }
std::string Client::GetExpiresAt()    const { return DecryptField(m_enc_expires_at); }

Client::~Client() {
    StopHeartbeatThread();
    auto wipe = [](std::vector<unsigned char>& value) {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        value.clear();
    };
    wipe(m_enc_server_url);
    wipe(m_enc_app_id);
    wipe(m_enc_version);
    wipe(m_enc_response_public_key);
    wipe(m_enc_token);
    wipe(m_enc_license_key);
    wipe(m_enc_expires_at);
    wipe(m_enc_memory_key);
    m_xor_key = 0;
}

std::string Client::GetHwid() const { return hwid::Collect(); }

InitResult Client::Init() {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    SecurityCheck();
    InitResult result;
    try {
        std::string ver = GetVersion();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("version"), ver) + "," +
            JsonStr(OBFUSCATE("sdk_version"), SDK_VERSION) + "}";
        SecureZeroMemory(&ver[0], ver.size());
        const std::string endpoint = OBFUSCATE("/api/client/init");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);

        result.success          = JsonBool(dec, OBFUSCATE("success"));
        result.message          = JsonGet(dec, OBFUSCATE("message"));
        result.status           = MessageToStatus(result.message);
        result.server_time      = JsonGet(dec, OBFUSCATE("server_time"));
        result.required_version = JsonGet(dec, OBFUSCATE("required_version"));
        result.minimum_sdk_version = JsonGet(dec, OBFUSCATE("minimum_sdk_version"));
        result.recommended_sdk_version = JsonGet(dec, OBFUSCATE("recommended_sdk_version"));
        result.upgrade_message = JsonGet(dec, OBFUSCATE("upgrade_message"));

        if (result.success) m_initialized = true;
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

LoginResult Client::Login(const std::string& license_key,
                           const std::string& product_id,
                           const std::string& level) {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    LoginResult result;
    try {
        std::string hw = hwid::Collect();
        std::string version = GetVersion();
        std::string payload = std::string("{") +
            JsonStr(OBFUSCATE("license_key"), license_key) + "," +
            JsonStr(OBFUSCATE("hwid"), hw) + "," +
            JsonStr(OBFUSCATE("version"), version) + "," +
            JsonStr(OBFUSCATE("sdk_version"), SDK_VERSION);
        if (!product_id.empty()) payload += "," + JsonStr(OBFUSCATE("product_id"), product_id);
        if (!level.empty())      payload += "," + JsonStr(OBFUSCATE("level"), level);
        payload += "}";
        if (!version.empty()) SecureZeroMemory(version.data(), version.size());
        const std::string endpoint = OBFUSCATE("/api/client/login");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);

        result.success    = JsonBool(dec, OBFUSCATE("success"));
        result.message    = JsonGet(dec, OBFUSCATE("message"));
        result.status     = MessageToStatus(result.message);
        result.token      = JsonGet(dec, OBFUSCATE("token"));
        result.expires_at = JsonGet(dec, OBFUSCATE("expires_at"));
        result.minimum_sdk_version = JsonGet(dec, OBFUSCATE("minimum_sdk_version"));
        result.recommended_sdk_version = JsonGet(dec, OBFUSCATE("recommended_sdk_version"));
        result.upgrade_message = JsonGet(dec, OBFUSCATE("upgrade_message"));

        if (result.message.empty()) {
            if (!dec.empty()) {
                result.message = dec;
            } else if (!result.success) {
                result.message = OBFUSCATE("EMPTY_RESPONSE");
            }
        }

        std::string vars_json = JsonGet(dec, OBFUSCATE("variables"));
        if (!vars_json.empty()) {
            size_t pos = 0;
            while ((pos = vars_json.find('"', pos)) != std::string::npos) {
                size_t k_start = pos + 1;
                size_t k_end   = vars_json.find('"', k_start);
                if (k_end == std::string::npos) break;
                std::string key = vars_json.substr(k_start, k_end - k_start);
                pos = vars_json.find(':', k_end);
                if (pos == std::string::npos) break;
                pos = vars_json.find('"', pos);
                if (pos == std::string::npos) break;
                size_t v_start = pos + 1;
                size_t v_end   = vars_json.find('"', v_start);
                if (v_end == std::string::npos) break;
                std::string val = vars_json.substr(v_start, v_end - v_start);
                m_variables[key] = val;
                result.variables[key] = val;
                pos = v_end + 1;
            }
        }

        if (result.success) {
            EncryptStore(m_enc_token,       result.token);
            EncryptStore(m_enc_expires_at,  result.expires_at);
            EncryptStore(m_enc_license_key, license_key);
            m_logged_in   = true;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

NewsResult Client::GetNews() {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    NewsResult result;
    try {
        const std::string endpoint = OBFUSCATE("/api/client/news");
        std::string nonce;
        std::string body = BuildRequest("{}", nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);

        result.success = JsonBool(dec, OBFUSCATE("success"));
        result.message = JsonGet(dec, OBFUSCATE("message"));
        result.status  = MessageToStatus(result.message);

        if (result.success) {
            std::string items_json = JsonGet(dec, OBFUSCATE("news"));
            // Very basic manual JSON array parsing
            size_t pos = 0;
            while ((pos = items_json.find('{', pos)) != std::string::npos) {
                size_t end = items_json.find('}', pos);
                if (end == std::string::npos) break;
                std::string obj = items_json.substr(pos, end - pos + 1);
                NewsItem item;
                item.id         = JsonGet(obj, OBFUSCATE("id"));
                item.title      = JsonGet(obj, OBFUSCATE("title"));
                item.content    = JsonGet(obj, OBFUSCATE("content"));
                item.color      = JsonGet(obj, OBFUSCATE("color"));
                item.created_at = JsonGet(obj, OBFUSCATE("created_at"));
                result.items.push_back(item);
                pos = end + 1;
            }
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.message = e.what();
    }
    return result;
}

SimpleResult Client::Heartbeat() {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), GetHwid()) + "}";
        SecureZeroMemory(&token[0], token.size());
        const std::string endpoint = OBFUSCATE("/api/client/heartbeat");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);
        result.success  = JsonBool(dec, OBFUSCATE("success"));
        result.message  = JsonGet(dec, OBFUSCATE("message"));
        result.status   = MessageToStatus(result.message);
        const std::string rotatedToken = JsonGet(dec, OBFUSCATE("token"));
        if (result.success && !rotatedToken.empty()) EncryptStore(m_enc_token, rotatedToken);
        if (!result.success) m_logged_in = false;
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

SimpleResult Client::Logout() {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), GetHwid()) + "}";
        SecureZeroMemory(&token[0], token.size());
        const std::string endpoint = OBFUSCATE("/api/client/logout");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);
        result.success  = JsonBool(dec, OBFUSCATE("success"));
        result.message  = JsonGet(dec, OBFUSCATE("message"));
        result.status   = MessageToStatus(result.message);
    } catch (...) {}
    m_logged_in = false;
    m_enc_token.clear();
    m_enc_license_key.clear();
    m_enc_expires_at.clear();
    return result;
}

SimpleResult Client::ValidateSession() {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), GetHwid()) + "}";
        SecureZeroMemory(&token[0], token.size());
        const std::string endpoint = OBFUSCATE("/api/client/validate");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);
        result.success  = JsonBool(dec, OBFUSCATE("success"));
        result.message  = JsonGet(dec, OBFUSCATE("message"));
        result.status   = MessageToStatus(result.message);
        const std::string rotatedToken = JsonGet(dec, OBFUSCATE("token"));
        if (result.success && !rotatedToken.empty()) EncryptStore(m_enc_token, rotatedToken);
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

std::vector<unsigned char> Client::DownloadFile(const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    SecurityCheck();
    try {
        std::string token = GetSessionToken();
        std::string deviceHwid = GetHwid();
        std::string ticketPayload = std::string("{") +
            JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), deviceHwid) + "," +
            JsonStr(OBFUSCATE("name"), name) + "}";
        const std::string ticketEndpoint = OBFUSCATE("/api/client/download-ticket");
        std::string ticketNonce;
        std::string ticketBody = BuildRequest(ticketPayload, ticketNonce);
        std::string ticketRaw = Post(ticketEndpoint, ticketBody);
        std::string ticketResponse = DecryptResponse(ticketRaw, ticketEndpoint, ticketNonce);
        if (!JsonBool(ticketResponse, OBFUSCATE("success"))) {
            SecureZeroMemory(token.data(), token.size());
            SecureZeroMemory(deviceHwid.data(), deviceHwid.size());
            return {};
        }
        std::string ticket = JsonGet(ticketResponse, OBFUSCATE("ticket"));
        std::string ticketToken = JsonGet(ticketResponse, OBFUSCATE("token"));
        if (ticket.empty() || ticketToken.empty()) {
            SecureZeroMemory(token.data(), token.size());
            SecureZeroMemory(deviceHwid.data(), deviceHwid.size());
            return {};
        }
        SecureZeroMemory(token.data(), token.size());
        token = ticketToken;
        EncryptStore(m_enc_token, ticketToken);
        std::string payload = std::string("{") +
            JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), deviceHwid) + "," +
            JsonStr(OBFUSCATE("name"), name) + "," +
            JsonStr(OBFUSCATE("ticket"), ticket) + "}";
        SecureZeroMemory(ticket.data(), ticket.size());
        SecureZeroMemory(ticketToken.data(), ticketToken.size());
        
        const std::string endpoint = OBFUSCATE("/api/client/download");
        std::string nonce;
        std::string body = BuildRequest(payload, nonce);
        std::string raw = Post(endpoint, body);
        std::string dec = DecryptResponse(raw, endpoint, nonce);
        const std::string rotatedToken = JsonGet(dec, OBFUSCATE("token"));
        if (!rotatedToken.empty()) EncryptStore(m_enc_token, rotatedToken);

        if (JsonBool(dec, OBFUSCATE("success"))) {
            std::string b64_data = JsonGet(dec, OBFUSCATE("data"));
            const std::string encryption = JsonGet(dec, OBFUSCATE("encryption"));
            const std::string fileId = JsonGet(dec, OBFUSCATE("file_id"));
            if (!b64_data.empty() && encryption == OBFUSCATE("TLS-SIGNED-SESSION-v2") &&
                !fileId.empty()) {
                std::vector<unsigned char> decoded = Base64Decode(b64_data);
                std::string plaintext(decoded.begin(), decoded.end());
                const std::string expectedHash = JsonGet(dec, OBFUSCATE("sha256"));
                const bool validHash = decoded.size() <= 100u * 1024u * 1024u &&
                    expectedHash.size() == 64 && SHA256Hex(plaintext) == expectedHash &&
                    expectedHash == JsonGet(ticketResponse, "sha256") &&
                    fileId == JsonGet(ticketResponse, "file_id");
                if (!plaintext.empty()) SecureZeroMemory(plaintext.data(), plaintext.size());
                if (!validHash) {
                    if (!decoded.empty()) SecureZeroMemory(decoded.data(), decoded.size());
                    SecureZeroMemory(token.data(), token.size());
                    SecureZeroMemory(deviceHwid.data(), deviceHwid.size());
                    return {};
                }
                SecureZeroMemory(token.data(), token.size());
                SecureZeroMemory(deviceHwid.data(), deviceHwid.size());
                return decoded;
            }
        }
        if (!token.empty()) SecureZeroMemory(token.data(), token.size());
        if (!deviceHwid.empty()) SecureZeroMemory(deviceHwid.data(), deviceHwid.size());
    } catch (...) {}
    return {};
}

bool Client::AutoUpdateLoader(const std::string& name, const std::string& currentVersion) {
    std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
    if (!m_logged_in || name.empty() || currentVersion.empty()) return false;
    try {
        std::string token = GetSessionToken();
        std::string hwid = GetHwid();
        std::string payload = std::string("{") +
            JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("hwid"), hwid) + "," +
            JsonStr(OBFUSCATE("name"), name) + "}";
        const std::string endpoint = OBFUSCATE("/api/client/download-ticket");
        std::string nonce;
        std::string response = DecryptResponse(Post(endpoint, BuildRequest(payload, nonce)), endpoint, nonce);
        std::string rotatedToken = JsonGet(response, OBFUSCATE("token"));
        std::string latestVersion = JsonGet(response, OBFUSCATE("version"));
        std::string fileType = JsonGet(response, OBFUSCATE("file_type"));
        if (!rotatedToken.empty()) EncryptStore(m_enc_token, rotatedToken);
        SecureZeroMemory(token.data(), token.size());
        SecureZeroMemory(hwid.data(), hwid.size());
        if (!JsonBool(response, OBFUSCATE("success")) || fileType != OBFUSCATE("loader") ||
            latestVersion.empty() || latestVersion == currentVersion) return false;

        std::vector<unsigned char> update = DownloadFile(name);
        if (update.size() < 2 || update[0] != 'M' || update[1] != 'Z') {
            if (!update.empty()) SecureZeroMemory(update.data(), update.size());
            return false;
        }
        std::vector<wchar_t> pathBuffer(32768);
        DWORD pathLength = GetModuleFileNameW(nullptr, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
        if (!pathLength || pathLength >= pathBuffer.size()) {
            SecureZeroMemory(update.data(), update.size());
            return false;
        }
        std::wstring target(pathBuffer.data(), pathLength);
        std::wstring staged = target + L".update";
        std::wstring script = target + L".update.cmd";
        HANDLE stagedFile = CreateFileW(staged.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (stagedFile == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(update.data(), update.size());
            return false;
        }
        DWORD written = 0;
        const bool wroteUpdate = WriteFile(stagedFile, update.data(), static_cast<DWORD>(update.size()),
                                           &written, nullptr) && written == update.size();
        FlushFileBuffers(stagedFile);
        CloseHandle(stagedFile);
        SecureZeroMemory(update.data(), update.size());
        if (!wroteUpdate) {
            DeleteFileW(staged.c_str());
            return false;
        }
        auto batchEscape = [](std::string value) {
            size_t pos = 0;
            while ((pos = value.find('%', pos)) != std::string::npos) { value.replace(pos, 1, "%%"); pos += 2; }
            return value;
        };
        const std::string targetUtf8 = batchEscape(WideToUtf8(target.c_str()));
        const std::string stagedUtf8 = batchEscape(WideToUtf8(staged.c_str()));
        std::string commands = "@echo off\r\n:wait\r\ntasklist /FI \"PID eq " +
            std::to_string(GetCurrentProcessId()) + "\" | find \"" +
            std::to_string(GetCurrentProcessId()) + "\" >nul\r\nif not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\n" +
            "move /Y \"" + stagedUtf8 + "\" \"" + targetUtf8 + "\" >nul\r\n" +
            "start \"\" \"" + targetUtf8 + "\"\r\ndel \"%~f0\"\r\n";
        HANDLE scriptFile = CreateFileW(script.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (scriptFile == INVALID_HANDLE_VALUE) {
            DeleteFileW(staged.c_str());
            return false;
        }
        written = 0;
        const bool wroteScript = WriteFile(scriptFile, commands.data(), static_cast<DWORD>(commands.size()),
                                           &written, nullptr) && written == commands.size();
        CloseHandle(scriptFile);
        if (!wroteScript) {
            DeleteFileW(staged.c_str());
            DeleteFileW(script.c_str());
            return false;
        }
        std::wstring commandLine = L"cmd.exe /D /C \"\"" + script + L"\"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        const BOOL launched = CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                                             CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
        if (!launched) {
            DeleteFileW(staged.c_str());
            DeleteFileW(script.c_str());
            return false;
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return true;
    } catch (...) {
        return false;
    }
}

void Client::StartHeartbeatThread(int interval_sec, std::function<void()> on_expire) {
    m_hb_callback = on_expire;
    m_hb_running  = true;
    m_hb_thread   = std::thread([this, interval_sec]() {
        HideThread();
        int fail_count = 0;
        while (m_hb_running) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
            if (!m_hb_running) break;
            auto r = Heartbeat();
            if (!r.success) {
                ++fail_count;
                if (fail_count >= 3) {
                    m_logged_in = false;
                    if (m_hb_callback) m_hb_callback();
                    break;
                }
            } else {
                fail_count = 0;
            }
        }
    });
}

void Client::StopHeartbeatThread() {
    m_hb_running = false;
    if (m_hb_thread.joinable()) m_hb_thread.join();
}

static void SehCheck() {
    __try {
        CloseHandle((HANDLE)0x1337);
    } __except (GetExceptionCode() == EXCEPTION_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // exit(0); // Aggressive handle check
    }
}

void Client::SecurityCheck() {
    auto t1 = std::chrono::high_resolution_clock::now();
    AntiDebug();
    if (CheckHardwareBreakpoints()) exit(0);
    if (CheckNtInformation()) exit(0);
    
    SehCheck();

    if (IsEmulated()) exit(0);
    CheckHooks();

    auto t2 = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    if (elapsed > 500) exit(0);

    HMODULE hWinHttp = GetModuleHandleA(OBFUSCATE("winhttp.dll").c_str());
    if (hWinHttp) {
        std::string funcName = OBFUSCATE("WinHttpSendRequest");
        auto pFunc = (BYTE*)GetProcAddress(hWinHttp, funcName.c_str());
        if (pFunc && (*pFunc == 0xE9 || *pFunc == 0xCC)) exit(0xCC);
    }

    // VM Detection
    // 1. Hypervisor bit in CPUID
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    // if ((cpuInfo[2] >> 31) & 1) exit(0); // Hypervisor check (triggers on many dev PCs)

    // 2. Registry checks
    std::string vmKey = OBFUSCATE("HARDWARE\\Description\\System\\CentralProcessor\\0");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256]; DWORD len = sizeof(buf);
        if (RegQueryValueExA(hKey, OBFUSCATE("ProcessorNameString").c_str(), nullptr, nullptr, (LPBYTE)buf, &len) == ERROR_SUCCESS) {
            std::string cpuName = buf;
            // if (cpuName.find(OBFUSCATE("QEMU")) != std::string::npos || cpuName.find(OBFUSCATE("Virtual")) != std::string::npos) exit(0);
        }
        RegCloseKey(hKey);
    }

    // 3. module checks
    if (GetModuleHandleA(OBFUSCATE("VBoxGuest.sys").c_str()) || 
        GetModuleHandleA(OBFUSCATE("vmmouse.sys").c_str()) ||
        GetModuleHandleA(OBFUSCATE("vmusbmouse.sys").c_str()) ||
        GetModuleHandleA(OBFUSCATE("vboxguest.sys").c_str())) exit(0);
    
    // check for open windows
    std::string x64 = OBFUSCATE("The x64dbg");
    std::string ce = OBFUSCATE("Cheat Engine");
    if (FindWindowA(NULL, x64.c_str()) || FindWindowA(NULL, ce.c_str())) exit(0);
}

void Client::AntiDebug() {
    if (IsDebuggerPresent()) exit(0);
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) exit(0);

    const std::vector<std::string> dbgProcs = {
        OBFUSCATE("x64dbg.exe"), OBFUSCATE("x32dbg.exe"), OBFUSCATE("ollydbg.exe"), OBFUSCATE("windbg.exe"), 
        OBFUSCATE("cheatengine-x86_64.exe"), OBFUSCATE("cheatengine-i386.exe"), OBFUSCATE("ida64.exe"), OBFUSCATE("ida.exe"),
        OBFUSCATE("HTTPDebuggerUI.exe"), OBFUSCATE("HTTPDebuggerSvc.exe"), OBFUSCATE("ProcessHacker.exe"), 
        OBFUSCATE("Scylla.exe"), OBFUSCATE("x96dbg.exe"), OBFUSCATE("Dbgview.exe"), OBFUSCATE("Fiddler.exe"),
        OBFUSCATE("Wireshark.exe"), OBFUSCATE("dumpcap.exe"), OBFUSCATE("dnSpy.exe")
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
#ifdef UNICODE
                std::string name = WideToUtf8(pe.szExeFile);
#else
                std::string name = pe.szExeFile;
#endif
                for (const auto& dbg : dbgProcs) {
                    if (_stricmp(name.c_str(), dbg.c_str()) == 0) {
                        CloseHandle(hSnap);
                        // exit(0); // Aggressive process check
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    // OutputDebugString check
    SetLastError(0);
    OutputDebugStringA(OBFUSCATE("EnAuth_Check").c_str());
    if (GetLastError() == 0 && IsDebuggerPresent()) exit(0);
}

bool Client::CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
    }
    return false;
}

bool Client::CheckNtInformation() {
    HMODULE hNtdll = GetModuleHandleA(OBFUSCATE("ntdll.dll").c_str());
    if (!hNtdll) return false;

    auto pNtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(hNtdll, OBFUSCATE("NtQueryInformationProcess").c_str());
    if (!pNtQueryInfo) return false;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = pNtQueryInfo(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    if (status == 0 && debugPort != 0) return true;

    DWORD debugFlags = 0;
    status = pNtQueryInfo(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL);
    if (status == 0 && debugFlags == 0) return true;

    HANDLE debugObject = NULL;
    status = pNtQueryInfo(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), NULL);
    if (status == 0 && debugObject != NULL) return true;

    return false;
}

void Client::HideThread() {
    HMODULE hNtdll = GetModuleHandleA(OBFUSCATE("ntdll.dll").c_str());
    if (!hNtdll) return;

    auto pNtSetInfo = (pNtSetInformationThread)GetProcAddress(hNtdll, OBFUSCATE("NtSetInformationThread").c_str());
    if (!pNtSetInfo) return;

    pNtSetInfo(GetCurrentThread(), (THREADINFOCLASS)ThreadHideFromDebugger, NULL, 0);
}

void Client::CheckHooks() {
    HMODULE hMod = GetModuleHandleA(OBFUSCATE("winhttp.dll").c_str());
    if (hMod) {
        BYTE* pFunc = (BYTE*)GetProcAddress(hMod, OBFUSCATE("WinHttpSendRequest").c_str());
        if (pFunc && (*pFunc == 0xE9 || *pFunc == 0xCC || *pFunc == 0xEB)) exit(0);
    }
    
    hMod = GetModuleHandleA(OBFUSCATE("kernel32.dll").c_str());
    if (hMod) {
        BYTE* pFunc = (BYTE*)GetProcAddress(hMod, OBFUSCATE("IsDebuggerPresent").c_str());
        if (pFunc && (*pFunc == 0xE9 || *pFunc == 0xCC || *pFunc == 0xEB)) exit(0);
    }
}

bool Client::IsEmulated() {
    // Timing check: __rdtsc measures CPU cycles
    unsigned __int64 t1 = __rdtsc();
    for (volatile int i = 0; i < 1000; i++) {
        // Simple loop
    }
    unsigned __int64 t2 = __rdtsc();
    
    // If the loop took an impossible amount of time (too fast or way too slow), 
    // it's likely being emulated or traced.
    unsigned __int64 diff = t2 - t1;
    if (diff < 10 || diff > 1000000) return true;
    
    return false;
}

} // namespace enauth
