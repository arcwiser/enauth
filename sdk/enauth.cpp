/*
 *  EnAuth C++ Client — Implementation
 *
 *  Link: winhttp.lib  bcrypt.lib  crypt32.lib
 */
#include "enauth.h"
#include "string_obfuscation.h"
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
std::vector<unsigned char> Base64Decode(const std::string& b64);

// Declared in hwid.cpp
namespace enauth { namespace hwid { std::string Collect(); } }

namespace enauth {

// ─── JSON helpers (minimal, no external dep) ─────────────────────────────────

static std::string JsonStr(const std::string& k, const std::string& v) {
    return "\"" + k + "\":\"" + v + "\"";
}
static std::string JsonInt(const std::string& k, long long v) {
    return "\"" + k + "\":" + std::to_string(v);
}

static std::string JsonGet(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) ++pos;
    
    if (pos >= json.size()) return {};

    if (json[pos] == '"') {
        auto start = pos + 1;
        auto end   = json.find('"', start);
        if (end == std::string::npos) return {};
        return json.substr(start, end - start);
    }
    
    // Handle objects, arrays, or numbers/booleans
    auto start = pos;
    int depth = 0;
    while (pos < json.size()) {
        if (json[pos] == '{' || json[pos] == '[') depth++;
        else if (json[pos] == '}' || json[pos] == ']') {
            if (depth == 0) break;
            depth--;
        }
        else if (depth == 0 && (json[pos] == ',' || json[pos] == '}')) break;
        pos++;
    }
    return json.substr(start, pos - start);
}

static bool JsonBool(const std::string& json, const std::string& key) {
    return JsonGet(json, key) == OBFUSCATE("true");
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

    std::string result(static_cast<size_t>(required - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), required, nullptr, nullptr);
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
    if (!https && !localhost)
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
            if (response.size() + avail > 4 * 1024 * 1024) {
                WinHttpCloseHandle(hReq);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                throw std::runtime_error(OBFUSCATE("Server response exceeded 4 MiB"));
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

std::string Client::BuildRequest(const std::string& json_payload) {
    long long ts     = UnixTime();
    std::string secret = GetAppSecret();
    std::string appId  = GetAppId();
    std::string enc    = AES256CBCEncrypt(json_payload, secret);

    // HMAC now covers: app_id + "|" + ts + "|" + enc  (matches server)
    std::string hmacMsg = appId + "|" + std::to_string(ts) + "|" + enc;
    std::string sig     = HmacSHA256Hex(secret, hmacMsg);

    // Generate a per-request nonce (first 32 chars of a fresh random hex)
    // We reuse SHA256 of (sig + ts) as a cheap nonce — unique per request
    std::string nonce = SHA256Hex(sig + std::to_string(ts)).substr(0, 32);

    std::string res = std::string("{") +
        JsonStr(OBFUSCATE("app_id"), appId)          + "," +
        JsonStr(OBFUSCATE("data"),   enc)             + "," +
        JsonStr(OBFUSCATE("sig"),    sig)             + "," +
        JsonInt(OBFUSCATE("ts"),     ts)              + "," +
        JsonStr(OBFUSCATE("nonce"),  nonce)           +
        "}";

    SecureZeroMemory(&appId[0],  appId.size());
    SecureZeroMemory(&secret[0], secret.size());
    return res;
}

std::string Client::DecryptResponse(const std::string& json_response) {
    if (json_response.find(OBFUSCATE("\"data\"")) == std::string::npos) {
        std::string detail = JsonGet(json_response, OBFUSCATE("detail"));
        if (!detail.empty()) {
            return OBFUSCATE("{\"success\":false,\"message\":\"") + detail + OBFUSCATE("\"}");
        }
        return json_response;
    }

    std::string enc = JsonGet(json_response, OBFUSCATE("data"));
    if (enc.empty()) throw std::runtime_error(OBFUSCATE("No data in response"));
    
    std::string secret = GetAppSecret();
    std::string dec = AES256CBCDecrypt(enc, secret);
    SecureZeroMemory(&secret[0], secret.size());
    return dec;
}

Status Client::MessageToStatus(const std::string& msg) {
    if (msg == OBFUSCATE("INVALID_APP"))        return Status::InvalidApp;
    if (msg == OBFUSCATE("OUTDATED_VERSION"))   return Status::OutdatedVersion;
    if (msg == OBFUSCATE("INVALID_KEY"))        return Status::InvalidKey;
    if (msg == OBFUSCATE("EXPIRED_KEY"))        return Status::ExpiredKey;
    if (msg == OBFUSCATE("BANNED_KEY"))         return Status::BannedKey;
    if (msg == OBFUSCATE("BANNED_HWID"))        return Status::BannedHwid;
    if (msg == OBFUSCATE("MAX_HWIDS"))          return Status::MaxHwids;
    if (msg == OBFUSCATE("SESSION_EXPIRED"))    return Status::SessionExpired;
    if (msg == OBFUSCATE("LEVEL_REQUIRED"))     return Status::LevelRequired;
    if (msg == OBFUSCATE("LEVEL_NOT_ALLOWED"))  return Status::LevelNotAllowed;
    if (msg == OBFUSCATE("APP_PAUSED"))         return Status::AppPaused;
    if (msg == OBFUSCATE("PRODUCT_PAUSED"))     return Status::ProductPaused;
    if (msg == OBFUSCATE("ENTITLEMENT_PAUSED")) return Status::EntitlementPaused;
    if (msg == OBFUSCATE("OK"))                 return Status::Success;
    return Status::Unknown;
}

Client::Client(const std::string& server_url, const std::string& app_id,
               const std::string& app_secret, const std::string& version)
{
    m_xor_key = GenerateRuntimeKey();
    EncryptStore(m_enc_server_url, server_url);
    EncryptStore(m_enc_app_id,     app_id);
    EncryptStore(m_enc_app_secret, app_secret);
    EncryptStore(m_enc_version,    version);
    
#ifdef ENAUTH_ENABLE_ANTI_DEBUG
    SecurityCheck();
    HideThread();
#endif
}

void Client::EncryptStore(std::vector<unsigned char>& target, const std::string& source) {
    target.clear();
    for (size_t i = 0; i < source.size(); i++) {
        target.push_back((unsigned char)source[i] ^ m_xor_key);
    }
}

std::string Client::DecryptField(const std::vector<unsigned char>& field) const {
    std::string s;
    for (unsigned char b : field) s += (char)(b ^ m_xor_key);
    return s;
}

std::string Client::GetServerUrl()  const { return DecryptField(m_enc_server_url); }
std::string Client::GetAppId()      const { return DecryptField(m_enc_app_id); }
std::string Client::GetAppSecret()  const { return DecryptField(m_enc_app_secret); }
std::string Client::GetVersion()    const { return DecryptField(m_enc_version); }
std::string Client::GetSessionToken() const { return DecryptField(m_enc_token); }
std::string Client::GetLicenseKey()   const { return DecryptField(m_enc_license_key); }
std::string Client::GetExpiresAt()    const { return DecryptField(m_enc_expires_at); }

Client::~Client() { StopHeartbeatThread(); }

std::string Client::GetHwid() const { return hwid::Collect(); }

InitResult Client::Init() {
    SecurityCheck();
    InitResult result;
    try {
        std::string ver = GetVersion();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("version"), ver) + "}";
        SecureZeroMemory(&ver[0], ver.size());
        std::string body    = BuildRequest(payload);
        std::string raw     = Post(OBFUSCATE("/api/client/init"), body);
        std::string dec     = DecryptResponse(raw);

        result.success          = JsonBool(dec, OBFUSCATE("success"));
        result.message          = JsonGet(dec, OBFUSCATE("message"));
        result.status           = MessageToStatus(result.message);
        result.server_time      = JsonGet(dec, OBFUSCATE("server_time"));
        result.required_version = JsonGet(dec, OBFUSCATE("required_version"));

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
    LoginResult result;
    try {
        std::string hw = hwid::Collect();
        std::string payload = std::string("{") +
            JsonStr(OBFUSCATE("license_key"), license_key) + "," +
            JsonStr(OBFUSCATE("hwid"), hw);
        if (!product_id.empty()) payload += "," + JsonStr(OBFUSCATE("product_id"), product_id);
        if (!level.empty())      payload += "," + JsonStr(OBFUSCATE("level"), level);
        payload += "}";
        std::string body = BuildRequest(payload);
        std::string raw  = Post(OBFUSCATE("/api/client/login"), body);
        std::string dec  = DecryptResponse(raw);

        result.success    = JsonBool(dec, OBFUSCATE("success"));
        result.message    = JsonGet(dec, OBFUSCATE("message"));
        result.status     = MessageToStatus(result.message);
        result.token      = JsonGet(dec, OBFUSCATE("token"));
        result.expires_at = JsonGet(dec, OBFUSCATE("expires_at"));

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
    NewsResult result;
    try {
        std::string raw = Post(OBFUSCATE("/api/client/news"), BuildRequest("{}"));
        std::string dec = DecryptResponse(raw);

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
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "}";
        SecureZeroMemory(&token[0], token.size());
        std::string raw = Post(OBFUSCATE("/api/client/heartbeat"), BuildRequest(payload));
        std::string dec = DecryptResponse(raw);
        result.success  = JsonBool(dec, OBFUSCATE("success"));
        result.message  = JsonGet(dec, OBFUSCATE("message"));
        result.status   = MessageToStatus(result.message);
        if (!result.success) m_logged_in = false;
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

SimpleResult Client::Logout() {
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "}";
        SecureZeroMemory(&token[0], token.size());
        std::string raw = Post(OBFUSCATE("/api/client/logout"), BuildRequest(payload));
        std::string dec = DecryptResponse(raw);
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
    SimpleResult result;
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + JsonStr(OBFUSCATE("token"), token) + "}";
        SecureZeroMemory(&token[0], token.size());
        std::string raw = Post(OBFUSCATE("/api/client/validate"), BuildRequest(payload));
        std::string dec = DecryptResponse(raw);
        result.success  = JsonBool(dec, OBFUSCATE("success"));
        result.message  = JsonGet(dec, OBFUSCATE("message"));
        result.status   = MessageToStatus(result.message);
    } catch (const std::exception& e) {
        result.success = false;
        result.status  = Status::NetworkError;
        result.message = e.what();
    }
    return result;
}

std::vector<unsigned char> Client::DownloadFile(const std::string& name) {
    SecurityCheck();
    try {
        std::string token = GetSessionToken();
        std::string payload = std::string("{") + 
            JsonStr(OBFUSCATE("token"), token) + "," +
            JsonStr(OBFUSCATE("name"), name) + "}";
        SecureZeroMemory(&token[0], token.size());
        
        std::string raw = Post(OBFUSCATE("/api/client/download"), BuildRequest(payload));
        std::string dec = DecryptResponse(raw);

        if (JsonBool(dec, OBFUSCATE("success"))) {
            std::string b64_data = JsonGet(dec, OBFUSCATE("data"));
            if (!b64_data.empty()) {
                return Base64Decode(b64_data);
            }
        }
    } catch (...) {}
    return {};
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
