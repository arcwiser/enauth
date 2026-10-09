#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#include <winhttp.h>

#include "string_obfuscation.h"

namespace enauth {

inline constexpr const char* SDK_VERSION = "2.2.0";

namespace hwid { std::string Collect(); }


enum class Status {
    Success,
    InvalidApp,
    OutdatedVersion,
    SdkUpdateRequired,
    InvalidKey,
    ExpiredKey,
    BannedKey,
    BannedHwid,
    MaxHwids,
    SessionExpired,
    SessionIdentityMismatch,
    NetworkError,
    ServerError,
    DecryptError,
    ReplayAttack,
    LevelRequired,
    LevelNotAllowed,
    AppPaused,
    ProductPaused,
    EntitlementPaused,
    SuspiciousLogin,
    Unknown,
};

struct InitResult {
    bool        success = false;
    Status      status  = Status::Unknown;
    std::string message;
    std::string server_time;
    std::string required_version;
    std::string minimum_sdk_version;
    std::string recommended_sdk_version;
    std::string upgrade_message;
};

struct LoginResult {
    bool        success    = false;
    Status      status     = Status::Unknown;
    std::string message;
    std::string token;
    std::string expires_at;
    std::string minimum_sdk_version;
    std::string recommended_sdk_version;
    std::string upgrade_message;
    std::map<std::string, std::string> variables;
};

struct SimpleResult {
    bool        success = false;
    Status      status  = Status::Unknown;
    std::string message;
};

struct NewsItem {
    std::string id;
    std::string title;
    std::string content;
    std::string color;
    std::string created_at;
};

struct NewsResult {
    bool                    success = false;
    Status                  status  = Status::Unknown;
    std::string             message;
    std::vector<NewsItem>   items;
};

// ─── Client ──────────────────────────────────────────────────────────────────

class Client {
public:
    /**
     * @param server_url   Base URL of the EnAuth server, e.g. "https://auth.example.com"
     * @param app_id       UUID of your application (from admin panel)
     * @param version      Version string that must match the server-side setting
     * @param response_public_key_hex ECDSA P-256 public key (X || Y, 128 hex chars)
     */
    Client(const std::string& server_url,
           const std::string& app_id,
           const std::string& version,
           const std::string& response_public_key_hex);

    ~Client();

    // ── Core API calls ──────────────────────────────────────────────────────

    /** Validate app version with server. Call this first. */
    InitResult   Init();

    /** Login with a license key. HWID is collected automatically.
     *  Optional product_id/level is sent for server-side level enforcement
     *  on multi-level keys. Pass empty strings if you don't use levels. */
    LoginResult  Login(const std::string& license_key,
                       const std::string& product_id = "",
                       const std::string& level      = "");

    /** Send heartbeat; returns false if session has expired. */
    SimpleResult Heartbeat();

    /** Gracefully log out and clear session. */
    SimpleResult Logout();

    /** Verify the current session is still valid. */
    SimpleResult ValidateSession();

    /**
     * Download an app file by name.
     * Content is decrypted and returned as a vector of bytes.
     * SHA-256 integrity of the payload is verified before returning.
     */
    std::vector<unsigned char> DownloadFile(const std::string& name);

    /**
     * Check the current loader release and stage a verified self-update when newer.
     * Returns true only when an updater was launched; the caller must exit promptly.
     */
    bool AutoUpdateLoader(const std::string& name, const std::string& current_version);

    /** Fetch public news items from the server. No login required after Init(). */
    NewsResult GetNews();

    // ── State ───────────────────────────────────────────────────────────────

    bool        IsInitialized()  const { return m_initialized; }
    bool        IsLoggedIn()     const { return m_logged_in; }
    std::string GetSessionToken() const;
    std::string GetLicenseKey()   const;
    std::string GetExpiresAt()    const;
    std::string GetHwid()        const;

    /** Get a global variable value by name. Returns empty if not found. */
    std::string GetVariable(const std::string& name, const std::string& fallback = "") {
        std::lock_guard<std::recursive_mutex> lock(m_request_mutex);
        auto it = m_variables.find(name);
        return (it != m_variables.end()) ? it->second : fallback;
    }

    // ── Heartbeat helper ────────────────────────────────────────────────────

    /**
     * Start a background thread that sends a heartbeat every `interval_sec` seconds.
     * `on_expire` runs on the heartbeat worker; it must not destroy this client.
     * Call StopHeartbeat() before destroying the client.
     */
    void StartHeartbeatThread(int interval_sec = 60,
                              std::function<void()> on_expire = nullptr);
    void StopHeartbeatThread();

private:
    // Serialize requests across token reads, network calls and token rotation.
    mutable std::recursive_mutex m_request_mutex;
    // Per-instance layered storage: a runtime XOR transform inside an
    // independently randomized AES-256-GCM envelope for every field.
    unsigned char m_xor_key = 0;
    std::vector<unsigned char> m_enc_memory_key;

    std::vector<unsigned char> m_enc_server_url;
    std::vector<unsigned char> m_enc_app_id;
    std::vector<unsigned char> m_enc_version;
    std::vector<unsigned char> m_enc_response_public_key;

    // Session state uses the same layered runtime storage.
    std::vector<unsigned char> m_enc_token;
    std::vector<unsigned char> m_enc_license_key;
    std::vector<unsigned char> m_enc_expires_at;

    std::string GetServerUrl()  const;
    std::string GetAppId()      const;
    std::string GetVersion()    const;
    std::string GetResponsePublicKey() const;

    void EncryptStore(std::vector<unsigned char>& target, const std::string& source);
    std::string DecryptField(const std::vector<unsigned char>& field) const;
    std::string GetMemoryKey() const;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_logged_in{false};
    std::map<std::string, std::string> m_variables;

    // Heartbeat thread
    std::thread            m_hb_thread;
    std::atomic<bool>      m_hb_running{false};
    std::function<void()>  m_hb_callback;

    // Internal helpers
    std::string  BuildRequest(const std::string& json_payload, std::string& request_nonce);
    std::string  Post(const std::string& endpoint, const std::string& body);
    std::string  DecryptResponse(const std::string& json_response,
                                 const std::string& endpoint,
                                 const std::string& request_nonce);
    SimpleResult ParseSimple(const std::string& decrypted_json);
    Status       MessageToStatus(const std::string& msg);

    // Security Logic
    void        SecurityCheck();
    static void AntiDebug();
    static bool CheckHardwareBreakpoints();
    static bool CheckNtInformation();
    static void HideThread();
    void        CheckHooks();
    static bool IsEmulated();
};

} // namespace enauth
