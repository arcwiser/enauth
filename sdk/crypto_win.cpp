/*
 *  EnAuth — Windows CNG (BCrypt) crypto helpers  [v2 — AES-256-GCM + PBKDF2]
 *
 *  Wire format (encrypt):
 *    Base64( salt[16] | nonce[12] | ciphertext | gcm_tag[16] )
 *
 *  HMAC covers:  app_id + "|" + timestamp + "|" + base64_data
 *
 *  Link: bcrypt.lib  crypt32.lib
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// ─── Constants ───────────────────────────────────────────────────────────────
static constexpr DWORD SALT_LEN      = 16;
static constexpr DWORD NONCE_LEN     = 12;
static constexpr DWORD GCM_TAG_LEN   = 16;
static constexpr DWORD AES_KEY_LEN   = 32;   // AES-256
static constexpr DWORD PBKDF2_ITERS  = 100000;

// ─── Utility ─────────────────────────────────────────────────────────────────

static std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : bytes) ss << std::setw(2) << (int)b;
    return ss.str();
}

static std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back((BYTE)std::stoul(hex.substr(i, 2), nullptr, 16));
    return out;
}

// ─── Base64 via CryptStringToBinary / CryptBinaryToString ────────────────────

std::string Base64Encode(const std::vector<BYTE>& data) {
    DWORD needed = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &needed);
    std::string out(needed, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &needed);
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    DWORD needed = 0;
    CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr);
    std::vector<BYTE> out(needed);
    CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64, out.data(), &needed, nullptr, nullptr);
    out.resize(needed);
    return out;
}

// ─── Random bytes ─────────────────────────────────────────────────────────────

static std::vector<BYTE> RandomBytes(DWORD count) {
    std::vector<BYTE> buf(count);
    if (BCryptGenRandom(nullptr, buf.data(), count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
    return buf;
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

std::string SHA256Hex(const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashLen = 0, objLen = 0, cbResult = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(DWORD), &cbResult, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,   (PBYTE)&hashLen, sizeof(DWORD), &cbResult, 0);

    std::vector<BYTE> hashObj(objLen), digest(hashLen);
    BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen, nullptr, 0, 0);
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, digest.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BytesToHex(digest);
}

// ─── PBKDF2-SHA256 key derivation ────────────────────────────────────────────
// Derives a 32-byte AES key from app_secret + salt using PBKDF2 with 100k iterations.

static std::vector<BYTE> DeriveKeyPBKDF2(const std::string& app_secret,
                                          const std::vector<BYTE>& salt) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    std::vector<BYTE> key(AES_KEY_LEN);

    // BCryptDeriveKeyPBKDF2 is available on Windows 8+ / Server 2012+
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)app_secret.data(), (ULONG)app_secret.size(),
        (PUCHAR)salt.data(),       (ULONG)salt.size(),
        PBKDF2_ITERS,
        key.data(), AES_KEY_LEN,
        0
    );

    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0)
        throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed");

    return key;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────
// Message format: app_id + "|" + timestamp_str + "|" + data_b64

std::string HmacSHA256Hex(const std::string& key, const std::string& msg) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashLen = 0, objLen = 0, cbResult = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(DWORD), &cbResult, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,   (PBYTE)&hashLen, sizeof(DWORD), &cbResult, 0);

    std::vector<BYTE> hashObj(objLen), digest(hashLen);
    BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen,
                     (PUCHAR)key.data(), (ULONG)key.size(), 0);
    BCryptHashData(hHash, (PUCHAR)msg.data(), (ULONG)msg.size(), 0);
    BCryptFinishHash(hHash, digest.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BytesToHex(digest);
}

// ─── AES-256-GCM Authenticated Encryption ────────────────────────────────────
//
// Wire format: Base64( salt[16] | nonce[12] | ciphertext | gcm_tag[16] )
//
// BCrypt GCM: use BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO with the nonce and tag.

std::string AES256GCMEncrypt(const std::string& plaintext, const std::string& app_secret) {
    auto salt  = RandomBytes(SALT_LEN);
    auto nonce = RandomBytes(NONCE_LEN);
    auto key   = DeriveKeyPBKDF2(app_secret, salt);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD objLen = 0, cbResult = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(DWORD), &cbResult, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    std::vector<BYTE> keyObj(objLen);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), objLen,
                               key.data(), AES_KEY_LEN, 0);

    std::vector<BYTE> tag(GCM_TAG_LEN, 0);
    std::vector<BYTE> nonceCopy = nonce;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce      = nonceCopy.data();
    authInfo.cbNonce      = NONCE_LEN;
    authInfo.pbTag        = tag.data();
    authInfo.cbTag        = GCM_TAG_LEN;
    authInfo.pbAuthData   = nullptr;
    authInfo.cbAuthData   = 0;

    std::vector<BYTE> pt(plaintext.begin(), plaintext.end());
    DWORD ctLen = (DWORD)pt.size();
    std::vector<BYTE> ct(ctLen);

    BCryptEncrypt(hKey, pt.data(), (ULONG)pt.size(),
                  &authInfo, nullptr, 0,
                  ct.data(), ctLen, &ctLen, 0);
    ct.resize(ctLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Assemble: salt | nonce | ciphertext | tag
    std::vector<BYTE> result;
    result.insert(result.end(), salt.begin(),  salt.end());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ct.begin(),    ct.end());
    result.insert(result.end(), tag.begin(),   tag.end());
    return Base64Encode(result);
}

std::string AES256GCMDecrypt(const std::string& b64, const std::string& app_secret) {
    auto raw = Base64Decode(b64);
    const size_t minLen = SALT_LEN + NONCE_LEN + GCM_TAG_LEN + 1;
    if (raw.size() < minLen)
        throw std::runtime_error("Ciphertext too short");

    std::vector<BYTE> salt (raw.begin(),                          raw.begin() + SALT_LEN);
    std::vector<BYTE> nonce(raw.begin() + SALT_LEN,              raw.begin() + SALT_LEN + NONCE_LEN);
    // ciphertext is everything between nonce and the last GCM_TAG_LEN bytes
    std::vector<BYTE> ct   (raw.begin() + SALT_LEN + NONCE_LEN,  raw.end()   - GCM_TAG_LEN);
    std::vector<BYTE> tag  (raw.end()   - GCM_TAG_LEN,           raw.end());

    auto key = DeriveKeyPBKDF2(app_secret, salt);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD objLen = 0, cbResult = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(DWORD), &cbResult, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    std::vector<BYTE> keyObj(objLen);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), objLen,
                               key.data(), AES_KEY_LEN, 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce    = nonce.data();
    authInfo.cbNonce    = NONCE_LEN;
    authInfo.pbTag      = tag.data();
    authInfo.cbTag      = GCM_TAG_LEN;
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;

    DWORD ptLen = (DWORD)ct.size();
    std::vector<BYTE> pt(ptLen);

    NTSTATUS status = BCryptDecrypt(hKey, ct.data(), (ULONG)ct.size(),
                                    &authInfo, nullptr, 0,
                                    pt.data(), ptLen, &ptLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // STATUS_AUTH_TAG_MISMATCH = 0xC000A002 — ciphertext was tampered
    if (status != 0)
        throw std::runtime_error("AES-GCM authentication failed — tampered ciphertext");

    pt.resize(ptLen);
    return std::string(pt.begin(), pt.end());
}

// ─── Legacy aliases (kept so enauth.cpp compiles without changes) ─────────────
// These forward to the new GCM functions.

std::string AES256CBCEncrypt(const std::string& plaintext, const std::string& app_secret) {
    return AES256GCMEncrypt(plaintext, app_secret);
}

std::string AES256CBCDecrypt(const std::string& b64, const std::string& app_secret) {
    return AES256GCMDecrypt(b64, app_secret);
}
