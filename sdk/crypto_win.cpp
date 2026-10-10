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
#include <cstring>
#include <limits>

// ─── Constants ───────────────────────────────────────────────────────────────
static constexpr DWORD SALT_LEN      = 16;
static constexpr DWORD NONCE_LEN     = 12;
static constexpr DWORD GCM_TAG_LEN   = 16;
static constexpr DWORD AES_KEY_LEN   = 32;   // AES-256
static constexpr DWORD PBKDF2_ITERS  = 100000;

class ScopedAlgorithm final {
public:
    BCRYPT_ALG_HANDLE value = nullptr;
    ~ScopedAlgorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
};

class ScopedHash final {
public:
    BCRYPT_HASH_HANDLE value = nullptr;
    ~ScopedHash() { if (value) BCryptDestroyHash(value); }
};

class ScopedKey final {
public:
    BCRYPT_KEY_HANDLE value = nullptr;
    ~ScopedKey() { if (value) BCryptDestroyKey(value); }
};

class ScopedWipe final {
public:
    explicit ScopedWipe(std::vector<BYTE>& value) : value_(value) {}
    ~ScopedWipe() { if (!value_.empty()) SecureZeroMemory(value_.data(), value_.size()); }
private:
    std::vector<BYTE>& value_;
};

static void RequireSuccess(NTSTATUS status, const char* operation) {
    if (status < 0) throw std::runtime_error(operation);
}

// ─── Utility ─────────────────────────────────────────────────────────────────

static std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : bytes) ss << std::setw(2) << (int)b;
    return ss.str();
}

static std::vector<BYTE> HexToBytes(const std::string& hex) {
    if (hex.empty() || (hex.size() % 2) != 0)
        throw std::runtime_error("Invalid hexadecimal input");
    std::vector<BYTE> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> BYTE {
        if (c >= '0' && c <= '9') return static_cast<BYTE>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<BYTE>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<BYTE>(c - 'A' + 10);
        throw std::runtime_error("Invalid hexadecimal input");
    };
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<BYTE>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    return out;
}

// ─── Base64 via CryptStringToBinary / CryptBinaryToString ────────────────────

std::string Base64Encode(const std::vector<BYTE>& data) {
    if (data.size() > std::numeric_limits<DWORD>::max())
        throw std::runtime_error("Base64 input too large");
    DWORD needed = 0;
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &needed))
        throw std::runtime_error("Base64 encoding failed");
    std::string out(needed, '\0');
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &needed))
        throw std::runtime_error("Base64 encoding failed");
    while (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    if (b64.size() > std::numeric_limits<DWORD>::max())
        throw std::runtime_error("Base64 input too large");
    DWORD needed = 0;
    if (b64.empty() || !CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                         nullptr, &needed, nullptr, nullptr))
        throw std::runtime_error("Invalid base64 input");
    std::vector<BYTE> out(needed);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                         out.data(), &needed, nullptr, nullptr))
        throw std::runtime_error("Invalid base64 input");
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

std::string SecureRandomHex(size_t byteCount) {
    if (byteCount > std::numeric_limits<DWORD>::max())
        throw std::runtime_error("Random request too large");
    auto bytes = RandomBytes(static_cast<DWORD>(byteCount));
    ScopedWipe wipeBytes(bytes);
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (BYTE value : bytes) {
        result.push_back(hex[(value >> 4) & 0x0F]);
        result.push_back(hex[value & 0x0F]);
    }
    return result;
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

std::string SHA256Hex(const std::string& data) {
    if (data.size() > std::numeric_limits<ULONG>::max())
        throw std::runtime_error("SHA-256 input too large");
    ScopedAlgorithm algorithm;
    ScopedHash hash;
    DWORD hashLen = 0, objLen = 0, cbResult = 0;

    RequireSuccess(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
                   "SHA-256 provider initialization failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen,
                                    sizeof(DWORD), &cbResult, 0), "SHA-256 object query failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_HASH_LENGTH, (PBYTE)&hashLen,
                                    sizeof(DWORD), &cbResult, 0), "SHA-256 length query failed");
    if (objLen == 0 || hashLen != 32) throw std::runtime_error("Unexpected SHA-256 provider properties");

    std::vector<BYTE> hashObj(objLen), digest(hashLen);
    ScopedWipe wipeObject(hashObj), wipeDigest(digest);
    RequireSuccess(BCryptCreateHash(algorithm.value, &hash.value, hashObj.data(), objLen, nullptr, 0, 0),
                   "SHA-256 hash initialization failed");
    RequireSuccess(BCryptHashData(hash.value, (PUCHAR)data.data(), (ULONG)data.size(), 0),
                   "SHA-256 update failed");
    RequireSuccess(BCryptFinishHash(hash.value, digest.data(), hashLen, 0),
                   "SHA-256 finalization failed");
    return BytesToHex(digest);
}

// ─── PBKDF2-SHA256 key derivation ────────────────────────────────────────────
// Derives a 32-byte AES key from app_secret + salt using PBKDF2 with 100k iterations.

static std::vector<BYTE> DeriveKeyPBKDF2(const std::string& app_secret,
                                          const std::vector<BYTE>& salt) {
    if (app_secret.empty() || app_secret.size() > std::numeric_limits<ULONG>::max() ||
        salt.empty() || salt.size() > std::numeric_limits<ULONG>::max())
        throw std::runtime_error("Invalid PBKDF2 input");
    ScopedAlgorithm algorithm;
    std::vector<BYTE> key(AES_KEY_LEN);

    // BCryptDeriveKeyPBKDF2 is available on Windows 8+ / Server 2012+
    RequireSuccess(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr,
                                               BCRYPT_ALG_HANDLE_HMAC_FLAG),
                   "PBKDF2 provider initialization failed");

    NTSTATUS status = BCryptDeriveKeyPBKDF2(
        algorithm.value,
        (PUCHAR)app_secret.data(), (ULONG)app_secret.size(),
        (PUCHAR)salt.data(),       (ULONG)salt.size(),
        PBKDF2_ITERS,
        key.data(), AES_KEY_LEN,
        0
    );

    RequireSuccess(status, "PBKDF2 derivation failed");

    return key;
}

// ─── HMAC-SHA256 ─────────────────────────────────────────────────────────────
// Message format: app_id + "|" + timestamp_str + "|" + data_b64

std::string HmacSHA256Hex(const std::string& key, const std::string& msg) {
    if (key.empty() || key.size() > std::numeric_limits<ULONG>::max() ||
        msg.size() > std::numeric_limits<ULONG>::max())
        throw std::runtime_error("Invalid HMAC input");
    ScopedAlgorithm algorithm;
    ScopedHash hash;
    DWORD hashLen = 0, objLen = 0, cbResult = 0;

    RequireSuccess(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr,
                                               BCRYPT_ALG_HANDLE_HMAC_FLAG),
                   "HMAC provider initialization failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen,
                                    sizeof(DWORD), &cbResult, 0), "HMAC object query failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_HASH_LENGTH, (PBYTE)&hashLen,
                                    sizeof(DWORD), &cbResult, 0), "HMAC length query failed");
    if (objLen == 0 || hashLen != 32) throw std::runtime_error("Unexpected HMAC provider properties");

    std::vector<BYTE> hashObj(objLen), digest(hashLen);
    ScopedWipe wipeObject(hashObj), wipeDigest(digest);
    RequireSuccess(BCryptCreateHash(algorithm.value, &hash.value, hashObj.data(), objLen,
                                    (PUCHAR)key.data(), (ULONG)key.size(), 0),
                   "HMAC initialization failed");
    RequireSuccess(BCryptHashData(hash.value, (PUCHAR)msg.data(), (ULONG)msg.size(), 0),
                   "HMAC update failed");
    RequireSuccess(BCryptFinishHash(hash.value, digest.data(), hashLen, 0),
                   "HMAC finalization failed");
    return BytesToHex(digest);
}

bool VerifyEcdsaP256Signature(const std::string& publicKeyHex,
                             const std::string& message,
                             const std::string& signatureB64) {
    if (publicKeyHex.size() != 128) return false;
    std::vector<BYTE> coordinates;
    std::vector<BYTE> signature;
    try {
        coordinates = HexToBytes(publicKeyHex);
        signature = Base64Decode(signatureB64);
    }
    catch (...) { return false; }
    if (coordinates.size() != 64 || signature.size() != 64) return false;
    ScopedWipe wipeCoordinates(coordinates), wipeSignature(signature);

    ScopedAlgorithm algorithm;
    ScopedKey publicKey;
    if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0)
        return false;

    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header.cbKey = 32;
    std::vector<BYTE> blob(sizeof(header) + coordinates.size());
    ScopedWipe wipeBlob(blob);
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), coordinates.data(), coordinates.size());
    if (BCryptImportKeyPair(algorithm.value, nullptr, BCRYPT_ECCPUBLIC_BLOB, &publicKey.value,
                            blob.data(), static_cast<ULONG>(blob.size()), 0) != 0) {
        return false;
    }

    auto digest = HexToBytes(SHA256Hex(message));
    ScopedWipe wipeDigest(digest);
    const NTSTATUS status = BCryptVerifySignature(
        publicKey.value, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0);
    return status == 0;
}

// ─── AES-256-GCM Authenticated Encryption ────────────────────────────────────
//
// Wire format: Base64( salt[16] | nonce[12] | ciphertext | gcm_tag[16] )
//
// BCrypt GCM: use BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO with the nonce and tag.

std::string AES256GCMEncrypt(const std::string& plaintext, const std::string& app_secret) {
    if (plaintext.empty() || plaintext.size() > std::numeric_limits<ULONG>::max())
        throw std::runtime_error("Invalid AES-GCM plaintext");
    auto salt  = RandomBytes(SALT_LEN);
    auto nonce = RandomBytes(NONCE_LEN);
    auto key   = DeriveKeyPBKDF2(app_secret, salt);
    ScopedWipe wipeSalt(salt), wipeNonce(nonce), wipeKey(key);

    ScopedAlgorithm algorithm;
    ScopedKey aesKey;
    DWORD objLen = 0, cbResult = 0;

    RequireSuccess(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_AES_ALGORITHM, nullptr, 0),
                   "AES provider initialization failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen,
                                    sizeof(DWORD), &cbResult, 0), "AES object query failed");
    if (objLen == 0) throw std::runtime_error("Unexpected AES provider properties");
    RequireSuccess(BCryptSetProperty(algorithm.value, BCRYPT_CHAINING_MODE,
                                    (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0),
                   "AES-GCM mode setup failed");

    std::vector<BYTE> keyObj(objLen);
    ScopedWipe wipeKeyObject(keyObj);
    RequireSuccess(BCryptGenerateSymmetricKey(algorithm.value, &aesKey.value, keyObj.data(), objLen,
                                              key.data(), AES_KEY_LEN, 0),
                   "AES key initialization failed");

    std::vector<BYTE> tag(GCM_TAG_LEN, 0);
    std::vector<BYTE> nonceCopy = nonce;
    ScopedWipe wipeTag(tag), wipeNonceCopy(nonceCopy);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce      = nonceCopy.data();
    authInfo.cbNonce      = NONCE_LEN;
    authInfo.pbTag        = tag.data();
    authInfo.cbTag        = GCM_TAG_LEN;
    authInfo.pbAuthData   = nullptr;
    authInfo.cbAuthData   = 0;

    std::vector<BYTE> pt(plaintext.begin(), plaintext.end());
    ScopedWipe wipePlaintext(pt);
    DWORD ctLen = (DWORD)pt.size();
    std::vector<BYTE> ct(ctLen);
    ScopedWipe wipeCiphertext(ct);

    RequireSuccess(BCryptEncrypt(aesKey.value, pt.data(), (ULONG)pt.size(),
                                 &authInfo, nullptr, 0,
                                 ct.data(), ctLen, &ctLen, 0),
                   "AES-GCM encryption failed");
    if (ctLen > ct.size()) throw std::runtime_error("Invalid AES-GCM output length");
    ct.resize(ctLen);

    // Assemble: salt | nonce | ciphertext | tag
    std::vector<BYTE> result;
    result.reserve(salt.size() + nonce.size() + ct.size() + tag.size());
    result.insert(result.end(), salt.begin(),  salt.end());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ct.begin(),    ct.end());
    result.insert(result.end(), tag.begin(),   tag.end());
    ScopedWipe wipeResult(result);
    return Base64Encode(result);
}

std::string AES256GCMDecrypt(const std::string& b64, const std::string& app_secret) {
    auto raw = Base64Decode(b64);
    ScopedWipe wipeRaw(raw);
    const size_t minLen = SALT_LEN + NONCE_LEN + GCM_TAG_LEN + 1;
    if (raw.size() < minLen)
        throw std::runtime_error("Ciphertext too short");

    std::vector<BYTE> salt (raw.begin(),                          raw.begin() + SALT_LEN);
    std::vector<BYTE> nonce(raw.begin() + SALT_LEN,              raw.begin() + SALT_LEN + NONCE_LEN);
    // ciphertext is everything between nonce and the last GCM_TAG_LEN bytes
    std::vector<BYTE> ct   (raw.begin() + SALT_LEN + NONCE_LEN,  raw.end()   - GCM_TAG_LEN);
    std::vector<BYTE> tag  (raw.end()   - GCM_TAG_LEN,           raw.end());
    ScopedWipe wipeSalt(salt), wipeNonce(nonce), wipeCiphertext(ct), wipeTag(tag);

    auto key = DeriveKeyPBKDF2(app_secret, salt);
    ScopedWipe wipeKey(key);

    ScopedAlgorithm algorithm;
    ScopedKey aesKey;
    DWORD objLen = 0, cbResult = 0;

    RequireSuccess(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_AES_ALGORITHM, nullptr, 0),
                   "AES provider initialization failed");
    RequireSuccess(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen,
                                    sizeof(DWORD), &cbResult, 0), "AES object query failed");
    if (objLen == 0) throw std::runtime_error("Unexpected AES provider properties");
    RequireSuccess(BCryptSetProperty(algorithm.value, BCRYPT_CHAINING_MODE,
                                    (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0),
                   "AES-GCM mode setup failed");

    std::vector<BYTE> keyObj(objLen);
    ScopedWipe wipeKeyObject(keyObj);
    RequireSuccess(BCryptGenerateSymmetricKey(algorithm.value, &aesKey.value, keyObj.data(), objLen,
                                              key.data(), AES_KEY_LEN, 0),
                   "AES key initialization failed");

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
    ScopedWipe wipePlaintext(pt);

    NTSTATUS status = BCryptDecrypt(aesKey.value, ct.data(), (ULONG)ct.size(),
                                    &authInfo, nullptr, 0,
                                    pt.data(), ptLen, &ptLen, 0);

    // STATUS_AUTH_TAG_MISMATCH = 0xC000A002 — ciphertext was tampered
    if (status != 0)
        throw std::runtime_error("AES-GCM authentication failed — tampered ciphertext");

    if (ptLen > pt.size()) throw std::runtime_error("Invalid AES-GCM output length");
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
