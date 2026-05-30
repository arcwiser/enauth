#ifndef STRING_OBFUSCATION_H
#define STRING_OBFUSCATION_H

#include <string>
#include <array>
#include <utility>

/**
 * EnAuth — Advanced Character-Unrolling Obfuscator
 * Designed to defeat MSVC String Pooling and /O2 optimizations.
 */

namespace enauth {
namespace internal {

template <size_t N, char K>
struct OpaqueData {
    std::array<char, N> encrypted_data;

    // The key is to XOR every character individually in the constructor
    // to prevent the compiler from storing the original literal.
    template <size_t... Is>
    constexpr OpaqueData(const char* str, std::index_sequence<Is...>)
        : encrypted_data{ static_cast<char>(str[Is] ^ K)... } {}

    std::string decrypt() const {
        std::string decrypted;
        decrypted.reserve(N);
        // Volatile key to force runtime execution
        volatile char key = K;
        for (size_t i = 0; i < N - 1; ++i) {
            decrypted += static_cast<char>(encrypted_data[i] ^ key);
        }
        return decrypted;
    }
};

template <size_t N, wchar_t K>
struct OpaqueWData {
    std::array<wchar_t, N> encrypted_data;

    template <size_t... Is>
    constexpr OpaqueWData(const wchar_t* str, std::index_sequence<Is...>)
        : encrypted_data{ static_cast<wchar_t>(str[Is] ^ K)... } {}

    std::wstring decrypt() const {
        std::wstring decrypted;
        decrypted.reserve(N);
        volatile wchar_t key = K;
        for (size_t i = 0; i < N - 1; ++i) {
            decrypted += static_cast<wchar_t>(encrypted_data[i] ^ key);
        }
        return decrypted;
    }
};

} // namespace internal
} // namespace enauth

// Macros to handle the index sequence generation
#define OBFUSCATE(s) ([]() { \
    constexpr size_t N = sizeof(s) / sizeof(char); \
    constexpr char K = static_cast<char>((N * 0x3F) ^ 0xAD); \
    static const enauth::internal::OpaqueData<N, K> obfuscated(s, std::make_index_sequence<N>{}); \
    return obfuscated.decrypt(); \
}())

#define W_OBFUSCATE(s) ([]() { \
    constexpr size_t N = sizeof(s) / sizeof(wchar_t); \
    constexpr wchar_t K = static_cast<wchar_t>((N * 0x3F) ^ 0xAD); \
    static const enauth::internal::OpaqueWData<N, K> obfuscated(s, std::make_index_sequence<N>{}); \
    return obfuscated.decrypt(); \
}())

#endif
