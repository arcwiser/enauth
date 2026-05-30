/*
 *  EnAuth — Windows HWID collection
 *  Collects: Volume Serial, Machine GUID (registry), Computer Name, CPU info
 *  All combined and SHA-256 hashed → a stable, unique machine fingerprint
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <string>
#include <sstream>
#include <iomanip>

#include "string_obfuscation.h"

// Forward declaration (defined in crypto_win.cpp)
std::string SHA256Hex(const std::string& data);

namespace enauth {
namespace hwid {

static std::string GetVolumeSerial() {
    DWORD serial = 0;
    if (GetVolumeInformationA(OBFUSCATE("C:\\").c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << serial;
        return ss.str();
    }
    return OBFUSCATE("NOVOL");
}

static std::string GetMachineGuid() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        OBFUSCATE("SOFTWARE\\Microsoft\\Cryptography").c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return OBFUSCATE("NOGUID");

    char buf[256] = {};
    DWORD len = sizeof(buf);
    DWORD type = REG_SZ;
    RegQueryValueExA(hKey, OBFUSCATE("MachineGuid").c_str(), nullptr, &type, (LPBYTE)buf, &len);
    RegCloseKey(hKey);
    return std::string(buf);
}

static std::string GetComputerName_() {
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD len = sizeof(buf);
    GetComputerNameA(buf, &len);
    return std::string(buf);
}

static std::string GetCpuId() {
    int info[4] = {};
    __cpuid(info, 1);
    std::ostringstream ss;
    ss << std::hex << std::uppercase
       << std::setw(8) << std::setfill('0') << info[0]
       << std::setw(8) << std::setfill('0') << info[3];
    return ss.str();
}

/** Collect all hardware info, combine, and SHA-256 hash it. */
std::string Collect() {
    std::string raw =
        OBFUSCATE("VOL:")  + GetVolumeSerial()   +
        OBFUSCATE("|GUID:") + GetMachineGuid()    +
        OBFUSCATE("|CPU:")  + GetCpuId()          +
        OBFUSCATE("|NAME:") + GetComputerName_();
    return SHA256Hex(raw);
}

} // namespace hwid
} // namespace enauth
