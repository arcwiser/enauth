/* EnAuth Windows device fingerprinting. Raw identifiers never leave the client. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <intrin.h>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include "string_obfuscation.h"

std::string SHA256Hex(const std::string& data);

namespace enauth { namespace hwid {
static std::string HexDword(DWORD value) { std::ostringstream out; out << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value; return out.str(); }
static std::string Normalize(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) { return c == '\0' || std::isspace(c); }), value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    static const char* bad[] = {"", "UNKNOWN", "NONE", "DEFAULTSTRING", "TOBEFILLEDBYO.E.M.", "SYSTEMSERIALNUMBER"};
    for (const char* item : bad) if (value == item) return {};
    return value;
}
static std::string MachineGuid() {
    HKEY key = nullptr; char data[256] = {}; DWORD size = sizeof(data), type = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBFUSCATE("SOFTWARE\\Microsoft\\Cryptography").c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return {};
    const LONG result = RegQueryValueExA(key, OBFUSCATE("MachineGuid").c_str(), nullptr, &type, reinterpret_cast<BYTE*>(data), &size);
    RegCloseKey(key); return result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) ? Normalize(data) : std::string();
}
static std::string VolumeSerial() { DWORD serial = 0; return GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0) ? HexDword(serial) : std::string(); }
static std::string CpuSignature() { int cpu[4] = {}; __cpuid(cpu, 1); return HexDword(static_cast<DWORD>(cpu[0])) + HexDword(static_cast<DWORD>(cpu[3])); }
static std::string DiskSerial() {
    HANDLE disk = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (disk == INVALID_HANDLE_VALUE) return {};
    STORAGE_PROPERTY_QUERY query{}; query.PropertyId = StorageDeviceProperty; query.QueryType = PropertyStandardQuery;
    std::vector<BYTE> buffer(4096); DWORD returned = 0;
    const BOOL ok = DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr);
    CloseHandle(disk);
    if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return {};
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    if (!descriptor->SerialNumberOffset || descriptor->SerialNumberOffset >= returned) return {};
    return Normalize(reinterpret_cast<const char*>(buffer.data() + descriptor->SerialNumberOffset));
}
static std::string FirmwareUuid() {
    const DWORD provider = 'RSMB'; const UINT size = GetSystemFirmwareTable(provider, 0, nullptr, 0);
    if (size < 16 || size > 4 * 1024 * 1024) return {};
    std::vector<BYTE> data(size); if (GetSystemFirmwareTable(provider, 0, data.data(), size) != size) return {};
    const DWORD tableLength = *reinterpret_cast<const DWORD*>(data.data() + 4);
    size_t pos = 8, end = std::min<size_t>(data.size(), 8ull + tableLength);
    while (pos + 4 <= end) {
        const BYTE type = data[pos], length = data[pos + 1]; if (length < 4 || pos + length > end) break;
        if (type == 1 && length >= 25) {
            const BYTE* uuid = data.data() + pos + 8; bool allZero = true, allFF = true;
            for (int i = 0; i < 16; ++i) { allZero &= uuid[i] == 0; allFF &= uuid[i] == 0xFF; }
            if (!allZero && !allFF) { std::ostringstream out; for (int i = 0; i < 16; ++i) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(uuid[i]); return Normalize(out.str()); }
        }
        size_t next = pos + length; while (next + 1 < end && (data[next] != 0 || data[next + 1] != 0)) ++next; pos = next + 2;
    }
    return {};
}
static std::string HexBytes(const BYTE* data, size_t size) {
    std::ostringstream out;
    for (size_t i = 0; i < size; ++i) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return out.str();
}
static std::string InstallationSecret() {
    const std::string path = OBFUSCATE("Software\\EnAuth");
    const std::string valueName = OBFUSCATE("DeviceSeedV1");
    HKEY key = nullptr;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS) return {};
    std::vector<BYTE> protectedData(512); DWORD type = 0, size = static_cast<DWORD>(protectedData.size());
    LONG read = RegQueryValueExA(key, valueName.c_str(), nullptr, &type, protectedData.data(), &size);
    if (read != ERROR_SUCCESS || type != REG_BINARY || size == 0 || size > protectedData.size()) {
        BYTE random[32] = {};
        if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { RegCloseKey(key); return {}; }
        DATA_BLOB plain{sizeof(random), random}, sealed{};
        if (!CryptProtectData(&plain, L"EnAuth device seed", nullptr, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &sealed)) {
            SecureZeroMemory(random, sizeof(random)); RegCloseKey(key); return {};
        }
        const LONG written = RegSetValueExA(key, valueName.c_str(), 0, REG_BINARY, sealed.pbData, sealed.cbData);
        if (written == ERROR_SUCCESS) { protectedData.assign(sealed.pbData, sealed.pbData + sealed.cbData); size = sealed.cbData; }
        LocalFree(sealed.pbData); SecureZeroMemory(random, sizeof(random));
        if (written != ERROR_SUCCESS) { RegCloseKey(key); return {}; }
    } else protectedData.resize(size);
    RegCloseKey(key);
    DATA_BLOB sealed{size, protectedData.data()}, plain{};
    if (!CryptUnprotectData(&sealed, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return {};
    std::string result = plain.cbData == 32 ? HexBytes(plain.pbData, plain.cbData) : std::string();
    if (plain.pbData) { SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData); }
    SecureZeroMemory(protectedData.data(), protectedData.size());
    return result;
}
std::string CollectLegacy() {
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {}; DWORD nameLength = sizeof(name); GetComputerNameA(name, &nameLength);
    const std::string volume = VolumeSerial(), machine = MachineGuid();
    return SHA256Hex(OBFUSCATE("VOL:") + (volume.empty() ? OBFUSCATE("NOVOL") : volume) + OBFUSCATE("|GUID:") +
        (machine.empty() ? OBFUSCATE("NOGUID") : machine) + OBFUSCATE("|CPU:") + CpuSignature() + OBFUSCATE("|NAME:") + std::string(name));
}
static std::string CollectHardwareV2() {
    const std::string firmware = FirmwareUuid(), disk = DiskSerial(), machine = MachineGuid();
    const unsigned strongSignals = (!firmware.empty()) + (!disk.empty()) + (!machine.empty());
    if (strongSignals < 2) return CollectLegacy();
    return SHA256Hex(OBFUSCATE("ENA-HWID-V2|FW:") + firmware + OBFUSCATE("|DISK:") + disk + OBFUSCATE("|MACHINE:") + machine +
        OBFUSCATE("|VOL:") + VolumeSerial() + OBFUSCATE("|CPU:") + CpuSignature());
}
std::string CollectPrevious() { return CollectHardwareV2(); }
std::string Collect() {
    const std::string hardware = CollectHardwareV2(), seed = InstallationSecret();
    if (seed.empty()) return hardware;
    return SHA256Hex(OBFUSCATE("ENA-HWID-V3|HW:") + hardware + OBFUSCATE("|POSSESSION:") + seed);
}
} }
