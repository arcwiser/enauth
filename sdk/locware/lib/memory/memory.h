#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>

class Memory {
private:
    HANDLE procHandle;
    DWORD procID;
public:
    Memory(const wchar_t* procName);
    ~Memory();

    bool AttachProcess(const wchar_t* procName);

    template <typename T>
    T ReadMemory(uintptr_t address) {
        T buffer{};
        ReadProcessMemory(procHandle, (LPCVOID)address, &buffer, sizeof(T), nullptr);
        return buffer;
    }

    template <typename T>
    bool WriteMemory(uintptr_t address, const T& data) {
        return WriteProcessMemory(procHandle, (LPVOID)address, &data, sizeof(T), nullptr);
    }

    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName);
};
