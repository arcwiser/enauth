#include "memory.h"

Memory::Memory(const wchar_t* procName)
{
    procHandle = nullptr;
    procID = 0;
    AttachProcess(procName);
}

Memory::~Memory()
{
    if (procHandle)
        CloseHandle(procHandle);
}

bool Memory::AttachProcess(const wchar_t* procName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do {
            if (!_wcsicmp(pe.szExeFile, procName))
            {
                procID = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    if (!procID)
        return false;

    procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    return procHandle != nullptr;
}

uintptr_t Memory::GetModuleBaseAddress(const wchar_t* moduleName)
{
    uintptr_t base = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me))
    {
        do {
            if (!_wcsicmp(me.szModule, moduleName))
            {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return base;
}
