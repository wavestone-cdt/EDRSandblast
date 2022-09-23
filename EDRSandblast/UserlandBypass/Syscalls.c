#include <Windows.h>
#include "UserlandHooks.h"
#include "PEParser.h"
#include "PEBBrowse.h"

#define INVALID_SYSCALL_NUMBER 0xFFFFFFFF

DWORD GetSyscallNumberFromMemoryScanning(LPCSTR ntFunctionName) {
    PE* ntdll_disk;
    PE* ntdll_mem;
    getNtdllPEs(&ntdll_mem, &ntdll_disk);
    DWORD syscallNumber = INVALID_SYSCALL_NUMBER;

    PBYTE scanner = PE_functionAddr(ntdll_disk, ntFunctionName);
    for (int i = 0; i < 0x10; i++, scanner++) {
        PDWORD pPotentialSycallNumber = (PDWORD)(scanner + 1);
        if (*scanner == 0xB8 && *pPotentialSycallNumber < 0x10000) { //B8 : mov eax, imm32
            syscallNumber = *pPotentialSycallNumber;
            break;
        }
    }
    return syscallNumber;
}

typedef struct SYSCALL_t {
    LPCSTR Name;
    DWORD RVA;
    DWORD Number;
}SYSCALL;

int CmpSyscallsByRVA(SYSCALL const* a, SYSCALL const* b) {
    if (a->RVA < b->RVA) {
        return -1;
    }
    else if (a->RVA > b->RVA) {
        return +1;
    }
    else {
        return 0;
    }
}

int CmpSyscallsByName(SYSCALL const* a, SYSCALL const* b) {
    return strcmp(a->Name, b->Name);
}

DWORD g_nbSyscalls = 0;
DWORD g_nbSyscallsMax = 0;
SYSCALL* g_syscalls = NULL;

SYSCALL* GetSyscallTable(PDWORD syscallTableSize) {
    if (g_syscalls !=  NULL) {
        *syscallTableSize = g_nbSyscalls;
        return g_syscalls;
    }
    g_nbSyscallsMax = 0x10;
    g_syscalls = calloc(g_nbSyscallsMax, sizeof(SYSCALL));
    if (!g_syscalls) {
        return NULL;
    }
    PE* ntdll_mem = NULL;
    PE* ntdll_disk = NULL;
    getNtdllPEs(&ntdll_mem, &ntdll_disk);

    // Store all Zw* function as a syscall
    for (DWORD nameOrdinal = 0; nameOrdinal < ntdll_mem->exportedNamesLength; nameOrdinal++) {
        LPCSTR functionName = PE_RVA_to_Addr(ntdll_mem, ntdll_mem->exportedNames[nameOrdinal]);
        if (functionName[0]=='Z' && functionName[1] == 'w') {
            if (g_nbSyscalls == g_nbSyscallsMax) {
                g_nbSyscallsMax *= 2;
                PVOID tmp = realloc(g_syscalls, g_nbSyscallsMax * sizeof(SYSCALL));
                if (!tmp) {
                    return NULL;
                }
                g_syscalls = tmp;
            }
            g_syscalls[g_nbSyscalls].Name = functionName;
            g_syscalls[g_nbSyscalls].RVA = PE_functionRVA(ntdll_mem, functionName);
            g_nbSyscalls++;
        }
    }
    PVOID tmp = realloc(g_syscalls, g_nbSyscalls * sizeof(SYSCALL));
    if (!tmp || !g_nbSyscalls) {
        return NULL;
    }
    g_syscalls = tmp;
    g_nbSyscallsMax = g_nbSyscalls;

    // Sort the Zw* functions by RVA
    qsort(g_syscalls, g_nbSyscalls, sizeof(SYSCALL), CmpSyscallsByRVA);

    // Deduce the syscall numbers from order in table
    for (DWORD j = 0; j < g_nbSyscalls; j++) {
#pragma warning(disable : 6386) //compiler analysis is wrong for some reason (or maybe I am)
        g_syscalls[j].Number = j;
#pragma warning(disable : 6386)
    }
    // Sort the function back in alphabetical order
    qsort(g_syscalls, g_nbSyscalls, sizeof(SYSCALL), CmpSyscallsByName);

    *syscallTableSize = g_nbSyscalls;
    return g_syscalls;
}

DWORD GetSyscallNumberFromHardcodedInformation(LPCSTR ntFunctionName) {
    PE* ntdll_mem = NULL;
    PE* ntdll_disk = NULL;
    getNtdllPEs(&ntdll_mem, &ntdll_disk);

    DWORD syscallNumber = INVALID_SYSCALL_NUMBER;

    if (!strcmp(ntFunctionName, "NtProtectVirtualMemory")) {
        pRtlGetVersion RtlGetVersion = (pRtlGetVersion)PE_functionAddr(ntdll_mem, "RtlGetVersion");
        OSVERSIONINFOEXW versionInformation = { 0 };
        RtlGetVersion(&versionInformation);
        if (versionInformation.dwMajorVersion == 10 && versionInformation.dwMinorVersion == 0 && versionInformation.dwBuildNumber <= 19044) {
            syscallNumber = 0x50; // win10
        }
        else if (versionInformation.dwMajorVersion == 6 && versionInformation.dwMinorVersion == 3) {
            syscallNumber = 0x4F; // win8.1 / 2012 R2
        }
        else if (versionInformation.dwMajorVersion == 6 && versionInformation.dwMinorVersion == 2) {
            syscallNumber = 0x4E; // win8 / 2012
        }
        else if (versionInformation.dwMajorVersion <= 6) {
            syscallNumber = 0x4D; // win7 / 2008 R2 & before
        }
    }
    return syscallNumber;
}


DWORD GetSyscallNumberFromExportOrdering(LPCSTR ntFunctionName) {
    DWORD syscallTableSize;
    SYSCALL* syscallTable = GetSyscallTable(&syscallTableSize);
    if (syscallTable == NULL) {
        return INVALID_SYSCALL_NUMBER;
    }
    LPSTR zwFunctionName = _strdup(ntFunctionName);
    if (zwFunctionName == NULL) {
        return INVALID_SYSCALL_NUMBER;
    }
    zwFunctionName[0] = 'Z';
    zwFunctionName[1] = 'w';
    
    DWORD down = 0;
    DWORD up = syscallTableSize;
    while (up - down > 1) {
        DWORD mid = (down + up) / 2;
        if (strcmp(syscallTable[mid].Name, zwFunctionName) <= 0) {
            down = mid;
        }
        else {
            up = mid;
        }
    }
    if (!strcmp(syscallTable[down].Name, zwFunctionName)) {
        return syscallTable[down].Number;
    }
    else {
        return INVALID_SYSCALL_NUMBER;
    }
}

PVOID CreateSyscallStubWithVirtuallAlloc(LPCSTR ntFunctionName) {
    BYTE mov_eax_syscall_number[] = { 0xB8, 0x42, 0x42, 0x42, 0x42 };
    BYTE mov_r10_rcx[] = { 0x4C, 0x8B, 0xD1 };
    BYTE syscall_ret[] = { 0x0F, 0x05, 0xC3 };

    SIZE_T shellcode_len = sizeof(mov_eax_syscall_number) + sizeof(mov_r10_rcx) + sizeof(syscall_ret);
    PBYTE shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcode) {
        return NULL;
    }
    PBYTE pShellcode = shellcode;

    // get the syscall number through different techniques and check they give the same result
    DWORD syscallNumber = INVALID_SYSCALL_NUMBER;
    DWORD(*GetSyscallNumberFunc[])(LPCSTR) = { GetSyscallNumberFromMemoryScanning , GetSyscallNumberFromExportOrdering , GetSyscallNumberFromHardcodedInformation };

    for (DWORD i = 0; i < _countof(GetSyscallNumberFunc); i++) {
        DWORD syscallNumberCandidate = GetSyscallNumberFunc[i](ntFunctionName);
        if (syscallNumberCandidate != INVALID_SYSCALL_NUMBER) {
            if (syscallNumber != INVALID_SYSCALL_NUMBER && syscallNumber != syscallNumberCandidate) {
                return NULL;
            }
            syscallNumber = syscallNumberCandidate;
        }
    }

    if (syscallNumber == INVALID_SYSCALL_NUMBER) {
        return NULL;
    }

    *(DWORD*)&mov_eax_syscall_number[1] = syscallNumber;
    memcpy(pShellcode, mov_eax_syscall_number, sizeof(mov_eax_syscall_number));
    pShellcode += sizeof(mov_eax_syscall_number);
    memcpy(pShellcode, mov_r10_rcx, sizeof(mov_r10_rcx));
    pShellcode += sizeof(mov_r10_rcx);
    memcpy(pShellcode, syscall_ret, sizeof(syscall_ret));
    pShellcode += sizeof(syscall_ret);

    DWORD oldProtect;
    VirtualProtect(shellcode, shellcode_len, PAGE_EXECUTE_READ, &oldProtect);

    return shellcode;
}
