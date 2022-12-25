#include <Windows.h>
#include <Psapi.h>
#include <Tchar.h>

#include "../EDRSandblast.h"

DWORD64 g_NtoskrnlBaseAddress;
DWORD64 FindNtoskrnlBaseAddress(void) {
    if (g_NtoskrnlBaseAddress == 0) {
        DWORD cbNeeded = 0;
        LPVOID drivers[1024] = { 0 };

        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            g_NtoskrnlBaseAddress = (DWORD64)drivers[0];
        }
        else {
            return 0;
        }
    }
    return g_NtoskrnlBaseAddress;
}

/*
* Returns the name of the driver where "address" seems to be located
* Optionnaly, return in "offset" the distance between "address" and the driver base address.
*/
TCHAR* FindDriverName(DWORD64 address, _Out_opt_ PDWORD64 offset) {
    LPVOID drivers[1024] = { 0 };
    DWORD cbNeeded;
    int cDrivers = 0;
    int i = 0;
    TCHAR szDriver[1024] = { 0 };
    DWORD64 minDiff = MAXDWORD64;
    DWORD64 diff;
    if (offset) {
        *offset = 0;
    }
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < cDrivers; i++) {
            if ((DWORD64)drivers[i] <= address) {
                diff = address - (DWORD64)drivers[i];
                if (diff < minDiff) {
                    minDiff = diff;
                }
            }
        }
    }
    else {
        _tprintf_or_not(TEXT("[!] Could not resolve driver for 0x%I64x, an EDR driver might be missed\n"), address);
        return NULL;
    }

    if (GetDeviceDriverBaseName((LPVOID)(address - minDiff), szDriver, _countof(szDriver))) {

        if (offset) {
            *offset = minDiff;
        }

        TCHAR* const szDriver_cpy = _tcsdup(szDriver);

        if (!szDriver_cpy) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory to store the driver name"));
            return NULL;
        }

        return szDriver_cpy;
    }
    else {
        _tprintf_or_not(TEXT("[!] Could not resolve driver for 0x%I64x, an EDR driver might be missed\n"), address);
        return NULL;
    }
}

/*
* Return the driver path given an address in kernel memory (the driver base or an address inside)
* TODO : might return paths that begins with "\systemroot\" for the moment, need fixing (cf. Firewalling.c)
*/
TCHAR* FindDriverPath(DWORD64 address) {
    DWORD64 offset;
    TCHAR* name = FindDriverName(address, &offset);
    free(name);
    name = NULL;
    DWORD64 driverBaseAddress = address - offset;
    TCHAR szDriver[MAX_PATH] = { 0 };
    GetDeviceDriverFileName((PVOID)driverBaseAddress, szDriver, _countof(szDriver));
    TCHAR* const szDriver_cpy = _tcsdup(szDriver);

    if (!szDriver_cpy) {
        _putts_or_not(TEXT("[!] Couldn't allocate memory to store the driver path"));
        return NULL;
    }

    return szDriver_cpy;
}

DWORD64 GetKernelFunctionAddress(LPCSTR function) {
    DWORD64 ntoskrnlBaseAddress = FindNtoskrnlBaseAddress();
    DWORD64 address = 0;
    HMODULE ntoskrnl = LoadLibrary(TEXT("ntoskrnl.exe"));
    if (ntoskrnl) {
        DWORD64 offset = (DWORD64)(GetProcAddress(ntoskrnl, function)) - (DWORD64)(ntoskrnl);
        address = ntoskrnlBaseAddress + offset;
        FreeLibrary(ntoskrnl);
    }
    // _tprintf_or_not(TEXT("[+] %s address: 0x%I64x\n"), function, address);
    return address;
}

