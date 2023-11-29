#pragma once

#include <Windows.h>

#define RTCore 0
#define DBUtil 1
#define GDRV 2
// Select the driver to use with the following #define
#define VULN_DRIVER GDRV

//TODO : design a way to make an atomic write given a non-atomic one
//idea : modify a PTE to mark a page userland-reachable and perform the write from the process
#if VULN_DRIVER == RTCore
#define DEFAULT_DRIVER_FILE TEXT("RTCore64.sys")
#define CloseDriverHandle CloseDriverHandle_RTCore
#define ReadMemoryPrimitive ReadMemoryPrimitive_RTCore
#define WriteMemoryPrimitive WriteMemoryPrimitive_RTCore
#define WriteMemoryPrimitiveIsAtomic 0 //RTCore only allows to write up to a DWORD at a time
#elif VULN_DRIVER == DBUtil
#define DEFAULT_DRIVER_FILE TEXT("DBUtil_2_3.sys")
#define CloseDriverHandle CloseDriverHandle_DBUtil
#define ReadMemoryPrimitive ReadMemoryPrimitive_DBUtil
#define WriteMemoryPrimitive WriteMemoryPrimitive_DBUtil
#define WriteMemoryPrimitiveIsAtomic 1 //DBUtil allows to write an arbitrary size
#elif VULN_DRIVER == GDRV
#define DEFAULT_DRIVER_FILE TEXT("gdrv.sys")
#define CloseDriverHandle CloseDriverHandle_GDRV
#define ReadMemoryPrimitive ReadMemoryPrimitive_GDRV
#define WriteMemoryPrimitive WriteMemoryPrimitive_GDRV
#define WriteMemoryPrimitiveIsAtomic 1 //DBUtil allows to write an arbitrary size
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
