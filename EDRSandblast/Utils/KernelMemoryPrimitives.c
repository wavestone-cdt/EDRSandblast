#include <Windows.h>
#include <Tchar.h>
#include <stdio.h>
#include <assert.h>

#include "DriverRTCore.h"
#include "DriverDBUtil.h"
#include "DriverGDRV.h"
#include "KernelUtils.h"

#include "KernelMemoryPrimitives.h"

VOID ReadMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
    ReadMemoryPrimitive(Size, Address, Buffer);
}

VOID WriteMemory(DWORD64 Address, PVOID Buffer, SIZE_T Size) {
    WriteMemoryPrimitive(Size, Address, Buffer);
}

#define ReadMemoryType(TYPE) \
TYPE ReadMemory ## TYPE ## (DWORD64 Address) {\
    TYPE res;\
    ReadMemoryPrimitive(sizeof(TYPE), Address, &res);\
    return res;\
}
ReadMemoryType(BYTE);
ReadMemoryType(WORD);
ReadMemoryType(DWORD);
ReadMemoryType(DWORD64);

#define ReadKernelMemoryType(TYPE) \
TYPE ReadKernelMemory ## TYPE ## (DWORD64 Offset) {\
    TYPE res;\
    DWORD64 Address = FindNtoskrnlBaseAddress() + Offset;\
    ReadMemoryPrimitive(sizeof(TYPE), Address, &res);\
    return res;\
}

ReadKernelMemoryType(BYTE);
ReadKernelMemoryType(WORD);
ReadKernelMemoryType(DWORD);
ReadKernelMemoryType(DWORD64);

#define WriteMemoryType(TYPE) \
VOID WriteMemory ## TYPE ## (DWORD64 Address, TYPE Value) {\
    WriteMemoryPrimitive(sizeof(TYPE), Address, &Value);\
}

WriteMemoryType(BYTE);
WriteMemoryType(WORD);
WriteMemoryType(DWORD);
WriteMemoryType(DWORD64);


#define WriteKernelMemoryType(TYPE) \
VOID WriteKernelMemory ## TYPE ## (DWORD64 Offset, TYPE Value) {\
    DWORD64 Address = FindNtoskrnlBaseAddress() + Offset;\
    WriteMemoryPrimitive(sizeof(TYPE), Address, &Value);\
}

WriteKernelMemoryType(BYTE);
WriteKernelMemoryType(WORD);
WriteKernelMemoryType(DWORD);
WriteKernelMemoryType(DWORD64);

BOOL TestReadPrimitive() {
    WORD startWord = ReadKernelMemoryWORD(0);
    return ((startWord & 0xFF) == 'M') && ((startWord >> 8) == 'Z');
}
