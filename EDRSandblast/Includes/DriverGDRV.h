#pragma once
#include <Windows.h>

HANDLE GetDriverHandle_GDRV();
VOID CloseDriverHandle_GDRV();
VOID ReadMemoryPrimitive_GDRV(SIZE_T Size, DWORD64 Address, PVOID Buffer);
VOID WriteMemoryPrimitive_GDRV(SIZE_T Size, DWORD64 Address, PVOID Buffer);
