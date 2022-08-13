#pragma once

#include <Windows.h>

HANDLE GetDriverHandle_RTCore();
VOID CloseDriverHandle_RTCore();
VOID WriteMemoryPrimitive_RTCore(SIZE_T Size, DWORD64 Address, PVOID Buffer);
VOID ReadMemoryPrimitive_RTCore(SIZE_T Size, DWORD64 Address, PVOID Buffer);
