#pragma once

#include <Windows.h>

HANDLE GetDriverHandle_DBUtil();
VOID CloseDriverHandle_DBUtil();
VOID WriteMemoryPrimitive_DBUtil(SIZE_T Size, DWORD64 Address, PVOID Buffer);
VOID ReadMemoryPrimitive_DBUtil(SIZE_T Size, DWORD64 Address, PVOID Buffer);
