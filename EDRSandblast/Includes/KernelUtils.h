#pragma once
#include <Windows.h>

DWORD64 FindNtoskrnlBaseAddress(void);
TCHAR* FindDriverName(DWORD64 address, _Out_opt_ PDWORD64 offset);
TCHAR* FindDriverPath(DWORD64 address);
DWORD64 GetKernelFunctionAddress(LPCSTR function);
