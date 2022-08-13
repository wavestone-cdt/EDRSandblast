#pragma once
#include <Windows.h>
#include <tchar.h>

#include "../EDRSandblast.h"
#include "SW2_Syscalls.h"

#define ProcessImageFileName 27

DWORD SandGetProcessPID(HANDLE hProcess);

PUNICODE_STRING SandGetProcessImage(HANDLE hProcess);

DWORD SandGetProcessFilename(PUNICODE_STRING ProcessImageUnicodeStr, TCHAR* ImageFileName, DWORD  nSize);

DWORD SandFindProcessPidByName(TCHAR* targetProcessName, DWORD* pPid);