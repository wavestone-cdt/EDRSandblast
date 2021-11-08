/*

--- LSASS dump functions.

*/

#pragma once

#include <Windows.h>
#include <Dbghelp.h>
#include <Tchar.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD WINAPI dumpLSASSProcess(void* data);