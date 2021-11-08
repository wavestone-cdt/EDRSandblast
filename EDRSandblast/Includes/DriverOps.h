/*

--- Driver install / uninstall functions.
--- Source and credit: https://github.com/gentilkiwi/mimikatz

*/

#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <Tchar.h>
#include <stdio.h>

#include "Globals.h"

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (_tprintf(TEXT("[!] ERROR ") TEXT(__FUNCTION__) TEXT(" ; ") func TEXT(" (0x%08x)\n"), GetLastError()))
#endif

#define MAX_UNINSTALL_ATTEMPTS 3
#define OP_SLEEP_TIME 1000

BOOL InstallVulnerableDriver(TCHAR* driverPath);

BOOL UninstallVulnerableDriver();