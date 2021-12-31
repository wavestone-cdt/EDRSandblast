/*

--- Driver install / uninstall functions.
--- Source and credit: https://github.com/gentilkiwi/mimikatz

*/

#pragma once
#include <Windows.h>

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (_tprintf(TEXT("[!] ERROR ") TEXT(__FUNCTION__) TEXT(" ; ") func TEXT(" (0x%08x)\n"), GetLastError()))
#endif

#define SERVICE_NAME_LENGTH 8
#define MAX_UNINSTALL_ATTEMPTS 3
#define OP_SLEEP_TIME 1000

TCHAR* GetServiceName(void);
void SetServiceName(TCHAR* newName, size_t szNewName);

BOOL InstallVulnerableDriver(TCHAR* driverPath);

BOOL UninstallVulnerableDriver(void);