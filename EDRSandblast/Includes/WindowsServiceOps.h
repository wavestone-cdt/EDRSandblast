#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <Tchar.h>
#include <stdio.h>
#include <time.h>

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) _tprintf_or_not(TEXT("[!] ERROR ") TEXT(__FUNCTION__) TEXT(" ; ") func TEXT(" (0x%08x)\n"), GetLastError())
#endif

#define MAX_UNINSTALL_ATTEMPTS 3
#define OP_SLEEP_TIME 1000

BOOL ServiceAddEveryoneAccess(SC_HANDLE serviceHandle);

BOOL ServiceGenericControl(PCTSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus);

DWORD ServiceInstall(PCTSTR serviceName, PCTSTR displayName, PCTSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt);

BOOL ServiceUninstall(PCTSTR serviceName, DWORD attemptCount);