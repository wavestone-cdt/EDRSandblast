#pragma once
#pragma comment(lib, "ntdll.lib")
#define DEFAULT_EVIL_DRIVER_FILE TEXT("evil.sys")

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) _tprintf_or_not(TEXT("[!] ERROR ") TEXT(__FUNCTION__) TEXT(" ; ") func TEXT(" (0x%08x)\n"), GetLastError())
#endif

BOOLEAN IsCiEnabled();
DWORD64  FindCIBaseAddress(BOOL verbose);
BOOL patch_gCiOptions(DWORD64 CiVariableAddress, ULONG CiOptionsValue, PULONG OldCiOptionsValue);
