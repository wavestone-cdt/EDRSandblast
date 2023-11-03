#pragma once
#pragma comment(lib, "ntdll.lib")
#define DEFAULT_EVIL_DRIVER_FILE TEXT("evil.sys")

#include "PrintFunctions.h"

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) _tprintf_or_not(TEXT("[!] ERROR ") TEXT(__FUNCTION__) TEXT(" ; ") func TEXT(" (0x%08x)\n"), GetLastError())
#endif


enum dseDisablingMethods_e {
    G_CIOPTIONS_PATCHING,
    CALLBACK_SWAPPING,
};

BOOLEAN IsCiEnabled();
DWORD64  FindCIBaseAddress();
BOOL patch_gCiOptions(DWORD64 CiVariableAddress, ULONG CiOptionsValue, PULONG OldCiOptionsValue);

BOOL disableDSE(enum dseDisablingMethods_e method, BOOL verbose);
BOOL reenableDSE(enum dseDisablingMethods_e method, BOOL verbose);


BOOL disableDSEbyCallbackSwapping(DWORD64* oldCiValidateImageHeaderEntryAddr);
BOOL reenableDSEbyCallbackSwapping(DWORD64 ciValidateImageHeaderEntryAddr);
BOOL disableDSEbyPatchingCiOptions(BOOL verbose, _Out_ ULONG* OldCiOptionsValue);
BOOL reenableDSEbyPatchingCiOptions(ULONG OldCiOptionsValue);