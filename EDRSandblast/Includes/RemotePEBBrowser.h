#include <Windows.h>
#include <tchar.h>

#include "Undoc.h"

typedef struct _MODULE_INFO {
    struct _MODULE_INFO* next;
    ULONG64 dllBase;
    ULONG32 ImageSize;
    WCHAR dllName[256];
    ULONG32 nameRVA;
    ULONG32 timeDateStamp;
    ULONG32 checkSum;
} MODULE_INFO, * PMODULE_INFO;

typedef struct _MEMORY_PAGE_INFO {
    struct _MEMORY_PAGE_INFO* next;
    ULONG64 startOfMemoryPage;
    ULONG64 dataSize;
    DWORD   state;
    DWORD   protect;
    DWORD   type;
} MEMORY_PAGE_INFO, * PMEMORY_PAGE_INFO;

PVOID GetRVA(ULONG_PTR baseAddress, ULONG_PTR RVA);

// Return a pointer to the target process PEB Ldr (as a pseudo LDR_DATA_TABLE_ENTRY).
PLDR_DATA_TABLE_ENTRY getPebLdrAddress(HANDLE hProcess);

// Return a module info list of loaded moduler in InMemoryOrder.
PMODULE_INFO getModulesInLdrByInMemoryOrder(HANDLE hProcess);

PMEMORY_PAGE_INFO getMemoryPagesInfo(HANDLE hProcess, BOOL filterPage);