#pragma once
#include <Windows.h>
#include <tchar.h>

enum ProcessorArchitecture {
    AMD64 = 9,
    INTEL = 0,
};

#if _WIN64
#define PROCESSOR_ARCHITECTURE AMD64
#define SIZE_OF_SYSTEM_INFO_STREAM 48
#else
#define PROCESSOR_ARCHITECTURE INTEL
#define SIZE_OF_SYSTEM_INFO_STREAM 56
#endif

typedef struct _DUMP_CONTEXT {
    HANDLE  hProcess;
    PVOID   BaseAddress;
    ULONG32 RVA;
    SIZE_T  DumpMaxSize;
    ULONG32 Signature;
    USHORT  Version;
    USHORT  ImplementationVersion;
} DUMP_CONTEXT, * PDUMP_CONTEXT;

DWORD SandMiniDumpWriteDump(TCHAR* targetProcessName, WCHAR* dumpFilePath);
DWORD SandMiniDumpWriteDumpFromThread(PVOID* args);
