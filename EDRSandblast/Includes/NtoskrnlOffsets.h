/*

--- ntoskrnl Notify Routines' offsets from CSV functions.
--- Hardcoded patterns, with offsets for 350+ ntoskrnl versions provided in the CSV file.

*/

#pragma once

#include <Windows.h>


enum NtoskrnlOffsetType {
    CREATE_PROCESS_ROUTINE = 0,
    CREATE_THREAD_ROUTINE = 1,
    LOAD_IMAGE_ROUTINE = 2,
    PROTECTION_LEVEL = 3,
    ETW_THREAT_INT_PROV_REG_HANDLE = 4,
    ETW_REG_ENTRY_GUIDENTRY = 5,
    ETW_GUID_ENTRY_PROVIDERENABLEINFO = 6,
    _SUPPORTED_NTOSKRNL_OFFSETS_END
};

union NtoskrnlOffsets {
    // structure version of ntoskrnl.exe's offsets
    struct {
        // ntoskrnl's PspCreateProcessNotifyRoutine
        DWORD64 pspCreateProcessNotifyRoutine;
        // ntoskrnl's PspCreateThreadNotifyRoutine
        DWORD64 pspCreateThreadNotifyRoutine;
        // ntoskrnl's PspLoadImageNotifyRoutine
        DWORD64 pspLoadImageNotifyRoutine;
        // ntoskrnl EPROCESS's _PS_PROTECTION
        DWORD64 ps_protection;
        // ntoskrnl ETW Threat Intelligence's EtwThreatIntProvRegHandle
        DWORD64 etwThreatIntProvRegHandle;
        // ntoskrnl _ETW_REG_ENTRY's GuidEntry
        DWORD64 etwRegEntry_GuidEntry;
        // ntoskrnl _ETW_GUID_ENTRY's ProviderEnableInfo
        DWORD64 etwGuidEntry_ProviderEnableInfo;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_NTOSKRNL_OFFSETS_END];
};

union NtoskrnlOffsets ntoskrnlOffsets;

// Return the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
union NtoskrnlOffsets GetNtoskrnlVersionOffsets(TCHAR* ntoskrnlOffsetFilename);