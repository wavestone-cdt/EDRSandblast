/*

--- ntoskrnl Notify Routines' offsets from CSV functions.
--- Hardcoded patterns, with offsets for 350+ ntoskrnl versions provided in the CSV file.

*/

#pragma once

#include <Windows.h>


enum NtoskrnlOffsetType {
    CREATE_PROCESS_ROUTINE,
    CREATE_THREAD_ROUTINE,
    LOAD_IMAGE_ROUTINE,
    PROTECTION_LEVEL,
    ETW_THREAT_INT_PROV_REG_HANDLE,
    ETW_REG_ENTRY_GUIDENTRY,
    ETW_GUID_ENTRY_PROVIDERENABLEINFO,
    PSPROCESSTYPE,
    PSTHREADTYPE,
    OBJECT_TYPE_CALLBACKLIST,
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
        // ntoskrnl EPROCESS's Protection field offset
        DWORD64 eprocess_protection;
        // ntoskrnl ETW Threat Intelligence's EtwThreatIntProvRegHandle
        DWORD64 etwThreatIntProvRegHandle;
        // ntoskrnl _ETW_REG_ENTRY's GuidEntry
        DWORD64 etwRegEntry_GuidEntry;
        // ntoskrnl _ETW_GUID_ENTRY's ProviderEnableInfo
        DWORD64 etwGuidEntry_ProviderEnableInfo;
        // ntoskrnl PsProcessType symbol offset
        DWORD64 psProcessType;
        // ntoskrnl PsThreadType symbol offset
        DWORD64 psThreadType;
        // ntoskrnl _OBJECT_TYPE's CallbackList symbol offset
        DWORD64 object_type_callbacklist;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_NTOSKRNL_OFFSETS_END];
};

union NtoskrnlOffsets g_ntoskrnlOffsets;

// Stores, in a global variable, the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
void LoadNtoskrnlOffsetsFromFile(TCHAR* ntoskrnlOffsetFilename);

// Saves the offsets, stored in global variable, in the provided CSV file
void SaveNtoskrnlOffsetsToFile(TCHAR* ntoskrnlOffsetFilename);

// Print the Ntosknrl offsets.
void PrintNtoskrnlOffsets();

void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb);

BOOL NtoskrnlOffsetsAreAllPresent();
BOOL NtoskrnlAllKernelCallbacksOffsetsArePresent();
BOOL NtoskrnlNotifyRoutinesOffsetsArePresent();
BOOL NtoskrnlEtwtiOffsetsArePresent();
BOOL NtoskrnlObjectCallbackOffsetsArePresent();