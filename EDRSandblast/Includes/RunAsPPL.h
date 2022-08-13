/*

--- Functions to set the current process as a Protected Process (PsProtectedSignerWinTcb-Light).
--- The code to locate the EPROCESS structure is adapted from:
    http://blog.rewolf.pl/blog/?p=1683

*/

#pragma once

#include <Windows.h>

//extern union NtoskrnlOffsets ntoskrnlOffsets;



/*
* Defines the NtQuerySystemInformation function.
* Undocumented function with a signature subject to possible change in futher Windows versions.
*/
#define SystemHandleInformation 0x10
#define SystemHandleInformationBaseSize 0x1000

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

/*
* Source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm
*/
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

/*
* Source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
*/
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

/*
* Defines the structures related to the process protection (EPROCESS's Protection attribute).
* Source: https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
*/
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

DWORD64 GetSelfEPROCESSAddress(BOOL verbose);

int SetCurrentProcessAsProtected(BOOL verbose);
