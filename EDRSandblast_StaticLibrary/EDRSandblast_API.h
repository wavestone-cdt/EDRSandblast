#pragma once
#include <Windows.h>

#include "..\EDRSandblast\Includes\PrintFunctions.h"
#include "..\EDRSandblast\Includes\UserlandHooks.h"

typedef struct EDRSB_SINGLETONS_t {
    HANDLE NtdllCopyHandle;
} EDRSB_SINGLETONS;


typedef struct EDRSB_CONTEXT_t {
    // Generic
    struct EDRSB_CONFIG_t* config;
    // Kernel related
    BOOL isDriverInstalled;
    BOOL krnlmodeMonitoringEnumDone;
    BOOL foundNotifyRoutineCallbacks;
    BOOL foundObjectCallbacks;
    BOOL foundMinifilterCallbacks;
    struct FOUND_EDR_CALLBACKS* foundEDRDrivers;
    BOOL isETWTISystemEnabled;
    BOOL isETWTICurrentlyEnabled;
    // Usermode related
    BOOL usermodeMonitoringRemoved;
    HOOK* foundUserlandHooks;
    // Singletons / open handles / allocated buffer, etc. that should be opened once and used multiple times
    EDRSB_SINGLETONS Cache;
} EDRSB_CONTEXT;


typedef struct EDRSB_BYPASS_MODE_t {
    BYTE Usermode : 1;
    BYTE Krnlmode : 1;
} EDRSB_BYPASS_MODE;

typedef enum EDRSB_USERMODE_TECHNIQUE_e {
    EDRSB_UMTECH_Unhook_with_ntdll_NtProtectVirtualMemory,
    EDRSB_UMTECH_Copy_ntdll_and_load,
    EDRSB_UMTECH_Allocate_trampoline,
    EDRSB_UMTECH_Find_and_use_existing_trampoline,
    EDRSB_UMTECH_Use_direct_syscall,
} EDRSB_USERMODE_TECHNIQUE;

// TODO: update values.
typedef struct EDRSB_ACTIONS_t {
    DWORD ProtectProcess : 1;
    DWORD BypassCredguard : 1;
    DWORD ExecProcess : 1;
    DWORD FirewallEDR : 1;
    DWORD DontUnloadDriver : 1;
    DWORD DontRestoreCallBacks : 1;
    DWORD DontRestoreETWTI : 1;
} EDRSB_ACTIONS;

typedef struct EDRSB_OFFSETS_RETRIEVAL_METHOD_t {
    BYTE Embeded : 1;
    BYTE File : 1;
    BYTE Internet : 1;
} EDRSB_OFFSETS_RETRIEVAL_METHOD;

typedef enum EDRSB_STATUS_e {
    EDRSB_SUCCESS,
    //Driver related errors
    EDRSB_DRIVER_NOT_SPECIFIED,
    EDRSB_DRIVER_NOT_FOUND,
    EDRSB_DRIVER_INSTALL_FAILED,
    // Config related errors.
    EDRSB_KERNEL_OFFSETS_NOT_FOUND,
    EDRSB_WDIGEST_OFFSETS_NOT_FOUND,
    // Kernel mode related errors.
    EDRSB_MISSING_KRNLMODE,
    // Usermode mode related errors.
    EDRSB_NT_FUNCTION_NOT_FOUND,
    EDRSB_TRAMPOLINE_NOT_FOUND,
    EDRSB_FUNCTION_NOT_HOOKED,
    EDRSB_NTPROTECTVIRTUALMEMORY_FAILED,
    // Actions related errors.
    EDRSB_MISSING_DUMPPROCESS,
    EDRSB_MISSING_PROTECTPROCESS,
    EDRSB_MISSING_BYPASSCREDGUARD,
    EDRSB_MISSING_EXECPROCESS,
    EDRSB_MISSING_FIREWALLEDR,
    EDRSB_BYPASSCREDGUARD_FAILED,
    EDRSB_EXECPROCESS_FAILED,
    //Other errors
    EDRSB_FAILURE,
    EDRSB_MEMALLOC_FAIL,
    EDRSB_KNRL_MONITORING,
    EDRSB_ACCESS_DENIED,  
} EDRSB_STATUS;

/*
* EDRSandblast configuration structure
*/
typedef struct EDRSB_CONFIG_t {
    /*
    * Defines the bypass mode to use.
    */
    EDRSB_BYPASS_MODE bypassMode;

    /*
    * Defines the actions that will be performed.
    */
    EDRSB_ACTIONS actions;

    EDRSB_OFFSETS_RETRIEVAL_METHOD offsetRetrievalMethod;

    /*
    * Path of the CSV file that contains the needed offsets for kernel mode operations
    * If NULL, tries to load NtoskrnlOffsets.csv
    * If empty string, disable NtoskrnlOffsets.csv loading (relies on symbol download every time)
    */
    LPWSTR kernelOffsetFilePath; //TODO : unifier les offsets dans un seul fichier (un json ?) pour �viter de demander � l'utilisateur de passer plusieurs fichiers

    /*
    * Path of the CSV file that contains the needed offsets for minifilter enum and bypass
    * If NULL, tries to load FltmgrOffsets.csv
    * If empty string, disable FltmgrOffsets.csv loading (relies on symbol download every time)
    */
    LPWSTR fltmgrOffsetFilePath;
    /*
    * Path of the CSV file that contains the needed offsets for credential guard related operations
    * If NULL, tries to load WdigestOffsets.csv
    * If empty string, disable WdigestOffsets.csv loading (relies on symbol download every time)
    */
    LPWSTR wdigestOffsetFilePath;

    /*
    * Path of the vulnerable driver to install
    * If NULL, tries to load RTCore64.sys
    */
    LPWSTR vulerableDriverPath;

    /*
    * If additionnal debug messages are wanted
    */
    BOOL verbose;

} EDRSB_CONFIG;

/*
* Global init.
*/
EDRSB_STATUS EDRSB_Init(_Out_ EDRSB_CONTEXT* ctx, _In_ EDRSB_CONFIG* config);
VOID EDRSB_CleanUp(_Inout_ EDRSB_CONTEXT* ctx);

/*
* Usermode APIs.
*/
EDRSB_STATUS Usermode_GetSafeNtFunc(_Inout_ EDRSB_CONTEXT* ctx, _In_ LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function, EDRSB_USERMODE_TECHNIQUE technique);

VOID Usermode_EnumAllMonitoring(_Inout_ EDRSB_CONTEXT* ctx);

VOID Usermode_RemoveAllMonitoring(_Inout_ EDRSB_CONTEXT* ctx, EDRSB_USERMODE_TECHNIQUE technique);

/*
* Krnlmode APIs.
*/
EDRSB_STATUS Krnlmode_EnumAllMonitoring(_In_opt_ EDRSB_CONTEXT* ctx);

EDRSB_STATUS Krnlmode_RemoveAllMonitoring(_In_ EDRSB_CONTEXT* ctx);

EDRSB_STATUS Krnlmode_RestoreAllMonitoring(_In_ EDRSB_CONTEXT* ctx);

/*
* Actions APIs.
*/
// Set the protection level of the current process to Light WinTcb(PsProtectedSignerWinTcb - Light). Allows access to other protected processes, such as lsass when RunAsPPL is enabled
EDRSB_STATUS Action_SetCurrentProcessAsProtected(_In_ EDRSB_CONTEXT* ctx);

EDRSB_STATUS Action_DumpProcessByName(_In_ EDRSB_CONTEXT* ctx, _In_ LPWSTR processName, _In_ LPWSTR outputPath, EDRSB_USERMODE_TECHNIQUE usermodeTechnique);

EDRSB_STATUS Action_FirewallBlockEDR(_In_ EDRSB_CONTEXT* ctx);

EDRSB_STATUS Action_DisableCredGuard(_In_ EDRSB_CONTEXT* ctx);

