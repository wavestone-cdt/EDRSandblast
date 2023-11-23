#include <Windows.h>
#include <tchar.h>

#include "SW2_Syscalls.h"
#include "PrintFunctions.h"

#include "SyscallProcessUtils.h"

// Retrieve a given process PID.
DWORD SandGetProcessPID(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION basicInformation;
    basicInformation.UniqueProcessId = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessInformationClass, &basicInformation, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Couldn't retrieve process PID as NtQueryInformationProcess syscall failed with error 0x%x.\n"), status);
        return 0;
    }

    return (DWORD)basicInformation.UniqueProcessId;
}

// Retrieve a given process image (PE full path).
PUNICODE_STRING SandGetProcessImage(HANDLE hProcess) {
    NTSTATUS status;
    ULONG ProcessImageLength = 1;
    PUNICODE_STRING ProcessImageBuffer = NULL;

    do {
        ProcessImageBuffer = calloc(ProcessImageLength, sizeof(WCHAR));
        if (!ProcessImageBuffer) {
            _tprintf_or_not(TEXT("[-] Couldn't allocate memory for process image\n"));
            return NULL;
        }

        status = NtQueryInformationProcess(hProcess, ProcessImageFileName, ProcessImageBuffer, ProcessImageLength, &ProcessImageLength);
        if (NT_SUCCESS(status)) {
            break;
        }

        free(ProcessImageBuffer);
        ProcessImageBuffer = NULL;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!ProcessImageBuffer) {
        _tprintf_or_not(TEXT("[-] Failed to retrieve process image: %08x\n"), status);
        return NULL;
    }

    return ProcessImageBuffer;
}

// Extract filename from process image full path.
DWORD SandGetProcessFilename(PUNICODE_STRING ProcessImageUnicodeStr, LPWSTR ImageFileName, DWORD nSize) {
    if (ProcessImageUnicodeStr->Length == 0) {
        return 0;
    }

    // Process name will be /binary.exe.
    WCHAR* ProcessName = wcsrchr(ProcessImageUnicodeStr->Buffer, L'\\');
    if (!ProcessName) {
        return 0;
    }

    // Skip the /.
    ProcessName = &ProcessName[1];

    DWORD ProcessNameLength = (DWORD)wcslen(ProcessName);
    if (ProcessNameLength > nSize) {
        _tprintf_or_not(TEXT("[-] Input buffer size is too small for file name\n"));
        return 0;
    }

    wcsncat_s(ImageFileName, nSize, ProcessName, _TRUNCATE);
    return ProcessNameLength;
}

// Find a process PID using its filename.
DWORD SandFindProcessPidByName(LPCWSTR targetProcessName, DWORD* pPid) {
    DWORD status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;
    HANDLE hOldProcess = NULL;
    PUNICODE_STRING currentProcessImage = NULL;
    LPWSTR currentProcessName = NULL;
    DWORD currentProcessNameSz = 0;

    *pPid = 0;

    while (*pPid == 0) {
        status = NtGetNextProcess(hOldProcess, MAXIMUM_ALLOWED, 0, 0, &hProcess);
        if (hOldProcess) {
            NtClose(hOldProcess);
        }

        if (status == STATUS_NO_MORE_ENTRIES) {
            _tprintf_or_not(TEXT("[-] The process '%s' was not found\n"), targetProcessName);
            return STATUS_NO_MORE_ENTRIES;
        }
        else if (!NT_SUCCESS(status)) {
            _tprintf_or_not(TEXT("[-] Syscall NtGetNextProcess failed with error 0x%x.\n"), status);
            return status;
        }

        currentProcessImage = SandGetProcessImage(hProcess);
        if (currentProcessImage) {
            currentProcessName = calloc(currentProcessImage->MaximumLength, sizeof(WCHAR));
            if (!currentProcessName) {
                _tprintf_or_not(TEXT("[-] Couldn't allocate memory for process filename\n"));
                return STATUS_UNSUCCESSFUL;
            }
            _putws(currentProcessImage->Buffer);
            currentProcessNameSz = SandGetProcessFilename(currentProcessImage, currentProcessName, currentProcessImage->MaximumLength);

            if (currentProcessNameSz != 0 && !_tcsicmp(targetProcessName, currentProcessName)) {
                *pPid = SandGetProcessPID(hProcess);
                break;
            }

            free(currentProcessImage);
            currentProcessImage = NULL;
            free(currentProcessName);
            currentProcessName = NULL;
        }
        hOldProcess = hProcess;
    }
    if (currentProcessImage) {
        free(currentProcessImage);
    }
    if (currentProcessName) {
        free(currentProcessName);
    }
    if (hProcess) {
        NtClose(hProcess);
    }
    if (*pPid) {
        return STATUS_SUCCES;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }
}
