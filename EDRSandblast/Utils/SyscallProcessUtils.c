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

    return (DWORD) basicInformation.UniqueProcessId;
}

// Retrieve a given process image (PE full path).
PUNICODE_STRING SandGetProcessImage(HANDLE hProcess) {
    NTSTATUS status;
    ULONG ProcessImageLength = 1;
    PUNICODE_STRING ProcessImageBuffer = NULL;

    do {
        ProcessImageBuffer = calloc(ProcessImageLength, sizeof(TCHAR));
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
        _tprintf_or_not(TEXT("[-] Failed to retrieve process image\n"));
        return NULL;
    }
    
    return ProcessImageBuffer;
}

// Extract filename from process image full path.
DWORD SandGetProcessFilename(PUNICODE_STRING ProcessImageUnicodeStr, TCHAR* ImageFileName, DWORD nSize) {
    if (ProcessImageUnicodeStr->Length == 0) {
        return 0;
    }

    // Process name will be /binary.exe.
    TCHAR* ProcessName = _tcsrchr(ProcessImageUnicodeStr->Buffer, TEXT('\\'));
    if (!ProcessName) {
        return 0;
    }

    // Skip the /.
    ProcessName = &ProcessName[1];
    
    DWORD ProcessNameLength = (DWORD)_tcslen(ProcessName);
    if (ProcessNameLength > nSize) {
        _tprintf_or_not(TEXT("[-] Input buffer size is too small for file name\n"));
        return 0;
    }
    
    _tcsncat_s(ImageFileName, nSize, ProcessName, _TRUNCATE);
    return ProcessNameLength;
}

// Find a process PID using its filename.
DWORD SandFindProcessPidByName(TCHAR* targetProcessName, DWORD* pPid) {
    DWORD status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;
    PUNICODE_STRING currentProcessImage = NULL;
    TCHAR* currentProcessName = NULL;
    DWORD currentProcessNameSz = 0;
    
    *pPid = 0;

    while (*pPid == 0) {
        status = NtGetNextProcess(hProcess, PROCESS_QUERY_INFORMATION, 0, 0, &hProcess);

        if (status == STATUS_NO_MORE_ENTRIES) {
            _tprintf_or_not(TEXT("[-] The process '%s' was not found\n"), targetProcessName);
            return STATUS_NO_MORE_ENTRIES;
        }
        else if (!NT_SUCCESS(status)) {
            _tprintf_or_not(TEXT("[-] Syscall NtGetNextProcess failed with error 0x%x.\n"), status);
            return status;
        }

        currentProcessImage = SandGetProcessImage(hProcess);
        currentProcessName = calloc(currentProcessImage->MaximumLength, sizeof(TCHAR));
        if (!currentProcessName) {
            _tprintf_or_not(TEXT("[-] Couldn't allocate memory for process filename\n"));
            return STATUS_UNSUCCESSFUL;
        }
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

    if (*pPid) {
        return STATUS_SUCCES;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }
}
