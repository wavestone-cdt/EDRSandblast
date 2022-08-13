#include "RemotePEBBrowser.h"
#include "SW2_Syscalls.h"

PVOID GetRVA(ULONG_PTR baseAddress, ULONG_PTR RVA) {
    return (PVOID)(baseAddress + RVA);
}

// Return a pointer to the target process (PEB) Ldr's InMemoryOrderModuleList.
PLDR_DATA_TABLE_ENTRY getPebLdrAddress(HANDLE hProcess) {
    // Get target process PEB address.
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    basicInfo.PebBaseAddress = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessInformationClass, &basicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't get target process PEB address\n"));
        return NULL;
    }
    
#if _WIN64
    PVOID pPebLdrAddress = (PVOID)((ULONG_PTR) basicInfo.PebBaseAddress + offsetof(PEB64, Ldr));
#else
    PVOID pPebLdrAddress = (PVOID)((ULONG_PTR) basicInfo.PebBaseAddress + offsetof(PEB, Ldr));
#endif

    PPEB_LDR_DATA pprocessLdr = NULL;
    status = NtReadVirtualMemory(hProcess, pPebLdrAddress, &pprocessLdr, sizeof(PPEB_LDR_DATA), NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't get target process Ldr address (NtReadVirtualMemory error 0x%x).\n"), status);
        return NULL;
    }

    // As PLDR_DATA_TABLE_ENTRY starts with InLoadOrderLinks while PEB_LDR_DATA's InLoadOrderModuleList is at offset 0x0C.
    return (PLDR_DATA_TABLE_ENTRY)(((PBYTE)pprocessLdr) + offsetof(PEB_LDR_DATA, InLoadOrderModuleList));
}

PMODULE_INFO createModuleInfo(HANDLE hProcess, PLDR_DATA_TABLE_ENTRY ldrEntry) {
    PMODULE_INFO newModuleInfo = calloc(1, sizeof(MODULE_INFO));

    if (!newModuleInfo) {
        _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't allocate new module info\n"));
        return NULL;
    }

    newModuleInfo->next = NULL;
    newModuleInfo->dllBase = (ULONG64)(ULONG_PTR) ldrEntry->DllBase;
    newModuleInfo->ImageSize = ldrEntry->SizeOfImage;
    newModuleInfo->timeDateStamp = ldrEntry->TimeDateStampOrLoadedImports.TimeDateStamp;
    newModuleInfo->checkSum = ldrEntry->HashLinksOrSectionPointerAndCheckSum.SectionPointerAndCheckSum.CheckSum;

    // read the full path of the DLL
    NTSTATUS status = NtReadVirtualMemory(hProcess, (PVOID) ldrEntry->FullDllName.Buffer, newModuleInfo->dllName, ldrEntry->FullDllName.Length, NULL);
    if (!NT_SUCCESS(status)) {
        _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't retrieve dllName from Ldr entry (NtReadVirtualMemory error 0x%x).\n"), status);
        return NULL; 
    }

    return newModuleInfo;
}

PMODULE_INFO getModulesInLdrByInMemoryOrder(HANDLE hProcess) {
    PMODULE_INFO pmoduleList = NULL;
    NTSTATUS status = FALSE;

    // Retrieve the remote process Ldr address as pseudo PLDR_DATA_TABLE_ENTRY.
    PLDR_DATA_TABLE_ENTRY pLdrAddressInPeb = getPebLdrAddress(hProcess);
    if (!pLdrAddressInPeb) {
        return NULL;
    }

    // Iterate over the linked list by InMemoryOrderModuleList order.
    LDR_DATA_TABLE_ENTRY LdrCurrentEntry;
    PLDR_DATA_TABLE_ENTRY pLdrCurrentEntryAddress = pLdrAddressInPeb;

    while (TRUE) {
        // Add InMemoryOrderLinks offset to iterate on InMemoryOrderLinks order (by retrieving the ptr at InMemoryOrderLinks).
        status = NtReadVirtualMemory(hProcess, ((PBYTE) pLdrCurrentEntryAddress) + offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &pLdrCurrentEntryAddress, sizeof(PLDR_DATA_TABLE_ENTRY), NULL);
        if (!NT_SUCCESS(status)) {
            _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't get Ldr InLoadOrderModuleList first element address (NtReadVirtualMemory error 0x%x).\n"), status);
            return NULL;
        }
    
        // Substract InMemoryOrderLinks offset to be at the top of the LDR_DATA_TABLE_ENTRY struct.
        pLdrCurrentEntryAddress = (PLDR_DATA_TABLE_ENTRY)(((PBYTE)pLdrCurrentEntryAddress) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        // Looped back to the first entry.
        if (pLdrAddressInPeb == pLdrCurrentEntryAddress) {
            break;
        }
        
        // Read LDR_DATA_TABLE_ENTRY data for the current element.
        status = NtReadVirtualMemory(hProcess, pLdrCurrentEntryAddress, &LdrCurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
        if (!NT_SUCCESS(status)) {
            _tprintf_or_not(TEXT("[-] Module parsing failed: couldn't get Ldr InLoadOrderModuleList next element (NtReadVirtualMemory error 0x%x).\n"), status);
            return NULL;
        }

        // Create module info for list using the current LDR_DATA_TABLE_ENTRY entry.
        PMODULE_INFO pnewModuleInfo = createModuleInfo(hProcess, &LdrCurrentEntry);
        if (!pnewModuleInfo) {
            return NULL;
        }

        // Insert the new module info element to the module list.
        if (!pmoduleList) {
            pmoduleList = pnewModuleInfo;
        }
        else {
            PMODULE_INFO plastModule = pmoduleList;
            while (plastModule->next) {
                plastModule = plastModule->next;
            }
            plastModule->next = pnewModuleInfo;
        }
    }

    return pmoduleList;
}

PMEMORY_PAGE_INFO getMemoryPagesInfo(HANDLE hProcess, BOOL filterPage) {
    PMEMORY_PAGE_INFO prangesList = NULL;
    PMEMORY_PAGE_INFO newRange = NULL;
    PVOID baseAddress = NULL;
    PVOID currentAddress = NULL;
    ULONG64 regionSize = 0;
    MEMORY_INFORMATION_CLASS memoryInfoClass = { 0 };
    MEMORY_BASIC_INFORMATION memoryBasicInfo = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    while (TRUE) {
        status = NtQueryVirtualMemory(hProcess, (PVOID)currentAddress, memoryInfoClass, &memoryBasicInfo, sizeof(memoryBasicInfo), NULL);
        
        // The specified base address is outside the range of accessible addresses, iteration is finished.
        if (status == STATUS_INVALID_PARAMETER) {
            break;
        }
        else if (!NT_SUCCESS(status)) {
            _tprintf_or_not(TEXT("[-] Memory pages info retrieval failed: couldn't query memory page (NtQueryVirtualMemory error 0x%x).\n"), status);
            return NULL;
        }

        baseAddress = memoryBasicInfo.BaseAddress;
        regionSize = memoryBasicInfo.RegionSize;

        // Overflow.
        if (((ULONG_PTR) baseAddress + regionSize) < (ULONG_PTR) baseAddress) {
            break;
        }

        // Next memory range.
        currentAddress = (PVOID) GetRVA((ULONG_PTR) baseAddress, (ULONG_PTR) regionSize);

        if (filterPage) {
            // Ignore non-commited pages.
            if (memoryBasicInfo.State != MEM_COMMIT) {
                continue;
            }

            // Ignore mapped pages.
            if (memoryBasicInfo.Type == MEM_MAPPED) {
                continue;
            }

            // Ignore pages with PAGE_NOACCESS. {
            if ((memoryBasicInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS) {
                continue;
            }

            // Ignore pages with PAGE_GUARD.
            if ((memoryBasicInfo.Protect & PAGE_GUARD) == PAGE_GUARD) {
                continue;
            }

            // Ignore pages with PAGE_EXECUTE. {
            if ((memoryBasicInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE) {
                continue;
            }
        }

        newRange = calloc(1, sizeof(MEMORY_PAGE_INFO));
        if (!newRange) {
            _tprintf_or_not(TEXT("[-] Memory pages info retrieval failed: couldn't allocate memory for new MEMORY_RANGE_INFO"));
            return NULL;
        }

        newRange->next = NULL;
        newRange->startOfMemoryPage = (ULONG_PTR)baseAddress;
        newRange->dataSize = regionSize;
        newRange->state = memoryBasicInfo.State;
        newRange->protect = memoryBasicInfo.Protect;
        newRange->type = memoryBasicInfo.Type;

        if (!prangesList) {
            prangesList = newRange;
        }
        else {
            PMEMORY_PAGE_INFO lastRange = prangesList;
            while (lastRange->next) {
                lastRange = lastRange->next;
            }
            lastRange->next = newRange;
        }
    }

    if (!prangesList) {
        _tprintf_or_not(TEXT("[-] Memory pages info retrieval failed: couldn't retrieve any page"));
        return NULL;
    }

    return prangesList;
}
