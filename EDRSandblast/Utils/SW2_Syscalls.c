#include "PEBBrowse.h"
#include "PEParser.h"
#include "SW2_Syscalls.h"

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList;

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

int CmpSyscallEntriesByRVA(SW2_SYSCALL_ENTRY const* a, SW2_SYSCALL_ENTRY const* b) {
    if (a->RVA < b->RVA) {
        return -1;
    }
    else if (a->RVA > b->RVA) {
        return +1;
    }
    else {
        return 0;
    }
}

int CmpSyscallEntriesByHash(SW2_SYSCALL_ENTRY const* a, SW2_SYSCALL_ENTRY const* b) {
    if (a->Hash < b->Hash) {
        return -1;
    }
    else if (a->Hash > b->Hash) {
        return +1;
    }
    else {
        return 0;
    }
}

BOOL SW2_PopulateSyscallList(void)
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PE* ntdll = PE_create(getModuleEntryFromNameW(L"ntdll.dll")->DllBase, TRUE);
    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    for (DWORD nameOrdinal = 0; nameOrdinal < ntdll->exportedNamesLength; nameOrdinal++) {
        LPCSTR functionName = PE_RVA_to_Addr(ntdll, ntdll->exportedNames[nameOrdinal]);
        if ((functionName[0] == 'Z') && (functionName[1] == 'w')) {
            Entries[i].Hash = SW2_HashSyscall(functionName);
            Entries[i].RVA = PE_functionRVA(ntdll, functionName);
            i++;
        }
    }

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    qsort(Entries, SW2_SyscallList.Count, sizeof(SW2_SYSCALL_ENTRY), CmpSyscallEntriesByRVA);

    // Deduce the syscall numbers.
    for (DWORD j = 0; j < SW2_SyscallList.Count; j++) {
        SW2_SyscallList.Entries[j].SyscallNumber = j;
    }

    // Sort the list by hash for quicker search.
    qsort(Entries, SW2_SyscallList.Count, sizeof(SW2_SYSCALL_ENTRY), CmpSyscallEntriesByHash);

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return 0xFFFFFFFF;

    DWORD down = 0;
    DWORD up = SW2_SyscallList.Count;
    while (up - down > 1) {
        DWORD mid = (down + up) / 2;
        if (SW2_SyscallList.Entries[mid].Hash <= FunctionHash) {
            down = mid;
        }
        else {
            up = mid;
        }
    }
    if (SW2_SyscallList.Entries[down].Hash == FunctionHash) {
        return SW2_SyscallList.Entries[down].SyscallNumber;
    }
    else {
        return 0xFFFFFFFF;
    }

}
