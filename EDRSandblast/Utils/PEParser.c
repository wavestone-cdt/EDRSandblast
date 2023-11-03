/*
* Full library whose job is to parse PE structures, on disk, on memory and even in another process memory
* Among other things, reimplements GetProcAddress and the PE relocation process
*/

#include "PEParser.h"
#include <stdio.h>
#include <assert.h>

#include "PrintFunctions.h"


IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
    IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
    for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
        DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
        DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
        if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
            return &sectionHeaders[sectionIndex];
        }
    }
    return NULL;
}

/*
Get the next section header having the given memory access permissions, after the provided section headers "prev".
Exemple : PE_nextSectionHeader_fromPermissions(pe, textSection, 1, -1, 0) returns the first section header in the list after "textSection" that is readable and not writable.
Returns NULL if no section header is found.
*/
IMAGE_SECTION_HEADER* PE_nextSectionHeader_fromPermissions(PE* pe, IMAGE_SECTION_HEADER* prev, INT8 readable, INT8 writable, INT8 executable) {
    IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
    DWORD firstSectionIndex = prev == NULL ? 0 : (DWORD)((prev + 1) - sectionHeaders);
    for (DWORD sectionIndex = firstSectionIndex; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
        DWORD sectionCharacteristics = sectionHeaders[sectionIndex].Characteristics;
        if (readable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_READ) {
                if (readable == -1) {
                    continue;
                }
            }
            else {
                if (readable == 1) {
                    continue;
                }
            }
        }
        if (writable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_WRITE) {
                if (writable == -1) {
                    continue;
                }
            }
            else {
                if (writable == 1) {
                    continue;
                }
            }
        }
        if (executable != 0) {
            if (sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
                if (executable == -1) {
                    continue;
                }
            }
            else {
                if (executable == 1) {
                    continue;
                }
            }
        }
        return &sectionHeaders[sectionIndex];
    }
    return NULL;
}


PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
    PVOID peBase = pe->dosHeader;
    if (pe->isMemoryMapped) {
        return (PBYTE)peBase + rva;
    }

    IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
    if (NULL == rvaSectionHeader) {
        return NULL;
    }
    else {
        return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
    }
}

DWORD PE_Addr_to_RVA(PE* pe, PVOID addr) {
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
        PVOID sectionAddr = PE_RVA_to_Addr(pe, sectionVA);
        if (sectionAddr <= addr && addr < (PVOID)((intptr_t)sectionAddr + (intptr_t)sectionSize)) {
            intptr_t relativeOffset = ((intptr_t)addr - (intptr_t)sectionAddr);
            assert(relativeOffset <= MAXDWORD);
            return sectionVA + (DWORD)relativeOffset;
        }
    }
    return 0;
}


VOID PE_parseRelocations(PE* pe) {
    IMAGE_BASE_RELOCATION* relocationBlocks = PE_RVA_to_Addr(pe, pe->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    IMAGE_BASE_RELOCATION* relocationBlockPtr = relocationBlocks;
    IMAGE_BASE_RELOCATION* nextRelocationBlockPtr;
    pe->nbRelocations = 0;
    DWORD relocationsLength = 16;
    pe->relocations = calloc(relocationsLength, sizeof(PE_relocation));
    if (NULL == pe->relocations)
        exit(1);

    while (((size_t)relocationBlockPtr - (size_t)relocationBlocks) < pe->dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_RELOCATION_ENTRY* relocationEntry = (IMAGE_RELOCATION_ENTRY*)&relocationBlockPtr[1];
        nextRelocationBlockPtr = (IMAGE_BASE_RELOCATION*)(((PBYTE)relocationBlockPtr) + relocationBlockPtr->SizeOfBlock);
        while ((PBYTE)relocationEntry < (PBYTE)nextRelocationBlockPtr) {
            DWORD relocationRVA = relocationBlockPtr->VirtualAddress + relocationEntry->Offset;
            if (pe->nbRelocations >= relocationsLength) {
                relocationsLength *= 2;
                void* pe_relocations = pe->relocations;
                assert(NULL != pe_relocations);
                pe->relocations = realloc(pe_relocations, relocationsLength * sizeof(PE_relocation));
                assert(NULL != pe->relocations);
            }
            pe->relocations[pe->nbRelocations].RVA = relocationRVA;
            pe->relocations[pe->nbRelocations].Type = relocationEntry->Type;
            pe->nbRelocations++;
            relocationEntry++;
        }
        relocationBlockPtr = nextRelocationBlockPtr;
    }
    void* pe_relocations = pe->relocations;
    assert(pe_relocations != NULL);
    pe->relocations = realloc(pe_relocations, pe->nbRelocations * sizeof(PE_relocation));
    if (NULL == pe->relocations)
        exit(1);
}

VOID PE_rebasePE(PE* pe, LPVOID newBaseAddress)
{
    DWORD* relocDwAddress;
    QWORD* relocQwAddress;

    if (pe->isMemoryMapped) {
        printf_or_not("ERROR : Cannot rebase PE that is memory mapped (LoadLibrary'd)\n");
        return;
    }
    if (NULL == pe->relocations) {
        PE_parseRelocations(pe);
    }
    assert(pe->relocations != NULL);
    PVOID oldBaseAddress = pe->baseAddress;
    pe->baseAddress = newBaseAddress;
    intptr_t relativeOffset = ((intptr_t)newBaseAddress) - ((intptr_t)oldBaseAddress);
    for (DWORD i = 0; i < pe->nbRelocations; i++) {
        switch (pe->relocations[i].Type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            relocDwAddress = (DWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
            assert(relativeOffset <= MAXDWORD);
            *relocDwAddress += (DWORD)relativeOffset;
            break;
        case IMAGE_REL_BASED_DIR64:
            relocQwAddress = (QWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
            *relocQwAddress += (QWORD)relativeOffset;
            break;
        default:
            printf_or_not("Unsupported relocation : 0x%x\nExiting...\n", pe->relocations[i].Type);
            exit(1);
        }
    }
    return;
}

VOID PE_read(PE* pe, LPCVOID address, SIZE_T size, PVOID buffer) {
    if (pe->isInAnotherAddressSpace) {
        ReadProcessMemory(pe->hProcess, address, buffer, size, NULL);
    }
    else if (pe->isInKernelLand) {
        pe->kernel_read((DWORD64) address, buffer, size);
    } else {
        memcpy(buffer, address, size);
    }
}

#define PE_ReadMemoryType(TYPE) \
TYPE PE_ ## TYPE ## (PE* pe, LPCVOID address) {\
    TYPE res;\
    PE_read(pe, address, sizeof(TYPE), &res);\
    return res;\
}
PE_ReadMemoryType(BYTE);
PE_ReadMemoryType(WORD);
PE_ReadMemoryType(DWORD);
PE_ReadMemoryType(DWORD64);

#define PE_ArrayType(TYPE) \
TYPE PE_ ## TYPE ## _Array(PE* pe, PVOID address, SIZE_T index) {\
    return PE_ ## TYPE ## (pe, (PVOID)(((intptr_t)address)+index*sizeof(TYPE)));\
}
PE_ArrayType(BYTE);
PE_ArrayType(WORD);
PE_ArrayType(DWORD);
PE_ArrayType(DWORD64);

LPCSTR PE_STR(PE* pe, LPCSTR address) {
    if (pe->isInAnotherAddressSpace || pe->isInKernelLand) {
        SIZE_T slen = 16;
        LPSTR s = calloc(slen, 1);
        if (s == NULL) {
            exit(1);
        }
        SIZE_T i = 0;
        do {
            if (slen <= i) {
                slen *= 2;
                LPSTR tmp = realloc(s, slen);
                if (NULL == tmp) {
                    exit(1);
                }
                s = tmp;
            }
            s[i] = PE_BYTE(pe, address + i);
            i++;
        } while (s[i - 1] != '\0');
        return s;
    }
    else {
        return address;
    }
}

VOID PE_STR_free(PE* pe, LPCSTR s) {
    if (pe->isInAnotherAddressSpace || pe->isInKernelLand) {
        free((PVOID)s);
    }
}


PE* _PE_create_common(PVOID imageBase, BOOL isMemoryMapped, BOOL isInAnotherAddressSpace, HANDLE hProcess, BOOL isInKernelLand, kernel_read_memory_func ReadPrimitive);

PE* PE_create_from_another_address_space(HANDLE hProcess, PVOID imageBase) {
    return _PE_create_common(imageBase, TRUE, TRUE, hProcess, FALSE, NULL);
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
    return _PE_create_common(imageBase, isMemoryMapped, FALSE, INVALID_HANDLE_VALUE, FALSE, NULL);
}

PE* PE_create_from_kernel(PVOID imageBase, kernel_read_memory_func ReadPrimitive) {
    return _PE_create_common(imageBase, TRUE, FALSE, INVALID_HANDLE_VALUE, TRUE, ReadPrimitive);
}


PE* _PE_create_common(PVOID imageBase, BOOL isMemoryMapped, BOOL isInAnotherAddressSpace, HANDLE hProcess, BOOL isInKernelLand, kernel_read_memory_func ReadPrimitive) {
    PE* pe = calloc(1, sizeof(PE));
    if (NULL == pe) {
        exit(1);
    }
    pe->isMemoryMapped = isMemoryMapped;
    pe->hProcess = hProcess;
    pe->isInAnotherAddressSpace = isInAnotherAddressSpace;
    pe->isInKernelLand = isInKernelLand;
    pe->kernel_read = ReadPrimitive;
    pe->baseAddress = imageBase;
    pe->dosHeader = imageBase;
    DWORD ntHeaderPtrAddress = PE_DWORD(pe, &((IMAGE_DOS_HEADER*)imageBase)->e_lfanew);
    pe->ntHeader = (IMAGE_NT_HEADERS*)((intptr_t)pe->baseAddress + ntHeaderPtrAddress);
    pe->optHeader = (IMAGE_OPTIONAL_HEADER*)(&pe->ntHeader->OptionalHeader);
    pe->dataDir = pe->optHeader->DataDirectory;
    WORD sizeOfOptionnalHeader = PE_WORD(pe, &pe->ntHeader->FileHeader.SizeOfOptionalHeader);
    pe->sectionHeaders = (IMAGE_SECTION_HEADER*)((intptr_t)pe->optHeader + sizeOfOptionnalHeader);
    DWORD exportRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (exportRVA == 0) {
        pe->exportDirectory = NULL;
        pe->exportedNames = NULL;
        pe->exportedFunctions = NULL;
        pe->exportedOrdinals = NULL;
    }
    else {
        pe->exportDirectory = PE_RVA_to_Addr(pe, exportRVA);

        DWORD AddressOfNames = PE_DWORD(pe, &pe->exportDirectory->AddressOfNames);
        pe->exportedNames = PE_RVA_to_Addr(pe, AddressOfNames);

        DWORD AddressOfFunctions = PE_DWORD(pe, &pe->exportDirectory->AddressOfFunctions);
        pe->exportedFunctions = PE_RVA_to_Addr(pe, AddressOfFunctions);

        DWORD AddressOfNameOrdinals = PE_DWORD(pe, &pe->exportDirectory->AddressOfNameOrdinals);
        pe->exportedOrdinals = PE_RVA_to_Addr(pe, AddressOfNameOrdinals);

        pe->exportedNamesLength = PE_DWORD(pe, &pe->exportDirectory->NumberOfNames);
    }
    pe->relocations = NULL;
    DWORD debugRVA = PE_DWORD(pe, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    if (debugRVA == 0) {
        pe->debugDirectory = NULL;
    }
    else {
        pe->debugDirectory = PE_RVA_to_Addr(pe, debugRVA);
        DWORD debugDirectoryType = PE_DWORD(pe, &pe->debugDirectory->Type);
        if (debugDirectoryType != IMAGE_DEBUG_TYPE_CODEVIEW) {
            pe->debugDirectory = NULL;
        }
        else {
            DWORD debugDirectoryAddressOfRawData = PE_DWORD(pe, &pe->debugDirectory->AddressOfRawData);
            pe->codeviewDebugInfo = PE_RVA_to_Addr(pe, debugDirectoryAddressOfRawData);
            DWORD codeviewDebugInfoSignature = PE_DWORD(pe, &pe->codeviewDebugInfo->signature);
            if (codeviewDebugInfoSignature != *((DWORD*)"RSDS")) {
                pe->debugDirectory = NULL;
                pe->codeviewDebugInfo = NULL;
            }
        }
    }
    return pe;
}

//TODO : implement the case where the PE is in another address space
DWORD PE_functionRVA(PE* pe, LPCSTR functionName) {
    IMAGE_EXPORT_DIRECTORY* exportDirectory = pe->exportDirectory;
    LPDWORD exportedNames = pe->exportedNames;
    LPDWORD exportedFunctions = pe->exportedFunctions;
    LPWORD exportedNameOrdinals = pe->exportedOrdinals;

    DWORD nameOrdinal_low = 0;
    LPCSTR exportName_low = PE_RVA_to_Addr(pe, PE_DWORD_Array(pe, exportedNames, nameOrdinal_low));
    exportName_low = PE_STR(pe, exportName_low);
    DWORD nameOrdinal_high = PE_DWORD(pe, &exportDirectory->NumberOfNames);
    DWORD nameOrdinal_mid;
    LPCSTR exportName_mid = NULL;

    while (nameOrdinal_high - nameOrdinal_low > 1) {
        nameOrdinal_mid = (nameOrdinal_high + nameOrdinal_low) / 2;
        if (exportName_mid) {
            PE_STR_free(pe, exportName_mid);
        }
        exportName_mid = PE_RVA_to_Addr(pe, PE_DWORD_Array(pe, exportedNames, nameOrdinal_mid));
        exportName_mid = PE_STR(pe, exportName_mid);

        if (strcmp(exportName_mid, functionName) > 0) {
            nameOrdinal_high = nameOrdinal_mid;
        }
        else {
            nameOrdinal_low = nameOrdinal_mid;
            PE_STR_free(pe, exportName_low);
            exportName_low = exportName_mid;
            exportName_mid = NULL;
        }
    }
    if (exportName_mid) {
        PE_STR_free(pe, exportName_mid);
    }
    if (!strcmp(exportName_low, functionName)) {
        PE_STR_free(pe, exportName_low);
        return PE_DWORD_Array(pe, exportedFunctions, PE_WORD_Array(pe, exportedNameOrdinals, nameOrdinal_low));
    }
    return 0;
}

PVOID PE_functionAddr(PE* pe, LPCSTR functionName) {
    DWORD functionRVA = PE_functionRVA(pe, functionName);
    if (functionRVA == 0) {
        return NULL;
    }
    return PE_RVA_to_Addr(pe, functionRVA);
}

PVOID PE_search_pattern(PE* pe, PBYTE pattern, size_t patternSize) {
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
        if ((size_t)sectionSize < patternSize) {
            continue;
        }
        assert(patternSize <= MAXDWORD);
        DWORD endSize = sectionSize - (DWORD)patternSize;
        for (DWORD offset = 0; offset < endSize; offset++) {
            PBYTE ptr = PE_RVA_to_Addr(pe, sectionVA + offset);
            if (!memcmp(ptr, pattern, patternSize)) {
                return ptr;
            }
        }
    }
    return NULL;
}

/*
* Look for an instruction that references address targetRVA relatively from its own address, starting the search at fromRVA.
* Searches a 8, 16 or 32 bits relative displacement that points to targetRVA (on x86_84, 64-bits relative displacements do not exist)
* Returns the RVA of the reference (in the middle of the instruction)
* 
* Example:
*
* PAGE:14084EA2B 45 33 FF                             xor     r15d, r15d
* PAGE:14084EA2E 4C 8D 2D [6B DA 49 00]               lea     r13, PspCreateProcessNotifyRoutine ; array at address 140CEC4A0
* PAGE:14084EA35 4E 8D 24 FD 00 00 00 00              lea     r12, ds:0[r15*8]
*
* At address 14084EA31 (14084EA2E+3), we find the DWORD 0x0049DA6B (see brackets), which is a displacement relative to the
* address of the next instruction (14084EA35). 0x0049DA6B + 0x14084EA35 being equal to 0x140CEC4A0, this is how the array
* PspCreateProcessNotifyRoutine is referenced by the lea instruction.
*/
DWORD PE_find_static_relative_reference(PE* pe, DWORD targetRVA, DWORD relativeReferenceSize, DWORD fromRVA) {
    QWORD startRVA;
    QWORD endRVA;

    switch (relativeReferenceSize)
    {
    case 1:
        startRVA = (QWORD)targetRVA - MAXINT8 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT8 - relativeReferenceSize;
        break;
    case 2:
        startRVA = (QWORD)targetRVA - MAXINT16 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT16 - relativeReferenceSize;
        break;
    case 4:
        startRVA = (QWORD)targetRVA - MAXINT32 - relativeReferenceSize;
        endRVA = (QWORD)targetRVA - MININT32 - relativeReferenceSize;
        break;
    default:
        return 0;
    }
    if (startRVA > targetRVA) {
        startRVA = 0;
    }
    if (startRVA < fromRVA) {
        startRVA = fromRVA;
    }
    if (endRVA > MAXDWORD) {
        endRVA = MAXDWORD;
    }
    for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD startRVA_inSection = pe->sectionHeaders[i].VirtualAddress;
        startRVA_inSection = max(startRVA_inSection, (DWORD)startRVA);
        DWORD endRVA_inSection = startRVA_inSection + pe->sectionHeaders[i].Misc.VirtualSize - relativeReferenceSize;
        endRVA_inSection = min(endRVA_inSection, (DWORD)endRVA);
        for (DWORD rva = startRVA_inSection; rva <= endRVA_inSection; rva++) {
            switch (relativeReferenceSize) {
            case 1:
                if (rva + relativeReferenceSize + *(INT8*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            case 2:
                if (rva + relativeReferenceSize + *(INT16*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            case 4:
                if (rva + relativeReferenceSize + *(INT32*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
                    return rva;
                }
                break;
            }
        }

    }
    return 0;
}

VOID PE_destroy(PE* pe)
{
    if (pe->relocations) {
        free(pe->relocations);
        pe->relocations = NULL;
    }
    free(pe);
}
