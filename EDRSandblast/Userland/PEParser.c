/*
* Full library whose job is to parse PE structures, on disk, on memory and even in another process memory
* Among other things, reimplements GetProcAddress and the PE relocation process
*/

#include "PEParser.h"
#include <stdio.h>
#include <assert.h>

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
		printf("ERROR : Cannot rebase PE that is memory mapped (LoadLibrary'd)\n");
		return;
	}
	if (NULL == pe->relocations) {
		PE_parseRelocations(pe);
	}
	assert(pe->relocations != NULL);
	PVOID oldBaseAddress = pe->baseAddress;
	pe->baseAddress = newBaseAddress;
	for (DWORD i = 0; i < pe->nbRelocations; i++) {
		switch (pe->relocations[i].Type) {
		case IMAGE_REL_BASED_ABSOLUTE:
			break;
		case IMAGE_REL_BASED_HIGHLOW:
			relocDwAddress = (DWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
			intptr_t relativeOffset = ((intptr_t)newBaseAddress) - ((intptr_t)oldBaseAddress);
			assert(relativeOffset <= MAXDWORD);
			*relocDwAddress += (DWORD)relativeOffset;
			break;
		case IMAGE_REL_BASED_DIR64:
			relocQwAddress = (QWORD*)PE_RVA_to_Addr(pe, pe->relocations[i].RVA);
			*relocQwAddress += ((intptr_t)newBaseAddress) - ((intptr_t)oldBaseAddress);
			break;
		default:
			printf("Unsupported relocation : 0x%x\nExiting...\n", pe->relocations[i].Type);
			exit(1);
		}
	}
	return;
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = imageBase;
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	return pe;
}

PE* PE_create_from_another_address_space(HANDLE hProcess, PVOID imageBase) {
	PE* pe = calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = TRUE;
	pe->hProcess = hProcess;
	pe->isInAnotherAddressSpace = TRUE;
	pe->baseAddress = imageBase;
	pe->dosHeader = imageBase;
	DWORD ntHeaderPtrAddress = 0;
	ReadProcessMemory(hProcess, (LPCVOID)((intptr_t)imageBase + offsetof(IMAGE_DOS_HEADER, e_lfanew)), &ntHeaderPtrAddress, sizeof(ntHeaderPtrAddress), NULL);
	pe->ntHeader = (IMAGE_NT_HEADERS*)((intptr_t)pe->baseAddress + ntHeaderPtrAddress);
	pe->optHeader = (IMAGE_OPTIONAL_HEADER*)(&pe->ntHeader->OptionalHeader);
	pe->dataDir = pe->optHeader->DataDirectory;
	WORD sizeOfOptionnalHeader = 0;
	ReadProcessMemory(hProcess, &pe->ntHeader->FileHeader.SizeOfOptionalHeader, &sizeOfOptionnalHeader, sizeof(sizeOfOptionnalHeader), NULL);
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)((intptr_t)pe->optHeader + sizeOfOptionnalHeader);
	DWORD exportRVA = 0;
	ReadProcessMemory(hProcess, &pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &exportRVA, sizeof(exportRVA), NULL);
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = PE_RVA_to_Addr(pe, exportRVA);

		DWORD AddressOfNames = 0;
		ReadProcessMemory(pe->hProcess, &pe->exportDirectory->AddressOfNames, &AddressOfNames, sizeof(AddressOfNames), NULL);
		pe->exportedNames = PE_RVA_to_Addr(pe, AddressOfNames);

		DWORD AddressOfFunctions = 0;
		ReadProcessMemory(pe->hProcess, &pe->exportDirectory->AddressOfFunctions, &AddressOfFunctions, sizeof(AddressOfFunctions), NULL);
		pe->exportedFunctions = PE_RVA_to_Addr(pe, AddressOfFunctions);

		DWORD AddressOfNameOrdinals = 0;
		ReadProcessMemory(pe->hProcess, &pe->exportDirectory->AddressOfNameOrdinals, &AddressOfNameOrdinals, sizeof(AddressOfNameOrdinals), NULL);
		pe->exportedOrdinals = PE_RVA_to_Addr(pe, AddressOfNameOrdinals);

		ReadProcessMemory(pe->hProcess, &pe->exportDirectory->NumberOfNames, &pe->exportedNamesLength, sizeof(pe->exportedNamesLength), NULL);
	}
	pe->relocations = NULL;
	return pe;
}


DWORD PE_functionRVA(PE* pe, LPCSTR functionName) {
	IMAGE_EXPORT_DIRECTORY* exportDirectory = pe->exportDirectory;
	LPDWORD exportedNames = pe->exportedNames;
	LPDWORD exportedFunctions = pe->exportedFunctions;
	LPWORD exportedNameOrdinals = pe->exportedOrdinals;

	DWORD nameOrdinal_low = 0;
	LPCSTR exportName_low = PE_RVA_to_Addr(pe, exportedNames[nameOrdinal_low]);
	DWORD nameOrdinal_high = exportDirectory->NumberOfNames;
	DWORD nameOrdinal_mid;
	LPCSTR exportName_mid;

	while (nameOrdinal_high - nameOrdinal_low > 1) {
		nameOrdinal_mid = (nameOrdinal_high + nameOrdinal_low) / 2;
		exportName_mid = PE_RVA_to_Addr(pe, exportedNames[nameOrdinal_mid]);
		if (strcmp(exportName_mid, functionName) > 0) {
			nameOrdinal_high = nameOrdinal_mid;
		}
		else {
			nameOrdinal_low = nameOrdinal_mid;
			exportName_low = exportName_mid;
		}
	}
	if (!strcmp(exportName_low, functionName))
		return exportedFunctions[exportedNameOrdinals[nameOrdinal_low]];
	return 0;
}

PVOID PE_functionAddr(PE* pe, LPCSTR functionName) {
	DWORD functionRVA = PE_functionRVA(pe, functionName);
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

PVOID PE_search_relative_reference(PE* pe, PVOID target, DWORD relativeReferenceSize) {
	signed long long int maximum;
	signed long long int minimum;

	switch (relativeReferenceSize)
	{
	case 1:
		minimum = MININT8;
		maximum = MAXINT8;
		break;
	case 2:
		minimum = MININT16;
		maximum = MAXINT16;
		break;
	case 4:
		minimum = MININT32;
		maximum = MAXINT32;
		break;
	default:
		minimum = 0;
		maximum = 0;
		break;
	}
	for (int i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
		DWORD sectionVA = pe->sectionHeaders[i].VirtualAddress;
		DWORD sectionSize = pe->sectionHeaders[i].Misc.VirtualSize;
		DWORD targetRVA = PE_Addr_to_RVA(pe, target);
		//TODO : implement optimization rva in range(targetRVA - maximum - relativeReferenceSize,targetRVA + minimum - relativeReferenceSize) inter range(sectionVA, sectionVA+sectionSize)
		for (DWORD rva = sectionVA; rva <= sectionVA + sectionSize - relativeReferenceSize; rva++) {
			switch (relativeReferenceSize) {
			case 1:
				if (rva + relativeReferenceSize + *(INT8*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
					return PE_RVA_to_Addr(pe, rva);
				}
				break;
			case 2:
				if (rva + relativeReferenceSize + *(INT16*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
					return PE_RVA_to_Addr(pe, rva);
				}
				break;
			case 4:
				if (rva + relativeReferenceSize + *(INT32*)PE_RVA_to_Addr(pe, rva) == targetRVA) {
					return PE_RVA_to_Addr(pe, rva);
				}
				break;
			default:
				minimum = 0;
				maximum = 0;
				break;
			}
		}

	}
	return NULL;
}