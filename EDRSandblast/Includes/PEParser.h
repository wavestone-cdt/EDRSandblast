#pragma once
#include <Windows.h>

typedef unsigned __int64    QWORD;


typedef struct _IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY;

typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
} PE;

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped);
PE* PE_create_from_another_address_space(HANDLE hProcess, PVOID imageBase);
PVOID PE_RVA_to_Addr(PE* pe, DWORD rva);
DWORD PE_Addr_to_RVA(PE* pe, PVOID addr);
IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva);
IMAGE_SECTION_HEADER* PE_nextSectionHeader_fromPermissions(PE* pe, IMAGE_SECTION_HEADER* prev, INT8 readable, INT8 writable, INT8 executable);
DWORD PE_functionRVA(PE* pe, LPCSTR functionName);
PVOID PE_functionAddr(PE* pe, LPCSTR functionName);
VOID PE_parseRelocations(PE* pe);
VOID PE_rebasePE(PE* pe, LPVOID newBaseAddress);
PVOID PE_search_pattern(PE* pe, PBYTE pattern, size_t patternSize);
PVOID PE_search_relative_reference(PE* pe, PVOID target, DWORD relativeReferenceSize);