#pragma once
#pragma warning (disable:4214) //Warning Level 4: C4214: nonstandard extension used : bit field types other than int

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

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef VOID(*kernel_read_memory_func) (DWORD64 Address, PVOID Buffer, SIZE_T Size);

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	
	BOOL isInKernelLand;
	kernel_read_memory_func kernel_read;

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
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped);
PE* PE_create_from_another_address_space(HANDLE hProcess, PVOID imageBase);
PE* PE_create_from_kernel(PVOID imageBase, kernel_read_memory_func ReadPrimitive);
PVOID PE_RVA_to_Addr(PE* pe, DWORD rva);
DWORD PE_Addr_to_RVA(PE* pe, PVOID addr);
IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva);
IMAGE_SECTION_HEADER* PE_nextSectionHeader_fromPermissions(PE* pe, IMAGE_SECTION_HEADER* prev, INT8 readable, INT8 writable, INT8 executable);
DWORD PE_functionRVA(PE* pe, LPCSTR functionName);
PVOID PE_functionAddr(PE* pe, LPCSTR functionName);
VOID PE_parseRelocations(PE* pe);
VOID PE_rebasePE(PE* pe, LPVOID newBaseAddress);
PVOID PE_search_pattern(PE* pe, PBYTE pattern, size_t patternSize);
DWORD PE_find_static_relative_reference(PE* pe, DWORD targetRVA, DWORD relativeReferenceSize, DWORD fromRVA);
VOID PE_destroy(PE* pe);