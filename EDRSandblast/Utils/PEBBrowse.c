/*
* Functions that browse the PEB structure instead of relying on GetModuleHandle
*/

#include "Undoc.h"
#include "PEBBrowse.h"
#include "PrintFunctions.h"
#include <stdio.h>

/*
	Get the module entry in the InLoadOrderModuleList given the module name
*/
LDR_DATA_TABLE_ENTRY* getModuleEntryFromNameW(const WCHAR* name) {
	size_t nameSize = wcslen(name);

	for (LDR_DATA_TABLE_ENTRY* currentModuleEntry = getNextModuleEntryInLoadOrder(NULL); currentModuleEntry != NULL; currentModuleEntry = getNextModuleEntryInLoadOrder(currentModuleEntry)) {
		if (!_memicmp(currentModuleEntry->BaseDllName.Buffer, name, sizeof(WCHAR) * nameSize)) {
			return currentModuleEntry;
		}
	}
#ifdef _DEBUG
	printf_or_not("getModuleEntryFromNameW failed to find module\n");
#endif // _DEBUG
	return NULL;
}


/*
	Get the module entry in the InLoadOrderModuleList given an address inside it
	Assumes : the address belong to a module
	Returns : the module it should belong to
*/
LDR_DATA_TABLE_ENTRY* getModuleEntryFromAbsoluteAddr(PVOID addr) {
	LDR_DATA_TABLE_ENTRY* closest = NULL;
	uintptr_t distance = (uintptr_t)-1;

	for (LDR_DATA_TABLE_ENTRY* ptr = getNextModuleEntryInLoadOrder(NULL); ptr != NULL; ptr = getNextModuleEntryInLoadOrder(ptr)) {
		if (ptr->DllBase <= addr && ((uintptr_t)addr - (uintptr_t)ptr->DllBase) < distance) {
			distance = ((uintptr_t)addr - (uintptr_t)ptr->DllBase);
			closest = ptr;
		}
	}
	return closest;
}


/*
	Returns the next module entry in the InLoadOrderModuleList
	Assumes : curr is a ptr to a module entry in the list or NULL
	Returns :
		* if curr is non-NULL:
			* A pointer to the next entry in the list, or
			* A NULL pointer, if end of the list is reached
		* if curr is NULL
			* A pointer to the first element of the list
*/
LDR_DATA_TABLE_ENTRY* getNextModuleEntryInLoadOrder(LDR_DATA_TABLE_ENTRY* curr) {
	LDR_DATA_TABLE_ENTRY* start = (LDR_DATA_TABLE_ENTRY*)getPEB()->Ldr->InLoadOrderModuleList.Flink;
	if (curr == NULL) {
		return start;
	}
	LDR_DATA_TABLE_ENTRY* next = (LDR_DATA_TABLE_ENTRY*)curr->InLoadOrderLinks.Flink;
	if (next == start) {
		return NULL;
	}
	return next;
}

#if _WIN64
PEB64* getPEB() {
	return (PEB64*)__readgsqword(0x60);
}

TEB64* getTEB() {
	return (TEB64*)__readgsqword(0x30);
}
#else
PEB* getPEB() {
	return (PEB*)__readfsdword(0x30);
}

TEB* getTEB() {
	return (TEB*)__readfsdword(0x18);
}
#endif