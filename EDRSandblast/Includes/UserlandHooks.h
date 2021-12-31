#pragma once
#include "PEParser.h"

typedef struct diff_t {
	PVOID disk_ptr;
	PVOID mem_ptr;
	size_t size;
} diff;

typedef struct hook_t {
	PVOID disk_function;
	PVOID mem_function;
	LPCSTR functionName;
	diff* list_patches;
} hook;

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory) (
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS(NTAPI* pRtlGetVersion)(
	OUT LPOSVERSIONINFOEXW lpVersionInformation);

enum unhook_method_e {
	UNHOOK_NONE,

	// Uses the (probably monitored) NtProtectVirtualMemory function in ntdll to remove all detected hooks
	UNHOOK_WITH_NTPROTECTVIRTUALMEMORY,

	// Constructs an "unhooked" (i.e. unmonitored) version of NtProtectVirtualMemory, by allocating an executable trampoling jumping over the hook, and remove all detected hooks
	UNHOOK_WITH_INHOUSE_NTPROTECTVIRTUALMEMORY_TRAMPOLINE,

	// Search for an existing trampoline allocated by the EDR itself, to get an "unhooked" (i.e. unmonitored) version of NtProtectVirtualMemory, and remove all detected hooks
	UNHOOK_WITH_EDR_NTPROTECTVIRTUALMEMORY_TRAMPOLINE,

	// Loads an additionnal version of ntdll library into memory, and use the (hopefully unmonitored) version of NtProtectVirtualMemory present in this library to remove all detected hooks
	UNHOOK_WITH_DUPLICATE_NTPROTECTVIRTUALMEMORY,

	// Allocates a shellcode that uses a direct syscall to call NtProtectVirtualMemory, and uses it to remove all detected hooks
	UNHOOK_WITH_DIRECT_SYSCALL
};

hook* searchHooks(const char* csvFileName);
PVOID hookResolver(PBYTE hookAddr);
pNtProtectVirtualMemory getSafeVirtualProtectUsingTrampoline(DWORD unhook_method);
VOID unhook(hook* hook, DWORD unhook_method);


/*
* Cache for NTDLL PE (accessed often)
*/
PE* ntdllDiskPe_g;
PE* ntdllMemPe_g;
void getNtdllPEs(PE** ntdllPE_mem, PE** ntdllPE_disk);