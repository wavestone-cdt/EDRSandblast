/*

--- Kernel callbacks operations.
--- Inspiration and credit: https://github.com/br-sn/CheekyBlinder

*/

#pragma once

#include <Windows.h>


/*
* PspCreateProcessNotifyRoutine / PspCreateThreadNotifyRoutine max: 64 callbacks
* PspLoadImageNotifyRoutine max: 8 callbacks
* Source: https://blog.gentilkiwi.com/retro-ingenierie/windbg-notifications-kernel
*/
#define PSP_MAX_CALLBACKS 0x40

//TODO : split notify routines & object callbacks in different files, but keep this base to implement more kernel callbacks types (CMRegisterCallbacks, etc)
enum kernel_callback_type_e {
	NOTIFY_ROUTINE_CB,
	OBJECT_CALLBACK,
	MINIFILTER_CALLBACK,
};
struct KRNL_CALLBACK {
	enum kernel_callback_type_e type;
	TCHAR const* driver_name;
	union callback_addr_e {
		struct notify_routine_t {
			DWORD64 callback_struct_addr;
			DWORD64 callback_struct;
			enum NtoskrnlOffsetType type; //TODO : decorrelate indices in CSV from notify routine types
		} notify_routine;
		struct object_callback_t {
			DWORD64 enable_addr;
		} object_callback;
		struct minifilter_callback_t {
			DWORD64 callback_node;
		} minifilter_callback;
	} addresses;
	DWORD64 callback_func; //TODO: reorganize this struct since object callbacks and minifilter callbacks have preoperations and postoperations
	BOOL removed;
};

struct FOUND_EDR_CALLBACKS {
	SIZE_T size;
	SIZE_T max_size;
	struct KRNL_CALLBACK* EDR_CALLBACKS;
};

VOID AddFoundKernelCallback(struct FOUND_EDR_CALLBACKS* foundCallbacks, struct KRNL_CALLBACK* newCallback);

BOOL isDriverEDR(TCHAR* driver);
void RestoreEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers);

/*

------ Process (PspCreateProcessNotifyRoutine) callbacks.

*/

DWORD64 GetPspCreateProcessNotifyRoutineAddress(void);

void EnumPspCreateProcessNotifyRoutine(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

void RemoveEDRProcessNotifyCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

/*

------ Thread (PspCreateThreadNotifyRoutine) callbacks.

*/

DWORD64 GetPspCreateThreadNotifyRoutineAddress(void);

void EnumPspCreateThreadNotifyRoutine(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

void RemoveEDRThreadNotifyCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

/*

------ Image loading (PspLoadImageNotifyRoutine) callbacks.

*/

DWORD64 GetPspLoadImageNotifyRoutineAddress(void);

void EnumPspLoadImageNotifyRoutine(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

void RemoveEDRImageNotifyCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

/*

------ All EDR Kernel callbacks enumeration / removal.

*/

BOOL EnumEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

void RemoveEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers);

// Helps at locating some DLL in the kernel, for example CI.dll
DWORD64 GetNotifyRoutineAddress(enum NtoskrnlOffsetType nrt);
