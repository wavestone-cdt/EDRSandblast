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

struct KRNL_CALLBACK {
    TCHAR const* driver;
    DWORD64 callback_addr;
    DWORD64 callback_struct;
    DWORD64 callback_func;
    BOOL removed;
};

struct FOUND_EDR_CALLBACKS {
    DWORD64 index;
    struct KRNL_CALLBACK EDR_CALLBACKS[256];
};

TCHAR const* EDR_DRIVERS[];

BOOL isDriverEDR(TCHAR* driver);

void RestoreEDRCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers);

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

void EnumAllEDRKernelCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);

void RemoveAllEDRKernelCallbacks(struct FOUND_EDR_CALLBACKS* edrDrivers, BOOL verbose);