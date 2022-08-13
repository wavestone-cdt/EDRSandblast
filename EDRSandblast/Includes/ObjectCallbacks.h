#pragma once
#include <Windows.h>

#define DECLARE_OFFSET(STRUCTNAME, OFFSETNAME) DWORD64 Offset_ ## STRUCTNAME ## _ ## OFFSETNAME
#define DECLARE_SYMBOL(SYMBOL) DWORD64 Sym_ ## SYMBOL

// Offset used in experimental functions (EnumAllObjectsCallbacks, EnableDisableProcessAndThreadObjectsCallbacksSupport)
DECLARE_OFFSET(_OBJECT_TYPE, Name);
DECLARE_OFFSET(_OBJECT_TYPE, TotalNumberOfObjects);
DECLARE_OFFSET(_OBJECT_TYPE, TypeInfo);
DECLARE_OFFSET(_OBJECT_TYPE_INITIALIZER, ObjectTypeFlags);
DECLARE_SYMBOL(ObpObjectTypes);
DECLARE_SYMBOL(ObpTypeObjectType);


//callback support strategy
void EnableDisableProcessAndThreadObjectsCallbacksSupport(BOOL enable);
BOOL AreProcessAndThreadsObjectsCallbacksSupportEnabled();

//undoc struct strategy
void EnumAllObjectsCallbacks();
BOOL EnumEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks);
void EnableEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks);
void DisableEDRProcessAndThreadObjectsCallbacks(struct FOUND_EDR_CALLBACKS* FoundObjectCallbacks);
void EnableDisableAllProcessAndThreadObjectsCallbacks(BOOL enable);

//full black box strategy
SIZE_T CountProcessAndThreadObjectsCallbacks();
void RemoveAllProcessAndThreadObjectsCallbacks();
void RestoreAllProcessAndThreadObjectsCallbacks();