#pragma once
#include <Windows.h>
#include "KernelCallbacks.h"

BOOL EnumEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* foundEDRCallbacks, BOOL verbose);
#if WriteMemoryPrimitiveIsAtomic
void RemoveEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks);
BOOL RestoreEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks);
#endif