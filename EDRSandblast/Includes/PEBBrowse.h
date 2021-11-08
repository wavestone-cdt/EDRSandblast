#pragma once
#include "Undoc.h"

LDR_DATA_TABLE_ENTRY* getModuleEntryFromAbsoluteAddr(PVOID addr);
LDR_DATA_TABLE_ENTRY* getModuleEntryFromNameW(const WCHAR* name);
LDR_DATA_TABLE_ENTRY* getNextModuleEntryInLoadOrder(LDR_DATA_TABLE_ENTRY* curr);

#if _WIN64
PEB64* getPEB();
TEB64* getTEB();
#else
PEB* getPEB(void);
TEB* getTEB(void);
#endif