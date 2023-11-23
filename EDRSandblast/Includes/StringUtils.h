#pragma once

#include <Windows.h>
#include <Tchar.h>

#include "Undoc.h"
#include "time.h"

VOID getUnicodeStringFromWCHAR(OUT PUNICODE_STRING unicodeString, IN WCHAR* tcharString);

TCHAR* generateRandomString(TCHAR* str, size_t size);
TCHAR* allocAndGenerateRandomString(size_t length);