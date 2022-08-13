#pragma once

#include <Windows.h>

LPTSTR GetNtoskrnlPath();

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename);

LPTSTR GetNtoskrnlVersion();

LPTSTR GetWdigestVersion();