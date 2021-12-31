#pragma once

#include <Windows.h>

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename);

void GetNtoskrnlVersion(TCHAR* ntoskrnlVersion);

void GetWdigestVersion(TCHAR* wdigestVersion);