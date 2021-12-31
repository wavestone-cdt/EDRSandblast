/*

--- ntoskrnl.exe / wdigest.dll version compute functions.

*/
#include <Tchar.h>
#include <stdio.h>

#include "FileVersion.h"

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            _tprintf(TEXT("[!] Couldn't allocate memory to retrieve version data\n"));
            return;
        }

        if (GetFileVersionInfo(filename, 0, verSize, verData)) {
            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                        _stprintf_s(buffer, bufferLen, TEXT("%ld-%ld"), majorVersion, minorVersion);
                        // _tprintf(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}

void GetNtoskrnlVersion(TCHAR* ntoskrnlVersion) {
    // Retrieves the system folder (eg C:\Windows\System32).
    TCHAR systemDirectory[MAX_PATH] = { 0 };
    GetSystemDirectory(systemDirectory, _countof(systemDirectory));

    // Compute ntoskrnl.exe path.
    TCHAR ntoskrnlPath[MAX_PATH] = { 0 };
    _tcscat_s(ntoskrnlPath, _countof(ntoskrnlPath), systemDirectory);
    _tcscat_s(ntoskrnlPath, _countof(ntoskrnlPath), TEXT("\\ntoskrnl.exe"));

    TCHAR versionBuffer[256] = { 0 };
    GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);
    _stprintf_s(ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
}

void GetWdigestVersion(TCHAR* wdigestVersion) {
    // Retrieves the system folder (eg C:\Windows\System32).
    TCHAR systemDirectory[MAX_PATH] = { 0 };
    GetSystemDirectory(systemDirectory, _countof(systemDirectory));

    // Compute ntoskrnl.exe path.
    TCHAR wdigestPath[MAX_PATH] = { 0 };
    _tcscat_s(wdigestPath, _countof(wdigestPath), systemDirectory);
    _tcscat_s(wdigestPath, _countof(wdigestPath), TEXT("\\wdigest.dll"));

    TCHAR versionBuffer[256] = { 0 };
    GetFileVersion(versionBuffer, _countof(versionBuffer), wdigestPath);

    _stprintf_s(wdigestVersion, 256, TEXT("wdigest_%s.dll"), versionBuffer);
}