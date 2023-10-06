/*

--- ntoskrnl.exe / wdigest.dll version compute functions.

*/
#include <Tchar.h>
#include <stdio.h>

#include "PrintFunctions.h"

#include "FileVersion.h"

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory to retrieve version data"));
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
                        // _tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}
