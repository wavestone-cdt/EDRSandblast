/*

--- ntoskrnl Notify Routines' offsets from CSV functions.
--- Hardcoded patterns, with offsets for 350+ ntoskrnl versions provided in the CSV file.

*/
#include <tchar.h>
#include <stdio.h>

#include "FileVersion.h"
#include "PdbSymbols.h"
#include "../EDRSandblast.h"

#include "NtoskrnlOffsets.h"

union NtoskrnlOffsets g_ntoskrnlOffsets = { 0 };

// Return the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
void LoadNtoskrnlOffsetsFromFile(TCHAR* ntoskrnlOffsetFilename) {
    LPTSTR ntoskrnlVersion = GetNtoskrnlVersion();
    _tprintf_or_not(TEXT("[*] System's ntoskrnl.exe file version is: %s\n"), ntoskrnlVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ntoskrnlOffsetFilename, TEXT("r"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Offset CSV file connot be opened"));
        return;
    }

    TCHAR lineNtoskrnlVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineNtoskrnlVersion, _countof(lineNtoskrnlVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (_tcscmp(ntoskrnlVersion, lineNtoskrnlVersion) == 0) {
            TCHAR* endptr;
            _tprintf_or_not(TEXT("[+] Offsets are available for this version of ntoskrnl.exe (%s)!\n"), ntoskrnlVersion);
            for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END; i++) {
                g_ntoskrnlOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }
    fclose(offsetFileStream);
}

void SaveNtoskrnlOffsetsToFile(TCHAR* ntoskrnlOffsetFilename) {
    LPTSTR ntoskrnlVersion = GetNtoskrnlVersion();

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ntoskrnlOffsetFilename, TEXT("a"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Offset CSV file connot be opened"));
        return;
    }

    _ftprintf(offsetFileStream, TEXT("%s"), ntoskrnlVersion);
    for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END; i++) {
        _ftprintf(offsetFileStream, TEXT(",%llx"), g_ntoskrnlOffsets.ar[i]);
    }
    _fputts(TEXT(""), offsetFileStream);

    fclose(offsetFileStream);
}

void PrintNtoskrnlOffsets() {
    _tprintf_or_not(TEXT("[+] Ntoskrnl offsets: "));
    for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END - 1; i++) {
        _tprintf_or_not(TEXT(" %llx |"), g_ntoskrnlOffsets.ar[i]);
    }
    _tprintf_or_not(TEXT("%llx\n"), g_ntoskrnlOffsets.ar[_SUPPORTED_NTOSKRNL_OFFSETS_END - 1]);
}
void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetNtoskrnlPath());
    if (sym_ctx == NULL) {
        return;
    }
    g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateProcessNotifyRoutine");
    g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateThreadNotifyRoutine");
    g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine = GetSymbolOffset(sym_ctx, "PspLoadImageNotifyRoutine");
    g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle = GetSymbolOffset(sym_ctx, "EtwThreatIntProvRegHandle");
    g_ntoskrnlOffsets.st.eprocess_protection= GetFieldOffset(sym_ctx, "_EPROCESS", L"Protection");
    g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry= GetFieldOffset(sym_ctx, "_ETW_REG_ENTRY", L"GuidEntry");
    g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo = GetFieldOffset(sym_ctx, "_ETW_GUID_ENTRY", L"ProviderEnableInfo");
    g_ntoskrnlOffsets.st.psProcessType = GetSymbolOffset(sym_ctx, "PsProcessType");
    g_ntoskrnlOffsets.st.psThreadType = GetSymbolOffset(sym_ctx, "PsThreadType");
    g_ntoskrnlOffsets.st.object_type_callbacklist = GetFieldOffset(sym_ctx, "_OBJECT_TYPE", L"CallbackList");
    UnloadSymbols(sym_ctx, delete_pdb);
}

BOOL NtoskrnlOffsetsAreAllPresent() {
    return NtoskrnlNotifyRoutinesOffsetsArePresent() && NtoskrnlEtwtiOffsetsArePresent() && g_ntoskrnlOffsets.st.eprocess_protection != 0 && NtoskrnlObjectCallbackOffsetsArePresent();
}

BOOL NtoskrnlAllKernelCallbacksOffsetsArePresent() {
    return NtoskrnlNotifyRoutinesOffsetsArePresent() && NtoskrnlObjectCallbackOffsetsArePresent();
}

BOOL NtoskrnlNotifyRoutinesOffsetsArePresent() {
    return g_ntoskrnlOffsets.st.pspCreateProcessNotifyRoutine != 0 &&
        g_ntoskrnlOffsets.st.pspCreateThreadNotifyRoutine != 0 &&
        g_ntoskrnlOffsets.st.pspLoadImageNotifyRoutine != 0;
}

BOOL NtoskrnlEtwtiOffsetsArePresent() {
    return g_ntoskrnlOffsets.st.etwGuidEntry_ProviderEnableInfo != 0 &&
        g_ntoskrnlOffsets.st.etwRegEntry_GuidEntry != 0 &&
        g_ntoskrnlOffsets.st.etwThreatIntProvRegHandle != 0;
}

BOOL NtoskrnlObjectCallbackOffsetsArePresent() {
    return g_ntoskrnlOffsets.st.psProcessType != 0 &&
        g_ntoskrnlOffsets.st.psThreadType != 0 &&
        g_ntoskrnlOffsets.st.object_type_callbacklist != 0;
}

TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
LPTSTR GetNtoskrnlPath() {
    if (_tcslen(g_ntoskrnlPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        TCHAR systemDirectory[MAX_PATH] = { 0 };
        GetSystemDirectory(systemDirectory, _countof(systemDirectory));

        // Compute ntoskrnl.exe path.
        _tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), systemDirectory);
        _tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), TEXT("\\ntoskrnl.exe"));
    }
    return g_ntoskrnlPath;
}

TCHAR g_ntoskrnlVersion[256] = { 0 };
LPTSTR GetNtoskrnlVersion() {
    if (_tcslen(g_ntoskrnlVersion) == 0) {

        LPTSTR ntoskrnlPath = GetNtoskrnlPath();
        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);
        _stprintf_s(g_ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
    }
    return g_ntoskrnlVersion;
}