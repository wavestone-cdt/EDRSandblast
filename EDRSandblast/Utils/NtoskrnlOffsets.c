/*

--- ntoskrnl Notify Routines' offsets from CSV functions.
--- Hardcoded patterns, with offsets for 350+ ntoskrnl versions provided in the CSV file.

*/
#include <tchar.h>
#include <stdio.h>

#include "NtoskrnlOffsets.h"
#include "FileVersion.h"

union NtoskrnlOffsets ntoskrnlOffsets = { 0 };

// Return the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
union NtoskrnlOffsets GetNtoskrnlVersionOffsets(TCHAR* ntoskrnlOffsetFilename) {
    TCHAR ntoskrnlVersion[256] = { 0 };
    GetNtoskrnlVersion(ntoskrnlVersion);
    _tprintf(TEXT("[*] System's ntoskrnl.exe file version is: %s\n"), ntoskrnlVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ntoskrnlOffsetFilename, TEXT("r"));

    union NtoskrnlOffsets offset_results = { 0 };
    if (offsetFileStream == NULL) {
        _tprintf(TEXT("[!] Offset CSV file not found / invalid. A valid offset file must be specifed!\n"));
        return offset_results;
    }

    TCHAR lineNtoskrnlVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineNtoskrnlVersion, _countof(lineNtoskrnlVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (_tcscmp(ntoskrnlVersion, lineNtoskrnlVersion) == 0) {
            TCHAR* endptr;
            _tprintf(TEXT("[+] Offsets are available for this version of ntoskrnl.exe (%s)!\n"), ntoskrnlVersion);
            for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END; i++) {
                offset_results.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }
    fclose(offsetFileStream);
    return offset_results;
}