#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <tchar.h>

#include "FileUtils.h"
#include "FileVersion.h"
#include "PrintFunctions.h"
#include "PdbSymbols.h"

#include "FltmgrOffsets.h"

union FltmgrOffsets g_fltmgrOffsets = { 0 };


BOOL FltmgrOffsetsAreLoaded() {
	return g_fltmgrOffsets.ar[0] != 0;
}


BOOL LoadFltmgrOffsets(_In_opt_ TCHAR* fltmgrOffsetFilename, BOOL canUseInternet) {
	if (FltmgrOffsetsAreLoaded()) {
		//offsets already loaded
		return TRUE;
	}

	// load via CSV first
	if (fltmgrOffsetFilename && FileExists(fltmgrOffsetFilename)) {
		if (LoadFltmgrOffsetsFromFile(fltmgrOffsetFilename)) {
			return TRUE;
		}
		_putts_or_not(TEXT("[!] Offsets are missing from the CSV for the version of fltmgr.sys in use."));
	}

	// load via internet then
	if (canUseInternet) {
		_putts_or_not(TEXT("[+] Downloading fltmgr.sys related offsets from the MS Symbol Server (will drop a .pdb file in current directory)"));
#if _DEBUG
		if (LoadFltmgrOffsetsFromInternet(FALSE)) {
#else
		if (LoadFltmgrOffsetsFromInternet(TRUE)) {
#endif
			_putts_or_not(TEXT("[+] Downloading offsets succeeded !"));
			if (fltmgrOffsetFilename && FileExists(fltmgrOffsetFilename)) {
				_putts_or_not(TEXT("[+] Saving them to the CSV file..."));
				SaveFltmgrOffsetsToFile(fltmgrOffsetFilename);
			}
			return TRUE;
		}
		_putts_or_not(TEXT("[-] Downloading offsets from the internet failed !"));
	}

	return FALSE;
}

BOOL LoadFltmgrOffsetsFromFile(TCHAR * fltmgrOffsetFilename) {
	LPTSTR fltmgrVersion = GetFltmgrVersion();
	_tprintf_or_not(TEXT("[*] System's fltmgr.sys file version is: %s\n"), fltmgrVersion);

	FILE* offsetFileStream = NULL;
	_tfopen_s(&offsetFileStream, fltmgrOffsetFilename, TEXT("r"));

	if (offsetFileStream == NULL) {
		_putts_or_not(TEXT("[!] Offset CSV file not found / invalid. A valid offset file must be specifed!"));
		return FALSE;
	}

	TCHAR lineFltmgrVersion[256];
	TCHAR line[2048];
	while (_fgetts(line, _countof(line), offsetFileStream)) {
		TCHAR* dupline = _tcsdup(line);
		TCHAR* tmpBuffer = NULL;
		_tcscpy_s(lineFltmgrVersion, _countof(lineFltmgrVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
		if (_tcscmp(fltmgrVersion, lineFltmgrVersion) == 0) {
			TCHAR* endptr;
			_tprintf_or_not(TEXT("[+] Offsets are available for this version of fltmgr.sys (%s)!\n"), fltmgrVersion);
			for (int i = 0; i < _SUPPORTED_FLTMGR_OFFSETS_END; i++) {
				g_fltmgrOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
			}
			break;
		}
	}
	fclose(offsetFileStream);

	return FltmgrOffsetsAreLoaded();
}

void SaveFltmgrOffsetsToFile(TCHAR * fltmgrOffsetFilename) {
	LPTSTR fltmgrVersion = GetFltmgrVersion();

	FILE* offsetFileStream = NULL;
	_tfopen_s(&offsetFileStream, fltmgrOffsetFilename, TEXT("a"));

	if (offsetFileStream == NULL) {
		_putts_or_not(TEXT("[!] Offset CSV file connot be opened"));
		return;
	}

	_ftprintf(offsetFileStream, TEXT("%s"), fltmgrVersion);
	for (int i = 0; i < _SUPPORTED_FLTMGR_OFFSETS_END; i++) {
		_ftprintf(offsetFileStream, TEXT(",%llx"), g_fltmgrOffsets.ar[i]);
	}
	_fputts(TEXT("\n"), offsetFileStream);

	fclose(offsetFileStream);
}


BOOL LoadFltmgrOffsetsFromInternet(BOOL delete_pdb) {
	LPTSTR fltmgrPath = GetFltmgrPath();
	symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(fltmgrPath);
	if (sym_ctx == NULL) {
		return FALSE;
	}
	g_fltmgrOffsets.st.FltGlobals = GetSymbolOffset(sym_ctx, "FltGlobals");
	g_fltmgrOffsets.st._DRIVER_OBJECT_DriverInit = GetFieldOffset(sym_ctx, "_DRIVER_OBJECT", L"DriverInit");
	g_fltmgrOffsets.st._FLTP_FRAME_Links = GetFieldOffset(sym_ctx, "_FLTP_FRAME", L"Links");
	g_fltmgrOffsets.st._FLTP_FRAME_RegisteredFilters = GetFieldOffset(sym_ctx, "_FLTP_FRAME", L"RegisteredFilters");
	g_fltmgrOffsets.st._FLT_FILTER_DriverObject = GetFieldOffset(sym_ctx, "_FLT_FILTER", L"DriverObject");
	g_fltmgrOffsets.st._FLT_FILTER_InstanceList = GetFieldOffset(sym_ctx, "_FLT_FILTER", L"InstanceList");
	g_fltmgrOffsets.st._FLT_INSTANCE_CallbackNodes = GetFieldOffset(sym_ctx, "_FLT_INSTANCE", L"CallbackNodes");
	g_fltmgrOffsets.st._FLT_INSTANCE_FilterLink = GetFieldOffset(sym_ctx, "_FLT_INSTANCE", L"FilterLink");
	g_fltmgrOffsets.st._FLT_OBJECT_PrimaryLink = GetFieldOffset(sym_ctx, "_FLT_OBJECT", L"PrimaryLink");
	g_fltmgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList = GetFieldOffset(sym_ctx, "_FLT_RESOURCE_LIST_HEAD", L"rList");
	g_fltmgrOffsets.st._GLOBALS_FrameList = GetFieldOffset(sym_ctx, "_GLOBALS", L"FrameList");
	UnloadSymbols(sym_ctx, delete_pdb);

	return FltmgrOffsetsAreLoaded();
}

TCHAR g_fltmgrPath[MAX_PATH] = { 0 };
LPTSTR GetFltmgrPath() {
	if (_tcslen(g_fltmgrPath) == 0) {
		// Retrieves the system folder (eg C:\Windows\System32).
		TCHAR systemDirectory[MAX_PATH] = { 0 };
		GetSystemDirectory(systemDirectory, _countof(systemDirectory));

		// Compute fltmgr.sys path.
		PathAppend(g_fltmgrPath, systemDirectory);
		PathAppend(g_fltmgrPath, TEXT("drivers"));
		PathAppend(g_fltmgrPath, TEXT("fltMgr.sys"));
	}
	return g_fltmgrPath;
}

TCHAR g_fltmgrVersion[256] = { 0 };
LPTSTR GetFltmgrVersion() {
	if (_tcslen(g_fltmgrVersion) == 0) {
		LPTSTR fltmgrPath = GetFltmgrPath();

		TCHAR versionBuffer[256] = { 0 };
		GetFileVersion(versionBuffer, _countof(versionBuffer), fltmgrPath);

		_stprintf_s(g_fltmgrVersion, 256, TEXT("fltmgr_%s.sys"), versionBuffer);
	}
	return g_fltmgrVersion;
}