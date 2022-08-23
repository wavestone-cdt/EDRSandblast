#include <Windows.h>
#include <shlwapi.h>
#include <dbghelp.h>
#include <stdio.h>

#include "FileUtils.h"
#include "HttpClient.h"
#include "PEParser.h"
#include "PrintFunctions.h"
#include "PdbParser.h"

#include "PdbSymbols.h"


BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

BOOL DownloadOriginalFileW(DWORD image_timestamp, DWORD image_size, LPCWSTR image_name, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%X/%s", image_name, image_timestamp, image_size, image_name);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadOriginalFileFromPE(PE* image_pe, _In_opt_ LPCWSTR image_name, PBYTE* file, SIZE_T* file_size) {
	DWORD image_size = image_pe->optHeader->SizeOfImage;
	//useless check
	if (image_size & 0xFFF) {
		image_size &= ~0xFFF;
		image_size += 0x1000;
	}
	DWORD image_timestamp = image_pe->ntHeader->FileHeader.TimeDateStamp;
	WCHAR image_name_w[MAX_PATH] = { 0 };
	if (image_name == NULL) {
		if (image_pe->exportDirectory != NULL) {
			LPCSTR image_name_a = (LPCSTR)PE_RVA_to_Addr(image_pe, image_pe->exportDirectory->Name);
			MultiByteToWideChar(CP_UTF8, 0, image_name_a, -1, image_name_w, _countof(image_name_w));
			image_name = image_name_w;
		}
		else {
			return FALSE;
		}
	}
	return DownloadOriginalFileW(image_timestamp, image_size, image_name, file, file_size);
}


symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	if (strchr(pe->codeviewDebugInfo->pdbName, '\\')) {
		// path is strange, PDB file won't be found on Microsoft Symbol Server, better give up...
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	BOOL needPdbDownload = FALSE;
	if (!FileExistsW(ctx->pdb_name_w)) {
		needPdbDownload = TRUE;
	}
	else {
		// PDB file exists, but is it the right version ?
		GUID* guid = extractGuidFromPdb(ctx->pdb_name_w);
		if (!guid || memcmp(guid, &pe->codeviewDebugInfo->guid, sizeof(GUID))) {
			needPdbDownload = TRUE;
		}
		free(guid);
	}
	if (needPdbDownload){
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	DWORD64 asked_pdb_base_addr = 0x1337000;
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	if (!SymInitialize(cp, NULL, FALSE)) {
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf_or_not("PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		printf_or_not("SymLoadModuleExW, error 0x%x\n", GetLastError());
		asked_pdb_base_addr += 0x1000000;
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
	if (res) {
		return si.si.Address - ctx->pdb_base_addr;
	}
	else {
		return 0;
	}
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = {0};
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res){
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	return offset;
}

void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
	SymCleanup(ctx->sym_handle);
	if (delete_pdb) {
		DeleteFileW(ctx->pdb_name_w);
	}
	free(ctx->pdb_name_w);
	ctx->pdb_name_w = NULL;
	free(ctx);
}
