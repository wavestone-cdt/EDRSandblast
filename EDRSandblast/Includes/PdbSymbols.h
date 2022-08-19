#pragma once

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path);
DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name);
DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name);
void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb);