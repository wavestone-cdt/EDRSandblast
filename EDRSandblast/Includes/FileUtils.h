#pragma once

PBYTE ReadFullFileW(LPCWSTR fileName);

BOOL FileExistsA(LPCSTR szPath);
BOOL FileExistsW(LPCWSTR szPath);
#ifdef UNICODE
#define FileExists  FileExistsW
#else
#define FileExists  FileExistsA
#endif // !UNICODE

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize);