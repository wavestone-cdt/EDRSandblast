#include <Windows.h>

/*
* Dumps the full content of a single file into a newly allocated buffer
*/
PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = malloc(fileSize);
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}


/*
* Checks is a file extists (and is not a directory)
*/
BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
BOOL FileExistsA(LPCSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
* Dumps the content of a buffer into a new file
*/
BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}
