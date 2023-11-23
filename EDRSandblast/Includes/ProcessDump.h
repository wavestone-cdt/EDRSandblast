/*

--- LSASS dump functions.

*/

#pragma once

#include <Windows.h>

//typedef BOOL(WINAPI* _MiniDumpWriteDump)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
typedef BOOL(WINAPI* _MiniDumpWriteDump)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PVOID ExceptionParam, PVOID UserStreamParam, PVOID CallbackParam);


DWORD WINAPI dumpProcess(LPTSTR processName, TCHAR* outputDumpFile);
DWORD WINAPI dumpProcessFromThread(PVOID* args);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
