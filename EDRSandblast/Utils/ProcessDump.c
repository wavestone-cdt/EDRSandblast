/*

--- Process dump functions.

*/
#include <Windows.h>
#include <TlHelp32.h>
#include <minidumpapiset.h>
#include <tchar.h>

#include "../EDRSandblast.h"
#include "PEParser.h"
#include "ProcessDump.h"

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    LUID luid;
    BOOL bRet = FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        TOKEN_PRIVILEGES tp = { 0 };

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
            bRet = (GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}

DWORD WINAPI dumpProcess(LPTSTR processName, TCHAR* outputDumpFile) {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32 = { 0 };

    //Enable the SeDebugPrivilege
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        CloseHandle(hToken);
    }

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        _tprintf_or_not(TEXT("[!] %s dump failed: impossible to get snapshot of the system's processes (CreateToolhelp32Snapshot)\n"), processName);
        return 1;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        _tprintf_or_not(TEXT("[!] %s dump failed: obtained invalid process handle\n"), processName); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return 1;
    }

    //HANDLE hDbghelp = LoadLibrary(TEXT("dbgcore.dll"));
    //PE* dbghelpPe = PE_create(hDbghelp, TRUE);
    //_MiniDumpWriteDump MiniDumpWriteDumpFunc = (_MiniDumpWriteDump) PE_functionAddr(dbghelpPe, "MiniDumpWriteDump");

    _MiniDumpWriteDump MiniDumpWriteDumpFunc = (_MiniDumpWriteDump) GetProcAddress(LoadLibrary(TEXT("dbghelp.dll")), "MiniDumpWriteDump");

    // Now walk the snapshot of processes, and look for the specified process.
    do {
        if (_tcscmp(pe32.szExeFile, processName)) {
            continue;
        }

        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[!] %s dump failed: couldn't open process memory (OpenProcesswith error 0x%x)\n"), processName, GetLastError());
            return 1;
        }

        HANDLE hDumpFile = CreateFile(outputDumpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDumpFile == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[!] %s dump failed: couldn't create dump file (CreateFile)\n"), processName);
            return 1;
        }
        BOOL dumped = MiniDumpWriteDumpFunc(hProcess, pe32.th32ProcessID, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (!dumped) {
            _tprintf_or_not(TEXT("[!] %s dump failed: couldn't dump process (MiniDumpWriteDump with error 0x%x)\n"), processName, GetLastError());
            return 1;
        }
        _tprintf_or_not(TEXT("[+] %s sucessfully dumped to: %s\n"), processName, outputDumpFile);
        CloseHandle(hProcess);

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

DWORD WINAPI dumpProcessFromThread(PVOID* args) {
    return dumpProcess(args[0], args[1]);
}