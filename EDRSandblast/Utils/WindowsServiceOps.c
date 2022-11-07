#include "../EDRSandblast.h"
#include "WindowsServiceOps.h"

BOOL ServiceAddEveryoneAccess(SC_HANDLE serviceHandle) {
    BOOL status = FALSE;
    DWORD dwSizeNeeded;
    PSECURITY_DESCRIPTOR oldSd, newSd;
    SECURITY_DESCRIPTOR dummySdForXP;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

    EXPLICIT_ACCESS ForEveryoneACL = {
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
        SET_ACCESS,
        NO_INHERITANCE,
        {NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}
    };

    if (!QueryServiceObjectSecurity(serviceHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
        oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded);
        if (oldSd) {
            if (QueryServiceObjectSecurity(serviceHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded)) {
                if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&ForEveryoneACL.Trustee.ptstrName)) {

                    if (BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryoneACL, 0, NULL, oldSd, &dwSizeNeeded, &newSd) == ERROR_SUCCESS) {
                        status = SetServiceObjectSecurity(serviceHandle, DACL_SECURITY_INFORMATION, newSd);
                        LocalFree(newSd);
                    }

                    FreeSid(ForEveryoneACL.Trustee.ptstrName);
                }
            }
            LocalFree(oldSd);
        }
    }
    return status;
}

DWORD ServiceInstall(PCTSTR serviceName, PCTSTR displayName, PCTSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt) {
    SC_HANDLE hSC = NULL;
    SC_HANDLE hS = NULL;
    TCHAR absoluteBinPath[MAX_PATH] = { 0 };
    DWORD absLen = GetFullPathName(binPath, _countof(absoluteBinPath), absoluteBinPath, NULL);
    if (absLen == 0) {
        DWORD lastError = GetLastError();
        _tprintf_or_not(TEXT("[*] Error 0x%lx converting \'%s\' path to absolute ...\n"), lastError, binPath);
        return lastError;
    }

    hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSC) {
        hS = OpenService(hSC, serviceName, SERVICE_START);
        if (hS) {
            _tprintf_or_not(TEXT("[+] \'%s\' service already registered\n"), serviceName);
        }

        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                _tprintf_or_not(TEXT("[*] \'%s\' service was not present\n"), serviceName);

                hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, absoluteBinPath, NULL, NULL, NULL, NULL, NULL);

                if (hS) {
                    _tprintf_or_not(TEXT("[+] \'%s\' service is successfully registered\n"), serviceName);
                    if (ServiceAddEveryoneAccess(hS)) {
                        _tprintf_or_not(TEXT("[+] \'%s\' service ACL configured to for Everyone\n"), serviceName);
                    }
                    else {
                        _putts_or_not(TEXT("[!] ServiceAddEveryoneAccess"));
                    }
                }
                else {
                    PRINT_ERROR_AUTO(TEXT("CreateService"));
                }
            }
            else {
                PRINT_ERROR_AUTO(TEXT("OpenService"));
            }
        }

        if (hS) {
            if (startIt) {
                if (StartService(hS, 0, NULL)) {
                    _tprintf_or_not(TEXT("[+] \'%s\' service started\n"), serviceName);
                }
                else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                    _tprintf_or_not(TEXT("[*] \'%s\' service already started\n"), serviceName);
                }
                else {
                    PRINT_ERROR_AUTO(TEXT("StartService"));
                    return GetLastError();
                }
            }
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }

    else {
        PRINT_ERROR_AUTO(TEXT("OpenSCManager(create)"));
        return GetLastError();
    }
    return 0x0;
}

BOOL ServiceGenericControl(PCTSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus) {
    BOOL status = FALSE;
    SC_HANDLE hSC, hS;
    SERVICE_STATUS serviceStatus;

    hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (hSC) {
        hS = OpenService(hSC, serviceName, dwDesiredAccess);
        if (hS) {
            status = ControlService(hS, dwControl, ptrServiceStatus ? ptrServiceStatus : &serviceStatus);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return status;
}

BOOL ServiceUninstall(PCTSTR serviceName, DWORD attemptCount) {

    // Used as a stop point for recursive calls to ServiceUninstall.
    if (attemptCount > MAX_UNINSTALL_ATTEMPTS) {
        _tprintf_or_not(TEXT("[!] Reached maximun number of attempts (%i) to uninstall the service \'%s\'\n"), MAX_UNINSTALL_ATTEMPTS, serviceName);
        return FALSE;
    }

    if (ServiceGenericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL)) {
        _tprintf_or_not(TEXT("[+] \'%s\' service stopped\n"), serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        _tprintf_or_not(TEXT("[*] \'%s\' service not running\n"), serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
        _tprintf_or_not(TEXT("[*] \'%s\' service cannot accept control messages at this time, waiting...\n"), serviceName);
        Sleep(OP_SLEEP_TIME);
    }
    else {
        PRINT_ERROR_AUTO(TEXT("ServiceUninstall"));
        Sleep(OP_SLEEP_TIME);
        return ServiceUninstall(serviceName, attemptCount + 1);
    }

    SERVICE_STATUS status;
    BOOL deleted = FALSE;
    SC_HANDLE hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (hSC) {
        SC_HANDLE hS = OpenService(hSC, serviceName, SERVICE_QUERY_STATUS | DELETE);
        if (hS) {
            if (QueryServiceStatus(hS, &status)) {
                if (!(status.dwCurrentState == SERVICE_STOPPED)) {
                    CloseServiceHandle(hS);
                    CloseServiceHandle(hSC);
                    Sleep(OP_SLEEP_TIME);
                    return ServiceUninstall(serviceName, attemptCount + 1);
                }
                else {
                    deleted = DeleteService(hS);
                    CloseServiceHandle(hS);
                }
            }
        }
        CloseServiceHandle(hSC);
    }
    if (!deleted) {
        Sleep(OP_SLEEP_TIME);
        return ServiceUninstall(serviceName, attemptCount + 1);
    }
    return deleted;
}