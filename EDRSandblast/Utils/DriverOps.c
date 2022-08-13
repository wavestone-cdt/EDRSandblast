/*

--- Driver install / uninstall functions.
--- Source and credit: https://github.com/gentilkiwi/mimikatz

*/
#include <Windows.h>
#include <aclapi.h>
#include <Shlwapi.h>
#include <Tchar.h>
#include <time.h>

#include "DriverOps.h"

#include "../EDRSandblast.h"
#include "StringUtils.h"
#include "WindowsServiceOps.h"
/*

--- Vulnerable driver install / uninstall functions.

*/


TCHAR* g_driverServiceName;

TCHAR* GetDriverServiceName(void) {
    if (!g_driverServiceName || _tcslen(g_driverServiceName) == 0) {
        g_driverServiceName = allocAndGenerateRandomString(SERVICE_NAME_LENGTH);
    }
    return g_driverServiceName;
}

void SetDriverServiceName(_In_z_ TCHAR *newName) {
    if (g_driverServiceName) {
        free(g_driverServiceName);
    }
    g_driverServiceName = _tcsdup(newName);

    if (!g_driverServiceName) {
        _putts_or_not(TEXT("[!] Error while attempting to set the service name."));
        return;
    }
}

BOOL InstallVulnerableDriver(TCHAR* driverPath) {
    TCHAR* svcName = GetDriverServiceName();

    DWORD status = ServiceInstall(svcName, svcName, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    if (status == 0x00000005) {
        _putts_or_not(TEXT("[!] 0x00000005 - Access Denied when attempting to install the driver - Did you run as administrator?"));
    }

    return status == 0x0;
}

BOOL UninstallVulnerableDriver(void) {
    TCHAR* svcName = GetDriverServiceName();

    BOOL status = ServiceUninstall(svcName, 0);
    
    if (!status) {
        PRINT_ERROR_AUTO(TEXT("ServiceUninstall"));
    }

    return status;
}

BOOL IsDriverServiceRunning(LPTSTR driverPath, LPTSTR* serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    BOOL isRunning = FALSE;
    if (hSCM) {
        DWORD cbBufSize, cbBytesNeeded;
        DWORD nbServices;
        BOOL bRes = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &cbBytesNeeded, &nbServices, NULL, NULL);
        if (!bRes && GetLastError() == ERROR_MORE_DATA) {
            ENUM_SERVICE_STATUS_PROCESS* services = calloc(1, cbBytesNeeded);
            if (services){
                cbBufSize = cbBytesNeeded;
                bRes = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, (LPBYTE)services, cbBufSize, &cbBytesNeeded, &nbServices, NULL, NULL);
                if (bRes) {
                    for (DWORD i = 0; i < nbServices; i++) {
                        SC_HANDLE hS = OpenService(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                        if (hS && _tcscmp(services[i].lpServiceName, GetDriverServiceName())) {
                            bRes = QueryServiceConfig(hS, NULL, 0, &cbBytesNeeded);
                            if (!bRes && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                                QUERY_SERVICE_CONFIG* serviceConfig = calloc(1, cbBytesNeeded);
                                if (serviceConfig) {
                                    cbBufSize = cbBytesNeeded;
                                    bRes = QueryServiceConfig(hS, serviceConfig, cbBufSize, &cbBytesNeeded);
                                    if (bRes) {
                                        if (!_tcscmp(PathFindFileName(serviceConfig->lpBinaryPathName), PathFindFileName(driverPath))) {
                                            isRunning = TRUE;
                                            if (serviceName) {
                                                *serviceName = _tcsdup(services[i].lpServiceName);
                                            }
                                        }
                                    }
                                    free(serviceConfig);
                                }
                            }
                            CloseServiceHandle(hS);
                        }
                    }
                }
                free(services);
            }
        }
        CloseServiceHandle(hSCM);
    }
    else {
        PRINT_ERROR_AUTO(TEXT("OpenSCManager(create)"));
        return FALSE;
    }
    return isRunning;
}
