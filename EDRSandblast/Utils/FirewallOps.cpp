extern "C" {
#include "../EDRSandblast.h"
#include "FirewallOps.h"
}

HRESULT ComInitNetFwPolicy2(INetFwPolicy2** ppNetFwPolicy2) {
	HRESULT hrStatus = S_OK;

	hrStatus = CoInitializeEx(0, COINIT_APARTMENTTHREADED);

	// Ignore RPC_E_CHANGED_MODE (Microsoft documentation stating that the existing mode does not matter).
	if (hrStatus != RPC_E_CHANGED_MODE && FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Error while initializing COM (CoInitializeEx failed: 0x%08lx)\n"), hrStatus);
		return hrStatus;
	}

	hrStatus = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)ppNetFwPolicy2);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Error while initializing the INetFwPolicy2 interface (CoCreateInstance for INetFwPolicy2 failed: 0x%08lx)\n"), hrStatus);
		return hrStatus;
	}

	return hrStatus;
}

extern "C" HRESULT IsFirewallEnabled(BOOL* firewallIsOn);
HRESULT IsFirewallEnabled(BOOL* firewallIsOn) {
	HRESULT hrComInit = E_FAIL;
	HRESULT hrStatus = S_OK;

	INetFwPolicy2* pNetFwPolicy2 = NULL;
	long CurrentProfilesBitMask = 0;
	VARIANT_BOOL vbFirewallsEnabled = VARIANT_TRUE;
	VARIANT_BOOL vbFirewallProfileEnabled = VARIANT_FALSE;

	struct ProfileMapElement {
		NET_FW_PROFILE_TYPE2 Id;
		LPCWSTR Name;
	};
	
	ProfileMapElement ProfileMap[3];
	ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
	ProfileMap[0].Name = L"Domain";
	ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
	ProfileMap[1].Name = L"Private";
	ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
	ProfileMap[2].Name = L"Public";

	hrComInit = ComInitNetFwPolicy2(&pNetFwPolicy2);
	if (FAILED(hrComInit)) {
		hrStatus = E_FAIL;
		goto cleanup;
	}

	hrStatus = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Could not determine Firewall status (failed to get the active Firewall profiles - get_CurrentProfileTypes failed: 0x%08lx)\n"), hrStatus);
		goto cleanup;
	}

	for (DWORD i = 0; i < 3; i++) {
		if (CurrentProfilesBitMask & ProfileMap[i].Id) {
			hrStatus = pNetFwPolicy2->get_FirewallEnabled(ProfileMap[i].Id, &vbFirewallProfileEnabled);
			if (FAILED(hrStatus)) {
				wprintf_or_not(L"[!] Could not determine Firewall status (failed to retrieve FirewallEnabled settings for %s profile - get_FirewallEnabled failed: 0x%08lx)\n", ProfileMap[i].Name, hrStatus);
				goto cleanup;
			}
			if (vbFirewallProfileEnabled == VARIANT_FALSE) {
				wprintf_or_not(L"[*] The Windows Firewall is off on the (active) '%s' profile.\n", ProfileMap[i].Name);
				vbFirewallsEnabled = VARIANT_FALSE;
			}
		}
	}
	
	*firewallIsOn = (BOOL)(vbFirewallsEnabled == VARIANT_TRUE);

cleanup:
	if (pNetFwPolicy2) {
		pNetFwPolicy2->Release();
		pNetFwPolicy2 = NULL;
	}

	if (SUCCEEDED(hrComInit)) {
		CoUninitialize();
	}

	return hrStatus;
}

extern "C" HRESULT CreateFirewallRuleBlockBinary(TCHAR* binaryPath, NET_FW_RULE_DIRECTION direction, TCHAR* ruleName);
HRESULT CreateFirewallRuleBlockBinary(TCHAR* binaryPath, NET_FW_RULE_DIRECTION direction, TCHAR* ruleName) {
	HRESULT hrComInit = E_FAIL;
	HRESULT hrStatus = S_OK;

	INetFwPolicy2* pNetFwPolicy2 = NULL;
	INetFwRules* pFwRules = NULL;
	INetFwRule* pFwRule = NULL;

	BSTR bstrRuleName = NULL;
	BSTR bstrRuleDescription = NULL;
	BSTR bstrRuleApplication = NULL;

	hrComInit = ComInitNetFwPolicy2(&pNetFwPolicy2);
	if (FAILED(hrComInit)) {
		hrStatus = E_FAIL;
		goto cleanup;
	}
	
	// Rules parameters.
	generateRandomString(ruleName, FW_RULE_NAME_MAX_LENGTH);
	bstrRuleName = SysAllocString(ruleName);
	bstrRuleDescription = SysAllocString(ruleName);
	bstrRuleApplication = SysAllocString(binaryPath);

	// hrStatus = pNetFwPolicy2->get_Rules(&pFwRules);
	hrStatus = pNetFwPolicy2->get_Rules(&pFwRules);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Could not retrieve current Firewall rules (pNetFwPolicy2->get_Rules failed: 0x%08lx).\n"), hrStatus);
		goto cleanup;
	}

	// Create a new Firewall Rule object.
	hrStatus = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Error while attempting to initiate the INetFwRule (CoCreateInstance failed: 0x%08lx).\n"), hrStatus);
		goto cleanup;
	}

	// Populates the rule's parameters.
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_ApplicationName(bstrRuleApplication);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
	pFwRule->put_Direction(direction);
	pFwRule->put_Profiles(FW_PROFILE_TYPE_ALL);
	pFwRule->put_Action(NET_FW_ACTION_BLOCK);
	pFwRule->put_Enabled(VARIANT_TRUE);

	// Add the new rule.
	hrStatus = pFwRules->Add(pFwRule);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Error while adding the firewall blocking rule for %s (INetFwRule->Add failed: 0x%08lx)\n"), binaryPath, hrStatus);
	}

cleanup:

	if (pFwRule) {
		pFwRule->Release();
	}

	if (pFwRules) {
		pFwRules->Release();
	}

	if (pNetFwPolicy2) {
		pNetFwPolicy2->Release();
	}

	if (bstrRuleName) {
		SysFreeString(bstrRuleName);
		bstrRuleName = NULL;
	}

	if (bstrRuleDescription) {
		SysFreeString(bstrRuleDescription);
		bstrRuleDescription = NULL;

	}

	if (bstrRuleApplication) {
		SysFreeString(bstrRuleApplication);
		bstrRuleApplication = NULL;
	}

	if (SUCCEEDED(hrComInit)) {
		CoUninitialize();
	}

	return hrStatus;
}

extern "C" HRESULT DeleteFirewallRule(TCHAR* ruleName);
HRESULT DeleteFirewallRule(TCHAR* ruleName) {
	HRESULT hrComInit = E_FAIL;
	HRESULT hrStatus = S_OK;

	INetFwPolicy2* pNetFwPolicy2 = NULL;
	INetFwRules* pFwRules = NULL;

	hrComInit = ComInitNetFwPolicy2(&pNetFwPolicy2);
	if (FAILED(hrComInit)) {
		hrStatus = E_FAIL;
		goto cleanup;
	}

	hrStatus = pNetFwPolicy2->get_Rules(&pFwRules);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Could not retrieve current Firewall rules (pNetFwPolicy2->get_Rules: 0x%08lx).\n"), hrStatus);
		goto cleanup;
	}

	hrStatus = pFwRules->Remove(ruleName);
	if (FAILED(hrStatus)) {
		_tprintf_or_not(TEXT("[!] Error while removing Firewall rule \"%s\" (failed with: 0x%08lx)\n"), ruleName, hrStatus);
		_tprintf_or_not(TEXT("[!] The rule can be removed manually using: netsh advfirewall firewall delete rule name=%s\n"), ruleName);
	}
	else {
		_tprintf_or_not(TEXT("[+] Successfully removed Firewall rule \"%s\"\n"), ruleName);
	}

cleanup:

	if (pFwRules) {
		pFwRules->Release();
	}

	if (SUCCEEDED(hrComInit)) {
		pNetFwPolicy2->Release();
	}

	return hrStatus;
}