#pragma once

#include <Windows.h>
#pragma warning(disable : 4201)
#include <netfw.h>
#pragma warning(default : 4201)

#include <Tchar.h>
#include <stdio.h>

#include "StringUtils.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef FW_PROFILE_TYPE_ALL
#define FW_PROFILE_TYPE_ALL 0x7FFFFFFF
#endif

#define FW_RULE_NAME_MAX_LENGTH 20

HRESULT IsFirewallEnabled(BOOL* firewallIsOn);

HRESULT CreateFirewallRuleBlockBinary(TCHAR* binaryPath, NET_FW_RULE_DIRECTION direction, TCHAR* ruleName);

HRESULT DeleteFirewallRule(TCHAR * ruleName);
