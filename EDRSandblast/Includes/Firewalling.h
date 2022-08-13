/*

--- Firewall rules to block EDR products from the network (inboud / outbound connections).

*/

#pragma once

#include <Windows.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Tchar.h>

#include "FirewallOps.h"
#include "IsEDRChecks.h"
#include "IsElevatedProcess.h"

// Singly-linked list used to hold the paths of binaries executed by EDRs (processes / services).
typedef struct sFwBinaryRules_ {
    TCHAR* binaryPath;
    TCHAR* ruleInboundName;
    TCHAR* ruleOutboundName;
    struct sFwBinaryRules_* next;
} fwBinaryRules;

typedef struct fwBlockingRulesList_ {
    fwBinaryRules* first;
}fwBlockingRulesList;

void FirewallPrintManualDeletion(fwBlockingRulesList* fwEntries);

HRESULT FirewallBlockEDR(fwBlockingRulesList* fwEntries);

HRESULT FirewallUnblockEDR(fwBlockingRulesList* fwEntries);

void fwList_insertSorted(fwBlockingRulesList* fwEntries, fwBinaryRules* newFWEntry);