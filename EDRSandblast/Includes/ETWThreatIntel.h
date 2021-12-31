/*

--- ETW Threat Intelligence operations.
--- Inspiration and credit: https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider

*/

#pragma once

#include <Windows.h>

#define DISABLE_PROVIDER 0x0
#define ENABLE_PROVIDER 0x1

DWORD64 GetEtwThreatIntProvRegHandleAddress();

DWORD64 GetEtwThreatInt_ProviderEnableInfoAddress(BOOL verbose);

void DisableETWThreatIntelProvider(BOOL verbose);

void EnableETWThreatIntelProvider(BOOL verbose);

BOOL isETWThreatIntelProviderEnabled(BOOL verbose);