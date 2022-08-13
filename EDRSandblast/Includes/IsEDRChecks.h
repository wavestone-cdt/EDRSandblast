/*
* Primitives to check if a binary or driver belongs to an EDR product.
*/

#pragma once

#include <Windows.h>
#include <Tchar.h>

#include "SignatureOps.h"

TCHAR const* EDR_SIGNATURE_KEYWORDS[];
TCHAR const* EDR_BINARIES[];
TCHAR const* EDR_DRIVERS[];

BOOL isFileSignatureMatchingEDR(TCHAR* filePath);

BOOL isBinaryNameMatchingEDR(TCHAR* binaryName);

BOOL isBinaryPathMatchingEDR(TCHAR* binaryPath);

BOOL isDriverNameMatchingEDR(TCHAR* driverName);

BOOL isDriverPathMatchingEDR(TCHAR* driverPath);