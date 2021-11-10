#pragma once

#include <Windows.h>
#include <stdio.h>

#include <Psapi.h>
#include <tlhelp32.h>

#include "WdigestOffsets.h"

DWORD WINAPI disableCredGuardByPatchingLSASS(void);
