#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <Dbghelp.h>
#include <stdlib.h>
#include <Psapi.h>
#include <Tchar.h>
#include <tlhelp32.h>
#include <malloc.h>
#include <assert.h>

#include "CredGuard.h"
#include "DriverOps.h"
#include "ETWThreatIntel.h"
#include "FileVersion.h"
#include "KernelCallbacks.h"
#include "KernelMemoryPrimitives.h"
#include "KernelPatternSearch.h"
#include "LSASSDump.h"
#include "NtoskrnlOffsets.h"
#include "RunAsPPL.h"
#include "WdigestOffsets.h"
#include "UserlandHooks.h"

#define SERVICE_NAME_LENGTH 8

typedef enum _START_MODE {
    dump,
    cmd,
    credguard,
    audit
} START_MODE;