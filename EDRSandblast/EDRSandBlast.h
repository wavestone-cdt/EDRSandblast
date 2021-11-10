#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <Dbghelp.h>
#include <stdlib.h>
#include <Psapi.h>
#include <Tchar.h>
#include <time.h>
#include <tlhelp32.h>
#include <malloc.h>
#include <assert.h>

#include "Includes/Globals.h"
#include "Includes/CredGuard.h"
#include "Includes/DriverOps.h"
#include "Includes/ETWThreatIntel.h"
#include "Includes/FileVersion.h"
#include "Includes/KernelCallbacks.h"
#include "Includes/KernelMemoryPrimitives.h"
#include "Includes/KernelPatternSearch.h"
#include "Includes/LSASSDump.h"
#include "Includes/NtoskrnlOffsets.h"
#include "Includes/RunAsPPL.h"
#include "Includes/WdigestOffsets.h"
#include "Includes/UserlandHooks.h"

typedef enum _START_MODE {
    dump,
    cmd,
    credguard,
    audit
} START_MODE;