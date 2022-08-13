/*

--- Functions to bypass Credential Guard by enabling Wdigest through patching of the g_fParameter_UseLogonCredential and g_IsCredGuardEnabled attributes in memory.
--- Full source and credit to https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
--- Code adapted from: https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240

*/

#pragma once

#include <Windows.h>


enum WdigestOffsetType {
    g_fParameter_UseLogonCredential = 0,
    g_IsCredGuardEnabled = 1,
    _SUPPORTED_WDIGEST_OFFSETS_END
};

union WdigestOffsets {
    // structure version of wdigest.dll's offsets
    struct {
        // wdigest.dll's g_fParameter_UseLogonCredential
        DWORD64 g_fParameter_UseLogonCredential;
        // wdigest.dll's g_IsCredGuardEnabled 
        DWORD64 g_IsCredGuardEnabled;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[2];
};

union WdigestOffsets g_wdigestOffsets;

// Return the offsets of nt!PspCreateProcessNotifyRoutine, nt!PspCreateThreadNotifyRoutine, nt!PspLoadImageNotifyRoutine, and nt!_PS_PROTECTION for the specific Windows version in use.
void LoadWdigestOffsetsFromFile(TCHAR* wdigestOffsetFilename);
void SaveWdigestOffsetsToFile(TCHAR* wdigestOffsetFilename);

void LoadWdigestOffsetsFromInternet(BOOL delete_pdb);

LPTSTR GetWdigestPath();