/*

--- Functions to bypass Digital Signature Enforcement by disabling DSE through patching of the g_CiOptions attributes in memory.
--- Full source and credit to https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/
--- Code adapted from: https://github.com/kkent030315/gdrv-loader/tree/1909_mitigation

*/

#pragma once

#include <Windows.h>


enum CiOffsetType {
    g_CiOptions = 0,
    CiValidateImageHeader,
    _SUPPORTED_CI_OFFSETS_END
};

union CiOffsets {
    // structure version of Ci.dll's offsets
    struct {
        DWORD64 g_CiOptions;
        DWORD64 CiValidateImageHeader;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_CI_OFFSETS_END];
};

union CiOffsets g_ciOffsets;

// Return the offsets of CI!g_CiOptions for the specific Windows version in use.
BOOL LoadCiOffsets(_In_opt_ TCHAR* ciOffsetFilename, BOOL canUseInternet);
BOOL CiOffsetsAreLoaded();
BOOL LoadCiOffsetsFromFile(TCHAR* CiOffsetFilename);
void SaveCiOffsetsToFile(TCHAR* CiOffsetFilename);
BOOL LoadCiOffsetsFromInternet(BOOL delete_pdb);
LPTSTR GetCiVersion();
LPTSTR GetCiPath();