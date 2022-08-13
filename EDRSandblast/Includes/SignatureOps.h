#pragma once

#include <windows.h>
#include "winerror.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "crypt32.lib")

typedef
enum _SignatureOpsError {
    E_FILE_NOT_FOUND = -2,
    E_KO = -1,
    E_SUCCESS = 0,
    E_INSUFFICIENT_BUFFER = 1,
    E_NOT_SIGNED = 2
} SignatureOpsError;
//typedef enum _signatureOpsError signatureOpsError;

/*
* Retrieves a string containing the Signers of the specificied file concatenated.
* Parameters:
*             [in] pFilePath: path the file.
*             [out] outSigners: out string that will contain the concatenated Signers. If outSigners is NULL, szOutSigners will contain the number of TCHAR required for the output string (termination included).
*             [in,out] szOutSigners: length of outSigners. If szOutSigners is too small, szOutSigners will contain the number of TCHAR required for the output string (termination included).
*/
SignatureOpsError GetFileSigners(TCHAR* pFilePath, TCHAR* outSigners, size_t* szOutSigners);