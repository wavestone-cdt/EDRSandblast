/*

--- Utility function to generate a random string.

*/

#include "StringUtils.h"

//BOOL isFullPath(IN TCHAR* filename) {
//    char c;
//
//    if (filename[0] == filename[1] && filename[1] == TEXT('\\')) {
//        return TRUE;
//    }
//
//    c = filename[0] | 0x20;
//    if (c < 97 || c > 122) {
//        return FALSE;
//    }
//
//    c = filename[1];
//    if (c != ':') {
//        return FALSE;
//    }
//
//    c = filename[2];
//    if (c != '\\') {
//        return FALSE;
//    }
//
//    return TRUE;
//}

VOID getUnicodeStringFromWCHAR(OUT PUNICODE_STRING unicodeString, IN WCHAR* wcharString) {
    unicodeString->Buffer = wcharString;
    unicodeString->Length = (WORD)wcslen(unicodeString->Buffer) * sizeof(WCHAR);
    unicodeString->MaximumLength = unicodeString->Length + sizeof(WCHAR);
}

BOOL srandDone = FALSE;

/*
* Generates a "length"-long random alphanumeric string
* Assumes the allocation is big enough to receive "length" chararcters (so is at least "length + 1" long)
*/
TCHAR* generateRandomString(TCHAR* str, size_t length) {
    if (!srandDone) {
        srand((unsigned int)time(0));
        srandDone = TRUE;
    }

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    if (length) {
        for (size_t n = 0; n < length; n++) {
            int key = rand() % (int)(sizeof charset - 1);
            str[n] = charset[key];
        }
        str[length] = '\0';
    }
    return str;
}


TCHAR* allocAndGenerateRandomString(size_t length) {
    LPTSTR str = calloc(length + 1, sizeof(TCHAR));
    if (str == NULL) {
        return NULL;
    }
    generateRandomString(str, length);
    return str;
}
