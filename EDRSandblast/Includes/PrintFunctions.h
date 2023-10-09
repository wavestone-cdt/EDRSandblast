#pragma once

#include <stdio.h>
#include <tchar.h>

#define NO_STRINGS 0

#if NO_STRINGS
#define _putts_or_not(...)
#define _tprintf_or_not(...)
#define wprintf_or_not(...)
#define printf_or_not(...)
#pragma warning(disable : 4189)

#else
#define _putts_or_not(...) _putts(__VA_ARGS__)
#define _tprintf_or_not(...) _tprintf(__VA_ARGS__)
#define printf_or_not(...) printf(__VA_ARGS__)
#define wprintf_or_not(...) wprintf(__VA_ARGS__)
#endif