#pragma once

//TODO P1 : implement a "clean" mode that only removes the driver if installed
//TODO P2 : replace all instances of exit(1) by a clean_exit() function that uninstalls the driver before exiting
typedef enum _START_MODE {
    dump,
    cmd,
    credguard,
    audit,
    firewall,
    none
} START_MODE;

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