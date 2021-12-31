/*

--- ntoskrnl Notify Routines' offsets search functions using patterns.
--- Ultimately not used because too unreliable and too prone to BSoD.

*/

#pragma once

#include <Windows.h>

DWORD64 PatternSearchStartingFromAddress(HANDLE Device, DWORD64 startAddress, DWORD bytesToScan, DWORD64 pattern, DWORD64 mask);

DWORD64 ExtractRelativeAddress(HANDLE Device, DWORD64 instructionStartAddress, DWORD64 instructionRelativeAddressOffset, DWORD64 nextInstructionOffset);

DWORD64 GetPspCreateProcessNotifyRoutineAddressUsingPattern(void);

DWORD64 GetPspCreateThreadNotifyRoutineAddressUsingPattern(void);

DWORD64 GetPspLoadImageNotifyRoutineAddressUsingPattern(void);