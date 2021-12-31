/*

--- ntoskrnl Notify Routines' offsets search functions using patterns.
--- Ultimately not used because too unreliable and too prone to BSoD.

*/
#include <Windows.h>
#include <Tchar.h>
#include "KernelMemoryPrimitives.h"

DWORD64 PatternSearchStartingFromAddress(HANDLE Device, DWORD64 startAddress, DWORD bytesToScan, DWORD64 pattern, DWORD64 mask) {
    for (DWORD i = 0; i < bytesToScan; i++) {
        DWORD64 instructionAddress = startAddress + i;
        DWORD64 dword64Instruction = ReadMemoryDWORD64(Device, instructionAddress);
        DWORD64 dword64InstructionFixed = dword64Instruction & mask;
        // _tprintf(TEXT("i = %i, pattern = 0x%I64x, instructionAddress = 0x%I64x, wordInstruction = 0x%I64x, wordInstructionFixed = 0x%I64x\n"), i, pattern, instructionAddress, dword64Instruction, dword64InstructionFixed);
        if (dword64InstructionFixed == pattern) {
            _tprintf(TEXT("[+] Found pattern = 0x%I64x at offset i = %i [instructionAddress = 0x%I64x, wordInstruction = 0x%I64x, wordInstructionFixed = 0x%I64x]\n"), pattern, i, instructionAddress, dword64Instruction, dword64InstructionFixed);
            return instructionAddress;
        }
    }
    return 0x0;
}

DWORD64 ExtractRelativeAddress(HANDLE Device, DWORD64 instructionStartAddress, DWORD64 instructionRelativeAddressOffset, DWORD64 nextInstructionOffset) {
    DWORD64 procedureRelativeAddress = (signed int)ReadMemoryDWORD64(Device, instructionStartAddress + instructionRelativeAddressOffset);
    DWORD64 nextInstructionAddress = instructionStartAddress + nextInstructionOffset;
    return nextInstructionAddress + procedureRelativeAddress;
}

DWORD64 GetPspCreateProcessNotifyRoutineAddressUsingPattern(void) {
    _tprintf(TEXT("[*] Searching for PspCreateProcessNotifyRoutine address using pattern\n"));
    HANDLE Device = GetDriverHandle();

    // Extracting PspSetCreateProcessNotifyRoutine address in PsSetCreateProcessNotifyRoutine using the pattern "E8" (CALL) to match "[e80e010000]  call nt!PspSetCreateProcessNotifyRoutine".
    DWORD64 PsSetCreateProcessNotifyRoutineAddress = GetFunctionAddress("PsSetCreateProcessNotifyRoutine");
    DWORD64 CallPspSetCreateProcessNotifyRoutineAddress = PatternSearchStartingFromAddress(Device, PsSetCreateProcessNotifyRoutineAddress, 64, 0x00000000000000E8, 0x00000000000000FF);
    DWORD64 PspSetCreateProcessNotifyRoutineAddress = ExtractRelativeAddress(Device, CallPspSetCreateProcessNotifyRoutineAddress, 1, 5);

    // Extracting PspCreateProcessNotifyRoutine address in PspSetCreateProcessNotifyRoutine using the pattern "4C 8D" (LEA 4C) to match "[4c8d2d371ddaff]  lea r13,[nt!PspCreateProcessNotifyRoutine".
    DWORD64 LeaPspCreateProcessNotifyRoutineAddress = PatternSearchStartingFromAddress(Device, PspSetCreateProcessNotifyRoutineAddress, 256, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspCreateProcessNotifyRoutineAddress = ExtractRelativeAddress(Device, LeaPspCreateProcessNotifyRoutineAddress, 3, 7);
    _tprintf(TEXT("[+] Pattern search found PspCreateProcessNotifyRoutine address: 0x%I64x\n"), PspCreateProcessNotifyRoutineAddress);
    
    CloseHandle(Device);

    return PspCreateProcessNotifyRoutineAddress;
}

DWORD64 GetPspCreateThreadNotifyRoutineAddressUsingPattern(void) {
    _tprintf(TEXT("[*] Searching for PspCreateThreadNotifyRoutine address using pattern\n"));
    HANDLE Device = GetDriverHandle();

    // Extracting nt!PspSetCreateThreadNotifyRoutine address in nt!PsSetCreateThreadNotifyRoutine using the pattern "E8" (CALL) to match "[e865000000]  call nt!PspSetCreateThreadNotifyRoutine".
    DWORD64 PsSetCreateThreadNotifyRoutineAddress = GetFunctionAddress("PsSetCreateThreadNotifyRoutine");
    DWORD64 CallPspSetCreateThreadNotifyRoutineAddress = PatternSearchStartingFromAddress(Device, PsSetCreateThreadNotifyRoutineAddress, 64, 0x00000000000000E8, 0x00000000000000FF);
    DWORD64 PspSetCreateThreadNotifyRoutineAddress = ExtractRelativeAddress(Device, CallPspSetCreateThreadNotifyRoutineAddress, 1, 5);

    // Extracting nt!PspCreateThreadNotifyRoutine address in nt!PspSetCreateThreadNotifyRoutine using the pattern "4C 8D" (LEA 4C) to match "[488d0d431cdaff]  lea rcx,[nt!PspCreateThreadNotifyRoutine]".
    DWORD64 LeaPspCreateThreadNotifyRoutineAddress = PatternSearchStartingFromAddress(Device, PspSetCreateThreadNotifyRoutineAddress, 256, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspCreateThreadNotifyRoutineAddress = ExtractRelativeAddress(Device, LeaPspCreateThreadNotifyRoutineAddress, 3, 7);
    _tprintf(TEXT("[+] Pattern search found PspCreateThreadNotifyRoutine address: 0x%I64x\n"), PspCreateThreadNotifyRoutineAddress);
    
    CloseHandle(Device);

    return PspCreateThreadNotifyRoutineAddress;
}

DWORD64 GetPspLoadImageNotifyRoutineAddressUsingPattern(void) {
    _tprintf(TEXT("[*] Searching for PspLoadImageNotifyRoutine address using pattern\n"));
    HANDLE Device = GetDriverHandle();

    // Extracting nt!PspLoadImageNotifyRoutine address directly from nt!PsSetLoadImageNotifyRoutineEx using the pattern "4C 8D" (LEA 4C) to match "[488d0d981ddaff]  lea rcx,[nt!PspLoadImageNotifyRoutine]".
    DWORD64 PsSetLoadImageNotifyRoutineExAddress = GetFunctionAddress("PsSetLoadImageNotifyRoutineEx");
    DWORD64 LeaPspLoadImageNotifyRoutineAddress = PatternSearchStartingFromAddress(Device, PsSetLoadImageNotifyRoutineExAddress, 128, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspLoadImageNotifyRoutineAddress = ExtractRelativeAddress(Device, LeaPspLoadImageNotifyRoutineAddress, 3, 7);;
    _tprintf(TEXT("[+] Pattern search found PspLoadImageNotifyRoutine address: 0x%I64x\n"), PspLoadImageNotifyRoutineAddress);
    
    CloseHandle(Device);

    return PspLoadImageNotifyRoutineAddress;
}