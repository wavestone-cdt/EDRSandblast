#pragma once
#include "Undoc.h"

//
// [TEB/PEB UNDER 64-BIT WINDOWS]
// This file represents the 64-bit PEB and associated data structures for 64-bit Windows
// This PEB is allegedly valid between XP thru [at least] Windows 8
//
// [REFERENCES]
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB64_x86.html
//      https://github.com/giampaolo/psutil/commit/babd2b73538fcb6f3931f0ab6d9c100df6f37bcb     (RTL_USER_PROCESS_PARAMETERS)
//      https://redplait.blogspot.com/2011/09/w8-64bit-teb-peb.html                             (TEB)
//
// [CHANGELIST]
//    2018-05-02:   -now can be compiled alongside windows.h (without changes) or by defining WANT_ALL_WINDOWS_H_DEFINITIONS so this file can be used standalone
//                  -this file may also be included alongside tebpeb32.h which can be found at http://bytepointer.com/resources/tebpeb32.h
//                  -64-bit types no longer clash with the 32-bit ones; e.g. UNICODE_STRING64, RTL_USER_PROCESS_PARAMETERS64, PEB64 (same result whether 32 or 64-bit compiler is used)
//                  -added more QWORD aliases (i.e. HANDLE64 and PTR64) so underlying types are clearer, however most PEB members remain generic QWORD placeholders for now
//                  -fixed missing semicolon bug in UNICODE_STRING64
//                  -added prliminary RTL_USER_PROCESS_PARAMETERS64 and TEB64 with offsets
//                  -included byte offsets for PEB64
//
//    2017-08-25:   initial public release
//


//
// base types
//

//always declare 64-bit types
#ifdef _MSC_VER
	//Visual C++
typedef unsigned __int64    QWORD;
typedef __int64             INT64;
#else
	//GCC
typedef unsigned long long  QWORD;
typedef long long           INT64;
#endif
typedef QWORD                   PTR64;
#ifndef __HANDLE64_DEFINED__
typedef QWORD                   HANDLE64;
#endif

#include <windows.h>
//UNCOMMENT line below if you are not including windows.h
//#define WANT_ALL_WINDOWS_H_DEFINITIONS
#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

//base types
typedef unsigned char           BYTE;
typedef char                    CHAR;
typedef unsigned short          WORD;
typedef short                   INT16;
typedef unsigned long           DWORD;
typedef long                    INT32;
typedef unsigned __int64        QWORD;
typedef __int64                 INT64;
typedef void* HANDLE;
typedef unsigned short          WCHAR;

//base structures
union LARGE_INTEGER
{
	struct
	{
		DWORD   LowPart;
		INT32   HighPart;
	} u;
	INT64       QuadPart;
};

union ULARGE_INTEGER
{
	struct
	{
		DWORD LowPart;
		DWORD HighPart;
	} u;
	QWORD       QuadPart;
};

#endif //#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

typedef struct UNICODE_STRING64
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		} u;
		QWORD dummyalign;
	} uOrDummyAlign;
	WCHAR* Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _CLIENT_ID64
{
	QWORD  ProcessId;
	QWORD  ThreadId;
} CLIENT_ID64;

//NOTE: the members of this structure are not yet complete
typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
	BYTE                    Reserved1[16];                 //0x00
	QWORD                   Reserved2[5];                  //0x10
	UNICODE_STRING64        CurrentDirectoryPath;          //0x38
	HANDLE64                CurrentDirectoryHandle;        //0x48
	UNICODE_STRING64        DllPath;                       //0x50
	UNICODE_STRING64        ImagePathName;                 //0x60
	UNICODE_STRING64        CommandLine;                   //0x70
	PTR64                   Environment;                   //0x80
} RTL_USER_PROCESS_PARAMETERS64;

//
// PEB64 structure - TODO: comb more through http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html and add OS delineations and Windows 10 updates
//
// The structure represented here is a work-in-progress as only members thru offset 0x320 are listed; the actual sizes per OS are:
//    0x0358    XP/WS03
//    0x0368    Vista
//    0x037C    Windows 7
//    0x0388    Windows 8
//    0x07A0    Windows 10
//
typedef struct PEB64
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;                                 //0x000
			BYTE ReadImageFileExecOptions;                              //0x001
			BYTE BeingDebugged;                                         //0x002
			BYTE _SYSTEM_DEPENDENT_01;                                  //0x003
		} flags;
		QWORD dummyalign;
	} dword0;
	QWORD                           Mutant;                             //0x0008
	QWORD                           ImageBaseAddress;                   //0x0010
	PEB_LDR_DATA* Ldr;                                //0x0018
	PTR64                           ProcessParameters;                  //0x0020 / pointer to RTL_USER_PROCESS_PARAMETERS64
	QWORD                           SubSystemData;                      //0x0028
	QWORD                           ProcessHeap;                        //0x0030
	QWORD                           FastPebLock;                        //0x0038
	QWORD                           _SYSTEM_DEPENDENT_02;               //0x0040
	QWORD                           _SYSTEM_DEPENDENT_03;               //0x0048
	QWORD                           _SYSTEM_DEPENDENT_04;               //0x0050
	union
	{
		QWORD                       KernelCallbackTable;                //0x0058
		QWORD                       UserSharedInfoPtr;                  //0x0058
	}KernelCallbackTableOrUserSharedInfoPtr;
	DWORD                           SystemReserved;                     //0x0060
	DWORD                           _SYSTEM_DEPENDENT_05;               //0x0064
	QWORD                           _SYSTEM_DEPENDENT_06;               //0x0068
	QWORD                           TlsExpansionCounter;                //0x0070
	QWORD                           TlsBitmap;                          //0x0078
	DWORD                           TlsBitmapBits[2];                   //0x0080
	QWORD                           ReadOnlySharedMemoryBase;           //0x0088
	QWORD                           _SYSTEM_DEPENDENT_07;               //0x0090
	QWORD                           ReadOnlyStaticServerData;           //0x0098
	QWORD                           AnsiCodePageData;                   //0x00A0
	QWORD                           OemCodePageData;                    //0x00A8
	QWORD                           UnicodeCaseTableData;               //0x00B0
	DWORD                           NumberOfProcessors;                 //0x00B8
	union
	{
		DWORD                       NtGlobalFlag;                       //0x00BC
		DWORD                       dummy02;                            //0x00BC
	}NtGlobalFlagOrdummy02;
	LARGE_INTEGER                   CriticalSectionTimeout;             //0x00C0
	QWORD                           HeapSegmentReserve;                 //0x00C8
	QWORD                           HeapSegmentCommit;                  //0x00D0
	QWORD                           HeapDeCommitTotalFreeThreshold;     //0x00D8
	QWORD                           HeapDeCommitFreeBlockThreshold;     //0x00E0
	DWORD                           NumberOfHeaps;                      //0x00E8
	DWORD                           MaximumNumberOfHeaps;               //0x00EC
	QWORD                           ProcessHeaps;                       //0x00F0
	QWORD                           GdiSharedHandleTable;               //0x00F8
	QWORD                           ProcessStarterHelper;               //0x0100
	QWORD                           GdiDCAttributeList;                 //0x0108
	QWORD                           LoaderLock;                         //0x0110
	DWORD                           OSMajorVersion;                     //0x0118
	DWORD                           OSMinorVersion;                     //0x011C
	WORD                            OSBuildNumber;                      //0x0120
	WORD                            OSCSDVersion;                       //0x0122
	DWORD                           OSPlatformId;                       //0x0124
	DWORD                           ImageSubsystem;                     //0x0128
	DWORD                           ImageSubsystemMajorVersion;         //0x012C
	QWORD                           ImageSubsystemMinorVersion;         //0x0130
	union
	{
		QWORD                       ImageProcessAffinityMask;           //0x0138
		QWORD                       ActiveProcessAffinityMask;          //0x0138
	}ImageProcessAffinityMaskOrActiveProcessAffinityMask;
	QWORD                           GdiHandleBuffer[30];                //0x0140
	QWORD                           PostProcessInitRoutine;             //0x0230
	QWORD                           TlsExpansionBitmap;                 //0x0238
	DWORD                           TlsExpansionBitmapBits[32];         //0x0240
	QWORD                           SessionId;                          //0x02C0
	ULARGE_INTEGER                  AppCompatFlags;                     //0x02C8
	ULARGE_INTEGER                  AppCompatFlagsUser;                 //0x02D0
	QWORD                           pShimData;                          //0x02D8
	QWORD                           AppCompatInfo;                      //0x02E0
	UNICODE_STRING64                CSDVersion;                         //0x02E8
	QWORD                           ActivationContextData;              //0x02F8
	QWORD                           ProcessAssemblyStorageMap;          //0x0300
	QWORD                           SystemDefaultActivationContextData; //0x0308
	QWORD                           SystemAssemblyStorageMap;           //0x0310
	QWORD                           MinimumStackCommit;                 //0x0318

} PEB64, * PPEB64; //struct PEB64

//
// TEB64 structure - preliminary structure; the portion listed current at least as of Windows 8
//
typedef struct TEB64
{
	BYTE                            NtTib[56];                          //0x0000 / NT_TIB64 structure
	PTR64                           EnvironmentPointer;                 //0x0038
	CLIENT_ID64                     ClientId;                           //0x0040
	PTR64                           ActiveRpcHandle;                    //0x0050
	PTR64                           ThreadLocalStoragePointer;          //0x0058
	PTR64                           ProcessEnvironmentBlock;            //0x0060 / ptr to PEB64
	DWORD                           LastErrorValue;                     //0x0068
	DWORD                           CountOfOwnedCriticalSections;       //0x006C
	PTR64                           CsrClientThread;                    //0x0070
	PTR64                           Win32ThreadInfo;                    //0x0078
	DWORD                           User32Reserved[26];                 //0x0080
	DWORD                           UserReserved[6];                    //0x00E8
	PTR64                           WOW32Reserved;                      //0x0100
	DWORD                           CurrentLocale;                      //0x0108
	DWORD                           FpSoftwareStatusRegister;           //0x010C
	PTR64                           SystemReserved1[54];                //0x0110
	DWORD                           ExceptionCode;                      //0x02C0
	PTR64                           ActivationContextStackPointer;      //0x02C8

} TEB64; //struct TEB64
