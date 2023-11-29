#pragma once
#include <Windows.h>


enum FltmgrOffsetType {
	FltGlobals = 0,
	_GLOBALS_FrameList,
	_FLT_RESOURCE_LIST_HEAD_rList,
	_FLTP_FRAME_Links,
	_FLTP_FRAME_RegisteredFilters,
	_FLT_OBJECT_PrimaryLink,
	_FLT_FILTER_DriverObject,
	_FLT_FILTER_InstanceList,
	_DRIVER_OBJECT_DriverInit,
	_FLT_INSTANCE_CallbackNodes,
	_FLT_INSTANCE_FilterLink,
	_SUPPORTED_FLTMGR_OFFSETS_END
};

union FltmgrOffsets {
	// structure version of fltmgr.sys's offsets
	struct {
		DWORD64 FltGlobals;
		DWORD64 _GLOBALS_FrameList;
		DWORD64 _FLT_RESOURCE_LIST_HEAD_rList;
		DWORD64 _FLTP_FRAME_Links;
		DWORD64 _FLTP_FRAME_RegisteredFilters;
		DWORD64 _FLT_OBJECT_PrimaryLink;
		DWORD64 _FLT_FILTER_DriverObject;
		DWORD64 _FLT_FILTER_InstanceList;
		DWORD64 _DRIVER_OBJECT_DriverInit;
		DWORD64 _FLT_INSTANCE_CallbackNodes;
		DWORD64 _FLT_INSTANCE_FilterLink;
	} st;

	// array version (usefull for code factoring)
	DWORD64 ar[_SUPPORTED_FLTMGR_OFFSETS_END];
};

union FltmgrOffsets g_fltmgrOffsets;

BOOL LoadFltmgrOffsets(_In_opt_ TCHAR* fltmgrOffsetFilename, BOOL canUseInternet);

BOOL LoadFltmgrOffsetsFromFile(TCHAR* fltmgrOffsetFilename);
void SaveFltmgrOffsetsToFile(TCHAR* fltmgrOffsetFilename);

BOOL LoadFltmgrOffsetsFromInternet(BOOL delete_pdb);

LPTSTR GetFltmgrPath();
LPTSTR GetFltmgrVersion();