#include <Windows.h>

typedef struct _LINKED_LIST {
	struct _LINKED_LIST* next;
} LINKED_LIST, * PLINKED_LIST;

VOID freeLinkedList(PVOID head);