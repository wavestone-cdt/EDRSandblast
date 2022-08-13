#include "ListUtils.h"

VOID freeLinkedList(PVOID head) {
    PLINKED_LIST previousNode = NULL;
    PLINKED_LIST currentNode = (PLINKED_LIST)head;

    while (currentNode) {
        previousNode = currentNode;
        currentNode = currentNode->next;
        free(previousNode);
        previousNode = NULL;
    }

    return;
}