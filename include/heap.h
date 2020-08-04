#pragma once

//#define _DEBUG_HEAP

#include <stdint.h>
#include <stddef.h>

typedef void* HEAPHANDLE;

typedef struct _HEAPINFO
{
	int freeBytes;
	int usedBytes;
	int totalBytes;
	int largestFree;
} HEAPINFO;

// Initialize the private heap with buffer or bufferLen bytes
HEAPHANDLE heap_init(uint8_t *buffer, size_t bufferLen);

// Allocate memory bytes from the private heap
void* heap_malloc(HEAPHANDLE hHeap, size_t bytes);

// Free the memoary at address from the priate heap
void heap_free(HEAPHANDLE hHeap, void* address);

// Reallocate memory at address for new length newLength
void* heap_realloc(HEAPHANDLE hHeap, void* address, uint16_t newLength);

// Get information about the heap state in heapInfo
void heap_get_info(HEAPHANDLE hHeap, HEAPINFO *heapInfo);

#ifdef _DEBUG_HEAP
void heap_sanity(HEAPHANDLE hHeap);
int heap_check(HEAPHANDLE hHeap);
#endif

