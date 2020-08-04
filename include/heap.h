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
HEAPHANDLE heapInit(uint8_t *buffer, size_t bufferLen);

// Allocate memory bytes from the private heap
void* heapMalloc(HEAPHANDLE hHeap, size_t bytes);

// Free the memoary at address from the priate heap
void heapFree(HEAPHANDLE hHeap, void* address);

// Reallocate memory at address for new length newLength
void* heapRealloc(HEAPHANDLE hHeap, void* address, uint16_t newLength);

// Get information about the heap state in heapInfo
void heapGetInfo(HEAPHANDLE hHeap, HEAPINFO *heapInfo);

#ifdef _DEBUG_HEAP
void heapSanity(HEAPHANDLE hHeap);
int heapCheck(HEAPHANDLE hHeap);
#endif

