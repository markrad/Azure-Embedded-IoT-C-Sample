#include "heap.h"

#ifdef _DEBUG_HEAP
#include <stdio.h>

#define _DEBUG_HEAP_SANITY(HEAP) (heap_sanity(HEAP));
#define _DEBUG_HEAP_CHECK(HEAP) (heap_check(HEAP))
#else
#define _DEBUG_HEAP_SANITY(HEAP) (0)
#define _DEBUG_HEAP_CHECK(HEAP) (0)
#endif

#include <memory.h>

#define MIN_ALLOC sizeof(MEMORYBLOCKSTRUCT) + 4
#define CHAIN_END UINT16_MAX
#define MIN_BUFFER 1024
#define MAX_BUFFER UINT16_MAX

typedef struct _MEMORYBLOCK
{
	uint16_t length;
	uint16_t next;
	uint16_t previous;
} MEMORYBLOCKSTRUCT, * MEMORYBLOCK;

typedef struct _HEAPHANDLE
{
	MEMORYBLOCKSTRUCT freeList;
	MEMORYBLOCKSTRUCT usedList;
} HHEAPSTRUCT, * HHEAP;

static MEMORYBLOCK heap_get_free_list(HEAPHANDLE hHeap);
static MEMORYBLOCK heap_get_used_list(HEAPHANDLE hHeap);
static uint16_t heap_get_offset(HEAPHANDLE hHeap, MEMORYBLOCK mb);
static MEMORYBLOCK heap_get_next_address(HEAPHANDLE hHead, MEMORYBLOCK mb);
static MEMORYBLOCK heap_get_previous_address(HEAPHANDLE hHead, MEMORYBLOCK mb);
static MEMORYBLOCK heap_get_MB(uint8_t* address);
static uint8_t* heap_get_data(MEMORYBLOCK mb);
static void heap_insert_into_free_list(HEAPHANDLE hHead, MEMORYBLOCK mb);
static void heap_insert_after(HEAPHANDLE hHeap, MEMORYBLOCK target, MEMORYBLOCK newItem);
static void heap_remove_from_list(HEAPHANDLE hHeap, MEMORYBLOCK mb);
static int heap_get_is_adjacent(MEMORYBLOCK first, MEMORYBLOCK second);
static void* heapTruncate(HEAPHANDLE hHeap, void* address, uint16_t newLength);
static void* heap_extend(HEAPHANDLE hHeap, void* address, uint16_t newLength);

// Initialize the heap structures
HEAPHANDLE heap_init(uint8_t *buffer, size_t bufferLen)
{
	if (buffer == NULL || bufferLen < MIN_BUFFER || bufferLen > MAX_BUFFER)
		return NULL;

#ifdef _DEBUG_HEAP
	memset(buffer, 0xee, bufferLen);
#endif

	HHEAP hHeap = (HHEAP)buffer;

	hHeap->usedList.length = 0;
	hHeap->usedList.next = CHAIN_END;
	hHeap->usedList.previous = CHAIN_END;
	hHeap->freeList.length = 1;
	hHeap->freeList.next = (uint16_t)sizeof(HHEAPSTRUCT);
	hHeap->freeList.previous = CHAIN_END;

	MEMORYBLOCK first = heap_get_next_address(hHeap, &hHeap->freeList);

	first->length = (uint16_t)(bufferLen - sizeof(HHEAPSTRUCT) - sizeof(MEMORYBLOCKSTRUCT));
	first->next = CHAIN_END;
	first->previous = (uint16_t)((uint8_t*)&hHeap->freeList - buffer);

	_DEBUG_HEAP_SANITY(hHeap);

	return (HEAPHANDLE)hHeap;
}

// Allocate a block
void* heap_malloc(HEAPHANDLE hHeap, size_t bytes)
{
	HHEAP h = (HHEAP)hHeap;

	void* result = NULL;

	if (hHeap != NULL && bytes != 0)
	{
		if (bytes % 2 != 0)
			bytes += 1;

		if (bytes < MIN_ALLOC - sizeof(MEMORYBLOCKSTRUCT))
			bytes = MIN_ALLOC - sizeof(MEMORYBLOCKSTRUCT);

		MEMORYBLOCK mb = heap_get_free_list(hHeap);

		while (NULL != (mb = heap_get_next_address(hHeap, mb)))
		{
			if (mb->length > bytes)
				break;
		}

		if (mb != NULL)
		{
			if (mb->length - bytes > MIN_ALLOC)
			{
				MEMORYBLOCK add = (MEMORYBLOCK)(heap_get_data(mb) + bytes);
				add->next = mb->next;
				add->previous = mb->previous;
				heap_get_previous_address(hHeap, mb)->next = heap_get_offset(hHeap, add);

				if (add->next != CHAIN_END)
					heap_get_next_address(hHeap, add)->previous = heap_get_offset(hHeap, add);

				add->length = mb->length - sizeof(MEMORYBLOCKSTRUCT) - (uint16_t)bytes;
				mb->length = (uint16_t)bytes;
			}
			else
			{
				#ifdef _DEBUG_HEAP
				if (h->freeList.length == 0)
				{
					// Heap failure
					int x = 1, y = 0;
					x = x / y;
				}
				#endif

				heap_remove_from_list(hHeap, mb);
				h->freeList.length--;
			}

			heap_insert_after(hHeap, heap_get_used_list(hHeap), mb);
			h->usedList.length++;

			result = heap_get_data(mb);
		}
	}

	_DEBUG_HEAP_SANITY(hHeap);

	return result;
}

// Free an allocated block
void heap_free(HEAPHANDLE hHeap, void* address)
{
	HHEAP h = (HHEAP)hHeap;

	if (hHeap != NULL && address != NULL)
	{
		MEMORYBLOCK mb = heap_get_MB(address);

		heap_remove_from_list(hHeap, mb);
		h->usedList.length--;

		MEMORYBLOCK search = heap_get_free_list(hHeap);
		search = heap_get_next_address(hHeap, search);

		while (search != NULL)
		{
			int adj = heap_get_is_adjacent(search, mb);

			switch (adj)
			{
			case 0:
				break;
			case -1:
				// Is before freed entry - add search to current
				search->length += (mb->length + sizeof(MEMORYBLOCKSTRUCT));
				mb = search;
				heap_remove_from_list(hHeap, mb);
				h->freeList.length--;
				search = heap_get_free_list(hHeap);
				break;
			case 1:
				// Is after freed entry - add current to search
				heap_remove_from_list(hHeap, search);
				h->freeList.length--;
				mb->length += (search->length + sizeof(MEMORYBLOCKSTRUCT));
				search = heap_get_free_list(hHeap);
				break;
			default:
				break;
			}

			search = heap_get_next_address(hHeap, search);
		}

		heap_insert_into_free_list(hHeap, mb);
		h->freeList.length++;
	}

	_DEBUG_HEAP_SANITY(hHeap);
}

void* heap_realloc(HEAPHANDLE hHeap, void* address, uint16_t newLength)
{
	if (hHeap != NULL)
	{
		if (address == NULL)
		{
			return heap_malloc(hHeap, newLength);
		}
		else
		{
			MEMORYBLOCK mb = heap_get_MB(address);

			return mb->length > newLength
				? heapTruncate(hHeap, address, newLength)
				: mb->length < newLength
				? heap_extend(hHeap, address, newLength)
				: address;
		}
	}
	else
	{
		return NULL;
	}
}

static void* heapTruncate(HEAPHANDLE hHeap, void* address, uint16_t newLength)
{
	HHEAP h = (HHEAP)hHeap;
	void* result = address;

	if (hHeap != NULL && address != NULL)
	{
		if (newLength == 0)
		{
			heap_free(hHeap, address);
		}
		else
		{
			if (newLength % 2 != 0)
				newLength += 1;

			MEMORYBLOCK mb = heap_get_MB(address);

			if (newLength < mb->length)
			{
				result = address;

				MEMORYBLOCK search = heap_get_next_address(hHeap, heap_get_free_list(hHeap));

				while (search != NULL)
				{
					if (1 == heap_get_is_adjacent(search, mb))
						break;

					search = heap_get_next_address(hHeap, search);
				}

				if (search != NULL || mb->length - newLength > MIN_ALLOC)
				{
					MEMORYBLOCK trailer = (MEMORYBLOCK)((uint8_t*)address + newLength);
					trailer->length = mb->length - newLength - sizeof(MEMORYBLOCKSTRUCT);
					mb->length = newLength;

					if (search != NULL)
					{
#ifdef _DEBUG_HEAP
						if (h->freeList.length == 0)
						{
							// Heap failure
							int x = 1, y = 0;
							x = x / y;
						}
#endif
						heap_remove_from_list(hHeap, search);
						h->freeList.length--;
						trailer->length += (search->length + sizeof(MEMORYBLOCKSTRUCT));
					}

					heap_insert_into_free_list(hHeap, trailer);
					h->freeList.length++;
				}
			}
		}
	}

	_DEBUG_HEAP_SANITY(hHeap);

	return result;
}

static void* heap_extend(HEAPHANDLE hHeap, void* address, uint16_t newLength)
{
	HHEAP h = (HHEAP)hHeap;
	void* result = address;

	if (hHeap != NULL && address != NULL)
	{
		if (newLength % 2 != 0)
			newLength += 1;

		MEMORYBLOCK mb = heap_get_MB(address);

		if (newLength > mb->length)
		{
			MEMORYBLOCK search = heap_get_next_address(hHeap, heap_get_free_list(hHeap));

			while (search != NULL)
			{
				if (1 == heap_get_is_adjacent(search, mb))
					break;

				search = heap_get_next_address(hHeap, search);
			}

			if (search != NULL && search->length + sizeof(MEMORYBLOCKSTRUCT) >= newLength - mb->length)
			{
				// Can extend into adjacent free node
#ifdef _DEBUG_HEAP
				if (h->freeList.length == 0)
				{
					// Heap failure
					int x = 1, y = 0;
					x = x / y;
				}
#endif
				heap_remove_from_list(hHeap, search);
				h->freeList.length--;

				MEMORYBLOCK newFree = (MEMORYBLOCK)(heap_get_data(mb) + newLength);

				newFree->length = search->length - (newLength - mb->length);
				mb->length = newLength;

				if (newFree->length > 0)
				{
#ifdef _DEBUG_HEAP
				if (h->freeList.length == 0)
				{
					// Heap failure
					int x = 1, y = 0;
					x = x / y;
				}
#endif
					heap_insert_into_free_list(hHeap, newFree);
					h->freeList.length++;
					result = address;
				}
			}
			else
			{
				result = heap_malloc(hHeap, newLength);

				if (result != NULL)
				{
					memcpy(result, heap_get_data(mb), mb->length);
					heap_free(hHeap, heap_get_data(mb));
				}
			}
		}
	}

	_DEBUG_HEAP_SANITY(hHeap);

	return result;
}

void heap_get_info(HEAPHANDLE hHeap, HEAPINFO *heapInfo)
{
	MEMORYBLOCK mb;

	memset(heapInfo, 0, sizeof(HEAPINFO));

	mb = heap_get_used_list(hHeap);
	
	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		heapInfo->totalBytes += mb->length + sizeof(MEMORYBLOCKSTRUCT);
		heapInfo->usedBytes += mb->length;
	}

	mb = heap_get_free_list(hHeap);

	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		heapInfo->totalBytes += mb->length + sizeof(MEMORYBLOCKSTRUCT);
		heapInfo->freeBytes += mb->length;

		if (mb->length > heapInfo->largestFree)
			heapInfo->largestFree = mb->length;
	}
}

#ifdef _DEBUG_HEAP
void heap_sanity(HEAPHANDLE hHeap)
{
	HHEAP h = (HHEAP)hHeap;
	MEMORYBLOCK mb;

	static int leastFreeBytes = UINT16_MAX;
	int freeBytes = 0;
	int usedBytes = 0;
	int totalBytes = 0;
	int largestFree = 0;

	int cnt;
	
	printf("\n# usedlist entries = %d\n# freelist entries = %d\n", h->usedList.length, h->freeList.length);

	printf("\r\nUsed list\r\n\n");

	mb = heap_get_used_list(hHeap);
	cnt = 0;
	
	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		if (++cnt > h->usedList.length)
		{
			printf("heap is broken - used list counts do not agree\n");
			return;
		}
		printf("offset=%d;next=%d;previous=%d;length=%d\r\n", heap_get_offset(hHeap, mb), mb->next, mb->previous, mb->length);
		totalBytes += mb->length + sizeof(MEMORYBLOCKSTRUCT);
		usedBytes += mb->length;
	}

	printf("\r\nFree list\r\n\n");

	mb = heap_get_free_list(hHeap);
	cnt = 0;

	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		if (++cnt > h->freeList.length)
		{
			printf("heap is broken - used list counts do not agree\n");
			return;
		}
		printf("offset=%d;next=%d;previous=%d;length=%d\r\n", heap_get_offset(hHeap, mb), mb->next, mb->previous, mb->length);
		totalBytes += mb->length + sizeof(MEMORYBLOCKSTRUCT);
		freeBytes += mb->length;

		if (mb->length > largestFree)
			largestFree = mb->length;
	}

	if (freeBytes < leastFreeBytes)
		leastFreeBytes = freeBytes;

	printf("\n  bytes accounted for = %05d\n", (int)(totalBytes + sizeof(HHEAPSTRUCT)));
	printf("           free bytes = %05d\n", freeBytes);
	printf("           used bytes = %05d\n", usedBytes);
	printf("   largest free block = %05d\n", largestFree);
	printf("least ever free bytes = %05d\n", leastFreeBytes);
}

int heap_check(HEAPHANDLE hHeap)
{
	HHEAP h = (HHEAP)hHeap;
	MEMORYBLOCK mb;
	int cnt;

	mb = heap_get_used_list(hHeap);
	cnt = 0;
	
	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		if (++cnt > h->usedList.length)
		{
			printf("heap is broken - used list counts do not agree\n");
			return -1;
		}
	}

	mb = heap_get_free_list(hHeap);
	cnt = 0;

	while (NULL != (mb = heap_get_next_address(hHeap, mb)))
	{
		if (++cnt > h->freeList.length)
		{
			printf("heap is broken - free list counts do not agree\n");
			return 1;
		}
	}

	return 0;
}
#endif

// Insert the block into the free list sorted by length
inline void heap_insert_into_free_list(HEAPHANDLE hHeap, MEMORYBLOCK mb)
{
	MEMORYBLOCK target = NULL;

	for (target = heap_get_free_list(hHeap);
		NULL != heap_get_next_address(hHeap, target) && heap_get_next_address(hHeap, target)->length < mb->length;
		target = heap_get_next_address(hHeap, target))
	{
	}

	heap_insert_after(hHeap, target, mb);
}

// Calculate the mb's offset in the buffer
inline uint16_t heap_get_offset(HEAPHANDLE hHeap, MEMORYBLOCK mb)
{
	return (uint16_t)((uint8_t *)mb - (uint8_t *)hHeap);
}

// Return the next block
inline MEMORYBLOCK heap_get_next_address(HEAPHANDLE hHead, MEMORYBLOCK mb)
{
	return mb->next != CHAIN_END
		? (MEMORYBLOCK)((uint8_t *)hHead + mb->next) 
		: NULL;
}

// Return the previous block
inline MEMORYBLOCK heap_get_previous_address(HEAPHANDLE hHead, MEMORYBLOCK mb)
{
	return mb->previous != CHAIN_END
		? (MEMORYBLOCK)((uint8_t*)hHead + mb->previous)
		: NULL;
}

// Returns the memory block for the specified address
inline MEMORYBLOCK heap_get_MB(uint8_t *address)
{
	return (MEMORYBLOCK)(address - sizeof(MEMORYBLOCKSTRUCT));
}

// Returns a pointer to the data referenced by the offset
inline uint8_t* heap_get_data(MEMORYBLOCK mb)
{
	return (uint8_t*)((uint8_t*)mb + sizeof(MEMORYBLOCKSTRUCT));
}

// Returns the free list head
inline MEMORYBLOCK heap_get_free_list(HEAPHANDLE hHeap)
{
	return &(((HHEAP)hHeap)->freeList);
}

// Returns the used list head
inline MEMORYBLOCK heap_get_used_list(HEAPHANDLE hHeap)
{
	return &(((HHEAP)hHeap)->usedList);
}

// Insert newItem after target
void heap_insert_after(HEAPHANDLE hHeap, MEMORYBLOCK target, MEMORYBLOCK newItem)
{
#ifdef _DEBUG_HEAP
	heapCheck(hHeap);
#endif
	newItem->next = target->next;
	newItem->previous = heap_get_offset(hHeap, target);
	target->next = heap_get_offset(hHeap, newItem);

	if (newItem->next != CHAIN_END)
		heap_get_next_address(hHeap, newItem)->previous = heap_get_offset(hHeap, newItem);
}

// Remove mb from the list within which it resides
void heap_remove_from_list(HEAPHANDLE hHeap, MEMORYBLOCK mb)
{
	heap_get_previous_address(hHeap, mb)->next = mb->next;

	if (mb->next != CHAIN_END)
		heap_get_next_address(hHeap, mb)->previous = mb->previous;
}

// Returns:
// -1 if first is adjacent and before second
// 1 if second is adjacent and before first
// 0 if they are not adacent to each other
int heap_get_is_adjacent(MEMORYBLOCK first, MEMORYBLOCK second)
{
	if (heap_get_data(first) + first->length == (uint8_t *)second)
		return -1;
	else if (heap_get_data(second) + second->length == (uint8_t*)first)
		return 1;
	else
		return 0;
}
