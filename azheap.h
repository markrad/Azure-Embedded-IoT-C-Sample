#pragma once

#include <azure/core/az_span.h>
#include "heap.h"

// Allocate an az_span from the private heap for size bytes
az_span az_heap_alloc(HEAPHANDLE h, size_t bytes);

// Reallocate on the private heap the az_span target to its actual length
az_span az_heap_adjust(HEAPHANDLE h, az_span target);

// Free an az_span from the private heap
void az_heap_free(HEAPHANDLE h, az_span target);
