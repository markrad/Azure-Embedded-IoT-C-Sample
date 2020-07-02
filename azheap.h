#pragma once

#include <azure/core/az_span.h>
#include "heap.h"

az_span az_heap_alloc(HEAPHANDLE h, size_t bytes);
az_span az_heap_adjust(HEAPHANDLE h, az_span target);
void az_heap_free(HEAPHANDLE h, az_span target);
