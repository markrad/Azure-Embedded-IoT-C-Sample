#include "azheap.h"

inline az_span az_heap_alloc(HEAPHANDLE h, size_t bytes)
{
    return az_span_init(heapMalloc(h, bytes), bytes);
}

inline az_span az_heap_adjust(HEAPHANDLE h, az_span target)
{
    return az_span_init(heapRealloc(h, az_span_ptr(target), az_span_size(target)) , az_span_size(target));
}

inline void az_heap_free(HEAPHANDLE h, az_span target)
{
    heapFree(h, az_span_ptr(target));
    target = AZ_SPAN_NULL;
}
