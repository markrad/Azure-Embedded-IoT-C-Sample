#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "heap.h"

typedef void* VECTORHANDLE;

// Create a new vector on the private heap
VECTORHANDLE vector_create(HEAPHANDLE hheap, uint16_t element_size);

// Wraps an existing buffer
VECTORHANDLE vector_wrap(HEAPHANDLE hheap, void *in, uint16_t element_size, uint16_t count);

// Append a new entry to the end of the vector
int vector_append(VECTORHANDLE hvector, void* new_element);

// Push a new entry to the front of the vector
int vector_push(VECTORHANDLE hvector, void* new_element);

// Insert a new element before entry indicated by before
int vector_insert(VECTORHANDLE hvector, void* new_element, uint16_t before);

// Pop the first entry of the front optionally copying to out if not NULL
int vector_pop(VECTORHANDLE hvector, void *out);

// Remove the entry indicated by entry optionally copying to out if not NULL
int vector_remove(VECTORHANDLE hvector, uint16_t entry, void *out);

// Returns the entry indiated bentry
void* vector_get(VECTORHANDLE hvector, uint16_t entry);

void* vector_get_buffer(VECTORHANDLE hvector);

// Destroys the vector freeing the control block and optionally the buffer too
int vector_destroy(VECTORHANDLE hvector, bool keep_buffer);

// Checks for any errors that may have been encountered - typically memory errors
int vector_check(VECTORHANDLE hvector);

// Returns the current number of elements in the vector
int vector_get_count(VECTORHANDLE hvector);
