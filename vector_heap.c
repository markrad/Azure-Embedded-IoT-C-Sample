#include <memory.h>

#include "vector_heap.h"

static const uint16_t growth = 4;

typedef struct _VECTOR
{
    HEAPHANDLE hheap;
    uint16_t all_elements;
    uint16_t current_elements;
    uint16_t element_size;
    uint16_t error;
    uint8_t* elements;
} VECTOR_STRUCT, *VECTOR;

static int vector_size_check(VECTOR vector)
{
    if (0 != vector_check(vector))
    {
        return vector->error;
    }

    if (vector->all_elements == vector->current_elements)
    {
        vector->elements = heapRealloc(vector->hheap, vector->elements, (vector->all_elements + growth) * vector->element_size);

        if (vector->elements == NULL)
        {
            vector->error = -4;
        }
        else
        {
            vector->all_elements += growth;
        }
    }

    return vector->error;
}

VECTORHANDLE vector_create(HEAPHANDLE hheap, uint16_t element_size)
{
    if (element_size == 0)
    {
        return NULL;
    }

    VECTOR vector = heapMalloc(hheap, sizeof(VECTOR_STRUCT));

    if (vector != NULL)
    {
        vector->hheap = hheap;
        vector->all_elements = 0;
        vector->current_elements = 0;
        vector->element_size = element_size;
        vector->error = 0;
        vector->elements = NULL;
    }

    return (VECTORHANDLE)vector;
}

VECTORHANDLE vector_wrap(HEAPHANDLE hheap, void *in, uint16_t element_size, uint16_t count)
{
    if (element_size == 0)
    {
        return NULL;
    }

    VECTOR vector = heapMalloc(hheap, sizeof(VECTOR_STRUCT));

    if (vector != NULL)
    {
        vector->hheap = hheap;
        vector->all_elements = count;
        vector->current_elements = count;
        vector->element_size = element_size;
        vector->error = 0;
        vector->elements = in;
    }

    return (VECTORHANDLE)vector;
}

int vector_append(VECTORHANDLE hvector, void* new_element)
{
    if (hvector == NULL || new_element == NULL)
    {
        return -1;
    }

    VECTOR vector = (VECTOR)hvector;

    vector_size_check(vector);

    if (vector->error == 0)
    {
        memcpy(vector->elements + (vector->current_elements++ * vector->element_size), new_element, vector->element_size);
    }

    return vector->error;
}

void* vector_get(VECTORHANDLE hvector, uint16_t entry)
{
    VECTOR vector = (VECTOR)hvector;

    if (vector == NULL || entry >= vector->current_elements)
    {
        return NULL;
    }

    return vector->elements + (entry * vector->element_size);
}

int vector_push(VECTORHANDLE hvector, void* new_element)
{
    return vector_insert(hvector, new_element, 0);
}

int vector_insert(VECTORHANDLE hvector, void* new_element, uint16_t before)
{
    if (hvector == NULL || new_element == NULL)
    {
        return -1;
    }

    VECTOR vector = (VECTOR)hvector;

    if (before >= vector->current_elements)
    {
        return -1;
    }

    vector_size_check(vector);

    if (vector->error == 0)
    {
        for (int i = vector->current_elements; i > before; i--)
        {
            memcpy(vector->elements + (vector->element_size * i), vector->elements + (vector->element_size * (i - 1)), vector->element_size);
        }

        memcpy(vector->elements + (vector->element_size * before), new_element, vector->element_size);
        vector->current_elements++;
    }

    return vector->error;
}

int vector_pop(VECTORHANDLE hvector, void* out)
{
    return vector_remove(hvector, 0, out);
}

int vector_remove(VECTORHANDLE hvector, uint16_t entry, void* out)
{
    if (hvector == NULL || out == NULL)
    {
        return -1;
    }

    VECTOR vector = (VECTOR)hvector;

    if (entry >= vector->current_elements)
    {
        return -2;
    }

    if (vector->error == 0)
    {
        if (out != NULL)
        {
            memcpy(out, vector->elements + (entry * vector->element_size), vector->element_size);
        }

        vector->current_elements--;

        for (int i = entry; i < vector->current_elements; i++)
        {
            memcpy(vector->elements + (i * vector->element_size), vector->elements + ((i + 1) * vector->element_size), vector->element_size);
        }
    }

    return vector->error;
}

void* vector_get_buffer(VECTORHANDLE hvector)
{
    return ((VECTOR)hvector)->elements;
}

int vector_destroy(VECTORHANDLE hvector, bool keep_buffer)
{
    if (hvector == NULL)
    {
        return -1;
    }

    VECTOR vector = (VECTOR)hvector;

    if (keep_buffer == false)
    {
        heapFree(vector->hheap, vector->elements);
    }

    heapFree(vector->hheap, vector);

    return 0;
}

int vector_check(VECTORHANDLE hvector)
{
    return ((VECTOR)hvector)->error;
}

int vector_get_count(VECTORHANDLE hvector)
{
    return ((VECTOR)hvector)->current_elements;
}
