/* Moonlight libc - malloc.h (allocator introspection over the
 * K&R arena in src/stdlib.c). */
#pragma once

#include <stddef.h>

struct mallinfo {
    int arena;
    int ordblks;
    int smblks;
    int hblks;
    int hblkhd;
    int usmblks;
    int fsmblks;
    int uordblks;
    int fordblks;
    int keepcost;
};

#define M_MXFAST 1
#define M_TRIM_THRESHOLD -1
#define M_TOP_PAD -2
#define M_MMAP_THRESHOLD -3
#define M_MMAP_MAX -4
#define M_CHECK_ACTION -5
#define M_PERTURB -6
#define M_ARENA_TEST -7
#define M_ARENA_MAX -8

struct mallinfo mallinfo(void);
int mallopt(int param, int value);
int malloc_trim(size_t pad);
size_t malloc_usable_size(void *p);
void malloc_stats(void);
