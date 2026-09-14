/* Moonlight libc - assert. */
#pragma once

#include <stdlib.h>

#ifdef NDEBUG
#define assert(e) ((void)0)
#else
#define assert(e) \
    ((e) ? (void)0 : __assert_fail(#e, __FILE__, __LINE__))
#endif
