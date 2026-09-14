/* Moonlight libc - stddef (freestanding C11, LP64).
 *
 * Self-contained: works on the rv64 target (clang) and on the host
 * (gcc) unit tests. Uses compiler built-in types where available so
 * size_t/ptrdiff_t/wchar_t always match the ABI. */
#pragma once

typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __WCHAR_TYPE__ wchar_t;

#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void *)0)
#endif
#endif

#define offsetof(t, m) __builtin_offsetof(t, m)

typedef struct {
    long long __ml_align;
    char __ml_c[];
} max_align_t;
