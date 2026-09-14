/* Moonlight libc - execinfo.h (stack backtraces via frame
 * chain + dladdr; implemented in src/execinfo.c). */
#pragma once

#include <stddef.h>

int backtrace(void **buffer, int size);
char **backtrace_symbols(void *const *buffer, int size);
void backtrace_symbols_fd(void *const *buffer, int size, int fd);
