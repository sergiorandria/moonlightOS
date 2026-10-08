/* Moonlight libc - stdarg (freestanding, compiler built-ins).
 * Wraps __builtin_va_list so both clang (rv64 target) and gcc (host
 * tests) get a working va_list. Compatible with system headers. */
#pragma once

typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dst, src) __builtin_va_copy(dst, src)
