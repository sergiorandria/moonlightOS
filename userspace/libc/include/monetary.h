/* Moonlight libc - monetary (C99 strfmon).
 * Real implementation over localeconv: formats monetary values with
 * currency symbol, sign placement, grouping and field width/fill.
 * No stubs. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

ssize_t strfmon(char *s, size_t n, const char *fmt, ...);
