/* Moonlight libc - uchar (C11, UTF-8/UTF-16 transcoding).
 * Implemented in src/wchar.c alongside the UTF-8 codec. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;

size_t mbrtoc16(char16_t *pc16, const char *s, size_t n, mbstate_t *ps);
size_t c16rtomb(char *s, char16_t c16, mbstate_t *ps);
size_t mbrtoc32(char32_t *pc32, const char *s, size_t n, mbstate_t *ps);
size_t c32rtomb(char *s, char32_t c32, mbstate_t *ps);
