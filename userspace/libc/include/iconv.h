/* Moonlight libc - iconv (POSIX, UTF subset).
 * Real conversion engine: UTF-8 <-> UTF-16LE/BE, UTF-32LE/BE,
 * ISO-8859-1 (Latin1), US-ASCII. Strict: overlongs, surrogates and
 * >U+10FFFF are EILSEQ; truncated input is EINVAL; undersized output
 * is E2BIG. No stubs. */
#pragma once

#include <stddef.h>

typedef void *iconv_t;

iconv_t iconv_open(const char *to, const char *from);
size_t iconv(iconv_t cd, char **inbuf, size_t *inleft, char **outbuf,
             size_t *outleft);
int iconv_close(iconv_t cd);
