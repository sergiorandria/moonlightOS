/* Moonlight libc - fnmatch. */
#pragma once

#define FNM_NOESCAPE 1
#define FNM_PATHNAME 2
#define FNM_PERIOD 4
#define FNM_NOCASE 16
#define FNM_CASEFOLD FNM_NOCASE
#define FNM_LEADING_DIR 8
#define FNM_EXTMATCH 32
#define FNM_MATCH 0
#define FNM_NOMATCH 1

int fnmatch(const char *pat, const char *s, int flags);
