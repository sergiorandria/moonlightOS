/* Moonlight libc - wordexp (tilde + quote + field splitting;
 * command substitution is rejected, like a non-exec shell). */
#pragma once

#include <stddef.h>

typedef struct {
    size_t we_wordc;
    char **we_wordv;
    size_t we_offs;
} wordexp_t;

#define WRDE_APPEND 1
#define WRDE_DOOFFS 2
#define WRDE_SHOWERR 4
#define WRDE_REUSE 8
#define WRDE_NOCMD 16
#define WRDE_UNDEF 32
#define WRDE_NOSPACE 1
#define WRDE_BADCHAR 2
#define WRDE_BADVAL 3
#define WRDE_CMDSUB 4
#define WRDE_SYNTAX 5

int wordexp(const char *s, wordexp_t *w, int flags);
void wordfree(wordexp_t *w);
