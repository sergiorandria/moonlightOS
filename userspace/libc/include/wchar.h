/* Moonlight libc - wchar (C99, UTF-8 only, no locale switching).
 *
 * wchar_t is 32-bit (clang __WCHAR_TYPE__); multibyte encodings are
 * strict UTF-8: overlongs, surrogates and >U+10FFFF are EILSEQ, never
 * silently accepted. mbstate_t carries a partial sequence across calls
 * plus a pending UTF-16 surrogate for mbrtoc16/c16rtomb (see uchar.h).
 * Everything declared here is implemented in src/wchar.c.
 */
#pragma once

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef __ML_WINT_T_DEFINED
#define __ML_WINT_T_DEFINED
typedef int wint_t;
#endif

#ifndef WEOF
#define WEOF ((wint_t)-1)
#endif

typedef struct {
    unsigned ch;    /* accumulated value bits of a partial sequence */
    unsigned need;  /* continuation bytes still missing */
    unsigned total; /* expected sequence length (overlong floor check) */
    unsigned surv;  /* pending UTF-16 high surrogate (mbrtoc16/c16rtomb) */
} mbstate_t;

int mbsinit(const mbstate_t *ps);
size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);
size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps);
size_t mbsrtowcs(wchar_t *dst, const char **src, size_t n, mbstate_t *ps);
size_t wcsrtombs(char *dst, const wchar_t **src, size_t n, mbstate_t *ps);

/* wide string (wmem* included; all real). */
size_t wcslen(const wchar_t *s);
size_t wcsnlen(const wchar_t *s, size_t n);
wchar_t *wcscpy(wchar_t *d, const wchar_t *s);
wchar_t *wcsncpy(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wcscat(wchar_t *d, const wchar_t *s);
wchar_t *wcsncat(wchar_t *d, const wchar_t *s, size_t n);
int wcscmp(const wchar_t *a, const wchar_t *b);
int wcsncmp(const wchar_t *a, const wchar_t *b, size_t n);
int wcscoll(const wchar_t *a, const wchar_t *b);
size_t wcsxfrm(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wcschr(const wchar_t *s, wchar_t c);
wchar_t *wcsrchr(const wchar_t *s, wchar_t c);
wchar_t *wcsstr(const wchar_t *h, const wchar_t *n);
wchar_t *wcspbrk(const wchar_t *s, const wchar_t *acc);
size_t wcsspn(const wchar_t *s, const wchar_t *acc);
size_t wcscspn(const wchar_t *s, const wchar_t *rej);
wchar_t *wcstok(wchar_t *s, const wchar_t *delim, wchar_t **save);
wchar_t *wcsdup(const wchar_t *s);
wchar_t *wmemcpy(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wmemmove(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n);
int wmemcmp(const wchar_t *a, const wchar_t *b, size_t n);
wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n);

/* number conversion (wide in, via exact narrow conversion). */
long wcstol(const wchar_t *s, wchar_t **end, int base);
unsigned long wcstoul(const wchar_t *s, wchar_t **end, int base);
long long wcstoll(const wchar_t *s, wchar_t **end, int base);
unsigned long long wcstoull(const wchar_t *s, wchar_t **end, int base);
double wcstod(const wchar_t *s, wchar_t **end);
float wcstof(const wchar_t *s, wchar_t **end);
long double wcstold(const wchar_t *s, wchar_t **end);
intmax_t wcstoimax(const wchar_t *s, wchar_t **end, int base);
uintmax_t wcstoumax(const wchar_t *s, wchar_t **end, int base);

/* single-byte compat. */
wint_t btowc(int c);
int wctob(wint_t c);

/* wide stdio (implemented over the narrow engine + FILE byte layer). */
int fwide(FILE *f, int mode);
wint_t fgetwc(FILE *f);
wchar_t *fgetws(wchar_t *s, int n, FILE *f);
wint_t getwchar(void);
wint_t getwc(FILE *f);
wint_t fputwc(wchar_t c, FILE *f);
int fputws(const wchar_t *s, FILE *f);
wint_t putwchar(wchar_t c);
wint_t putwc(wchar_t c, FILE *f);
wint_t ungetwc(wint_t c, FILE *f);
int fwprintf(FILE *f, const wchar_t *fmt, ...);
int vfwprintf(FILE *f, const wchar_t *fmt, va_list ap);
int wprintf(const wchar_t *fmt, ...);
int vwprintf(const wchar_t *fmt, va_list ap);
int swprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...);
int vswprintf(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap);

/* restartable bounded conversion, width, case, wide strftime. */
size_t mbsnrtowcs(wchar_t *dst, const char **src, size_t nmc, size_t n,
                  mbstate_t *ps);
size_t wcsnrtombs(char *dst, const wchar_t **src, size_t nwc, size_t n,
                  mbstate_t *ps);
int wcwidth(wchar_t c);
int wcswidth(const wchar_t *s, size_t n);
int wcscasecmp(const wchar_t *a, const wchar_t *b);
int wcsncasecmp(const wchar_t *a, const wchar_t *b, size_t n);
size_t wcsftime(wchar_t *s, size_t n, const wchar_t *fmt,
                const struct tm *tm);
FILE *open_wmemstream(wchar_t **ptr, size_t *len);
