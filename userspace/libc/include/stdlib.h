/* Moonlight libc - stdlib. */
#pragma once

#include <stddef.h>

void abort(void) __attribute__((noreturn));
void exit(int code) __attribute__((noreturn));
void _Exit(int code) __attribute__((noreturn));
void quick_exit(int code) __attribute__((noreturn));
int atexit(void (*fn)(void));
int at_quick_exit(void (*fn)(void));

int atoi(const char *s);
long atol(const char *s);
long long atoll(const char *s);
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
long long strtoll(const char *s, char **end, int base);
unsigned long long strtoull(const char *s, char **end, int base);
double strtod(const char *s, char **end);
float strtof(const char *s, char **end);
long double strtold(const char *s, char **end);

void *malloc(size_t n);
void *calloc(size_t n, size_t sz);
void *realloc(void *p, size_t n);
void *reallocarray(void *p, size_t n, size_t sz);
void *aligned_alloc(size_t align, size_t n);
int posix_memalign(void **pp, size_t align, size_t n);
void free(void *p);
int system(const char *cmd);

int abs(int x);
long labs(long x);
long long llabs(long long x);
typedef struct {
    int quot;
    int rem;
} div_t;
typedef struct {
    long quot;
    long rem;
} ldiv_t;
typedef struct {
    long long quot;
    long long rem;
} lldiv_t;
div_t div(int n, int d);
ldiv_t ldiv(long n, long d);
lldiv_t lldiv(long long n, long long d);
int rand(void);
void srand(unsigned seed);
long random(void);
void srandom(unsigned seed);
char *initstate(unsigned seed, char *state, size_t n);
char *setstate(char *state);
void qsort(void *base, size_t n, size_t sz,
           int (*cmp)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t n, size_t sz,
              int (*cmp)(const void *, const void *));

extern char **environ;
char *getenv(const char *name);
int setenv(const char *name, const char *val, int overwrite);
int unsetenv(const char *name);
int putenv(char *s);
int clearenv(void);
/* Multibyte (C89; UTF-8, implemented in wchar.c). */
int mblen(const char *s, size_t n);
int mbtowc(wchar_t *pwc, const char *s, size_t n);
int wctomb(char *s, wchar_t wc);
size_t mbstowcs(wchar_t *dst, const char *src, size_t n);
size_t wcstombs(char *dst, const wchar_t *src, size_t n);
int mkstemp(char *t);
int mkstemps(char *t, int suffixlen);
int mkostemp(char *t, int flags);
int mkostemps(char *t, int suffixlen, int flags);
char *mkdtemp(char *t);
char *mktemp(char *t);
void qsort_r(void *base, size_t n, size_t sz,
             int (*cmp)(const void *, const void *, void *), void *arg);
int getsubopt(char **optionp, char *const *tokens, char **valuep);
char *l64a(long v);
long a64l(const char *s);
double drand48(void);
double erand48(unsigned short x[3]);
long lrand48(void);
long nrand48(unsigned short x[3]);
long mrand48(void);
long jrand48(unsigned short x[3]);
void srand48(long seed);
unsigned short *seed48(unsigned short seed[3]);
void lcong48(unsigned short param[7]);
char *realpath(const char *path, char *out);
unsigned arc4random(void);
void arc4random_buf(void *buf, size_t n);
unsigned arc4random_uniform(unsigned bound);
long random(void);
void __assert_fail(const char *expr, const char *file, int line)
    __attribute__((noreturn));

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 32767
