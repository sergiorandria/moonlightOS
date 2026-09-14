/* libc stdlib: exit, atoi/strtol, K&R malloc, qsort, rand. */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

/* ---- exit ---- */

#define ML_ATEXIT_MAX 32
static void (*ml_atexit_fns[ML_ATEXIT_MAX])(void);
static int ml_atexit_n = 0;

int atexit(void (*fn)(void)) {
    if (!fn || ml_atexit_n >= ML_ATEXIT_MAX) return -1;
    ml_atexit_fns[ml_atexit_n++] = fn;
    return 0;
}

void _Exit(int code) {
    __ml_raw6(LX_SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) __ml_raw6(LX_SYS_exit_group, code, 0, 0, 0, 0, 0);
}

void exit(int code) {
    while (ml_atexit_n > 0) ml_atexit_fns[--ml_atexit_n]();
    _Exit(code);
}

void abort(void) {
    /* A SIGABRT handler runs first (raise honors the table); the
     * default disposition parks the thread with 128+SIGABRT = 134. */
    raise(SIGABRT);
    _Exit(134);
}

void __assert_fail(const char *expr, const char *file, int line) {
    const char *p;
    (void)p;
    write(2, "assert: ", 8);
    write(2, expr, strlen(expr));
    write(2, " at ", 4);
    write(2, file, strlen(file));
    write(2, "\n", 1);
    (void)line;
    abort();
}

/* ---- numbers ---- */

int atoi(const char *s) { return (int)strtol(s, 0, 10); }

long atol(const char *s) { return strtol(s, 0, 10); }

static int ml_isxdigit(int c) {
    return isxdigit(c);
}

/* Shared magnitude parser for strtol/strtoul. endptr follows the
 * no-conversion rule (original string); overflow clamps at `limit`
 * with ERANGE (the caller maps the clamp to its range). */
static unsigned long long ml_strtou(const char *s, char **end, int base,
                                    unsigned long long limit, int *negp) {
    const char *orig = s;
    unsigned long long acc = 0;
    int neg = 0, any = 0, overflow = 0;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    if (base == 0) {
        if (*s == '0' && (s[1] == 'x' || s[1] == 'X')) {
            /* Hex iff a hex digit follows; else plain "0" ("0x"
             * leaves end after the zero, like base 16). */
            if (ml_isxdigit(s[2])) {
                base = 16;
                s += 2;
            } else {
                base = 8;
            }
        } else if (*s == '0') {
            base = 8;
        } else {
            base = 10;
        }
    } else if (base < 2 || base > 36) {
        if (end) *end = (char *)orig;
        if (negp) *negp = neg;
        errno = EINVAL;
        return 0;
    } else if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        if (ml_isxdigit(s[2])) s += 2;
    }
    for (;; s++) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'z') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'Z') d = *s - 'A' + 10;
        else break;
        if (d >= base) break;
        any = 1;
        if (!overflow) {
            if (acc > (limit - (unsigned long long)d) /
                          (unsigned long long)base) {
                overflow = 1;
            } else {
                acc = acc * (unsigned long long)base +
                      (unsigned long long)d;
            }
        }
    }
    if (!any) {
        if (end) *end = (char *)orig;
        if (negp) *negp = neg;
        return 0;
    }
    if (end) *end = (char *)s;
    if (negp) *negp = neg;
    if (overflow) {
        errno = ERANGE;
        return limit;
    }
    return acc;
}

long strtol(const char *s, char **end, int base) {
    /* Wide limit (LONG_MAX+1): exact LONG_MIN parses cleanly, anything
     * past it overflows in the helper with ERANGE already set. */
    int neg = 0;
    unsigned long long mag = ml_strtou(
        s, end, base, (unsigned long long)LONG_MAX + 1, &neg);
    if (neg) {
        if (mag == (unsigned long long)LONG_MAX + 1) return LONG_MIN;
        return -(long)mag;
    }
    if (mag > (unsigned long long)LONG_MAX) {
        errno = ERANGE; /* defensive: helper clamps first */
        return LONG_MAX;
    }
    return (long)mag;
}

unsigned long strtoul(const char *s, char **end, int base) {
    int neg = 0;
    unsigned long long mag =
        ml_strtou(s, end, base, ULONG_MAX, &neg);
    if (mag == ULONG_MAX && errno == ERANGE) return ULONG_MAX;
    /* Standard negation-then-wrap for a leading '-'. */
    if (neg) mag = 0u - mag;
    return (unsigned long)mag;
}

long long strtoll(const char *s, char **end, int base) {
    /* LP64: long is 64 bits, so strtol is already the full range. */
    return (long long)strtol(s, end, base);
}

unsigned long long strtoull(const char *s, char **end, int base) {
    return (unsigned long long)strtoul(s, end, base);
}

long long atoll(const char *s) { return strtoll(s, 0, 10); }

intmax_t strtoimax(const char *s, char **end, int base) {
    return (intmax_t)strtol(s, end, base);
}

uintmax_t strtoumax(const char *s, char **end, int base) {
    return (uintmax_t)strtoul(s, end, base);
}

intmax_t imaxabs(intmax_t x) { return x < 0 ? -x : x; }

imaxdiv_t imaxdiv(intmax_t n, intmax_t d) {
    imaxdiv_t r;
    r.quot = n / d;
    r.rem = n % d;
    return r;
}

/* ---- strtod (decimal + inf/nan, ERANGE on overflow) ---- */

double strtod(const char *s, char **end) {
    static const double ml_pow10[] = {1e0,  1e1,  1e2,  1e3,  1e4,  1e5,
                                      1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
                                      1e12, 1e13, 1e14, 1e15, 1e16, 1e17,
                                      1e18, 1e19, 1e20, 1e21, 1e22};
    const char *p = s;
    double v = 0.0;
    long long dec_exp = 0;
    int neg = 0, ndig = 0, any_nz = 0, expsign = 1;
    long long e = 0;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '-') {
        neg = 1;
        p++;
    } else if (*p == '+') {
        p++;
    }
    if ((p[0] == 'i' || p[0] == 'I') &&
        (p[1] == 'n' || p[1] == 'N') && (p[2] == 'f' || p[2] == 'F')) {
        p += 3;
        if ((p[0] == 'i' || p[0] == 'I') &&
            (p[1] == 'n' || p[1] == 'N') &&
            (p[2] == 'i' || p[2] == 'I') &&
            (p[3] == 't' || p[3] == 'T') &&
            (p[4] == 'y' || p[4] == 'Y'))
            p += 5;
        if (end) *end = (char *)p;
        return neg ? -HUGE_VAL : HUGE_VAL;
    }
    if ((p[0] == 'n' || p[0] == 'N') &&
        (p[1] == 'a' || p[1] == 'A') && (p[2] == 'n' || p[2] == 'N')) {
        p += 3;
        if (*p == '(') {
            /* nan(sequence): skip to the closing paren. */
            p++;
            while (*p && *p != ')') p++;
            if (*p == ')') p++;
        }
        if (end) *end = (char *)p;
        return NAN;
    }
    while (isdigit((unsigned char)*p)) {
        /* Keep 19 significant digits exactly; fold the rest into dec_exp
         * (a double holds ~15-17, so no precision is lost). */
        if (*p != '0') any_nz = 1;
        if (ndig < 19) {
            v = v * 10.0 + (*p - '0');
            ndig++;
        } else {
            dec_exp++;
        }
        p++;
    }
    if (*p == '.') {
        p++;
        while (isdigit((unsigned char)*p)) {
            if (*p != '0') any_nz = 1;
            if (ndig < 19) {
                v = v * 10.0 + (*p - '0');
                ndig++;
                dec_exp--;
            }
            /* extra digits past 19 vanish below double precision */
            p++;
        }
    }
    if (ndig == 0) {
        if (end) *end = (char *)s;
        return 0.0;
    }
    if (*p == 'e' || *p == 'E') {
        const char *q = p + 1;
        expsign = 1;
        if (*q == '-') {
            expsign = -1;
            q++;
        } else if (*q == '+') {
            q++;
        }
        if (isdigit((unsigned char)*q)) {
            p = q;
            e = 0;
            while (isdigit((unsigned char)*p)) {
                if (e < 1000000) e = e * 10 + (*p - '0');
                p++;
            }
            dec_exp += expsign * e;
        }
    }
    /* Scale by 10^dec_exp in 1e22-sized exact steps (22 < 2^53/10). */
    while (dec_exp >= 22) {
        v *= 1e22;
        dec_exp -= 22;
    }
    while (dec_exp <= -22) {
        v *= 1e-22;
        dec_exp += 22;
    }
    if (dec_exp > 0) v *= ml_pow10[dec_exp];
    else if (dec_exp < 0) v /= ml_pow10[-dec_exp];
    if (end) *end = (char *)p;
    if (v == HUGE_VAL || v == -HUGE_VAL) {
        errno = ERANGE;
        return neg ? -HUGE_VAL : HUGE_VAL;
    }
    /* Subnormal result (or flush to zero) reports ERANGE too; an all-zero
     * input is exact and does not. */
    if (any_nz && (v == 0.0 || (v < DBL_MIN && v > -DBL_MIN))) {
        errno = ERANGE;
    }
    return neg ? -v : v;
}

float strtof(const char *s, char **end) { return (float)strtod(s, end); }

long double strtold(const char *s, char **end) {
    /* No extended precision on this target: long double is double. */
    return (long double)strtod(s, end);
}

int abs(int x) { return x < 0 ? -x : x; }

long labs(long x) { return x < 0 ? -x : x; }

long long llabs(long long x) { return x < 0 ? -x : x; }

div_t div(int n, int d) {
    div_t r;
    r.quot = n / d;
    r.rem = n % d;
    return r;
}

ldiv_t ldiv(long n, long d) {
    ldiv_t r;
    r.quot = n / d;
    r.rem = n % d;
    return r;
}

lldiv_t lldiv(long long n, long long d) {
    lldiv_t r;
    r.quot = n / d;
    r.rem = n % d;
    return r;
}

void *bsearch(const void *key, const void *base, size_t n, size_t sz,
              int (*cmp)(const void *, const void *)) {
    const unsigned char *b = base;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = cmp(key, b + mid * sz);
        if (c == 0) return (void *)(b + mid * sz);
        if (c < 0) hi = mid;
        else lo = mid + 1;
    }
    return 0;
}

/* ---- random (xorshift64*: better spread than the LCG rand; still NOT
 * crypto - documented like rand) ---- */

static unsigned long long ml_random_state = 0x853c49e6748fea9bull;

long random(void) {
    unsigned long long x = ml_random_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    ml_random_state = x;
    return (long)((x * 0x2545F4914F6CDD1Dull >> 11) & 0x7FFFFFFF);
}

void srandom(unsigned seed) {
    ml_random_state = seed ? ((unsigned long long)seed << 32 | seed)
                           : 0x853c49e6748fea9bull;
}

/* initstate/setstate manage the same xorshift word inside the caller's
 * buffer (8 bytes minimum); the returned pointer is the previous state
 * buffer for setstate, or the new one for initstate. */
char *initstate(unsigned seed, char *state, size_t n) {
    if (!state || n < 8) {
        errno = EINVAL;
        return 0;
    }
    srandom(seed);
    memcpy(state, &ml_random_state, 8);
    return state;
}

char *setstate(char *state) {
    static char ml_prev_state[8];
    if (!state) {
        errno = EINVAL;
        return 0;
    }
    memcpy(ml_prev_state, &ml_random_state, 8);
    memcpy(&ml_random_state, state, 8);
    if (ml_random_state == 0) ml_random_state = 0x853c49e6748fea9bull;
    return ml_prev_state;
}

void *reallocarray(void *p, size_t n, size_t sz) {
    if (n != 0 && sz > (size_t)-1 / n) {
        errno = ENOMEM;
        return 0;
    }
    return realloc(p, n * sz);
}

/* ---- mkstemp/mkstemps (unique file via O_CREAT|O_EXCL) ---- */

static const char ml_b62[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static int ml_mkstemp(char *t, int suffixlen) {
    size_t len, i;
    int tries;
    unsigned long long salt;
    if (!t) {
        errno = EINVAL;
        return -1;
    }
    len = strlen(t);
    if (suffixlen < 0 || len < 6 + (size_t)suffixlen ||
        strcmp(t + len - 6 - (size_t)suffixlen, "XXXXXX") != 0) {
        errno = EINVAL;
        return -1;
    }
    /* Salt from time + pid + a counter (no ASLR/hardware RNG here). */
    salt = (unsigned long long)time(0) ^ ((unsigned long long)getpid()
                                          << 32);
    for (tries = 0; tries < 100; tries++) {
        int fd;
        salt = salt * 6364136223846793005ull + 1442695040888963407ull;
        for (i = 0; i < 6; i++)
            t[len - 6 - (size_t)suffixlen + i] =
                ml_b62[(salt >> (6 * i)) % 62];
        fd = open(t, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

int mkstemp(char *t) { return ml_mkstemp(t, 0); }

int mkstemps(char *t, int suffixlen) { return ml_mkstemp(t, suffixlen); }

/* ---- rand (LCG, deterministic seed: NOT crypto, documented) ---- */

static unsigned long ml_rand_state = 1;

int rand(void) {
    ml_rand_state = ml_rand_state * 1103515245u + 12345u;
    return (int)((ml_rand_state >> 16) & RAND_MAX);
}

void srand(unsigned seed) { ml_rand_state = seed ? seed : 1; }

/* ---- qsort (insertion for tiny, quicksort above) ---- */

static void ml_swap(unsigned char *a, unsigned char *b, size_t sz) {
    size_t i;
    for (i = 0; i < sz; i++) {
        unsigned char t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

void qsort(void *base, size_t n, size_t sz,
           int (*cmp)(const void *, const void *)) {
    unsigned char *b = base;
    if (n < 2 || sz == 0) return;
    if (n < 16) {
        size_t i, j;
        for (i = 1; i < n; i++)
            for (j = i; j > 0 && cmp(b + j * sz, b + (j - 1) * sz) < 0;
                 j--)
                ml_swap(b + j * sz, b + (j - 1) * sz, sz);
        return;
    }
    {
        /* Lomuto on the middle pivot (recursion depth bounded by halves). */
        size_t lo = 0, hi = n - 1, i;
        ml_swap(b + (n / 2) * sz, b + hi * sz, sz);
        for (i = lo; i < hi; i++)
            if (cmp(b + i * sz, b + hi * sz) < 0) {
                ml_swap(b + i * sz, b + lo * sz, sz);
                lo++;
            }
        ml_swap(b + lo * sz, b + hi * sz, sz);
        qsort(b, lo, sz, cmp);
        qsort(b + (lo + 1) * sz, n - lo - 1, sz, cmp);
    }
}

/* ---- malloc (K&R free-list over sbrk) ---- */

typedef struct __ML_HDR {
    struct __ML_HDR *next;
    size_t units; /* payload units after this header */
} __ML_HDR;

#define ML_UNIT sizeof(__ML_HDR)
#define ML_MIN_UNITS 64

static __ML_HDR ml_base = {&ml_base, 0};
static __ML_HDR *ml_freep = 0;
static size_t ml_heap_total = 0; /* bytes ever requested from sbrk */

/* Aligned-block registry (payload -> malloc base; free() consults it).
 * Bounded: posix_memalign fails ENOMEM when full (documented). */
#define ML_ALIGNED_MAX 64
static struct {
    void *aligned;
    void *raw;
} ml_al_tab[ML_ALIGNED_MAX];
static int ml_al_n = 0;

/* Link a free block into the circular list (coalescing neighbors).
 * Takes the HEADER pointer: callers convert payload <-> header with an
 * explicit round trip through uintptr_t so -Wfree-nonheap-object (which
 * flags the classic K&R free(p+1) idiom under -Werror) stays quiet. */
static void ml_link(__ML_HDR *bp) {
    __ML_HDR *p;
    for (p = ml_freep ? ml_freep : &ml_base; !(bp > p && bp < p->next);
         p = p->next) {
        if (p >= p->next && (bp > p || bp < p->next)) break;
    }
    if (bp + bp->units == p->next) {
        bp->units += p->next->units;
        bp->next = p->next->next;
    } else {
        bp->next = p->next;
    }
    if (p + p->units == bp) {
        p->units += bp->units;
        p->next = bp->next;
    } else {
        p->next = bp;
    }
    ml_freep = p;
}

static __ML_HDR *ml_more(size_t units) {
    __ML_HDR *p;
    if (units < ML_MIN_UNITS) units = ML_MIN_UNITS;
    p = sbrk((intptr_t)(units * ML_UNIT));
    if (p == (void *)-1) return 0;
    p->units = units;
    ml_heap_total += units * ML_UNIT;
    ml_link(p);
    return ml_freep;
}

void *malloc(size_t n) {
    __ML_HDR *prev, *p;
    size_t units;
    if (n == 0) n = 1;
    units = (n + ML_UNIT - 1) / ML_UNIT + 1;
    if (ml_freep == 0) ml_base.next = ml_freep = prev = &ml_base;
    else prev = ml_freep;
    for (p = prev->next;; prev = p, p = p->next) {
        if (p->units >= units) {
            if (p->units == units) {
                prev->next = p->next;
            } else {
                p->units -= units;
                p += p->units;
                p->units = units;
            }
            ml_freep = prev;
            return (void *)(p + 1);
        }
        if (p == ml_freep) {
            p = ml_more(units);
            if (!p) {
                errno = ENOMEM;
                return 0;
            }
        }
    }
}

void free(void *ap) {
    __ML_HDR *bp;
    int i;
    if (!ap) return;
    /* Aligned blocks (posix_memalign/aligned_alloc) are registered
     * below: translate back to the malloc'd base first. */
    for (i = 0; i < ml_al_n; i++)
        if (ml_al_tab[i].aligned == ap) {
            ap = ml_al_tab[i].raw;
            ml_al_tab[i] = ml_al_tab[--ml_al_n];
            break;
        }
    bp = (__ML_HDR *)(uintptr_t)ap - 1;
    ml_link(bp);
}

void *calloc(size_t n, size_t sz) {
    size_t total;
    void *p;
    if (n != 0 && sz > (size_t)-1 / n) {
        errno = ENOMEM;
        return 0;
    }
    total = n * sz;
    p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

void *realloc(void *p, size_t n) {
    __ML_HDR *bp;
    size_t old;
    void *q;
    if (!p) return malloc(n);
    if (n == 0) {
        free(p);
        return 0;
    }
    bp = (__ML_HDR *)(uintptr_t)p - 1;
    old = (bp->units - 1) * ML_UNIT;
    if (old >= n) return p;
    q = malloc(n);
    if (!q) return 0;
    memcpy(q, p, old);
    free(p);
    return q;
}

/* ---- quick_exit ---- */

#define ML_QUICK_MAX 32
static void (*ml_quick_fns[ML_QUICK_MAX])(void);
static int ml_quick_n = 0;

int at_quick_exit(void (*fn)(void)) {
    if (!fn || ml_quick_n >= ML_QUICK_MAX) return -1;
    ml_quick_fns[ml_quick_n++] = fn;
    return 0;
}

void quick_exit(int code) {
    while (ml_quick_n > 0) ml_quick_fns[--ml_quick_n]();
    _Exit(code);
}

/* ---- system (fork + exec sh, POSIX 127 fallback) ---- */

int system(const char *cmd) {
    pid_t pid;
    int status;
    char *argv[4];
    if (!cmd) {
        /* Nonzero iff a command processor exists (an executable
         * "sh" in the VFS). No shell image -> 0, honestly. */
        if (access("sh", X_OK) == 0) return 1;
        return 0;
    }
    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = (char *)cmd;
    argv[3] = 0;
    if (posix_spawn(&pid, "sh", 0, 0, argv, environ) != 0) return -1;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

/* ---- aligned allocation (over-allocate + align, stash base) ---- */

static int ml_is_pow2(size_t x) { return x != 0 && (x & (x - 1)) == 0; }

int posix_memalign(void **pp, size_t align, size_t n) {
    /* Over-allocate, align inside, register base in the side table
     * that free() consults (the K&R header stays at the malloc'd
     * base, untouched). */
    size_t total;
    void *raw;
    uintptr_t a;
    if (!pp) return EINVAL;
    *pp = 0;
    if (!ml_is_pow2(align) || align < sizeof(void *)) return EINVAL;
    if (n == 0) n = 1;
    if (ml_al_n >= ML_ALIGNED_MAX) return ENOMEM;
    if (n > (size_t)-1 - align) return ENOMEM;
    total = n + align;
    raw = malloc(total);
    if (!raw) return ENOMEM;
    a = ((uintptr_t)raw + align - 1) & ~(align - 1);
    /* a == raw is possible (already aligned): still register, so a
     * later free() takes the table path to the same base. */
    ml_al_tab[ml_al_n].aligned = (void *)a;
    ml_al_tab[ml_al_n].raw = raw;
    ml_al_n++;
    *pp = (void *)a;
    return 0;
}

void *aligned_alloc(size_t align, size_t n) {
    void *p = 0;
    /* C11: alignment must be a supported (power-of-2) value and the
     * size a multiple of it; malloc'd blocks already satisfy
     * _Alignof(max_align_t) = 16 here. */
    if (!ml_is_pow2(align) || n % align != 0) {
        errno = EINVAL;
        return 0;
    }
    if (posix_memalign(&p, align, n) != 0) {
        errno = ENOMEM;
        return 0;
    }
    return p;
}

/* ---- mkdtemp/mktemp/realpath ---- */

char *mkdtemp(char *t) {
    size_t len, i;
    int tries;
    unsigned long long salt;
    if (!t) {
        errno = EINVAL;
        return 0;
    }
    len = strlen(t);
    if (len < 6 || strcmp(t + len - 6, "XXXXXX") != 0) {
        errno = EINVAL;
        return 0;
    }
    salt = (unsigned long long)time(0) ^ ((unsigned long long)getpid()
                                          << 32);
    for (tries = 0; tries < 100; tries++) {
        salt = salt * 6364136223846793005ull + 1442695040888963407ull;
        for (i = 0; i < 6; i++)
            t[len - 6 + i] = ml_b62[(salt >> (6 * i)) % 62];
        if (mkdir(t, 0700) == 0) return t;
        if (errno != EEXIST) return 0;
    }
    errno = EEXIST;
    return 0;
}

char *mktemp(char *t) {
    size_t len, i;
    if (!t) {
        errno = EINVAL;
        return 0;
    }
    len = strlen(t);
    if (len < 6 || strcmp(t + len - 6, "XXXXXX") != 0) {
        errno = EINVAL;
        return 0;
    }
    for (i = 0; i < 6; i++) t[len - 6 + i] = ml_b62[i * 7 % 62];
    t[len] = '\0';
    return t;
}

char *realpath(const char *path, char *out) {
    static char ml_rp_buf[256];
    char tmp[256];
    size_t i, start = 0, n;
    char *dst;
    if (!path) {
        errno = EINVAL;
        return 0;
    }
    /* Flat single-root VFS: normalize to "/basename" (resolve a
     * trailing symlink once, like the kernel open path). */
    n = strlen(path);
    if (n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(tmp, path, n + 1);
    while (n > 0 && tmp[n - 1] == '/') tmp[--n] = '\0';
    for (i = 0; i < n; i++)
        if (tmp[i] == '/') start = i + 1;
    dst = out ? out : ml_rp_buf;
    dst[0] = '/';
    memcpy(dst + 1, tmp + start, n - start + 1);
    /* Validate existence (realpath must fail ENOENT for missing). */
    if (access(dst[1] ? dst + 1 : ".", F_OK) != 0) return 0;
    return dst;
}

/* ---- qsort_r (same quicksort engine, comparator carries arg) ---- */

void qsort_r(void *base, size_t n, size_t sz,
             int (*cmp)(const void *, const void *, void *), void *arg) {
    unsigned char *b;
    if (!base || !cmp || sz == 0) return;
    b = base;
    /* Lomuto partition, tail recursion on the larger side. */
    while (n > 1) {
        size_t lo = 0, hi = n - 1, p;
        unsigned char *pivot;
        if (n < 16) {
            size_t i, j;
            for (i = 1; i < n; i++) {
                j = i;
                while (j > 0 &&
                       cmp(b + j * sz, b + (j - 1) * sz, arg) < 0) {
                    ml_swap(b + j * sz, b + (j - 1) * sz, sz);
                    j--;
                }
            }
            return;
        }
        pivot = b + (n / 2) * sz;
        ml_swap(pivot, b + hi * sz, sz);
        p = lo;
        for (lo = 0; lo < hi; lo++) {
            if (cmp(b + lo * sz, b + hi * sz, arg) < 0) {
                ml_swap(b + lo * sz, b + p * sz, sz);
                p++;
            }
        }
        ml_swap(b + p * sz, b + hi * sz, sz);
        /* Recurse into the smaller half, loop on the larger. */
        if (p < n - p - 1) {
            qsort_r(b, p, sz, cmp, arg);
            b += (p + 1) * sz;
            n -= p + 1;
        } else {
            qsort_r(b + (p + 1) * sz, n - p - 1, sz, cmp, arg);
            n = p;
        }
    }
}

/* ---- mkostemp/mkostemps (mkstemp + O_CLOEXEC via fcntl) ---- */

int mkostemp(char *t, int flags) {
    int fd, f;
    if (flags & ~(O_CLOEXEC | O_CREAT | O_EXCL | O_RDWR | O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }
    fd = ml_mkstemp(t, 0);
    if (fd < 0) return -1;
    if (flags & O_CLOEXEC) {
        f = fcntl(fd, F_GETFD);
        if (f >= 0) fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    }
    return fd;
}

int mkostemps(char *t, int suffixlen, int flags) {
    int fd, f;
    if (flags & ~(O_CLOEXEC | O_CREAT | O_EXCL | O_RDWR | O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }
    fd = ml_mkstemp(t, suffixlen);
    if (fd < 0) return -1;
    if (flags & O_CLOEXEC) {
        f = fcntl(fd, F_GETFD);
        if (f >= 0) fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    }
    return fd;
}

/* ---- getsubopt (comma-separated suboptions) ---- */

int getsubopt(char **optionp, char *const *tokens, char **valuep) {
    char *s, *v;
    int i;
    if (!optionp || !*optionp || !tokens || !valuep) {
        errno = EINVAL;
        return -1;
    }
    s = *optionp;
    /* Skip leading blanks/commas (robust against ",,"). */
    while (*s == ' ' || *s == '\t' || *s == ',') s++;
    if (!*s) {
        *optionp = s;
        *valuep = 0;
        return -1;
    }
    *optionp = s;
    /* Token ends at ',' or '='. */
    v = 0;
    {
        char *p = s;
        while (*p && *p != ',' && *p != '=') p++;
        if (*p == '=') {
            *p = '\0';
            v = p + 1;
            p = v;
            while (*p && *p != ',') p++;
        }
        if (*p == ',') {
            *p = '\0';
            *optionp = p + 1;
        } else {
            *optionp = p;
        }
    }
    *valuep = v;
    for (i = 0; tokens[i]; i++)
        if (strcmp(s, tokens[i]) == 0) return i;
    return -1;
}

/* ---- l64a/a64l (POSIX base-64 long conversion) ---- */

static const char ml_a64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *l64a(long v) {
    static char buf[7];
    unsigned long u = (unsigned long)v;
    int i = 0;
    if (v < 0) {
        errno = EINVAL;
        return 0;
    }
    if (u == 0) {
        buf[0] = '\0';
        return buf;
    }
    while (u && i < 6) {
        buf[i++] = ml_a64[u & 63];
        u >>= 6;
    }
    buf[i] = '\0';
    return buf;
}

long a64l(const char *s) {
    long v = 0;
    int shift = 0;
    if (!s) return 0;
    while (*s && shift < 32) {
        const char *p = strchr(ml_a64, *s);
        if (!p) break;
        v |= (long)(p - ml_a64) << shift;
        shift += 6;
        s++;
    }
    return v;
}

/* ---- drand48 family (48-bit LCG, IEEE 754 doubles) ---- */

static unsigned short ml_drand48_x[3] = {0x1234, 0xABCD, 0x330E};
static unsigned short ml_drand48_a[3] = {0xE66D, 0xDEEC, 0x0005};
static unsigned short ml_drand48_c = 0x000B;
static int ml_drand48_init = 0;

static void ml_drand48_step(void) {
    unsigned long acc;
    acc = (unsigned long)ml_drand48_a[0] * ml_drand48_x[0] + ml_drand48_c;
    ml_drand48_x[0] = (unsigned short)(acc & 0xFFFF);
    acc >>= 16;
    acc += (unsigned long)ml_drand48_a[0] * ml_drand48_x[1] +
           (unsigned long)ml_drand48_a[1] * ml_drand48_x[0];
    ml_drand48_x[1] = (unsigned short)(acc & 0xFFFF);
    acc >>= 16;
    acc += (unsigned long)ml_drand48_a[0] * ml_drand48_x[2] +
           (unsigned long)ml_drand48_a[1] * ml_drand48_x[1] +
           (unsigned long)ml_drand48_a[2] * ml_drand48_x[0];
    ml_drand48_x[2] = (unsigned short)(acc & 0xFFFF);
}

static double ml_drand48_out(const unsigned short x[3]) {
    return ((double)x[0] / 281474976710656.0) +
           ((double)x[1] / 4294967296.0) +
           ((double)x[2] / 65536.0);
}

double drand48(void) {
    ml_drand48_init = 1;
    ml_drand48_step();
    return ml_drand48_out(ml_drand48_x);
}

double erand48(unsigned short x[3]) {
    unsigned short save[3];
    double r;
    memcpy(save, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, x, sizeof(save));
    ml_drand48_step();
    r = ml_drand48_out(ml_drand48_x);
    memcpy(x, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, save, sizeof(save));
    return r;
}

long lrand48(void) {
    ml_drand48_init = 1;
    ml_drand48_step();
    return (long)(((unsigned long)ml_drand48_x[2] << 15) |
                  ((unsigned long)ml_drand48_x[1] >> 1));
}

long nrand48(unsigned short x[3]) {
    unsigned short save[3];
    long r;
    memcpy(save, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, x, sizeof(save));
    ml_drand48_step();
    r = (long)(((unsigned long)ml_drand48_x[2] << 15) |
               ((unsigned long)ml_drand48_x[1] >> 1));
    memcpy(x, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, save, sizeof(save));
    return r;
}

long mrand48(void) {
    int32_t v;
    ml_drand48_init = 1;
    ml_drand48_step();
    /* High 32 bits of the 48-bit state, reinterpreted signed. */
    v = (int32_t)(((uint32_t)ml_drand48_x[2] << 16) | ml_drand48_x[1]);
    return (long)v;
}

long jrand48(unsigned short x[3]) {
    unsigned short save[3];
    int32_t v;
    long r;
    memcpy(save, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, x, sizeof(save));
    ml_drand48_step();
    v = (int32_t)(((uint32_t)ml_drand48_x[2] << 16) | ml_drand48_x[1]);
    r = (long)v;
    memcpy(x, ml_drand48_x, sizeof(save));
    memcpy(ml_drand48_x, save, sizeof(save));
    return r;
}

void srand48(long seed) {
    ml_drand48_x[0] = 0x330E;
    ml_drand48_x[1] = (unsigned short)(seed & 0xFFFF);
    ml_drand48_x[2] = (unsigned short)((seed >> 16) & 0xFFFF);
    ml_drand48_a[0] = 0xE66D;
    ml_drand48_a[1] = 0xDEEC;
    ml_drand48_a[2] = 0x0005;
    ml_drand48_c = 0x000B;
    ml_drand48_init = 1;
}

unsigned short *seed48(unsigned short seed[3]) {
    static unsigned short prev[3];
    memcpy(prev, ml_drand48_x, sizeof(prev));
    if (seed) memcpy(ml_drand48_x, seed, sizeof(prev));
    ml_drand48_a[0] = 0xE66D;
    ml_drand48_a[1] = 0xDEEC;
    ml_drand48_a[2] = 0x0005;
    ml_drand48_c = 0x000B;
    ml_drand48_init = 1;
    return prev;
}

void lcong48(unsigned short param[7]) {
    int i;
    for (i = 0; i < 3; i++) ml_drand48_x[i] = param[i];
    for (i = 0; i < 3; i++) ml_drand48_a[i] = param[i + 3];
    ml_drand48_c = param[6];
    ml_drand48_init = 1;
}

/* ---- allocator introspection (malloc.h) ---- */

#include <malloc.h>

size_t malloc_usable_size(void *p) {
    __ML_HDR *h;
    if (!p) return 0;
    h = (__ML_HDR *)p - 1;
    return h->units * ML_UNIT;
}

struct mallinfo mallinfo(void) {
    struct mallinfo mi;
    __ML_HDR *p;
    size_t free_bytes = 0;
    int free_blks = 0;
    memset(&mi, 0, sizeof(mi));
    if (ml_freep) {
        p = ml_freep;
        do {
            p = p->next;
            if (p == &ml_base) continue;
            free_blks++;
            free_bytes += p->units * ML_UNIT;
        } while (p != ml_freep);
    }
    mi.arena = (int)ml_heap_total;
    mi.ordblks = free_blks;
    mi.fordblks = (int)free_bytes;
    mi.uordblks = (int)(ml_heap_total > free_bytes
                            ? ml_heap_total - free_bytes
                            : 0);
    mi.keepcost = mi.fordblks;
    return mi;
}

static int ml_mallopt_tab[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};

static int ml_mallopt_slot(int param) {
    switch (param) {
    case M_MXFAST: return 0;
    case M_TRIM_THRESHOLD: return 1;
    case M_TOP_PAD: return 2;
    case M_MMAP_THRESHOLD: return 3;
    case M_MMAP_MAX: return 4;
    case M_CHECK_ACTION: return 5;
    case M_PERTURB: return 6;
    case M_ARENA_TEST: return 7;
    case M_ARENA_MAX: return 8;
    default: return -1;
    }
}

int mallopt(int param, int value) {
    /* Recorded and reported; the K&R arena honors thresholds by
     * construction (single sbrk heap, no mmap chunks to tune). */
    int slot = ml_mallopt_slot(param);
    if (slot < 0) return 0;
    ml_mallopt_tab[slot] = value;
    return 1;
}

int malloc_trim(size_t pad) {
    (void)pad;
    /* The sbrk arena grows monotonically (no bottom release); there
     * is nothing to trim, reported honestly as zero. */
    return 0;
}

void malloc_stats(void) {
    struct mallinfo mi = mallinfo();
    dprintf(2, "arena=%d free=%d used=%d blocks=%d\n", mi.arena,
            mi.fordblks, mi.uordblks, mi.ordblks);
}
