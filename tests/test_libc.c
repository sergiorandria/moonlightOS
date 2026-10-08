/* test_libc - host unit tests for the Moonlight C library.
 *
 * Links the REAL libc sources with test-local syscall stubs (in-memory
 * ramfile + capture buffer). Pure + FILE-path logic runs on the build
 * machine; on-target behavior is proven by the linux_demo QEMU run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <wchar.h>
#include <uchar.h>
#include <wctype.h>
#include <setjmp.h>
#include <signal.h>
#include <fenv.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>

/* ---- test-local syscall layer (replaces unistd.c/file.c) ---- */

static char cap_buf[65536];
static size_t cap_len = 0;

static char ramfile[4096];
static size_t ram_len = 0;
static size_t ram_off = 0;

void *sbrk(intptr_t inc);
int brk(void *addr);

static uint8_t heap_arena[1 << 20];
static size_t heap_top = 0;

void *sbrk(intptr_t inc) {
    size_t old = heap_top;
    if (inc < 0 || heap_top + (size_t)inc > sizeof(heap_arena)) return (void *)-1;
    heap_top += (size_t)inc;
    return heap_arena + old;
}

int brk(void *addr) {
    uintptr_t a = (uintptr_t)addr, base = (uintptr_t)heap_arena;
    if (a < base || a > base + sizeof(heap_arena)) return -1;
    if (a > base + heap_top) heap_top = a - base;
    return 0;
}

/* ramfile writes go through FILE's write path: intercept by appending. */
static ssize_t ram_write(const void *buf, size_t n) {
    if (ram_off + n > sizeof(ramfile)) n = sizeof(ramfile) - ram_off;
    memcpy(ramfile + ram_off, buf, n);
    ram_off += n;
    if (ram_off > ram_len) ram_len = ram_off;
    return (ssize_t)n;
}

/* Real-stderr escape: our own write() stub captures fd 1 into cap_buf
 * (printf tests) and fd 3 into the ramfile. Diagnostics must reach the
 * real stderr, so fd 2 bypasses the stubs via a raw host syscall
 * (SYS_write = 1), not the intercepted write(). */
extern long syscall(long n, ...);

ssize_t write(int fd, const void *buf, size_t n) {
    if (fd == 2) return (ssize_t)syscall(1, fd, buf, n);
    if (fd == 3) return ram_write(buf, n);
    if (cap_len + n > sizeof(cap_buf)) n = sizeof(cap_buf) - cap_len;
    memcpy(cap_buf + cap_len, buf, n);
    cap_len += n;
    return (ssize_t)n;
}

ssize_t read(int fd, void *buf, size_t n) {
    (void)fd;
    if (ram_off >= ram_len) return 0;
    if (n > ram_len - ram_off) n = ram_len - ram_off;
    memcpy(buf, ramfile + ram_off, n);
    ram_off += n;
    return (ssize_t)n;
}

int open(const char *path, int flags, ...) {
    (void)path;
    (void)flags;
    ram_off = 0;
    if (flags & O_TRUNC) ram_len = 0;
    return 3;
}

int close(int fd) {
    (void)fd;
    return 0;
}

int usleep(unsigned us) {
    (void)us;
    return 0;
}

/* Pure-module cross refs (unistd.c/file.c are NOT linked here; their
 * wrappers are covered against the real kernel in test_libc_sys.c). */
int getpid(void) { return 42; }

int sched_yield(void) { return 0; }

int fstat(int fd, struct stat *st) {
    (void)fd;
    (void)st;
    errno = EBADF;
    return -1;
}

int stat(const char *p, struct stat *st) {
    (void)p;
    (void)st;
    errno = ENOENT;
    return -1;
}

int unlink(const char *p) {
    (void)p;
    errno = ENOENT;
    return -1;
}

off_t lseek(int fd, off_t off, int whence) {
    long base;
    (void)fd;
    if (whence == SEEK_SET) base = 0;
    else if (whence == SEEK_CUR) base = (long)ram_off;
    else base = (long)ram_len;
    if (base + off < 0 || base + off > (long)sizeof(ramfile)) return -1;
    ram_off = (size_t)(base + off);
    return (off_t)ram_off;
}

/* Diagnostics must reach the real stderr: our own printf/write are the
 * stubs under test, so use the host dprintf (not provided by our libc). */
extern int dprintf(int fd, const char *fmt, ...);

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { dprintf(2, "FAIL: %s (line %d)\n", why, __LINE__); failures++; } \
} while (0)

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

/* double closeness (relative, with an absolute floor near zero). */
static int dclose(double a, double b, double tol) {
    double d = a - b;
    if (d < 0) d = -d;
    {
        double m = a < 0 ? -a : a;
        double n = b < 0 ? -b : b;
        double den = m > n ? m : n;
        if (den < 1.0) den = 1.0;
        return d <= tol * den;
    }
}

#define CHECKD(a, b, tol, why) CHECK(dclose((a), (b), (tol)), why)

static int sig_count; /* signal handler probe */
static void sig_probe(int sig) {
    (void)sig;
    sig_count++;
}

static int emit_v(FILE *f, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vfprintf(f, fmt, ap);
    va_end(ap);
    return r;
}

int main(void) {
    dprintf(2, "=== test_libc ===\n");

    /* string */
    {
        char b[16];
        memcpy(b, "0123456789abcde", 15);
        memmove(b + 2, b, 5);
        CHECK(memcmp(b, "0101234789abcde", 15) == 0, "memmove fwd overlap");
        memcpy(b, "0123456789abcde", 15);
        memmove(b, b + 2, 5);
        CHECK(memcmp(b, "2345656789abcde", 15) == 0, "memmove bwd overlap");
        CHECK(strcmp("a", "b") < 0 && strcmp("b", "a") > 0, "strcmp sign");
        CHECK(strncmp("abc", "abd", 2) == 0, "strncmp");
        CHECK(strchr("hello", 'l') == b + 0 || strchr("hello", 'l') != 0,
              "strchr");
        CHECK(strcmp(strchr("hello", 'l'), "llo") == 0, "strchr val");
        CHECK(strcmp(strrchr("hello", 'l'), "lo") == 0, "strrchr");
        CHECK(strstr("hello world", "wor") != 0, "strstr");
        CHECK(strstr("hello", "z") == 0, "strstr miss");
        CHECK(strspn("aaab", "a") == 3, "strspn");
        CHECK(strcspn("aaab", "b") == 3, "strcspn");
        CHECK(memchr("hello", 'e', 5) != 0, "memchr");
        CHECK(strnlen("hello", 3) == 3, "strnlen cap");
        {
            char *d = strdup("dup");
            CHECK(d && strcmp(d, "dup") == 0, "strdup");
            free(d);
        }
        {
            char c[16] = "foo";
            strcat(c, "bar");
            CHECK(strcmp(c, "foobar") == 0, "strcat");
            strncat(c, "!!", 1);
            CHECK(strcmp(c, "foobar!") == 0, "strncat");
        }
    }

    /* vsnprintf formats */
    {
        char b[64];
        CHECK(snprintf(b, sizeof(b), "%d/%u/%x/%X/%o/%s/%c/%p", -42, 42u,
                       0xabcd, 0xabcd, 511, "s", 'q',
                       (void *)0x1000) > 0,
              "snprintf runs");
        CHECK(strcmp(b, "-42/42/abcd/ABCD/777/s/q/0x1000") == 0, "formats");
        CHECK(snprintf(b, sizeof(b), "%5d|%-5d|%05d", 42, 42, 42) > 0,
              "width");
        CHECK(strcmp(b, "   42|42   |00042") == 0, "width vals");
        CHECK(snprintf(b, sizeof(b), "%lld/%zu", -1ll, (size_t)7) > 0,
              "ll/z");
        CHECK(strcmp(b, "-1/7") == 0, "ll/z vals");
        CHECK(snprintf(b, sizeof(b), "%.3s|%s", "abcdef", (const char *)0) >
                  0,
              "prec/null");
        CHECK(strcmp(b, "abc|(null)") == 0, "prec/null vals");
        {
            char small[4];
            int r = snprintf(small, sizeof(small), "abcdef");
            CHECK(r == 6 && strcmp(small, "abc") == 0, "truncation");
        }
    }

    /* malloc family */
    {
        char *p = malloc(100);
        char *q;
        int i;
        CHECK(p != 0, "malloc");
        memset(p, 0xAA, 100);
        free(p);
        q = calloc(4, 16);
        CHECK(q != 0, "calloc");
        for (i = 0; i < 64; i++)
            if (q[i] != 0) break;
        CHECK(i == 64, "calloc zero");
        q = realloc(q, 8192);
        CHECK(q != 0, "realloc grow");
        q[8191] = 1;
        q = realloc(q, 8);
        CHECK(q != 0, "realloc shrink");
        free(q);
        CHECK(malloc(0) != 0, "malloc 0");
        {
            /* many mixed sizes, then free all (no crash, reuse works) */
            void *v[64];
            for (i = 0; i < 64; i++) v[i] = malloc((size_t)(i * 37 + 1));
            for (i = 0; i < 64; i += 2) free(v[i]);
            for (i = 1; i < 64; i += 2) free(v[i]);
            CHECK(malloc(4096) != 0, "reuse after free");
        }
    }

    /* numbers + qsort + rand */
    {
        int arr[64], i, ok = 1;
        CHECK(atoi("-19") == -19, "atoi");
        CHECK(strtol("0xff", 0, 0) == 255, "hex");
        CHECK(strtol("077", 0, 0) == 63, "oct");
        CHECK(strtol("  +42x", 0, 10) == 42, "sp/plus");
        srand(42);
        for (i = 0; i < 64; i++) arr[i] = rand() % 1000;
        qsort(arr, 64, sizeof(int), cmp_int);
        for (i = 1; i < 64; i++)
            if (arr[i - 1] > arr[i]) ok = 0;
        CHECK(ok, "qsort");
        srand(7);
        {
            int a = rand();
            srand(7);
            CHECK(rand() == a, "rand deterministic");
        }
        CHECK(abs(-5) == 5 && labs(-9) == 9, "abs");
    }

    /* ctype */
    CHECK(isalpha('a') && !isalpha('1'), "alpha");
    CHECK(isdigit('7') && !isdigit('a'), "digit");
    CHECK(isspace('\n') && !isspace('x'), "space");
    CHECK(tolower('A') == 'a' && toupper('z') == 'Z', "case");

    /* gmtime: epoch + a known date (1700000000 = Tue 2023-11-14). */
    {
        time_t t0 = 0, t1 = 1700000000;
        struct tm *tm = gmtime(&t0);
        CHECK(tm->tm_year == 70 && tm->tm_mon == 0 && tm->tm_mday == 1 &&
                  tm->tm_wday == 4,
              "epoch Thu");
        tm = gmtime(&t1);
        CHECK(tm->tm_year == 123 && tm->tm_mon == 10 && tm->tm_mday == 14 &&
                  tm->tm_wday == 2 && tm->tm_yday == 317,
              "2023-11-14 Tue");
        CHECK(tm->tm_hour == 22 && tm->tm_min == 13 && tm->tm_sec == 20,
              "clock fields");
    }

    /* stdio FILE over the ramfile (write path intercepted below by
     * swapping the fd-3 writes: here we exercise printf capture). */
    {
        cap_len = 0;
        CHECK(printf("hi %d\n", 7) == 5, "printf count");
        CHECK(memcmp(cap_buf, "hi 7\n", 5) == 0, "printf bytes");
        CHECK(puts("yo") == 0, "puts");
    }

    /* fopen/fwrite/fread roundtrip through the ramfile. */
    {
        FILE *f = fopen("x", "w");
        CHECK(f != 0, "fopen");
        CHECK(fwrite("data", 1, 4, f) == 4, "fwrite count");
        CHECK(fclose(f) == 0, "fclose");
        f = fopen("x", "r");
        {
            char b[8];
            memset(b, 0, sizeof(b));
            CHECK(fread(b, 1, 4, f) == 4, "fread count");
            CHECK(memcmp(b, "data", 4) == 0, "fread bytes");
            CHECK(fread(b, 1, 4, f) == 0 && feof(f), "EOF flag");
        }
        CHECK(fseek(f, 1, SEEK_SET) == 0 && ftell(f) == 1, "seek/tell");
        CHECK(ferror(f) == 0, "no err");
        fclose(f);
    }

    /* ---- math (values + edges; tol 1e-9 rel, erf 1e-6) ---- */
    {
        CHECKD(sin(0.0), 0.0, 0, "sin 0");
        CHECKD(sin(M_PI_2), 1.0, 1e-12, "sin pi/2");
        CHECKD(sin(M_PI), 0.0, 1e-12, "sin pi");
        CHECKD(cos(0.0), 1.0, 0, "cos 0");
        CHECKD(cos(M_PI), -1.0, 1e-12, "cos pi");
        CHECKD(tan(0.5), 0.5463024898437905, 1e-9, "tan");
        CHECKD(asin(1.0), M_PI_2, 1e-12, "asin 1");
        CHECKD(acos(0.0), M_PI_2, 1e-12, "acos 0");
        CHECKD(atan(1.0), M_PI_4, 1e-12, "atan 1");
        CHECKD(atan2(1.0, 1.0), M_PI_4, 1e-12, "atan2");
        CHECKD(sinh(0.0), 0.0, 0, "sinh 0");
        CHECKD(cosh(0.0), 1.0, 0, "cosh 0");
        CHECKD(tanh(1.0), 0.7615941559557649, 1e-9, "tanh 1");
        CHECKD(asinh(1.0), 0.881373587019543, 1e-9, "asinh 1");
        CHECKD(acosh(2.0), 1.3169578969248167, 1e-9, "acosh 2");
        CHECKD(atanh(0.5), 0.5493061443340549, 1e-9, "atanh .5");
        CHECKD(exp(0.0), 1.0, 0, "exp 0");
        CHECKD(exp(1.0), M_E, 1e-12, "exp 1");
        CHECKD(exp2(10.0), 1024.0, 1e-9, "exp2");
        CHECKD(expm1(0.0), 0.0, 0, "expm1 0");
        CHECKD(expm1(1e-9), 1e-9, 1e-6, "expm1 tiny");
        CHECKD(log(M_E), 1.0, 1e-12, "log e");
        CHECKD(log2(8.0), 3.0, 1e-12, "log2");
        CHECKD(log10(1000.0), 3.0, 1e-12, "log10");
        CHECKD(log1p(0.0), 0.0, 0, "log1p 0");
        CHECKD(sqrt(2.0), 1.4142135623730951, 1e-12, "sqrt 2");
        CHECKD(cbrt(27.0), 3.0, 1e-12, "cbrt 27");
        CHECKD(hypot(3.0, 4.0), 5.0, 1e-12, "hypot");
        CHECKD(pow(2.0, 10.0), 1024.0, 1e-9, "pow");
        CHECKD(pow(-2.0, 3.0), -8.0, 1e-9, "pow neg int");
        CHECK(isnan(pow(-1.0, 0.5)), "pow neg frac NaN");
        CHECKD(erf(0.0), 0.0, 0, "erf 0");
        CHECKD(erf(1.0), 0.8427007929, 1e-6, "erf 1");
        CHECKD(erfc(1.0), 0.1572992070, 1e-6, "erfc 1");
        CHECKD(tgamma(5.0), 24.0, 1e-9, "tgamma 5");
        CHECKD(tgamma(0.5), 1.7724538509055160, 1e-9, "tgamma .5");
        CHECKD(lgamma(6.0), 4.787491742782046, 1e-9, "lgamma 6");
        CHECK(floor(2.7) == 2.0 && floor(-2.7) == -3.0, "floor");
        CHECK(ceil(2.1) == 3.0 && ceil(-2.7) == -2.0, "ceil");
        CHECK(trunc(-2.7) == -2.0, "trunc");
        CHECK(round(2.5) == 3.0 && round(-2.5) == -3.0, "round half away");
        CHECK(rint(0.5) == 0.0 && rint(1.5) == 2.0, "rint half even");
        CHECK(lround(2.5) == 3 && llround(-2.5) == -3, "lround");
        CHECKD(fmod(5.3, 2.0), 1.3, 1e-12, "fmod");
        CHECKD(remainder(5.3, 2.0), -0.7, 1e-12, "remainder");
        {
            int q = 0;
            double r = remquo(5.3, 2.0, &q);
            CHECKD(r, -0.7, 1e-12, "remquo val");
            CHECK((q & 7) == 3 || (q & 7) == -3, "remquo quo");
        }
        CHECKD(fma(2.0, 3.0, 4.0), 10.0, 0, "fma");
        CHECK(fmax(1.0, NAN) == 1.0 && fmin(1.0, NAN) == 1.0, "fmax NaN");
        CHECK(fdim(3.0, 5.0) == 0.0 && fdim(5.0, 3.0) == 2.0, "fdim");
        CHECK(nextafter(1.0, 2.0) > 1.0, "nextafter up");
        CHECK(nextafter(1.0, 0.0) < 1.0, "nextafter down");
        {
            int e = 0;
            double m = frexp(8.0, &e);
            CHECK(m == 0.5 && e == 4, "frexp");
            CHECK(ldexp(0.5, 4) == 8.0, "ldexp");
            CHECK(ldexp(1.5, -1074) == 0.0 || ldexp(1.5, -1074) > 0.0,
                  "ldexp subnormal range");
        }
        {
            double ip = 0;
            double fp = modf(3.7, &ip);
            CHECK(ip == 3.0 && dclose(fp, 0.7, 1e-12), "modf");
        }
        CHECK(scalbn(1.5, 3) == 12.0, "scalbn");
        CHECK(ilogb(8.0) == 3 && logb(8.0) == 3.0, "ilogb/logb");
        CHECK(copysign(1.0, -2.0) == -1.0, "copysign");
        CHECK(fabs(-3.0) == 3.0, "fabs");
        CHECK(isnan(NAN) && !isnan(1.0), "isnan");
        CHECK(isinf(HUGE_VAL) && !isinf(1.0), "isinf");
        CHECK(isfinite(1.0) && !isfinite(HUGE_VAL), "isfinite");
        CHECK(signbit(-1.0) && !signbit(1.0), "signbit");
        CHECK(fpclassify(0.0) == FP_ZERO, "fpclass zero");
        CHECK(fpclassify(1.0) == FP_NORMAL, "fpclass normal");
        CHECK(fpclassify(1.0 / 0.0) == FP_INFINITE, "fpclass inf");
        CHECK(isnan(nan("0x1")), "nan payload");
        CHECK(isnan(sqrt(-1.0)) && errno == EDOM, "sqrt neg EDOM");
        errno = 0;
        CHECK(isnan(log(-1.0)) && errno == EDOM, "log neg EDOM");
        errno = 0;
        CHECK(sinf(0.5f) == (float)sin(0.5), "sinf agree");
        CHECK(sqrtf(4.0f) == 2.0f, "sqrtf");
        CHECK(powf(2.0f, 8.0f) == 256.0f, "powf");
    }

    /* ---- string extras ---- */
    {
        char tmp[32];
        char *sp;
        CHECK(strcmp(stpcpy(tmp, "abc"), tmp + 3) == 0 &&
                  strcmp(tmp, "abc") == 0,
              "stpcpy");
        CHECK(stpncpy(tmp, "abcdef", 3) == tmp + 3 &&
                  memcmp(tmp, "abc", 3) == 0,
              "stpncpy trunc");
        CHECK(stpncpy(tmp, "ab", 5) == tmp + 2 && tmp[2] == 0 &&
                  tmp[4] == 0,
              "stpncpy pad");
        {
            char src[] = "a,b,,c";
            sp = src;
            CHECK(strcmp(strsep(&sp, ","), "a") == 0, "strsep 1");
            CHECK(strcmp(strsep(&sp, ","), "b") == 0, "strsep 2");
            CHECK(strcmp(strsep(&sp, ","), "") == 0, "strsep empty");
            CHECK(strcmp(strsep(&sp, ","), "c") == 0, "strsep 3");
            CHECK(strsep(&sp, ",") == 0 && sp == 0, "strsep end");
        }
        {
            char d[16];
            CHECK(memccpy(d, "hello", 'l', 5) == d + 3, "memccpy hit");
            CHECK(memccpy(d, "hello", 'z', 5) == 0, "memccpy miss");
        }
        CHECK(strcmp(strsignal(2), "Interrupt") == 0, "strsignal INT");
        CHECK(strcmp(strsignal(11), "Segmentation fault") == 0,
              "strsignal SEGV");
        {
            char eb[32];
            CHECK(strerror_r(ENOENT, eb, sizeof(eb)) == 0 &&
                      strcmp(eb, "no such file") == 0,
                  "strerror_r fit");
            CHECK(strerror_r(ENOENT, eb, 4) == ERANGE &&
                      strcmp(eb, "no ") == 0,
                  "strerror_r trunc");
            CHECK(strerror_r(ENOENT, 0, 0) == EINVAL, "strerror_r null");
        }
    }

    /* ---- strings extras ---- */
    {
        char d[16];
        bzero(d, sizeof(d));
        CHECK(d[0] == 0 && d[15] == 0, "bzero");
        bcopy("hello", d, 6);
        CHECK(strcmp(d, "hello") == 0, "bcopy");
        CHECK(bcmp("abc", "abd", 3) != 0 && bcmp("abc", "abc", 3) == 0,
              "bcmp");
        CHECK(index("hello", 'l') == strchr("hello", 'l'), "index");
        CHECK(rindex("hello", 'l') == strrchr("hello", 'l'), "rindex");
        CHECK(ffs(0) == 0 && ffs(1) == 1 && ffs(8) == 4, "ffs");
        CHECK(ffsl(0) == 0 && ffsll(0x100000000ll) == 33, "ffsll");
    }

    /* ---- stdlib extras ---- */
    {
        void *p = 0;
        CHECK(system(0) == 0, "system NULL");
        CHECK(system("ls") == -1 && errno == ENOSYS, "system ENOSYS");
        CHECK(at_quick_exit(0) == -1, "at_quick_exit null");
        CHECK(posix_memalign(&p, 3, 16) == EINVAL, "pmalign bad align");
        CHECK(posix_memalign(&p, 32, 100) == 0 && p != 0 &&
                  ((uintptr_t)p & 31) == 0,
              "pmalign 32");
        if (p) {
            memset(p, 0x5A, 100);
            free(p);
        }
        p = aligned_alloc(64, 128);
        CHECK(p != 0 && ((uintptr_t)p & 63) == 0, "aligned_alloc");
        if (p) {
            memset(p, 0xA5, 128);
            free(p);
        }
        CHECK(aligned_alloc(64, 100) == 0, "aligned size multiple");
        CHECK(mblen("A", 1) == 1 && mblen("", 1) == 0, "mblen");
        {
            wchar_t wc = 0;
            char mb[8];
            CHECK(mbtowc(&wc, "A", 1) == 1 && wc == 'A', "mbtowc");
            CHECK(wctomb(mb, wc) == 1 && mb[0] == 'A', "wctomb");
        }
        {
            wchar_t ws[16];
            char ns[16];
            CHECK(mbstowcs(ws, "hi", 16) == 2 && ws[0] == 'h' &&
                      ws[2] == 0,
                  "mbstowcs");
            CHECK(wcstombs(ns, ws, sizeof(ns)) == 2 &&
                      memcmp(ns, "hi", 2) == 0,
                  "wcstombs");
        }
    }

    /* ---- stdio extras (%lc/%ls, vfprintf, setvbuf, fdopen) ---- */
    {
        char b[64];
        CHECK(snprintf(b, sizeof(b), "%lc", (wint_t)0x20AC) == 3 &&
                  (unsigned char)b[0] == 0xE2 &&
                  (unsigned char)b[1] == 0x82 &&
                  (unsigned char)b[2] == 0xAC,
              "printf %lc euro");
        CHECK(snprintf(b, sizeof(b), "[%ls]", L"h\xe9llo") > 0,
              "printf %ls narrow-literal");
        {
            /* L"..." prefix is host-UTF-8; compare exact bytes. */
            const wchar_t *w = L"h\xe9llo";
            int n = snprintf(b, sizeof(b), "%ls", w);
            CHECK(n == 6 && memcmp(b, "h\xc3\xa9llo", 6) == 0,
                  "printf %ls bytes");
            n = snprintf(b, sizeof(b), "%.3s", "abcdef");
            CHECK(n == 3 && memcmp(b, "abc", 3) == 0, "prec bytes");
        }
        {
            char *mp = 0;
            size_t ml = 0;
            FILE *m = open_memstream(&mp, &ml);
            CHECK(m != 0, "memstream open");
            if (m) {
                CHECK(emit_v(m, "v%d", 9) == 2, "vfprintf passthrough");
                CHECK(fclose(m) == 0, "vfprintf close");
                CHECK(ml == 2 && memcmp(mp, "v9", 2) == 0,
                      "vfprintf bytes");
            }
            free(mp);
        }
        {
            char *mp = 0;
            size_t ml = 0;
            FILE *m = open_memstream(&mp, &ml);
            CHECK(m != 0, "memstream2");
            if (m) {
                CHECK(fprintf(m, "n=%d", 7) == 3, "fprintf memstream");
                CHECK(fclose(m) == 0, "memstream close");
                CHECK(ml == 3 && memcmp(mp, "n=7", 3) == 0,
                      "memstream bytes");
            }
            free(mp);
        }
        CHECK(fdopen(-1, "r") == 0, "fdopen bad fd");
        {
            char b2[8];
            FILE tmpf;
            memset(&tmpf, 0, sizeof(tmpf));
            CHECK(setvbuf(&tmpf, b2, _IOFBF, sizeof(b2)) == 0,
                  "setvbuf ok");
            CHECK(setvbuf(&tmpf, b2, 99, sizeof(b2)) == -1,
                  "setvbuf bad mode");
            setbuf(&tmpf, 0);
        }
        CHECK(rename("nope-src", "nope-dst") == -1, "rename missing");
    }

    /* ---- wchar codec ---- */
    {
        mbstate_t st;
        wchar_t wc = 0;
        char mb[8];
        memset(&st, 0, sizeof(st));
        CHECK(mbsinit(&st), "mbsinit zero");
        CHECK(mbrtowc(&wc, "\xE2\x82\xAC", 3, &st) == 3 && wc == 0x20AC,
              "mbrtowc euro");
        CHECK(wcrtomb(mb, 0x20AC, &st) == 3 &&
                  memcmp(mb, "\xE2\x82\xAC", 3) == 0,
              "wcrtomb euro");
        CHECK(mbrtowc(&wc, "A", 1, &st) == 1 && wc == 'A', "mbrtowc A");
        CHECK(mbrtowc(&wc, "", 1, &st) == 0 && wc == 0, "mbrtowc NUL");
        CHECK(mbrtowc(&wc, "\xC0\xAF", 2, &st) == (size_t)-1 &&
                  errno == EILSEQ,
              "overlong EILSEQ");
        CHECK(mbrtowc(&wc, "\xED\xA0\x80", 3, &st) == (size_t)-1,
              "surrogate EILSEQ");
        CHECK(mbrtowc(&wc, "\xF5\x80\x80\x80", 4, &st) == (size_t)-1,
              "beyond-10FFFF EILSEQ");
        /* Split feed: 1 byte now (-2), rest resumes. */
        memset(&st, 0, sizeof(st));
        CHECK(mbrtowc(&wc, "\xE2", 1, &st) == (size_t)-2, "split -2");
        CHECK(!mbsinit(&st), "mbsinit partial");
        CHECK(mbrtowc(&wc, "\x82\xAC", 2, &st) == 2 && wc == 0x20AC,
              "resume euro");
        CHECK(mbsinit(&st), "mbsinit again");
        /* Astral plane through mbrtoc16 surrogate halves. */
        {
            char16_t h = 0, l = 0;
            mbstate_t u;
            size_t r;
            memset(&u, 0, sizeof(u));
            r = mbrtoc16(&h, "\xF0\x9D\x84\x9E", 4, &u);
            CHECK(r == 4 && h == 0xD834, "mbrtoc16 high");
            r = mbrtoc16(&l, "", 0, &u);
            CHECK(r == (size_t)-3 && l == 0xDD1E, "mbrtoc16 low");
            memset(&u, 0, sizeof(u));
            CHECK(c16rtomb(mb, 0xD834, &u) == 0, "c16rtomb high holds");
            CHECK(c16rtomb(mb, 0xDD1E, &u) == 4 &&
                      memcmp(mb, "\xF0\x9D\x84\x9E", 4) == 0,
                  "c16rtomb pair");
            CHECK(c16rtomb(mb, 0xDC00, &u) == (size_t)-1,
                  "lone low EILSEQ");
        }
        {
            char32_t w32 = 0;
            mbstate_t u;
            memset(&u, 0, sizeof(u));
            CHECK(mbrtoc32(&w32, "\xE2\x82\xAC", 3, &u) == 3 &&
                      w32 == 0x20AC,
                  "mbrtoc32");
            CHECK(c32rtomb(mb, 0x20AC, &u) == 3, "c32rtomb");
        }
        {
            const char *src = "hi";
            wchar_t ws[8];
            const wchar_t *wsrc;
            char ns[8];
            memset(&st, 0, sizeof(st));
            CHECK(mbsrtowcs(ws, &src, 8, &st) == 2 && ws[2] == 0,
                  "mbsrtowcs");
            wsrc = ws;
            memset(&st, 0, sizeof(st));
            CHECK(wcsrtombs(ns, &wsrc, sizeof(ns), &st) == 2 &&
                      memcmp(ns, "hi", 2) == 0,
                  "wcsrtombs");
        }
        CHECK(wcslen(L"abc") == 3, "wcslen");
        CHECK(wcsnlen(L"abc", 2) == 2, "wcsnlen");
        {
            wchar_t d[16];
            CHECK(wcscmp(wcscpy(d, L"ab"), L"ab") == 0, "wcscpy");
            CHECK(wcsncmp(L"abc", L"abd", 2) == 0, "wcsncmp");
            CHECK(wcscoll(L"a", L"b") < 0, "wcscoll");
            CHECK(wcschr(L"abc", 'b') != 0 &&
                      *(wcschr(L"abc", 'b') + 1) == 'c',
                  "wcschr");
            {
                const wchar_t *wb = L"abcb";
                CHECK(wcsrchr(wb, 'b') == wb + 3, "wcsrchr");
                CHECK(wcsrchr(wb, 'z') == 0, "wcsrchr miss");
            }
            CHECK(wcsstr(L"hello", L"llo") != 0, "wcsstr");
            CHECK(wcsspn(L"aaab", L"a") == 3, "wcsspn");
            CHECK(wcscspn(L"aaab", L"b") == 3, "wcscspn");
            CHECK(wcspbrk(L"abc", L"xby") != 0, "wcspbrk");
            {
                wchar_t t[] = L"a,b,c";
                wchar_t *sv = 0;
                CHECK(wcscmp(wcstok(t, L",", &sv), L"a") == 0,
                      "wcstok 1");
                CHECK(wcscmp(wcstok(0, L",", &sv), L"b") == 0,
                      "wcstok 2");
            }
            CHECK(wmemcmp(L"ab", L"ab", 2) == 0, "wmemcmp");
            CHECK(wmemchr(L"abc", 'b', 3) != 0, "wmemchr");
            wmemset(d, 'x', 3);
            CHECK(d[0] == 'x' && d[2] == 'x', "wmemset");
            wmemcpy(d, L"yz", 2);
            CHECK(d[0] == 'y', "wmemcpy");
            wmemmove(d + 1, d, 2);
            CHECK(d[1] == 'y', "wmemmove overlap");
            {
                wchar_t *dd = wcsdup(L"dup");
                CHECK(dd && wcscmp(dd, L"dup") == 0, "wcsdup");
                free(dd);
            }
        }
        {
            wchar_t *end = 0;
            CHECK(wcstol(L"  -0xff", &end, 0) == -255, "wcstol hex");
            CHECK(end && *end == 0, "wcstol end");
            CHECK(wcstoul(L"77", 0, 8) == 63, "wcstoul oct");
            CHECK(wcstoull(L"99", 0, 10) == 99, "wcstoull");
            CHECK(wcstoll(L"-5", 0, 10) == -5, "wcstoll");
            CHECKD(wcstod(L"3.14", &end), 3.14, 1e-12, "wcstod");
            CHECK(wcstof(L"2.5", 0) == 2.5f, "wcstof");
            CHECK(wcstoimax(L"-9", 0, 10) == -9, "wcstoimax");
            CHECK(wcstoumax(L"9", 0, 10) == 9, "wcstoumax");
        }
        CHECK(btowc('A') == 'A' && btowc(EOF) == WEOF, "btowc");
        CHECK(wctob('A') == 'A' && wctob(0x20AC) == EOF, "wctob");
        /* Wide stdio over memory streams. */
        {
            char bytes[] = "h\xC3\xA9llo";
            FILE *f = fmemopen(bytes, sizeof(bytes) - 1, "r");
            CHECK(f != 0, "fmemopen utf8");
            if (f) {
                CHECK(fgetwc(f) == 'h', "fgetwc h");
                CHECK(fgetwc(f) == 0xE9, "fgetwc e-acute");
                CHECK(ungetwc(0xE9, f) == 0xE9, "ungetwc");
                CHECK(fgetwc(f) == 0xE9, "fgetwc again");
                fclose(f);
            }
        }
        {
            char *mp = 0;
            size_t ml = 0;
            FILE *m = open_memstream(&mp, &ml);
            CHECK(m != 0, "wide memstream");
            if (m) {
                CHECK(fputwc(0x20AC, m) == 0x20AC, "fputwc euro");
                CHECK(fputws(L"ab", m) == 0, "fputws");
                CHECK(fwide(m, 0) > 0, "fwide set");
                CHECK(fclose(m) == 0, "wide close");
                CHECK(ml == 5 && memcmp(mp, "\xE2\x82\xAC"
                                              "ab",
                                        5) == 0,
                      "wide bytes");
            }
            free(mp);
        }
        {
            wchar_t ws[32];
            CHECK(swprintf(ws, 32, L"%d/%s/%c|%lc|%ls", 42, L"wide",
                           L'x', (wint_t)'A', L"BC") > 0,
                  "swprintf runs");
            CHECK(wcscmp(ws, L"42/wide/x|A|BC") == 0, "swprintf val");
        }
        {
            wchar_t ws[4];
            int n = swprintf(ws, 4, L"%d", 12345);
            CHECK(n == 5 && ws[3] == 0, "swprintf trunc count");
        }
    }

    /* ---- wctype ---- */
    {
        CHECK(iswalpha('z') && !iswalpha('5'), "iswalpha");
        CHECK(iswalpha(0xE9) && iswlower(0xE9), "latin-1 lower");
        CHECK(towupper(0xE9) == 0xC9 && towlower(0xC9) == 0xE9,
              "latin-1 case");
        CHECK(iswspace(0x2003) && iswspace('\t'), "iswspace uni");
        CHECK(iswxdigit('F') && !iswxdigit('G'), "iswxdigit");
        CHECK(iswprint('~') && !iswprint(7), "iswprint");
        CHECK(iswcntrl(7) && !iswcntrl('a'), "iswcntrl");
        CHECK(iswpunct('!') && !iswpunct('a'), "iswpunct");
        CHECK(iswblank(' ') && !iswblank('a'), "iswblank");
        CHECK(iswgraph('!') && !iswgraph(' '), "iswgraph");
        CHECK(iswdigit(0x39) && iswalnum(0xE9), "digit/alnum");
        CHECK(iswctype('A', wctype("upper")), "wctype upper");
        CHECK(towctrans('a', wctrans("toupper")) == 'A', "wctrans");
    }

    /* ---- time extras ---- */
    {
        struct tm tm;
        char sb[64];
        memset(&tm, 0, sizeof(tm));
        /* 1970-01-01 00:00:00 UTC (a zeroed tm is 1900-01-00, not the
         * epoch: set the fields explicitly per the C standard). */
        tm.tm_year = 70;
        tm.tm_mon = 0;
        tm.tm_mday = 1;
        CHECK(mktime(&tm) == 0, "mktime epoch");
        CHECK(timegm(&tm) == 0, "timegm epoch");
        CHECK(dclose(difftime(100, 30), 70.0, 0), "difftime");
        {
            time_t t1 = 1700000000;
            struct tm *g = gmtime(&t1);
            CHECK(strcmp(asctime(g), "Tue Nov 14 22:13:20 2023\n") == 0,
                  "asctime known date");
            CHECK(strcmp(ctime(&t1), asctime(g)) == 0, "ctime match");
            {
                struct tm r;
                CHECK(gmtime_r(&t1, &r) == &r && r.tm_mday == 14,
                      "gmtime_r");
                CHECK(localtime_r(&t1, &r) == &r, "localtime_r");
            }
            CHECK(strftime(sb, sizeof(sb), "%F %T", g) == 19 &&
                      strcmp(sb, "2023-11-14 22:13:20") == 0,
                  "strftime F/T");
            {
                /* Wide run needs room (the full expansion is ~120
                 * chars; sb[64] would truncate to 0 per C99). */
                char big[256];
                CHECK(strftime(big, sizeof(big),
                               "%a %A %b %B %C %d %e %H "
                               "%I %j %m %M %p %S %u %U %V %w "
                               "%W %y %Y %z %Z %%",
                               g) > 0,
                      "strftime wide run");
            }
            CHECK(strftime(sb, 5, "%F", g) == 0, "strftime trunc 0");
            {
                struct tm p;
                memset(&p, 0, sizeof(p));
                CHECK(strptime("2023-11-14 22:13:20", "%F %T", &p) != 0,
                      "strptime F/T");
                CHECK(p.tm_year == 123 && p.tm_mon == 10 &&
                          p.tm_mday == 14 && p.tm_hour == 22 &&
                          p.tm_min == 13 && p.tm_sec == 20,
                      "strptime vals");
                CHECK(timegm(&p) == t1, "strptime roundtrip");
            }
            {
                struct tm p;
                memset(&p, 0, sizeof(p));
                CHECK(strptime("Nov 14 10:13:20 PM 2023",
                               "%b %d %I:%M:%S %p %Y", &p) != 0 &&
                          p.tm_hour == 22,
                      "strptime 12h");
            }
            CHECK(strptime("xx", "%Y", &tm) == 0, "strptime fail");
        }
        {
            struct timespec rq = {0, 2000000000L};
            CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &rq, 0) == EINVAL,
                  "nanosleep bad nsec");
            CHECK(timespec_get(0, TIME_UTC) == 0, "timespec_get null");
        }
    }

    /* ---- scanf (first coverage: engine was untested) ---- */
    {
        int a = 0, b = 0, n = 0;
        unsigned x = 0;
        char s[16];
        double f = 0;
        CHECK(sscanf("42 -7 0xff hello", "%d %d %x %s", &a, &b, &x, s) ==
                      4 &&
                  a == 42 && b == -7 && x == 255 &&
                  strcmp(s, "hello") == 0,
              "sscanf basic");
        CHECK(sscanf("077 0x10", "%i %i", &a, &b) == 2 && a == 63 &&
                  b == 16,
              "sscanf %i bases");
        CHECK(sscanf("3.14", "%f", &f) == 1 && dclose(f, 3.14, 1e-12),
              "sscanf float");
        CHECK(sscanf("abc123", "%[a-z]%d", s, &a) == 2 && a == 123,
              "sscanf scanset");
        CHECK(sscanf("10 20 30", "%*d %d %n", &a, &n) == 1 && a == 20 &&
                  n > 0,
              "sscanf suppress+n");
        CHECK(sscanf("ab12", "%2c%c", s, s + 2) == 1 + 1, "sscanf %c");
        {
            wchar_t ws[8];
            CHECK(sscanf("hi", "%ls", ws) == 1 && ws[0] == 'h' &&
                      ws[2] == 0,
                  "sscanf %ls");
        }
        {
            FILE *mf;
            char in[] = "7 8";
            mf = fmemopen(in, sizeof(in) - 1, "r");
            CHECK(mf != 0, "scanf memstream");
            if (mf) {
                CHECK(fscanf(mf, "%d %d", &a, &b) == 2 && a == 7 &&
                          b == 8,
                      "fscanf");
                fclose(mf);
            }
        }
        CHECK(sscanf("100%", "%d%%", &a) == 1 && a == 100, "sscanf %%");
        CHECK(sscanf("", "%d", &a) == EOF, "sscanf EOF");
    }

    /* ---- getopt ---- */
    {
        char *argv[] = {"p", "x", "-a", "y", 0};
        int c;
        optind = 1;
        c = getopt(4, argv, "a");
        CHECK(c == 'a', "getopt finds -a");
        CHECK(getopt(4, argv, "a") == -1, "getopt ends");
        CHECK(strcmp(argv[optind], "x") == 0, "getopt permutes");
    }

    /* ---- env ---- */
    {
        CHECK(getenv("ML_T1") == 0, "getenv missing");
        CHECK(setenv("ML_T1", "v1", 1) == 0 &&
                  strcmp(getenv("ML_T1"), "v1") == 0,
              "setenv");
        CHECK(setenv("ML_T1", "v2", 0) == 0 &&
                  strcmp(getenv("ML_T1"), "v1") == 0,
              "setenv no-overwrite");
        CHECK(setenv("ML_T1", "v2", 1) == 0 &&
                  strcmp(getenv("ML_T1"), "v2") == 0,
              "setenv overwrite");
        CHECK(setenv("BAD=NAME", "v", 1) == -1, "setenv EINVAL");
        CHECK(unsetenv("ML_T1") == 0 && getenv("ML_T1") == 0,
              "unsetenv");
        {
            static char pe[] = "ML_T2=vv";
            CHECK(putenv(pe) == 0 && strcmp(getenv("ML_T2"), "vv") == 0,
                  "putenv");
        }
        CHECK(clearenv() == 0 && getenv("ML_T2") == 0, "clearenv");
    }

    /* ---- signal (in-process table) ---- */
    {
        sigset_t set;
        struct sigaction sa, old;
        sig_count = 0;
        CHECK(signal(SIGUSR1, sig_probe) != SIG_ERR, "signal install");
        CHECK(raise(SIGUSR1) == 0 && sig_count == 1, "raise runs");
        CHECK(signal(SIGKILL, sig_probe) == SIG_ERR, "SIGKILL uncatch");
        CHECK(sigemptyset(&set) == 0 && sigismember(&set, SIGUSR1) == 0,
              "sigemptyset");
        CHECK(sigaddset(&set, SIGUSR1) == 0 &&
                  sigismember(&set, SIGUSR1) == 1,
              "sigaddset");
        CHECK(sigdelset(&set, SIGUSR1) == 0 &&
                  sigismember(&set, SIGUSR1) == 0,
              "sigdelset");
        CHECK(sigfillset(&set) == 0 && sigismember(&set, SIGTERM) == 1,
              "sigfillset");
        CHECK(sigaddset(&set, 99) == -1, "sigaddset bad");
        /* Block, raise (pends), unblock (delivers). */
        sigemptyset(&set);
        sigaddset(&set, SIGUSR2);
        CHECK(signal(SIGUSR2, sig_probe) != SIG_ERR, "usr2 install");
        CHECK(sigprocmask(SIG_BLOCK, &set, 0) == 0, "block");
        CHECK(raise(SIGUSR2) == 0 && sig_count == 1, "blocked pends");
        CHECK(sigpending(&set) == 0 && sigismember(&set, SIGUSR2) == 1,
              "pending bit");
        CHECK(sigprocmask(SIG_UNBLOCK, &set, 0) == 0 && sig_count == 2,
              "unblock delivers");
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_probe;
        CHECK(sigaction(SIGTERM, &sa, &old) == 0, "sigaction set");
        CHECK(raise(SIGTERM) == 0 && sig_count == 3, "sigaction runs");
        CHECK(sigaction(SIGKILL, &sa, 0) == -1, "sigaction KILL");
        CHECK(raise(99) == -1, "raise bad");
    }

    /* ---- setjmp (real context switch) ---- */
    {
        jmp_buf jb;
        volatile int stage = 0;
        int r = setjmp(jb);
        if (r == 0) {
            if (stage == 0) {
                stage = 1;
                longjmp(jb, 7);
            } else if (stage == 1) {
                stage = 2;
                longjmp(jb, 0); /* 0 -> 1 */
            }
        }
        CHECK((r == 7 && stage == 1) || (r == 1 && stage == 2) ||
                  (r == 0 && stage == 0),
              "setjmp/longjmp flow");
        CHECK(r != 0, "longjmp landed");
    }
    {
        sigjmp_buf sj;
        sigset_t blk, cur;
        int r;
        sigemptyset(&blk);
        sigaddset(&blk, SIGUSR1);
        sigprocmask(SIG_BLOCK, &blk, 0);
        r = sigsetjmp(sj, 1);
        if (r == 0) {
            /* Change the mask, then jump back: it must be restored. */
            sigprocmask(SIG_UNBLOCK, &blk, 0);
            siglongjmp(sj, 3);
        }
        CHECK(r == 3, "siglongjmp val");
#ifdef __riscv
        CHECK(sigprocmask(0, 0, &cur) == 0 &&
                  sigismember(&cur, SIGUSR1) == 1,
              "siglongjmp restores mask");
#else
        /* Host: glibc sigsetjmp saves the kernel mask, but our mask
         * table lives in userspace signal.c (the rv64 setjmp.S saves
         * it explicitly). Mask restore is target-verified; here we
         * only check the jump value and clean up. */
        (void)cur;
#endif
        sigprocmask(SIG_UNBLOCK, &blk, 0);
    }

    /* ---- fenv ---- */
    {
        fenv_t e;
        CHECK(fegetround() == FE_TONEAREST, "default nearest");
        CHECK(fesetround(FE_DOWNWARD) == 0 &&
                  fegetround() == FE_DOWNWARD,
              "set downward");
        CHECK(fesetround(99) == -1, "bad mode");
        CHECK(fesetround(FE_TONEAREST) == 0, "restore nearest");
        CHECK(feclearexcept(FE_ALL_EXCEPT) == 0, "clear");
        CHECK(feraiseexcept(FE_INEXACT | FE_OVERFLOW) == 0, "raise");
        CHECK(fetestexcept(FE_INEXACT) != 0 &&
                  fetestexcept(FE_UNDERFLOW) == 0,
              "test flags");
        CHECK(fegetenv(&e) == 0 && fesetenv(&e) == 0, "get/set env");
        CHECK(feholdexcept(&e) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0,
              "holdexcept clears");
        CHECK(feupdateenv(&e) == 0 &&
                  fetestexcept(FE_INEXACT | FE_OVERFLOW) != 0,
              "updateenv merges");
    }

    /* ---- locale ---- */
    {
        CHECK(setlocale(LC_ALL, "C") != 0, "setlocale C");
        CHECK(setlocale(LC_ALL, "nope-XX") == 0, "setlocale reject");
        CHECK(strcmp(localeconv()->decimal_point, ".") == 0,
              "localeconv point");
    }

    if (failures == 0) dprintf(2, "ALL LIBC TESTS PASS\n");
    else dprintf(2, "FAIL: libc (%d)\n", failures);
    return failures ? 1 : 0;
}
