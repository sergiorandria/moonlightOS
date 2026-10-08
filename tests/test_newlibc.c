/* test_newlibc - host unit tests for the extended Moonlight C library.
 *
 * Links the REAL pure sources (complex, monetary, langinfo, iconv,
 * locale, math, threads-over-stub-pthread) on the build machine.
 * Mirrors the style of test_libc.c: failures go to real stderr via
 * dprintf. pthread_* here are test-local stubs with the same struct
 * layout (the real pthread.c needs rv64 clone and is target-proven
 * by the linux_demo QEMU run instead).
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdalign.h>
#include <complex.h>
#include <monetary.h>
#include <langinfo.h>
#include <iconv.h>
#include <stdatomic.h>
#include <tgmath.h>
#include <iso646.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/types.h>

/* ---- test-local pthread backing for threads.c ---- */
#include <pthread.h>
#include <errno.h>

int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    (void)a;
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    m->lock = 0;
    m->kind = 0;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *m) {
    (void)m;
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    while (__sync_lock_test_and_set(&m->lock, 1)) {
    }
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    if (__sync_lock_test_and_set(&m->lock, 1)) return EBUSY;
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *m) {
    if (!m) {
        errno = EINVAL;
        return EINVAL;
    }
    __sync_lock_release(&m->lock);
    return 0;
}

int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    (void)a;
    if (!c) {
        errno = EINVAL;
        return EINVAL;
    }
    c->lock = 0;
    c->clocked = 0;
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *c) {
    (void)c;
    return 0;
}

int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    int g;
    if (!c || !m) return EINVAL;
    g = c->clocked;
    pthread_mutex_unlock(m);
    while (c->clocked == g) {
    }
    pthread_mutex_lock(m);
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                           const struct timespec *t) {
    (void)t;
    return pthread_cond_wait(c, m);
}

int pthread_cond_signal(pthread_cond_t *c) {
    if (!c) return EINVAL;
    __sync_fetch_and_add(&c->clocked, 1);
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *c) {
    return pthread_cond_signal(c);
}

static long ml_tss_vals[32];
static int ml_tss_used[32];

int pthread_key_create(pthread_key_t *k, void (*d)(void *)) {
    int i;
    (void)d;
    for (i = 0; i < 32; i++) {
        if (!ml_tss_used[i]) {
            ml_tss_used[i] = 1;
            ml_tss_vals[i] = 0;
            *k = (pthread_key_t)i;
            return 0;
        }
    }
    return EAGAIN;
}

int pthread_key_delete(pthread_key_t k) {
    if (k >= 32) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_tss_used[k] = 0;
    return 0;
}

int pthread_setspecific(pthread_key_t k, const void *v) {
    if (k >= 32) {
        errno = EINVAL;
        return EINVAL;
    }
    ml_tss_vals[k] = (long)v;
    return 0;
}

void *pthread_getspecific(pthread_key_t k) {
    if (k >= 32) return 0;
    return (void *)ml_tss_vals[k];
}

int pthread_once(pthread_once_t *o, void (*f)(void)) {
    if (!o || !f) return EINVAL;
    while (__sync_lock_test_and_set(&o->lock, 1)) {
    }
    if (!o->done) {
        o->done = 1;
        __sync_lock_release(&o->lock);
        f();
    } else {
        __sync_lock_release(&o->lock);
    }
    return 0;
}

#include <threads.h>

extern int dprintf(int fd, const char *fmt, ...);

static int failures = 0;
#define CHECK(cond, why) do { \
    if (!(cond)) { dprintf(2, "FAIL: %s (line %d)\n", why, __LINE__); failures++; } \
} while (0)

static void once_probe(void) {}

int main(void) {
    dprintf(2, "=== test_newlibc ===\n");

    /* freestanding core headers */
    CHECK(sizeof(int32_t) == 4, "i32");
    CHECK(sizeof(int64_t) == 8, "i64");
    CHECK(sizeof(size_t) == 8, "size");
    CHECK(offsetof(struct { char a; int b; }, b) == 4, "offsetof");
    CHECK(alignof(double) == 8, "alignof");
    CHECK(true && !false, "stdbool");

    /* complex */
    {
        double complex z = 1.0 + 2.0 * I;
        CHECK(creal(z) == 1.0, "creal");
        CHECK(cimag(z) == 2.0, "cimag");
        CHECK(cabs(3.0 + 4.0 * I) == 5.0, "cabs 3-4-5");
        CHECK(carg(1.0 + 0.0 * I) == 0.0, "carg");
        {
            double complex e = cexp(0.0 + 0.0 * I);
            CHECK(creal(e) == 1.0 && cimag(e) == 0.0, "cexp 0");
        }
        {
            double complex s = csqrt(-1.0 + 0.0 * I);
            CHECK(cimag(s) == 1.0, "csqrt -1");
        }
        {
            double complex p = cpow(2.0 + 0.0 * I, 3.0 + 0.0 * I);
            CHECK(creal(p) == 8.0, "cpow int path");
        }
        CHECK(crealf(1.0f + 2.0f * I) == 1.0f, "crealf");
        CHECK(cabsf(3.0f + 4.0f * I) == 5.0f, "cabsf");
        {
            float complex s = csqrtf(-1.0f + 0.0f * I);
            CHECK(cimagf(s) == 1.0f, "csqrtf -1");
        }
    }

    /* tgmath + iso646 */
    {
        double v = sqrt(4.0);
        CHECK(v == 2.0, "tgmath sqrt");
        CHECK((1 == 1 and 2 == 2) or (1 == 2), "iso646");
    }

    /* langinfo */
    CHECK(strcmp(nl_langinfo(CODESET), "UTF-8") == 0, "codeset");
    CHECK(strcmp(nl_langinfo(DAY_1), "Sunday") == 0, "day");
    CHECK(strcmp(nl_langinfo(MON_1), "January") == 0, "month");

    /* monetary */
    {
        char b[64];
        ssize_t r = strfmon(b, sizeof(b), "%n", 12.5);
        CHECK(r > 0 && strchr(b, '1') != 0, "strfmon basic");
        r = strfmon(b, sizeof(b), "[%i]", 12.5);
        CHECK(r > 0 && b[0] == '[', "strfmon intl");
    }

    /* iconv */
    {
        iconv_t c = iconv_open("UTF-16LE", "UTF-8");
        CHECK(c != (iconv_t)-1, "iconv open");
        if (c != (iconv_t)-1) {
            char in[] = "A\xC3\xA9";
            char out[16];
            char *ip = in, *op = out;
            size_t il = 3, ol = sizeof(out);
            CHECK(iconv(c, &ip, &il, &op, &ol) != (size_t)-1,
                  "iconv utf8->u16");
            CHECK(il == 0, "iconv consumed");
            iconv_close(c);
        }
    }
    {
        iconv_t c = iconv_open("UTF-8", "UTF-8");
        char bad[] = "\xC0\xAF";
        char out[8];
        char *ip = bad, *op = out;
        size_t il = 2, ol = sizeof(out);
        CHECK(iconv(c, &ip, &il, &op, &ol) == (size_t)-1,
              "iconv overlong EILSEQ");
        iconv_close(c);
    }
    {
        iconv_t c = iconv_open("UTF-8", "UTF-8");
        char trunc[] = "\xE2";
        char out[8];
        char *ip = trunc, *op = out;
        size_t il = 1, ol = sizeof(out);
        CHECK(iconv(c, &ip, &il, &op, &ol) == (size_t)-1,
              "iconv trunc EINVAL");
        iconv_close(c);
    }

    /* atomics */
    {
        atomic_int a = 3;
        atomic_store(&a, 7);
        CHECK(atomic_load(&a) == 7, "atomic store/load");
        CHECK(atomic_fetch_add(&a, 1) == 7 && atomic_load(&a) == 8,
              "atomic fetch_add");
        {
            atomic_flag f = ATOMIC_FLAG_INIT;
            CHECK(!atomic_flag_test_and_set(&f), "flag set");
            atomic_flag_clear(&f);
            CHECK(!atomic_flag_test_and_set(&f), "flag re-set");
        }
    }

    /* C11 threads (mutex/cond/tss/once; spawn needs rv64 clone) */
    {
        mtx_t m;
        cnd_t c;
        tss_t k;
        once_flag o = ONCE_FLAG_INIT;
        CHECK(mtx_init(&m, mtx_plain) == thrd_success, "mtx init");
        CHECK(mtx_lock(&m) == thrd_success, "mtx lock");
        CHECK(mtx_trylock(&m) == thrd_busy, "mtx try busy");
        CHECK(mtx_unlock(&m) == thrd_success, "mtx unlock");
        mtx_destroy(&m);
        CHECK(cnd_init(&c) == thrd_success, "cnd init");
        CHECK(cnd_signal(&c) == thrd_success, "cnd signal");
        cnd_destroy(&c);
        CHECK(tss_create(&k, 0) == thrd_success, "tss create");
        CHECK(tss_set(k, (void *)5) == thrd_success, "tss set");
        CHECK(tss_get(k) == (void *)5, "tss get");
        tss_delete(k);
        call_once(&o, once_probe);
        call_once(&o, once_probe);
    }

    /* sys/queue + sys/param */
    {
        struct E {
            int v;
            STAILQ_ENTRY(E) q;
        };
        STAILQ_HEAD(H, E) h;
        struct E a = {1}, b = {2}, *e;
        int n = 0;
        STAILQ_INIT(&h);
        STAILQ_INSERT_TAIL(&h, &a, q);
        STAILQ_INSERT_TAIL(&h, &b, q);
        STAILQ_FOREACH(e, &h, q) n += e->v;
        CHECK(n == 3, "stailq");
        CHECK(MAXPATHLEN == 256 && MAXNAMLEN == 31, "param");
    }

    if (failures == 0) dprintf(2, "ALL NEWLIBC TESTS PASS\n");
    else dprintf(2, "FAIL: newlibc (%d)\n", failures);
    return failures ? 1 : 0;
}
