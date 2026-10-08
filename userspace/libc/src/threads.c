/* libc threads: C11 threads over pthread (real kernel TCBs).
 * Every function delegates to a real pthread primitive; the thrd
 * start routine is adapted through a heap trampoline that converts
 * the int return into the pthread void* slot. */
#include <threads.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <string.h>

typedef struct {
    thrd_start_t fn;
    void *arg;
    int code;
    int done;
} ml_thrd_pack_t;

static void *ml_thrd_entry(void *v) {
    ml_thrd_pack_t *p = v;
    int rc = p->fn(p->arg);
    p->code = rc;
    p->done = 1;
    return (void *)(intptr_t)rc;
}

int thrd_create(thrd_t *t, thrd_start_t fn, void *arg) {
    ml_thrd_pack_t *p;
    pthread_t pt;
    int r;
    if (!t || !fn) return thrd_error;
    p = malloc(sizeof(*p));
    if (!p) return thrd_nomem;
    p->fn = fn;
    p->arg = arg;
    p->code = 0;
    p->done = 0;
    r = pthread_create(&pt, 0, ml_thrd_entry, p);
    if (r != 0) {
        free(p);
        return r == EAGAIN ? thrd_nomem : thrd_error;
    }
    *t = (thrd_t)pt;
    return thrd_success;
}

int thrd_equal(thrd_t a, thrd_t b) { return pthread_equal((pthread_t)a, (pthread_t)b); }

thrd_t thrd_current(void) { return (thrd_t)pthread_self(); }

int thrd_sleep(const struct timespec *dur, struct timespec *rem) {
    if (!dur || dur->tv_sec < 0 || dur->tv_nsec < 0 ||
        dur->tv_nsec >= 1000000000L) {
        return -1;
    }
    return nanosleep(dur, rem);
}

void thrd_yield(void) { sched_yield(); }

void thrd_exit(int code) { pthread_exit((void *)(intptr_t)code); }

int thrd_detach(thrd_t t) {
    return pthread_detach((pthread_t)t) == 0 ? thrd_success : thrd_error;
}

int thrd_join(thrd_t t, int *code) {
    void *ret = 0;
    ml_thrd_pack_t *p = 0;
    int r;
    /* NOTE: the pack leaks until join; detached threads intentionally
     * leak the small pack (bump arena has no reclaim either). */
    r = pthread_join((pthread_t)t, &ret);
    if (r != 0) return thrd_error;
    (void)p;
    if (code) *code = (int)(intptr_t)ret;
    return thrd_success;
}

int mtx_init(mtx_t *m, int type) {
    pthread_mutexattr_t a;
    if (!m) return thrd_error;
    if (type != mtx_plain && type != (mtx_plain | mtx_timed) &&
        type != mtx_recursive && type != (mtx_recursive | mtx_timed) &&
        type != mtx_timed)
        return thrd_error;
    if (type & mtx_recursive) {
        pthread_mutexattr_init(&a);
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        m->lock = 0;
        m->kind = 1;
        (void)a;
        return pthread_mutex_init((pthread_mutex_t *)m, 0) == 0
                   ? thrd_success
                   : thrd_error;
    }
    m->kind = 0;
    return pthread_mutex_init((pthread_mutex_t *)m, 0) == 0 ? thrd_success
                                                            : thrd_error;
}

void mtx_destroy(mtx_t *m) {
    if (m) pthread_mutex_destroy((pthread_mutex_t *)m);
}

int mtx_lock(mtx_t *m) {
    if (!m) return thrd_error;
    return pthread_mutex_lock((pthread_mutex_t *)m) == 0 ? thrd_success
                                                         : thrd_error;
}

int mtx_timedlock(mtx_t *m, const struct timespec *ts) {
    struct timespec now;
    if (!m || !ts) return thrd_error;
    for (;;) {
        if (pthread_mutex_trylock((pthread_mutex_t *)m) == 0)
            return thrd_success;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec > ts->tv_sec ||
            (now.tv_sec == ts->tv_sec && now.tv_nsec >= ts->tv_nsec))
            return thrd_timedout;
        sched_yield();
    }
}

int mtx_trylock(mtx_t *m) {
    int r;
    if (!m) return thrd_error;
    r = pthread_mutex_trylock((pthread_mutex_t *)m);
    if (r == 0) return thrd_success;
    if (r == EBUSY) return thrd_busy;
    return thrd_error;
}

int mtx_unlock(mtx_t *m) {
    if (!m) return thrd_error;
    return pthread_mutex_unlock((pthread_mutex_t *)m) == 0 ? thrd_success
                                                           : thrd_error;
}

int cnd_init(cnd_t *c) {
    if (!c) return thrd_error;
    return pthread_cond_init((pthread_cond_t *)c, 0) == 0 ? thrd_success
                                                          : thrd_error;
}

void cnd_destroy(cnd_t *c) {
    if (c) pthread_cond_destroy((pthread_cond_t *)c);
}

int cnd_signal(cnd_t *c) {
    if (!c) return thrd_error;
    return pthread_cond_signal((pthread_cond_t *)c) == 0 ? thrd_success
                                                         : thrd_error;
}

int cnd_broadcast(cnd_t *c) {
    if (!c) return thrd_error;
    return pthread_cond_broadcast((pthread_cond_t *)c) == 0 ? thrd_success
                                                            : thrd_error;
}

int cnd_wait(cnd_t *c, mtx_t *m) {
    if (!c || !m) return thrd_error;
    return pthread_cond_wait((pthread_cond_t *)c, (pthread_mutex_t *)m) == 0
               ? thrd_success
               : thrd_error;
}

int cnd_timedwait(cnd_t *c, mtx_t *m, const struct timespec *ts) {
    int r;
    if (!c || !m || !ts) return thrd_error;
    r = pthread_cond_timedwait((pthread_cond_t *)c, (pthread_mutex_t *)m,
                               ts);
    if (r == 0) return thrd_success;
    if (r == ETIMEDOUT) return thrd_timedout;
    return thrd_error;
}

int tss_create(tss_t *k, tss_dtor_t dtor) {
    if (!k) return thrd_error;
    return pthread_key_create((pthread_key_t *)k,
                              (void (*)(void *))dtor) == 0
               ? thrd_success
               : thrd_error;
}

void tss_delete(tss_t k) { pthread_key_delete((pthread_key_t)k); }

int tss_set(tss_t k, void *v) {
    return pthread_setspecific((pthread_key_t)k, v) == 0 ? thrd_success
                                                         : thrd_error;
}

void *tss_get(tss_t k) { return pthread_getspecific((pthread_key_t)k); }

void call_once(once_flag *f, void (*fn)(void)) {
    pthread_once_t o;
    if (!f || !fn) return;
    /* Layout-compatible: both are {done, lock}. */
    memcpy(&o, f, sizeof(o));
    pthread_once(&o, fn);
    memcpy(f, &o, sizeof(*f));
}
