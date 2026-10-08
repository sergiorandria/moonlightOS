/* libc ptimer: POSIX per-process timers (timer_create/settime/
 * gettime/getoverrun/delete). One manager thread polls armed timers
 * every millisecond; expiry fires SIGEV_THREAD (callback thread),
 * SIGEV_SIGNAL (raise), or nothing (SIGEV_NONE). Overruns count
 * firings missed while a previous notification was outstanding. */
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define ML_TIMER_MAX 16

typedef struct {
    int used;
    timer_t id;
    int clockid;
    struct sigevent ev;
    struct itimerspec spec;
    long long arm_ns;
    int armed;
    unsigned overruns;
    int firing;
} ml_timer_t;

static ml_timer_t ml_timers[ML_TIMER_MAX];
static int ml_timer_lock = 0;
static int ml_timer_next = 1;
static int ml_timer_thread_on = 0;

static void ml_tm_lock(void) {
    while (__sync_lock_test_and_set(&ml_timer_lock, 1)) {
    }
}

static void ml_tm_unlock(void) { __sync_lock_release(&ml_timer_lock); }

static long long ml_tm_now(int clockid) {
    struct timespec ts;
    if (clock_gettime(clockid, &ts) != 0) return -1;
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static ml_timer_t *ml_tm_lookup(timer_t id) {
    int i;
    for (i = 0; i < ML_TIMER_MAX; i++)
        if (ml_timers[i].used && ml_timers[i].id == id) return &ml_timers[i];
    return 0;
}

static void ml_tm_fire(ml_timer_t *t) {
    if (t->ev.sigev_notify == SIGEV_THREAD &&
        t->ev.sigev_notify_function) {
        pthread_t th;
        pthread_attr_t a;
        union sigval v = t->ev.sigev_value;
        void (*fn)(union sigval) = t->ev.sigev_notify_function;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &a, (void *(*)(void *))fn,
                           v.sival_ptr) != 0)
            fn(v); /* birth failed: run inline, still delivers */
        pthread_attr_destroy(&a);
    } else if (t->ev.sigev_notify == SIGEV_SIGNAL) {
        raise(t->ev.sigev_signo);
    }
}

static void *ml_tm_manager(void *arg) {
    (void)arg;
    for (;;) {
        int i, alive = 0;
        struct timespec sl = {0, 1000000L};
        nanosleep(&sl, 0);
        ml_tm_lock();
        for (i = 0; i < ML_TIMER_MAX; i++) {
            ml_timer_t *t = &ml_timers[i];
            long long now, end;
            if (!t->used || !t->armed) continue;
            alive = 1;
            now = ml_tm_now(t->clockid);
            if (now < 0) continue;
            end = t->arm_ns + t->spec.it_value.tv_sec * 1000000000LL +
                  t->spec.it_value.tv_nsec;
            if (now < end) continue;
            /* Expired. */
            if (t->firing) {
                t->overruns++;
            } else {
                t->firing = 1;
            }
            if (t->spec.it_interval.tv_sec == 0 &&
                t->spec.it_interval.tv_nsec == 0) {
                t->armed = 0;
            } else {
                t->arm_ns = now;
                t->spec.it_value = t->spec.it_interval;
            }
            ml_tm_unlock();
            ml_tm_fire(t);
            ml_tm_lock();
            t->firing = 0;
        }
        (void)alive;
        ml_tm_unlock();
    }
    return 0;
}

static void ml_tm_ensure(void) {
    if (ml_timer_thread_on) return;
    {
        pthread_t th;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &a, ml_tm_manager, 0) == 0)
            ml_timer_thread_on = 1;
        pthread_attr_destroy(&a);
    }
}

int timer_create(int clockid, struct sigevent *ev, timer_t *id) {
    int i;
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC &&
        clockid != CLOCK_BOOTTIME && clockid != CLOCK_PROCESS_CPUTIME_ID) {
        errno = EINVAL;
        return -1;
    }
    if (!id) {
        errno = EINVAL;
        return -1;
    }
    if (ev && ev->sigev_notify != SIGEV_NONE &&
        ev->sigev_notify != SIGEV_SIGNAL &&
        ev->sigev_notify != SIGEV_THREAD) {
        errno = EINVAL;
        return -1;
    }
    ml_tm_lock();
    for (i = 0; i < ML_TIMER_MAX; i++) {
        if (!ml_timers[i].used) {
            memset(&ml_timers[i], 0, sizeof(ml_timers[i]));
            ml_timers[i].used = 1;
            ml_timers[i].id = ml_timer_next++;
            ml_timers[i].clockid = clockid;
            if (ev) ml_timers[i].ev = *ev;
            else ml_timers[i].ev.sigev_notify = SIGEV_SIGNAL;
            if (!ev) ml_timers[i].ev.sigev_signo = SIGALRM;
            *id = ml_timers[i].id;
            ml_tm_unlock();
            ml_tm_ensure();
            return 0;
        }
    }
    ml_tm_unlock();
    errno = EAGAIN;
    return -1;
}

int timer_settime(timer_t id, int flags, const struct itimerspec *newv,
                  struct itimerspec *oldv) {
    ml_timer_t *t;
    long long now;
    if (!newv || (flags & ~TIMER_ABSTIME)) {
        errno = EINVAL;
        return -1;
    }
    if (newv->it_value.tv_nsec < 0 || newv->it_value.tv_nsec >= 1000000000L ||
        newv->it_interval.tv_nsec < 0 ||
        newv->it_interval.tv_nsec >= 1000000000L ||
        newv->it_value.tv_sec < 0 || newv->it_interval.tv_sec < 0) {
        errno = EINVAL;
        return -1;
    }
    ml_tm_lock();
    t = ml_tm_lookup(id);
    if (!t) {
        ml_tm_unlock();
        errno = EINVAL;
        return -1;
    }
    now = ml_tm_now(t->clockid);
    if (now < 0) {
        ml_tm_unlock();
        return -1;
    }
    if (oldv) {
        *oldv = t->spec;
        if (t->armed) {
            long long left = (t->arm_ns + t->spec.it_value.tv_sec * 1000000000LL +
                              t->spec.it_value.tv_nsec) -
                             now;
            if (left < 0) left = 0;
            oldv->it_value.tv_sec = (time_t)(left / 1000000000LL);
            oldv->it_value.tv_nsec = (long)(left % 1000000000LL);
        } else {
            oldv->it_value.tv_sec = 0;
            oldv->it_value.tv_nsec = 0;
        }
    }
    t->spec = *newv;
    t->overruns = 0;
    if (flags & TIMER_ABSTIME) {
        long long abs_ns = newv->it_value.tv_sec * 1000000000LL +
                           newv->it_value.tv_nsec;
        long long rel = abs_ns - now;
        if (rel < 1) rel = 1;
        t->spec.it_value.tv_sec = (time_t)(rel / 1000000000LL);
        t->spec.it_value.tv_nsec = (long)(rel % 1000000000LL);
    }
    if (t->spec.it_value.tv_sec == 0 && t->spec.it_value.tv_nsec == 0) {
        t->armed = 0;
    } else {
        t->armed = 1;
        t->arm_ns = now;
    }
    ml_tm_unlock();
    ml_tm_ensure();
    return 0;
}

int timer_gettime(timer_t id, struct itimerspec *cur) {
    ml_timer_t *t;
    long long now;
    if (!cur) {
        errno = EINVAL;
        return -1;
    }
    ml_tm_lock();
    t = ml_tm_lookup(id);
    if (!t) {
        ml_tm_unlock();
        errno = EINVAL;
        return -1;
    }
    *cur = t->spec;
    if (!t->armed) {
        cur->it_value.tv_sec = 0;
        cur->it_value.tv_nsec = 0;
        ml_tm_unlock();
        return 0;
    }
    now = ml_tm_now(t->clockid);
    {
        long long left =
            (t->arm_ns + t->spec.it_value.tv_sec * 1000000000LL +
             t->spec.it_value.tv_nsec) -
            now;
        if (left < 0) left = 0;
        cur->it_value.tv_sec = (time_t)(left / 1000000000LL);
        cur->it_value.tv_nsec = (long)(left % 1000000000LL);
    }
    ml_tm_unlock();
    return 0;
}

int timer_getoverrun(timer_t id) {
    ml_timer_t *t;
    unsigned o;
    ml_tm_lock();
    t = ml_tm_lookup(id);
    if (!t) {
        ml_tm_unlock();
        errno = EINVAL;
        return -1;
    }
    o = t->overruns > 99 ? 99 : t->overruns;
    ml_tm_unlock();
    return (int)o;
}

int timer_delete(timer_t id) {
    ml_timer_t *t;
    ml_tm_lock();
    t = ml_tm_lookup(id);
    if (!t) {
        ml_tm_unlock();
        errno = EINVAL;
        return -1;
    }
    memset(t, 0, sizeof(*t));
    ml_tm_unlock();
    return 0;
}
