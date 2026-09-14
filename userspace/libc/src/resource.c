/* libc resource: rlimits (real stored table), getrusage (heap
 * high-water + tick clock), times, priorities (single user). */
#include <sys/resource.h>
#include <sys/times.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

static struct rlimit ml_limits[16] = {
    {RLIM_INFINITY, RLIM_INFINITY}, /* CPU */
    {RLIM_INFINITY, RLIM_INFINITY}, /* FSIZE */
    {RLIM_INFINITY, RLIM_INFINITY}, /* DATA */
    {8 * 1024 * 1024, RLIM_INFINITY}, /* STACK */
    {0, 0}, /* CORE */
    {RLIM_INFINITY, RLIM_INFINITY}, /* RSS */
    {0, 0},
    {16, 16}, /* NOFILE */
    {0, 0},
    {RLIM_INFINITY, RLIM_INFINITY}, /* AS */
};

int getrlimit(int res, struct rlimit *r) {
    if (!r || res < 0 || res > 9) {
        errno = EINVAL;
        return -1;
    }
    *r = ml_limits[res];
    return 0;
}

int setrlimit(int res, const struct rlimit *r) {
    if (!r || res < 0 || res > 9) {
        errno = EINVAL;
        return -1;
    }
    if (r->rlim_cur > r->rlim_max) {
        errno = EINVAL;
        return -1;
    }
    ml_limits[res] = *r;
    return 0;
}

int getrusage(int who, struct rusage *r) {
    struct timespec ts;
    /* Image end from the linker script (weak: host unit tests link
     * without user.ld, so guard for NULL). */
    extern char _user_end[] __attribute__((weak));
    if (!r || (who != RUSAGE_SELF && who != RUSAGE_CHILDREN)) {
        errno = EINVAL;
        return -1;
    }
    memset(r, 0, sizeof(*r));
    if (who == RUSAGE_CHILDREN) return 0; /* no reaped stats kept */
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0) {
        r->ru_utime.tv_sec = ts.tv_sec;
        r->ru_utime.tv_usec = ts.tv_nsec / 1000;
    }
    /* maxrss: current break minus image end, in KiB. */
    {
        long brk = __ml_call6(LX_SYS_brk, 0, 0, 0, 0, 0, 0);
        if (_user_end && brk > (long)_user_end)
            r->ru_maxrss = (brk - (long)_user_end) / 1024;
    }
    return 0;
}

clock_t times(struct tms *t) {
    struct timespec ts;
    long long ticks;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return (clock_t)-1;
    ticks = ts.tv_sec * 100 + ts.tv_nsec / 10000000L;
    if (t) {
        t->tms_utime = (clock_t)ticks;
        t->tms_stime = 0;
        t->tms_cutime = 0;
        t->tms_cstime = 0;
    }
    return (clock_t)ticks;
}

int getpriority(int which, id_t who) {
    (void)who;
    if (which < 0 || which > 2) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int setpriority(int which, id_t who, int prio) {
    (void)who;
    (void)prio;
    if (which < 0 || which > 2) {
        errno = EINVAL;
        return -1;
    }
    /* Single scheduling class: accept, like nice() succeeding. */
    return 0;
}

/* ---- ulimit (file-size limit via the rlimit table) ---- */

#include <ulimit.h>
#include <stdarg.h>

long ulimit(int cmd, ...) {
    va_list ap;
    long v = 0;
    va_start(ap, cmd);
    if (cmd == UL_SETFSIZE) v = va_arg(ap, long);
    va_end(ap);
    if (cmd == UL_GETFSIZE) {
        struct rlimit r;
        if (getrlimit(RLIMIT_FSIZE, &r) != 0) return -1;
        if (r.rlim_cur == RLIM_INFINITY) return 16384; /* blocks */
        return (long)(r.rlim_cur / 512);
    }
    if (cmd == UL_SETFSIZE) {
        struct rlimit r;
        if (v < 0) {
            errno = EINVAL;
            return -1;
        }
        r.rlim_cur = r.rlim_max = (rlim_t)v * 512;
        if (setrlimit(RLIMIT_FSIZE, &r) != 0) return -1;
        return 0;
    }
    errno = EINVAL;
    return -1;
}
