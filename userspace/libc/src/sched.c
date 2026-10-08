/* libc sched: affinity (single hart: mask must name CPU 0) and
 * priority range queries. */
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int sched_getaffinity(int pid, unsigned n, void *mask) {
    int me = getpid();
    if (pid != 0 && pid != me) {
        errno = ESRCH;
        return -1;
    }
    if (!mask || n < sizeof(unsigned long)) {
        errno = EINVAL;
        return -1;
    }
    memset(mask, 0, n);
    *(unsigned char *)mask = 1; /* CPU 0 only */
    return 0;
}

int sched_setaffinity(int pid, unsigned n, const void *mask) {
    int me = getpid();
    if (pid != 0 && pid != me) {
        errno = ESRCH;
        return -1;
    }
    if (!mask || n < 1) {
        errno = EINVAL;
        return -1;
    }
    /* Only CPU 0 exists: masks naming it succeed, others fail. */
    if (!(*(const unsigned char *)mask & 1)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sched_get_priority_max(int policy) {
    if (policy < 0 || policy > 2) {
        errno = EINVAL;
        return -1;
    }
    return policy == SCHED_OTHER ? 0 : 99;
}

int sched_get_priority_min(int policy) {
    if (policy < 0 || policy > 2) {
        errno = EINVAL;
        return -1;
    }
    return policy == SCHED_OTHER ? 0 : 1;
}
