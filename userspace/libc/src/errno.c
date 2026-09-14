/* libc errno + raw-return folding. */
#include <errno.h>
#include <bits/ml_sys.h>

int errno;

int *__errno_location(void) { return &errno; }

long __ml_ret(long r) {
    if (r < 0 && r >= -4095) {
        errno = (int)-r;
        return -1;
    }
    return r;
}

long __ml_call6(long nr, long a0, long a1, long a2, long a3, long a4,
                long a5) {
    /* Bounded EAGAIN retry (see ml_sys.h). The yield is the ungated
     * cooperative path: it always runs, so replenish can land. */
    int i;
    long r = __ml_raw6(nr, a0, a1, a2, a3, a4, a5);
    for (i = 0; i < 8 && r == -LX_EAGAIN; i++) {
        __ml_raw6(LX_SYS_sched_yield, 0, 0, 0, 0, 0, 0);
        r = __ml_raw6(nr, a0, a1, a2, a3, a4, a5);
    }
    return r;
}
