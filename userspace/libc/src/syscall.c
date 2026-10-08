/* libc syscall: public variadic system-call gateway over the
 * raw ecall layer (numbers from kernel linux_abi.h). */
#include <sys/syscall.h>
#include <stdarg.h>
#include <bits/ml_sys.h>

long syscall(long nr, ...) {
    va_list ap;
    long a0, a1, a2, a3, a4, a5;
    va_start(ap, nr);
    a0 = va_arg(ap, long);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    va_end(ap);
    return __ml_raw6(nr, a0, a1, a2, a3, a4, a5);
}
