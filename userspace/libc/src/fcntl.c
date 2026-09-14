/* libc fcntl: F_DUPFD/FD/FL commands, flock, ioctl over the Linux
 * personality. All paths execute real kernel ops (dup shares the file
 * description, NONBLOCK/APPEND/CLOEXEC bits persist in the fd table). */
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <errno.h>
#include <bits/ml_sys.h>
#include <bits/ml_fd.h>
long __ml_ret(long r);

__attribute__((weak)) int __ml_fd_getfl(int fd, int *flags);
__attribute__((weak)) int __ml_fd_setfl(int fd, int flags);
__attribute__((weak)) int __ml_fd_ioctl(int fd, unsigned req, void *arg);

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    long arg = 0;
    va_start(ap, cmd);
    /* POSIX passes an int for the value commands (F_DUPFD, F_SETFD,
     * F_SETFL): read int, not long — on LP64 hosts a long read would
     * consume 4 undefined upper bytes from the caller-passed int
     * (x86_64 SysV leaves them garbage), corrupting validation.
     * Lock commands take struct flock * (forwarded to the kernel). */
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC || cmd == F_SETFD ||
        cmd == F_SETFL)
        arg = (long)va_arg(ap, int);
    else if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW)
        arg = (long)va_arg(ap, struct flock *);
    va_end(ap);
    /* Validate here so a bad cmd/arg fails without a syscall (and
     * identically on host-sim, where the syscall is ENOSYS). */
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        if (fd < 0 || arg < 0) {
            errno = EINVAL;
            return -1;
        }
    } else if (cmd == F_SETFD) {
        if ((arg & ~FD_CLOEXEC) != 0) {
            errno = EINVAL;
            return -1;
        }
    } else if (cmd == F_SETFL) {
        if ((arg & ~(O_NONBLOCK | O_APPEND)) != 0) {
            errno = EINVAL;
            return -1;
        }
    }
    if ((cmd == F_GETFL || cmd == F_GETFD) && __ml_fd_getfl) {
        int flags = 0, r = __ml_fd_getfl(fd, &flags);
        if (r != -2) return r;
    }
    if ((cmd == F_SETFL || cmd == F_SETFD) && __ml_fd_setfl) {
        int r = __ml_fd_setfl(fd, (int)arg);
        if (r != -2) return r;
    }
    return (int)__ml_ret(__ML_SYS3(LX_SYS_fcntl, fd, cmd, arg));
}

int flock(int fd, int op) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_flock, fd, op));
}

int ioctl(int fd, unsigned req, ...) {
    va_list ap;
    void *arg = 0;
    va_start(ap, req);
    /* All supported ioctls take a pointer (FIONREAD, TIOCGWINSZ,
     * TIOCSWINSZ, TCGETS, TCSETS). */
    if (req == FIONREAD || req == TIOCGWINSZ || req == TIOCSWINSZ ||
        req == 0x5401 || req == 0x5402)
        arg = va_arg(ap, void *);
    va_end(ap);
    if (__ml_fd_ioctl) {
        int r = __ml_fd_ioctl(fd, req, arg);
        if (r != -2) return r;
    }
    return (int)__ml_ret(__ML_SYS3(LX_SYS_ioctl, fd, req, arg));
}
