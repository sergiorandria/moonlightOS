/* libc termios: TCGETS/TCSETS over the kernel console state, plus
 * the cf/speed helpers and tc* queue controls (real where the line
 * discipline exists, accepted where the virt has no queue). */
#include <termios.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

#define LX_TCGETS 0x5401
#define LX_TCSETS 0x5402

speed_t cfgetispeed(const struct termios *t) {
    if (!t) return 0;
    return 9600; /* stored rate is nominal; see cfsetspeed */
}

speed_t cfgetospeed(const struct termios *t) {
    if (!t) return 0;
    return 9600;
}

int cfsetispeed(struct termios *t, speed_t s) {
    if (!t || s > 115200) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int cfsetospeed(struct termios *t, speed_t s) {
    return cfsetispeed(t, s);
}

int cfsetspeed(struct termios *t, speed_t s) {
    return cfsetispeed(t, s);
}

int tcgetattr(int fd, struct termios *t) {
    long r;
    if (!t) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_call6(LX_SYS_ioctl, (long)fd, LX_TCGETS, (long)t, 0, 0, 0);
    return (int)__ml_ret(r);
}

int tcsetattr(int fd, int action, const struct termios *t) {
    long r;
    if (!t || action < 0 || action > 2) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_call6(LX_SYS_ioctl, (long)fd, LX_TCSETS, (long)t, 0, 0, 0);
    return (int)__ml_ret(r);
}

int tcsendbreak(int fd, int dur) {
    (void)dur;
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    return 0; /* no break signalling on virt UART */
}

int tcdrain(int fd) {
    /* Unbuffered console writes complete at write() return. */
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int tcflush(int fd, int what) {
    if (fd < 0 || what < 0 || what > 2) {
        errno = EINVAL;
        return -1;
    }
    /* Input ring has no userspace-drain op; output is unbuffered.
     * TCIFLUSH on stdin is honored by dropping... nothing (the ring
     * is kernel-owned). Accept, like tcdrain. */
    return 0;
}

int tcflow(int fd, int action) {
    if (fd < 0 || action < 0 || action > 3) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

pid_t tcgetsid(int fd) {
    if (fd < 0 || fd > 2) {
        errno = EBADF;
        return (pid_t)-1;
    }
    return getpid();
}
