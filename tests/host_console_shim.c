/* host_console_shim: host-only test helper (never linked into rv64 ELFs).
 *
 * Host unit tests link the REAL libc I/O paths (unistd.c/file.c write),
 * whose final transport is a kernel ecall that can only return -ENOSYS
 * on the build machine. That would silence every dprintf diagnostic and
 * make failures invisible. This shim overrides the weak managed-fd hooks
 * so console fds 0/1/2 reach the build machine's real console via a raw
 * host syscall (no libc call: at link time plain write() would resolve
 * to the code under test and recurse); every other fd returns -2
 * (ML_FD_PASSTHROUGH), leaving libc's validation and ENOSYS behavior
 * exactly as tested.
 */
#include <stddef.h>
#include <sys/types.h>

#ifdef __x86_64__
static long ml_host_syscall3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}
#endif

__attribute__((weak)) ssize_t __ml_fd_write(int fd, const void *buf, size_t n) {
#ifdef __x86_64__
    if (fd >= 0 && fd <= 2)
        return ml_host_syscall3(1 /* SYS_write */, fd, (long)buf,
                                (long)n);
#else
    (void)buf;
    (void)n;
#endif
    (void)fd;
    return -2;
}

__attribute__((weak)) ssize_t __ml_fd_read(int fd, void *buf, size_t n) {
    (void)fd;
    (void)buf;
    (void)n;
    return -2;
}

__attribute__((weak)) int __ml_fd_close(int fd) {
    (void)fd;
    return -2;
}

__attribute__((weak)) off_t __ml_fd_lseek(int fd, off_t off, int whence) {
    (void)fd;
    (void)off;
    (void)whence;
    return -2;
}
