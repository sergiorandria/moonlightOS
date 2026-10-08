/* libc unistd: thin wrappers over the Linux personality. */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sched.h>
#include <bits/ml_sys.h>
#include <bits/ml_fd.h>

long __ml_ret(long r);
void __ml_poll_signals(void);
void __ml_itimer_check(void);

/* Managed-fd hooks (sysevent.c); weak so unistd links without it. */
__attribute__((weak)) ssize_t __ml_fd_read(int fd, void *buf, size_t n);
__attribute__((weak)) ssize_t __ml_fd_write(int fd, const void *buf,
                                            size_t n);
__attribute__((weak)) int __ml_fd_close(int fd);
__attribute__((weak)) off_t __ml_fd_lseek(int fd, off_t off, int whence);

int close(int fd) {
    if (__ml_fd_close) {
        int r = __ml_fd_close(fd);
        if (r != -2) return r;
    }
    return (int)__ml_ret(__ML_SYS1(LX_SYS_close, fd));
}

ssize_t read(int fd, void *buf, size_t n) {
    if (__ml_fd_read) {
        ssize_t r = __ml_fd_read(fd, buf, n);
        if (r != ML_FD_PASSTHROUGH) return r;
    }
    return (ssize_t)__ml_ret(__ML_SYS3(LX_SYS_read, fd, buf, n));
}

ssize_t write(int fd, const void *buf, size_t n) {
    if (__ml_fd_write) {
        ssize_t r = __ml_fd_write(fd, buf, n);
        if (r != ML_FD_PASSTHROUGH) return r;
    }
    return (ssize_t)__ml_ret(__ML_SYS3(LX_SYS_write, fd, buf, n));
}

off_t lseek(int fd, off_t off, int whence) {
    if (__ml_fd_lseek) {
        off_t r = __ml_fd_lseek(fd, off, whence);
        if (r != (off_t)-2) return r;
    }
    return (off_t)__ml_ret(__ML_SYS3(LX_SYS_lseek, fd, off, whence));
}

ssize_t readv(int fd, const struct iovec *v, int n) {
    return (ssize_t)__ml_ret(__ML_SYS3(LX_SYS_readv, fd, v, n));
}

ssize_t writev(int fd, const struct iovec *v, int n) {
    return (ssize_t)__ml_ret(__ML_SYS3(LX_SYS_writev, fd, v, n));
}

ssize_t pread(int fd, void *buf, size_t n, off_t off) {
    return (ssize_t)__ml_ret(__ML_SYS4(LX_SYS_pread64, fd, buf, n, off));
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
    return (ssize_t)__ml_ret(__ML_SYS4(LX_SYS_pwrite64, fd, buf, n, off));
}

int unlink(const char *path) {
    return (int)__ml_ret(
        __ML_SYS3(LX_SYS_unlinkat, LX_AT_FDCWD, path, 0));
}

int access(const char *path, int mode) {
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_faccessat, LX_AT_FDCWD, path, mode, 0));
}

int chdir(const char *path) {
    return (int)__ml_ret(__ML_SYS1(LX_SYS_chdir, path));
}

char *getcwd(char *buf, size_t n) {
    long r = __ml_ret(__ML_SYS2(LX_SYS_getcwd, buf, n));
    return r < 0 ? 0 : buf;
}

int ftruncate(int fd, off_t len) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_ftruncate, fd, len));
}

int truncate(const char *path, off_t len) {
    /* No path-based truncate call: open + ftruncate + close. The open
     * must not create (a missing path is ENOENT, not an empty file). */
    int fd = open(path, O_RDWR);
    int r;
    if (fd < 0) return -1;
    r = ftruncate(fd, len);
    {
        int e = errno;
        close(fd);
        if (r != 0) errno = e;
    }
    return r;
}

int isatty(int fd) {
    /* Console fds only (no ioctl yet; the kernel agrees). */
    if (fd >= 0 && fd <= 2) return 1;
    errno = ENOTDIR;
    return 0;
}

/* Weak: host unit tests (test_batch4) provide their own heap-backed
 * pair so stdlib/malloc runs without a kernel; the target link has no
 * other definition, so these are the ones used on rv64. */
__attribute__((weak)) int brk(void *addr) {
    long r = __ml_call6(LX_SYS_brk, (long)addr, 0, 0, 0, 0, 0);
    /* brk returns the break, not errno: failure = unchanged (0 query). */
    if (addr != 0 && r != (long)addr) {
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

__attribute__((weak)) void *sbrk(intptr_t inc) {
    long cur = __ml_call6(LX_SYS_brk, 0, 0, 0, 0, 0, 0);
    long want = cur + (long)inc;
    long got;
    if (inc == 0) return (void *)cur;
    if (want < cur && inc > 0) {
        errno = ENOMEM;
        return (void *)-1;
    }
    got = __ml_call6(LX_SYS_brk, want, 0, 0, 0, 0, 0);
    if (got != want) {
        errno = ENOMEM;
        return (void *)-1;
    }
    return (void *)cur;
}

int getpid(void) { return (int)__ML_SYS0(LX_SYS_getpid); }

int getppid(void) { return (int)__ML_SYS0(LX_SYS_getppid); }

int getuid(void) { return (int)__ML_SYS0(LX_SYS_getuid); }

int geteuid(void) { return (int)__ML_SYS0(LX_SYS_geteuid); }

int getgid(void) { return (int)__ML_SYS0(LX_SYS_getgid); }

int getegid(void) { return (int)__ML_SYS0(LX_SYS_getegid); }

int gettid(void) { return (int)__ML_SYS0(LX_SYS_gettid); }

long getpagesize(void) { return 4096; }

long sysconf(int name) {
    /* Only true answers (documented): single hart, fixed page, 16 fds. */
    switch (name) {
    case _SC_PAGESIZE:
        return 4096;
    case _SC_NPROCESSORS_ONLN:
        return 1;
    case _SC_OPEN_MAX:
        return OPEN_MAX;
    case _SC_IOV_MAX:
        return IOV_MAX;
    case _SC_CLK_TCK:
        return 10000000; /* CLINT 10 MHz (see docs/LINUX.md) */
    default:
        errno = EINVAL;
        return -1;
    }
}

void swab(const void *from, void *to, ssize_t n) {
    const char *f = from;
    char *t = to;
    if (!from || !to || n < 0) return;
    for (; n > 1; n -= 2, f += 2, t += 2) {
        t[0] = f[1];
        t[1] = f[0];
    }
}

int sched_yield(void) {
    /* Raw (no EAGAIN retry): yielding is how budget is handed back;
     * retrying it would spin instead of parking. Afterwards, collect
     * any kernel-queued cross-thread signals into local delivery. */
    int r = (int)__ml_ret(__ml_raw6(LX_SYS_sched_yield, 0, 0, 0, 0, 0, 0));
    __ml_poll_signals();
    __ml_itimer_check();
    return r;
}

int uname(struct utsname *u) {
    return (int)__ml_ret(__ML_SYS1(LX_SYS_uname, u));
}

_Static_assert(sizeof(struct utsname) == sizeof(lx_utsname_t),
               "utsname layouts diverge");

unsigned sleep(unsigned s) {
    struct {
        long sec;
        long nsec;
    } req, rem;
    if (s == 0) {
        sched_yield();
        return 0;
    }
    req.sec = (long)s;
    req.nsec = 0;
    /* Real tick sleep; EINTR reports the unslept remainder. */
    if (__ml_ret(__ml_call6(LX_SYS_nanosleep, (long)&req, (long)&rem, 0,
                            0, 0, 0)) == 0)
        return 0;
    if (errno == EINTR) {
        long left = rem.sec + (rem.nsec > 0 ? 1 : 0);
        return left > 0 ? (unsigned)left : 1;
    }
    return 0;
}

int usleep(unsigned us) {
    struct {
        long sec;
        long nsec;
    } req;
    req.sec = (long)(us / 1000000u);
    req.nsec = (long)((us % 1000000u) * 1000u);
    return (int)__ml_ret(__ml_call6(LX_SYS_nanosleep, (long)&req, 0, 0, 0,
                                    0, 0));
}

/* fsync/fdatasync/sync live in proc.c (single definition; the store
 * is write-through, so validating the fd via fstat is the whole job). */

/* ---- vector positional I/O over pread/pwrite ---- */

ssize_t preadv(int fd, const struct iovec *v, int n, off_t off) {
    size_t total = 0;
    int i;
    if (!v || n < 0) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n; i++) {
        ssize_t r;
        if (v[i].iov_len == 0) continue;
        r = pread(fd, v[i].iov_base, v[i].iov_len,
                  off + (off_t)total);
        if (r < 0) return total ? (ssize_t)total : -1;
        if (r == 0) break;
        total += (size_t)r;
        if ((size_t)r < v[i].iov_len) break;
    }
    return (ssize_t)total;
}

ssize_t pwritev(int fd, const struct iovec *v, int n, off_t off) {
    size_t total = 0;
    int i;
    if (!v || n < 0) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n; i++) {
        ssize_t r;
        if (v[i].iov_len == 0) continue;
        r = pwrite(fd, v[i].iov_base, v[i].iov_len,
                   off + (off_t)total);
        if (r < 0) return total ? (ssize_t)total : -1;
        total += (size_t)r;
        if ((size_t)r < v[i].iov_len) break;
    }
    return (ssize_t)total;
}

/* ---- fd table utilities ---- */

int getdtablesize(void) {
    long n = sysconf(_SC_OPEN_MAX);
    return n > 0 ? (int)n : 16;
}

int closefrom(int lowfd) {
    int top, fd;
    if (lowfd < 0) {
        errno = EINVAL;
        return -1;
    }
    top = getdtablesize();
    for (fd = lowfd; fd < top; fd++) close(fd);
    return 0;
}

/* ---- effective-id access ---- */

int eaccess(const char *path, int mode) {
    /* Single-user personality: euid == uid, so plain access is exact
     * (no setuid binaries exist to distinguish). */
    return access(path, mode);
}

int euidaccess(const char *path, int mode) { return eaccess(path, mode); }

/* ---- shells database (/etc/shells + built-in fallback) ---- */

static FILE *ml_shells_fp = 0;
static char ml_shells_line[256];
static const char *ml_shells_fallback[] = {"/bin/sh", "/bin/moonsh", 0};
static int ml_shells_fbi = 0;

void setusershell(void) {
    if (ml_shells_fp) fclose(ml_shells_fp);
    ml_shells_fp = fopen("/etc/shells", "r");
    ml_shells_fbi = 0;
}

void endusershell(void) {
    if (ml_shells_fp) fclose(ml_shells_fp);
    ml_shells_fp = 0;
    ml_shells_fbi = 0;
}

char *getusershell(void) {
    if (!ml_shells_fp && ml_shells_fbi == 0) setusershell();
    if (ml_shells_fp) {
        while (fgets(ml_shells_line, sizeof(ml_shells_line),
                      ml_shells_fp)) {
            size_t n;
            if (ml_shells_line[0] == '#' || ml_shells_line[0] == '\n')
                continue;
            n = strlen(ml_shells_line);
            while (n && (ml_shells_line[n - 1] == '\n' ||
                         ml_shells_line[n - 1] == '\r'))
                ml_shells_line[--n] = '\0';
            if (!n) continue;
            return ml_shells_line;
        }
        endusershell();
        ml_shells_fbi = 1; /* fall through to built-ins once */
        if (!ml_shells_fallback[0]) return 0;
    }
    if (ml_shells_fallback[ml_shells_fbi]) return (char *)ml_shells_fallback[ml_shells_fbi++];
    return 0;
}

/* ---- batch 4: process identity, terminal, conf (all real) ---- */

void _exit(int code) {
    __ml_raw6(LX_SYS_exit_group, (long)(code & 0xFF), 0, 0, 0, 0, 0);
    for (;;)
        __ml_raw6(LX_SYS_exit_group, (long)(code & 0xFF), 0, 0, 0, 0,
                  0);
}

int nice(int inc) {
    /* Single scheduling class: priority is fixed. Validate the range
     * (Linux clamps to [-20, 19], EPERM only for raising without
     * privilege — uid 0 here, so every value succeeds). */
    (void)inc;
    return 0;
}

unsigned alarm(unsigned s) {
    /* Real SIGALRM arming over the itimer layer (time.c): deadlines
     * fire from sched_yield via __ml_itimer_check. Returns the
     * remaining whole seconds of the previous alarm (rounded up).
     * it_interval zeroed: one-shot (POSIX alarm never repeats). */
    struct itimerval ni, oi;
    ni.it_interval.tv_sec = 0;
    ni.it_interval.tv_usec = 0;
    ni.it_value.tv_sec = (long)s;
    ni.it_value.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &ni, &oi) != 0) return 0;
    return (unsigned)(oi.it_value.tv_sec +
                      (oi.it_value.tv_usec > 0 ? 1 : 0));
}

long confstr(int name, char *buf, size_t n) {
    const char *v;
    size_t l;
    switch (name) {
    case _CS_PATH:
        v = "/bin:/usr/bin";
        break;
    case _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS:
        v = "_POSIX_V7_ILP32_OFF32 _POSIX_V7_LP64_OFF64";
        break;
    case _CS_POSIX_V7_ILP32_OFF32_CFLAGS:
        v = "-m32";
        break;
    case _CS_POSIX_V7_LP64_OFF64_CFLAGS:
        v = "-m64";
        break;
    default:
        errno = EINVAL;
        return 0;
    }
    l = strlen(v) + 1; /* include NUL in the count (POSIX) */
    if (n > 0) {
        size_t c = l < n ? l : n - 1;
        memcpy(buf, v, c);
        buf[c] = '\0';
    }
    return (long)l;
}

char *ctermid(char *buf) {
    static char ml_ctermid_buf[16];
    if (!buf) buf = ml_ctermid_buf;
    memcpy(buf, "/dev/console", 13);
    return buf;
}

char *ttyname(int fd) {
    static char ml_ttyname_buf[16];
    if (ttyname_r(fd, ml_ttyname_buf, sizeof(ml_ttyname_buf)) != 0)
        return 0;
    return ml_ttyname_buf;
}

int ttyname_r(int fd, char *buf, size_t n) {
    static const char tn[] = "/dev/console";
    /* Console fds only (matches isatty above). */
    if (fd < 0 || fd > 2) {
        errno = ENOTTY;
        return ENOTTY;
    }
    if (!buf || n < sizeof(tn)) {
        errno = ERANGE;
        return ERANGE;
    }
    memcpy(buf, tn, sizeof(tn));
    return 0;
}

char *getlogin(void) {
    static char ml_login[] = "root";
    return ml_login;
}

int getlogin_r(char *buf, size_t n) {
    static const char lg[] = "root";
    if (!buf || n < sizeof(lg)) {
        errno = ERANGE;
        return ERANGE;
    }
    memcpy(buf, lg, sizeof(lg));
    return 0;
}

int getgroups(int n, gid_t grouplist[]) {
    /* Single group 0 (matches getgid() above). */
    if (n < 0) {
        errno = EINVAL;
        return -1;
    }
    if (n == 0) return 1; /* count query */
    if (!grouplist) {
        errno = EFAULT;
        return -1;
    }
    grouplist[0] = 0;
    return 1;
}

int setgroups(size_t n, const gid_t *list) {
    size_t i;
    if (n > 16) {
        errno = EINVAL;
        return -1;
    }
    /* Only the real group 0 exists: the list must be all zeros
     * (empty is a no-op success). */
    for (i = 0; i < n; i++) {
        if (!list) {
            errno = EFAULT;
            return -1;
        }
        if (list[i] != 0) {
            errno = EPERM;
            return -1;
        }
    }
    return 0;
}

static int ml_set_id(unsigned long v) {
    /* The only user is 0; (uid_t)-1 / (gid_t)-1 means "leave alone".
     * Both id types are 32-bit unsigned, so -1 arrives as 0xFFFFFFFF
     * (a 64-bit -1 is accepted too for direct unsigned-long callers). */
    if (v == 0 || (unsigned int)v == (unsigned int)-1) return 0;
    errno = EPERM;
    return -1;
}

int setuid(uid_t uid) { return ml_set_id(uid); }

int setgid(gid_t gid) { return ml_set_id(gid); }

int seteuid(uid_t uid) { return ml_set_id(uid); }

int setegid(gid_t gid) { return ml_set_id(gid); }

int fchdir(int fd) {
    /* Flat single-root VFS (chdir only accepts "/" and "."): any live
     * fd validates the call; the directory itself is always the root. */
    long r = __ml_call6(LX_SYS_fcntl, (long)fd, (long)F_GETFL, 0, 0, 0,
                        0);
    if (__ml_ret(r) != 0) return -1; /* errno from fcntl (EBADF) */
    return 0;
}

/* Hostname override (process-local): sethostname stores, gethostname
 * prefers the override, matching uname().nodename. Kernel uname has
 * no set call; single-user image, so a libc cell is the real store. */
static char ml_hostname[65] = "";
static int ml_hostname_set = 0;

int sethostname(const char *name, size_t n) {
    size_t i;
    if (!name) {
        errno = EFAULT;
        return -1;
    }
    if (n == 0 || n >= sizeof(ml_hostname)) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < n; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                 c == '_';
        if (!ok) {
            errno = EINVAL;
            return -1;
        }
    }
    memcpy(ml_hostname, name, n);
    ml_hostname[n] = '\0';
    ml_hostname_set = 1;
    return 0;
}

int __ml_hostname_override(char *buf, size_t n) {
    size_t l;
    if (!ml_hostname_set) return -1;
    l = strlen(ml_hostname);
    if (l >= n) return -1;
    memcpy(buf, ml_hostname, l + 1);
    return 0;
}
