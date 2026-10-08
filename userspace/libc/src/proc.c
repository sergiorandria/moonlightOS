/* libc proc: processes, pipes, dup, wait, spawn over the Linux
 * personality. One TCB = one process; fork/clone share the single
 * address space (nommu semantics: fork copies a 16KB stack window,
 * clone uses the caller-supplied stack). execve loads user ELFs from
 * the VFS. system() forks + execs sh with a 127 fallback when no
 * shell image exists (POSIX behavior). */
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <spawn.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

int kill(int pid, int sig) {
    long r;
    if (sig < 0 || sig >= NSIG) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_raw6(LX_SYS_kill, (long)pid, (long)sig, 0, 0, 0, 0);
    return (int)__ml_ret(r);
}

int killpg(int grp, int sig) {
    /* Single process group per thread (getpgrp == getpid): only our
     * own group exists. */
    if (grp != 0 && grp != getpid()) {
        errno = ESRCH;
        return -1;
    }
    return kill(grp == 0 ? getpid() : grp, sig);
}

int tgkill(int tgid, int tid, int sig) {
    long r;
    if (sig < 0 || sig >= NSIG) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_raw6(LX_SYS_tgkill, (long)tgid, (long)tid, (long)sig, 0, 0,
                  0);
    return (int)__ml_ret(r);
}

/* atfork hooks (strong definitions live in pthread.c; these weak
 * no-ops keep proc.c linkable without it). */
__attribute__((weak)) void __ml_atfork_prepare(void) {}
__attribute__((weak)) void __ml_atfork_parent(void) {}
__attribute__((weak)) void __ml_atfork_child(void) {}

int fork(void) {
    long r;
    __ml_atfork_prepare();
    r = __ml_call6(LX_SYS_clone, 17, 0, 0, 0, 0, 0);
    if (r == 0) __ml_atfork_child();
    else if (r > 0) __ml_atfork_parent();
    return (int)__ml_ret(r);
}

int vfork(void) {
    long r;
    __ml_atfork_prepare();
    r = __ml_call6(LX_SYS_clone, LX_CLONE_VFORK | LX_CLONE_VM | 17, 0,
                   0, 0, 0, 0);
    if (r == 0) __ml_atfork_child();
    else if (r > 0) __ml_atfork_parent();
    return (int)__ml_ret(r);
}

long clone(unsigned long flags, void *stack, int *ptid, void *tls,
           int *ctid) {
    long r = __ml_call6(LX_SYS_clone, (long)flags, (long)stack,
                        (long)ptid, (long)tls, (long)ctid, 0);
    return __ml_ret(r);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    long r;
    (void)argv;
    (void)envp; /* _start synthesizes argc/argv; environ is inherited */
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    r = __ml_call6(LX_SYS_execve, (long)path, (long)argv, (long)envp, 0,
                   0, 0);
    __ml_ret(r);
    return -1; /* success never returns */
}

int execv(const char *path, char *const argv[]) {
    return execve(path, argv, environ);
}

static int ml_exec_path(const char *file, char *const argv[],
                        char *const envp[]) {
    /* PATH search (execvp/execlp): slash means direct, else try
     * each colon component with a bounded buffer. */
    const char *path = getenv("PATH");
    char cand[256];
    size_t i;
    if (!file) {
        errno = ENOENT;
        return -1;
    }
    if (strchr(file, '/')) return execve(file, argv, envp);
    if (!path || !*path) path = "/bin:/usr/bin";
    for (;;) {
        size_t n = 0;
        while (*path && *path != ':') {
            if (n + 1 < sizeof(cand)) cand[n++] = *path;
            path++;
        }
        if (*path == ':') path++;
        if (n > 0) {
            if (n + 1 + strlen(file) >= sizeof(cand)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            cand[n++] = '/';
            for (i = 0; file[i]; i++) cand[n++] = file[i];
            cand[n] = '\0';
            execve(cand, argv, envp);
            if (errno != ENOENT) return -1;
        }
        if (!*path) break;
    }
    errno = ENOENT;
    return -1;
}

int execvp(const char *file, char *const argv[]) {
    return ml_exec_path(file, argv, environ);
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    const char *old_path;
    char *path_copy = 0;
    int r;
    if (!file || !argv) {
        errno = file ? EINVAL : ENOENT;
        return -1;
    }
    if (strchr(file, '/')) return execve(file, argv, envp);
    /* PATH search honoring the caller's envp, not environ. */
    old_path = 0;
    if (envp) {
        int i;
        for (i = 0; envp[i]; i++) {
            if (strncmp(envp[i], "PATH=", 5) == 0) {
                old_path = envp[i] + 5;
                break;
            }
        }
    }
    if (!old_path) old_path = getenv("PATH");
    if (!old_path || !*old_path) old_path = "/bin:/usr/bin";
    path_copy = strdup(old_path);
    if (!path_copy) return -1;
    {
        char *save = 0, *dir, cand[256];
        size_t i;
        for (dir = strtok_r(path_copy, ":", &save); dir;
             dir = strtok_r(0, ":", &save)) {
            size_t n = strlen(dir);
            if (n == 0 || n + 1 + strlen(file) >= sizeof(cand)) continue;
            memcpy(cand, dir, n);
            cand[n] = '/';
            for (i = 0; file[i] && n + 1 + i < sizeof(cand); i++)
                cand[n + 1 + i] = file[i];
            cand[n + 1 + i] = '\0';
            execve(cand, argv, envp);
            if (errno != ENOENT) {
                free(path_copy);
                return -1;
            }
        }
    }
    free(path_copy);
    errno = ENOENT;
    return -1;
}

int execl(const char *path, const char *arg, ...) {
    va_list ap;
    char *argv[16];
    int i = 0;
    va_start(ap, arg);
    while (i < 15) {
        const char *a = (i == 0) ? arg : va_arg(ap, const char *);
        argv[i++] = (char *)a;
        if (!a) break;
    }
    argv[15] = 0;
    va_end(ap);
    return execve(path, argv, environ);
}

int execlp(const char *file, const char *arg, ...) {
    va_list ap;
    char *argv[16];
    int i = 0;
    va_start(ap, arg);
    while (i < 15) {
        const char *a = (i == 0) ? arg : va_arg(ap, const char *);
        argv[i++] = (char *)a;
        if (!a) break;
    }
    argv[15] = 0;
    va_end(ap);
    return execvp(file, argv);
}

int execle(const char *path, const char *arg, ...) {
    va_list ap;
    char *argv[16];
    char *const *envp;
    int i = 0;
    va_start(ap, arg);
    while (i < 15) {
        const char *a = (i == 0) ? arg : va_arg(ap, const char *);
        argv[i++] = (char *)a;
        if (!a) break;
    }
    argv[15] = 0;
    envp = va_arg(ap, char *const *);
    va_end(ap);
    return execve(path, argv, envp);
}

int pipe(int fd2[2]) { return pipe2(fd2, 0); }

int pipe2(int fd2[2], int flags) {
    long r;
    if (!fd2) {
        errno = EFAULT;
        return -1;
    }
    if (flags & ~(O_NONBLOCK | O_CLOEXEC)) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_call6(LX_SYS_pipe2, (long)fd2, (long)flags, 0, 0, 0, 0);
    return (int)__ml_ret(r);
}

int dup(int fd) {
    long r = __ml_call6(LX_SYS_dup, (long)fd, 0, 0, 0, 0, 0);
    return (int)__ml_ret(r);
}

int dup2(int oldfd, int newfd) {
    long r;
    if (newfd < 0) {
        errno = EBADF;
        return -1;
    }
    if (oldfd == newfd) {
        /* Validate oldfd (Linux succeeds only for a live fd). */
        r = __ml_call6(LX_SYS_fcntl, (long)oldfd, LX_F_GETFD, 0, 0, 0,
                       0);
        if (__ml_ret(r) != 0 && errno == EBADF) return -1;
        return newfd;
    }
    r = __ml_call6(LX_SYS_dup3, (long)oldfd, (long)newfd, 0, 0, 0, 0);
    return (int)__ml_ret(r);
}

int dup3(int oldfd, int newfd, int flags) {
    long r;
    if (flags & ~O_CLOEXEC) {
        errno = EINVAL;
        return -1;
    }
    if (oldfd == newfd) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_call6(LX_SYS_dup3, (long)oldfd, (long)newfd, (long)flags, 0,
                   0, 0);
    return (int)__ml_ret(r);
}

int wait(int *status) { return waitpid(-1, status, 0); }

int waitpid(int pid, int *status, int options) {
    long r;
    /* waitpid-only options: WNOWAIT/WEXITED/WSTOPPED belong to
     * waitid (Linux rejects them here with EINVAL). WUNTRACED and
     * WCONTINUED are accepted (no job control: never match, but
     * valid). pid 0 / <-1 are group forms (single group per
     * thread); pid < -1 with -pid != self matches nothing, which
     * the kernel reports as ECHILD. */
    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED)) {
        errno = EINVAL;
        return -1;
    }
    if (pid == 0) pid = -1; /* own group == self: any child */
    r = __ml_call6(LX_SYS_wait4, (long)pid, (long)status,
                   (long)options, 0, 0, 0);
    return (int)__ml_ret(r);
}

int wait3(int *status, int options, struct rusage *rusage) {
    int r = waitpid(-1, status, options);
    if (r >= 0 && rusage) {
        /* No per-child accounting on this target (documented):
         * report real zeros. */
        memset(rusage, 0, sizeof(*rusage));
    }
    return r;
}

int wait4(int pid, int *status, int options, struct rusage *rusage) {
    long r;
    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED)) {
        errno = EINVAL;
        return -1;
    }
    if (pid == 0) pid = -1;
    r = __ml_call6(LX_SYS_wait4, (long)pid, (long)status,
                   (long)options, 0, 0, 0);
    r = __ml_ret(r);
    if (r >= 0 && rusage) memset(rusage, 0, sizeof(*rusage));
    return (int)r;
}

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
    int pid, status = 0, r;
    unsigned kopt = 0;
    if (idtype < P_ALL || idtype > P_PIDFD ||
        (options & ~(WNOHANG | WUNTRACED | WCONTINUED | WEXITED |
                     WSTOPPED | WNOWAIT))) {
        errno = EINVAL;
        return -1;
    }
    if (idtype == P_PIDFD) { /* no pidfds on this target */
        errno = EINVAL;
        return -1;
    }
    /* Exactly one state selector is required (Linux EINVAL). */
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
        errno = EINVAL;
        return -1;
    }
    if (idtype == P_ALL) {
        if (id != 0) { /* Linux: P_ALL takes no id */
            errno = EINVAL;
            return -1;
        }
        pid = -1;
    } else if (idtype == P_PID) {
        if (id <= 0) {
            errno = EINVAL;
            return -1;
        }
        pid = (int)id;
    } else { /* P_PGID */
        if (id < 0) {
            errno = EINVAL;
            return -1;
        }
        pid = id == 0 ? 0 : -(int)id;
    }
    /* Only exited children exist (no job control): a wait without
     * WEXITED can never match. WNOHANG reports "no change" with a
     * zeroed siginfo (si_pid 0); blocking would hang forever, so
     * report the same (stop events never occur). */
    if (!(options & WEXITED)) {
        if (infop) memset(infop, 0, sizeof(*infop));
        return 0;
    }
    if (options & WNOHANG) kopt |= WNOHANG;
    if (options & WNOWAIT) kopt |= LX_WNOWAIT;
    /* WUNTRACED/WCONTINUED/WSTOPPED/WEXITED need no kernel bits:
     * accepted above, no stopped/continued states exist. */
    r = (int)__ml_ret(__ml_call6(LX_SYS_wait4, (long)pid, (long)&status,
                                 (long)kopt, 0, 0, 0));
    if (r == -1 && errno == EAGAIN && (options & WNOHANG)) {
        /* Translate: kernel EAGAIN == "would block". waitpid leaks
         * the raw EAGAIN too, but waitid's contract is "return 0
         * with si_pid 0 when nothing changed". */
        if (infop) memset(infop, 0, sizeof(*infop));
        return 0;
    }
    if (r < 0) return -1;
    if (infop) {
        memset(infop, 0, sizeof(*infop));
        infop->si_signo = SIGCHLD;
        infop->si_errno = 0;
        infop->si_value.sigchld_pid = r;
        if (WIFEXITED(status)) {
            infop->si_code = CLD_EXITED;
            infop->si_value.sival_int = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            infop->si_code = CLD_KILLED;
            infop->si_value.sival_int = WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            infop->si_code = CLD_STOPPED;
            infop->si_value.sival_int = WSTOPSIG(status);
        } else {
            infop->si_code = CLD_CONTINUED;
        }
    }
    return 0;
}

/* ---- sessions: one group/session per thread (real, trivial) ---- */

int getpgrp(void) { return getpid(); }

int getpgid(int pid) {
    int me = getpid();
    if (pid != 0 && pid != me) {
        errno = ESRCH;
        return -1;
    }
    return me;
}

int setpgid(int pid, int pgid) {
    int me = getpid();
    if (pid != 0 && pid != me) {
        errno = ESRCH;
        return -1;
    }
    if (pgid != 0 && pgid != me) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setsid(void) { return getpid(); }

/* ---- hostname / conf / sync ---- */

/* Weak so proc.c links without unistd.c (host unit tests stub it out
 * by absence: the address test below folds to false). */
__attribute__((weak)) int __ml_hostname_override(char *buf, size_t n);

int gethostname(char *buf, size_t n) {
    struct utsname u;
    size_t l;
    if (!buf || n == 0) {
        errno = EINVAL;
        return -1;
    }
    /* sethostname() override wins when present. */
    if (__ml_hostname_override && __ml_hostname_override(buf, n) == 0)
        return 0;
    if (uname(&u) != 0) return -1;
    l = strlen(u.nodename);
    if (l >= n) {
        memcpy(buf, u.nodename, n - 1);
        buf[n - 1] = '\0';
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, u.nodename, l + 1);
    return 0;
}

long pathconf(const char *path, int name) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (access(path, F_OK) != 0 && name != _PC_PATH_MAX &&
        name != _PC_NAME_MAX) {
        return -1; /* errno from access (ENOENT) */
    }
    switch (name) {
    case _PC_NAME_MAX:
        return NAME_MAX;
    case _PC_PATH_MAX:
        return PATH_MAX;
    case _PC_PIPE_BUF:
        return 4096;
    default:
        errno = EINVAL;
        return -1;
    }
}

long fpathconf(int fd, int name) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    switch (name) {
    case _PC_NAME_MAX:
        return NAME_MAX;
    case _PC_PATH_MAX:
        return PATH_MAX;
    case _PC_PIPE_BUF:
        return 4096;
    default:
        errno = EINVAL;
        return -1;
    }
}

int fsync(int fd) {
    /* Store-through VFS: bytes are in server memory at write() return,
     * so validating the fd (via fstat) is the whole job. */
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    return 0;
}

int fdatasync(int fd) { return fsync(fd); }

void sync(void) {
    /* Nothing to flush (unbuffered libc, store-through VFS). */
}
