/* libc spawn: posix_spawn over vfork + execve + file actions.
 * The child applies fd actions (open/close/dup2) then execs; on exec
 * failure it exits 127 (POSIX). The parent waits nothing (async). */
#include <spawn.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

int posix_spawnattr_init(posix_spawnattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    memset(a, 0, sizeof(*a));
    return 0;
}

int posix_spawnattr_destroy(posix_spawnattr_t *a) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

int posix_spawnattr_setflags(posix_spawnattr_t *a, short f) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->flags = f;
    return 0;
}

int posix_spawnattr_getflags(const posix_spawnattr_t *a, short *f) {
    if (!a || !f) {
        errno = EINVAL;
        return EINVAL;
    }
    *f = a->flags;
    return 0;
}

int posix_spawnattr_setpgroup(posix_spawnattr_t *a, pid_t p) {
    if (!a) {
        errno = EINVAL;
        return EINVAL;
    }
    a->flags |= POSIX_SPAWN_SETPGROUP;
    a->pgroup = p;
    return 0;
}

int posix_spawnattr_getpgroup(const posix_spawnattr_t *a, pid_t *p) {
    if (!a || !p) {
        errno = EINVAL;
        return EINVAL;
    }
    *p = a->pgroup;
    return 0;
}

int posix_spawnattr_setsigmask(posix_spawnattr_t *a, const sigset_t *m) {
    if (!a || !m) {
        errno = EINVAL;
        return EINVAL;
    }
    a->flags |= POSIX_SPAWN_SETSIGMASK;
    a->mask = *m;
    return 0;
}

int posix_spawnattr_getsigmask(const posix_spawnattr_t *a, sigset_t *m) {
    if (!a || !m) {
        errno = EINVAL;
        return EINVAL;
    }
    *m = a->mask;
    return 0;
}

int posix_spawnattr_setsigdefault(posix_spawnattr_t *a,
                                  const sigset_t *m) {
    if (!a || !m) {
        errno = EINVAL;
        return EINVAL;
    }
    a->flags |= POSIX_SPAWN_SETSIGDEF;
    a->def = *m;
    return 0;
}

int posix_spawnattr_getsigdefault(const posix_spawnattr_t *a,
                                  sigset_t *m) {
    if (!a || !m) {
        errno = EINVAL;
        return EINVAL;
    }
    *m = a->def;
    return 0;
}

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *f) {
    if (!f) {
        errno = EINVAL;
        return EINVAL;
    }
    memset(f, 0, sizeof(*f));
    return 0;
}

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *f) {
    if (!f) {
        errno = EINVAL;
        return EINVAL;
    }
    return 0;
}

static int ml_fa_add(posix_spawn_file_actions_t *f, int op, int fd,
                     int fd2) {
    if (!f || f->fd_n >= 16) {
        errno = EINVAL;
        return EINVAL;
    }
    f->fd_op[f->fd_n] = op;
    f->fd_fd[f->fd_n] = fd;
    f->fd_map[f->fd_n] = fd2;
    f->fd_flags[f->fd_n] = 0;
    f->fd_path[f->fd_n][0] = '\0';
    f->fd_n++;
    return 0;
}

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *f,
                                     int fd, const char *path, int flags,
                                     mode_t mode) {
    size_t n;
    (void)mode;
    if (!f || !path) {
        errno = EINVAL;
        return EINVAL;
    }
    n = strlen(path);
    if (n >= 64) {
        errno = ENAMETOOLONG;
        return ENAMETOOLONG;
    }
    if (ml_fa_add(f, 1, fd, 0) != 0) return EINVAL;
    f->fd_flags[f->fd_n - 1] = flags;
    memcpy(f->fd_path[f->fd_n - 1], path, n + 1);
    return 0;
}

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *f,
                                      int fd) {
    return ml_fa_add(f, 2, fd, 0);
}

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *f,
                                     int old, int newf) {
    return ml_fa_add(f, 3, old, newf);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr, char *const argv[],
                char *const envp[]) {
    long c;
    int status_pipe[2];
    if (!path) {
        errno = EINVAL;
        return EINVAL;
    }
    /* Error pipe: child reports exec errno to the parent. */
    if (pipe(status_pipe) != 0) return errno;
    c = __ml_call6(LX_SYS_clone, LX_CLONE_VFORK | LX_CLONE_VM | 17, 0, 0,
                   0, 0, 0);
    if (__ml_ret(c) != 0 && c < 0) {
        int e = errno;
        close(status_pipe[0]);
        close(status_pipe[1]);
        errno = e;
        return e;
    }
    if (c == 0) {
        /* Child (vfork: parent sleeps until we exec/exit). */
        int i, e;
        close(status_pipe[0]);
        if (attr && (attr->flags & POSIX_SPAWN_SETSIGMASK))
            sigprocmask(SIG_SETMASK, &attr->mask, 0);
        if (fa) {
            for (i = 0; i < fa->fd_n; i++) {
                if (fa->fd_op[i] == 1) {
                    int nf =
                        open(fa->fd_path[i], fa->fd_flags[i], 0666);
                    if (nf < 0) {
                        e = errno;
                        write(status_pipe[1], &e, sizeof(e));
                        close(status_pipe[1]);
                        goto child_fail;
                    }
                    if (nf != fa->fd_fd[i]) {
                        dup2(nf, fa->fd_fd[i]);
                        close(nf);
                    }
                } else if (fa->fd_op[i] == 2) {
                    close(fa->fd_fd[i]);
                } else if (fa->fd_op[i] == 3) {
                    dup2(fa->fd_fd[i], fa->fd_map[i]);
                }
            }
        }
        execve(path, argv, envp ? envp : environ);
        e = errno;
        /* Report failure to the parent, then exit 127. */
        write(status_pipe[1], &e, sizeof(e));
        close(status_pipe[1]);
    child_fail: {
        long code = 127;
        __ml_raw6(LX_SYS_exit, code, 0, 0, 0, 0, 0);
        for (;;) {
        }
    }
    }
    /* Parent (resumed after child exec/exit). */
    {
        int e = 0;
        long n;
        close(status_pipe[1]);
        n = read(status_pipe[0], &e, sizeof(e));
        close(status_pipe[0]);
        if (n == sizeof(e)) {
            /* Child failed before exec: reap the 127 corpse. */
            int st;
            waitpid((int)c, &st, 0);
            errno = e;
            return e;
        }
        if (pid) *pid = (pid_t)c;
        return 0;
    }
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr, char *const argv[],
                 char *const envp[]) {
    const char *path;
    char cand[256];
    pid_t p;
    int r;
    if (!file) {
        errno = EINVAL;
        return EINVAL;
    }
    if (strchr(file, '/')) return posix_spawn(pid, file, fa, attr, argv,
                                              envp);
    path = getenv("PATH");
    if (!path || !*path) path = "/bin:/usr/bin";
    for (;;) {
        size_t n = 0;
        while (*path && *path != ':') {
            if (n + 1 < sizeof(cand)) cand[n++] = *path;
            path++;
        }
        if (*path == ':') path++;
        if (n > 0) {
            size_t i;
            if (n + 1 + strlen(file) < sizeof(cand)) {
                cand[n++] = '/';
                for (i = 0; file[i]; i++) cand[n++] = file[i];
                cand[n] = '\0';
                r = posix_spawn(&p, cand, fa, attr, argv, envp);
                if (r == 0) {
                    if (pid) *pid = p;
                    return 0;
                }
                if (r != ENOENT) return r;
            }
        }
        if (!*path) break;
    }
    return ENOENT;
}
