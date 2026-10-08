/* libc fcntl/stat/mman: thin wrappers. */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

/* Kernel lx_stat_t and libc struct stat must agree byte-for-byte. */
_Static_assert(sizeof(struct stat) == 128, "struct stat must be 128 bytes");
_Static_assert(sizeof(struct stat) == sizeof(lx_stat_t),
               "stat layouts diverge");
_Static_assert(__builtin_offsetof(struct stat, st_mode) == 16, "stat mode");
_Static_assert(__builtin_offsetof(struct stat, st_size) == 48, "stat size");
_Static_assert(__builtin_offsetof(struct stat, st_blocks) == 64,
               "stat blocks");
_Static_assert(__builtin_offsetof(lx_stat_t, st_blocks) == 64,
               "lx blocks");

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    (void)mode;
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_openat, LX_AT_FDCWD, path, flags, 0666));
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    (void)mode;
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_openat, dirfd, path, flags, 0666));
}

int creat(const char *path, int mode) {
    (void)mode;
    return (int)__ml_ret(__ML_SYS4(LX_SYS_openat, LX_AT_FDCWD, path,
                                  O_CREAT | O_WRONLY | O_TRUNC, 0666));
}

int unlinkat(int dirfd, const char *path, int flags) {
    return (int)__ml_ret(__ML_SYS3(LX_SYS_unlinkat, dirfd, path, flags));
}

int stat(const char *path, struct stat *st) {
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_newfstatat, LX_AT_FDCWD, path, st, 0));
}

int lstat(const char *path, struct stat *st) {
    /* With real symlinks, lstat must not follow: pass NOFOLLOW. */
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_newfstatat, LX_AT_FDCWD, path, st,
                  LX_AT_SYMLINK_NOFOLLOW));
}

int fstat(int fd, struct stat *st) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_fstat, fd, st));
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_newfstatat, dirfd, path, st, flags));
}

int statx(int dirfd, const char *path, int flags, unsigned mask,
          struct statx *buf) {
    /* Full mask/flags semantics: the kernel store is synchronous, so
     * SYNC_TYPE bits are accepted and ignored; the returned stx_mask
     * is (requested & BASIC_STATS) — unknown mask bits are EINVAL,
     * unknown flags are EINVAL. AT_EMPTY_PATH with an empty path
     * stats dirfd itself (fstat path). */
    int r;
    if (!buf) {
        errno = EFAULT;
        return -1;
    }
    if (mask & ~STATX_ALL) {
        errno = EINVAL;
        return -1;
    }
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH |
                  AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE)) {
        errno = EINVAL;
        return -1;
    }
    /* Linux: a NULL pathname with AT_EMPTY_PATH operates on dirfd
     * itself; without it, NULL is EFAULT. */
    if (!path) {
        if (!(flags & AT_EMPTY_PATH)) {
            errno = EFAULT;
            return -1;
        }
        path = "";
    }
    if ((flags & AT_EMPTY_PATH) && path[0] == '\0') {
        struct stat st;
        if (dirfd == AT_FDCWD) {
            errno = ENOENT;
            return -1;
        }
        if (fstat(dirfd, &st) != 0) return -1;
        memset(buf, 0, sizeof(*buf));
        buf->stx_mask = mask & STATX_BASIC_STATS;
        buf->stx_mode = (unsigned short)st.st_mode;
        buf->stx_blksize = (unsigned)st.st_blksize;
        buf->stx_nlink = st.st_nlink;
        buf->stx_uid = st.st_uid;
        buf->stx_gid = st.st_gid;
        buf->stx_ino = st.st_ino;
        buf->stx_size = (unsigned long long)(st.st_size >= 0 ? st.st_size : 0);
        buf->stx_blocks = (unsigned long long)(st.st_blocks >= 0 ? st.st_blocks : 0);
        buf->stx_atime.tv_sec = (long long)st.st_atime;
        buf->stx_atime.tv_nsec = (unsigned)st.st_atime_nsec;
        buf->stx_mtime.tv_sec = (long long)st.st_mtime;
        buf->stx_mtime.tv_nsec = (unsigned)st.st_mtime_nsec;
        buf->stx_ctime.tv_sec = (long long)st.st_ctime;
        buf->stx_ctime.tv_nsec = (unsigned)st.st_ctime_nsec;
        buf->stx_dev_major = 1;
        return 0;
    }
    r = (int)__ml_ret(
        __ML_SYS6(LX_SYS_statx, dirfd, path, flags, mask, buf, 0));
    if (r == 0) buf->stx_mask &= mask;
    return r;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off) {
    long r = __ml_call6(LX_SYS_mmap, (long)addr, (long)len, prot, flags,
                        fd, off);
    if (r < 0 && r >= -4095) {
        errno = (int)-r;
        return MAP_FAILED;
    }
    return (void *)r;
}

int munmap(void *addr, size_t len) {
    return (int)__ml_ret(__ML_SYS2(LX_SYS_munmap, addr, len));
}

int mprotect(void *addr, size_t len, int prot) {
    return (int)__ml_ret(__ML_SYS3(LX_SYS_mprotect, addr, len, prot));
}

int madvise(void *addr, size_t len, int advice) {
    return (int)__ml_ret(__ML_SYS3(LX_SYS_madvise, addr, len, advice));
}

/* ---- permissions (owner model: bits accepted + ignored) ---- */

static mode_t ml_umask = 0;

mode_t umask(mode_t mask) {
    mode_t old = ml_umask;
    ml_umask = mask & 0777;
    return old;
}

int chmod(const char *path, mode_t mode) {
    struct stat st;
    (void)mode; /* accepted, ignored: files are always 0644 */
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    /* Validate the target; the mode itself needs no storage. */
    if (stat(path, &st) != 0) return -1;
    return 0;
}

int fchmod(int fd, mode_t mode) {
    struct stat st;
    (void)mode;
    if (fstat(fd, &st) != 0) return -1;
    return 0;
}

static int ml_chown_ok(uid_t uid, gid_t gid) {
    /* The only user is 0; -1 means "leave alone" (POSIX). */
    if ((uid == 0 || uid == (uid_t)-1) && (gid == 0 || gid == (gid_t)-1))
        return 0;
    errno = EPERM;
    return -1;
}

int chown(const char *path, uid_t uid, gid_t gid) {
    struct stat st;
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    if (stat(path, &st) != 0) return -1;
    return ml_chown_ok(uid, gid);
}

int fchown(int fd, uid_t uid, gid_t gid) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    return ml_chown_ok(uid, gid);
}

int lchown(const char *path, uid_t uid, gid_t gid) {
    return chown(path, uid, gid); /* no symlinks: same call */
}

/* ---- namespace ops: real VFS nodes (dirs, symlinks, fifos) ---- */

int rmdir(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS3(LX_SYS_unlinkat, LX_AT_FDCWD, path, LX_AT_REMOVEDIR));
}

int mkdir(const char *path, mode_t mode) {
    (void)mode; /* owner model: dirs are always 0755 */
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS3(LX_SYS_mkdirat, LX_AT_FDCWD, path, 0755));
}

int mkdirat(int dirfd, const char *path, unsigned mode) {
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return mkdir(path, (mode_t)mode);
}

int symlink(const char *oldp, const char *newp) {
    if (!oldp || !newp) {
        errno = EFAULT;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS3(LX_SYS_symlinkat, oldp, LX_AT_FDCWD, newp));
}

int symlinkat(const char *target, int dirfd, const char *path) {
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return symlink(target, path);
}

int link(const char *oldp, const char *newp) {
    if (!oldp || !newp) {
        errno = EFAULT;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS6(LX_SYS_linkat, LX_AT_FDCWD, oldp, LX_AT_FDCWD, newp,
                  0, 0));
}

int linkat(int olddir, const char *oldp, int newdir, const char *newp,
           int flags) {
    if (olddir != AT_FDCWD || newdir != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS6(LX_SYS_linkat, olddir, oldp, newdir, newp, flags, 0));
}

ssize_t readlink(const char *path, char *buf, size_t n) {
    return readlinkat(AT_FDCWD, path, buf, (unsigned)n);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, unsigned n) {
    if (!path || !buf) {
        errno = EFAULT;
        return -1;
    }
    return (ssize_t)__ml_ret(
        __ML_SYS4(LX_SYS_readlinkat, dirfd, path, buf, n));
}

int mkfifo(const char *path, mode_t mode) {
    (void)mode;
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_mknodat, LX_AT_FDCWD, path, 0010000, 0));
}

int mkfifoat(int dirfd, const char *path, mode_t mode) {
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return mkfifo(path, mode);
}

int mknod(const char *path, mode_t mode, dev_t dev) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return (int)__ml_ret(
        __ML_SYS4(LX_SYS_mknodat, LX_AT_FDCWD, path, mode, dev));
}

int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev) {
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return mknod(path, mode, dev);
}

/* ---- locking / sync (no paging: validate, succeed) ---- */

int mlock(const void *addr, size_t len) {
    if (!addr || len == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0; /* always resident: static arenas, no swap */
}

int munlock(const void *addr, size_t len) {
    if (!addr || len == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int msync(void *addr, size_t len, int flags) {
    if (!addr || len == 0) {
        errno = EINVAL;
        return -1;
    }
    if (flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) {
        errno = EINVAL;
        return -1;
    }
    if ((uintptr_t)addr & 4095) {
        errno = EINVAL; /* msync needs a page-aligned base */
        return -1;
    }
    return 0; /* store-through: nothing to write back */
}

void *mremap(void *old, size_t oldlen, size_t newlen, int flags, ...) {
    void *n;
    /* Bump-arena: no in-place growth; allocate fresh, copy the common
     * prefix, keep the old mapping live (munmap never reclaims). */
    if (!old || oldlen == 0 || newlen == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED)) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    n = mmap(0, newlen, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (n == MAP_FAILED) return MAP_FAILED;
    memcpy(n, old, oldlen < newlen ? oldlen : newlen);
    return n;
}

int mlockall(int flags) {
    if (flags & ~(MCL_CURRENT | MCL_FUTURE)) {
        errno = EINVAL;
        return -1;
    }
    return 0; /* always resident */
}

int munlockall(void) { return 0; }

/* ---- shm: VFS files named "shm.<name>" ---- */

static int ml_shm_name(const char *name, char *out, size_t cap) {
    size_t i = 0;
    if (!name || name[0] != '/' || name[1] == '\0') {
        errno = EINVAL;
        return -1;
    }
    /* Exactly one leading slash, then a VFS-ok name. */
    name++;
    while (name[i] != '\0') {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (c == '/' || !ok || i >= 27) {
            errno = EINVAL;
            return -1;
        }
        i++;
    }
    if (i == 0 || name[0] == '-') {
        errno = EINVAL;
        return -1;
    }
    if (4 + i + 1 > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, "shm.", 4);
    memcpy(out + 4, name, i + 1);
    return 0;
}

int shm_open(const char *name, int flags, mode_t mode) {
    char mapped[32];
    (void)mode; /* owner model: accepted, ignored */
    if (ml_shm_name(name, mapped, sizeof(mapped)) != 0) return -1;
    return open(mapped, flags, 0666);
}

int shm_unlink(const char *name) {
    char mapped[32];
    if (ml_shm_name(name, mapped, sizeof(mapped)) != 0) return -1;
    return unlink(mapped);
}

/* ---- fchmodat/fchownat ---- */

int fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    (void)flags;
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return chmod(path, mode);
}

int fchownat(int dirfd, const char *path, uid_t uid, gid_t gid,
             int flags) {
    (void)flags;
    if (dirfd != AT_FDCWD) {
        errno = EBADF;
        return -1;
    }
    return chown(path, uid, gid);
}
