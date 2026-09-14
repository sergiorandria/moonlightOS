/* libc dir: real enumeration over getdents64. DIR holds a small
 * readahead buffer; telldir/seekdir are entry offsets (d_off). */
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

typedef struct {
    unsigned long d_ino;
    long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[32];
} ml_dirent64_t;

DIR *opendir(const char *path) {
    int fd;
    DIR *d;
    if (!path) {
        errno = EINVAL;
        return 0;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        /* Not a directory but exists: Linux says ENOTDIR (openat
         * without O_DIRECTORY succeeds on files). */
        if (errno == ENOENT) return 0;
        if (errno == ENOTDIR) return 0;
        return 0;
    }
    d = malloc(sizeof(DIR));
    if (!d) {
        int e = errno;
        close(fd);
        errno = e;
        return 0;
    }
    d->fd = fd;
    d->off = 0;
    d->eof = 0;
    d->len = 0;
    d->pos = 0;
    memset(&d->cur, 0, sizeof(d->cur));
    return d;
}

DIR *fdopendir(int fd) {
    DIR *d;
    struct stat {
        unsigned long long a[16];
    } st;
    (void)st;
    if (fd < 0) {
        errno = EBADF;
        return 0;
    }
    /* Validate the fd first (EBADF for garbage), then require that a
     * directory listing works on it. */
    {
        char probe[sizeof(ml_dirent64_t)];
        long r = __ml_call6(LX_SYS_getdents64, fd, (long)probe,
                            sizeof(probe), 0, 0, 0);
        if (r < 0 && r != 0) {
            /* getdents on a non-dir fd fails ENOTDIR; on a closed fd
             * the lookup fails EBADF. Distinguish via fstat. */
            long f = __ml_call6(LX_SYS_fstat, fd, (long)probe, 0, 0, 0,
                                0);
            if (f < 0) {
                __ml_ret(f);
                return 0;
            }
            /* Valid fd but not listable: rewind probe offset is
             * unchanged (0 bytes consumed on error). */
            errno = ENOTDIR;
            return 0;
        }
        /* Rewind: the probe may have advanced the cursor. */
        __ml_call6(LX_SYS_lseek, fd, 0, 0, 0, 0, 0);
    }
    d = malloc(sizeof(DIR));
    if (!d) return 0;
    d->fd = fd;
    d->off = 0;
    d->eof = 0;
    d->len = 0;
    d->pos = 0;
    memset(&d->cur, 0, sizeof(d->cur));
    return d;
}

int closedir(DIR *d) {
    int fd, r;
    if (!d) {
        errno = EBADF;
        return -1;
    }
    fd = d->fd;
    free(d);
    r = close(fd);
    return r;
}

int dirfd(DIR *d) {
    if (!d) {
        errno = EINVAL;
        return -1;
    }
    return d->fd;
}

struct dirent *readdir(DIR *d) {
    long r;
    ml_dirent64_t *k;
    if (!d) return 0;
    if (d->eof) return 0;
    if (d->pos >= d->len) {
        r = __ml_call6(LX_SYS_getdents64, d->fd, (long)d->buf,
                       sizeof(d->buf), 0, 0, 0);
        if (r < 0) {
            __ml_ret(r);
            return 0;
        }
        if (r == 0) {
            d->eof = 1;
            return 0;
        }
        d->len = (unsigned)r;
        d->pos = 0;
    }
    k = (ml_dirent64_t *)(d->buf + d->pos);
    d->pos += k->d_reclen ? k->d_reclen : sizeof(ml_dirent64_t);
    d->off = k->d_off;
    d->cur.d_ino = k->d_ino;
    d->cur.d_off = k->d_off;
    d->cur.d_reclen = k->d_reclen;
    d->cur.d_type = k->d_type;
    memcpy(d->cur.d_name, k->d_name, 32);
    return &d->cur;
}

long telldir(DIR *d) {
    if (!d) {
        errno = EBADF;
        return -1;
    }
    return d->off;
}

void seekdir(DIR *d, long off) {
    if (!d || off < 0) return;
    __ml_ret(__ml_call6(LX_SYS_lseek, d->fd, off, 0, 0, 0, 0));
    d->off = off;
    d->len = 0;
    d->pos = 0;
    d->eof = 0;
}

void rewinddir(DIR *d) {
    if (d) seekdir(d, 0);
}

int alphasort(const struct dirent **a, const struct dirent **b) {
    return strcmp((*a)->d_name, (*b)->d_name);
}

/* versionsort: numeric runs compare by value, ties by length. */
int versionsort(const struct dirent **a, const struct dirent **b) {
    const char *x = (*a)->d_name, *y = (*b)->d_name;
    while (*x && *y) {
        if (*x >= '0' && *x <= '9' && *y >= '0' && *y <= '9') {
            unsigned long vx = 0, vy = 0;
            while (*x == '0') x++;
            while (*y == '0') y++;
            while (*x >= '0' && *x <= '9') {
                vx = vx * 10 + (unsigned)(*x - '0');
                x++;
            }
            while (*y >= '0' && *y <= '9') {
                vy = vy * 10 + (unsigned)(*y - '0');
                y++;
            }
            if (vx != vy) return vx < vy ? -1 : 1;
        } else if (*x != *y) {
            return (unsigned char)*x < (unsigned char)*y ? -1 : 1;
        } else {
            x++;
            y++;
        }
    }
    if (*x) return 1;
    if (*y) return -1;
    return 0;
}

int scandir(const char *path, struct dirent ***list,
            int (*sel)(const struct dirent *),
            int (*cmp)(const struct dirent **, const struct dirent **)) {
    DIR *d = opendir(path);
    struct dirent **v = 0;
    size_t n = 0, cap = 0;
    struct dirent *e;
    size_t i, j;
    if (!d) return -1;
    if (list) *list = 0;
    while ((e = readdir(d)) != 0) {
        struct dirent *c;
        if (strcmp(e->d_name, ".") == 0 ||
            strcmp(e->d_name, "..") == 0)
            continue;
        if (sel && !sel(e)) continue;
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            struct dirent **nv = realloc(v, nc * sizeof(*nv));
            if (!nv) {
                for (i = 0; i < n; i++) free(v[i]);
                free(v);
                closedir(d);
                errno = ENOMEM;
                return -1;
            }
            v = nv;
            cap = nc;
        }
        c = malloc(sizeof(*c));
        if (!c) {
            for (i = 0; i < n; i++) free(v[i]);
            free(v);
            closedir(d);
            errno = ENOMEM;
            return -1;
        }
        *c = *e;
        v[n++] = c;
    }
    closedir(d);
    if (cmp && n > 1) {
        /* Insertion sort (comparison-driven, stable). */
        for (i = 1; i < n; i++) {
            struct dirent *t = v[i];
            j = i;
            while (j > 0 && cmp((const struct dirent **)&v[j - 1],
                                (const struct dirent **)&t) > 0) {
                v[j] = v[j - 1];
                j--;
            }
            v[j] = t;
        }
    }
    if (list) *list = v;
    else {
        for (i = 0; i < n; i++) free(v[i]);
        free(v);
    }
    return (int)n;
}
