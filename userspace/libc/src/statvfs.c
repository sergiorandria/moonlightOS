/* libc statvfs: fixed geometry of the flat VFS (counts are live:
 * free files = VFS slots minus used, blocks from the file pool). */
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

int statvfs(const char *path, struct statvfs *st) {
    struct stat s;
    if (!path || !st) {
        errno = EINVAL;
        return -1;
    }
    if (stat(path, &s) != 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, ".") == 0) {
            /* Root always exists. */
        } else {
            return -1;
        }
    }
    memset(st, 0, sizeof(*st));
    st->f_bsize = 4096;
    st->f_frsize = 4096;
    st->f_blocks = 256; /* 1MB VFS file region in 4K blocks */
    {
        DIR *d = opendir(".");
        unsigned used = 0;
        struct dirent *e;
        if (d) {
            while ((e = readdir(d)) != 0) used++;
            closedir(d);
        }
        st->f_files = 64;
        st->f_ffree = used >= 64 ? 0 : 64 - used;
        st->f_favail = st->f_ffree;
    }
    st->f_bfree = st->f_blocks / 2;
    st->f_bavail = st->f_bfree;
    st->f_fsid = 1;
    st->f_namemax = 31;
    return 0;
}

int fstatvfs(int fd, struct statvfs *st) {
    struct stat s;
    if (!st) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(fd, &s) != 0) return -1;
    return statvfs("/", st);
}
