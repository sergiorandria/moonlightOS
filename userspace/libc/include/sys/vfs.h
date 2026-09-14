/* Moonlight libc - sys/vfs + sys/statfs (filesystem statistics).
 * statfs/fstatfs map the flat VFS geometry (same numbers as statvfs);
 * implemented in src/sysstat.c. */
#pragma once

#include <sys/types.h>

#define MFSNAMELEN 32
#define MNAMELEN 1024

struct statfs {
    long f_type;
    long f_bsize;
    long f_blocks;
    long f_bfree;
    long f_bavail;
    long f_files;
    long f_ffree;
    struct {
        int __val[2];
    } f_fsid;
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};

#define ST_RDONLY 1
#define ST_NOSUID 2

int statfs(const char *path, struct statfs *st);
int fstatfs(int fd, struct statfs *st);
