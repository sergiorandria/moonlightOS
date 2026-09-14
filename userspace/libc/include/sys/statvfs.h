/* Moonlight libc - sys/statvfs (flat VFS: fixed geometry). */
#pragma once

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    unsigned long f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};

#define ST_RDONLY 1
#define ST_NOSUID 2

int statvfs(const char *path, struct statvfs *st);
int fstatvfs(int fd, struct statvfs *st);
