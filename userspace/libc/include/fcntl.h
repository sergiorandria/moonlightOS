/* Moonlight libc - fcntl / sys/stat / sys/mman / types / time. */
#pragma once

#include <sys/types.h>

#define O_RDONLY 0
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_EXCL 0200
#define O_NOCTTY 0400
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_DIRECTORY 040000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000
#define O_ACCMODE 03

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define AT_EMPTY_PATH 0x1000
#define AT_SYMLINK_NOFOLLOW 0x100

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC 1

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

struct flock {
    short l_type;
    short l_whence;
    long l_start;
    long l_len;
    int l_pid;
};
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

int open(const char *path, int flags, ...);
int openat(int dirfd, const char *path, int flags, ...);
int creat(const char *path, int mode);
int unlinkat(int dirfd, const char *path, int flags);
int fcntl(int fd, int cmd, ...);
int flock(int fd, int op);
int mkdirat(int dirfd, const char *path, unsigned mode);
int mknodat(int dirfd, const char *path, unsigned mode, unsigned long dev);
int symlinkat(const char *target, int dirfd, const char *path);
int linkat(int olddir, const char *oldp, int newdir, const char *newp,
           int flags);
ssize_t readlinkat(int dirfd, const char *path, char *buf, unsigned n);
