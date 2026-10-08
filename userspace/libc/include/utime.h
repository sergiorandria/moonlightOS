/* Moonlight libc - utime/utimens (mtimes are real VFS fields). */
#pragma once

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

struct utimbuf {
    time_t actime;
    time_t modtime;
};

int utime(const char *path, const struct utimbuf *t);
int utimes(const char *path, const struct timeval *t);
int utimensat(int dirfd, const char *path, const struct timespec t[2],
              int flags);
int futimens(int fd, const struct timespec t[2]);

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define UTIME_NOW 0x3fffffff
#define UTIME_OMIT 0x3ffffffe
