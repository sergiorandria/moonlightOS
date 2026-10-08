/* Moonlight libc - ftw/nftw over getdents64. */
#pragma once

#include <sys/stat.h>

#define FTW_F 1
#define FTW_D 2
#define FTW_DNR 3
#define FTW_NS 4
#define FTW_SL 6
#define FTW_DP 8
#define FTW_PHYS 1
#define FTW_MOUNT 2
#define FTW_DEPTH 8
#define FTW_CHDIR 4

struct FTW {
    int base;
    int level;
};

int ftw(const char *path, int (*fn)(const char *f, const struct stat *st,
                                    int type),
        int nfds);
int nftw(const char *path,
         int (*fn)(const char *f, const struct stat *st, int type,
                   struct FTW *ftw),
         int nfds, int flags);
