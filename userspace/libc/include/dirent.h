/* Moonlight libc - dirent (real enumeration over getdents64). */
#pragma once

#include <stddef.h>

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12

struct dirent {
    unsigned long d_ino;
    long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[32];
};

typedef struct __ML_DIR {
    int fd;
    long off;
    int eof;
    char buf[512];
    unsigned len;
    unsigned pos;
    struct dirent cur;
} DIR;

DIR *opendir(const char *path);
DIR *fdopendir(int fd);
int closedir(DIR *d);
struct dirent *readdir(DIR *d);
long telldir(DIR *d);
void seekdir(DIR *d, long off);
void rewinddir(DIR *d);
int dirfd(DIR *d);
int scandir(const char *path, struct dirent ***list,
            int (*sel)(const struct dirent *),
            int (*cmp)(const struct dirent **, const struct dirent **));
int alphasort(const struct dirent **a, const struct dirent **b);
int versionsort(const struct dirent **a, const struct dirent **b);
