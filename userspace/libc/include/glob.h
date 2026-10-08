/* Moonlight libc - glob/fnmatch/regex/ftw/wordexp (pattern + walk). */
#pragma once

#include <stddef.h>
#include <sys/stat.h>
#include <dirent.h>

typedef struct {
    size_t gl_pathc;
    char **gl_pathv;
    size_t gl_offs;
    int gl_flags;
    void *(*gl_opendir)(const char *name);
    struct dirent *(*gl_readdir)(void *dir);
    void (*gl_closedir)(void *dir);
    int (*gl_lstat)(const char *name, struct stat *st);
    int (*gl_stat)(const char *name, struct stat *st);
} glob_t;

#define GLOB_ERR 1
#define GLOB_MARK 2
#define GLOB_NOSORT 4
#define GLOB_DOOFFS 8
#define GLOB_NOCHECK 16
#define GLOB_APPEND 32
#define GLOB_NOESCAPE 64
#define GLOB_PERIOD 128
#define GLOB_ALTDIRFUNC 512
#define GLOB_BRACE 1024
#define GLOB_NOMAGIC 2048
#define GLOB_TILDE 4096
#define GLOB_TILDE_CHECK 16384
#define GLOB_NOMATCH 3
#define GLOB_ABORTED 2
#define GLOB_NOSPACE 1

int glob(const char *pat, int flags,
         int (*err)(const char *path, int err), glob_t *g);
void globfree(glob_t *g);
