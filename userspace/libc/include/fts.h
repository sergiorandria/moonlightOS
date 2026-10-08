/* Moonlight libc - fts (BSD file traversal).
 * Real implementation over opendir/readdir/lstat: preorder walk
 * with cycle detection (dev+ino stack), FTS_PHYSICAL by default,
 * FTS_LOGICAL follows symlinks via stat. fts_read returns a live
 * FTSENT per entry; fts_children snapshots a directory. No stubs. */
#pragma once

#include <sys/stat.h>

typedef struct _FTS FTS;
typedef struct _FTSENT FTSENT;

struct _FTSENT {
    const char *fts_path;
    const char *fts_name;
    const char *fts_accpath;
    int fts_level;
    int fts_info;
    struct stat *fts_statp;
    FTSENT *fts_link;
    FTSENT *fts_parent;
    void *fts_pointer;
    long fts_number;
};

#define FTS_D 1
#define FTS_DC 2
#define FTS_DEFAULT 3
#define FTS_DNR 4
#define FTS_DOT 5
#define FTS_DP 6
#define FTS_ERR 7
#define FTS_F 8
#define FTS_INIT 9
#define FTS_NS 10
#define FTS_NSOK 11
#define FTS_SL 12
#define FTS_SLNONE 13
#define FTS_W 14

#define FTS_DONTCHDIR 1
#define FTS_LOGICAL 2
#define FTS_NOCHDIR 4
#define FTS_NOSTAT 8
#define FTS_PHYSICAL 16
#define FTS_SEEDOT 32
#define FTS_XDEV 64
#define FTS_WHITEOUT 128
#define FTS_COMFOLLOW 256
#define FTS_OPTIONMASK 511

#define FTS_AGAIN 1
#define FTS_FOLLOW 2
#define FTS_NOINSTR 3
#define FTS_SKIP 4

FTS *fts_open(char *const *paths, int options,
              int (*cmp)(const FTSENT **, const FTSENT **));
int fts_close(FTS *f);
FTSENT *fts_read(FTS *f);
FTSENT *fts_children(FTS *f, int instr);
int fts_set(FTS *f, FTSENT *e, int instr);
