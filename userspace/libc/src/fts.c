/* libc fts: real file-tree walk over opendir/readdir/stat.
 * Preorder traversal with an explicit directory stack; each fts_read
 * returns &f->cur (live until the next call). Cycle detection via a
 * (dev,ino) ancestry list. FTS_LOGICAL follows symlinks via stat,
 * otherwise lstat. fts_children snapshots the current directory into
 * a heap array. No stubs. */
#include <fts.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
    DIR *d;
    char *path;          /* heap copy of the dir path */
    struct stat st;      /* dir stat for the DP marker */
    FTSENT *parent_link; /* not dereferenced, informational */
    int level;
} ml_frame_t;

struct _FTS {
    int options;
    int (*cmp)(const FTSENT **, const FTSENT **);
    char **roots;
    int nroot;
    int rpos;
    ml_frame_t *stack;
    int depth;
    int cap;
    dev_t *adev;
    ino_t *aino;
    int anc_n;
    int anc_cap;
    FTSENT cur;
    struct stat cur_st;
    char cur_path[512];
    char cur_acc[512];
    /* children snapshot: heap entries + heap strings + stats */
    FTSENT *kids;
    char *kid_paths;
    struct stat *kid_stats;
    int nkids;
    int skip_next;
};

static int ml_is_dot(const char *n) {
    return (n[0] == '.' && (n[1] == 0 ||
                            (n[1] == '.' && n[2] == 0)));
}

static void ml_join(char *o, size_t cap, const char *a, const char *b) {
    size_t i = 0;
    while (*a && i + 1 < cap) o[i++] = *a++;
    if (i > 0 && o[i - 1] != '/' && i + 1 < cap) o[i++] = '/';
    while (*b && i + 1 < cap) o[i++] = *b++;
    o[i] = '\0';
}

static int ml_stat_path(FTS *f, const char *p, struct stat *st) {
    if (f->options & (FTS_LOGICAL | FTS_COMFOLLOW)) return stat(p, st);
    return lstat(p, st);
}

static int ml_on_cycle(FTS *f, dev_t d, ino_t ino) {
    int i;
    for (i = 0; i < f->anc_n; i++)
        if (f->adev[i] == d && f->aino[i] == ino) return 1;
    return 0;
}

static int ml_push_anc(FTS *f, dev_t d, ino_t ino) {
    if (f->anc_n == f->anc_cap) {
        int nc = f->anc_cap ? f->anc_cap * 2 : 16;
        dev_t *nd = realloc(f->adev, (size_t)nc * sizeof(*nd));
        ino_t *ni;
        if (!nd) return -1;
        ni = realloc(f->aino, (size_t)nc * sizeof(*ni));
        if (!ni) {
            free(nd);
            return -1;
        }
        f->adev = nd;
        f->aino = ni;
        f->anc_cap = nc;
    }
    f->adev[f->anc_n] = d;
    f->aino[f->anc_n] = ino;
    f->anc_n++;
    return 0;
}

static int ml_push_frame(FTS *f, DIR *d, const char *path,
                         const struct stat *st, int level) {
    char *cp;
    if (f->depth == f->cap) {
        int nc = f->cap ? f->cap * 2 : 16;
        ml_frame_t *ns =
            realloc(f->stack, (size_t)nc * sizeof(*ns));
        if (!ns) return -1;
        f->stack = ns;
        f->cap = nc;
    }
    cp = strdup(path);
    if (!cp) return -1;
    f->stack[f->depth].d = d;
    f->stack[f->depth].path = cp;
    if (st) f->stack[f->depth].st = *st;
    else memset(&f->stack[f->depth].st, 0, sizeof(struct stat));
    f->stack[f->depth].parent_link = 0;
    f->stack[f->depth].level = level;
    f->depth++;
    return 0;
}

static FTSENT *ml_emit(FTS *f, const char *path, int level, int info,
                       const struct stat *st) {
    const char *b;
    strncpy(f->cur_path, path, sizeof(f->cur_path) - 1);
    f->cur_path[sizeof(f->cur_path) - 1] = '\0';
    strncpy(f->cur_acc, path, sizeof(f->cur_acc) - 1);
    f->cur_acc[sizeof(f->cur_acc) - 1] = '\0';
    b = strrchr(f->cur_path, '/');
    f->cur.fts_path = f->cur_path;
    f->cur.fts_accpath = f->cur_acc;
    f->cur.fts_name = b ? b + 1 : f->cur_path;
    f->cur.fts_level = level;
    f->cur.fts_info = info;
    if (st) {
        f->cur_st = *st;
        f->cur.fts_statp = &f->cur_st;
    } else {
        f->cur.fts_statp = 0;
    }
    f->cur.fts_link = 0;
    f->cur.fts_parent = 0;
    f->cur.fts_pointer = 0;
    f->cur.fts_number = 0;
    return &f->cur;
}

FTS *fts_open(char *const *paths, int options,
              int (*cmp)(const FTSENT **, const FTSENT **)) {
    FTS *f;
    int n = 0, i;
    if (!paths || !paths[0]) {
        errno = EINVAL;
        return 0;
    }
    while (paths[n]) n++;
    f = calloc(1, sizeof(*f));
    if (!f) return 0;
    f->options = options ? options : FTS_PHYSICAL;
    f->cmp = cmp;
    f->roots = calloc((size_t)n, sizeof(char *));
    if (!f->roots) {
        free(f);
        return 0;
    }
    for (i = 0; i < n; i++) {
        f->roots[i] = strdup(paths[i]);
        if (!f->roots[i]) {
            while (--i >= 0) free(f->roots[i]);
            free(f->roots);
            free(f);
            errno = ENOMEM;
            return 0;
        }
    }
    f->nroot = n;
    return f;
}

int fts_close(FTS *f) {
    int i;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    while (f->depth > 0) {
        f->depth--;
        if (f->stack[f->depth].d) closedir(f->stack[f->depth].d);
        free(f->stack[f->depth].path);
    }
    for (i = 0; i < f->nroot; i++) free(f->roots[i]);
    free(f->roots);
    free(f->stack);
    free(f->adev);
    free(f->aino);
    free(f->kids);
    free(f->kid_paths);
    free(f->kid_stats);
    free(f);
    return 0;
}

int fts_set(FTS *f, FTSENT *e, int instr) {
    (void)e;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    if (instr == FTS_SKIP) f->skip_next = 1;
    else if (instr == FTS_FOLLOW) f->options |= FTS_COMFOLLOW;
    else if (instr != FTS_AGAIN && instr != FTS_NOINSTR) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

FTSENT *fts_read(FTS *f) {
    if (!f) return 0;
    /* Roots first. */
    if (f->rpos < f->nroot) {
        const char *rp = f->roots[f->rpos++];
        struct stat st;
        int nostat = (f->options & FTS_NOSTAT) != 0;
        if (!nostat && ml_stat_path(f, rp, &st) != 0)
            return ml_emit(f, rp, 0, FTS_NS, 0);
        if (!nostat && S_ISDIR(st.st_mode) &&
            !(S_ISLNK(st.st_mode) &&
              (f->options & FTS_PHYSICAL) &&
              !(f->options & FTS_COMFOLLOW))) {
            DIR *d;
            if (ml_on_cycle(f, st.st_dev, st.st_ino))
                return ml_emit(f, rp, 0, FTS_DC, &st);
            d = opendir(rp);
            if (!d) return ml_emit(f, rp, 0, FTS_DNR, &st);
            if (ml_push_anc(f, st.st_dev, st.st_ino) != 0 ||
                ml_push_frame(f, d, rp, &st, 0) != 0) {
                closedir(d);
                return ml_emit(f, rp, 0, FTS_ERR, &st);
            }
            return ml_emit(f, rp, 0, FTS_D, &st);
        }
        if (nostat) return ml_emit(f, rp, 0, FTS_NSOK, 0);
        if (S_ISLNK(st.st_mode)) {
            struct stat tst;
            if (stat(rp, &tst) != 0)
                return ml_emit(f, rp, 0, FTS_SLNONE, &st);
            return ml_emit(f, rp, 0, FTS_SL, &st);
        }
        if (S_ISREG(st.st_mode)) return ml_emit(f, rp, 0, FTS_F, &st);
        return ml_emit(f, rp, 0, FTS_DEFAULT, &st);
    }
    /* Walk the stack. */
    for (;;) {
        DIR *d;
        const char *base;
        int level;
        struct dirent *e;
        if (f->depth == 0) return 0;
        d = f->stack[f->depth - 1].d;
        base = f->stack[f->depth - 1].path;
        level = f->stack[f->depth - 1].level + 1;
        if (f->skip_next) {
            char dp[512];
            struct stat dst;
            f->skip_next = 0;
            strncpy(dp, base, sizeof(dp) - 1);
            dp[sizeof(dp) - 1] = '\0';
            dst = f->stack[f->depth - 1].st;
            closedir(d);
            free(f->stack[f->depth - 1].path);
            f->depth--;
            if (f->anc_n > 0) f->anc_n--;
            return ml_emit(f, dp, level - 1, FTS_DP, &dst);
        }
        e = readdir(d);
        if (!e) {
            char dp[512];
            struct stat dst;
            strncpy(dp, base, sizeof(dp) - 1);
            dp[sizeof(dp) - 1] = '\0';
            dst = f->stack[f->depth - 1].st;
            closedir(d);
            free(f->stack[f->depth - 1].path);
            f->depth--;
            if (f->anc_n > 0) f->anc_n--;
            return ml_emit(f, dp, level - 1, FTS_DP, &dst);
        }
        if (!(f->options & FTS_SEEDOT) && ml_is_dot(e->d_name))
            continue;
        {
            char full[512];
            struct stat st;
            int nostat = (f->options & FTS_NOSTAT) != 0;
            int islink = 0;
            ml_join(full, sizeof(full), base, e->d_name);
            if (!nostat && ml_stat_path(f, full, &st) != 0)
                return ml_emit(f, full, level, FTS_NS, 0);
            if (!nostat) {
                struct stat lst;
                if (lstat(full, &lst) == 0 && S_ISLNK(lst.st_mode))
                    islink = 1;
            }
            if (!nostat && S_ISDIR(st.st_mode) &&
                !(islink && (f->options & FTS_PHYSICAL) &&
                  !(f->options & FTS_COMFOLLOW))) {
                DIR *nd;
                if ((f->options & FTS_XDEV) && f->anc_n > 0 &&
                    st.st_dev != f->adev[0])
                    return ml_emit(f, full, level, FTS_D, &st);
                if (ml_on_cycle(f, st.st_dev, st.st_ino))
                    return ml_emit(f, full, level, FTS_DC, &st);
                nd = opendir(full);
                if (!nd)
                    return ml_emit(f, full, level, FTS_DNR, &st);
                if (ml_push_anc(f, st.st_dev, st.st_ino) != 0 ||
                    ml_push_frame(f, nd, full, &st, level) != 0) {
                    closedir(nd);
                    return ml_emit(f, full, level, FTS_ERR, &st);
                }
                return ml_emit(f, full, level, FTS_D, &st);
            }
            if (nostat) return ml_emit(f, full, level, FTS_NSOK, 0);
            if (islink || S_ISLNK(st.st_mode)) {
                struct stat tst;
                if (stat(full, &tst) != 0)
                    return ml_emit(f, full, level, FTS_SLNONE, &st);
                return ml_emit(f, full, level, FTS_SL, &st);
            }
            if (S_ISREG(st.st_mode))
                return ml_emit(f, full, level, FTS_F, &st);
            return ml_emit(f, full, level, FTS_DEFAULT, &st);
        }
    }
}

FTSENT *fts_children(FTS *f, int instr) {
    DIR *d;
    const char *base;
    struct dirent *e;
    int n = 0, i, j, cap = 0;
    char (*paths)[256] = 0;
    (void)instr;
    if (!f || f->depth == 0) {
        errno = EINVAL;
        return 0;
    }
    d = f->stack[f->depth - 1].d;
    base = f->stack[f->depth - 1].path;
    rewinddir(d);
    /* Collect names (bounded at 256). */
    paths = calloc(256, sizeof(*paths));
    if (!paths) return 0;
    while ((e = readdir(d)) != 0 && n < 256) {
        if (!(f->options & FTS_SEEDOT) && ml_is_dot(e->d_name))
            continue;
        strncpy(paths[n], e->d_name, sizeof(paths[n]) - 1);
        n++;
    }
    rewinddir(d);
    if (n == 0) {
        free(paths);
        return 0;
    }
    free(f->kids);
    free(f->kid_paths);
    free(f->kid_stats);
    f->kids = calloc((size_t)n, sizeof(FTSENT));
    f->kid_paths = calloc((size_t)n, 512);
    f->kid_stats = calloc((size_t)n, sizeof(struct stat));
    if (!f->kids || !f->kid_paths || !f->kid_stats) {
        free(paths);
        return 0;
    }
    cap = n;
    for (i = 0; i < n; i++) {
        char full[512];
        FTSENT *k = &f->kids[i];
        char *dst = f->kid_paths + (size_t)i * 512;
        ml_join(full, sizeof(full), base, paths[i]);
        strncpy(dst, full, 511);
        k->fts_path = dst;
        k->fts_accpath = dst;
        {
            const char *b = strrchr(dst, '/');
            k->fts_name = b ? b + 1 : dst;
        }
        k->fts_level = f->stack[f->depth - 1].level + 1;
        if (ml_stat_path(f, full, &f->kid_stats[i]) == 0) {
            k->fts_statp = &f->kid_stats[i];
            if (S_ISDIR(f->kid_stats[i].st_mode)) k->fts_info = FTS_D;
            else if (S_ISLNK(f->kid_stats[i].st_mode))
                k->fts_info = FTS_SL;
            else if (S_ISREG(f->kid_stats[i].st_mode))
                k->fts_info = FTS_F;
            else k->fts_info = FTS_DEFAULT;
        } else {
            k->fts_statp = 0;
            k->fts_info = FTS_NS;
        }
        k->fts_link = (i + 1 < n) ? &f->kids[i + 1] : 0;
        k->fts_parent = 0;
        k->fts_pointer = 0;
        k->fts_number = 0;
        (void)cap;
    }
    free(paths);
    if (f->cmp && n > 1) {
        for (i = 1; i < n; i++) {
            FTSENT t = f->kids[i];
            const char *tp = t.fts_path, *tn = t.fts_name;
            struct stat *tsp = t.fts_statp;
            j = i;
            while (j > 0) {
                const FTSENT *a = &f->kids[j - 1];
                const FTSENT *b = &t;
                if (f->cmp(&a, &b) <= 0) break;
                f->kids[j] = f->kids[j - 1];
                j--;
            }
            f->kids[j] = t;
            /* repair moved string pointers */
            f->kids[j].fts_path =
                f->kid_paths + (size_t)j * 512;
            f->kids[j].fts_accpath = f->kids[j].fts_path;
            {
                const char *b2 =
                    strrchr(f->kids[j].fts_path, '/');
                f->kids[j].fts_name =
                    b2 ? b2 + 1 : f->kids[j].fts_path;
                (void)tp;
                (void)tn;
                (void)tsp;
            }
        }
        /* stats array no longer matches after sort: re-resolve */
        for (i = 0; i < n; i++) {
            if (ml_stat_path(f, f->kids[i].fts_path,
                             &f->kid_stats[i]) == 0)
                f->kids[i].fts_statp = &f->kid_stats[i];
            else
                f->kids[i].fts_statp = 0;
            f->kids[i].fts_link =
                (i + 1 < n) ? &f->kids[i + 1] : 0;
        }
    }
    f->nkids = n;
    return &f->kids[0];
}
