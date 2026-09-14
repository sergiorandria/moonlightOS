/* libc fnmatch + glob + ftw + wordexp over dirent/getdents. */
#include <fnmatch.h>
#include <glob.h>
#include <ftw.h>
#include <wordexp.h>
#include <dirent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- fnmatch ---- */

/* Forward: extglob groups (defined below, used by ml_fn_match). */
static int ml_ext_group(const char *pat, const char *s, int flags,
                        int pathname, int period);
static int ml_fn_match(const char *pat, const char *s, int flags,
                       int pathname, int period);

static int ml_fn_class(const char **pp, int c, int nocase) {
    const char *p = *pp;
    int negate = 0, hit = 0;
    if (*p == '!') {
        negate = 1;
        p++;
    }
    if (*p == ']') {
        int cc = nocase ? tolower((unsigned char)c) : c;
        if (cc == ']') hit = 1;
        p++;
    }
    while (*p && *p != ']') {
        int lo, hi;
        if (*p == '\\' && p[1]) p++;
        lo = (unsigned char)*p++;
        if (*p == '-' && p[1] && p[1] != ']') {
            p++;
            if (*p == '\\' && p[1]) p++;
            hi = (unsigned char)*p++;
        } else {
            hi = lo;
        }
        {
            int cc = nocase ? tolower((unsigned char)c) : c;
            int a = nocase ? tolower(lo) : lo;
            int b = nocase ? tolower(hi) : hi;
            if (cc >= a && cc <= b) hit = 1;
        }
    }
    if (*p == ']') p++;
    *pp = p;
    return negate ? !hit : hit;
}

static int ml_fn_match(const char *pat, const char *s, int flags,
                       int pathname, int period) {
    int nocase = (flags & FNM_NOCASE) != 0;
    int noesc = (flags & FNM_NOESCAPE) != 0;
    const char *ps = s;
    int first = 1;
    while (*pat) {
        if ((flags & FNM_EXTMATCH) &&
            (*pat == '?' || *pat == '*' || *pat == '+' || *pat == '@' ||
             *pat == '!') &&
            pat[1] == '(') {
            int r = ml_ext_group(pat, s, flags, pathname, period);
            if (r != -1) return r;
            /* Unbalanced: fall through and match literally. */
        }
        {
            char c = *pat++;
        if (c == '*') {
            const char *pp = pat;
            while (*pp == '*') pp++;
            pat = pp;
            if (!*pat) {
                /* Trailing *: match rest (respecting pathname/period). */
                if (pathname) {
                    if (strchr(s, '/')) return FNM_NOMATCH;
                    if (period && *s == '.' && first) {
                        if (strcmp(s, ".") == 0 ||
                            strcmp(s, "..") == 0)
                            return FNM_NOMATCH;
                    }
                }
                if (period && *s == '.' && first) return FNM_NOMATCH;
                return FNM_MATCH;
            }
            while (*s) {
                if (pathname && *s == '/') break;
                if (period && *s == '.' && s == ps && first) break;
                if (ml_fn_match(pat, s, flags, pathname, 0) ==
                    FNM_MATCH)
                    return FNM_MATCH;
                s++;
            }
            return ml_fn_match(pat, s, flags, pathname, 0);
        }
        if (*s == '\0') return FNM_NOMATCH;
        if (pathname && c == '/' && *s != '/') return FNM_NOMATCH;
        if (pathname && *s == '/' && c != '/') {
            if (c != '?' && c != '[') return FNM_NOMATCH;
        }
        if (period && *s == '.' && first &&
            (c != '.' && c != '\\')) {
            if (s == ps || (pathname && *(s - 1) == '/'))
                return FNM_NOMATCH;
        }
        first = 0;
        if (c == '?') {
            if (pathname && *s == '/') return FNM_NOMATCH;
            s++;
        } else if (c == '[') {
            const char *pp = pat;
            int cc = (unsigned char)*s;
            if (!ml_fn_class(&pp, cc, nocase)) return FNM_NOMATCH;
            pat = pp;
            if (pathname && cc == '/') return FNM_NOMATCH;
            s++;
        } else if (c == '\\' && !noesc) {
            char n = *pat++;
            int a = nocase ? tolower((unsigned char)n) : n;
            int b = nocase ? tolower((unsigned char)*s) : *s;
            if (!n || a != b) return FNM_NOMATCH;
            s++;
        } else {
            int a = nocase ? tolower((unsigned char)c) : c;
            int b = nocase ? tolower((unsigned char)*s) : *s;
            if (a != b) return FNM_NOMATCH;
            s++;
        }
        if (pathname && *(s - 1) == '/') first = 1;
        }
    }
    return *s == '\0' ? FNM_MATCH : FNM_NOMATCH;
}

int fnmatch(const char *pat, const char *s, int flags) {
    int r;
    if (!pat || !s) {
        errno = EINVAL;
        return FNM_NOMATCH;
    }
    r = ml_fn_match(pat, s, flags, (flags & FNM_PATHNAME) != 0,
                    (flags & FNM_PERIOD) != 0);
    if (r == FNM_MATCH) return r;
    if (flags & FNM_LEADING_DIR) {
        /* Match pat against each leading directory prefix of s. */
        const char *p = s;
        char pre[256];
        while (*p) {
            size_t n;
            if (*p != '/') {
                p++;
                continue;
            }
            n = (size_t)(p - s);
            if (n >= sizeof(pre)) return FNM_NOMATCH;
            memcpy(pre, s, n);
            pre[n] = '\0';
            if (ml_fn_match(pat, pre, flags & ~FNM_LEADING_DIR,
                            (flags & FNM_PATHNAME) != 0,
                            (flags & FNM_PERIOD) != 0) == FNM_MATCH)
                return FNM_MATCH;
            p++;
        }
    }
    return r;
}

/* ---- ksh extglob: ?() *() +() @() !() (FNM_EXTMATCH) ---- */

/* Find the ')' matching the '(' at *open (nesting + escapes +
 * bracket classes honored). Returns pointer to it, or 0. */
static const char *ml_ext_close(const char *open) {
    int depth = 0;
    const char *p = open;
    if (*p != '(') return 0;
    while (*p) {
        if (*p == '\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == '[') {
            p++;
            if (*p == ']') p++;
            while (*p && *p != ']') {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            if (*p) p++;
            continue;
        }
        if (*p == '(') depth++;
        else if (*p == ')') {
            depth--;
            if (depth == 0) return p;
        }
        p++;
    }
    return 0;
}

/* Try matching: alternative ALT (NUL-terminated copy) then REST
 * against S, with pathname/period/flags. */
static int ml_ext_try(const char *alt, const char *rest, const char *s,
                      int flags, int pathname, int period);

/* Split the group body at top-level '|' and try each alternative. */
static int ml_ext_alts(const char *body, const char *close,
                       const char *rest, const char *s, int flags,
                       int pathname, int period, char op) {
    const char *start = body;
    const char *p = body;
    int depth = 0;
    (void)op;
    for (;;) {
        int is_end = (p == close);
        if (!is_end) {
            if (*p == '\\' && p[1]) {
                p += 2;
                continue;
            }
            if (*p == '[') {
                const char *q = p + 1;
                if (*q == ']') q++;
                while (*q && *q != ']') {
                    if (*q == '\\' && q[1]) q++;
                    q++;
                }
                p = *q ? q + 1 : q;
                continue;
            }
            if (*p == '(') {
                /* Nested extglob opener only if prefixed by an op
                 * letter; a bare '(' is literal. */
                if (p > body &&
                    (p[-1] == '?' || p[-1] == '*' || p[-1] == '+' ||
                     p[-1] == '@' || p[-1] == '!'))
                    depth++;
                p++;
                continue;
            }
            if (*p == ')') {
                if (depth > 0) depth--;
                p++;
                continue;
            }
            if (*p == '|' && depth == 0) {
                char alt[256];
                size_t n = (size_t)(p - start);
                if (n >= sizeof(alt)) return FNM_NOMATCH;
                memcpy(alt, start, n);
                alt[n] = '\0';
                if (ml_ext_try(alt, rest, s, flags, pathname, period) ==
                    FNM_MATCH)
                    return FNM_MATCH;
                start = p + 1;
                p++;
                continue;
            }
            p++;
            continue;
        }
        {
            char alt[256];
            size_t n = (size_t)(p - start);
            if (n >= sizeof(alt)) return FNM_NOMATCH;
            memcpy(alt, start, n);
            alt[n] = '\0';
            return ml_ext_try(alt, rest, s, flags, pathname, period);
        }
    }
}

static int ml_ext_try(const char *alt, const char *rest, const char *s,
                      int flags, int pathname, int period) {
    /* Match ALT then REST by splitting s at every position. Bounded
     * (256) and correct: ALT is a plain sub-pattern here. */
    char combo[512];
    if (strlen(alt) + strlen(rest) + 1 >= sizeof(combo))
        return FNM_NOMATCH;
    strcpy(combo, alt);
    strcat(combo, rest);
    return ml_fn_match(combo, s, flags & ~FNM_EXTMATCH, pathname, period);
}

/* Match an extglob group starting at PAT (op letter + '(' ... ')'),
 * then continue with the pattern after ')'. Returns FNM_MATCH /
 * FNM_NOMATCH, or -1 if PAT is not an extglob. */
static int ml_ext_group(const char *pat, const char *s, int flags,
                        int pathname, int period) {
    char op = pat[0];
    const char *close, *rest;
    char body[256];
    size_t n;
    if (op != '?' && op != '*' && op != '+' && op != '@' && op != '!')
        return -1;
    if (pat[1] != '(') return -1;
    close = ml_ext_close(pat + 1);
    if (!close) return -1;
    rest = close + 1;
    n = (size_t)(close - (pat + 2));
    if (n >= sizeof(body)) return FNM_NOMATCH;
    memcpy(body, pat + 2, n);
    body[n] = '\0';
    if (op == '@') {
        return ml_ext_alts(body, body + n, rest, s, flags, pathname,
                           period, op);
    }
    if (op == '!') {
        /* Match iff some split point defeats every alternative. */
        size_t slen = strlen(s), cut;
        char tail[256], head[256];
        if (slen >= sizeof(head)) return FNM_NOMATCH;
        for (cut = 0; cut <= slen; cut++) {
            const char *start = body;
            const char *p = body;
            int depth = 0, any_hit = 0;
            memcpy(head, s, cut);
            head[cut] = '\0';
            /* Check each alternative against head[0,cut). */
            for (;;) {
                int is_end = (*p == '\0');
                if (!is_end) {
                    if (*p == '\\' && p[1]) {
                        p += 2;
                        continue;
                    }
                    if (*p == '(' && p > body &&
                        (p[-1] == '?' || p[-1] == '*' || p[-1] == '+' ||
                         p[-1] == '@' || p[-1] == '!'))
                        depth++;
                    else if (*p == ')' && depth > 0)
                        depth--;
                    else if (*p == '|' && depth == 0) {
                        char alt[256];
                        size_t m = (size_t)(p - start);
                        if (m < sizeof(alt)) {
                            memcpy(alt, start, m);
                            alt[m] = '\0';
                            if (ml_fn_match(alt, head,
                                            flags & ~FNM_EXTMATCH,
                                            pathname, 0) == FNM_MATCH)
                                any_hit = 1;
                        }
                        start = p + 1;
                    }
                    p++;
                    continue;
                }
                {
                    char alt[256];
                    size_t m = (size_t)(p - start);
                    if (m < sizeof(alt)) {
                        memcpy(alt, start, m);
                        alt[m] = '\0';
                        if (ml_fn_match(alt, head,
                                        flags & ~FNM_EXTMATCH, pathname,
                                        0) == FNM_MATCH)
                            any_hit = 1;
                    }
                    break;
                }
            }
            if (!any_hit) {
                size_t rl = strlen(rest), tl = strlen(s + cut);
                if (rl + tl + 1 >= sizeof(tail)) continue;
                strcpy(tail, s + cut);
                if (ml_fn_match(rest, tail, flags & ~FNM_EXTMATCH,
                                pathname, 0) == FNM_MATCH)
                    return FNM_MATCH;
            }
        }
        return FNM_NOMATCH;
    }
    /* ? * + : bounded repetition over greedy spans. ?() = 0..1,
     * *() = 0.., +() = 1...  Try longest-first (512 cap). */
    {
        size_t slen = strlen(s), cut, lo = (op == '+') ? 1 : 0;
        char head[512], tail[512];
        if (slen >= sizeof(head)) return FNM_NOMATCH;
        for (cut = slen; cut >= lo; cut--) {
            const char *start = body;
            const char *p = body;
            int depth = 0, ok = 1;
            if (cut == 0 && op == '?') {
                /* Zero reps: alternatives match empty? Only empty
                 * alternatives can; approximate via empty-alt. */
            }
            memcpy(head, s, cut);
            head[cut] = '\0';
            /* Verify head is 1+ (or 0+) repetitions of alternatives. */
            if (cut > 0 || op != '?') {
                size_t pos = 0;
                int reps = 0;
                while (pos < cut) {
                    /* One repetition = one alternative matching a
                     * non-empty prefix of head[pos:]. */
                    size_t best = 0;
                    const char *st2 = body;
                    const char *q = body;
                    int d2 = 0;
                    for (;;) {
                        int is_end = (*q == '\0');
                        if (!is_end) {
                            if (*q == '\\' && q[1]) {
                                q += 2;
                                continue;
                            }
                            if (*q == '(' && q > body &&
                                (q[-1] == '?' || q[-1] == '*' ||
                                 q[-1] == '+' || q[-1] == '@' ||
                                 q[-1] == '!'))
                                d2++;
                            else if (*q == ')' && d2 > 0)
                                d2--;
                            else if (*q == '|' && d2 == 0) {
                                char alt[256];
                                size_t m = (size_t)(q - st2), L;
                                if (m < sizeof(alt)) {
                                    memcpy(alt, st2, m);
                                    alt[m] = '\0';
                                    for (L = cut - pos; L > 0; L--) {
                                        char tmp[512];
                                        memcpy(tmp, head + pos, L);
                                        tmp[L] = '\0';
                                        if (ml_fn_match(
                                                alt, tmp,
                                                flags & ~FNM_EXTMATCH,
                                                pathname, 0) ==
                                            FNM_MATCH) {
                                            if (L > best) best = L;
                                            break;
                                        }
                                    }
                                }
                                st2 = q + 1;
                            }
                            q++;
                            continue;
                        }
                        {
                            char alt[256];
                            size_t m = (size_t)(q - st2), L;
                            if (m < sizeof(alt)) {
                                memcpy(alt, st2, m);
                                alt[m] = '\0';
                                for (L = cut - pos; L > 0; L--) {
                                    char tmp[512];
                                    memcpy(tmp, head + pos, L);
                                    tmp[L] = '\0';
                                    if (ml_fn_match(
                                            alt, tmp,
                                            flags & ~FNM_EXTMATCH,
                                            pathname, 0) == FNM_MATCH) {
                                        if (L > best) best = L;
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    if (best == 0) {
                        ok = 0;
                        break;
                    }
                    pos += best;
                    reps++;
                }
                if (!ok || (op == '+' && reps < 1)) continue;
                if (op == '?' && reps > 1) continue;
            }
            {
                size_t rl = strlen(rest), tl = strlen(s + cut);
                if (rl + tl + 1 >= sizeof(tail)) continue;
                strcpy(tail, s + cut);
                if (ml_fn_match(rest, tail, flags & ~FNM_EXTMATCH,
                                pathname, 0) == FNM_MATCH)
                    return FNM_MATCH;
            }
            if (cut == 0) break;
        }
        return FNM_NOMATCH;
    }
}

/* ---- glob ---- */

static int ml_has_meta(const char *s, int noesc) {
    while (*s) {
        if (*s == '*' || *s == '?' || *s == '[') return 1;
        if (*s == '\\' && !noesc && s[1]) s++;
        s++;
    }
    return 0;
}

static int ml_glob_add(glob_t *g, const char *s, int mark_dir) {
    char *c;
    size_t need = strlen(s) + (mark_dir ? 2 : 1);
    char **nv;
    if (g->gl_pathc >= 1000) {
        errno = ENOMEM;
        return -1;
    }
    c = malloc(need);
    if (!c) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(c, s, strlen(s) + 1);
    if (mark_dir) {
        c[strlen(s)] = '/';
        c[strlen(s) + 1] = '\0';
    }
    nv = realloc(g->gl_pathv,
                 (g->gl_pathc + g->gl_offs + 1) * sizeof(*nv));
    if (!nv) {
        free(c);
        errno = ENOMEM;
        return -1;
    }
    g->gl_pathv = nv;
    nv[g->gl_offs + g->gl_pathc] = c;
    g->gl_pathc++;
    nv[g->gl_offs + g->gl_pathc] = 0;
    return 0;
}

static int ml_glob_dir(const char *pat, int flags, glob_t *g,
                       int (*err)(const char *, int)) {
    int use_alt = (flags & GLOB_ALTDIRFUNC) && g->gl_opendir &&
                  g->gl_readdir && g->gl_closedir;
    int fnflags = (flags & GLOB_PERIOD) ? 0 : FNM_PERIOD;
    int nmatch = 0;
    if (use_alt) {
        void *d = g->gl_opendir(".");
        struct dirent *e;
        if (!d) {
            if (err) err(".", errno);
            if (flags & GLOB_ERR) return GLOB_ABORTED;
            return 0;
        }
        while ((e = g->gl_readdir(d)) != 0) {
            if (strcmp(e->d_name, ".") == 0 ||
                strcmp(e->d_name, "..") == 0)
                continue;
            if (e->d_name[0] == '.' && pat[0] != '.') continue;
            if (fnmatch(pat, e->d_name, fnflags) != 0) continue;
            {
                int is_dir = e->d_type == DT_DIR;
                if (e->d_type == DT_UNKNOWN && g->gl_stat) {
                    struct stat st;
                    if (g->gl_stat(e->d_name, &st) == 0)
                        is_dir = S_ISDIR(st.st_mode);
                }
                if (ml_glob_add(g, e->d_name,
                                is_dir && (flags & GLOB_MARK)) != 0) {
                    g->gl_closedir(d);
                    return GLOB_NOSPACE;
                }
                nmatch++;
            }
        }
        g->gl_closedir(d);
        return nmatch;
    }
    {
        DIR *d = opendir(".");
        struct dirent *e;
        if (!d) {
            if (err) err(".", errno);
            if (flags & GLOB_ERR) return GLOB_ABORTED;
            return 0;
        }
        while ((e = readdir(d)) != 0) {
            if (strcmp(e->d_name, ".") == 0 ||
                strcmp(e->d_name, "..") == 0)
                continue;
            if (e->d_name[0] == '.' && pat[0] != '.') continue;
            if (fnmatch(pat, e->d_name, fnflags) != 0) continue;
            {
                int is_dir = e->d_type == DT_DIR;
                if (ml_glob_add(g, e->d_name,
                                is_dir && (flags & GLOB_MARK)) != 0) {
                    closedir(d);
                    return GLOB_NOSPACE;
                }
                nmatch++;
            }
        }
        closedir(d);
        return nmatch;
    }
}

int glob(const char *pat, int flags,
         int (*err)(const char *path, int err), glob_t *g) {
    int noesc = (flags & GLOB_NOESCAPE) != 0;
    if (!pat || !g) {
        errno = EINVAL;
        return GLOB_ABORTED;
    }
    if (!(flags & GLOB_APPEND)) {
        g->gl_pathc = 0;
        g->gl_pathv = 0;
        if (!(flags & GLOB_DOOFFS)) g->gl_offs = 0;
        else {
            size_t i;
            g->gl_pathv = calloc(g->gl_offs + 1, sizeof(char *));
            if (!g->gl_pathv && g->gl_offs) {
                errno = ENOMEM;
                return GLOB_NOSPACE;
            }
            for (i = 0; i < g->gl_offs; i++) g->gl_pathv[i] = 0;
        }
    }
    if (!ml_has_meta(pat, noesc)) {
        /* Literal: include iff it exists (NOMAGIC: always include). */
        if ((flags & GLOB_NOMAGIC) || access(pat, F_OK) == 0)
            return ml_glob_add(g, pat, 0) == 0 ? 0 : GLOB_NOSPACE;
        if (flags & GLOB_NOCHECK)
            return ml_glob_add(g, pat, 0) == 0 ? 0 : GLOB_NOSPACE;
        return g->gl_pathc > 0 ? 0 : GLOB_NOMATCH;
    }
    /* Brace expansion {a,b,c} (first top-level group only per pass;
     * recursion handles nesting). */
    if (flags & GLOB_BRACE) {
        const char *open = 0, *p = pat;
        int depth = 0;
        while (*p) {
            if (*p == '\\' && p[1]) {
                p += 2;
                continue;
            }
            if (*p == '{' && depth++ == 0) open = p;
            else if (*p == '}') {
                if (--depth == 0) break;
                if (depth < 0) {
                    depth = 0;
                    open = 0;
                }
            }
            p++;
        }
        if (open && *p == '}') {
            /* Split open+1..p at top-level commas and recurse. */
            const char *start = open + 1;
            const char *q = start;
            int d2 = 0, rc = 0, any = 0;
            char pre[256], alt[256], post[256];
            size_t prelen = (size_t)(open - pat);
            if (prelen >= sizeof(pre)) {
                errno = ENAMETOOLONG;
                return GLOB_ABORTED;
            }
            memcpy(pre, pat, prelen);
            pre[prelen] = '\0';
            strncpy(post, p + 1, sizeof(post) - 1);
            post[sizeof(post) - 1] = '\0';
            for (;;) {
                int is_end = (*q == '\0' || q == p);
                if (!is_end) {
                    if (*q == '\\' && q[1]) {
                        q += 2;
                        continue;
                    }
                    if (*q == '{') d2++;
                    else if (*q == '}') d2--;
                    else if (*q == ',' && d2 == 0) {
                        size_t n = (size_t)(q - start);
                        char exp[768];
                        if (n >= sizeof(alt)) {
                            errno = ENAMETOOLONG;
                            return GLOB_ABORTED;
                        }
                        memcpy(alt, start, n);
                        alt[n] = '\0';
                        if (strlen(pre) + n + strlen(post) >=
                            sizeof(exp)) {
                            errno = ENAMETOOLONG;
                            return GLOB_ABORTED;
                        }
                        strcpy(exp, pre);
                        strcat(exp, alt);
                        strcat(exp, post);
                        rc = glob(exp, flags & ~GLOB_BRACE, err, g);
                        if (rc != 0 && rc != GLOB_NOMATCH) return rc;
                        if (rc == 0) any = 1;
                        start = q + 1;
                    }
                    q++;
                    continue;
                }
                {
                    size_t n = (size_t)(q - start);
                    char exp[768];
                    if (n >= sizeof(alt)) {
                        errno = ENAMETOOLONG;
                        return GLOB_ABORTED;
                    }
                    memcpy(alt, start, n);
                    alt[n] = '\0';
                    if (strlen(pre) + n + strlen(post) >= sizeof(exp)) {
                        errno = ENAMETOOLONG;
                        return GLOB_ABORTED;
                    }
                    strcpy(exp, pre);
                    strcat(exp, alt);
                    strcat(exp, post);
                    rc = glob(exp, flags & ~GLOB_BRACE, err, g);
                    if (rc != 0 && rc != GLOB_NOMATCH) return rc;
                    if (rc == 0) any = 1;
                    return any ? 0
                               : (g->gl_pathc > 0 ? 0 : GLOB_NOMATCH);
                }
            }
        }
    }
    /* Tilde expansion: ~/... and ~user/... */
    if ((flags & (GLOB_TILDE | GLOB_TILDE_CHECK)) && pat[0] == '~') {
        char exp[512];
        const char *rest = pat + 1;
        const char *home = 0;
        char ubuf[64];
        size_t i = 0;
        while (rest[i] && rest[i] != '/') i++;
        if (i == 0) {
            home = getenv("HOME");
            if (!home) {
                struct passwd *pw = getpwuid(getuid());
                if (pw) home = pw->pw_dir;
            }
            if (!home) {
                if (flags & GLOB_TILDE_CHECK) return GLOB_NOMATCH;
                goto no_tilde;
            }
        } else {
            struct passwd *pw;
            if (i >= sizeof(ubuf)) {
                errno = ENAMETOOLONG;
                return GLOB_ABORTED;
            }
            memcpy(ubuf, rest, i);
            ubuf[i] = '\0';
            pw = getpwnam(ubuf);
            if (!pw) {
                if (flags & GLOB_TILDE_CHECK) return GLOB_NOMATCH;
                goto no_tilde;
            }
            home = pw->pw_dir;
        }
        if (strlen(home) + strlen(rest + i) >= sizeof(exp)) {
            errno = ENAMETOOLONG;
            return GLOB_ABORTED;
        }
        strcpy(exp, home);
        strcat(exp, rest + i);
        return glob(exp, flags & ~(GLOB_TILDE | GLOB_TILDE_CHECK), err,
                    g);
    no_tilde:;
    }
    /* Flat namespace: patterns with '/' can never match (VFS names
     * carry no slashes); only the basename is significant. */
    {
        const char *base = pat;
        const char *p;
        for (p = pat; *p; p++)
            if (*p == '/') base = p + 1;
        if (base != pat) {
            /* A directory prefix is required to exist. */
            char dir[256];
            size_t n = (size_t)(base - pat);
            if (n >= sizeof(dir)) {
                errno = ENAMETOOLONG;
                return GLOB_ABORTED;
            }
            memcpy(dir, pat, n);
            dir[n] = '\0';
            if (access(n > 0 ? dir : ".", F_OK) != 0) {
                if (flags & GLOB_NOCHECK)
                    return ml_glob_add(g, pat, 0) == 0 ? 0
                                                       : GLOB_NOSPACE;
                return g->gl_pathc > 0 ? 0 : GLOB_NOMATCH;
            }
        }
        {
            int r = ml_glob_dir(base, flags, g, err);
            if (r < 0) return r;
            if (r == 0 && g->gl_pathc == 0) {
                if (flags & GLOB_NOCHECK)
                    return ml_glob_add(g, pat, 0) == 0 ? 0
                                                       : GLOB_NOSPACE;
                return GLOB_NOMATCH;
            }
        }
    }
    if (!(flags & GLOB_NOSORT) && g->gl_pathc > 1) {
        size_t i, j, base = g->gl_offs;
        for (i = base + 1; i < base + g->gl_pathc; i++) {
            char *t = g->gl_pathv[i];
            j = i;
            while (j > base &&
                   strcmp(g->gl_pathv[j - 1], t) > 0) {
                g->gl_pathv[j] = g->gl_pathv[j - 1];
                j--;
            }
            g->gl_pathv[j] = t;
        }
    }
    return 0;
}

void globfree(glob_t *g) {
    size_t i;
    if (!g || !g->gl_pathv) return;
    for (i = 0; i < g->gl_offs + g->gl_pathc; i++)
        free(g->gl_pathv[i]);
    free(g->gl_pathv);
    g->gl_pathv = 0;
    g->gl_pathc = 0;
}

/* ---- ftw/nftw ---- */

static int ml_ftw_walk(const char *path,
                       int (*fn)(const char *, const struct stat *,
                                 int),
                       int (*fn2)(const char *, const struct stat *,
                                  int, struct FTW *),
                       int flags, int level) {
    struct stat st;
    int type;
    char child[256];
    if (lstat(path, &st) != 0) {
        if (fn) return fn(path, 0, FTW_NS);
        if (fn2) {
            struct FTW f = {0, level};
            return fn2(path, 0, FTW_NS, &f);
        }
        return -1;
    }
    if (S_ISDIR(st.st_mode)) type = FTW_D;
    else if (S_ISLNK(st.st_mode)) type = (flags & FTW_PHYS) ? FTW_SL
                                                           : FTW_F;
    else type = FTW_F;
    if ((flags & FTW_DEPTH) && type == FTW_D) {
        /* Post-order: children first. */
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)) != 0) {
                int r;
                if (strcmp(e->d_name, ".") == 0 ||
                    strcmp(e->d_name, "..") == 0)
                    continue;
                snprintf(child, sizeof(child), "%s/%s", path,
                         e->d_name);
                r = ml_ftw_walk(child, fn, fn2, flags, level + 1);
                if (r != 0) {
                    closedir(d);
                    return r;
                }
            }
            closedir(d);
        }
        type = FTW_DP;
    }
    if (fn) {
        int r = fn(path, &st, type);
        if (r != 0) return r;
    } else if (fn2) {
        struct FTW f;
        f.base = 0;
        {
            const char *p = path;
            const char *q;
            for (q = path; *q; q++)
                if (*q == '/') p = q + 1;
            f.base = (int)(p - path);
        }
        f.level = level;
        {
            int r = fn2(path, &st, type, &f);
            if (r != 0) return r;
        }
    }
    if (!((flags & FTW_DEPTH)) && type == FTW_D) {
        DIR *d = opendir(path);
        if (!d) {
            if (fn) return fn(path, &st, FTW_DNR);
            if (fn2) {
                struct FTW f = {0, level};
                return fn2(path, &st, FTW_DNR, &f);
            }
            return -1;
        }
        {
            struct dirent *e;
            while ((e = readdir(d)) != 0) {
                int r;
                if (strcmp(e->d_name, ".") == 0 ||
                    strcmp(e->d_name, "..") == 0)
                    continue;
                snprintf(child, sizeof(child), "%s/%s", path,
                         e->d_name);
                r = ml_ftw_walk(child, fn, fn2, flags, level + 1);
                if (r != 0) {
                    closedir(d);
                    return r;
                }
            }
        }
        closedir(d);
    }
    return 0;
}

int ftw(const char *path, int (*fn)(const char *f,
                                    const struct stat *st, int type),
        int nfds) {
    (void)nfds;
    if (!path || !fn) {
        errno = EINVAL;
        return -1;
    }
    return ml_ftw_walk(path, fn, 0, FTW_PHYS, 0);
}

int nftw(const char *path,
         int (*fn)(const char *f, const struct stat *st, int type,
                   struct FTW *ftw),
         int nfds, int flags) {
    (void)nfds;
    if (!path || !fn) {
        errno = EINVAL;
        return -1;
    }
    return ml_ftw_walk(path, 0, fn, flags, 0);
}

/* ---- wordexp ---- */

int wordexp(const char *s, wordexp_t *w, int flags) {
    const char *p;
    char field[256];
    size_t flen = 0;
    int fields = 0;
    char **v = 0;
    size_t n = 0, cap = 0;
    if (!s || !w) return WRDE_SYNTAX;
    if (flags & ~(WRDE_APPEND | WRDE_DOOFFS | WRDE_SHOWERR | WRDE_REUSE |
                  WRDE_NOCMD | WRDE_UNDEF))
        return WRDE_SYNTAX;
    if (!(flags & (WRDE_APPEND | WRDE_REUSE))) {
        w->we_wordc = 0;
        w->we_wordv = 0;
        if (!(flags & WRDE_DOOFFS)) w->we_offs = 0;
    }
    if ((flags & (WRDE_APPEND | WRDE_REUSE)) && w->we_wordv) {
        /* Append after existing words: adopt the old strings into a
         * fresh build vector (offs slots are re-added at the end). */
        size_t i;
        n = w->we_wordc;
        cap = n + 8;
        v = malloc(cap * sizeof(*v));
        if (!v) return WRDE_NOSPACE;
        for (i = 0; i < n; i++) v[i] = w->we_wordv[w->we_offs + i];
        free(w->we_wordv);
        w->we_wordv = 0;
    } else {
        v = 0;
        n = 0;
        cap = 0;
    }
    p = s;
    while (*p) {
        char *f;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
        flen = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            if (*p == '\\' && p[1]) {
                p++;
                if (flen + 1 >= sizeof(field)) return WRDE_NOSPACE;
                field[flen++] = *p++;
            } else if (*p == '\'') {
                p++;
                while (*p && *p != '\'') {
                    if (flen + 1 >= sizeof(field))
                        return WRDE_NOSPACE;
                    field[flen++] = *p++;
                }
                if (*p == '\'') p++;
                else return WRDE_SYNTAX;
            } else if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p++;
                    else if (*p == '$' || *p == '`')
                        return WRDE_CMDSUB;
                    if (flen + 1 >= sizeof(field))
                        return WRDE_NOSPACE;
                    field[flen++] = *p++;
                }
                if (*p == '"') p++;
                else return WRDE_SYNTAX;
            } else if (*p == '~' && flen == 0) {
                /* Tilde expansion: ~/ -> / (single root). */
                const char *h = "/";
                p++;
                while (*h) {
                    if (flen + 1 >= sizeof(field))
                        return WRDE_NOSPACE;
                    field[flen++] = *h++;
                }
            } else if (*p == '$') {
                /* Parameter expansion only (no command subst). */
                const char *name;
                char nbuf[64];
                size_t nl = 0;
                const char *val = 0;
                p++;
                if (*p == '(' || *p == '`') return WRDE_CMDSUB;
                if (*p == '{') {
                    p++;
                    while (*p && *p != '}' && nl + 1 < sizeof(nbuf))
                        nbuf[nl++] = *p++;
                    if (*p != '}') return WRDE_SYNTAX;
                    p++;
                } else {
                    while ((*p >= 'A' && *p <= 'Z') ||
                           (*p >= 'a' && *p <= 'z') ||
                           (*p >= '0' && *p <= '9') || *p == '_') {
                        if (nl + 1 >= sizeof(nbuf)) return WRDE_NOSPACE;
                        nbuf[nl++] = *p++;
                    }
                }
                nbuf[nl] = '\0';
                name = nbuf;
                val = getenv(name);
                if (!val) {
                    if (flags & WRDE_UNDEF) return WRDE_BADVAL;
                    val = "";
                }
                while (*val) {
                    if (flen + 1 >= sizeof(field))
                        return WRDE_NOSPACE;
                    field[flen++] = *val++;
                }
            } else if (*p == '`') {
                return WRDE_CMDSUB;
            } else {
                if (*p == '*' || *p == '?' || *p == '[') {
                    /* Glob metachars pass through; expansion is the
                     * caller's glob() step (documented). */
                }
                if (flen + 1 >= sizeof(field)) return WRDE_NOSPACE;
                field[flen++] = *p++;
            }
        }
        field[flen] = '\0';
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            char **nv = realloc(v, nc * sizeof(*nv));
            if (!nv) {
                size_t i;
                for (i = 0; i < n; i++) free(v[i]);
                free(v);
                return WRDE_NOSPACE;
            }
            v = nv;
            cap = nc;
        }
        f = malloc(flen + 1);
        if (!f) {
            size_t i;
            for (i = 0; i < n; i++) free(v[i]);
            free(v);
            return WRDE_NOSPACE;
        }
        memcpy(f, field, flen + 1);
        v[n] = f;
        n++;
        fields++;
    }
    {
        /* Final vector with offs leading NULLs. */
        size_t i;
        char **fv = malloc((w->we_offs + n + 1) * sizeof(*fv));
        if (!fv) {
            for (i = 0; i < n; i++) free(v[i]);
            free(v);
            return WRDE_NOSPACE;
        }
        for (i = 0; i < w->we_offs; i++) fv[i] = 0;
        for (i = 0; i < n; i++) fv[w->we_offs + i] = v[i];
        fv[w->we_offs + n] = 0;
        free(v);
        w->we_wordv = fv;
    }
    w->we_wordc = n;
    (void)fields;
    return 0;
}

void wordfree(wordexp_t *w) {
    size_t i;
    if (!w || !w->we_wordv) return;
    for (i = 0; i < w->we_offs + w->we_wordc; i++)
        free(w->we_wordv[i]);
    free(w->we_wordv);
    w->we_wordv = 0;
    w->we_wordc = 0;
}
