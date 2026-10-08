/* libc shadow: shadow-password database. Tries /etc/shadow
 * first (real parser), falls back to the static root/nobody rows
 * (same policy as pwdgrp.c). */
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static struct spwd ml_sh_fallback[] = {
    {"root", "x", 0, 0, 99999, 7, 0, 0, 0},
    {"nobody", "x", 0, 0, 99999, 7, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0},
};

/* Parse one "name:pass:lstchg:min:max:warn:inactive:expire:flag" line.
 * Numeric fields default to -1 (unset) except lstchg (0). */
static int ml_parse_sp(const char *line, struct spwd *sp, char *buf,
                       size_t n) {
    char *fields[9];
    int i = 0;
    size_t need;
    char *p = buf;
    if (!line || !sp || !buf || n == 0) return -1;
    need = strlen(line) + 1;
    if (need > n) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, line, need);
    /* Split into up to 9 fields. */
    fields[0] = buf;
    for (i = 1; i < 9; i++) fields[i] = 0;
    i = 0;
    for (p = buf; *p && i < 9; p++) {
        if (*p == ':') {
            *p = '\0';
            if (++i < 9) fields[i] = (char *)p + 1;
        }
    }
    if (!fields[0][0]) return -1;
    sp->sp_namp = fields[0];
    sp->sp_pwdp = fields[1] ? fields[1] : (char *)"";
    sp->sp_lstchg = fields[2] && fields[2][0] ? atol(fields[2]) : 0;
    sp->sp_min = fields[3] && fields[3][0] ? atol(fields[3]) : -1;
    sp->sp_max = fields[4] && fields[4][0] ? atol(fields[4]) : -1;
    sp->sp_warn = fields[5] && fields[5][0] ? atol(fields[5]) : -1;
    sp->sp_inact = fields[6] && fields[6][0] ? atol(fields[6]) : -1;
    sp->sp_expire = fields[7] && fields[7][0] ? atol(fields[7]) : -1;
    sp->sp_flag = fields[8] && fields[8][0] ? (unsigned long)atol(fields[8])
                                            : (unsigned long)-1;
    return 0;
}

int sgetspent(const char *s, struct spwd *sp, char *buf, size_t n) {
    return ml_parse_sp(s, sp, buf, n);
}

int fgetspent(FILE *fp, struct spwd *sp, char *buf, size_t n) {
    char line[512];
    if (!fp) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        if (!fgets(line, sizeof(line), fp)) return -1;
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\n")] = '\0';
        if (ml_parse_sp(line, sp, buf, n) == 0) return 0;
        /* Malformed line: skip, keep scanning. */
    }
}

static FILE *ml_sh_fp = 0;
static int ml_sh_eof = 0;
static int ml_sh_idx = 0;

void setspent(void) {
    if (ml_sh_fp) fclose(ml_sh_fp);
    ml_sh_fp = fopen("/etc/shadow", "r");
    ml_sh_eof = 0;
    ml_sh_idx = 0;
}

void endspent(void) {
    if (ml_sh_fp) fclose(ml_sh_fp);
    ml_sh_fp = 0;
    ml_sh_eof = 0;
    ml_sh_idx = 0;
}

static struct spwd ml_sh_cur;
static char ml_sh_buf[512];

struct spwd *getspent(void) {
    /* No auto-open (mirrors pwdgrp.c): setspent() owns the rewind.
     * Without it, a NULL file yields the fallback rows once. */
    if (ml_sh_fp) {
        if (fgetspent(ml_sh_fp, &ml_sh_cur, ml_sh_buf,
                      sizeof(ml_sh_buf)) == 0)
            return &ml_sh_cur;
        ml_sh_eof = 1;
        return 0;
    }
    /* Fallback rows, walked once per setspent (index reset there). */
    if (ml_sh_fallback[ml_sh_idx].sp_namp)
        return &ml_sh_fallback[ml_sh_idx++];
    ml_sh_eof = 1;
    return 0;
}

struct spwd *getspnam(const char *name) {
    struct spwd *sp;
    int i;
    if (!name) {
        errno = EINVAL;
        return 0;
    }
    setspent();
    while ((sp = getspent()) != 0) {
        if (strcmp(sp->sp_namp, name) == 0) {
            endspent();
            return sp;
        }
    }
    endspent();
    /* Static fallback (covers missing /etc/shadow). */
    for (i = 0; ml_sh_fallback[i].sp_namp; i++)
        if (strcmp(ml_sh_fallback[i].sp_namp, name) == 0)
            return &ml_sh_fallback[i];
    errno = ENOENT;
    return 0;
}

int getspnam_r(const char *name, struct spwd *sp, char *buf, size_t n,
               struct spwd **result) {
    FILE *fp;
    char line[512];
    *result = 0;
    if (!name || !sp || !buf || n == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    fp = fopen("/etc/shadow", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *nl;
            if (line[0] == '#') continue;
            nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            if (ml_parse_sp(line, sp, buf, n) != 0) continue;
            if (strcmp(sp->sp_namp, name) == 0) {
                fclose(fp);
                *result = sp;
                return 0;
            }
        }
        fclose(fp);
    }
    {
        int i;
        for (i = 0; ml_sh_fallback[i].sp_namp; i++) {
            if (strcmp(ml_sh_fallback[i].sp_namp, name) == 0) {
                char tmp[256];
                snprintf(tmp, sizeof(tmp), "%s:%s:0:-1:-1:-1:-1:-1:-1",
                         ml_sh_fallback[i].sp_namp,
                         ml_sh_fallback[i].sp_pwdp);
                if (ml_parse_sp(tmp, sp, buf, n) != 0) return ERANGE;
                *result = sp;
                return 0;
            }
        }
    }
    return ENOENT;
}

int getspent_r(struct spwd *sp, char *buf, size_t n, struct spwd **result) {
    struct spwd *cur;
    *result = 0;
    if (!sp || !buf || n == 0) {
        errno = EINVAL;
        return EINVAL;
    }
    cur = getspent();
    if (!cur) return ENOENT;
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s:%s:%ld:%ld:%ld:%ld:%ld:%ld:%lu",
                 cur->sp_namp, cur->sp_pwdp, cur->sp_lstchg, cur->sp_min,
                 cur->sp_max, cur->sp_warn, cur->sp_inact, cur->sp_expire,
                 cur->sp_flag);
        if (ml_parse_sp(tmp, sp, buf, n) != 0) return ERANGE;
    }
    *result = sp;
    return 0;
}
