/* libc pwd/grp: the two-row user database (root + nobody). */
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <errno.h>

static char *ml_nobody_mem[] = {0};
static char *ml_root_mem[] = {"root", 0};

static struct passwd ml_users[] = {
    {"root", "x", 0, 0, "root", "/", "/bin/sh"},
    {"nobody", "x", 99, 99, "nobody", "/", "/bin/false"},
};

static struct group ml_groups[] = {
    {"root", "x", 0, ml_root_mem},
    {"nobody", "x", 99, ml_nobody_mem},
};

struct passwd *getpwnam(const char *name) {
    int i;
    if (!name) return 0;
    for (i = 0; i < 2; i++)
        if (strcmp(name, ml_users[i].pw_name) == 0) return &ml_users[i];
    return 0;
}

struct passwd *getpwuid(uid_t uid) {
    int i;
    for (i = 0; i < 2; i++)
        if (ml_users[i].pw_uid == uid) return &ml_users[i];
    return 0;
}

static int ml_copy_passwd(struct passwd *dst, const struct passwd *src,
                          char *buf, unsigned n) {
    size_t need = strlen(src->pw_name) + strlen(src->pw_passwd) +
                  strlen(src->pw_gecos) + strlen(src->pw_dir) +
                  strlen(src->pw_shell) + 5;
    char *p;
    if (need > n) {
        errno = ERANGE;
        return ERANGE;
    }
    p = buf;
    *dst = *src;
    dst->pw_name = p;
    p += strlen(src->pw_name) + 1;
    memcpy(dst->pw_name, src->pw_name, strlen(src->pw_name) + 1);
    dst->pw_passwd = p;
    p += strlen(src->pw_passwd) + 1;
    memcpy(dst->pw_passwd, src->pw_passwd,
           strlen(src->pw_passwd) + 1);
    dst->pw_gecos = p;
    p += strlen(src->pw_gecos) + 1;
    memcpy(dst->pw_gecos, src->pw_gecos, strlen(src->pw_gecos) + 1);
    dst->pw_dir = p;
    p += strlen(src->pw_dir) + 1;
    memcpy(dst->pw_dir, src->pw_dir, strlen(src->pw_dir) + 1);
    dst->pw_shell = p;
    memcpy(dst->pw_shell, src->pw_shell, strlen(src->pw_shell) + 1);
    return 0;
}

int getpwnam_r(const char *name, struct passwd *pw, char *buf,
               unsigned n, struct passwd **res) {
    struct passwd *f = getpwnam(name);
    if (!pw || !buf || !res) {
        errno = EINVAL;
        return EINVAL;
    }
    if (!f) {
        *res = 0;
        return 0;
    }
    if (ml_copy_passwd(pw, f, buf, n) != 0) {
        *res = 0;
        return ERANGE;
    }
    *res = pw;
    return 0;
}

int getpwuid_r(uid_t uid, struct passwd *pw, char *buf, unsigned n,
               struct passwd **res) {
    struct passwd *f = getpwuid(uid);
    if (!pw || !buf || !res) {
        errno = EINVAL;
        return EINVAL;
    }
    if (!f) {
        *res = 0;
        return 0;
    }
    if (ml_copy_passwd(pw, f, buf, n) != 0) {
        *res = 0;
        return ERANGE;
    }
    *res = pw;
    return 0;
}

struct group *getgrnam(const char *name) {
    int i;
    if (!name) return 0;
    for (i = 0; i < 2; i++)
        if (strcmp(name, ml_groups[i].gr_name) == 0)
            return &ml_groups[i];
    return 0;
}

struct group *getgrgid(gid_t gid) {
    int i;
    for (i = 0; i < 2; i++)
        if (ml_groups[i].gr_gid == gid) return &ml_groups[i];
    return 0;
}

int getgrnam_r(const char *name, struct group *g, char *buf, unsigned n,
               struct group **res) {
    struct group *f = getgrnam(name);
    size_t need;
    if (!g || !buf || !res) {
        errno = EINVAL;
        return EINVAL;
    }
    if (!f) {
        *res = 0;
        return 0;
    }
    need = strlen(f->gr_name) + 1;
    if (need > n) {
        *res = 0;
        errno = ERANGE;
        return ERANGE;
    }
    *g = *f;
    memcpy(buf, f->gr_name, need);
    g->gr_name = buf;
    *res = g;
    return 0;
}

int getgrgid_r(gid_t gid, struct group *g, char *buf, unsigned n,
               struct group **res) {
    struct group *f = getgrgid(gid);
    size_t need;
    if (!g || !buf || !res) {
        errno = EINVAL;
        return EINVAL;
    }
    if (!f) {
        *res = 0;
        return 0;
    }
    need = strlen(f->gr_name) + 1;
    if (need > n) {
        *res = 0;
        errno = ERANGE;
        return ERANGE;
    }
    *g = *f;
    memcpy(buf, f->gr_name, need);
    g->gr_name = buf;
    *res = g;
    return 0;
}

/* ---- enumeration over /etc/passwd + /etc/group (static fallback) ---- */

#include <stdio.h>
#include <stdlib.h>

static FILE *ml_pw_fp = 0;
static int ml_pw_idx = 0;
static FILE *ml_gr_fp = 0;
static int ml_gr_idx = 0;
static struct passwd ml_pw_cur;
static char ml_pw_buf[256];
static struct group ml_gr_cur;
static char ml_gr_buf[256];
static char *ml_gr_mems[17];

static int ml_parse_passwd(const char *line, struct passwd *pw, char *buf,
                           size_t n) {
    char *f[7];
    int i = 0;
    size_t need = strlen(line) + 1;
    char *p;
    if (need > n) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, line, need);
    f[0] = buf;
    for (i = 1; i < 7; i++) f[i] = 0;
    i = 0;
    for (p = buf; *p && i < 7; p++) {
        if (*p == ':') {
            *p = '\0';
            if (++i < 7) f[i] = (char *)p + 1;
        }
    }
    if (!f[0][0] || !f[2] || !f[3]) return -1;
    pw->pw_name = f[0];
    pw->pw_passwd = f[1] ? f[1] : (char *)"";
    pw->pw_uid = (uid_t)strtoul(f[2], 0, 10);
    pw->pw_gid = (gid_t)strtoul(f[3], 0, 10);
    pw->pw_gecos = f[4] ? f[4] : (char *)"";
    pw->pw_dir = f[5] && f[5][0] ? f[5] : (char *)"/";
    pw->pw_shell = f[6] && f[6][0] ? f[6] : (char *)"";
    return 0;
}

static int ml_parse_group(const char *line, struct group *g, char *buf,
                          size_t n) {
    char *f[4];
    int i = 0, nm = 0;
    size_t need = strlen(line) + 1;
    char *p;
    char *mem;
    if (need > n) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, line, need);
    f[0] = buf;
    for (i = 1; i < 4; i++) f[i] = 0;
    i = 0;
    for (p = buf; *p && i < 4; p++) {
        if (*p == ':') {
            *p = '\0';
            if (++i < 4) f[i] = (char *)p + 1;
        }
    }
    if (!f[0][0] || !f[2]) return -1;
    g->gr_name = f[0];
    g->gr_passwd = f[1] ? f[1] : (char *)"";
    g->gr_gid = (gid_t)strtoul(f[2], 0, 10);
    g->gr_mem = ml_gr_mems;
    if (f[3] && f[3][0]) {
        mem = f[3];
        while (*mem && nm < 16) {
            char *comma = strchr(mem, ',');
            if (comma) *comma = '\0';
            ml_gr_mems[nm++] = mem;
            if (!comma) break;
            mem = comma + 1;
        }
    }
    ml_gr_mems[nm] = 0;
    return 0;
}

void setpwent(void) {
    if (ml_pw_fp) fclose(ml_pw_fp);
    ml_pw_fp = fopen("/etc/passwd", "r");
    ml_pw_idx = 0;
}

void endpwent(void) {
    if (ml_pw_fp) fclose(ml_pw_fp);
    ml_pw_fp = 0;
    ml_pw_idx = 0;
}

struct passwd *getpwent(void) {
    if (ml_pw_fp) {
        char line[256];
        while (fgets(line, sizeof(line), ml_pw_fp)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            line[strcspn(line, "\n")] = '\0';
            if (ml_parse_passwd(line, &ml_pw_cur, ml_pw_buf,
                                sizeof(ml_pw_buf)) == 0)
                return &ml_pw_cur;
        }
        return 0;
    }
    if (ml_pw_idx < 2) return &ml_users[ml_pw_idx++];
    return 0;
}

void setgrent(void) {
    if (ml_gr_fp) fclose(ml_gr_fp);
    ml_gr_fp = fopen("/etc/group", "r");
    ml_gr_idx = 0;
}

void endgrent(void) {
    if (ml_gr_fp) fclose(ml_gr_fp);
    ml_gr_fp = 0;
    ml_gr_idx = 0;
}

struct group *getgrent(void) {
    if (ml_gr_fp) {
        char line[256];
        while (fgets(line, sizeof(line), ml_gr_fp)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            line[strcspn(line, "\n")] = '\0';
            if (ml_parse_group(line, &ml_gr_cur, ml_gr_buf,
                               sizeof(ml_gr_buf)) == 0)
                return &ml_gr_cur;
        }
        return 0;
    }
    if (ml_gr_idx < 2) return &ml_groups[ml_gr_idx++];
    return 0;
}

int getgrouplist(const char *user, gid_t group, gid_t *groups,
                 int *ngroups) {
    struct group *g;
    int n = 0, need = 1, i, total = 0;
    if (!user || !groups || !ngroups) {
        errno = EINVAL;
        return -1;
    }
    /* Count first (primary + memberships). */
    setgrent();
    while ((g = getgrent()) != 0) {
        int member = (g->gr_gid == group);
        if (!member) {
            char **m;
            for (m = g->gr_mem; m && *m; m++) {
                if (strcmp(*m, user) == 0) {
                    member = 1;
                    break;
                }
            }
        }
        if (member) total++;
    }
    endgrent();
    if (*ngroups < total) {
        /* Still report the count the caller needs. */
        *ngroups = total;
        errno = ERANGE;
        return -1;
    }
    (void)need;
    setgrent();
    while ((g = getgrent()) != 0) {
        int member = (g->gr_gid == group), dup = 0;
        if (!member) {
            char **m;
            for (m = g->gr_mem; m && *m; m++) {
                if (strcmp(*m, user) == 0) {
                    member = 1;
                    break;
                }
            }
        }
        if (!member) continue;
        for (i = 0; i < n; i++)
            if (groups[i] == g->gr_gid) {
                dup = 1;
                break;
            }
        if (!dup) groups[n++] = g->gr_gid;
    }
    endgrent();
    /* Primary group first (conventional order). */
    for (i = 0; i < n; i++) {
        if (groups[i] == group) {
            gid_t t = groups[0];
            groups[0] = groups[i];
            groups[i] = t;
            break;
        }
    }
    if (n == 0) {
        groups[0] = group;
        n = 1;
    }
    *ngroups = n;
    return n;
}
