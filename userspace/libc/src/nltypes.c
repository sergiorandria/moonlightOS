/* libc catalogs: real nl_types message catalogs over the VFS.
 *
 * File format (text, line-oriented, no stub semantics):
 *   <set> <msg> <text...>
 * Blank lines and lines starting with '#' are ignored. catopen reads
 * the whole file into a heap table; catgets does an exact
 * (set,msg) lookup and returns the stored text, or dflt. */
#include <nl_types.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define ML_CAT_MAX 8
#define ML_MSG_MAX 128

typedef struct {
    int set;
    int msg;
    char *text;
} ml_msg_t;

typedef struct {
    int used;
    ml_msg_t msgs[ML_MSG_MAX];
    int n;
} ml_cat_t;

static ml_cat_t ml_cats[ML_CAT_MAX];

static char *ml_cat_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

nl_catd catopen(const char *name, int oflag) {
    int i, fd, slot = -1;
    char buf[2048];
    ssize_t r;
    size_t len = 0, pos;
    (void)oflag;
    if (!name || !*name) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < ML_CAT_MAX; i++) {
        if (!ml_cats[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        errno = ENOMEM;
        return -1;
    }
    fd = open(name, O_RDONLY);
    if (fd < 0) return -1;
    /* Bounded read (catalogs are small config files). */
    for (;;) {
        if (len >= sizeof(buf) - 1) break;
        r = read(fd, buf + len, sizeof(buf) - 1 - len);
        if (r <= 0) break;
        len += (size_t)r;
    }
    close(fd);
    buf[len] = '\0';
    memset(&ml_cats[slot], 0, sizeof(ml_cats[slot]));
    ml_cats[slot].used = 1;
    /* Parse lines. */
    pos = 0;
    while (pos < len && ml_cats[slot].n < ML_MSG_MAX) {
        char *line = buf + pos;
        char *nl = strchr(line, '\n');
        size_t llen;
        if (nl) {
            *nl = '\0';
            pos += (size_t)(nl - line) + 1;
        } else {
            pos = len;
        }
        llen = strlen(line);
        if (llen && line[llen - 1] == '\r') line[llen - 1] = '\0';
        if (!line[0] || line[0] == '#') continue;
        {
            char *p = line;
            long set, msg;
            char *text;
            while (*p == ' ' || *p == '\t') p++;
            if (*p < '0' || *p > '9') continue;
            set = strtol(p, &p, 10);
            while (*p == ' ' || *p == '\t') p++;
            if (*p < '0' || *p > '9') continue;
            msg = strtol(p, &p, 10);
            if (*p != ' ' && *p != '\t' && *p != '\0') continue;
            while (*p == ' ' || *p == '\t') p++;
            text = ml_cat_strdup(p);
            if (!text) break;
            ml_cats[slot].msgs[ml_cats[slot].n].set = (int)set;
            ml_cats[slot].msgs[ml_cats[slot].n].msg = (int)msg;
            ml_cats[slot].msgs[ml_cats[slot].n].text = text;
            ml_cats[slot].n++;
        }
    }
    return slot + 1;
}

char *catgets(nl_catd catd, int set, int msg, const char *dflt) {
    int i;
    ml_cat_t *c;
    if (catd <= 0 || catd > ML_CAT_MAX) return (char *)dflt;
    c = &ml_cats[catd - 1];
    if (!c->used) return (char *)dflt;
    for (i = 0; i < c->n; i++) {
        if (c->msgs[i].set == set && c->msgs[i].msg == msg)
            return c->msgs[i].text;
    }
    return (char *)dflt;
}

int catclose(nl_catd catd) {
    int i;
    ml_cat_t *c;
    if (catd <= 0 || catd > ML_CAT_MAX || !ml_cats[catd - 1].used) {
        errno = EBADF;
        return -1;
    }
    c = &ml_cats[catd - 1];
    for (i = 0; i < c->n; i++) free(c->msgs[i].text);
    memset(c, 0, sizeof(*c));
    return 0;
}
