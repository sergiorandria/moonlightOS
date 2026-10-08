/* libc utmpx: file-backed user accounting. Records are
 * fixed-size; the file is a flat array indexed by slot. pututxline
 * matches LOGIN/USER entries by (line,id) like glibc. */
#include <utmpx.h>
#include <paths.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static char ml_utmp_file[256] = _PATH_UTMP;
static int ml_utmp_fd = -1;
static long ml_utmp_slot = 0;
static struct utmpx ml_utmp_cur;

int utmpxname(const char *file) {
    size_t n;
    if (!file) {
        errno = EINVAL;
        return -1;
    }
    n = strlen(file) + 1;
    if (n > sizeof(ml_utmp_file)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (ml_utmp_fd >= 0) close(ml_utmp_fd);
    ml_utmp_fd = -1;
    ml_utmp_slot = 0;
    memcpy(ml_utmp_file, file, n);
    return 0;
}

void setutxent(void) {
    if (ml_utmp_fd >= 0) {
        lseek(ml_utmp_fd, 0, SEEK_SET);
    }
    ml_utmp_slot = 0;
}

void endutxent(void) {
    if (ml_utmp_fd >= 0) {
        close(ml_utmp_fd);
        ml_utmp_fd = -1;
    }
    ml_utmp_slot = 0;
}

static int ml_utmp_open(int writable) {
    if (ml_utmp_fd >= 0) return 0;
    ml_utmp_fd = open(ml_utmp_file, writable ? O_RDWR | O_CREAT : O_RDONLY,
                      0644);
    if (ml_utmp_fd < 0) {
        if (!writable && errno == ENOENT) return -1;
        if (writable) return -1;
        return -1;
    }
    return 0;
}

struct utmpx *getutxent(void) {
    ssize_t r;
    if (ml_utmp_open(0) != 0) return 0;
    if (lseek(ml_utmp_fd, ml_utmp_slot * (off_t)sizeof(ml_utmp_cur),
              SEEK_SET) < 0)
        return 0;
    r = read(ml_utmp_fd, &ml_utmp_cur, sizeof(ml_utmp_cur));
    if (r != (ssize_t)sizeof(ml_utmp_cur)) return 0;
    ml_utmp_slot++;
    return &ml_utmp_cur;
}

static int ml_id_match(const struct utmpx *a, const struct utmpx *b) {
    if ((a->ut_type == RUN_LVL || a->ut_type == BOOT_TIME ||
         a->ut_type == NEW_TIME || a->ut_type == OLD_TIME) &&
        a->ut_type == b->ut_type)
        return 1;
    if ((a->ut_type == INIT_PROCESS || a->ut_type == LOGIN_PROCESS ||
         a->ut_type == USER_PROCESS || a->ut_type == DEAD_PROCESS) &&
        a->ut_type == b->ut_type &&
        memcmp(a->ut_id, b->ut_id, sizeof(a->ut_id)) == 0)
        return 1;
    return 0;
}

struct utmpx *getutxid(const struct utmpx *id) {
    struct utmpx *u;
    if (!id) {
        errno = EINVAL;
        return 0;
    }
    setutxent();
    while ((u = getutxent()) != 0) {
        if (ml_id_match(u, id)) return u;
    }
    return 0;
}

struct utmpx *getutxline(const struct utmpx *line) {
    struct utmpx *u;
    if (!line) {
        errno = EINVAL;
        return 0;
    }
    setutxent();
    while ((u = getutxent()) != 0) {
        if ((u->ut_type == USER_PROCESS || u->ut_type == LOGIN_PROCESS) &&
            strncmp(u->ut_line, line->ut_line, UT_LINESIZE) == 0)
            return u;
    }
    return 0;
}

struct utmpx *pututxline(const struct utmpx *ut) {
    struct utmpx *slot;
    off_t off;
    if (!ut) {
        errno = EINVAL;
        return 0;
    }
    if (ml_utmp_open(1) != 0) return 0;
    /* Find the matching slot, else append. */
    setutxent();
    slot = 0;
    {
        struct utmpx *u;
        while ((u = getutxent()) != 0) {
            if (ml_id_match(u, ut)) {
                slot = u;
                break;
            }
        }
    }
    if (slot) off = (ml_utmp_slot - 1) * (off_t)sizeof(*ut);
    else off = lseek(ml_utmp_fd, 0, SEEK_END);
    if (off < 0) return 0;
    if (write(ml_utmp_fd, ut, sizeof(*ut)) != (ssize_t)sizeof(*ut))
        return 0;
    memcpy(&ml_utmp_cur, ut, sizeof(*ut));
    return &ml_utmp_cur;
}
