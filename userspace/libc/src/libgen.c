/* libc libgen: POSIX basename/dirname over the path string.
 * Both may modify the input (a trailing-slash-tolerant copy is used
 * internally, so callers' buffers are never written); results live in
 * per-call static buffers (POSIX permits static storage). */
#include <libgen.h>
#include <string.h>
#include <stddef.h>

static char ml_libgen_buf[2][256];
static int ml_libgen_which = 0;

static char *ml_slot(void) {
    ml_libgen_which ^= 1;
    return ml_libgen_buf[ml_libgen_which];
}

/* Strip trailing slashes (keeping a lone "/"), copy into dst. */
static size_t ml_norm(const char *path, char *dst, size_t cap) {
    size_t n = strlen(path);
    while (n > 1 && path[n - 1] == '/') n--;
    if (n >= cap) n = cap - 1;
    memcpy(dst, path, n);
    dst[n] = '\0';
    return n;
}

char *basename(char *path) {
    char tmp[256], *out, *slash;
    size_t n;
    if (!path || !*path) return (char *)".";
    n = ml_norm(path, tmp, sizeof(tmp));
    slash = strrchr(tmp, '/');
    if (!slash) {
        out = ml_slot();
        memcpy(out, tmp, n + 1);
        return out;
    }
    if (slash == tmp) return (char *)"/";
    out = ml_slot();
    {
        size_t m = strlen(slash + 1) + 1;
        memcpy(out, slash + 1, m);
    }
    return out;
}

char *dirname(char *path) {
    char tmp[256], *out, *slash;
    if (!path || !*path) return (char *)".";
    ml_norm(path, tmp, sizeof(tmp));
    slash = strrchr(tmp, '/');
    if (!slash) return (char *)".";
    if (slash == tmp) return (char *)"/";
    /* Trim trailing slashes of the directory part ("a/b//" -> "a"). */
    while (slash > tmp && slash[-1] == '/') slash--;
    *slash = '\0';
    out = ml_slot();
    {
        size_t m = strlen(tmp) + 1;
        if (m > sizeof(ml_libgen_buf[0])) m = sizeof(ml_libgen_buf[0]);
        memcpy(out, tmp, m);
        out[sizeof(ml_libgen_buf[0]) - 1] = '\0';
    }
    return out;
}
