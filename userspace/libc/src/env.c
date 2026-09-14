/* libc environ: in-memory table (the kernel passes no environment;
 * a child therefore starts empty - documented in docs/LINUX.md).
 * setenv/unsetenv own their storage (strdup'd "NAME=value"); putenv
 * takes ownership of the caller's string itself (POSIX semantics). */
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ML_ENV_MAX 64

static char *ml_env_tab[ML_ENV_MAX + 1];
static unsigned char ml_env_owned[ML_ENV_MAX];
static int ml_env_n = 0;

char **environ = ml_env_tab;

char *getenv(const char *name) {
    size_t nl;
    int i;
    if (!name || *name == '\0' || strchr(name, '=')) return 0;
    nl = strlen(name);
    for (i = 0; i < ml_env_n; i++)
        if (strncmp(ml_env_tab[i], name, nl) == 0 &&
            ml_env_tab[i][nl] == '=')
            return ml_env_tab[i] + nl + 1;
    return 0;
}

static int ml_env_drop(int idx) {
    if (ml_env_owned[idx]) free(ml_env_tab[idx]);
    ml_env_tab[idx] = ml_env_tab[ml_env_n - 1];
    ml_env_owned[idx] = ml_env_owned[ml_env_n - 1];
    ml_env_n--;
    ml_env_tab[ml_env_n] = 0;
    return 0;
}

int unsetenv(const char *name) {
    size_t nl;
    int i;
    if (!name || *name == '\0' || strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }
    nl = strlen(name);
    for (i = 0; i < ml_env_n; i++)
        if (strncmp(ml_env_tab[i], name, nl) == 0 &&
            ml_env_tab[i][nl] == '=')
            ml_env_drop(i--);
    return 0;
}

int setenv(const char *name, const char *val, int overwrite) {
    size_t nl, vl;
    char *e;
    int i;
    if (!name || *name == '\0' || strchr(name, '=') || !val) {
        errno = EINVAL;
        return -1;
    }
    nl = strlen(name);
    for (i = 0; i < ml_env_n; i++)
        if (strncmp(ml_env_tab[i], name, nl) == 0 &&
            ml_env_tab[i][nl] == '=') {
            if (!overwrite) return 0;
            ml_env_drop(i);
            break;
        }
    if (ml_env_n >= ML_ENV_MAX) {
        errno = ENOMEM;
        return -1;
    }
    vl = strlen(val);
    e = malloc(nl + 1 + vl + 1);
    if (!e) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(e, name, nl);
    e[nl] = '=';
    memcpy(e + nl + 1, val, vl + 1);
    ml_env_tab[ml_env_n] = e;
    ml_env_owned[ml_env_n] = 1;
    ml_env_n++;
    ml_env_tab[ml_env_n] = 0;
    return 0;
}

int putenv(char *s) {
    char *eq;
    int i;
    if (!s || (eq = strchr(s, '=')) == 0 || eq == s) {
        errno = EINVAL;
        return -1;
    }
    /* Drop any older binding of the same name first. */
    for (i = 0; i < ml_env_n; i++)
        if (strncmp(ml_env_tab[i], s, (size_t)(eq - s)) == 0 &&
            ml_env_tab[i][eq - s] == '=') {
            ml_env_drop(i);
            break;
        }
    if (ml_env_n >= ML_ENV_MAX) {
        errno = ENOMEM;
        return -1;
    }
    /* Stored as given: later writes through this pointer stay visible. */
    ml_env_tab[ml_env_n] = s;
    ml_env_owned[ml_env_n] = 0;
    ml_env_n++;
    ml_env_tab[ml_env_n] = 0;
    return 0;
}

int clearenv(void) {
    while (ml_env_n > 0) ml_env_drop(ml_env_n - 1);
    return 0;
}
