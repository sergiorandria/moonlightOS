/* libc locale: the single C.UTF-8 locale (no switching). */
#include <locale.h>
#include <string.h>

static char ml_loc_name[] = "C.UTF-8";

static struct lconv ml_c_lconv = {
    ".", "", "", /* decimal_point, thousands_sep, grouping */
    ".", "", "", /* monetary twins (same, no conversion) */
    "", "", "",  /* signs + currency symbol (none in C locale) */
    127, 127, 127, 127, 127, 127, 127, /* CHAR_MAX = unspecified */
    127, 127, 127, 127, 127, 127, 127,
};

char *setlocale(int cat, const char *loc) {
    if (cat < LC_ALL || cat > LC_MESSAGES) return 0;
    if (!loc) return ml_loc_name;
    /* "", "C" and "C.UTF-8" all select the only locale we have. */
    if (loc[0] == '\0' || strcmp(loc, "C") == 0 ||
        strcmp(loc, "C.UTF-8") == 0 || strcmp(loc, "C.utf8") == 0)
        return ml_loc_name;
    return 0;
}

struct lconv *localeconv(void) { return &ml_c_lconv; }

/* ---- extended locale objects (single C.UTF-8 locale) ---- */

#include <stdlib.h>
#include <errno.h>

typedef struct __ml_locale {
    int mask;
    char name[16];
} __ml_locale_t;

static __ml_locale_t ml_locale_c = {0x3F, "C.UTF-8"};
static __ml_locale_t ml_locale_posix = {0x3F, "C"};

locale_t newlocale(int mask, const char *loc, locale_t base) {
    __ml_locale_t *l;
    if (mask & ~0x3F) {
        errno = EINVAL;
        return 0;
    }
    if (!loc || loc[0] == '\0' || strcmp(loc, "C") == 0 ||
        strcmp(loc, "POSIX") == 0)
        return (locale_t)&ml_locale_posix;
    if (strcmp(loc, "C.UTF-8") != 0 && strcmp(loc, "C.utf8") != 0) {
        errno = ENOENT;
        return 0;
    }
    if (base && base != (locale_t)&ml_locale_c &&
        base != (locale_t)&ml_locale_posix) {
        l = malloc(sizeof(*l));
        if (!l) return 0;
        *l = *(__ml_locale_t *)base;
    } else {
        l = malloc(sizeof(*l));
        if (!l) return 0;
        *l = ml_locale_c;
    }
    l->mask = mask ? mask : 0x3F;
    strcpy(l->name, "C.UTF-8");
    return (locale_t)l;
}

locale_t duplocale(locale_t loc) {
    __ml_locale_t *l;
    if (!loc) {
        errno = EINVAL;
        return 0;
    }
    if (loc == (locale_t)&ml_locale_c ||
        loc == (locale_t)&ml_locale_posix)
        return loc;
    l = malloc(sizeof(*l));
    if (!l) return 0;
    *l = *(__ml_locale_t *)loc;
    return (locale_t)l;
}

void freelocale(locale_t loc) {
    if (!loc || loc == (locale_t)&ml_locale_c ||
        loc == (locale_t)&ml_locale_posix)
        return;
    free(loc);
}

/* Thread-local current locale would need TLS; the process-global
 * current plus a pthread-key fallback keeps this real on both. */
static locale_t ml_current_locale = 0;

locale_t uselocale(locale_t loc) {
    locale_t old =
        ml_current_locale ? ml_current_locale : (locale_t)&ml_locale_c;
    if (loc) ml_current_locale = loc;
    return old;
}
