/* libc string. When built into the kernel image (__MOONLIGHT_KERNEL__),
 * memcpy/memset/memmove/memcmp/strlen/strcmp/strncmp/strncpy come from
 * minilib.c (same semantics); everything else is defined here
 * unconditionally. */
#include <string.h>
#include <stdlib.h>

#ifndef __MOONLIGHT_KERNEL__

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *aa = a, *bb = b;
    while (n--) {
        if (*aa != *bb) return *aa - *bb;
        aa++;
        bb++;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

char *strncpy(char *d, const char *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i]) {
        d[i] = s[i];
        i++;
    }
    while (i < n) d[i++] = '\0';
    return d;
}

void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd == ss || n == 0) return d;
    if (dd < ss) {
        while (n--) *dd++ = *ss++;
    } else {
        dd += n;
        ss += n;
        while (n--) *--dd = *--ss;
    }
    return d;
}

#endif /* __MOONLIGHT_KERNEL__ */

void *memchr(const void *s, int c, size_t n) {
    const unsigned char *p = s;
    while (n--) {
        if (*p == (unsigned char)c) return (void *)p;
        p++;
    }
    return 0;
}

size_t strnlen(const char *s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}

char *strcpy(char *d, const char *s) {
    char *r = d;
    while ((*d++ = *s++)) {}
    return r;
}

char *strcat(char *d, const char *s) {
    char *r = d;
    while (*d) d++;
    while ((*d++ = *s++)) {}
    return r;
}

char *strncat(char *d, const char *s, size_t n) {
    char *r = d;
    while (*d) d++;
    while (n-- && *s) *d++ = *s++;
    *d = '\0';
    return r;
}

char *strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return c == 0 ? (char *)s : 0;
}

char *strrchr(const char *s, int c) {
    const char *last = 0;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    if (c == 0) return (char *)s;
    return (char *)last;
}

char *strstr(const char *h, const char *n) {
    size_t nl = strlen(n);
    if (nl == 0) return (char *)h;
    while (*h) {
        if (*h == *n && strncmp(h, n, nl) == 0) return (char *)h;
        h++;
    }
    return 0;
}

char *strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

size_t strspn(const char *s, const char *acc) {
    size_t n = 0;
    while (s[n] && strchr(acc, s[n])) n++;
    return n;
}

size_t strcspn(const char *s, const char *rej) {
    size_t n = 0;
    while (s[n] && !strchr(rej, s[n])) n++;
    return n;
}

char *strpbrk(const char *s, const char *acc) {
    while (*s) {
        if (strchr(acc, *s)) return (char *)s;
        s++;
    }
    return 0;
}

char *strtok_r(char *s, const char *delim, char **save) {
    char *p;
    if (s) *save = s;
    if (!*save) return 0;
    /* skip leading delimiters */
    p = *save + strspn(*save, delim);
    if (*p == '\0') {
        *save = 0;
        return 0;
    }
    s = p;
    p += strcspn(p, delim);
    if (*p == '\0') {
        *save = 0;
    } else {
        *p = '\0';
        *save = p + 1;
    }
    return s;
}

char *strtok(char *s, const char *delim) {
    /* Single-threaded libc: one global scan state (documented). */
    static char *ml_tok_save = 0;
    return strtok_r(s, delim, &ml_tok_save);
}

char *strchrnul(const char *s, int c) {
    while (*s && *s != (char)c) s++;
    return (char *)s;
}

void *memmem(const void *h, size_t hn, const void *n, size_t nl) {
    const unsigned char *hh = h, *nn = n;
    size_t i;
    if (nl == 0) return (void *)hh;
    if (hn < nl) return 0;
    for (i = 0; i + nl <= hn; i++)
        if (hh[i] == nn[0] && memcmp(hh + i, nn, nl) == 0)
            return (void *)(hh + i);
    return 0;
}

size_t strlcpy(char *d, const char *s, size_t n) {
    size_t sl = strlen(s);
    if (n > 0) {
        size_t c = sl < n - 1 ? sl : n - 1;
        memcpy(d, s, c);
        d[c] = '\0';
    }
    return sl;
}

size_t strlcat(char *d, const char *s, size_t n) {
    size_t dl = strnlen(d, n), sl = strlen(s);
    if (dl == n) return n + sl;
    strlcpy(d + dl, s, n - dl);
    return dl + sl;
}

void explicit_bzero(void *s, size_t n) {
    /* Volatile so the wipe is never optimized away (key material). */
    volatile unsigned char *p = s;
    while (n--) *p++ = 0;
}

int strcoll(const char *a, const char *b) { return strcmp(a, b); }

size_t strxfrm(char *d, const char *s, size_t n) {
    size_t sl = strlen(s);
    if (n > 0) strlcpy(d, s, n);
    return sl;
}

char *strndup(const char *s, size_t n) {
    size_t l = strnlen(s, n);
    char *p = malloc(l + 1);
    if (p) {
        memcpy(p, s, l);
        p[l] = '\0';
    }
    return p;
}

/* ---- POSIX/BSD extras (pure, real) ---- */

char *strsep(char **sp, const char *delim) {
    char *s, *p;
    if (!sp || !*sp) return 0;
    s = *sp;
    p = s + strcspn(s, delim ? delim : "");
    if (*p) {
        *p = '\0';
        *sp = p + 1;
    } else {
        *sp = 0;
    }
    return s;
}

void *memccpy(void *d, const void *s, int c, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    while (n--) {
        *dd = *ss;
        if (*ss == (unsigned char)c) return dd + 1;
        dd++;
        ss++;
    }
    return 0;
}

char *stpcpy(char *d, const char *s) {
    while ((*d = *s)) {
        d++;
        s++;
    }
    return d;
}

char *stpncpy(char *d, const char *s, size_t n) {
    size_t sl = strnlen(s, n), i;
    for (i = 0; i < sl; i++) d[i] = s[i];
    for (; i < n; i++) d[i] = '\0';
    /* NUL fit (sl < n) -> point at it; else d + n. */
    return d + sl;
}

char *strsignal(int sig) {
    /* Matches signal.h numbers; unknown -> "Unknown signal". */
    static const char *const ml_signames[] = {
        "Unknown signal", "Hangup", "Interrupt", "Quit",
        "Illegal instruction", "Trace/breakpoint trap", "Aborted",
        "Bus error", "Floating point exception", "Killed", "User defined 1",
        "Segmentation fault", "User defined 2", "Broken pipe",
        "Alarm clock", "Terminated", "Unknown signal", "Child exited",
        "Continued", "Stopped (signal)", "Stopped", "Stopped (tty input)",
        "Stopped (tty output)", "Urgent I/O", "CPU limit", "File size limit",
        "Virtual timer", "Profiling timer", "Window changed", "I/O possible",
        "Power failure", "Bad system call"};
    static char ml_sigbuf[32];
    if (sig < 0 ||
        sig >= (int)(sizeof(ml_signames) / sizeof(ml_signames[0]))) {
        size_t i = 0;
        const char *p = "Unknown signal ";
        unsigned u = (unsigned)(sig < 0 ? -sig : sig);
        char nb[12];
        int ni = 0;
        while (*p) ml_sigbuf[i++] = *p++;
        if (sig < 0) ml_sigbuf[i++] = '-';
        do {
            nb[ni++] = (char)('0' + u % 10);
            u /= 10;
        } while (u > 0);
        while (ni > 0) ml_sigbuf[i++] = nb[--ni];
        ml_sigbuf[i] = '\0';
        return ml_sigbuf;
    }
    return (char *)ml_signames[sig];
}

/* ---- GNU/BSD extras ---- */

void *memrchr(const void *s, int c, size_t n) {
    const unsigned char *p = s;
    while (n > 0) {
        n--;
        if (p[n] == (unsigned char)c) return (void *)(p + n);
    }
    return 0;
}

static int ml_todigit(int c) {
    return c >= '0' && c <= '9' ? c - '0' : -1;
}

/* strverscmp: numeric runs compare by magnitude (leading zeros make
 * the longer run larger only past the zero prefix, glibc rules). */
int strverscmp(const char *a, const char *b) {
    while (*a && *b) {
        int da = ml_todigit(*a) >= 0, db = ml_todigit(*b) >= 0;
        if (da && db) {
            /* Skip leading zeros on both sides. */
            while (*a == '0') a++;
            while (*b == '0') b++;
            {
                const char *pa = a, *pb = b;
                size_t na = 0, nb = 0;
                while (ml_todigit(*pa) >= 0) {
                    pa++;
                    na++;
                }
                while (ml_todigit(*pb) >= 0) {
                    pb++;
                    nb++;
                }
                if (na != nb) return na < nb ? -1 : 1;
                while (na > 0) {
                    if (*a != *b)
                        return (unsigned char)*a < (unsigned char)*b
                                   ? -1
                                   : 1;
                    a++;
                    b++;
                    na--;
                }
            }
        } else {
            if (*a != *b)
                return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
            a++;
            b++;
        }
    }
    if (*a) return 1;
    if (*b) return -1;
    return 0;
}

char *strcasestr(const char *h, const char *n) {
    size_t nl;
    if (!h || !n) return 0;
    nl = strlen(n);
    if (nl == 0) return (char *)h;
    while (*h) {
        size_t i;
        for (i = 0; i < nl; i++) {
            int hc = (unsigned char)h[i], nc = (unsigned char)n[i];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
        }
        if (i == nl) return (char *)h;
        h++;
    }
    return 0;
}
