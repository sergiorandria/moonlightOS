/* libc strings (POSIX): case-insensitive compare, find-first-set. */
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>

int strcasecmp(const char *a, const char *b) {
    while (*a && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int strncasecmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a &&
           tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
        a++;
        b++;
        n--;
    }
    if (n == 0) return 0;
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int ffs(int x) {
    int i = 1;
    unsigned u = (unsigned)x;
    if (u == 0) return 0;
    while ((u & 1u) == 0) {
        u >>= 1;
        i++;
    }
    return i;
}

int ffsl(long x) {
    int i = 1;
    unsigned long u = (unsigned long)x;
    if (u == 0) return 0;
    while ((u & 1ul) == 0) {
        u >>= 1;
        i++;
    }
    return i;
}

int ffsll(long long x) {
    int i = 1;
    unsigned long long u = (unsigned long long)x;
    if (u == 0) return 0;
    while ((u & 1ull) == 0) {
        u >>= 1;
        i++;
    }
    return i;
}

void bcopy(const void *s, void *d, size_t n) {
    /* memmove with BSD arg order (overlap-safe). */
    memmove(d, s, n);
}

void bzero(void *s, size_t n) { memset(s, 0, n); }

int bcmp(const void *a, const void *b, size_t n) {
    return memcmp(a, b, n);
}

char *index(const char *s, int c) { return strchr(s, c); }

char *rindex(const char *s, int c) { return strrchr(s, c); }
