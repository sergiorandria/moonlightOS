/* Moonlight libc - wchar: strict UTF-8 codec + wide strings.
 *
 * Sole locale is UTF-8 (like the rest of this libc): the codec accepts
 * exactly the valid UTF-8 forms and rejects overlongs, surrogates and
 * >U+10FFFF with EILSEQ. mbstate_t resume works across split reads
 * (partial bytes accumulate in the state, validated on completion).
 */
#include <wchar.h>
#include <uchar.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <wctype.h>

int mbsinit(const mbstate_t *ps) {
    if (!ps) return 1;
    return ps->ch == 0 && ps->need == 0 && ps->total == 0 && ps->surv == 0;
}

/* Smallest valid value for a `len`-byte sequence (overlong floor). */
static unsigned ml_utf8_min(unsigned len) {
    static const unsigned mins[5] = {0, 0, 0x80, 0x800, 0x10000};
    return len < 5 ? mins[len] : 0x110000u;
}

size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    unsigned char c;
    unsigned ch, need, total;
    size_t i = 0;
    if (!s) {
        memset(st, 0, sizeof(*st));
        return 0;
    }
    if (n == 0) return (size_t)-2;
    c = (unsigned char)s[0];
    if (st->need > 0) {
        /* Resuming a partial sequence. */
        ch = st->ch;
        need = st->need;
        total = st->total;
        goto cont;
    }
    if (c < 0x80) {
        if (pwc) *pwc = (wchar_t)c;
        if (c == 0) memset(st, 0, sizeof(*st));
        return c == 0 ? 0 : 1;
    }
    if (c < 0xC2) goto bad; /* continuation or overlong 2-byte */
    if (c < 0xE0) {
        total = 2;
        ch = c & 0x1F;
    } else if (c < 0xF0) {
        total = 3;
        ch = c & 0x0F;
    } else if (c < 0xF5) {
        total = 4;
        ch = c & 0x07;
    } else {
        goto bad; /* >U+10FFFF lead */
    }
    i = 1;
    need = total - 1;
cont:
    while (i < n && need > 0) {
        c = (unsigned char)s[i++];
        if ((c & 0xC0) != 0x80) {
            /* Bad continuation: resync (this byte starts over). */
            memset(st, 0, sizeof(*st));
            errno = EILSEQ;
            return (size_t)-1;
        }
        ch = (ch << 6) | (c & 0x3F);
        need--;
    }
    if (need > 0) {
        /* Ran out of input: stash progress, caller feeds more. */
        st->ch = ch;
        st->need = need;
        st->total = total;
        return (size_t)-2;
    }
    memset(st, 0, sizeof(*st));
    if (ch < ml_utf8_min(total) || (ch >= 0xD800 && ch <= 0xDFFF) ||
        ch > 0x10FFFF) {
        errno = EILSEQ;
        return (size_t)-1;
    }
    if (pwc) *pwc = (wchar_t)ch;
    return i; /* bytes consumed by this call (resume-aware) */
bad:
    memset(st, 0, sizeof(*st));
    errno = EILSEQ;
    return (size_t)-1;
}

size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    unsigned w = (unsigned)wc;
    (void)st;
    if (!s) {
        memset(st, 0, sizeof(*st));
        return 1; /* stateless encoding: no shift states */
    }
    if (w < 0x80) {
        s[0] = (char)w;
        return 1;
    }
    if (w < 0x800) {
        s[0] = (char)(0xC0 | (w >> 6));
        s[1] = (char)(0x80 | (w & 0x3F));
        return 2;
    }
    if (w < 0x10000) {
        if (w >= 0xD800 && w <= 0xDFFF) goto bad;
        s[0] = (char)(0xE0 | (w >> 12));
        s[1] = (char)(0x80 | ((w >> 6) & 0x3F));
        s[2] = (char)(0x80 | (w & 0x3F));
        return 3;
    }
    if (w <= 0x10FFFF) {
        s[0] = (char)(0xF0 | (w >> 18));
        s[1] = (char)(0x80 | ((w >> 12) & 0x3F));
        s[2] = (char)(0x80 | ((w >> 6) & 0x3F));
        s[3] = (char)(0x80 | (w & 0x3F));
        return 4;
    }
bad:
    errno = EILSEQ;
    return (size_t)-1;
}

size_t mbsrtowcs(wchar_t *dst, const char **src, size_t n, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    const char *p;
    size_t count = 0;
    if (!src || !*src) return 0;
    p = *src;
    for (;;) {
        wchar_t wc;
        size_t r;
        if (dst && count >= n) break; /* dst full: stop, *src stays */
        r = mbrtowc(&wc, p, MB_LEN_MAX, st);
        if (r == (size_t)-1) return (size_t)-1;
        if (r == (size_t)-2) break; /* cannot happen for NUL-terminated
                                     * input (truncation hits NUL first
                                     * and fails EILSEQ above); safe stop */
        if (r == 0) {
            if (dst && count < n) dst[count] = 0;
            *src = 0;
            return count; /* NUL stored but not counted */
        }
        if (dst) dst[count] = wc;
        count++;
        p += r;
    }
    *src = p;
    return count;
}

size_t wcsrtombs(char *dst, const wchar_t **src, size_t n, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    const wchar_t *p;
    size_t count = 0;
    char tmp[MB_LEN_MAX];
    if (!src || !*src) return 0;
    p = *src;
    while (*p) {
        size_t r = wcrtomb(tmp, *p, st);
        size_t i;
        if (r == (size_t)-1) return (size_t)-1;
        if (dst && count + r >= n) break; /* keep room for the NUL */
        if (dst) {
            for (i = 0; i < r; i++) dst[count + i] = tmp[i];
        }
        count += r;
        p++;
    }
    if (*p == 0) {
        if (dst) {
            if (count < n) dst[count] = '\0';
        } else {
            /* Sizing mode: converted bytes so far (NUL not counted). */
        }
        *src = 0;
        return count;
    }
    *src = p;
    return count;
}

/* ---- stdlib.h multibyte glue (internal static state, like the
 * single-threaded errno: documented). ---- */

int mblen(const char *s, size_t n) {
    static mbstate_t ml_st;
    if (!s) {
        memset(&ml_st, 0, sizeof(ml_st));
        return 0;
    }
    {
        size_t r = mbrtowc(0, s, n, &ml_st);
        if (r == (size_t)-1) {
            memset(&ml_st, 0, sizeof(ml_st));
            errno = EILSEQ;
            return -1;
        }
        if (r == (size_t)-2) return -2;
        return r == 0 ? 0 : (int)r;
    }
}

int mbtowc(wchar_t *pwc, const char *s, size_t n) {
    static mbstate_t ml_st;
    size_t r;
    if (!s) {
        memset(&ml_st, 0, sizeof(ml_st));
        return 0;
    }
    r = mbrtowc(pwc, s, n, &ml_st);
    if (r == (size_t)-1 || r == (size_t)-2) {
        if (r == (size_t)-1) memset(&ml_st, 0, sizeof(ml_st));
        return -1;
    }
    return r == 0 ? 0 : (int)r;
}

int wctomb(char *s, wchar_t wc) {
    static mbstate_t ml_st;
    size_t r;
    if (!s) {
        memset(&ml_st, 0, sizeof(ml_st));
        return 0;
    }
    r = wcrtomb(s, wc, &ml_st);
    return r == (size_t)-1 ? -1 : (int)r;
}

size_t mbstowcs(wchar_t *dst, const char *src, size_t n) {
    const char *p = src;
    mbstate_t st;
    memset(&st, 0, sizeof(st));
    if (!dst || !src) return 0;
    return mbsrtowcs(dst, &p, n, &st);
}

size_t wcstombs(char *dst, const wchar_t *src, size_t n) {
    const wchar_t *p = src;
    mbstate_t st;
    memset(&st, 0, sizeof(st));
    if (!dst || !src) return 0;
    return wcsrtombs(dst, &p, n, &st);
}

/* ---- wide strings ---- */

size_t wcslen(const wchar_t *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

size_t wcsnlen(const wchar_t *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i]) i++;
    return i;
}

wchar_t *wcscpy(wchar_t *d, const wchar_t *s) {
    wchar_t *r = d;
    while ((*d++ = *s++)) {}
    return r;
}

wchar_t *wcsncpy(wchar_t *d, const wchar_t *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i]) {
        d[i] = s[i];
        i++;
    }
    while (i < n) d[i++] = 0;
    return d;
}

wchar_t *wcscat(wchar_t *d, const wchar_t *s) {
    wchar_t *r = d;
    while (*d) d++;
    while ((*d++ = *s++)) {}
    return r;
}

wchar_t *wcsncat(wchar_t *d, const wchar_t *s, size_t n) {
    wchar_t *r = d;
    while (*d) d++;
    while (n-- && *s) *d++ = *s++;
    *d = 0;
    return r;
}

int wcscmp(const wchar_t *a, const wchar_t *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int wcsncmp(const wchar_t *a, const wchar_t *b, size_t n) {
    while (n > 0 && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    if (n == 0) return 0;
    return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int wcscoll(const wchar_t *a, const wchar_t *b) { return wcscmp(a, b); }

size_t wcsxfrm(wchar_t *d, const wchar_t *s, size_t n) {
    size_t sl = wcslen(s);
    if (n > 0) {
        size_t c = sl < n - 1 ? sl : n - 1;
        wmemcpy(d, s, c);
        d[c] = 0;
    }
    return sl;
}

wchar_t *wcschr(const wchar_t *s, wchar_t c) {
    while (*s) {
        if (*s == c) return (wchar_t *)s;
        s++;
    }
    return c == 0 ? (wchar_t *)s : 0;
}

wchar_t *wcsrchr(const wchar_t *s, wchar_t c) {
    const wchar_t *last = 0;
    while (*s) {
        if (*s == c) last = s;
        s++;
    }
    if (c == 0) return (wchar_t *)s;
    return (wchar_t *)last;
}

wchar_t *wcsstr(const wchar_t *h, const wchar_t *n) {
    size_t nl = wcslen(n);
    if (nl == 0) return (wchar_t *)h;
    while (*h) {
        if (*h == *n && wcsncmp(h, n, nl) == 0) return (wchar_t *)h;
        h++;
    }
    return 0;
}

wchar_t *wcspbrk(const wchar_t *s, const wchar_t *acc) {
    while (*s) {
        if (wcschr(acc, *s)) return (wchar_t *)s;
        s++;
    }
    return 0;
}

size_t wcsspn(const wchar_t *s, const wchar_t *acc) {
    size_t n = 0;
    while (s[n] && wcschr(acc, s[n])) n++;
    return n;
}

size_t wcscspn(const wchar_t *s, const wchar_t *rej) {
    size_t n = 0;
    while (s[n] && !wcschr(rej, s[n])) n++;
    return n;
}

wchar_t *wcstok(wchar_t *s, const wchar_t *delim, wchar_t **save) {
    wchar_t *p;
    if (s) *save = s;
    if (!*save) return 0;
    p = *save + wcsspn(*save, delim);
    if (*p == 0) {
        *save = 0;
        return 0;
    }
    s = p;
    p += wcscspn(p, delim);
    if (*p == 0) {
        *save = 0;
    } else {
        *p = 0;
        *save = p + 1;
    }
    return s;
}

wchar_t *wcsdup(const wchar_t *s) {
    size_t n = wcslen(s) + 1;
    wchar_t *p = malloc(n * sizeof(wchar_t));
    if (p) wmemcpy(p, s, n);
    return p;
}

wchar_t *wmemcpy(wchar_t *d, const wchar_t *s, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return d;
}

wchar_t *wmemmove(wchar_t *d, const wchar_t *s, size_t n) {
    if (d == s || n == 0) return d;
    if (d < s) {
        size_t i;
        for (i = 0; i < n; i++) d[i] = s[i];
    } else {
        while (n--) d[n] = s[n];
    }
    return d;
}

wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) s[i] = c;
    return s;
}

int wmemcmp(const wchar_t *a, const wchar_t *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n) {
    size_t i;
    for (i = 0; i < n; i++)
        if (s[i] == c) return (wchar_t *)(s + i);
    return 0;
}

/* ---- wide number conversion: exact round trip through a narrow
 * buffer (wcs length is known, so sizing is exact, no truncation). ---- */

static char *ml_widen_to_narrow(const wchar_t *s) {
    size_t wl;
    char *nb;
    const wchar_t *p;
    mbstate_t st;
    if (!s) {
        errno = EINVAL;
        return 0;
    }
    wl = wcslen(s);
    nb = malloc(wl * MB_LEN_MAX + 1);
    p = s;
    memset(&st, 0, sizeof(st));
    if (!nb) {
        errno = ENOMEM;
        return 0;
    }
    if (wcsrtombs(nb, &p, wl * MB_LEN_MAX + 1, &st) == (size_t)-1) {
        free(nb);
        return 0; /* errno = EILSEQ from the codec */
    }
    return nb;
}

/* Wide offset matching narrow byte offset `off` in the conversion of `s`:
 * the number of leading wide chars whose UTF-8 form fits in `off` bytes. */
static size_t ml_narrow_off_to_wide(const wchar_t *s, size_t off) {
    size_t woff = 0, boff = 0;
    mbstate_t st;
    memset(&st, 0, sizeof(st));
    while (s[woff]) {
        char tmp[MB_LEN_MAX];
        size_t w = wcrtomb(tmp, s[woff], &st);
        if (w == (size_t)-1 || boff + w > off) break;
        boff += w;
        woff++;
    }
    return woff;
}

#define ML_WCS_NUM_BODY(narrow_fn, wtype)                                     \
    {                                                                        \
        char *nb, *nend = 0;                                                 \
        wtype v;                                                             \
        if (!s) {                                                            \
            if (end) *end = 0;                                               \
            return 0;                                                        \
        }                                                                    \
        nb = ml_widen_to_narrow(s);                                          \
        if (!nb) {                                                           \
            if (end) *end = (wchar_t *)s;                                    \
            return 0;                                                        \
        }                                                                    \
        v = narrow_fn(nb, &nend, base);                                      \
        if (end)                                                             \
            *end = (wchar_t *)(s +                                           \
                               ml_narrow_off_to_wide(                        \
                                   s, (size_t)(nend - nb)));                 \
        free(nb);                                                            \
        return v;                                                            \
    }

long wcstol(const wchar_t *s, wchar_t **end, int base) {
    ML_WCS_NUM_BODY(strtol, long)
}

unsigned long wcstoul(const wchar_t *s, wchar_t **end, int base) {
    ML_WCS_NUM_BODY(strtoul, unsigned long)
}

long long wcstoll(const wchar_t *s, wchar_t **end, int base) {
    char *nb, *nend = 0;
    long long v;
    if (!s) {
        if (end) *end = 0;
        return 0;
    }
    nb = ml_widen_to_narrow(s);
    if (!nb) {
        if (end) *end = (wchar_t *)s;
        return 0;
    }
    v = strtoll(nb, &nend, base);
    if (end)
        *end = (wchar_t *)(s + ml_narrow_off_to_wide(s, (size_t)(nend - nb)));
    free(nb);
    return v;
}

unsigned long long wcstoull(const wchar_t *s, wchar_t **end, int base) {
    char *nb, *nend = 0;
    unsigned long long v;
    if (!s) {
        if (end) *end = 0;
        return 0;
    }
    nb = ml_widen_to_narrow(s);
    if (!nb) {
        if (end) *end = (wchar_t *)s;
        return 0;
    }
    v = strtoull(nb, &nend, base);
    if (end)
        *end = (wchar_t *)(s + ml_narrow_off_to_wide(s, (size_t)(nend - nb)));
    free(nb);
    return v;
}

double wcstod(const wchar_t *s, wchar_t **end) {
    char *nb, *nend = 0;
    double v;
    if (!s) {
        if (end) *end = 0;
        return 0;
    }
    nb = ml_widen_to_narrow(s);
    if (!nb) {
        if (end) *end = (wchar_t *)s;
        return 0;
    }
    v = strtod(nb, &nend);
    if (end)
        *end = (wchar_t *)(s + ml_narrow_off_to_wide(s, (size_t)(nend - nb)));
    free(nb);
    return v;
}

float wcstof(const wchar_t *s, wchar_t **end) {
    return (float)wcstod(s, end);
}

long double wcstold(const wchar_t *s, wchar_t **end) {
    return (long double)wcstod(s, end);
}

/* ---- single-byte compat ---- */

wint_t btowc(int c) {
    if (c == EOF) return WEOF;
    return (wint_t)(unsigned char)c; /* C locale subset == first 128 */
}

int wctob(wint_t c) {
    if (c == WEOF || (unsigned)c >= 128) return EOF;
    return (int)c;
}

/* ---- wide stdio ---- */

int fwide(FILE *f, int mode) {
    if (!f) return 0;
    if (mode == 0) return f->orient;
    if (f->orient == 0) f->orient = mode > 0 ? 1 : -1;
    return f->orient;
}

wint_t fgetwc(FILE *f) {
    unsigned char first;
    char mb[MB_LEN_MAX];
    mbstate_t st;
    wchar_t wc;
    size_t r, nread = 0;
    int c;
    if (!f) return WEOF;
    if (f->orient == 0) f->orient = 1;
    c = getc(f);
    if (c == EOF) return WEOF;
    mb[nread++] = (char)c;
    first = (unsigned char)c;
    {
        size_t want = 1;
        if (first >= 0xF0) want = 4;
        else if (first >= 0xE0) want = 3;
        else if (first >= 0xC0) want = 2;
        while (nread < want) {
            c = getc(f);
            if (c == EOF) {
                f->err = 1;
                return WEOF;
            }
            mb[nread++] = (char)c;
        }
    }
    memset(&st, 0, sizeof(st));
    r = mbrtowc(&wc, mb, nread, &st);
    if (r == (size_t)-1 || r == (size_t)-2) {
        f->err = 1;
        return WEOF;
    }
    return (wint_t)wc;
}

wchar_t *fgetws(wchar_t *s, int n, FILE *f) {
    int i = 0;
    wint_t c;
    if (!s || n <= 1 || !f) return 0;
    while (i < n - 1) {
        c = fgetwc(f);
        if (c == WEOF) break;
        s[i++] = (wchar_t)c;
        if (c == '\n') break;
    }
    s[i] = 0;
    return i > 0 ? s : 0;
}

wint_t getwchar(void) { return fgetwc(stdin); }

wint_t getwc(FILE *f) { return fgetwc(f); }

wint_t fputwc(wchar_t c, FILE *f) {
    char mb[MB_LEN_MAX];
    mbstate_t st;
    size_t r, i;
    if (!f) return WEOF;
    if (f->orient == 0) f->orient = 1;
    if (f->kind == 4) {
        /* Wide memstream: both views updated by the backend. */
        if (__ml_wputc(f, c) < 0) return WEOF;
        return (wint_t)c;
    }
    memset(&st, 0, sizeof(st));
    r = wcrtomb(mb, c, &st);
    if (r == (size_t)-1) {
        f->err = 1;
        return WEOF;
    }
    for (i = 0; i < r; i++)
        if (fputc(mb[i], f) == EOF) return WEOF;
    return (wint_t)c;
}

int fputws(const wchar_t *s, FILE *f) {
    if (!s || !f) return WEOF;
    while (*s)
        if (fputwc(*s++, f) == WEOF) return WEOF;
    return 0;
}

wint_t putwchar(wchar_t c) { return fputwc(c, stdout); }

wint_t putwc(wchar_t c, FILE *f) { return fputwc(c, f); }

wint_t ungetwc(wint_t c, FILE *f) {
    /* Push back the multibyte form (at most MB_LEN_MAX bytes; the
     * byte pushback holds ML_PBN=4, exactly enough). */
    char mb[MB_LEN_MAX];
    mbstate_t st;
    size_t r, i;
    if (c == WEOF || !f) return WEOF;
    memset(&st, 0, sizeof(st));
    r = wcrtomb(mb, (wchar_t)c, &st);
    if (r == (size_t)-1 || r > 4) return WEOF;
    for (i = r; i > 0; i--)
        if (ungetc(mb[i - 1], f) == EOF) return WEOF;
    return c;
}

/* Wide-format printf: translate the wide format to narrow, run the
 * tested narrow engine, then deliver bytes (files) or wide chars
 * (swprintf). Translation is byte-exact except for bare %c/%s, which
 * take wide args in wide printf and become %lc/%ls: %lc/%ls/%hs/%hhs
 * pass through untouched (narrow-string forms keep narrow semantics),
 * literal text is re-encoded to UTF-8. */
/* Worst case per wide char: 4 UTF-8 bytes, plus one 'l' inserted per
 * directive; cap = 5*wl + 16 covers everything with no regrowth. */
static int ml_wfmt_putc(char *nb, size_t *o, size_t cap, char c) {
    if (*o + 1 >= cap) return -1;
    nb[(*o)++] = c;
    return 0;
}

#define ML_WPUT(c) do { if (ml_wfmt_putc(nb, &o, cap, (c)) != 0) { \
    free(nb); return -1; } } while (0)

static int ml_wfmt_to_narrow(char **out, const wchar_t *fmt) {
    size_t wl = wcslen(fmt), i, o = 0, cap = wl * 5 + 16;
    char *nb = malloc(cap);
    if (!nb) return -1;
    for (i = 0; fmt[i]; i++) {
        wchar_t w = fmt[i];
        if (w != '%') {
            if (w < 0x80) {
                ML_WPUT( (char)w);
            } else {
                char tmp[MB_LEN_MAX];
                mbstate_t st;
                size_t r, k;
                memset(&st, 0, sizeof(st));
                r = wcrtomb(tmp, w, &st);
                if (r == (size_t)-1) {
                    free(nb);
                    errno = EILSEQ;
                    return -1;
                }
                for (k = 0; k < r; k++) ML_WPUT( tmp[k]);
            }
            continue;
        }
        /* Directive: copy flags/width/precision verbatim, then decide
         * the length row for c/s. */
        {
            size_t j = i + 1;
            ML_WPUT( '%');
            while (fmt[j] == '-' || fmt[j] == '+' || fmt[j] == ' ' ||
                   fmt[j] == '#' || fmt[j] == '0')
                ML_WPUT( (char)fmt[j++]);
            if (fmt[j] == '*') {
                ML_WPUT( '*');
                j++;
            } else {
                while (fmt[j] >= '0' && fmt[j] <= '9')
                    ML_WPUT( (char)fmt[j++]);
            }
            if (fmt[j] == '.') {
                ML_WPUT( '.');
                j++;
                if (fmt[j] == '*') {
                    ML_WPUT( '*');
                    j++;
                } else {
                    while (fmt[j] >= '0' && fmt[j] <= '9')
                        ML_WPUT( (char)fmt[j++]);
                }
            }
            /* Length row (copied, except bare c/s get an l). */
            {
                int has_len = 0;
                if (fmt[j] == 'h' || fmt[j] == 'l') {
                    has_len = 1;
                    ML_WPUT( (char)fmt[j]);
                    if ((fmt[j] == 'h' && fmt[j + 1] == 'h') ||
                        (fmt[j] == 'l' && fmt[j + 1] == 'l')) {
                        ML_WPUT( (char)fmt[j + 1]);
                        j += 2;
                    } else {
                        j++;
                    }
                } else if (fmt[j] == 'j' || fmt[j] == 'z' ||
                           fmt[j] == 't' || fmt[j] == 'L') {
                    has_len = 1;
                    ML_WPUT( (char)fmt[j++]);
                }
                if ((fmt[j] == 'c' || fmt[j] == 's') && !has_len)
                    ML_WPUT( 'l');
                if (fmt[j]) {
                    if (fmt[j] < 0x80) ML_WPUT(
                                                   (char)fmt[j++]);
                    else {
                        /* Non-ASCII spec: copy UTF-8 bytes through;
                         * the narrow engine echoes unknown specs. */
                        char tmp[MB_LEN_MAX];
                        mbstate_t st;
                        size_t r, m;
                        memset(&st, 0, sizeof(st));
                        r = wcrtomb(tmp, fmt[j++], &st);
                        if (r == (size_t)-1) r = 0;
                        for (m = 0; m < r; m++)
                            ML_WPUT( tmp[m]);
                    }
                }
            }
            i = j - 1;
        }
    }
    ML_WPUT( '\0');
    *out = nb;
    return 0;
}

int vfwprintf(FILE *f, const wchar_t *fmt, va_list ap) {
    /* Narrow engine has no FILE+vprintf entry: format to a bounded
     * stack buffer in chunks via vsnprintf-like streaming. Reuse the
     * public path: vasprintf (heap, exact size) then fwrite. */
    char *nfmt = 0, *out = 0;
    int n, wrote;
    if (!f || !fmt) return -1;
    if (ml_wfmt_to_narrow(&nfmt, fmt) != 0) return -1;
    n = vasprintf(&out, nfmt, ap);
    free(nfmt);
    if (n < 0) return -1;
    wrote = (int)fwrite(out, 1, (size_t)n, f);
    free(out);
    return wrote == n ? n : -1;
}

int fwprintf(FILE *f, const wchar_t *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vfwprintf(f, fmt, ap);
    va_end(ap);
    return r;
}

int vwprintf(const wchar_t *fmt, va_list ap) {
    return vfwprintf(stdout, fmt, ap);
}

int wprintf(const wchar_t *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vwprintf(fmt, ap);
    va_end(ap);
    return r;
}

int vswprintf(wchar_t *s, size_t n, const wchar_t *fmt, va_list ap) {
    char *nfmt = 0, *out = 0;
    int nb;
    if (!fmt) return -1;
    if (ml_wfmt_to_narrow(&nfmt, fmt) != 0) return -1;
    nb = vasprintf(&out, nfmt, ap);
    free(nfmt);
    if (nb < 0) return -1;
    /* Convert UTF-8 bytes back to wide, honoring the cap (C95: n
     * counts the NUL; truncation still returns the would-be count). */
    {
        const char *p = out;
        mbstate_t st;
        int total = 0;
        memset(&st, 0, sizeof(st));
        while (*p) {
            wchar_t wc;
            size_t r = mbrtowc(&wc, p, MB_LEN_MAX, &st);
            if (r == (size_t)-1 || r == (size_t)-2) break;
            if (r == 0) break;
            if (s && (size_t)total + 1 < n) s[total] = wc;
            total++;
            p += r;
        }
        if (s && n > 0) s[total < (int)n ? total : (int)n - 1] = 0;
        free(out);
        return total;
    }
}

int swprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vswprintf(s, n, fmt, ap);
    va_end(ap);
    return r;
}

/* ---- uchar.h (C11): UTF-8 <-> UTF-16/32 with surrogate state ---- */

size_t mbrtoc16(char16_t *pc16, const char *s, size_t n, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    wchar_t wc;
    size_t r;
    if (!s) {
        memset(st, 0, sizeof(*st));
        return 0;
    }
    if (st->surv) {
        /* A high surrogate is pending: emit the low half now. No
         * input is consumed, so this works even with n == 0. */
        if (pc16) *pc16 = (char16_t)st->surv;
        st->surv = 0;
        return (size_t)-3; /* low surrogate emitted, no input eaten */
    }
    r = mbrtowc(&wc, s, n, st);
    if (r == (size_t)-1 || r == (size_t)-2 || r == 0) {
        if (r == 0 && pc16) *pc16 = 0;
        return r;
    }
    if ((unsigned)wc < 0x10000) {
        if (pc16) *pc16 = (char16_t)wc;
        return r;
    }
    /* Astral: queue the pair; hand out the high half now. */
    {
        unsigned v = (unsigned)wc - 0x10000;
        if (pc16) *pc16 = (char16_t)(0xD800 + (v >> 10));
        st->surv = 0xDC00 + (v & 0x3FF);
        return r;
    }
}

size_t c16rtomb(char *s, char16_t c16, mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    if (!s) {
        memset(st, 0, sizeof(*st));
        return 1;
    }
    if (c16 >= 0xD800 && c16 <= 0xDBFF) {
        /* High half: stash, emit nothing yet. */
        st->surv = c16;
        return 0;
    }
    if (c16 >= 0xDC00 && c16 <= 0xDFFF) {
        if (st->surv >= 0xD800 && st->surv <= 0xDBFF) {
            wchar_t wc = (wchar_t)(0x10000 +
                                   ((st->surv - 0xD800) << 10) +
                                   (c16 - 0xDC00));
            st->surv = 0;
            return wcrtomb(s, wc, st);
        }
        errno = EILSEQ; /* lone low surrogate */
        return (size_t)-1;
    }
    if (st->surv) {
        st->surv = 0; /* unpaired high half followed by BMP char */
    }
    return wcrtomb(s, (wchar_t)c16, st);
}

size_t mbrtoc32(char32_t *pc32, const char *s, size_t n, mbstate_t *ps) {
    wchar_t wc;
    size_t r = mbrtowc(&wc, s, n, ps);
    if (r == (size_t)-1 || r == (size_t)-2 || r == 0) {
        if (r == 0 && pc32) *pc32 = 0;
        return r;
    }
    if (pc32) *pc32 = (char32_t)wc;
    return r;
}

size_t c32rtomb(char *s, char32_t c32, mbstate_t *ps) {
    if (!s) {
        if (ps) memset(ps, 0, sizeof(*ps));
        return 1;
    }
    return wcrtomb(s, (wchar_t)c32, ps);
}

/* ---- inttypes.h wide converters (exact, via the narrow core) ---- */

intmax_t wcstoimax(const wchar_t *s, wchar_t **end, int base) {
    char *nb, *nend = 0;
    intmax_t v;
    if (!s) {
        if (end) *end = 0;
        return 0;
    }
    nb = ml_widen_to_narrow(s);
    if (!nb) {
        if (end) *end = (wchar_t *)s;
        return 0;
    }
    v = strtoimax(nb, &nend, base);
    if (end)
        *end = (wchar_t *)(s + ml_narrow_off_to_wide(s, (size_t)(nend - nb)));
    free(nb);
    return v;
}

uintmax_t wcstoumax(const wchar_t *s, wchar_t **end, int base) {
    char *nb, *nend = 0;
    uintmax_t v;
    if (!s) {
        if (end) *end = 0;
        return 0;
    }
    nb = ml_widen_to_narrow(s);
    if (!nb) {
        if (end) *end = (wchar_t *)s;
        return 0;
    }
    v = strtoumax(nb, &nend, base);
    if (end)
        *end = (wchar_t *)(s + ml_narrow_off_to_wide(s, (size_t)(nend - nb)));
    free(nb);
    return v;
}

/* ---- bounded restartable conversion ---- */

size_t mbsnrtowcs(wchar_t *dst, const char **src, size_t nmc, size_t n,
                  mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    const char *p;
    size_t count = 0;
    if (!src || !*src) {
        errno = EINVAL;
        return (size_t)-1;
    }
    p = *src;
    while (nmc > 0) {
        wchar_t wc;
        size_t avail = nmc < MB_LEN_MAX ? nmc : MB_LEN_MAX, r;
        if (dst && count >= n) break;
        r = mbrtowc(&wc, p, avail, st);
        if (r == (size_t)-1) return (size_t)-1;
        if (r == (size_t)-2) break; /* truncated tail: stop, keep *src */
        if (r == 0) {
            if (dst && count < n) dst[count] = 0;
            *src = 0;
            return count;
        }
        if (dst) dst[count] = wc;
        count++;
        p += r;
        nmc -= r;
    }
    *src = p;
    return count;
}

size_t wcsnrtombs(char *dst, const wchar_t **src, size_t nwc, size_t n,
                  mbstate_t *ps) {
    static mbstate_t ml_internal;
    mbstate_t *st = ps ? ps : &ml_internal;
    const wchar_t *p;
    size_t count = 0;
    char tmp[MB_LEN_MAX];
    if (!src || !*src) {
        errno = EINVAL;
        return (size_t)-1;
    }
    p = *src;
    while (nwc > 0 && *p) {
        size_t r = wcrtomb(tmp, *p, st), i;
        if (r == (size_t)-1) return (size_t)-1;
        if (dst && count + r > n) break;
        if (dst) {
            for (i = 0; i < r; i++) dst[count + i] = tmp[i];
        }
        count += r;
        p++;
        nwc--;
    }
    if (*p == 0) {
        if (dst && count < n) dst[count] = '\0';
        *src = 0;
    } else {
        *src = p;
    }
    return count;
}

/* ---- character width (Unicode 15 ranges, condensed) ---- */

static int ml_is_combining(unsigned c) {
    /* Combining marks / zero-width (representative blocks). */
    return (c >= 0x300 && c <= 0x36F) || (c >= 0x1AB0 && c <= 0x1AFF) ||
           (c >= 0x1DC0 && c <= 0x1DFF) || (c >= 0x20D0 && c <= 0x20FF) ||
           (c >= 0xFE20 && c <= 0xFE2F) || c == 0x200B || c == 0x200C ||
           c == 0x200D || c == 0xFEFF || (c >= 0xE0100 && c <= 0xE01EF);
}

static int ml_is_wide(unsigned c) {
    return (c >= 0x1100 && c <= 0x115F) || c == 0x2329 || c == 0x232A ||
           (c >= 0x2E80 && c <= 0x303E) || (c >= 0x3041 && c <= 0x33FF) ||
           (c >= 0x3400 && c <= 0x4DBF) || (c >= 0x4E00 && c <= 0xA4CF) ||
           (c >= 0xA960 && c <= 0xA97F) || (c >= 0xAC00 && c <= 0xD7FF) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0xFE10 && c <= 0xFE19) ||
           (c >= 0xFE30 && c <= 0xFE4F) || (c >= 0xFF00 && c <= 0xFF60) ||
           (c >= 0xFFE0 && c <= 0xFFE6) || (c >= 0x20000 && c <= 0x3FFFD);
}

int wcwidth(wchar_t c) {
    unsigned u = (unsigned)c;
    if (u == 0) return 0;
    if (u < 32 || (u >= 0x7F && u < 0xA0)) return -1;
    if (ml_is_combining(u)) return 0;
    if (ml_is_wide(u)) return 2;
    return 1;
}

int wcswidth(const wchar_t *s, size_t n) {
    size_t i;
    int w = 0;
    if (!s) return -1;
    for (i = 0; i < n && s[i]; i++) {
        int c = wcwidth(s[i]);
        if (c < 0) return -1;
        w += c;
    }
    return w;
}

/* ---- wide case-insensitive compare (Latin-1 aware, like towlower) ---- */

static wchar_t ml_wlow(wchar_t c) { return (wchar_t)towlower((wint_t)c); }

int wcscasecmp(const wchar_t *a, const wchar_t *b) {
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && ml_wlow(*a) == ml_wlow(*b)) {
        a++;
        b++;
    }
    return (int)ml_wlow(*a) - (int)ml_wlow(*b);
}

int wcsncasecmp(const wchar_t *a, const wchar_t *b, size_t n) {
    size_t i;
    if (n == 0) return 0;
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    for (i = 0; i < n; i++) {
        if (!a[i] || ml_wlow(a[i]) != ml_wlow(b[i]))
            return (int)ml_wlow(a[i]) - (int)ml_wlow(b[i]);
        if (!b[i]) break;
    }
    return 0;
}

/* ---- wcsftime via the narrow engine ---- */

size_t wcsftime(wchar_t *s, size_t n, const wchar_t *fmt,
                const struct tm *tm) {
    /* Narrow the format (ASCII directives), run strftime, widen back. */
    char nfmt[256];
    char out[512];
    size_t r, i = 0, wi = 0;
    mbstate_t st;
    if (!s || !fmt || !tm || n == 0) return 0;
    while (fmt[i] && i < sizeof(nfmt) - 1) {
        if (fmt[i] >= 0x80) {
            char tmp[MB_LEN_MAX];
            size_t k, q;
            memset(&st, 0, sizeof(st));
            q = wcrtomb(tmp, fmt[i], &st);
            if (q == (size_t)-1 || i + q >= sizeof(nfmt) - 1) return 0;
            for (k = 0; k < q; k++) nfmt[i++] = tmp[k];
            continue;
        }
        nfmt[i] = (char)fmt[i];
        i++;
    }
    nfmt[i] = '\0';
    r = strftime(out, sizeof(out), nfmt, tm);
    if (r == 0) return 0;
    memset(&st, 0, sizeof(st));
    {
        const char *p = out;
        while (*p && wi + 1 < n) {
            wchar_t wc;
            size_t q = mbrtowc(&wc, p, MB_LEN_MAX, &st);
            if (q == (size_t)-1 || q == (size_t)-2 || q == 0) break;
            s[wi++] = wc;
            p += q;
        }
        s[wi] = 0;
    }
    return wi;
}

/* ---- open_wmemstream (kind-4 stream, backend in stdio.c) ---- */

FILE *open_wmemstream(wchar_t **ptr, size_t *len) {
    if (!ptr || !len) {
        errno = EINVAL;
        return 0;
    }
    return __ml_wmemstream_create(ptr, len);
}
