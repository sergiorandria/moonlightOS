/* libc scanf: vsscanf over a string cursor, vfscanf over getc/ungetc.
 * One shared engine. Pushback discipline: at most the final rejector
 * (plus up to 2 exponent-lookahead chars) is pushed back, so ML_PBN (4)
 * always suffices; a short %c at EOF keeps what it consumed (input
 * failure, stream at EOF). %n counts every consumed char, including
 * skipped whitespace. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <wchar.h>
#include <stdarg.h>

typedef struct {
    FILE *f;
    const char *s;  /* string input cursor (NULL for FILE) */
    long consumed;  /* chars pulled from the source, net of pushback */
    int failed;     /* sticky input failure (EOF/error mid-directive) */
} ML_IN;

static int ml_in_getc(ML_IN *in) {
    int c;
    if (in->failed) return EOF;
    if (in->f) {
        c = getc(in->f);
        if (c == EOF) in->failed = 1;
        else in->consumed++;
        return c;
    }
    if (*in->s == '\0') {
        in->failed = 1;
        return EOF;
    }
    in->consumed++;
    return (unsigned char)*in->s++;
}

static void ml_in_ungetc(int c, ML_IN *in) {
    if (c == EOF) return;
    if (in->f) {
        if (ungetc(c, in->f) != EOF) {
            in->consumed--;
            in->failed = 0;
        }
        return;
    }
    /* Only ever called for chars just pulled above: backing up is safe. */
    in->s--;
    in->consumed--;
    in->failed = 0;
}

static void ml_in_skipws(ML_IN *in) {
    int c;
    do {
        c = ml_in_getc(in);
    } while (c != EOF && isspace(c));
    if (c != EOF) ml_in_ungetc(c, in);
    else in->failed = 0; /* whitespace absence at EOF is not failure */
}

/* ---- token extraction (bounded, grammar-checked, ≤2 lookahead) ---- */

#define ML_TOKN 128

/* Integer token: sign + digits for the base. %i auto-detects (0x/0/oct).
 * Returns token length (>0) or 0 on matching failure (nothing consumed
 * except at most sign + rejector, which are pushed back). */
static int ml_tok_int(ML_IN *in, int base, int is_i, char *tok) {
    int c, n = 0;
    c = ml_in_getc(in);
    if (c == '+' || c == '-') {
        tok[n++] = (char)c;
        c = ml_in_getc(in);
    }
    if (c == EOF) {
        while (n > 0) ml_in_ungetc(tok[--n], in);
        return 0;
    }
    if (is_i) {
        if (c == '0') {
            tok[n++] = (char)c;
            c = ml_in_getc(in);
            if (c == 'x' || c == 'X') {
                int c3 = ml_in_getc(in);
                if (!isxdigit(c3)) {
                    /* "0x" with no hex digits: the item is "0". */
                    ml_in_ungetc(c3, in);
                    ml_in_ungetc(c, in);
                    tok[n] = '\0';
                    return n;
                }
                tok[n++] = (char)c;
                c = c3;
                base = 16;
                while (isxdigit(c) && n < ML_TOKN - 1) {
                    tok[n++] = (char)c;
                    c = ml_in_getc(in);
                }
                if (c != EOF) ml_in_ungetc(c, in);
                tok[n] = '\0';
                return n;
            }
            /* Octal (or lone zero): only [0-7] extend the token; a
             * trailing 8/9 stays unread ("09" is item "0" + "9"). */
            base = 8;
            while (c >= '0' && c <= '7' && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                c = ml_in_getc(in);
            }
            if (c != EOF) ml_in_ungetc(c, in);
            tok[n] = '\0';
            return n;
        }
        base = 10;
    }
    {
        if (base == 8) {
            if (c < '0' || c > '7') {
                ml_in_ungetc(c, in);
                while (n > 0) ml_in_ungetc(tok[--n], in);
                return 0;
            }
            while (c >= '0' && c <= '7' && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                c = ml_in_getc(in);
            }
        } else if (base == 10) {
            if (!isdigit(c)) {
                ml_in_ungetc(c, in);
                while (n > 0) ml_in_ungetc(tok[--n], in);
                return 0;
            }
            while (isdigit(c) && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                c = ml_in_getc(in);
            }
        } else { /* base 16 */
            if (c == '0') {
                int c2 = ml_in_getc(in);
                if (c2 == 'x' || c2 == 'X') {
                    int c3 = ml_in_getc(in);
                    if (!isxdigit(c3)) {
                        /* Bare "0x": the item is "0", "x..." unread. */
                        ml_in_ungetc(c3, in);
                        ml_in_ungetc(c2, in);
                        tok[n++] = (char)c;
                        tok[n] = '\0';
                        return n;
                    }
                    tok[n++] = (char)c;
                    tok[n++] = (char)c2;
                    c = c3;
                } else {
                    ml_in_ungetc(c2, in);
                }
            } else if (!isxdigit(c)) {
                ml_in_ungetc(c, in);
                while (n > 0) ml_in_ungetc(tok[--n], in);
                return 0;
            }
            while (isxdigit(c) && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                c = ml_in_getc(in);
            }
        }
        if (c != EOF) ml_in_ungetc(c, in);
        tok[n] = '\0';
        return n;
    }
}

/* Float token: [sign] (digits[.digits] | .digits | inf | nan) [exponent],
 * plus the 0x-hex form for %a. Same 0-on-failure contract. */
static int ml_tok_float(ML_IN *in, int allow_hex, char *tok) {
    int c, n = 0, ndig = 0;
    c = ml_in_getc(in);
    if (c == '+' || c == '-') {
        tok[n++] = (char)c;
        c = ml_in_getc(in);
    }
    if (c == EOF) {
        while (n > 0) ml_in_ungetc(tok[--n], in);
        return 0;
    }
    /* inf / nan (any case). */
    if (c == 'i' || c == 'I' || c == 'n' || c == 'N') {
        const char *w = (c == 'i' || c == 'I') ? "infinity" : "nan";
        int i = 1;
        tok[n++] = (char)c;
        for (;;) {
            c = ml_in_getc(in);
            if (c != EOF && tolower(c) == w[i] && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                i++;
                if (w[i] == '\0') break;
            } else {
                if (c != EOF) ml_in_ungetc(c, in);
                break;
            }
        }
        /* "inf" is a complete item even without the full "infinity". */
        if ((w[0] == 'i' && i >= 3) || (w[0] == 'n' && i >= 3)) {
            if (w[0] == 'n') {
                /* nan(sequence): consume to the closing paren. */
                c = ml_in_getc(in);
                if (c == '(') {
                    do {
                        c = ml_in_getc(in);
                    } while (c != EOF && c != ')');
                } else if (c != EOF) {
                    ml_in_ungetc(c, in);
                }
            }
            tok[n] = '\0';
            return n;
        }
        while (n > 0) ml_in_ungetc(tok[--n], in);
        return 0;
    }
    /* Hex form (only for %a): validated by peeking (≤3 chars), then
     * committed. Past "0x" + one hex digit the parse is committed: a
     * missing/malformed binary exponent is a matching failure with the
     * span consumed (glibc also consumes on hard failure; the one
     * divergence is "0x1234" with no 'p' at all, where glibc falls back
     * to decimal 0 — documented in docs/LINUX.md). */
    if (allow_hex && c == '0') {
        int c2 = ml_in_getc(in);
        if (c2 == 'x' || c2 == 'X') {
            int c3 = ml_in_getc(in);
            int hexok = isxdigit(c3) || c3 == '.';
            ml_in_ungetc(c3, in);
            ml_in_ungetc(c2, in);
            if (hexok) {
                int hexdig = 0;
                tok[n++] = (char)c;
                tok[n++] = (char)ml_in_getc(in); /* 'x' */
                c = ml_in_getc(in);
                while (isxdigit(c) && n < ML_TOKN - 1) {
                    tok[n++] = (char)c;
                    hexdig = 1;
                    c = ml_in_getc(in);
                }
                if (c == '.' && n < ML_TOKN - 1) {
                    tok[n++] = (char)c;
                    c = ml_in_getc(in);
                    while (isxdigit(c) && n < ML_TOKN - 1) {
                        tok[n++] = (char)c;
                        hexdig = 1;
                        c = ml_in_getc(in);
                    }
                }
                if (!hexdig || (c != 'p' && c != 'P')) {
                    tok[n] = '\0';
                    return 0; /* committed: span stays consumed */
                }
                tok[n++] = (char)c;
                c = ml_in_getc(in);
                if (c == '+' || c == '-') {
                    int c4 = ml_in_getc(in);
                    if (!isdigit(c4)) {
                        tok[n] = '\0';
                        return 0; /* committed */
                    }
                    tok[n++] = (char)c;
                    c = c4;
                }
                if (!isdigit(c)) {
                    tok[n] = '\0';
                    return 0; /* committed */
                }
                while (isdigit(c) && n < ML_TOKN - 1) {
                    tok[n++] = (char)c;
                    c = ml_in_getc(in);
                }
                if (c != EOF) ml_in_ungetc(c, in);
                tok[n] = '\0';
                return n;
            }
        } else {
            ml_in_ungetc(c2, in);
        }
    }
    while (isdigit(c) && n < ML_TOKN - 1) {
        tok[n++] = (char)c;
        ndig = 1;
        c = ml_in_getc(in);
    }
    if (c == '.' && n < ML_TOKN - 1) {
        tok[n++] = (char)c;
        c = ml_in_getc(in);
        while (isdigit(c) && n < ML_TOKN - 1) {
            tok[n++] = (char)c;
            ndig = 1;
            c = ml_in_getc(in);
        }
    }
    if (!ndig) {
        ml_in_ungetc(c, in);
        while (n > 0) ml_in_ungetc(tok[--n], in);
        return 0;
    }
    /* Exponent, with 2-char lookahead so a bare 'e' stays unread. */
    if ((c == 'e' || c == 'E') && n < ML_TOKN - 3) {
        int c1 = ml_in_getc(in);
        if (isdigit(c1)) {
            tok[n++] = (char)c;
            c = c1;
            while (isdigit(c) && n < ML_TOKN - 1) {
                tok[n++] = (char)c;
                c = ml_in_getc(in);
            }
            if (c != EOF) ml_in_ungetc(c, in);
        } else if (c1 == '+' || c1 == '-') {
            int c2 = ml_in_getc(in);
            if (isdigit(c2)) {
                tok[n++] = (char)c;
                tok[n++] = (char)c1;
                c = c2;
                while (isdigit(c) && n < ML_TOKN - 1) {
                    tok[n++] = (char)c;
                    c = ml_in_getc(in);
                }
                if (c != EOF) ml_in_ungetc(c, in);
            } else {
                if (c2 != EOF) ml_in_ungetc(c2, in);
                ml_in_ungetc(c1, in);
                ml_in_ungetc(c, in);
            }
        } else {
            if (c1 != EOF) ml_in_ungetc(c1, in);
            ml_in_ungetc(c, in);
        }
    } else {
        if (c != EOF) ml_in_ungetc(c, in);
    }
    tok[n] = '\0';
    return n;
}

/* ---- the engine ---- */

static int ml_scan(ML_IN *in, const char *fmt, va_list ap) {
    int assigned = 0;
    while (*fmt) {
        if (isspace((unsigned char)*fmt)) {
            ml_in_skipws(in);
            fmt++;
            continue;
        }
        if (*fmt != '%') {
            int c = ml_in_getc(in);
            if (c == EOF || c != (unsigned char)*fmt) {
                if (c != EOF) ml_in_ungetc(c, in);
                break; /* literal mismatch */
            }
            fmt++;
            continue;
        }
        fmt++; /* conversion */
        {
            int suppress = 0, width = 0, len = 0; /* 1 hh 2 h 3 l 4 ll 5 j 6 z 7 t 8 L */
            if (*fmt == '*') {
                suppress = 1;
                fmt++;
            }
            while (isdigit((unsigned char)*fmt)) {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
            if (*fmt == 'h') {
                fmt++;
                len = 2;
                if (*fmt == 'h') {
                    fmt++;
                    len = 1;
                }
            } else if (*fmt == 'l') {
                fmt++;
                len = 3;
                if (*fmt == 'l') {
                    fmt++;
                    len = 4;
                }
            } else if (*fmt == 'j') {
                fmt++;
                len = 5;
            } else if (*fmt == 'z') {
                fmt++;
                len = 6;
            } else if (*fmt == 't') {
                fmt++;
                len = 7;
            } else if (*fmt == 'L') {
                fmt++;
                len = 8;
            }
            {
                char spec = *fmt ? *fmt : '\0';
                char tok[ML_TOKN];
                int fwidth;
                if (spec == '\0') break;
                fmt++;
                if (spec == '%') {
                    int c;
                    ml_in_skipws(in);
                    c = ml_in_getc(in);
                    if (c != '%') {
                        if (c != EOF) ml_in_ungetc(c, in);
                        break;
                    }
                    continue;
                }
                if (spec == 'n') {
                    /* Consumed count (never fails, never counts). */
                    if (!suppress) {
                        int *p = va_arg(ap, int *);
                        *p = (int)in->consumed;
                    }
                    continue;
                }
                if (spec != 'c' && spec != '[') ml_in_skipws(in);
                fwidth = width ? width : ML_TOKN - 1;
                if (fwidth > ML_TOKN - 1) fwidth = ML_TOKN - 1;
                if (spec == 'c') {
                    int w = width ? width : 1, i;
                    if (len == 3) {
                        /* %lc: w multibyte chars -> wchar_t (UTF-8). */
                        wchar_t *wp = suppress ? 0 : va_arg(ap, wchar_t *);
                        int nw = 0;
                        for (i = 0; i < w; i++) {
                            char mb[4];
                            int nread = 0, c, k;
                            size_t r;
                            mbstate_t st;
                            memset(&st, 0, sizeof(st));
                            for (k = 0; k < 4; k++) {
                                c = ml_in_getc(in);
                                if (c == EOF) break;
                                mb[nread++] = (char)c;
                                r = mbrtowc(0, mb, (size_t)nread, &st);
                                if (r == (size_t)-2) continue;
                                break;
                            }
                            if (nread == 0) break;
                            r = mbrtowc(0, mb, (size_t)nread, &st);
                            if (r == (size_t)-1 || r == (size_t)-2) {
                                for (k = nread - 1; k >= 0; k--)
                                    ml_in_ungetc((unsigned char)mb[k],
                                                 in);
                                break;
                            }
                            for (k = nread - 1; k >= (int)r; k--)
                                ml_in_ungetc((unsigned char)mb[k], in);
                            if (!suppress) {
                                mbstate_t st2;
                                memset(&st2, 0, sizeof(st2));
                                mbrtowc(&wp[nw], mb, r, &st2);
                            }
                            nw++;
                        }
                        if (nw == 0) break;
                        if (!suppress) assigned++;
                        continue;
                    }
                    {
                        char *p = suppress ? 0 : va_arg(ap, char *);
                        for (i = 0; i < w; i++) {
                            int c = ml_in_getc(in);
                            if (c == EOF) break;
                            if (!suppress) p[i] = (char)c;
                        }
                        if (i == 0) break; /* nothing at all */
                        if (i < w) {
                            /* Short read: input failure (consumed kept). */
                            if (!suppress) assigned++;
                            break;
                        }
                        if (!suppress) assigned++;
                        continue;
                    }
                }
                if (spec == 's' || spec == '[') {
                    int i = 0, invert = 0;
                    char set[257];
                    int nset = 0;
                    if (spec == '[') {
                        /* Parse the scanset from the FORMAT (fmt already
                         * past '['). */
                        if (*fmt == '^') {
                            invert = 1;
                            fmt++;
                        }
                        if (*fmt == ']') {
                            set[nset++] = ']';
                            fmt++;
                        }
                        while (*fmt && *fmt != ']') {
                            if (fmt[0] == '-' && nset > 0 && fmt[1] &&
                                fmt[1] != ']' &&
                                (unsigned char)set[nset - 1] <=
                                    (unsigned char)fmt[1]) {
                                char lo = set[--nset], hi = fmt[1];
                                for (; lo <= hi && nset < 256; lo++)
                                    set[nset++] = lo;
                                fmt += 2;
                            } else {
                                if (nset < 256) set[nset++] = *fmt;
                                fmt++;
                            }
                        }
                        if (*fmt == ']') fmt++;
                        else break; /* unterminated scanset: stop */
                    }
                    if (len == 3) {
                        /* %ls: wide string via mbrtowc. */
                        wchar_t *wp = suppress ? 0 : va_arg(ap, wchar_t *);
                        int nw = 0;
                        mbstate_t st;
                        memset(&st, 0, sizeof(st));
                        for (;;) {
                            char mb[4];
                            int nread = 0, c;
                            size_t r;
                            if (width && nw >= width) break;
                            for (i = 0; i < 4; i++) {
                                c = ml_in_getc(in);
                                if (c == EOF) break;
                                if (spec == 's' && isspace(c)) {
                                    ml_in_ungetc(c, in);
                                    c = EOF;
                                    break;
                                }
                                mb[nread++] = (char)c;
                                r = mbrtowc(0, mb, (size_t)nread, &st);
                                if (r == (size_t)-2) continue;
                                break;
                            }
                            if (nread == 0) break;
                            r = mbrtowc(0, mb, (size_t)nread, &st);
                            if (r == (size_t)-1 || r == (size_t)-2) {
                                /* Invalid sequence ends the item;
                                 * push the bytes back. */
                                for (i = nread - 1; i >= 0; i--)
                                    ml_in_ungetc((unsigned char)mb[i],
                                                 in);
                                break;
                            }
                            for (i = nread - 1; i >= (int)r; i--)
                                ml_in_ungetc((unsigned char)mb[i], in);
                            {
                                wchar_t wc;
                                mbstate_t st2;
                                memset(&st2, 0, sizeof(st2));
                                mbrtowc(&wc, mb, r, &st2);
                                if (!suppress) wp[nw] = wc;
                            }
                            nw++;
                        }
                        if (nw == 0) break;
                        if (!suppress) {
                            wp[nw] = 0;
                            assigned++;
                        }
                        continue;
                    }
                    {
                        char *p = suppress ? 0 : va_arg(ap, char *);
                        for (;;) {
                            int c;
                            if (width && i >= width) break;
                            c = ml_in_getc(in);
                            if (c == EOF) break;
                            if (spec == 's') {
                                if (isspace(c)) {
                                    ml_in_ungetc(c, in);
                                    break;
                                }
                            } else {
                                int k, hit = 0;
                                for (k = 0; k < nset; k++)
                                    if (c == (unsigned char)set[k]) {
                                        hit = 1;
                                        break;
                                    }
                                if (invert) hit = !hit;
                                if (!hit) {
                                    ml_in_ungetc(c, in);
                                    break;
                                }
                            }
                            /* Uncapped %s trusts the caller buffer
                             * (standard semantics, like glibc). */
                            if (!suppress) p[i] = (char)c;
                            i++;
                        }
                        if (i == 0) break; /* empty item */
                        if (!suppress) {
                            p[i] = '\0';
                            assigned++;
                        }
                        continue;
                    }
                }
                if (spec == 'd' || spec == 'i' || spec == 'u' ||
                    spec == 'o' || spec == 'x' || spec == 'X' ||
                    spec == 'p') {
                    int base = 10, is_i = 0, tl;
                    int is_unsigned =
                        (spec == 'u' || spec == 'o' || spec == 'x' ||
                         spec == 'X' || spec == 'p');
                    if (spec == 'i') is_i = 1;
                    else if (spec == 'o') base = 8;
                    else if (spec == 'x' || spec == 'X' || spec == 'p')
                        base = 16;
                    tl = ml_tok_int(in, base, is_i || spec == 'p', tok);
                    if (tl == 0) break;
                    if (spec == 'p') {
                        void **pp =
                            suppress ? 0 : va_arg(ap, void **);
                        unsigned long long v =
                            strtoull(tok, 0, base);
                        if (!suppress) {
                            *pp = (void *)(uintptr_t)v;
                            assigned++;
                        }
                        continue;
                    }
                    if (is_unsigned) {
                        unsigned long long v =
                            strtoull(tok, 0, base);
                        if (!suppress) {
                            if (len == 1)
                                *va_arg(ap, unsigned char *) =
                                    (unsigned char)v;
                            else if (len == 2)
                                *va_arg(ap, unsigned short *) =
                                    (unsigned short)v;
                            else if (len == 3)
                                *va_arg(ap, unsigned long *) =
                                    (unsigned long)v;
                            else if (len == 4)
                                *va_arg(ap, unsigned long long *) = v;
                            else if (len == 5)
                                *va_arg(ap, uintmax_t *) =
                                    (uintmax_t)v;
                            else if (len == 6)
                                *va_arg(ap, size_t *) = (size_t)v;
                            else if (len == 7)
                                *va_arg(ap, ptrdiff_t *) =
                                    (ptrdiff_t)v;
                            else
                                *va_arg(ap, unsigned *) = (unsigned)v;
                            assigned++;
                        }
                    } else {
                        /* %i tokens carry their own base prefix
                         * ("077", "0x10"): convert with base 0 so
                         * strtoll auto-detects (else "077" reads 77). */
                        long long v = strtoll(tok, 0, is_i ? 0 : base);
                        if (!suppress) {
                            if (len == 1)
                                *va_arg(ap, signed char *) =
                                    (signed char)v;
                            else if (len == 2)
                                *va_arg(ap, short *) = (short)v;
                            else if (len == 3)
                                *va_arg(ap, long *) = (long)v;
                            else if (len == 4)
                                *va_arg(ap, long long *) = v;
                            else if (len == 5)
                                *va_arg(ap, intmax_t *) = (intmax_t)v;
                            else if (len == 6)
                                *va_arg(ap, ssize_t *) = (ssize_t)v;
                            else if (len == 7)
                                *va_arg(ap, ptrdiff_t *) =
                                    (ptrdiff_t)v;
                            else
                                *va_arg(ap, int *) = (int)v;
                            assigned++;
                        }
                    }
                    continue;
                }
                if (spec == 'f' || spec == 'F' || spec == 'e' ||
                    spec == 'E' || spec == 'g' || spec == 'G' ||
                    spec == 'a' || spec == 'A') {
                    int tl = ml_tok_float(
                        in, spec == 'a' || spec == 'A', tok);
                    double v;
                    if (tl == 0) break;
                    v = strtod(tok, 0);
                    if (!suppress) {
                        /* C: %f/%e/%g (and %lf) all take double*;
                         * only %Lf takes long double* (no float*
                         * form exists for scanf). */
                        if (len == 8)
                            *va_arg(ap, long double *) =
                                (long double)v;
                        else
                            *va_arg(ap, double *) = v;
                        assigned++;
                    }
                    continue;
                }
                /* Unknown specifier: stop (never consume). */
                break;
            }
            (void)suppress;
            break;
        }
    }
    if (assigned == 0 && in->failed) {
        /* Input failure before any conversion: EOF (errno untouched;
         * feof/ferror tell the story). */
        return EOF;
    }
    return assigned;
}

int vsscanf(const char *s, const char *fmt, va_list ap) {
    ML_IN in;
    if (!s || !fmt) return EOF;
    in.f = 0;
    in.s = s;
    in.consumed = 0;
    in.failed = 0;
    return ml_scan(&in, fmt, ap);
}

int sscanf(const char *s, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vsscanf(s, fmt, ap);
    va_end(ap);
    return r;
}

int vfscanf(FILE *f, const char *fmt, va_list ap) {
    ML_IN in;
    if (!f || !fmt) return EOF;
    in.f = f;
    in.s = 0;
    in.consumed = 0;
    in.failed = 0;
    return ml_scan(&in, fmt, ap);
}

int fscanf(FILE *f, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vfscanf(f, fmt, ap);
    va_end(ap);
    return r;
}

int vscanf(const char *fmt, va_list ap) { return vfscanf(stdin, fmt, ap); }

int scanf(const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vscanf(fmt, ap);
    va_end(ap);
    return r;
}
