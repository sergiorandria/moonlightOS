/* libc stdio: vsnprintf core + unbuffered FILE over fds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <sys/stat.h>
#include <wchar.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

/* ---- vsnprintf ---- */

typedef struct {
    char *buf;
    size_t cap; /* includes NUL */
    size_t len; /* chars that would be written (excl NUL) */
} __ML_OUT;

static void __ml_emit(__ML_OUT *o, char c) {
    if (o->len + 1 < o->cap) o->buf[o->len] = c;
    o->len++;
}

static void __ml_emitn(__ML_OUT *o, const char *s, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) __ml_emit(o, s[i]);
}

static size_t __ml_num(__ML_OUT *o, unsigned long long v, int base,
                       const char *digits, int width, int prec, int flags) {
    char tmp[64];
    int n = 0, neg = 0, i, pad;
    (void)prec;
    if ((flags & 32) && base == 10) {
        /* signed */
        if ((long long)v < 0) {
            neg = 1;
            v = (unsigned long long)(-(long long)v);
        }
    }
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0 && n < 63) {
            tmp[n++] = digits[v % (unsigned)base];
            v /= (unsigned)base;
        }
    }
    pad = width - n - neg - ((flags & 8) && !neg ? 1 : 0) -
          ((flags & 16) && !neg && !(flags & 8) ? 1 : 0);
    if (pad < 0) pad = 0;
    if (!(flags & 1) && !(flags & 2))
        for (i = 0; i < pad; i++) __ml_emit(o, ' ');
    if (neg) __ml_emit(o, '-');
    else if (flags & 8) __ml_emit(o, '+');
    else if (flags & 16) __ml_emit(o, ' ');
    if (!(flags & 1) && (flags & 2))
        for (i = 0; i < pad; i++) __ml_emit(o, '0');
    for (i = n - 1; i >= 0; i--) __ml_emit(o, tmp[i]);
    if (flags & 1)
        for (i = 0; i < pad; i++) __ml_emit(o, ' ');
    return o->len;
}

/* ---- floating point output (%f %e %g %a) ----
 * Digits come from the normalized mantissa (repeated x10+floor),
 * ~1ulp per step; one extra digit + sticky implements round-half-even.
 * flags: 1 left, 2 zero, 4 alt, 8 sign-always, 16 space. */

static void ml_fp_digits(double m, char *dig, int ndig, int *extra,
                         int *sticky) {
    int i;
    for (i = 0; i < ndig; i++) {
        int d = (int)m;
        if (d < 0) d = 0;
        if (d > 9) d = 9;
        dig[i] = (char)('0' + d);
        m = (m - d) * 10.0;
    }
    {
        int d = (int)m;
        if (d < 0) d = 0;
        if (d > 9) d = 9;
        *extra = d;
        *sticky = (m - d) > 0.0;
    }
}

/* Round dig[0,ndig) using extra+sticky (half-even). Carry may produce
 * a leading '10...'; returns 1 then (caller shifts, bumps exponent). */
static int ml_fp_round(char *dig, int ndig, int extra, int sticky) {
    int i;
    if (extra < 5 || (extra == 5 && !sticky && ((dig[ndig - 1] - '0') % 2 == 0)))
        return 0;
    if (extra > 5 || sticky || ((dig[ndig - 1] - '0') % 2 == 1)) {
        for (i = ndig - 1; i >= 0; i--) {
            if (dig[i] != '9') {
                dig[i]++;
                return 0;
            }
            dig[i] = '0';
        }
        return 1;
    }
    return 0;
}

static void ml_fp_pad_emit(__ML_OUT *o, const char *sign, const char *body,
                           size_t bodylen, int width, int flags,
                           int zero_ok) {
    int slen = sign && *sign ? 1 : 0;
    int pad = width - slen - (int)bodylen;
    int i;
    if (pad < 0) pad = 0;
    if (!(flags & 1) && !(flags & 2)) {
        for (i = 0; i < pad; i++) __ml_emit(o, ' ');
    }
    if (slen) __ml_emit(o, *sign);
    if (!(flags & 1) && (flags & 2) && zero_ok) {
        for (i = 0; i < pad; i++) __ml_emit(o, '0');
    }
    __ml_emitn(o, body, bodylen);
    if (flags & 1) {
        for (i = 0; i < pad; i++) __ml_emit(o, ' ');
    }
}

/* Scientific body: d.dddde±XX (ndig fractional digits). */
static void ml_fp_scientific(__ML_OUT *o, double v, int ndig, int width,
                             int flags, int upper, long exp10) {
    char body[400];
    size_t bl = 0;
    int i, extra, sticky, neg = signbit(v) ? 1 : 0;
    char signch = 0;
    double m;
    if (neg) {
        signch = '-';
        v = -v;
    } else if (flags & 8) {
        signch = '+';
    } else if (flags & 16) {
        signch = ' ';
    }
    /* Normalize m into [1,10). */
    m = v / pow(10.0, (double)exp10);
    if (m >= 10.0) {
        m /= 10.0;
        exp10++;
    } else if (m < 1.0 && m > 0.0) {
        m *= 10.0;
        exp10--;
    }
    {
        char dig[64];
        if (ndig > 60) ndig = 60;
        ml_fp_digits(m, dig, ndig + 1, &extra, &sticky);
        if (ml_fp_round(dig, ndig + 1, extra, sticky)) {
            /* 9.99.. rounded to 10.0: shift. */
            exp10++;
            dig[0] = '1';
            for (i = 1; i <= ndig; i++) dig[i] = '0';
        }
        body[bl++] = dig[0];
        if (ndig > 0 || (flags & 4)) body[bl++] = '.';
        for (i = 1; i <= ndig; i++) body[bl++] = dig[i];
    }
    body[bl++] = upper ? 'E' : 'e';
    {
        char eb[32];
        int el = 0;
        long e = exp10;
        char esign = '+';
        if (e < 0) {
            esign = '-';
            e = -e;
        }
        do {
            eb[el++] = (char)('0' + e % 10);
            e /= 10;
        } while (e > 0);
        body[bl++] = esign;
        while (el < 2) {
            body[bl++] = '0';
            el++;
        }
        while (el > 0) body[bl++] = eb[--el];
    }
    {
        char sign[2] = {signch, '\0'};
        ml_fp_pad_emit(o, signch ? sign : 0, body, bl, width, flags, 1);
    }
}

static void ml_fp_format(__ML_OUT *o, double v, int spec, int width,
                         int prec, int flags) {
    int upper = (spec == 'F' || spec == 'E' || spec == 'G' || spec == 'A');
    int neg = signbit(v) ? 1 : 0;
    char sign[2] = {0, '\0'};
    if (isnan(v)) {
        const char *t = upper ? "NAN" : "nan";
        if (neg) sign[0] = '-';
        else if (flags & 8) sign[0] = '+';
        else if (flags & 16) sign[0] = ' ';
        ml_fp_pad_emit(o, sign[0] ? sign : 0, t, 3, width, flags, 0);
        return;
    }
    if (isinf(v)) {
        const char *t = upper ? "INF" : "inf";
        if (neg) sign[0] = '-';
        else if (flags & 8) sign[0] = '+';
        else if (flags & 16) sign[0] = ' ';
        ml_fp_pad_emit(o, sign[0] ? sign : 0, t, 3, width, flags, 0);
        return;
    }
    if (spec == 'a' || spec == 'A') {
        /* Hex float: 0xh.hhhhp±d (exact with default precision). */
        char body[64];
        size_t bl = 0;
        int e = 0, i, ndig = prec >= 0 ? prec : 13;
        double m;
        const char *dig = upper ? "0123456789ABCDEF"
                                : "0123456789abcdef";
        if (neg) {
            sign[0] = '-';
            v = -v;
        } else if (flags & 8) {
            sign[0] = '+';
        } else if (flags & 16) {
            sign[0] = ' ';
        }
        if (v == 0.0) {
            body[bl++] = '0';
            body[bl++] = 'x';
            body[bl++] = '0';
            if (ndig > 0 || (flags & 4)) {
                body[bl++] = '.';
                for (i = 0; i < ndig && bl < sizeof(body) - 8; i++)
                    body[bl++] = '0';
            }
            body[bl++] = upper ? 'P' : 'p';
            body[bl++] = '+';
            body[bl++] = '0';
        } else {
            m = frexp(v, &e);
            m *= 2.0;
            e -= 1; /* m in [1,2) */
            if (ndig > 40) ndig = 40;
            body[bl++] = '0';
            body[bl++] = 'x';
            body[bl++] = dig[(int)m];
            m -= (int)m;
            if (ndig > 0 || (flags & 4)) {
                body[bl++] = '.';
                for (i = 0; i < ndig && bl < sizeof(body) - 8; i++) {
                    m *= 16.0;
                    body[bl++] = dig[(int)m];
                    m -= (int)m;
                }
            }
            body[bl++] = upper ? 'P' : 'p';
            if (e < 0) {
                body[bl++] = '-';
                e = -e;
            } else {
                body[bl++] = '+';
            }
            {
                char eb[32];
                int el = 0;
                do {
                    eb[el++] = (char)('0' + e % 10);
                    e /= 10;
                } while (e > 0);
                while (el--) body[bl++] = eb[el];
            }
        }
        ml_fp_pad_emit(o, sign[0] ? sign : 0, body, bl, width, flags, 0);
        return;
    }
    {
        double av = neg ? -v : v;
        long e10 = 0;
        if (neg) sign[0] = '-';
        else if (flags & 8) sign[0] = '+';
        else if (flags & 16) sign[0] = ' ';
        if (av != 0.0) e10 = (long)floor(log10(av));
        if (spec == 'f' || spec == 'F') {
            int p = prec >= 0 ? prec : 6, i;
            /* Digits: (e10+1) int + p frac (plus one extra). */
            long nint = e10 + 1;
            char dig[420];
            int ndig, extra, sticky;
            char body[440];
            size_t bl = 0;
            if (nint < 0) nint = 0;
            ndig = (int)(nint + p + 1);
            if (ndig < 1) ndig = 1;
            if (ndig > 400) ndig = 400;
            {
                double m = av / pow(10.0, (double)e10);
                if (e10 < -310) m = 0.0; /* underflow: all zeros */
                ml_fp_digits(m, dig, ndig, &extra, &sticky);
                if (ml_fp_round(dig, ndig, extra, sticky)) {
                    /* 9.99.. -> 10.0: exponent grows. */
                    e10++;
                    nint++;
                    dig[0] = '1';
                    for (i = 1; i < ndig; i++) dig[i] = '0';
                }
            }
            if (nint == 0) {
                body[bl++] = '0';
            } else {
                for (i = 0; i < nint && i < ndig; i++)
                    body[bl++] = dig[i];
                for (; i < nint; i++) body[bl++] = '0';
            }
            if (p > 0 || (flags & 4)) body[bl++] = '.';
            for (i = 0; i < p; i++) {
                long idx = nint + i;
                body[bl++] = (idx >= 0 && idx < ndig) ? dig[idx] : '0';
            }
            ml_fp_pad_emit(o, sign[0] ? sign : 0, body, bl, width,
                           flags, 1);
            return;
        }
        if (spec == 'e' || spec == 'E') {
            int p = prec >= 0 ? prec : 6;
            ml_fp_scientific(o, v, p, width, flags, upper, e10);
            return;
        }
        /* %g/%G: significant digits, %e iff exp < -4 or >= prec. */
        {
            int p = prec > 0 ? prec : (prec == 0 ? 1 : 6);
            char dig[64];
            int extra, sticky, i, use_e;
            long xs = e10;
            double m = av == 0.0 ? 0.0 : av / pow(10.0, (double)e10);
            use_e = (xs < -4 || xs >= p);
            if (av == 0.0) {
                /* Zeros: %g prints "0". */
                char body[64];
                size_t bl = 0;
                body[bl++] = '0';
                if (flags & 4) {
                    body[bl++] = '.';
                    for (i = 1; i < p && bl < sizeof(body); i++)
                        body[bl++] = '0';
                }
                ml_fp_pad_emit(o, sign[0] ? sign : 0, body, bl, width,
                               flags, 1);
                return;
            }
            ml_fp_digits(m, dig, p + 1, &extra, &sticky);
            if (ml_fp_round(dig, p + 1, extra, sticky)) {
                xs++;
                dig[0] = '1';
                for (i = 1; i <= p; i++) dig[i] = '0';
                use_e = (xs < -4 || xs >= p);
            }
            if (use_e) {
                /* Compact scientific form below (zeros stripped);
                 * nothing to emit here yet. */
            }
            /* Compact decimal or scientific form, zeros stripped. */
            {
                char body[128];
                size_t bl = 0;
                if (use_e) {
                    int dec = p - 1;
                    body[bl++] = dig[0];
                    /* Strip. */
                    while (dec > 0 && dig[dec] == '0') dec--;
                    if (dec > 0 || (flags & 4)) {
                        body[bl++] = '.';
                        for (i = 1; i <= dec; i++) body[bl++] = dig[i];
                        if ((flags & 4))
                            for (; i < p; i++) body[bl++] = '0';
                    }
                    body[bl++] = upper ? 'E' : 'e';
                    {
                        char eb[32];
                        int el = 0;
                        long ex = xs < 0 ? -xs : xs;
                        body[bl++] = xs < 0 ? '-' : '+';
                        do {
                            eb[el++] = (char)('0' + ex % 10);
                            ex /= 10;
                        } while (ex > 0);
                        while (el < 2) {
                            body[bl++] = '0';
                            el++;
                        }
                        while (el > 0) body[bl++] = eb[--el];
                    }
                } else {
                    /* Fixed with point after xs+1 digits. */
                    char all[80];
                    int k;
                    for (k = 0; k < p; k++) all[k] = dig[k];
                    if (xs >= 0) {
                        for (k = 0; k <= xs && k < p; k++)
                            body[bl++] = all[k];
                        for (; k <= xs; k++) body[bl++] = '0';
                        {
                            int fstart = (int)(xs + 1), fend = p;
                            while (fend > fstart &&
                                   all[fend - 1] == '0' &&
                                   !(flags & 4))
                                fend--;
                            if (fend > fstart || (flags & 4)) {
                                body[bl++] = '.';
                                for (k = fstart; k < fend; k++)
                                    body[bl++] = all[k];
                                if (flags & 4)
                                    for (; k < p; k++)
                                        body[bl++] = '0';
                            }
                        }
                    } else {
                        body[bl++] = '0';
                        body[bl++] = '.';
                        for (k = 0; k < -xs - 1; k++) body[bl++] = '0';
                        {
                            int fend = p;
                            while (fend > 0 && all[fend - 1] == '0' &&
                                   !(flags & 4))
                                fend--;
                            for (k = 0; k < fend; k++)
                                body[bl++] = all[k];
                            if (flags & 4)
                                for (; k < p; k++) body[bl++] = '0';
                            if (fend == 0 && !(flags & 4)) {
                                /* "0." with nothing: drop the point. */
                                bl -= 1;
                            }
                        }
                    }
                }
                ml_fp_pad_emit(o, sign[0] ? sign : 0, body, bl, width,
                               flags, 1);
                return;
            }
        }
    }
}

int vsnprintf(char *s, size_t n, const char *fmt, va_list ap) {
    __ML_OUT o = {s, n, 0};
    if (n > 0) s[0] = '\0';
    if (!fmt) return -1;
    while (*fmt) {
        if (*fmt != '%') {
            __ml_emit(&o, *fmt++);
            continue;
        }
        fmt++;
        {
            int flags = 0, width = 0, prec = -1, len = 0; /* len:0 none 1 l 2 ll/z */
            int done = 0;
            while (!done) {
                if (*fmt == '-') {
                    flags |= 1;
                    fmt++;
                } else if (*fmt == '0') {
                    flags |= 2;
                    fmt++;
                } else if (*fmt == '+') {
                    flags |= 8;
                    fmt++;
                } else if (*fmt == ' ') {
                    flags |= 16;
                    fmt++;
                } else if (*fmt == '#') {
                    flags |= 4;
                    fmt++;
                } else {
                    done = 1;
                }
            }
            if (*fmt == '*') {
                width = va_arg(ap, int);
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9')
                    width = width * 10 + (*fmt++ - '0');
            }
            if (*fmt == '.') {
                fmt++;
                prec = 0;
                if (*fmt == '*') {
                    prec = va_arg(ap, int);
                    fmt++;
                } else {
                    while (*fmt >= '0' && *fmt <= '9')
                        prec = prec * 10 + (*fmt++ - '0');
                }
            }
            if (*fmt == 'l') {
                fmt++;
                len = 1;
                if (*fmt == 'l') {
                    fmt++;
                    len = 2;
                }
            } else if (*fmt == 'z' || *fmt == 't') {
                fmt++;
                len = 2;
            } else if (*fmt == 'h') {
                fmt++; /* promoted anyway */
                if (*fmt == 'h') fmt++;
            }
            switch (*fmt) {
            case 'd':
            case 'i': {
                long long v = (len == 2) ? va_arg(ap, long long)
                              : (len == 1) ? va_arg(ap, long)
                                           : va_arg(ap, int);
                __ml_num(&o, (unsigned long long)v, 10, "0123456789",
                         width, prec, flags | 32);
                break;
            }
            case 'u': {
                unsigned long long v =
                    (len == 2)   ? va_arg(ap, unsigned long long)
                    : (len == 1) ? va_arg(ap, unsigned long)
                                 : va_arg(ap, unsigned);
                __ml_num(&o, v, 10, "0123456789", width, prec, flags);
                break;
            }
            case 'x':
            case 'X': {
                unsigned long long v =
                    (len == 2)   ? va_arg(ap, unsigned long long)
                    : (len == 1) ? va_arg(ap, unsigned long)
                                 : va_arg(ap, unsigned);
                __ml_num(&o, v, 16,
                         *fmt == 'x' ? "0123456789abcdef"
                                     : "0123456789ABCDEF",
                         width, prec, flags);
                break;
            }
            case 'o': {
                unsigned long long v =
                    (len == 2)   ? va_arg(ap, unsigned long long)
                    : (len == 1) ? va_arg(ap, unsigned long)
                                 : va_arg(ap, unsigned);
                __ml_num(&o, v, 8, "0123456789", width, prec, flags);
                break;
            }
            case 'p': {
                void *v = va_arg(ap, void *);
                __ml_emitn(&o, "0x", 2);
                __ml_num(&o, (unsigned long)v, 16, "0123456789abcdef", 0,
                         -1, 0);
                break;
            }
            case 'c': {
                int i;
                if (len == 1) {
                    /* %lc: wide char -> UTF-8, width-padded. */
                    wint_t wc = va_arg(ap, wint_t);
                    char mb[MB_LEN_MAX];
                    mbstate_t st;
                    size_t r;
                    memset(&st, 0, sizeof(st));
                    r = wcrtomb(mb, (wchar_t)wc, &st);
                    if (r == (size_t)-1) {
                        mb[0] = '?';
                        r = 1;
                    }
                    if (!(flags & 1))
                        for (i = (int)r; i < width; i++)
                            __ml_emit(&o, ' ');
                    __ml_emitn(&o, mb, r);
                    if (flags & 1)
                        for (i = (int)r; i < width; i++)
                            __ml_emit(&o, ' ');
                    break;
                }
                {
                    int c = va_arg(ap, int);
                    if (!(flags & 1))
                        for (i = 1; i < width; i++) __ml_emit(&o, ' ');
                    __ml_emit(&o, (char)c);
                    if (flags & 1)
                        for (i = 1; i < width; i++) __ml_emit(&o, ' ');
                }
                break;
            }
            case 's': {
                if (len == 1) {
                    /* %ls: wide string -> UTF-8. Width counts wide
                     * chars (minimum), precision caps output BYTES
                     * without splitting a char (documented). */
                    const wchar_t *wstr = va_arg(ap, const wchar_t *);
                    size_t wlen = 0, blen = 0, wi;
                    int i, pad;
                    mbstate_t st;
                    char *mb;
                    if (!wstr) wstr = L"(null)";
                    memset(&st, 0, sizeof(st));
                    while (wstr[wlen]) wlen++;
                    mb = malloc(wlen * MB_LEN_MAX + 1);
                    if (mb) {
                        for (wi = 0; wi < wlen; wi++) {
                            char tmp[MB_LEN_MAX];
                            size_t r = wcrtomb(tmp, wstr[wi], &st);
                            size_t k;
                            if (r == (size_t)-1) {
                                tmp[0] = '?';
                                r = 1;
                                memset(&st, 0, sizeof(st));
                            }
                            if (prec >= 0 && blen + r > (size_t)prec)
                                break;
                            for (k = 0; k < r; k++) mb[blen++] = tmp[k];
                        }
                        pad = width - (int)(wi < wlen ? wi : wlen);
                        if (pad < 0) pad = 0;
                        if (!(flags & 1))
                            for (i = 0; i < pad; i++) __ml_emit(&o, ' ');
                        __ml_emitn(&o, mb, blen);
                        if (flags & 1)
                            for (i = 0; i < pad; i++) __ml_emit(&o, ' ');
                        free(mb);
                    }
                    break;
                }
                {
                    const char *str = va_arg(ap, const char *);
                    size_t sl, i;
                    int pad;
                    if (!str) str = "(null)";
                    sl = strlen(str);
                    if (prec >= 0 && (size_t)prec < sl) sl = (size_t)prec;
                    pad = width - (int)sl;
                    if (pad < 0) pad = 0;
                    if (!(flags & 1))
                        for (i = 0; i < (size_t)pad; i++)
                            __ml_emit(&o, ' ');
                    __ml_emitn(&o, str, sl);
                    if (flags & 1)
                        for (i = 0; i < (size_t)pad; i++)
                            __ml_emit(&o, ' ');
                }
                break;
            }
            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A': {
                double v = va_arg(ap, double);
                ml_fp_format(&o, v, *fmt, width, prec, flags);
                break;
            }
            case 'm': {
                /* glibc: current errno string. */
                const char *str = strerror(errno);
                size_t sl;
                int pad, i;
                if (!str) str = "";
                sl = strlen(str);
                if (prec >= 0 && (size_t)prec < sl) sl = (size_t)prec;
                pad = width - (int)sl;
                if (pad < 0) pad = 0;
                if (!(flags & 1))
                    for (i = 0; i < pad; i++) __ml_emit(&o, ' ');
                __ml_emitn(&o, str, sl);
                if (flags & 1)
                    for (i = 0; i < pad; i++) __ml_emit(&o, ' ');
                break;
            }
            case 'n': {
                /* Store the count so far (never fails). */
                if (len == 2) *va_arg(ap, long long *) = (long long)o.len;
                else if (len == 1) *va_arg(ap, long *) = (long)o.len;
                else if (*fmt == 'n') {
                    /* bare %n: int (length modifiers h/hh/ etc. use
                     * the matching width below). */
                    *va_arg(ap, int *) = (int)o.len;
                }
                break;
            }
            case 'C':
            case 'S': {
                /* %C = %lc, %S = %ls (glibc compatibility). */
                if (*fmt == 'C') {
                    wint_t wc = va_arg(ap, wint_t);
                    char mb[MB_LEN_MAX];
                    mbstate_t st;
                    size_t r;
                    int k;
                    memset(&st, 0, sizeof(st));
                    r = wcrtomb(mb, (wchar_t)wc, &st);
                    if (r == (size_t)-1) {
                        mb[0] = '?';
                        r = 1;
                    }
                    if (!(flags & 1))
                        for (k = (int)r; k < width; k++)
                            __ml_emit(&o, ' ');
                    __ml_emitn(&o, mb, r);
                    if (flags & 1)
                        for (k = (int)r; k < width; k++)
                            __ml_emit(&o, ' ');
                } else {
                    const wchar_t *wstr = va_arg(ap, const wchar_t *);
                    size_t wlen = 0, blen = 0, wi;
                    int k, pad;
                    mbstate_t st;
                    char *mb;
                    if (!wstr) wstr = L"(null)";
                    memset(&st, 0, sizeof(st));
                    while (wstr[wlen]) wlen++;
                    mb = malloc(wlen * MB_LEN_MAX + 1);
                    if (mb) {
                        for (wi = 0; wi < wlen; wi++) {
                            char tmp[MB_LEN_MAX];
                            size_t r = wcrtomb(tmp, wstr[wi], &st);
                            size_t t;
                            if (r == (size_t)-1) {
                                tmp[0] = '?';
                                r = 1;
                                memset(&st, 0, sizeof(st));
                            }
                            if (prec >= 0 && blen + r > (size_t)prec)
                                break;
                            for (t = 0; t < r; t++) mb[blen++] = tmp[t];
                        }
                        pad = width - (int)(wi < wlen ? wi : wlen);
                        if (pad < 0) pad = 0;
                        if (!(flags & 1))
                            for (k = 0; k < pad; k++)
                                __ml_emit(&o, ' ');
                        __ml_emitn(&o, mb, blen);
                        if (flags & 1)
                            for (k = 0; k < pad; k++)
                                __ml_emit(&o, ' ');
                        free(mb);
                    }
                }
                break;
            }
            case '%':
                __ml_emit(&o, '%');
                break;
            default:
                /* Unknown specifier: echo literally (never drop input). */
                __ml_emit(&o, '%');
                if (*fmt) __ml_emit(&o, *fmt);
                break;
            }
            if (*fmt) fmt++;
        }
    }
    if (o.cap > 0) o.buf[o.len < o.cap ? o.len : o.cap - 1] = '\0';
    if (o.len > (size_t)0x7fffffff) return -1;
    return (int)o.len;
}

int snprintf(char *s, size_t n, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vsnprintf(s, n, fmt, ap);
    va_end(ap);
    return r;
}

int sprintf(char *s, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    /* vsnprintf has no bound here, like the standard sprintf: the
     * caller must size the buffer (documented). */
    r = vsnprintf(s, (size_t)-1, fmt, ap);
    va_end(ap);
    return r;
}

int vasprintf(char **sp, const char *fmt, va_list ap) {
    va_list aq;
    int n;
    char *p;
    if (!sp) return -1;
    *sp = 0;
    va_copy(aq, ap);
    n = vsnprintf(0, 0, fmt, aq);
    va_end(aq);
    if (n < 0) return -1;
    p = malloc((size_t)n + 1);
    if (!p) return -1;
    if (vsnprintf(p, (size_t)n + 1, fmt, ap) < 0) {
        free(p);
        return -1;
    }
    *sp = p;
    return n;
}

int asprintf(char **sp, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vasprintf(sp, fmt, ap);
    va_end(ap);
    return r;
}

int vdprintf(int fd, const char *fmt, va_list ap) {
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    long off = 0;
    if (n < 0) return n;
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    while (off < n) {
        long w = write(fd, buf + off, (size_t)(n - off));
        if (w <= 0) return -1;
        off += w;
    }
    return n;
}

int dprintf(int fd, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vdprintf(fd, fmt, ap);
    va_end(ap);
    return r;
}

/* ---- print to fds ---- */

static FILE __ml_stdin = {0, 0, 0};
static FILE __ml_stdout = {1, 0, 0};
static FILE __ml_stderr = {2, 0, 0};
FILE *__stdin_ptr = &__ml_stdin;
FILE *__stdout_ptr = &__ml_stdout;
FILE *__stderr_ptr = &__ml_stderr;

/* Forward: memory-stream byte sink (defined below with the memstreams). */
static int ml_mem_putc(int c, FILE *f);
static void ml_wbuf_publish(FILE *f);

int vprintf(const char *fmt, va_list ap) {
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    long off = 0;
    if (n < 0) return n;
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    while (off < n) {
        long w = write(1, buf + off, (size_t)(n - off));
        if (w <= 0) return -1;
        off += w;
    }
    return n;
}

int printf(const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vprintf(fmt, ap);
    va_end(ap);
    return r;
}

int vfprintf(FILE *f, const char *fmt, va_list ap) {
    char *out = 0;
    int n, wrote;
    if (!f || !fmt) return -1;
    n = vasprintf(&out, fmt, ap);
    if (n < 0) return -1;
    wrote = (int)fwrite(out, 1, (size_t)n, f);
    free(out);
    if (wrote != n) {
        f->err = 1;
        return -1;
    }
    return n;
}

int fprintf(FILE *f, const char *fmt, ...) {
    va_list ap;
    int n;
    if (!f) return -1;
    va_start(ap, fmt);
    n = vfprintf(f, fmt, ap);
    va_end(ap);
    return n;
}

int puts(const char *s) {
    size_t n = strlen(s);
    if (write(1, s, n) < 0) return EOF;
    if (write(1, "\n", 1) < 0) return EOF;
    return 0;
}

int putchar(int c) {
    char ch = (char)c;
    return write(1, &ch, 1) == 1 ? c : EOF;
}

int fputs(const char *s, FILE *f) {
    size_t n;
    if (!f) return EOF;
    n = strlen(s);
    return write(f->fd, s, n) < 0 ? EOF : 0;
}

int fputc(int c, FILE *f) {
    char ch = (char)c;
    if (!f) return EOF;
    if (f->kind != 0) return ml_mem_putc(c, f);
    if (write(f->fd, &ch, 1) != 1) {
        f->err = 1;
        return EOF;
    }
    return c;
}

int putc(int c, FILE *f) { return fputc(c, f); }

/* ---- memory streams (fmemopen / open_memstream) ---- */

static int ml_mem_getc(FILE *f) {
    if (f->mempos >= f->memlen) {
        f->eof = 1;
        return EOF;
    }
    return (unsigned char)f->membuf[f->mempos++];
}

static void ml_mem_sync(FILE *f) {
    /* Keep the C-string view current: memstreams always have room for
     * the NUL (cap + 1 allocated); fmemopen terminates when it fits. */
    if (f->kind == 2) {
        f->membuf[f->memlen] = '\0';
        if (f->pmem) *f->pmem = f->membuf;
        if (f->pmemlen) *f->pmemlen = f->memlen;
    } else {
        if (f->memlen < f->memcap) f->membuf[f->memlen] = '\0';
    }
    if (f->kind == 4) ml_wbuf_publish(f);
}

/* ---- wide memstream view (kind 4): the byte layer above always
 * holds the exact UTF-8 encoding of wbuf[0..wlen]. Narrow appends of
 * ASCII bytes extend both views in O(1); anything else (overwrites,
 * gaps, high bytes, seeks + wide writes) re-decodes (resync). Wide
 * reads decode the byte layer, so positions stay single-sourced. */

static int ml_wbuf_grow(FILE *f, size_t need) {
    size_t nc;
    wchar_t *nb;
    if (need <= f->wcap) return 0;
    nc = f->wcap ? f->wcap * 2 : 32;
    if (nc < need) nc = need;
    nb = realloc(f->wbuf, (nc + 1) * sizeof(wchar_t));
    if (!nb) {
        f->err = 1;
        return -1;
    }
    f->wbuf = nb;
    f->wcap = nc;
    if (f->pwmem) *f->pwmem = nb;
    return 0;
}

static void ml_wbuf_publish(FILE *f) {
    f->wbuf[f->wlen] = 0;
    if (f->pwmem) *f->pwmem = f->wbuf;
    if (f->pwmemlen) *f->pwmemlen = f->wlen;
}

/* Re-decode the whole byte layer into the wide view (stray bytes and
 * truncated tails become U+FFFD; the byte layer itself is untouched). */
static void ml_wbuf_resync(FILE *f) {
    mbstate_t st;
    size_t i = 0, w = 0;
    if (ml_wbuf_grow(f, f->memlen + 1) != 0) return;
    memset(&st, 0, sizeof(st));
    while (i < f->memlen) {
        wchar_t wc = 0;
        size_t r = mbrtowc(&wc, f->membuf + i, f->memlen - i, &st);
        if (r == (size_t)-1) {
            memset(&st, 0, sizeof(st));
            f->wbuf[w++] = 0xFFFD;
            i++;
        } else if (r == (size_t)-2) {
            memset(&st, 0, sizeof(st));
            while (i < f->memlen) f->wbuf[w++] = 0xFFFD, i++;
        } else if (r == 0) {
            f->wbuf[w++] = 0;
            i++;
        } else {
            f->wbuf[w++] = wc;
            i += r;
        }
    }
    f->wlen = w;
    ml_wbuf_publish(f);
}

static int ml_mem_putc(int c, FILE *f) {
    size_t pos = f->mempos;
    size_t oldlen = f->memlen;
    int growable = (f->kind == 2 || f->kind == 4);
    if (pos > f->memcap) return EOF;
    if (pos == f->memcap) {
        if (!growable) {
            f->err = 1; /* caller buffer full */
            return EOF;
        }
        {
            size_t nc = f->memcap ? f->memcap * 2 : 128;
            char *nb = realloc(f->membuf, nc + 1);
            if (!nb) {
                f->err = 1;
                return EOF;
            }
            f->membuf = nb;
            f->memcap = nc;
            if (f->pmem) *f->pmem = nb;
        }
    }
    if (pos > f->memlen) {
        /* Sparse write past the end: zero-fill the gap (matches the
         * VFS hole semantics in docs/LINUX.md). */
        size_t gap = pos - f->memlen;
        if (pos >= f->memcap && !growable) {
            f->err = 1;
            return EOF;
        }
        if (growable && pos > f->memcap) {
            size_t nc = pos;
            char *nb = realloc(f->membuf, nc + 1);
            if (!nb) {
                f->err = 1;
                return EOF;
            }
            f->membuf = nb;
            f->memcap = nc;
            if (f->pmem) *f->pmem = nb;
        }
        memset(f->membuf + f->memlen, 0, gap);
    }
    f->membuf[pos] = (char)c;
    f->mempos = pos + 1;
    if (f->mempos > f->memlen) f->memlen = f->mempos;
    f->eof = 0;
    ml_mem_sync(f);
    if (f->kind == 4) {
        /* Keep the wide view in lockstep: pure ASCII appends are O(1);
         * overwrites, gaps and high bytes re-decode (rare paths). */
        if (pos == oldlen && ((c & 0x80) == 0)) {
            if (ml_wbuf_grow(f, f->wlen + 1) == 0) {
                f->wbuf[f->wlen++] = (wchar_t)(unsigned char)c;
                ml_wbuf_publish(f);
            }
        } else {
            ml_wbuf_resync(f);
        }
    }
    return c;
}

static size_t ml_mem_read(FILE *f, char *buf, size_t want) {
    size_t avail = f->memlen > f->mempos ? f->memlen - f->mempos : 0;
    size_t n = want < avail ? want : avail;
    if (n == 0) {
        f->eof = 1;
        return 0;
    }
    memcpy(buf, f->membuf + f->mempos, n);
    f->mempos += n;
    return n;
}

static size_t ml_mem_write(FILE *f, const char *buf, size_t want) {
    size_t i;
    for (i = 0; i < want; i++)
        if (ml_mem_putc((unsigned char)buf[i], f) == EOF) break;
    return i;
}

static int ml_mem_seek(FILE *f, long off, int whence, long *newpos) {
    long base, n;
    if (whence == SEEK_SET) base = 0;
    else if (whence == SEEK_CUR) base = (long)f->mempos;
    else if (whence == SEEK_END) base = (long)f->memlen;
    else return -1;
    n = base + off;
    /* Seeking past the end is allowed (holes read as zero once
     * written); past a fixed caller buffer is not. Seeking only moves
     * the cursor (both views stay valid; wide writes recompute their
     * position on demand). */
    if (n < 0 || (f->kind != 2 && f->kind != 4 && n > (long)f->memcap))
        return -1;
    f->mempos = (size_t)n;
    f->eof = 0;
    f->npb = 0;
    if (newpos) *newpos = n;
    return 0;
}

FILE *fmemopen(void *buf, size_t size, const char *mode) {
    FILE *f;
    int plus = 0;
    char m;
    if (!buf || size == 0 || !mode) return 0;
    m = mode[0];
    if (m != 'r' && m != 'w' && m != 'a') return 0;
    if (mode[1] == '+') plus = 1;
    else if (mode[1] != '\0') return 0;
    (void)plus; /* reads are bounded by memlen either way here */
    f = malloc(sizeof(FILE));
    if (!f) return 0;
    memset(f, 0, sizeof(*f));
    f->kind = 1;
    f->membuf = buf;
    f->memcap = size;
    if (m == 'r') {
        f->memlen = size;
        f->mempos = 0;
    } else if (m == 'w') {
        f->memlen = 0;
        f->mempos = 0;
        if (size > 0) ((char *)buf)[0] = '\0';
    } else {
        f->memlen = size;
        f->mempos = size;
    }
    return f;
}

FILE *open_memstream(char **ptr, size_t *len) {
    FILE *f;
    char *b;
    if (!ptr || !len) return 0;
    b = malloc(128 + 1);
    if (!b) return 0;
    f = malloc(sizeof(FILE));
    if (!f) {
        free(b);
        return 0;
    }
    memset(f, 0, sizeof(*f));
    f->kind = 2;
    f->membuf = b;
    f->memcap = 128;
    f->memlen = 0;
    f->mempos = 0;
    f->memowned = 1;
    f->pmem = ptr;
    f->pmemlen = len;
    b[0] = '\0';
    *ptr = b;
    *len = 0;
    return f;
}

FILE *__ml_wmemstream_create(wchar_t **ptr, size_t *len) {
    FILE *f;
    char *b;
    wchar_t *w;
    if (!ptr || !len) {
        errno = EINVAL;
        return 0;
    }
    b = malloc(128 + 1);
    w = malloc((32 + 1) * sizeof(wchar_t));
    f = malloc(sizeof(FILE));
    if (!b || !w || !f) {
        free(b);
        free(w);
        free(f);
        errno = ENOMEM;
        return 0;
    }
    memset(f, 0, sizeof(*f));
    f->kind = 4;
    f->orient = 1;
    f->membuf = b;
    f->memcap = 128;
    f->memlen = 0;
    f->mempos = 0;
    f->memowned = 1;
    f->wbuf = w;
    f->wcap = 32;
    f->wlen = 0;
    f->pwmem = ptr;
    f->pwmemlen = len;
    b[0] = '\0';
    w[0] = 0;
    *ptr = w;
    *len = 0;
    return f;
}

/* Grow the byte layer to hold at least `need` bytes (+ NUL room). */
static int ml_byte_grow(FILE *f, size_t need) {
    size_t nc;
    char *nb;
    if (need <= f->memcap) return 0;
    nc = f->memcap ? f->memcap * 2 : 128;
    if (nc < need) nc = need;
    nb = realloc(f->membuf, nc + 1);
    if (!nb) {
        f->err = 1;
        return -1;
    }
    f->membuf = nb;
    f->memcap = nc;
    return 0;
}

int __ml_wputc(FILE *f, wchar_t c) {
    char mb[4];
    mbstate_t st;
    size_t r, i;
    if (!f || f->kind != 4) {
        errno = EINVAL;
        return -1;
    }
    if (f->orient == 0) f->orient = 1;
    memset(&st, 0, sizeof(st));
    r = wcrtomb(mb, c, &st);
    if (r == (size_t)-1) {
        f->err = 1;
        return -1;
    }
    if (f->mempos == f->memlen) {
        /* Append fast path (the common case). */
        if (ml_byte_grow(f, f->memlen + r) != 0) return -1;
        if (ml_wbuf_grow(f, f->wlen + 1) != 0) return -1;
        for (i = 0; i < r; i++) f->membuf[f->memlen++] = mb[i];
        f->mempos = f->memlen;
        f->wbuf[f->wlen++] = c;
        f->eof = 0;
        ml_mem_sync(f);
        return (int)c;
    }
    /* Overwrite path: walk char boundaries in [0, mempos], rounding
     * mempos down when mid-sequence, then splice the new encoding
     * over the old one. The tail is preserved. Stray bytes (which the
     * wide view holds as U+FFFD) take the insert + re-decode fallback,
     * which is exact by construction. */
    {
        size_t boff = 0, wpos = 0;
        int bad = 0;
        size_t oldlen;
        char ob[4];
        mbstate_t s0;
        memset(&s0, 0, sizeof(s0));
        while (boff < f->mempos) {
            wchar_t wc = 0;
            mbstate_t s2;
            size_t q;
            memset(&s2, 0, sizeof(s2));
            q = mbrtowc(&wc, f->membuf + boff, f->memlen - boff, &s2);
            if (q == (size_t)-1 || q == (size_t)-2) {
                bad = 1;
                break;
            }
            if (q == 0) q = 1; /* embedded NUL: one byte, one char */
            if (boff + q > f->mempos) break;
            boff += q;
            wpos++;
            (void)wc;
        }
        f->mempos = boff;
        if (bad || wpos >= f->wlen) {
            if (ml_byte_grow(f, f->memlen + r) != 0) return -1;
            if (ml_wbuf_grow(f, f->wlen + 1) != 0) return -1;
            memmove(f->membuf + boff + r, f->membuf + boff,
                    f->memlen - boff);
            memcpy(f->membuf + boff, mb, r);
            f->memlen += r;
            f->mempos = boff + r;
            /* Wide view: re-decode (positions shifted). */
            ml_wbuf_resync(f);
            f->eof = 0;
            ml_mem_sync(f);
            return (int)c;
        }
        oldlen = wcrtomb(ob, f->wbuf[wpos], &s0);
        if (oldlen == (size_t)-1 || oldlen == 0) {
            /* Should not happen (views are kept in sync): re-decode
             * and retry as an insert. */
            ml_wbuf_resync(f);
            if (ml_byte_grow(f, f->memlen + r) != 0) return -1;
            memmove(f->membuf + boff + r, f->membuf + boff,
                    f->memlen - boff);
            memcpy(f->membuf + boff, mb, r);
            f->memlen += r;
            f->mempos = boff + r;
            ml_wbuf_resync(f);
            f->eof = 0;
            ml_mem_sync(f);
            return (int)c;
        }
        if (r > oldlen && ml_byte_grow(f, f->memlen + (r - oldlen)) != 0)
            return -1;
        if (r != oldlen)
            memmove(f->membuf + boff + r, f->membuf + boff + oldlen,
                    f->memlen - (boff + oldlen));
        memcpy(f->membuf + boff, mb, r);
        f->memlen += r - oldlen;
        f->mempos = boff + r;
        f->wbuf[wpos] = c;
        f->eof = 0;
        ml_mem_sync(f);
        return (int)c;
    }
}

/* ---- tmpfile/tmpnam/remove ---- */

int remove(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }
    return unlink(path);
}

static unsigned ml_tmp_seq = 0;

char *tmpnam(char *s) {
    /* Flat namespace: "mltmp.<pid>.<seq>" (fits NAME_MAX comfortably).
     * NULL asks for an internal rotating buffer (two slots). */
    static char ml_tmp_bufs[2][L_tmpnam];
    static int ml_tmp_which = 0;
    char *b = s ? s : ml_tmp_bufs[ml_tmp_which ^= 1];
    unsigned seq = ml_tmp_seq++ % TMP_MAX;
    snprintf(b, L_tmpnam, "mltmp.%d.%u", getpid(), seq);
    return b;
}

FILE *tmpfile(void) {
    char name[L_tmpnam];
    int fd;
    FILE *f;
    unsigned i;
    /* Unique create (open refuses duplicates without O_EXCL elsewhere,
     * so probe-then-create is safe enough single-hart). */
    for (i = 0; i < TMP_MAX; i++) {
        unsigned seq = ml_tmp_seq++ % TMP_MAX;
        snprintf(name, sizeof(name), "mltmp.%d.%u", getpid(), seq);
        fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) return 0;
    }
    if (i >= TMP_MAX) {
        errno = EEXIST;
        return 0;
    }
    f = malloc(sizeof(FILE));
    if (!f) {
        close(fd);
        unlink(name);
        return 0;
    }
    memset(f, 0, sizeof(*f));
    f->fd = fd;
    f->tmpname = strdup(name);
    if (!f->tmpname) {
        close(fd);
        unlink(name);
        free(f);
        return 0;
    }
    return f;
}

/* ---- FILE over fds ---- */

FILE *fopen(const char *path, const char *mode) {
    int flags = 0, fd;
    FILE *f;
    if (!path || !mode) return 0;
    if (mode[0] == 'r') {
        flags = (mode[1] == '+') ? O_RDWR : O_RDONLY;
    } else if (mode[0] == 'w') {
        flags = O_CREAT | O_TRUNC | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else if (mode[0] == 'a') {
        flags = O_CREAT | O_APPEND | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else {
        return 0;
    }
    fd = open(path, flags, 0666);
    if (fd < 0) return 0;
    f = malloc(sizeof(FILE));
    if (!f) {
        close(fd);
        return 0;
    }
    memset(f, 0, sizeof(FILE));
    f->fd = fd;
    f->eof = 0;
    f->err = 0;
    return f;
}

FILE *fdopen(int fd, const char *mode) {
    FILE *f;
    struct stat st;
    if (!mode || (mode[0] != 'r' && mode[0] != 'w' && mode[0] != 'a'))
        return 0;
    /* Validate the fd through the kernel (fstat fails EBADF). */
    if (fstat(fd, &st) != 0) return 0;
    f = malloc(sizeof(FILE));
    if (!f) return 0;
    memset(f, 0, sizeof(FILE));
    f->fd = fd;
    return f;
}

FILE *freopen(const char *path, const char *mode, FILE *f) {
    int flags = 0, fd;
    if (!f || f == &__ml_stdin || f == &__ml_stdout || f == &__ml_stderr)
        return 0;
    if (!path || !mode) return 0;
    if (mode[0] == 'r') {
        flags = (mode[1] == '+') ? O_RDWR : O_RDONLY;
    } else if (mode[0] == 'w') {
        flags = O_CREAT | O_TRUNC | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else if (mode[0] == 'a') {
        flags = O_CREAT | O_APPEND | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else {
        return 0;
    }
    if (f->kind != 0) {
        /* Memory streams cannot be re-attached: fail cleanly. */
        errno = EINVAL;
        return 0;
    }
    fd = open(path, flags, 0666);
    if (fd < 0) {
        /* C leaves the old stream open on failure: keep f as-is. */
        return 0;
    }
    close(f->fd);
    if (f->tmpname) {
        unlink(f->tmpname);
        free(f->tmpname);
        f->tmpname = 0;
    }
    memset(f, 0, sizeof(FILE));
    f->fd = fd;
    return f;
}

int setvbuf(FILE *f, char *buf, int mode, size_t n) {
    /* Unbuffered implementation: every op is already a direct syscall,
     * so any buffering request is trivially satisfied. Validate the
     * args (real checks, not ignored) and report success. */
    (void)buf;
    (void)n;
    if (!f) {
        errno = EINVAL;
        return -1;
    }
    if (mode != _IOFBF && mode != _IOLBF && mode != _IONBF) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

void setbuf(FILE *f, char *buf) {
    (void)setvbuf(f, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}

int rename(const char *oldp, const char *newp) {
    /* No kernel rename (flat VFS, §7): copy + unlink. Succeeds fully
     * or leaves the source untouched (destination may be partial on
     * ENOSPC/IO error, reported like a short write). */
    int sfd = -1, dfd = -1, rc = -1;
    char io[1024];
    ssize_t r;
    struct stat st;
    if (!oldp || !newp) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(oldp, newp) == 0) return 0;
    sfd = open(oldp, O_RDONLY);
    if (sfd < 0) return -1;
    if (fstat(sfd, &st) != 0) goto out;
    if ((st.st_mode & S_IFMT) != S_IFREG) {
        errno = EINVAL;
        goto out;
    }
    dfd = open(newp, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (dfd < 0) goto out;
    for (;;) {
        r = read(sfd, io, sizeof(io));
        if (r < 0) goto out;
        if (r == 0) break;
        {
            ssize_t w = 0;
            while (w < r) {
                ssize_t k = write(dfd, io + w, (size_t)(r - w));
                if (k <= 0) {
                    if (k < 0) goto out;
                    break;
                }
                w += k;
            }
        }
    }
    if (unlink(oldp) != 0) goto out;
    rc = 0;
out: {
    int e = errno;
    if (sfd >= 0) close(sfd);
    if (dfd >= 0) close(dfd);
    if (rc != 0) errno = e;
    return rc;
}
}

int fclose(FILE *f) {
    int r = 0;
    if (!f || f == &__ml_stdin || f == &__ml_stdout || f == &__ml_stderr)
        return EOF;
    if (f->kind == 2) {
        /* Finalize the stream, then hand the buffer to the caller. */
        ml_mem_sync(f);
        f->memowned = 0;
    } else if (f->kind == 4) {
        /* Publish the wide buffer to the caller (it owns wbuf after
         * this); the UTF-8 working copy is discarded. */
        ml_mem_sync(f);
        free(f->membuf);
        f->membuf = 0;
        f->memowned = 0;
    } else if (f->kind == 1) {
        ml_mem_sync(f);
    } else {
        r = close(f->fd);
    }
    if (f->tmpname) {
        unlink(f->tmpname);
        free(f->tmpname);
    }
    if (f->memowned) free(f->membuf);
    free(f);
    return r;
}

size_t fread(void *buf, size_t sz, size_t n, FILE *f) {
    size_t want, got = 0;
    ssize_t r;
    if (!f || sz == 0 || n == 0) return 0;
    if (sz > 0 && n > (size_t)-1 / sz) return 0;
    want = sz * n;
    /* Drain pushback first (vfscanf lookahead lives here). */
    while (got < want && f->npb > 0) {
        ((char *)buf)[got++] = f->pb[--f->npb];
    }
    if (f->kind != 0) {
        got += ml_mem_read(f, (char *)buf + got, want - got);
        if (got < want) f->eof = 1;
        return got / sz;
    }
    while (got < want) {
        r = read(f->fd, (char *)buf + got, want - got);
        if (r < 0) {
            f->err = 1;
            break;
        }
        if (r == 0) {
            f->eof = 1;
            break;
        }
        got += (size_t)r;
    }
    return got / sz;
}

size_t fwrite(const void *buf, size_t sz, size_t n, FILE *f) {
    size_t want, got = 0;
    ssize_t r;
    if (!f || sz == 0 || n == 0) return 0;
    if (sz > 0 && n > (size_t)-1 / sz) return 0;
    want = sz * n;
    if (f->kind != 0) return ml_mem_write(f, buf, want) / sz;
    while (got < want) {
        r = write(f->fd, (const char *)buf + got, want - got);
        if (r < 0) {
            f->err = 1;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    return got / sz;
}

int fseek(FILE *f, long off, int whence) {
    off_t r;
    if (!f) return -1;
    if (f->kind != 0) {
        long np = 0;
        return ml_mem_seek(f, off, whence, &np);
    }
    r = lseek(f->fd, off, whence);
    if (r < 0) return -1;
    f->eof = 0;
    f->npb = 0;
    return 0;
}

long ftell(FILE *f) {
    off_t r;
    if (!f) return -1;
    if (f->kind != 0) return (long)f->mempos;
    r = lseek(f->fd, 0, SEEK_CUR);
    return (long)r;
}

int fgetpos(FILE *f, fpos_t *pos) {
    long p;
    if (!f || !pos) return -1;
    p = ftell(f);
    if (p < 0) return -1;
    *pos = p;
    return 0;
}

int fsetpos(FILE *f, const fpos_t *pos) {
    if (!f || !pos) return -1;
    return fseek(f, *pos, SEEK_SET);
}

void rewind(FILE *f) {
    if (f) {
        if (f->kind != 0) {
            f->mempos = 0;
            f->eof = 0;
            f->err = 0;
            f->npb = 0;
        } else {
            lseek(f->fd, 0, SEEK_SET);
            f->eof = 0;
            f->err = 0;
            f->npb = 0;
        }
    }
}

int feof(FILE *f) { return f ? f->eof : 1; }

int ferror(FILE *f) { return f ? f->err : 1; }

void clearerr(FILE *f) {
    if (f) {
        f->eof = 0;
        f->err = 0;
        f->npb = 0;
    }
}

int fflush(FILE *f) {
    if (!f) return 0;
    /* Unbuffered fd streams: nothing to flush. Memory streams publish
     * the current pointer/length (open_memstream contract). */
    if (f->kind != 0) ml_mem_sync(f);
    return 0;
}

int fileno(FILE *f) {
    if (!f || f->kind != 0) {
        errno = EBADF;
        return -1;
    }
    return f->fd;
}

int getc(FILE *f) {
    unsigned char c;
    ssize_t r;
    if (!f) return EOF;
    if (f->npb > 0) return (unsigned char)f->pb[--f->npb];
    if (f->kind != 0) return ml_mem_getc(f);
    r = read(f->fd, &c, 1);
    if (r == 1) return c;
    if (r == 0) f->eof = 1;
    else f->err = 1;
    return EOF;
}

int fgetc(FILE *f) { return getc(f); }

int ungetc(int c, FILE *f) {
    if (c == EOF || !f || f->npb >= ML_PBN) return EOF;
    f->pb[f->npb++] = (char)c;
    f->eof = 0;
    return c;
}

int getchar(void) { return getc(stdin); }

char *fgets(char *s, int n, FILE *f) {
    int i = 0, c;
    if (!s || n <= 1 || !f) return 0;
    while (i < n - 1) {
        c = getc(f);
        if (c == EOF) break;
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    s[i] = '\0';
    return i > 0 ? s : 0;
}

ssize_t getdelim(char **line, size_t *n, int delim, FILE *f) {
    size_t pos = 0;
    int c;
    if (!line || !n || !f) {
        errno = EINVAL;
        return -1;
    }
    if (*line == 0 || *n == 0) {
        *n = 128;
        *line = malloc(*n);
        if (!*line) {
            *n = 0;
            errno = ENOMEM;
            return -1;
        }
    }
    for (;;) {
        c = getc(f);
        if (c == EOF) break;
        if (pos + 2 > *n) {
            size_t nn = *n * 2;
            char *nb = realloc(*line, nn);
            if (!nb) {
                errno = ENOMEM;
                return -1;
            }
            *line = nb;
            *n = nn;
        }
        (*line)[pos++] = (char)c;
        if (c == delim) break;
    }
    if (pos == 0) return -1; /* EOF before any char (errno untouched) */
    (*line)[pos] = '\0';
    return (ssize_t)pos;
}

ssize_t getline(char **line, size_t *n, FILE *f) {
    return getdelim(line, n, '\n', f);
}

/* ---- diagnostics (text for every errno.h code) ---- */

static const struct {
    int e;
    const char *m;
} ml_errtab[] = {
    {0, "ok"},
    {EPERM, "not permitted"},
    {ENOENT, "no such file"},
    {ESRCH, "no such process"},
    {EINTR, "interrupted"},
    {EIO, "i/o error"},
    {ENXIO, "no such device"},
    {E2BIG, "argument list too long"},
    {ENOEXEC, "exec format error"},
    {EBADF, "bad fd"},
    {ECHILD, "no child"},
    {EAGAIN, "try again"},
    {ENOMEM, "out of memory"},
    {EACCES, "denied"},
    {EFAULT, "bad address"},
    {ENOTBLK, "not a block device"},
    {EBUSY, "busy"},
    {EEXIST, "exists"},
    {EXDEV, "cross-device link"},
    {ENODEV, "no such device"},
    {ENOTDIR, "not a directory"},
    {EISDIR, "is a directory"},
    {EINVAL, "invalid"},
    {ENFILE, "too many open files"},
    {EMFILE, "too many fds"},
    {ENOTTY, "not a tty"},
    {ETXTBSY, "text file busy"},
    {EFBIG, "file too large"},
    {ENOSPC, "no space"},
    {ESPIPE, "illegal seek"},
    {EROFS, "read-only filesystem"},
    {EMLINK, "too many links"},
    {EPIPE, "broken pipe"},
    {EDOM, "domain error"},
    {ERANGE, "range"},
    {EDEADLK, "would deadlock"},
    {ENAMETOOLONG, "name too long"},
    {ENOLCK, "no locks available"},
    {ENOSYS, "not implemented"},
    {ENOTEMPTY, "not empty"},
    {ELOOP, "too many links"},
    {ENOMSG, "no message"},
    {EIDRM, "identifier removed"},
    {ECHRNG, "channel out of range"},
    {EL2NSYNC, "level 2 not synchronized"},
    {EL3HLT, "level 3 halted"},
    {EL3RST, "level 3 reset"},
    {ELNRNG, "link out of range"},
    {EUNATCH, "protocol driver not attached"},
    {ENOCSI, "no CSI structure"},
    {EL2HLT, "level 2 halted"},
    {EBADE, "invalid exchange"},
    {EBADR, "invalid request descriptor"},
    {EXFULL, "exchange full"},
    {ENOANO, "no anode"},
    {EBADRQC, "invalid request code"},
    {EBADSLT, "invalid slot"},
    {EBFONT, "bad font file"},
    {ENOSTR, "not a stream"},
    {ENODATA, "no data available"},
    {ETIME, "timer expired"},
    {ENOSR, "no stream resources"},
    {ENONET, "not on network"},
    {ENOPKG, "package not installed"},
    {EREMOTE, "is remote"},
    {ENOLINK, "link severed"},
    {EADV, "advertise error"},
    {ESRMNT, "srmount error"},
    {ECOMM, "communication error"},
    {EPROTO, "protocol error"},
    {EMULTIHOP, "multihop attempted"},
    {EDOTDOT, "RFS specific error"},
    {EBADMSG, "bad message"},
    {EOVERFLOW, "value too large"},
    {ENOTUNIQ, "name not unique"},
    {EBADFD, "bad fd state"},
    {EREMCHG, "remote address changed"},
    {ELIBACC, "cannot access library"},
    {ELIBBAD, "corrupt library"},
    {ELIBSCN, "lib section corrupted"},
    {ELIBMAX, "too many libraries"},
    {ELIBEXEC, "cannot exec library"},
    {EILSEQ, "bad character sequence"},
    {ERESTART, "restart needed"},
    {ESTRPIPE, "streams pipe error"},
    {EUSERS, "too many users"},
    {ENOTSOCK, "not a socket"},
    {EDESTADDRREQ, "destination required"},
    {EMSGSIZE, "message too long"},
    {EPROTOTYPE, "wrong protocol type"},
    {ENOPROTOOPT, "protocol unavailable"},
    {EPROTONOSUPPORT, "protocol unsupported"},
    {ESOCKTNOSUPPORT, "socket type unsupported"},
    {EOPNOTSUPP, "operation unsupported"},
    {EPFNOSUPPORT, "protocol family unsupported"},
    {EAFNOSUPPORT, "address family unsupported"},
    {EADDRINUSE, "address in use"},
    {EADDRNOTAVAIL, "address unavailable"},
    {ENETDOWN, "network is down"},
    {ENETUNREACH, "network unreachable"},
    {ENETRESET, "network reset"},
    {ECONNABORTED, "connection aborted"},
    {ECONNRESET, "connection reset"},
    {ENOBUFS, "no buffer space"},
    {EISCONN, "already connected"},
    {ENOTCONN, "not connected"},
    {ESHUTDOWN, "shut down"},
    {ETOOMANYREFS, "too many references"},
    {ETIMEDOUT, "timed out"},
    {ECONNREFUSED, "connection refused"},
    {EHOSTDOWN, "host is down"},
    {EHOSTUNREACH, "host unreachable"},
    {EALREADY, "already in progress"},
    {EINPROGRESS, "in progress"},
    {ESTALE, "stale file handle"},
    {EUCLEAN, "structure needs cleaning"},
    {ENOTNAM, "not a named file"},
    {ENAVAIL, "not available"},
    {EISNAM, "is a named file"},
    {EREMOTEIO, "remote i/o error"},
    {EDQUOT, "quota exceeded"},
    {ENOMEDIUM, "no medium found"},
    {EMEDIUMTYPE, "wrong medium type"},
    {ECANCELED, "cancelled"},
    {ENOKEY, "no key"},
    {EKEYEXPIRED, "key expired"},
    {EKEYREVOKED, "key revoked"},
    {EKEYREJECTED, "key rejected"},
    {EOWNERDEAD, "owner died"},
    {ENOTRECOVERABLE, "state not recoverable"},
    {ERFKILL, "rf kill"},
    {EHWPOISON, "memory page poisoned"},
};

static const char *ml_strerror(int e) {
    size_t i;
    for (i = 0; i < sizeof(ml_errtab) / sizeof(ml_errtab[0]); i++)
        if (ml_errtab[i].e == e) return ml_errtab[i].m;
    return "unknown";
}

char *strerror(int e) { return (char *)ml_strerror(e); }

void perror(const char *msg) {
    int e = errno;
    if (msg && *msg) {
        write(2, msg, strlen(msg));
        write(2, ": ", 2);
    }
    write(2, ml_strerror(e), strlen(ml_strerror(e)));
    write(2, "\n", 1);
}

int strerror_r(int e, char *buf, size_t n) {
    const char *m = ml_strerror(e);
    size_t l = strlen(m);
    if (!buf || n == 0) return EINVAL;
    if (l >= n) {
        memcpy(buf, m, n - 1);
        buf[n - 1] = '\0';
        return ERANGE;
    }
    memcpy(buf, m, l + 1);
    return 0;
}
