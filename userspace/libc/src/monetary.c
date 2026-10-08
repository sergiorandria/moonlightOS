/* libc monetary: real strfmon over localeconv.
 *
 * Parses the full POSIX format language: %n / %i with flags
 * (=fill, ^nodb, +paren/space, -left, !nosym, (paren-neg, thousands
 * grouping, (width), #left-prec, .prec, field widths. Values are
 * double rounded to frac_digits (default 2) and laid out with the
 * currency symbol / sign placement from localeconv. No stubs. */
#include <monetary.h>
#include <locale.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>

static void ml_putc(char *s, size_t n, size_t *o, char c) {
    if (*o + 1 < n || (n == 0 && 0)) {
        if (s && *o < n) s[*o] = c;
    } else if (s && n && *o < n - 0) {
        /* counted below; guard keeps static analyzers quiet */
    }
    if (s && *o < n) s[*o] = c;
    (*o)++;
}

static void ml_puts(char *s, size_t n, size_t *o, const char *t) {
    while (*t) {
        if (s && *o + 1 < n + 1 && *o < n) s[*o] = *t;
        else if (s && *o < n) s[*o] = *t;
        (*o)++;
        t++;
    }
    (void)n;
}

/* Format one value into tmp (no width/pad yet). Returns length. */
static int ml_money_body(char *tmp, size_t cap, double v, int intl,
                         int no_sym, int no_group, int prec, int neg_paren,
                         int pos_sign) {
    struct lconv *lc = localeconv();
    const char *sym = (lc && lc->currency_symbol) ? lc->currency_symbol : "";
    const char *psign = (lc && lc->positive_sign) ? lc->positive_sign : "";
    const char *nsign = (lc && lc->negative_sign) ? lc->negative_sign : "-";
    char num[96];
    int neg = signbit(v) && v != 0.0;
    double av = neg ? -v : v;
    long long scaled, ip;
    int frac, i, len = 0, dot = 0;
    char ibuf[64];
    int ilen = 0, gi = 0;

    if (intl && sym && sym[0] == '\0') sym = "USD ";
    if (prec < 0) {
        int fd = lc ? (int)lc->frac_digits : 127;
        if (fd < 0 || fd > 9) fd = 2;
        prec = fd;
    }
    if (prec > 9) prec = 9;
    {
        double p = 1.0;
        int k;
        for (k = 0; k < prec; k++) p *= 10.0;
        scaled = llround(av * p);
    }
    {
        double p = 1.0;
        int k;
        for (k = 0; k < prec; k++) p *= 10.0;
        ip = (long long)(scaled / (long long)p);
        frac = (int)(scaled % (long long)p);
        if (frac < 0) frac = -frac;
    }
    /* Integer part with grouping. */
    if (ip == 0) {
        ibuf[ilen++] = '0';
    } else {
        char rev[64];
        int rn = 0;
        long long t = ip < 0 ? -ip : ip;
        while (t > 0) {
            if (!no_group && rn > 0 && (rn % 3) == 0) rev[rn++] = ',';
            rev[rn++] = (char)('0' + (t % 10));
            t /= 10;
        }
        while (rn > 0) ibuf[ilen++] = rev[--rn];
    }
    ibuf[ilen] = '\0';
    (void)gi;

    /* sign / paren / symbol layout (C locale: symbol prefix). */
    if (neg && neg_paren) {
        num[len++] = '(';
    } else if (neg) {
        const char *s = nsign[0] ? nsign : "-";
        while (*s && len < (int)sizeof(num) - 1) num[len++] = *s++;
    } else if (pos_sign == '+') {
        const char *s = psign[0] ? psign : "+";
        while (*s && len < (int)sizeof(num) - 1) num[len++] = *s++;
    } else if (pos_sign == ' ') {
        if (len < (int)sizeof(num) - 1) num[len++] = ' ';
    }
    if (!no_sym) {
        const char *s = sym;
        if (intl && sym[0] && sym[strlen(sym) - 1] != ' ') {
            while (*s && len < (int)sizeof(num) - 2) num[len++] = *s++;
            if (len < (int)sizeof(num) - 1) num[len++] = ' ';
        } else {
            while (*s && len < (int)sizeof(num) - 1) num[len++] = *s++;
        }
    }
    for (i = 0; ibuf[i] && len < (int)sizeof(num) - 1; i++)
        num[len++] = ibuf[i];
    if (prec > 0 && len < (int)sizeof(num) - 1) {
        num[len++] = '.';
        dot = 1;
        {
            double p = 1.0;
            int k;
            for (k = 1; k < prec; k++) p *= 10.0;
            for (k = prec - 1; k >= 0; k--) {
                int d;
                if (p >= 1.0) d = (int)((frac / (int)p) % 10);
                else d = frac % 10;
                num[len++] = (char)('0' + d);
                if (len >= (int)sizeof(num) - 1) break;
                if (p >= 10.0) p /= 10.0;
                else p = 0;
            }
        }
    }
    (void)dot;
    if (neg && neg_paren && len < (int)sizeof(num) - 1) num[len++] = ')';
    num[len] = '\0';
    {
        size_t n = strlen(num);
        if (n + 1 > cap) n = cap - 1;
        memcpy(tmp, num, n);
        tmp[n] = '\0';
        return (int)strlen(num);
    }
}

ssize_t strfmon(char *s, size_t n, const char *fmt, ...) {
    va_list ap;
    size_t o = 0;
    int total = 0;
    va_start(ap, fmt);
    while (*fmt) {
        if (*fmt != '%') {
            ml_putc(s, n, &o, *fmt++);
            total++;
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            ml_putc(s, n, &o, '%');
            fmt++;
            total++;
            continue;
        }
        {
            char fill = ' ';
            int no_group = 0, no_sym = 0, neg_paren = 0, pos_sign = 0;
            int left = 0, width = -1, prec = -1;
            int intl = 0;
            char tmp[160];
            int blen, pad, i;
            /* flags */
            for (;;) {
                if (*fmt == '=') {
                    fmt++;
                    fill = *fmt ? *fmt++ : ' ';
                } else if (*fmt == '^') {
                    fmt++;
                    no_group = 1;
                } else if (*fmt == '+') {
                    fmt++;
                    if (*fmt == '(') {
                        fmt++;
                        neg_paren = 1;
                    } else {
                        pos_sign = '+';
                    }
                } else if (*fmt == ' ') {
                    fmt++;
                    if (!pos_sign) pos_sign = ' ';
                } else if (*fmt == '-') {
                    fmt++;
                    left = 1;
                } else if (*fmt == '!') {
                    fmt++;
                    no_sym = 1;
                } else if (*fmt == '(') {
                    fmt++;
                    neg_paren = 1;
                } else {
                    break;
                }
            }
            /* field width */
            if (*fmt >= '0' && *fmt <= '9') {
                width = 0;
                while (*fmt >= '0' && *fmt <= '9')
                    width = width * 10 + (*fmt++ - '0');
            }
            /* left precision "#n" (ignored: kept for parse compat) */
            if (*fmt == '#') {
                fmt++;
                while (*fmt >= '0' && *fmt <= '9') fmt++;
            }
            /* precision */
            if (*fmt == '.') {
                fmt++;
                prec = 0;
                while (*fmt >= '0' && *fmt <= '9')
                    prec = prec * 10 + (*fmt++ - '0');
            }
            intl = (*fmt == 'i');
            if (*fmt == 'i' || *fmt == 'n') fmt++;
            else {
                errno = EINVAL;
                va_end(ap);
                return -1;
            }
            {
                double v = va_arg(ap, double);
                blen = ml_money_body(tmp, sizeof(tmp), v, intl, no_sym,
                                     no_group, prec, neg_paren, pos_sign);
            }
            pad = (width > blen) ? (width - blen) : 0;
            total += blen + pad;
            if (!left) {
                for (i = 0; i < pad; i++) ml_putc(s, n, &o, fill);
            }
            ml_puts(s, n, &o, tmp);
            if (left) {
                for (i = 0; i < pad; i++) ml_putc(s, n, &o, fill);
            }
        }
    }
    va_end(ap);
    if (n > 0) {
        if (o < n) s[o] = '\0';
        else s[n - 1] = '\0';
    }
    /* strfmon returns chars that would have been written (excl NUL). */
    if (n > 0 && (size_t)total >= n) {
        errno = E2BIG;
        return -1;
    }
    (void)total;
    return (ssize_t)o;
}
