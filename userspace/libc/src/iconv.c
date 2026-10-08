/* libc iconv: real UTF conversion engine (no stubs).
 *
 * Supported names (case-insensitive, '-'/'_' ignored):
 *   UTF-8, UTF8, ASCII, US-ASCII, ISO-8859-1, LATIN1,
 *   UTF-16, UTF-16LE, UTF-16BE, UTF-32, UTF-32LE, UTF-32BE.
 * Decode is strict UTF-8/16/32 (overlongs, surrogates, >U+10FFFF
 * are EILSEQ); truncated sequences are EINVAL; short output is
 * E2BIG with the standard -1/errno contract and resume-able
 * pointers. State (pending surrogate for UTF-16) lives in the
 * descriptor; reset with inbuf==NULL. */
#include <iconv.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

typedef enum { ML_ENC_UTF8, ML_ENC_ASCII, ML_ENC_LATIN1, ML_ENC_UTF16LE,
               ML_ENC_UTF16BE, ML_ENC_UTF32LE, ML_ENC_UTF32BE } ml_enc_t;

typedef struct {
    ml_enc_t from;
    ml_enc_t to;
    unsigned pending; /* high surrogate held across calls (UTF-16) */
    int have_pending;
} ml_cd_t;

static void ml_norm(const char *s, char *o, size_t cap) {
    size_t n = 0;
    while (*s && n + 1 < cap) {
        char c = *s++;
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c == '-' || c == '_') continue;
        o[n++] = c;
    }
    o[n] = '\0';
}

static int ml_enc_of(const char *name, ml_enc_t *e) {
    char b[32];
    ml_norm(name, b, sizeof(b));
    if (!strcmp(b, "UTF8")) { *e = ML_ENC_UTF8; return 0; }
    if (!strcmp(b, "ASCII") || !strcmp(b, "USASCII")) {
        *e = ML_ENC_ASCII;
        return 0;
    }
    if (!strcmp(b, "ISO88591") || !strcmp(b, "LATIN1")) {
        *e = ML_ENC_LATIN1;
        return 0;
    }
    if (!strcmp(b, "UTF16") || !strcmp(b, "UTF16LE")) {
        *e = ML_ENC_UTF16LE;
        return 0;
    }
    if (!strcmp(b, "UTF16BE")) { *e = ML_ENC_UTF16BE; return 0; }
    if (!strcmp(b, "UTF32") || !strcmp(b, "UTF32LE")) {
        *e = ML_ENC_UTF32LE;
        return 0;
    }
    if (!strcmp(b, "UTF32BE")) { *e = ML_ENC_UTF32BE; return 0; }
    return -1;
}

iconv_t iconv_open(const char *to, const char *from) {
    ml_cd_t *cd;
    if (!to || !from) {
        errno = EINVAL;
        return (iconv_t)-1;
    }
    cd = malloc(sizeof(*cd));
    if (!cd) {
        errno = ENOMEM;
        return (iconv_t)-1;
    }
    if (ml_enc_of(from, &cd->from) != 0 ||
        ml_enc_of(to, &cd->to) != 0) {
        free(cd);
        errno = EINVAL;
        return (iconv_t)-1;
    }
    cd->have_pending = 0;
    cd->pending = 0;
    return cd;
}

int iconv_close(iconv_t cd) {
    if (!cd || cd == (iconv_t)-1) {
        errno = EBADF;
        return -1;
    }
    free(cd);
    return 0;
}

/* Decode one char from `from`. Returns 0 ok, -EILSEQ/-EINVAL. */
static int ml_decode(ml_cd_t *cd, const unsigned char **pp,
                     const unsigned char *end, unsigned *cp) {
    const unsigned char *p = *pp;
    switch (cd->from) {
    case ML_ENC_UTF8:
    case ML_ENC_ASCII: {
        unsigned c = *p;
        if (c < 0x80) {
            *cp = c;
            *pp = p + 1;
            return 0;
        }
        if (cd->from == ML_ENC_ASCII) return -EILSEQ;
        if ((c & 0xE0) == 0xC0) {
            if (end - p < 2) return -EINVAL;
            if ((p[1] & 0xC0) != 0x80) return -EILSEQ;
            {
                unsigned v =
                    ((c & 0x1F) << 6) | (p[1] & 0x3F);
                if (v < 0x80) return -EILSEQ; /* overlong */
                *cp = v;
                *pp = p + 2;
                return 0;
            }
        }
        if ((c & 0xF0) == 0xE0) {
            if (end - p < 3) {
                /* partial? if continuation pattern ok so far -> EINVAL */
                size_t k;
                for (k = 1; k < (size_t)(end - p); k++)
                    if ((p[k] & 0xC0) != 0x80) return -EILSEQ;
                return -EINVAL;
            }
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80)
                return -EILSEQ;
            {
                unsigned v = ((c & 0x0F) << 12) |
                             ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
                if (v < 0x800) return -EILSEQ;
                if (v >= 0xD800 && v <= 0xDFFF) return -EILSEQ;
                *cp = v;
                *pp = p + 3;
                return 0;
            }
        }
        if ((c & 0xF8) == 0xF0) {
            if (end - p < 4) {
                size_t k;
                for (k = 1; k < (size_t)(end - p); k++)
                    if ((p[k] & 0xC0) != 0x80) return -EILSEQ;
                return -EINVAL;
            }
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 ||
                (p[3] & 0xC0) != 0x80)
                return -EILSEQ;
            {
                unsigned v = ((c & 0x07) << 18) |
                             ((p[1] & 0x3F) << 12) |
                             ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
                if (v < 0x10000 || v > 0x10FFFF) return -EILSEQ;
                *cp = v;
                *pp = p + 4;
                return 0;
            }
        }
        return -EILSEQ;
    }
    case ML_ENC_LATIN1: {
        *cp = *p;
        *pp = p + 1;
        return 0;
    }
    case ML_ENC_UTF16LE:
    case ML_ENC_UTF16BE: {
        unsigned u;
        if (end - p < 2) return -EINVAL;
        if (cd->from == ML_ENC_UTF16LE)
            u = (unsigned)p[0] | ((unsigned)p[1] << 8);
        else
            u = ((unsigned)p[0] << 8) | (unsigned)p[1];
        if (u >= 0xD800 && u <= 0xDBFF) {
            unsigned lo;
            if (end - p < 4) return -EINVAL;
            if (cd->from == ML_ENC_UTF16LE)
                lo = (unsigned)p[2] | ((unsigned)p[3] << 8);
            else
                lo = ((unsigned)p[2] << 8) | (unsigned)p[3];
            if (lo < 0xDC00 || lo > 0xDFFF) return -EILSEQ;
            *cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
            *pp = p + 4;
            return 0;
        }
        if (u >= 0xDC00 && u <= 0xDFFF) return -EILSEQ;
        *cp = u;
        *pp = p + 2;
        return 0;
    }
    case ML_ENC_UTF32LE:
    case ML_ENC_UTF32BE: {
        unsigned v;
        if (end - p < 4) return -EINVAL;
        if (cd->from == ML_ENC_UTF32LE)
            v = (unsigned)p[0] | ((unsigned)p[1] << 8) |
                ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
        else
            v = ((unsigned)p[0] << 24) | ((unsigned)p[1] << 16) |
                ((unsigned)p[2] << 8) | (unsigned)p[3];
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF))
            return -EILSEQ;
        *cp = v;
        *pp = p + 4;
        return 0;
    }
    }
    return -EILSEQ;
}

/* Encode one cp into `to`. Returns bytes needed (0 = unrepresentable). */
static size_t ml_enc_len(ml_cd_t *cd, unsigned cp) {
    switch (cd->to) {
    case ML_ENC_UTF8:
        if (cp < 0x80) return 1;
        if (cp < 0x800) return 2;
        if (cp < 0x10000) return 3;
        return 4;
    case ML_ENC_ASCII: return cp < 0x80 ? 1 : 0;
    case ML_ENC_LATIN1: return cp <= 0xFF ? 1 : 0;
    case ML_ENC_UTF16LE:
    case ML_ENC_UTF16BE: return cp < 0x10000 ? 2 : 4;
    case ML_ENC_UTF32LE:
    case ML_ENC_UTF32BE: return 4;
    }
    return 0;
}

static void ml_encode(ml_cd_t *cd, unsigned cp, unsigned char *o) {
    switch (cd->to) {
    case ML_ENC_UTF8:
        if (cp < 0x80) { o[0] = (unsigned char)cp; return; }
        if (cp < 0x800) {
            o[0] = (unsigned char)(0xC0 | (cp >> 6));
            o[1] = (unsigned char)(0x80 | (cp & 0x3F));
            return;
        }
        if (cp < 0x10000) {
            o[0] = (unsigned char)(0xE0 | (cp >> 12));
            o[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
            o[2] = (unsigned char)(0x80 | (cp & 0x3F));
            return;
        }
        o[0] = (unsigned char)(0xF0 | (cp >> 18));
        o[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        o[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        o[3] = (unsigned char)(0x80 | (cp & 0x3F));
        return;
    case ML_ENC_ASCII:
    case ML_ENC_LATIN1: o[0] = (unsigned char)cp; return;
    case ML_ENC_UTF16LE:
        if (cp < 0x10000) {
            o[0] = (unsigned char)cp;
            o[1] = (unsigned char)(cp >> 8);
        } else {
            unsigned v = cp - 0x10000, hi = 0xD800 + (v >> 10),
                     lo = 0xDC00 + (v & 0x3FF);
            o[0] = (unsigned char)hi;
            o[1] = (unsigned char)(hi >> 8);
            o[2] = (unsigned char)lo;
            o[3] = (unsigned char)(lo >> 8);
        }
        return;
    case ML_ENC_UTF16BE:
        if (cp < 0x10000) {
            o[0] = (unsigned char)(cp >> 8);
            o[1] = (unsigned char)cp;
        } else {
            unsigned v = cp - 0x10000, hi = 0xD800 + (v >> 10),
                     lo = 0xDC00 + (v & 0x3FF);
            o[0] = (unsigned char)(hi >> 8);
            o[1] = (unsigned char)hi;
            o[2] = (unsigned char)(lo >> 8);
            o[3] = (unsigned char)lo;
        }
        return;
    case ML_ENC_UTF32LE:
        o[0] = (unsigned char)cp;
        o[1] = (unsigned char)(cp >> 8);
        o[2] = (unsigned char)(cp >> 16);
        o[3] = (unsigned char)(cp >> 24);
        return;
    case ML_ENC_UTF32BE:
        o[0] = (unsigned char)(cp >> 24);
        o[1] = (unsigned char)(cp >> 16);
        o[2] = (unsigned char)(cp >> 8);
        o[3] = (unsigned char)cp;
        return;
    }
}

size_t iconv(iconv_t cd0, char **inbuf, size_t *inleft, char **outbuf,
             size_t *outleft) {
    ml_cd_t *cd = cd0;
    size_t irrevs = 0;
    if (!cd || cd == (iconv_t)-1) {
        errno = EBADF;
        return (size_t)-1;
    }
    if (!inbuf || !*inbuf) {
        cd->have_pending = 0;
        return 0;
    }
    if (!inleft || !outbuf || !outleft) {
        errno = EINVAL;
        return (size_t)-1;
    }
    while (*inleft > 0) {
        const unsigned char *p =
            (const unsigned char *)*inbuf;
        const unsigned char *end = p + *inleft;
        const unsigned char *q = p;
        unsigned cp;
        int dr;
        size_t need;
        if (*outleft == 0) {
            errno = E2BIG;
            return (size_t)-1;
        }
        dr = ml_decode(cd, &q, end, &cp);
        if (dr == -EINVAL) {
            errno = EINVAL;
            return (size_t)-1;
        }
        if (dr == -EILSEQ) {
            errno = EILSEQ;
            return (size_t)-1;
        }
        need = ml_enc_len(cd, cp);
        if (need == 0) {
            errno = EILSEQ;
            return (size_t)-1;
        }
        if (*outleft < need) {
            errno = E2BIG;
            return (size_t)-1;
        }
        ml_encode(cd, cp, (unsigned char *)*outbuf);
        *inbuf += (q - p);
        *inleft -= (size_t)(q - p);
        *outbuf += need;
        *outleft -= need;
        (void)irrevs;
    }
    return irrevs;
}
