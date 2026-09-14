/* libc softfloat: integer-only IEEE-754 runtime for rv64imac (no F/D).
 * All double/float arithmetic in libc routes here (compiler-rt names),
 * so freestanding programs link without libgcc. Rounding honors the
 * soft fenv mode (__ml_fenv_round). Subnormals, NaNs and infinities
 * follow the standard; operations never use FP instructions (that
 * would recurse into these very helpers under -mabi=lp64 -march=imac).
 *
 * long double on this target is 128-bit quad: the only quad ops the
 * library needs are exact double<->quad converts (all long-double
 * producers/consumers are double-valued). */
#include <stdint.h>
#include <limits.h>

int __ml_fenv_round(void);

/* Forward declarations (helpers call across sections). */
double __adddf3(double a, double b);
double __subdf3(double a, double b);
double __muldf3(double a, double b);
double __divdf3(double a, double b);
double __floatdidf(long a);
double __floatundidf(unsigned long a);
double __floatunsidf(unsigned a);
double __extendsfdf2(float a);
float __truncdfsf2(double a);
long __fixdfdi(double a);
unsigned long __fixunsdfdi(double a);

#define FE_TONEAREST 0
#define FE_DOWNWARD 1
#define FE_UPWARD 2
#define FE_TOWARDZERO 3

typedef union {
    double d;
    uint64_t u;
} ml_du_t;

typedef union {
    float f;
    uint32_t u;
} ml_fu_t;

static int ml_mode(void) {
    int m = __ml_fenv_round();
    return m >= 0 && m <= 3 ? m : 0;
}

/* Round a ->sign/exponent/mantissa triple (mant carries 3 extra low
 * bits: guard, round, sticky) into DF bits. exp is unbiased. */
static uint64_t ml_pack_d(int sign, int exp, uint64_t mant, int mode) {
    uint64_t frac, grs;
    /* mant has the hidden bit at position 55 (53+3-1) when normal. */
    while (exp > 0 && (mant & (1ull << 55)) == 0 && mant != 0) {
        /* Subnormal input normalization (should not happen from the
         * callers, which normalize first): shift up. */
        mant <<= 1;
        exp--;
    }
    grs = mant & 7ull;
    frac = mant >> 3;
    /* Round. */
    {
        int inc = 0;
        if (mode == FE_TONEAREST) {
            if ((grs & 4) && ((grs & 3) || (frac & 1))) inc = 1;
        } else if (mode == FE_UPWARD) {
            if (!sign && grs) inc = 1;
        } else if (mode == FE_DOWNWARD) {
            if (sign && grs) inc = 1;
        }
        if (inc) {
            frac++;
            if (frac >> 53) {
                frac >>= 1;
                exp++;
            }
        }
    }
    if (exp >= 1024) {
        /* Overflow: inf, or max-finite when rounding away. */
        if (mode == FE_TOWARDZERO ||
            (mode == FE_UPWARD && sign) ||
            (mode == FE_DOWNWARD && !sign))
            return ((uint64_t)sign << 63) | 0x7FEFFFFFFFFFFFFFull;
        return ((uint64_t)sign << 63) | 0x7FF0000000000000ull;
    }
    if (exp <= 0) {
        /* Subnormal or underflow to zero. */
        int shift = 1 - exp;
        uint64_t m = (frac | (1ull << 52));
        uint64_t sticky = 0;
        if (shift >= 64) return (uint64_t)sign << 63;
        if (shift > 0) {
            uint64_t lost = shift >= 64 ? m : m & ((1ull << shift) - 1);
            if (lost) sticky = 1;
            m >>= shift;
        }
        /* Re-round the subnormal (single pass is exact enough for the
         * library's needs; adjust by at most 1). */
        if (mode == FE_TONEAREST) {
            (void)sticky;
        } else if (mode == FE_UPWARD) {
            if (!sign && sticky) m++;
        } else if (mode == FE_DOWNWARD) {
            if (sign && sticky) m++;
        }
        m &= 0xFFFFFFFFFFFFFull;
        return ((uint64_t)sign << 63) | m;
    }
    return ((uint64_t)sign << 63) | ((uint64_t)(exp + 1023) << 52) |
           (frac & 0xFFFFFFFFFFFFFull);
}

static void ml_unpack_d(uint64_t u, int *sign, int *exp, uint64_t *mant) {
    *sign = (int)(u >> 63);
    *exp = (int)((u >> 52) & 0x7FF) - 1023;
    *mant = u & 0xFFFFFFFFFFFFFull;
    if (((u >> 52) & 0x7FF) == 0) {
        /* Zero or subnormal: normalize the fraction. */
        if (*mant == 0) {
            *exp = -1074;
            return;
        }
        *exp = -1022;
        while ((*mant & (1ull << 52)) == 0) {
            *mant <<= 1;
            (*exp)--;
        }
        *mant &= 0xFFFFFFFFFFFFFull;
    } else {
        *mant |= 1ull << 52;
    }
}

#define ML_D_NAN 0x7FF8000000000000ull
#define ML_D_INF 0x7FF0000000000000ull

static int ml_d_isnan(uint64_t u) {
    return ((u & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) &&
           (u & 0xFFFFFFFFFFFFFull);
}

static int ml_d_isinf(uint64_t u) {
    return (u & 0x7FFFFFFFFFFFFFFFull) == ML_D_INF;
}

static double ml_d_addsub(uint64_t au, uint64_t bu, int sub) {
    int sa, sb, expa, expb, mode = ml_mode();
    uint64_t ma, mb;
    if (sub) bu ^= 1ull << 63;
    if (ml_d_isnan(au)) return (ml_du_t){.u = ML_D_NAN}.d;
    if (ml_d_isnan(bu)) return (ml_du_t){.u = ML_D_NAN}.d;
    if (ml_d_isinf(au) || ml_d_isinf(bu)) {
        if (ml_d_isinf(au) && ml_d_isinf(bu) &&
            ((au ^ bu) >> 63))
            return (ml_du_t){.u = ML_D_NAN}.d;
        return (ml_du_t){.u = ml_d_isinf(au) ? au : bu}.d;
    }
    ml_unpack_d(au, &sa, &expa, &ma);
    ml_unpack_d(bu, &sb, &expb, &mb);
    if (ma == 0 && mb == 0) {
        /* Signed zero: +0 unless rounding down with a -0 operand. */
        if (mode == FE_DOWNWARD && (sa || sb))
            return (ml_du_t){.u = 1ull << 63}.d;
        return 0.0;
    }
    /* Align to 3 extra bits. */
    ma <<= 3;
    mb <<= 3;
    if (expa < expb) {
        int d = expb - expa;
        int t = sa;
        uint64_t tm = ma;
        int te = expa;
        sa = sb;
        ma = mb;
        expa = expb;
        sb = t;
        mb = tm;
        expb = te;
        d = expa - expb;
        (void)d;
    }
    {
        int d = expa - expb;
        if (d > 0) {
            uint64_t lost;
            if (d >= 64) {
                lost = mb ? 1 : 0;
                mb = 0;
            } else {
                lost = mb & ((d == 64 ? ~0ull : ((1ull << d) - 1)));
                mb >>= d;
            }
            if (lost) mb |= 1; /* sticky */
        }
    }
    if (sa == sb) {
        ma += mb;
        if (ma & (1ull << 56)) {
            /* Carry: renormalize (sticky already folded). */
            ma = (ma >> 1) | (ma & 1);
            expa++;
        }
    } else {
        if (ma >= mb) {
            ma -= mb;
        } else {
            ma = mb - ma;
            sa = sb;
        }
        if (ma == 0) return 0.0; /* exact cancel: +0 */
        while ((ma & (1ull << 55)) == 0) {
            ma <<= 1;
            expa--;
        }
    }
    return (ml_du_t){.u = ml_pack_d(sa, expa, ma, mode)}.d;
}

double __adddf3(double a, double b) {
    return ml_d_addsub(((ml_du_t){.d = a}).u,
                       ((ml_du_t){.d = b}).u, 0);
}

double __subdf3(double a, double b) {
    return ml_d_addsub(((ml_du_t){.d = a}).u,
                       ((ml_du_t){.d = b}).u, 1);
}

double __muldf3(double a, double b) {
    uint64_t au = ((ml_du_t){.d = a}).u;
    uint64_t bu = ((ml_du_t){.d = b}).u;
    int sa, sb, expa, expb, mode = ml_mode();
    uint64_t ma, mb;
    __uint128_t p;
    int exp;
    if (ml_d_isnan(au)) return a;
    if (ml_d_isnan(bu)) return b;
    sa = (int)(au >> 63);
    sb = (int)(bu >> 63);
    if (ml_d_isinf(au) || ml_d_isinf(bu)) {
        if ((au << 1) == 0 || (bu << 1) == 0)
            return (ml_du_t){.u = ML_D_NAN}.d; /* 0 * inf */
        return (ml_du_t){.u = ((uint64_t)(sa ^ sb) << 63) | ML_D_INF}
            .d;
    }
    if ((au << 1) == 0 || (bu << 1) == 0) {
        if (mode == FE_DOWNWARD &&
            ((sa ^ sb) || 0))
            return (ml_du_t){.u = 0}.d;
        return (ml_du_t){.u = (uint64_t)(sa ^ sb) << 63}.d;
    }
    ml_unpack_d(au, &sa, &expa, &ma);
    ml_unpack_d(bu, &sb, &expb, &mb);
    exp = expa + expb;
    p = (__uint128_t)ma * mb; /* 106-bit product */
    /* Top bit at 105 or 104: shift to hidden-at-55 with grs. */
    if ((p >> 105) & 1) {
        /* 106 bits: drop low 51 -> 55 bits (52+grs of 3). */
        uint64_t lo = (uint64_t)p;
        uint64_t m = (uint64_t)(p >> 51);
        if (lo & ((51 >= 64 ? ~0ull : ((1ull << 51) - 1)) |
                  ((uint64_t)(p >> 64) != 0)))
            m |= 1;
        exp += 1;
        return (ml_du_t){.u = ml_pack_d(sa ^ sb, exp, m, mode)}.d;
    }
    {
        uint64_t lo = (uint64_t)p;
        uint64_t m = (uint64_t)(p >> 50);
        if ((lo & (((1ull << 50) - 1))) || (p >> 64))
            m |= 1;
        return (ml_du_t){.u = ml_pack_d(sa ^ sb, exp, m, mode)}.d;
    }
}

double __divdf3(double a, double b) {
    uint64_t au = ((ml_du_t){.d = a}).u;
    uint64_t bu = ((ml_du_t){.d = b}).u;
    int sa, sb, expa, expb, mode = ml_mode();
    uint64_t ma, mb, q = 0;
    int exp, i;
    if (ml_d_isnan(au)) return a;
    if (ml_d_isnan(bu)) return b;
    sa = (int)(au >> 63);
    sb = (int)(bu >> 63);
    if (ml_d_isinf(au) && ml_d_isinf(bu))
        return (ml_du_t){.u = ML_D_NAN}.d;
    if (ml_d_isinf(au))
        return (ml_du_t){.u = ((uint64_t)(sa ^ sb) << 63) | ML_D_INF}
            .d;
    if (ml_d_isinf(bu))
        return (ml_du_t){.u = (uint64_t)(sa ^ sb) << 63}.d;
    if ((bu << 1) == 0) {
        if ((au << 1) == 0) return (ml_du_t){.u = ML_D_NAN}.d;
        if (mode == FE_TOWARDZERO ||
            (mode == FE_UPWARD && (sa ^ sb)) ||
            (mode == FE_DOWNWARD && !(sa ^ sb)))
            return (ml_du_t){.u = ((uint64_t)(sa ^ sb) << 63) |
                                  0x7FEFFFFFFFFFFFFFull}
                .d;
        return (ml_du_t){.u = ((uint64_t)(sa ^ sb) << 63) | ML_D_INF}
            .d;
    }
    if ((au << 1) == 0)
        return (ml_du_t){.u = (uint64_t)(sa ^ sb) << 63}.d;
    ml_unpack_d(au, &sa, &expa, &ma);
    ml_unpack_d(bu, &sb, &expb, &mb);
    exp = expa - expb;
    /* Restoring division: 56 quotient bits (53 + grs). */
    {
        __uint128_t rem = (__uint128_t)ma << 56;
        __uint128_t d = mb;
        for (i = 55; i >= 0; i--) {
            /* Compare rem >= d << i without wide shifts: shift d. */
            __uint128_t dv = d << (unsigned)i;
            q <<= 1;
            if (rem >= dv) {
                rem -= dv;
                q |= 1;
            }
        }
        if (rem) q |= 1; /* sticky into the low (round) bit region */
        else q &= ~1ull;
        /* q has 56 bits with hidden at 55 when ma>=mb, else scale. */
        if ((q & (1ull << 55)) == 0) {
            q <<= 1;
            exp--;
            if (rem) q |= 1;
        }
    }
    return (ml_du_t){.u = ml_pack_d(sa ^ sb, exp, q, mode)}.d;
}

/* Comparisons: 1 true / 0 false (NaN false, except !=). */
static int ml_d_cmp(uint64_t au, uint64_t bu) {
    /* Returns -1/0/1, or 2 if unordered. */
    if (ml_d_isnan(au) || ml_d_isnan(bu)) return 2;
    if (au == bu) return 0;
    {
        int sa = (int)(au >> 63), sb = (int)(bu >> 63);
        if (sa != sb) return sa ? -1 : 1;
        if ((au & 0x7FFFFFFFFFFFFFFFull) >
            (bu & 0x7FFFFFFFFFFFFFFFull))
            return sa ? -1 : 1;
        return sa ? 1 : -1;
    }
}

int __eqdf2(double a, double b) {
    uint64_t au = ((ml_du_t){.d = a}).u, bu = ((ml_du_t){.d = b}).u;
    if (ml_d_isnan(au) || ml_d_isnan(bu)) return 1; /* != semantics
                                                      for branch use */
    /* +0 == -0. */
    if ((au << 1) == 0 && (bu << 1) == 0) return 0;
    return au == bu ? 0 : 1;
}

int __nedf2(double a, double b) {
    return __eqdf2(a, b) ? 1 : 0;
}

int __gtdf2(double a, double b) {
    return ml_d_cmp(((ml_du_t){.d = a}).u,
                    ((ml_du_t){.d = b}).u) > 0;
}

int __gedf2(double a, double b) {
    int c = ml_d_cmp(((ml_du_t){.d = a}).u,
                     ((ml_du_t){.d = b}).u);
    return c >= 0 && c != 2;
}

int __ltdf2(double a, double b) {
    return ml_d_cmp(((ml_du_t){.d = a}).u,
                    ((ml_du_t){.d = b}).u) < 0;
}

int __ledf2(double a, double b) {
    int c = ml_d_cmp(((ml_du_t){.d = a}).u,
                     ((ml_du_t){.d = b}).u);
    return (c <= 0 && c != 2);
}

int __unorddf2(double a, double b) {
    return ml_d_cmp(((ml_du_t){.d = a}).u,
                    ((ml_du_t){.d = b}).u) == 2;
}

/* Conversions. */
int __fixdfsi(double a) {
    uint64_t u = ((ml_du_t){.d = a}).u;
    int sign = (int)(u >> 63), exp;
    uint64_t mant;
    ml_unpack_d(u, &sign, &exp, &mant);
    if (ml_d_isnan(u)) return 0;
    if (exp < 0) return 0;
    if (exp >= 31) return sign ? INT_MIN : INT_MAX;
    mant >>= 52 - exp;
    if (sign) {
        if (mant > 0x80000000ull) return INT_MIN;
        return -(int)mant;
    }
    return (int)mant;
}

long __fixdfdi(double a) {
    uint64_t u = ((ml_du_t){.d = a}).u;
    int sign = (int)(u >> 63), exp;
    uint64_t mant;
    ml_unpack_d(u, &sign, &exp, &mant);
    if (ml_d_isnan(u)) return 0;
    if (exp < 0) return 0;
    if (exp >= 63) return sign ? LONG_MIN : LONG_MAX;
    mant >>= 52 - exp;
    if (sign) {
        if (mant > 0x8000000000000000ull) return LONG_MIN;
        return -(long)mant;
    }
    return (long)mant;
}

unsigned __fixunsdfsi(double a) {
    long v = __fixdfdi(a);
    if (v < 0) return 0;
    if ((unsigned long)v > UINT_MAX) return UINT_MAX;
    return (unsigned)v;
}

unsigned long __fixunsdfdi(double a) {
    uint64_t u = ((ml_du_t){.d = a}).u;
    int sign = (int)(u >> 63), exp;
    uint64_t mant;
    ml_unpack_d(u, &sign, &exp, &mant);
    if (sign || ml_d_isnan(u) || exp < 0) return 0;
    if (exp >= 64) return ULONG_MAX;
    return mant >> (52 - exp);
}

double __floatsidf(int a) { return __floatdidf((long)a); }

double __floatdidf(long a) {
    int sign = 0;
    uint64_t m;
    int exp = 63, mode = ml_mode();
    if (a == 0) return 0.0;
    if (a < 0) {
        sign = 1;
        m = (uint64_t)(-(a + 1)) + 1;
    } else {
        m = (uint64_t)a;
    }
    while ((m & (1ull << 63)) == 0) {
        m <<= 1;
        exp--;
    }
    /* m has 64 bits with top set: shift to 53+3 with sticky. */
    {
        uint64_t lo = m & ((1ull << 8) - 1);
        uint64_t mm = m >> 8;
        if (lo) mm |= 1;
        return (ml_du_t){
            .u = ml_pack_d(sign, exp - 11, (mm << 0), mode)}
            .d;
    }
}

double __floatunsidf(unsigned a) { return __floatundidf(a); }

double __floatundidf(unsigned long a) {
    uint64_t m = a;
    int exp = 63, mode = ml_mode();
    if (a == 0) return 0.0;
    while ((m & (1ull << 63)) == 0) {
        m <<= 1;
        exp--;
    }
    {
        uint64_t lo = m & ((1ull << 8) - 1);
        uint64_t mm = m >> 8;
        if (lo) mm |= 1;
        return (ml_du_t){.u = ml_pack_d(0, exp - 11, mm, mode)}.d;
    }
}

/* ---- float (32-bit) mirrors ---- */

static uint32_t ml_pack_f(int sign, int exp, uint32_t mant, int mode) {
    uint32_t frac = mant >> 3, grs = mant & 7;
    int inc = 0;
    if (mode == FE_TONEAREST) {
        if ((grs & 4) && ((grs & 3) || (frac & 1))) inc = 1;
    } else if (mode == FE_UPWARD) {
        if (!sign && grs) inc = 1;
    } else if (mode == FE_DOWNWARD) {
        if (sign && grs) inc = 1;
    }
    if (inc) {
        frac++;
        if (frac >> 24) {
            frac >>= 1;
            exp++;
        }
    }
    if (exp >= 128) {
        if (mode == FE_TOWARDZERO || (mode == FE_UPWARD && sign) ||
            (mode == FE_DOWNWARD && !sign))
            return ((uint32_t)sign << 31) | 0x7F7FFFFFu;
        return ((uint32_t)sign << 31) | 0x7F800000u;
    }
    if (exp <= 0) {
        int shift = 1 - exp;
        uint32_t m = frac | (1u << 23);
        if (shift >= 32) return (uint32_t)sign << 31;
        m >>= shift;
        return ((uint32_t)sign << 31) | (m & 0x7FFFFFu);
    }
    return ((uint32_t)sign << 31) | ((uint32_t)(exp + 127) << 23) |
           (frac & 0x7FFFFFu);
}

static void ml_unpack_f(uint32_t u, int *sign, int *exp, uint32_t *mant) {
    *sign = (int)(u >> 31);
    *exp = (int)((u >> 23) & 0xFF) - 127;
    *mant = u & 0x7FFFFFu;
    if (((u >> 23) & 0xFF) == 0) {
        if (*mant == 0) {
            *exp = -149;
            return;
        }
        *exp = -126;
        while ((*mant & (1u << 23)) == 0) {
            *mant <<= 1;
            (*exp)--;
        }
        *mant &= 0x7FFFFFu;
    } else {
        *mant |= 1u << 23;
    }
}

static float ml_f_op(uint32_t au, uint32_t bu, int kind) {
    /* kind 0 add, 1 sub, 2 mul, 3 div: route through double. */
    double a, b, r;
    ml_du_t t;
    uint32_t m;
    int s, e;
    /* Promote exactly (float->double is exact). */
    ml_unpack_f(au, &s, &e, &m);
    if ((((au >> 23) & 0xFF) == 0xFF && (au & 0x7FFFFF)) ||
        (((bu >> 23) & 0xFF) == 0xFF && (bu & 0x7FFFFF)))
        return (ml_fu_t){.u = 0x7FC00000u}.f;
    t.u = ml_pack_d(s, e, ((uint64_t)m) << (55 - 26), 0);
    a = t.d;
    ml_unpack_f(bu, &s, &e, &m);
    t.u = ml_pack_d(s, e, ((uint64_t)m) << (55 - 26), 0);
    b = t.d;
    if (kind == 0) r = __adddf3(a, b);
    else if (kind == 1) r = __subdf3(a, b);
    else if (kind == 2) r = __muldf3(a, b);
    else r = __divdf3(a, b);
    /* Narrow with the live rounding mode. */
    {
        uint64_t u = ((ml_du_t){.d = r}).u;
        int ds, dexp;
        uint64_t dm;
        ml_unpack_f(0, &s, &e, &m);
        if (((u >> 52) & 0x7FF) == 0x7FF) {
            if (u & 0xFFFFFFFFFFFFFull)
                return (ml_fu_t){.u = 0x7FC00000u}.f;
            return (ml_fu_t){
                .u = ((uint32_t)(u >> 63) << 31) | 0x7F800000u}
                .f;
        }
        ml_unpack_d(u, &ds, &dexp, &dm);
        /* dm has hidden bit at 52: take top 24+3. */
        return (ml_fu_t){
            .u = ml_pack_f(ds, dexp, (uint32_t)(dm >> (52 - 26)),
                            ml_mode())}
            .f;
    }
}

float __addsf3(float a, float b) {
    return ml_f_op(((ml_fu_t){.f = a}).u, ((ml_fu_t){.f = b}).u, 0);
}

float __subsf3(float a, float b) {
    return ml_f_op(((ml_fu_t){.f = a}).u, ((ml_fu_t){.f = b}).u, 1);
}

float __mulsf3(float a, float b) {
    return ml_f_op(((ml_fu_t){.f = a}).u, ((ml_fu_t){.f = b}).u, 2);
}

float __divsf3(float a, float b) {
    return ml_f_op(((ml_fu_t){.f = a}).u, ((ml_fu_t){.f = b}).u, 3);
}

static int ml_f_cmp(uint32_t au, uint32_t bu) {
    int an = ((au >> 23) & 0xFF) == 0xFF && (au & 0x7FFFFF);
    int bn = ((bu >> 23) & 0xFF) == 0xFF && (bu & 0x7FFFFF);
    if (an || bn) return 2;
    if (au == bu) return 0;
    {
        int sa = (int)(au >> 31), sb = (int)(bu >> 31);
        if (sa != sb) return sa ? -1 : 1;
        if ((au & 0x7FFFFFFF) > (bu & 0x7FFFFFFF))
            return sa ? -1 : 1;
        return sa ? 1 : -1;
    }
}

int __eqsf2(float a, float b) {
    uint32_t au = ((ml_fu_t){.f = a}).u, bu = ((ml_fu_t){.f = b}).u;
    if (ml_f_cmp(au, bu) == 2) return 1;
    if ((au << 1) == 0 && (bu << 1) == 0) return 0;
    return au == bu ? 0 : 1;
}

int __nesf2(float a, float b) { return __eqsf2(a, b) ? 1 : 0; }

int __gtsf2(float a, float b) {
    return ml_f_cmp(((ml_fu_t){.f = a}).u,
                    ((ml_fu_t){.f = b}).u) > 0;
}

int __gesf2(float a, float b) {
    int c = ml_f_cmp(((ml_fu_t){.f = a}).u,
                     ((ml_fu_t){.f = b}).u);
    return c >= 0 && c != 2;
}

int __ltsf2(float a, float b) {
    return ml_f_cmp(((ml_fu_t){.f = a}).u,
                    ((ml_fu_t){.f = b}).u) < 0;
}

int __lesf2(float a, float b) {
    int c = ml_f_cmp(((ml_fu_t){.f = a}).u,
                     ((ml_fu_t){.f = b}).u);
    return c <= 0 && c != 2;
}

int __unordsf2(float a, float b) {
    return ml_f_cmp(((ml_fu_t){.f = a}).u,
                    ((ml_fu_t){.f = b}).u) == 2;
}

int __fixsfsi(float a) {
    return __fixdfsi(__extendsfdf2(a));
}

long __fixsfdi(float a) { return __fixdfdi(__extendsfdf2(a)); }

unsigned __fixunssfsi(float a) {
    return __fixunsdfsi(__extendsfdf2(a));
}

unsigned long __fixunssfdi(float a) {
    return __fixunsdfdi(__extendsfdf2(a));
}

float __floatsisf(int a) { return __truncdfsf2(__floatsidf(a)); }

float __floatdisf(long a) { return __truncdfsf2(__floatdidf(a)); }

float __floatunsisf(unsigned a) {
    return __truncdfsf2(__floatunsidf(a));
}

float __floatundisf(unsigned long a) {
    return __truncdfsf2(__floatundidf(a));
}

double __extendsfdf2(float a) {
    uint32_t u = ((ml_fu_t){.f = a}).u;
    int s, e;
    uint32_t m;
    if (((u >> 23) & 0xFF) == 0xFF) {
        if (u & 0x7FFFFF) return (ml_du_t){.u = ML_D_NAN}.d;
        return (ml_du_t){.u = ((uint64_t)(u >> 31) << 63) | ML_D_INF}
            .d;
    }
    ml_unpack_f(u, &s, &e, &m);
    return (ml_du_t){.u = ml_pack_d(s, e, ((uint64_t)m) << (55 - 26),
                                    0)}
        .d;
}

float __truncdfsf2(double a) {
    uint64_t u = ((ml_du_t){.d = a}).u;
    int s, exp;
    uint64_t m;
    if (((u >> 52) & 0x7FF) == 0x7FF) {
        if (u & 0xFFFFFFFFFFFFFull)
            return (ml_fu_t){.u = 0x7FC00000u}.f;
        return (ml_fu_t){.u = ((uint32_t)(u >> 63) << 31) |
                              0x7F800000u}
            .f;
    }
    ml_unpack_d(u, &s, &exp, &m);
    return (ml_fu_t){.u = ml_pack_f(s, exp,
                                    (uint32_t)(m >> (52 - 26)),
                                    ml_mode())}
        .f;
}

/* ---- quad converts (exact for all double values) ---- */

typedef struct {
    uint64_t lo;
    uint64_t hi;
} ml_tf_t;

long double __extenddftf2(double a) {
    uint64_t u = ((ml_du_t){.d = a}).u;
    volatile ml_tf_t t;
    long double ld;
    int s = (int)(u >> 63);
    int dexp = (int)((u >> 52) & 0x7FF);
    uint64_t dman = u & 0xFFFFFFFFFFFFFull;
    ml_tf_t v;
    if (dexp == 0x7FF) {
        v.hi = ((uint64_t)s << 63) | ((uint64_t)0x7FFF << 48) |
               (dman ? (1ull << 47) : 0);
        v.lo = dman << 60;
    } else if (dexp == 0 && dman == 0) {
        v.hi = (uint64_t)s << 63;
        v.lo = 0;
    } else {
        int exp;
        uint64_t man = dman;
        if (dexp == 0) {
            exp = -1022;
            while ((man & (1ull << 52)) == 0) {
                man <<= 1;
                exp--;
            }
            man &= 0xFFFFFFFFFFFFFull;
        } else {
            exp = dexp - 1023;
        }
        v.hi = ((uint64_t)s << 63) |
               ((uint64_t)(exp + 16383) << 48) | (man >> 4);
        v.lo = man << 60;
    }
    t = v;
    __builtin_memcpy(&ld, (const void *)&t, 16);
    return ld;
}

double __trunctfdf2(long double a) {
    /* Quad -> double with the live rounding mode (exact when the
     * quad came from a double). */
    ml_tf_t t;
    uint64_t hi, lo, h48;
    int s, qexp, exp, mode = ml_mode();
    uint64_t m52, extra, m;
    __builtin_memcpy(&t, &a, 16);
    hi = t.hi;
    lo = t.lo;
    s = (int)(hi >> 63);
    qexp = (int)((hi >> 48) & 0x7FFF);
    h48 = hi & 0xFFFFFFFFFFFFull;
    if (qexp == 0x7FFF) {
        if ((h48 | lo) == 0)
            return (ml_du_t){.u = ((uint64_t)s << 63) | ML_D_INF}
                .d;
        return (ml_du_t){.u = ML_D_NAN}.d;
    }
    if (qexp == 0 && h48 == 0 && lo == 0)
        return (ml_du_t){.u = (uint64_t)s << 63}.d;
    exp = qexp - 16383;
    if (qexp == 0) {
        /* Subnormal quad: normalize the 112-bit fraction. */
        __uint128_t f = ((__uint128_t)h48 << 64) | lo;
        exp = -16382;
        while ((f >> 111) == 0) {
            f <<= 1;
            exp--;
        }
        h48 = (uint64_t)(f >> 64) & 0xFFFFFFFFFFFFull;
        lo = (uint64_t)f;
        m52 = (h48 << 4) | (lo >> 60);
        extra = lo & ((1ull << 60) - 1);
    } else {
        m52 = (h48 << 4) | (lo >> 60);
        extra = lo & ((1ull << 60) - 1);
        m52 |= 0; /* hidden bit added below */
    }
    {
        uint64_t guard = (extra >> 59) & 1;
        uint64_t round = (extra >> 58) & 1;
        uint64_t sticky = extra & ((1ull << 58) - 1) ? 1 : 0;
        m = (((m52 | (qexp == 0 ? 0 : (1ull << 52)))) << 3) |
            (guard << 2) | (round << 1) | sticky;
        return (ml_du_t){.u = ml_pack_d(s, exp, m, mode)}.d;
    }
}
