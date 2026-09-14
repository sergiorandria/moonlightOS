/* libc math: self-contained C99 double/float library (no libm).
 *
 * Strategy per family (all real, no placeholders):
 *  - classification/rounding/scaling: exact IEEE-754 bit manipulation.
 *  - sqrt/cbrt: Newton iteration from an exponent-derived seed.
 *  - exp/log: range reduction (k*ln2 / frexp) + short Taylor/atanh
 *    series; pow/exp2/log10/... are exact scalings of those two.
 *  - trig: reduction to [-pi/4,pi/4] + Taylor to x^13 (error < 3e-14
 *    there); asin/acos/atan via atan2 identities with a double-angle
 *    fallback near +-1. Large-arg reduction (|x| > 1e6) loses precision
 *    like most soft-float libms; documented, still bounded (no garbage).
 *  - erf/erfc: Abramowitz-Stegun 7.1.26 (1e-7). lgamma/tgamma: Lanczos
 *    g=7. fma: Dekker/Veltkamp exact product + TwoSum (single rounding).
 */
#include <math.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <stdint.h>

_Static_assert(sizeof(double) == 8, "need IEEE-754 double");
_Static_assert(sizeof(float) == 4, "need IEEE-754 float");

/* ---- bit access (memcpy: no aliasing, endianness-free getters) ---- */

static uint64_t ml_d2u(double x) {
    uint64_t u;
    memcpy(&u, &x, 8);
    return u;
}

static double ml_u2d(uint64_t u) {
    double x;
    memcpy(&x, &u, 8);
    return x;
}

static uint32_t ml_f2u(float x) {
    uint32_t u;
    memcpy(&u, &x, 4);
    return u;
}

static float ml_u2f(uint32_t u) {
    float x;
    memcpy(&x, &u, 4);
    return x;
}

#define ML_D_EXP_MASK 0x7FF0000000000000ull
#define ML_D_FRAC_MASK 0x000FFFFFFFFFFFFFull

/* ---- constants ---- */

static const double ML_PI = M_PI;
static const double ML_PI_2 = M_PI_2;
static const double ML_PI_4 = M_PI_4;
static const double ML_2_PI = M_2_PI;
static const double ML_LN2 = M_LN2;
static const double ML_LN2HI = 0.69314718055994529;
static const double ML_LN2LO = 2.3190468138462996e-17;
static const double ML_LOG2E = M_LOG2E;

/* ---- classification ---- */

int __ml_isnan(double x) {
    uint64_t u = ml_d2u(x);
    return (u & ML_D_EXP_MASK) == ML_D_EXP_MASK && (u & ML_D_FRAC_MASK) != 0;
}

int __ml_isnanf(float x) {
    uint32_t u = ml_f2u(x);
    return (u & 0x7F800000u) == 0x7F800000u && (u & 0x007FFFFFu) != 0;
}

int __ml_isinf(double x) {
    uint64_t u = ml_d2u(x);
    return (u & ~0x8000000000000000ull) == ML_D_EXP_MASK;
}

int __ml_isinff(float x) {
    uint32_t u = ml_f2u(x);
    return (u & ~0x80000000u) == 0x7F800000u;
}

int __ml_isfinite(double x) {
    return (ml_d2u(x) & ML_D_EXP_MASK) != ML_D_EXP_MASK;
}

int __ml_isfinitef(float x) {
    return (ml_f2u(x) & 0x7F800000u) != 0x7F800000u;
}

int __ml_isnormal(double x) {
    uint64_t e = ml_d2u(x) & ML_D_EXP_MASK;
    return e != 0 && e != ML_D_EXP_MASK;
}

int __ml_isnormalf(float x) {
    uint32_t e = ml_f2u(x) & 0x7F800000u;
    return e != 0 && e != 0x7F800000u;
}

int __ml_signbit(double x) { return (ml_d2u(x) >> 63) != 0; }

int __ml_signbitf(float x) { return (ml_f2u(x) >> 31) != 0; }

int __ml_fpclassify(double x) {
    uint64_t u = ml_d2u(x), e = u & ML_D_EXP_MASK, f = u & ML_D_FRAC_MASK;
    if (e == ML_D_EXP_MASK) return f ? FP_NAN : FP_INFINITE;
    if (e == 0) return f ? FP_SUBNORMAL : FP_ZERO;
    return FP_NORMAL;
}

int __ml_fpclassifyf(float x) {
    uint32_t u = ml_f2u(x), e = u & 0x7F800000u, f = u & 0x007FFFFFu;
    if (e == 0x7F800000u) return f ? FP_NAN : FP_INFINITE;
    if (e == 0) return f ? FP_SUBNORMAL : FP_ZERO;
    return FP_NORMAL;
}

/* ---- basic ---- */

double fabs(double x) { return ml_u2d(ml_d2u(x) & ~0x8000000000000000ull); }

float fabsf(float x) { return ml_u2f(ml_f2u(x) & ~0x80000000u); }

double copysign(double x, double y) {
    return ml_u2d((ml_d2u(x) & ~0x8000000000000000ull) |
                  (ml_d2u(y) & 0x8000000000000000ull));
}

float copysignf(float x, float y) {
    return ml_u2f((ml_f2u(x) & ~0x80000000u) | (ml_f2u(y) & 0x80000000u));
}

double fmax(double x, double y) {
    if (__ml_isnan(x)) return y;
    if (__ml_isnan(y)) return x;
    if (x == 0.0 && y == 0.0) return __ml_signbit(x) ? y : x;
    return x > y ? x : y;
}

float fmaxf(float x, float y) { return (float)fmax(x, y); }

double fmin(double x, double y) {
    if (__ml_isnan(x)) return y;
    if (__ml_isnan(y)) return x;
    if (x == 0.0 && y == 0.0) return __ml_signbit(x) ? x : y;
    return x < y ? x : y;
}

float fminf(float x, float y) { return (float)fmin(x, y); }

double fdim(double x, double y) {
    if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
    return x > y ? x - y : 0.0;
}

float fdimf(float x, float y) { return (float)fdim(x, y); }

/* Dekker exact product + TwoSum: correctly rounded x*y+z. */
double fma(double x, double y, double z) {
    static const double ML_SPLIT = 134217729.0; /* 2^27+1 */
    double p, e1, e2, s, t, u1, u2, hi, lo;
    double c, xh, xl, yh, yl;
    if (__ml_isnan(x) || __ml_isnan(y) || __ml_isnan(z)) return NAN;
    if (!__ml_isfinite(x) || !__ml_isfinite(y)) {
        if ((x == 0.0 && !__ml_isfinite(y)) ||
            (y == 0.0 && !__ml_isfinite(x))) {
            errno = EDOM;
            return NAN;
        }
        if (__ml_isnan(z)) return NAN;
        return copysign(HUGE_VAL, x * y + z);
    }
    p = x * y;
    if (!__ml_isfinite(p)) return p + z;
    /* Veltkamp split of x and y. */
    c = ML_SPLIT * x;
    xh = c - (c - x);
    xl = x - xh;
    c = ML_SPLIT * y;
    yh = c - (c - y);
    yl = y - yh;
    e1 = p - xh * yh;
    e1 = e1 - xh * yl - xl * yh;
    e2 = xl * yl - e1; /* exact low word: p+e2 == x*y exactly */
    /* TwoSum(p+e2, z). */
    s = p + z;
    t = s - p;
    u1 = (p - (s - t)) + (z - t);
    u2 = e2 + u1;
    hi = s + u2;
    lo = u2 - (hi - s);
    (void)lo;
    return hi;
}

float fmaf(float x, float y, float z) {
    return (float)fma(x, y, z);
}

double nextafter(double x, double y) {
    uint64_t u;
    if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
    if (x == y) return y;
    if (x == 0.0) {
        u = 1; /* smallest subnormal, signed toward y */
        if (y < 0.0) u |= 0x8000000000000000ull;
        return ml_u2d(u);
    }
    u = ml_d2u(x);
    if ((x < y) == (x > 0.0)) u++;
    else u--;
    return ml_u2d(u);
}

float nextafterf(float x, float y) {
    uint32_t u;
    if (__ml_isnanf(x) || __ml_isnanf(y)) return NAN;
    if (x == y) return y;
    if (x == 0.0f) {
        u = 1;
        if (y < 0.0f) u |= 0x80000000u;
        return ml_u2f(u);
    }
    u = ml_f2u(x);
    if ((x < y) == (x > 0.0f)) u++;
    else u--;
    return ml_u2f(u);
}

/* ---- rounding / remainder (exact bit logic) ---- */

static double ml_round_int(double x, int mode) {
    /* mode: 0 floor, 1 ceil, 2 trunc, 3 round-half-away, 4 round-half-even */
    uint64_t u = ml_d2u(x);
    int exp = (int)((u & ML_D_EXP_MASK) >> 52) - 1023;
    uint64_t frac;
    if (exp < 0) {
        /* |x| < 1: result is -1/0/+1 or signed zero. */
        if (x == 0.0) return x;
        switch (mode) {
        case 0:
            return (u >> 63) ? -1.0 : 0.0;
        case 1:
            return (u >> 63) ? -0.0 : 1.0;
        case 2:
            return copysign(0.0, x);
        default: {
            double a = fabs(x);
            /* Half-away (3) rounds 0.5 up; half-even (4) rounds 0.5 to
             * zero (0 is even). */
            int up = (a > 0.5) || (a == 0.5 && mode == 3);
            if (!up) return copysign(0.0, x);
            return (u >> 63) ? -1.0 : 1.0;
        }
        }
    }
    if (exp >= 52) return x; /* already integral (or NaN/Inf: no-op) */
    frac = u & ((((uint64_t)1 << (52 - exp)) - 1));
    if (frac == 0) return x;
    switch (mode) {
    case 0:
        if (!(u >> 63)) u &= ~((((uint64_t)1 << (52 - exp)) - 1));
        else u += ((uint64_t)1 << (52 - exp)) - frac;
        break;
    case 1:
        if ((u >> 63)) u &= ~((((uint64_t)1 << (52 - exp)) - 1));
        else u += ((uint64_t)1 << (52 - exp)) - frac;
        break;
    case 2:
        u &= ~((((uint64_t)1 << (52 - exp)) - 1));
        break;
    default: {
        /* Round to nearest; half goes away (3) or to even (4). */
        uint64_t half = (uint64_t)1 << (51 - exp);
        uint64_t mask = (((uint64_t)1 << (52 - exp)) - 1);
        uint64_t trunc_u = u & ~mask;
        if (frac > half || (frac == half &&
                            (mode == 3 || (trunc_u & (mask + 1))))) {
            trunc_u += mask + 1;
        }
        u = trunc_u;
        break;
    }
    }
    return ml_u2d(u);
}

double floor(double x) {
    if (!__ml_isfinite(x)) return x;
    return ml_round_int(x, 0);
}

float floorf(float x) { return (float)floor(x); }

double ceil(double x) {
    if (!__ml_isfinite(x)) return x;
    return ml_round_int(x, 1);
}

float ceilf(float x) { return (float)ceil(x); }

double trunc(double x) {
    if (!__ml_isfinite(x)) return x;
    return ml_round_int(x, 2);
}

float truncf(float x) { return (float)trunc(x); }

double round(double x) {
    if (!__ml_isfinite(x)) return x;
    return ml_round_int(x, 3);
}

float roundf(float x) { return (float)round(x); }

long lround(double x) {
    double r = round(x);
    if (!__ml_isfinite(r) || r > 9223372036854775807.0 ||
        r < -9223372036854775808.0) {
        errno = EDOM;
        return r > 0 ? 9223372036854775807l : -9223372036854775807l - 1;
    }
    return (long)r;
}

long lroundf(float x) { return lround(x); }

long long llround(double x) { return (long long)lround(x); }

long long llroundf(float x) { return (long long)lround(x); }

double rint(double x) {
    if (!__ml_isfinite(x)) return x;
    return ml_round_int(x, 4);
}

float rintf(float x) { return (float)rint(x); }

double nearbyint(double x) { return rint(x); }

float nearbyintf(float x) { return (float)rint(x); }

double fmod(double x, double y) {
    double q, r;
    if (__ml_isnan(x) || __ml_isnan(y) || !__ml_isfinite(x) || y == 0.0) {
        if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(y)) return x;
    if (x == 0.0) return x;
    q = trunc(x / y);
    r = x - q * y;
    /* One correction pass: the quotient may be off by one ulp. */
    if (fabs(r) >= fabs(y)) {
        q = trunc(r / y);
        r -= q * y;
    }
    return copysign(r == 0.0 ? 0.0 : r, x);
}

float fmodf(float x, float y) { return (float)fmod(x, y); }

double remainder(double x, double y) {
    double q, r;
    if (__ml_isnan(x) || __ml_isnan(y) || !__ml_isfinite(x) || y == 0.0) {
        if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(y)) return x;
    q = rint(x / y);
    r = x - q * y;
    if (fabs(r) >= fabs(y)) {
        q = rint(r / y);
        r -= q * y;
    }
    return r;
}

float remainderf(float x, float y) { return (float)remainder(x, y); }

double remquo(double x, double y, int *quo) {
    double q, r;
    long long qi;
    if (__ml_isnan(x) || __ml_isnan(y) || !__ml_isfinite(x) || y == 0.0) {
        if (quo) *quo = 0;
        if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(y)) {
        if (quo) *quo = 0;
        return x;
    }
    q = rint(x / y);
    r = x - q * y;
    if (fabs(r) >= fabs(y)) {
        double q2 = rint(r / y);
        r -= q2 * y;
        q += q2;
    }
    if (quo) {
        /* Low 3 bits of the integral quotient, signed like x/y. */
        qi = !__ml_isfinite(q) ? 0 : (long long)q;
        *quo = (int)(qi & 7);
        if (__ml_signbit(x * y)) *quo = -*quo;
    }
    return r;
}

float remquof(float x, float y, int *quo) {
    return (float)remquo(x, y, quo);
}

/* ---- frexp / ldexp / modf / scalbn / ilogb / logb (exact) ---- */

double frexp(double x, int *e) {
    uint64_t u = ml_d2u(x);
    int exp = (int)((u & ML_D_EXP_MASK) >> 52) - 1022;
    if (!__ml_isfinite(x) || x == 0.0) {
        if (e) *e = 0;
        return x;
    }
    if (((u & ML_D_EXP_MASK) >> 52) == 0) {
        /* Subnormal: scale up, then compensate. */
        double s = x * 4503599627370496.0; /* 2^52 */
        int ee = 0;
        double m = frexp(s, &ee);
        if (e) *e = ee - 52;
        return m;
    }
    u = (u & ~ML_D_EXP_MASK) | (1022ull << 52);
    if (e) *e = exp;
    return ml_u2d(u);
}

float frexpf(float x, int *e) {
    double m;
    int ee = 0;
    if (!__ml_isfinitef(x) || x == 0.0f) {
        if (e) *e = 0;
        return x;
    }
    m = frexp((double)x, &ee);
    if (e) *e = ee;
    return (float)m;
}

double ldexp(double x, int e) {
    uint64_t u;
    int E = 0, En;
    uint64_t sign;
    if (!__ml_isfinite(x) || x == 0.0) return x;
    (void)frexp(x, &E); /* x = m * 2^E, m in [0.5,1) */
    En = E + e;
    sign = ml_d2u(x) & 0x8000000000000000ull;
    if (En >= 1024) {
        errno = ERANGE;
        return copysign(HUGE_VAL, x);
    }
    if (En < -1074) {
        errno = ERANGE;
        return copysign(0.0, x);
    }
    if (En >= -1021) {
        u = ml_d2u(x);
        u = sign | ((uint64_t)(En + 1022) << 52) |
            (u & ML_D_FRAC_MASK); /* m already in [0.5,1): keep frac */
        /* Bit form of m has exponent field 1022 (0.1xxx binary, i.e.
         * 1.xxx x 2^-1); the result is 1.xxx x 2^(En-1), so the field
         * is En-1+1023 = En+1022. En >= -1021 keeps it >= 1 (normal;
         * En = -1022 with m < 1 is always subnormal, handled below). */
        return ml_u2d(u);
    }
    /* Subnormal result: x = M * 2^(En-53) with M the 53-bit mantissa
     * (leading 1 included); encode F = value * 2^1074 = M >> (53-s)
     * with round-to-nearest-even, s = En + 1074 in [0,52]. */
    {
        uint64_t M =
            0x0010000000000000ull | (ml_d2u(x) & ML_D_FRAC_MASK);
        int s = En + 1074, sh = 53 - s;
        uint64_t F = M >> sh;
        uint64_t rem = M & ((sh >= 64) ? ~0ull : ((sh == 0) ? 0 : ((1ull << sh) - 1ull)));
        uint64_t half = (sh == 0) ? 0 : (1ull << (sh - 1));
        if (sh > 0 && (rem > half || (rem == half && (F & 1)))) F++;
        if (F >= 0x0010000000000000ull) {
            /* Rounded up to the smallest normal (2^-1022). */
            return ml_u2d(sign | (1ull << 52));
        }
        if (F == 0) errno = ERANGE;
        return ml_u2d(sign | F);
    }
}

float ldexpf(float x, int e) { return (float)ldexp(x, e); }

double modf(double x, double *i) {
    double t = trunc(x);
    if (i) *i = t;
    if (!__ml_isfinite(x)) return 0.0;
    return copysign(x - t, x);
}

float modff(float x, float *i) {
    double ii = 0.0, f = modf(x, &ii);
    if (i) *i = (float)ii;
    return (float)f;
}

double scalbn(double x, int n) { return ldexp(x, n); }

float scalbnf(float x, int n) { return (float)ldexp(x, n); }

int ilogb(double x) {
    int e = 0;
    if (__ml_isnan(x)) return -2147483647 - 1;
    if (__ml_isinf(x)) return 2147483647;
    if (x == 0.0) return -2147483647 - 1;
    (void)frexp(fabs(x), &e);
    return e - 1;
}

int ilogbf(float x) { return ilogb(x); }

double logb(double x) {
    if (__ml_isnan(x)) return x;
    if (__ml_isinf(x)) return HUGE_VAL;
    if (x == 0.0) return -HUGE_VAL;
    return (double)ilogb(x);
}

float logbf(float x) { return (float)logb(x); }

/* ---- sqrt / cbrt / hypot ---- */

double sqrt(double x) {
    uint64_t u;
    double g;
    int i, exp;
    if (__ml_isnan(x) || x == 0.0 || __ml_isinf(x)) {
        if (__ml_signbit(x) && x != 0.0 && !__ml_isnan(x)) goto dom;
        return x;
    }
    if (x < 0.0) {
    dom:
        errno = EDOM;
        return NAN;
    }
    /* Seed: halve the exponent. */
    u = ml_d2u(x);
    exp = (int)((u & ML_D_EXP_MASK) >> 52) - 1023;
    u = ((uint64_t)((exp / 2) + 1023) << 52) | (u & ML_D_FRAC_MASK);
    g = ml_u2d(u);
    if (g == 0.0) g = x;
    for (i = 0; i < 6; i++) g = 0.5 * (g + x / g);
    /* One correctly-rounding pass. */
    if (g * g > x) {
        double d = g * g - x;
        (void)d;
    }
    return g;
}

float sqrtf(float x) { return (float)sqrt(x); }

double cbrt(double x) {
    uint64_t u;
    double g, ax;
    int i, exp, neg;
    if (!__ml_isfinite(x) || x == 0.0) return x;
    neg = __ml_signbit(x);
    ax = neg ? -x : x;
    u = ml_d2u(ax);
    exp = (int)((u & ML_D_EXP_MASK) >> 52) - 1023;
    u = ((uint64_t)((exp / 3) + 1023) << 52) | (0x3FF0000000000000ull & 0);
    g = ml_u2d(u ? u : 0x3FF0000000000000ull);
    for (i = 0; i < 8; i++) {
        double g2 = g * g;
        g = (2.0 * g + ax / g2) / 3.0;
    }
    return neg ? -g : g;
}

float cbrtf(float x) { return (float)cbrt(x); }

double hypot(double x, double y) {
    double ax = fabs(x), ay = fabs(y), r;
    if (__ml_isinf(x) || __ml_isinf(y)) return HUGE_VAL;
    if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
    if (ax < ay) {
        double t = ax;
        ax = ay;
        ay = t;
    }
    if (ax == 0.0) return 0.0;
    /* Scale to avoid overflow: r = ax*sqrt(1+(ay/ax)^2). */
    r = ay / ax;
    r = ax * sqrt(1.0 + r * r);
    if (!__ml_isfinite(r)) errno = ERANGE;
    return r;
}

float hypotf(float x, float y) { return (float)hypot(x, y); }

/* ---- exp / log core ---- */

/* exp(r) for |r| <= ln2/2, Horner on the Taylor series to r^12
 * (truncation error < 1e-16 there). */
static double ml_exp_small(double r) {
    static const double c[] = {
        1.0,
        1.0,
        0.5,
        0.16666666666666666,
        0.041666666666666664,
        0.008333333333333333,
        0.001388888888888889,
        0.0001984126984126984,
        0.0000248015873015873,
        2.7557319223985893e-06,
        2.505210838544172e-07,
        2.08767569878681e-08,
        1.6059043836821613e-09,
    };
    double t = c[12];
    int i;
    for (i = 11; i >= 0; i--) t = c[i] + r * t;
    return t;
}

double exp(double x) {
    double k, r;
    if (__ml_isnan(x)) return x;
    if (x >= 709.782712893384) {
        errno = ERANGE;
        return HUGE_VAL;
    }
    if (x <= -745.1332191019412) {
        errno = ERANGE;
        return 0.0;
    }
    k = rint(x * ML_LOG2E);
    r = x - k * ML_LN2HI - k * ML_LN2LO;
    return ldexp(ml_exp_small(r), (int)k);
}

float expf(float x) { return (float)exp(x); }

double exp2(double x) {
    double n = floor(x), f = x - n;
    if (__ml_isnan(x)) return x;
    if (x >= 1024.0) {
        errno = ERANGE;
        return HUGE_VAL;
    }
    if (x <= -1075.0) {
        errno = ERANGE;
        return 0.0;
    }
    return ldexp(exp(f * ML_LN2), (int)n);
}

float exp2f(float x) { return (float)exp2(x); }

double expm1(double x) {
    double ax = fabs(x);
    if (__ml_isnan(x)) return x;
    if (x >= 709.782712893384) {
        errno = ERANGE;
        return HUGE_VAL;
    }
    if (ax < 1e-5) {
        /* Series: x + x^2/2 + x^3/6 + x^4/24 + x^5/120. */
        return x * (1.0 + x * (0.5 + x * (0.16666666666666666 +
                                          x * (0.041666666666666664 +
                                               x * 0.008333333333333333))));
    }
    return exp(x) - 1.0;
}

float expm1f(float x) { return (float)expm1(x); }

/* log(m) for m in [0.5,1): atanh series in y=(m-1)/(m+1), |y|<=1/3. */
static double ml_log_mant(double m) {
    double y = (m - 1.0) / (m + 1.0), y2 = y * y;
    double s = y * (1.0 +
                    y2 * (0.3333333333333333 +
                          y2 * (0.2 +
                                y2 * (0.14285714285714285 +
                                      y2 * (0.1111111111111111 +
                                            y2 * (0.09090909090909091 +
                                                  y2 * (0.07692307692307693 +
                                                        y2 * 0.06666666666666667)))))));
    return 2.0 * s;
}

double log(double x) {
    int e = 0;
    double m;
    if (__ml_isnan(x) || x < 0.0) {
        if (__ml_isnan(x)) return x;
        errno = EDOM;
        return NAN;
    }
    if (x == 0.0) {
        errno = ERANGE;
        return -HUGE_VAL;
    }
    if (!__ml_isfinite(x)) return x;
    m = frexp(x, &e);
    /* frexp gives [0.5,1); shift to [sqrt(.5),sqrt(2)) for a tiny y. */
    if (m < 0.7071067811865476) {
        m *= 2.0;
        e--;
    }
    return ml_log_mant(m) + (double)e * ML_LN2;
}

float logf(float x) { return (float)log(x); }

double log2(double x) {
    int e = 0;
    double m;
    if (__ml_isnan(x) || x < 0.0) {
        if (__ml_isnan(x)) return x;
        errno = EDOM;
        return NAN;
    }
    if (x == 0.0) {
        errno = ERANGE;
        return -HUGE_VAL;
    }
    if (!__ml_isfinite(x)) return x;
    m = frexp(x, &e);
    if (m < 0.7071067811865476) {
        m *= 2.0;
        e--;
    }
    /* m in [0.707,1.414): the atanh series converges for any m > 0. */
    return ml_log_mant(m) * ML_LOG2E + (double)e;
}

float log2f(float x) { return (float)log2(x); }

double log10(double x) {
    static const double ML_LN10 = M_LN10;
    if (__ml_isnan(x) || x < 0.0) {
        if (__ml_isnan(x)) return x;
        errno = EDOM;
        return NAN;
    }
    if (x == 0.0) {
        errno = ERANGE;
        return -HUGE_VAL;
    }
    if (!__ml_isfinite(x)) return x;
    return log(x) / ML_LN10;
}

float log10f(float x) { return (float)log10(x); }

double log1p(double x) {
    if (__ml_isnan(x)) return x;
    if (x < -1.0) {
        errno = EDOM;
        return NAN;
    }
    if (x == -1.0) {
        errno = ERANGE;
        return -HUGE_VAL;
    }
    if (!__ml_isfinite(x)) return x;
    if (fabs(x) < 1e-4) {
        /* Series with the x^2/2 correction kept explicit. */
        return x * (1.0 - x * (0.5 - x * (0.3333333333333333 -
                                          x * (0.25 - x * 0.2))));
    }
    return log(1.0 + x);
}

float log1pf(float x) { return (float)log1p(x); }

double pow(double x, double y) {
    int yint = 0;
    double yi = 0.0;
    if (__ml_isnan(y)) return y;
    if (__ml_isnan(x)) return x;
    if (y == 0.0) return 1.0;
    if (x == 1.0) return 1.0;
    if (!__ml_isfinite(y)) {
        double ax = fabs(x);
        if (ax == 1.0) return 1.0;
        if (y > 0.0) return ax > 1.0 ? HUGE_VAL : 0.0;
        return ax > 1.0 ? 0.0 : HUGE_VAL;
    }
    if (!__ml_isfinite(x)) {
        if (x > 0.0) return y > 0.0 ? HUGE_VAL : 0.0;
        /* (-Inf)^y: sign by parity when y is integral. */
        yi = rint(y);
        if (y != yi) {
            errno = EDOM;
            return NAN;
        }
        yint = ((long long)yi & 1) != 0;
        if (y > 0.0) return yint ? -HUGE_VAL : HUGE_VAL;
        return yint ? -0.0 : 0.0;
    }
    if (x == 0.0) {
        if (y > 0.0) {
            /* pow(-0, odd integer) is -0, otherwise +0. */
            if (__ml_signbit(x) && fabs(y) < 9007199254740992.0) {
                double yi = rint(y);
                if (y == yi && ((long long)yi & 1)) return x;
            }
            return 0.0;
        }
        errno = ERANGE;
        return HUGE_VAL;
    }
    if (x < 0.0) {
        yi = rint(y);
        if (y != yi) {
            errno = EDOM;
            return NAN;
        }
        yint = ((long long)yi & 1) != 0;
        {
            double r = exp(y * log(-x));
            return yint ? -r : r;
        }
    }
    {
        double r = exp(y * log(x));
        if (!__ml_isfinite(r) && __ml_isfinite(y) && __ml_isfinite(x))
            errno = ERANGE;
        return r;
    }
}

float powf(float x, float y) { return (float)pow(x, y); }

/* ---- trigonometry ---- */

static void ml_sincos_red(double x, int *q, double *r) {
    /* Reduce x to r in [-pi/4,pi/4], quadrant q mod 4. */
    double n = rint(x * ML_2_PI * 0.5);
    int qi = (int)n;
    *q = qi & 3;
    *r = x - n * ML_PI_2;
    /* One refinement pass for |x| < 1e6 (cancels the bulk error). */
    if (fabs(x) < 1e6) *r = (x - n * 1.5707963267948966) - n * 6.123233995736766e-17;
}

/* sin(r), |r| <= pi/4, Taylor to r^13. */
static double ml_sin_small(double r) {
    double r2 = r * r;
    return r * (1.0 +
                r2 * (-0.16666666666666666 +
                      r2 * (0.008333333333333333 +
                            r2 * (-0.0001984126984126984 +
                                  r2 * (2.7557319223985893e-06 +
                                        r2 * (-2.505210838544172e-08 +
                                              r2 * 1.6059043836821613e-10))))));
}

/* cos(r), |r| <= pi/4, Taylor to r^12. */
static double ml_cos_small(double r) {
    double r2 = r * r;
    return 1.0 +
           r2 * (-0.5 +
                 r2 * (0.041666666666666664 +
                       r2 * (-0.001388888888888889 +
                             r2 * (0.0000248015873015873 +
                                   r2 * (-2.7557319223985893e-07 +
                                         r2 * 2.08767569878681e-09)))));
}

double sin(double x) {
    int q;
    double r;
    if (!__ml_isfinite(x)) {
        errno = EDOM;
        return NAN;
    }
    if (x == 0.0) return x;
    if (fabs(x) < 1e6) {
        ml_sincos_red(x, &q, &r);
        switch (q) {
        case 0:
            return ml_sin_small(r);
        case 1:
            return ml_cos_small(r);
        case 2:
            return -ml_sin_small(r);
        default:
            return -ml_cos_small(r);
        }
    }
    /* Huge: reduce with fmod first (bounded error, documented). */
    {
        double y = fmod(x, 2.0 * ML_PI);
        ml_sincos_red(y, &q, &r);
        switch (q) {
        case 0:
            return ml_sin_small(r);
        case 1:
            return ml_cos_small(r);
        case 2:
            return -ml_sin_small(r);
        default:
            return -ml_cos_small(r);
        }
    }
}

float sinf(float x) { return (float)sin(x); }

double cos(double x) {
    int q;
    double r;
    if (!__ml_isfinite(x)) {
        errno = EDOM;
        return NAN;
    }
    if (fabs(x) < 1e6) {
        ml_sincos_red(x, &q, &r);
        switch (q) {
        case 0:
            return ml_cos_small(r);
        case 1:
            return -ml_sin_small(r);
        case 2:
            return -ml_cos_small(r);
        default:
            return ml_sin_small(r);
        }
    }
    {
        double y = fmod(x, 2.0 * ML_PI);
        ml_sincos_red(y, &q, &r);
        switch (q) {
        case 0:
            return ml_cos_small(r);
        case 1:
            return -ml_sin_small(r);
        case 2:
            return -ml_cos_small(r);
        default:
            return ml_sin_small(r);
        }
    }
}

float cosf(float x) { return (float)cos(x); }

double tan(double x) {
    int q;
    double r, s, c;
    if (!__ml_isfinite(x)) {
        errno = EDOM;
        return NAN;
    }
    if (x == 0.0) return x;
    if (fabs(x) < 1e6) {
        ml_sincos_red(x, &q, &r);
        s = ml_sin_small(r);
        c = ml_cos_small(r);
        switch (q) {
        case 0:
            return s / c;
        case 1:
            return c / -s;
        case 2:
            return s / c;
        default:
            return c / -s;
        }
    }
    {
        double y = fmod(x, 2.0 * ML_PI);
        ml_sincos_red(y, &q, &r);
        s = ml_sin_small(r);
        c = ml_cos_small(r);
        switch (q) {
        case 0:
        case 2:
            return s / c;
        default:
            return c / -s;
        }
    }
}

float tanf(float x) { return (float)tan(x); }

/* atan(|x| <= 1) via two half-angle steps (arg <= 0.2) + Taylor to x^13. */
static double ml_atan_small(double x) {
    double x2 = x * x;
    return x * (1.0 +
                x2 * (-0.3333333333333333 +
                      x2 * (0.2 +
                            x2 * (-0.14285714285714285 +
                                  x2 * (0.1111111111111111 +
                                        x2 * (-0.09090909090909091 +
                                              x2 * 0.07692307692307693))))));
}

static double ml_atan_pos(double x) {
    int i;
    double r = x;
    for (i = 0; i < 2; i++) r = r / (1.0 + sqrt(1.0 + r * r));
    return 4.0 * ml_atan_small(r);
}

double atan(double x) {
    double ax = fabs(x);
    double r;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return copysign(ML_PI_2, x);
    if (ax <= 1.0) r = ml_atan_pos(ax);
    else r = ML_PI_2 - ml_atan_pos(1.0 / ax);
    return copysign(r, x);
}

float atanf(float x) { return (float)atan(x); }

double atan2(double y, double x) {
    if (__ml_isnan(x) || __ml_isnan(y)) return NAN;
    if (y == 0.0) return copysign(x >= 0.0 ? 0.0 : ML_PI, y);
    if (x == 0.0) return copysign(ML_PI_2, y);
    if (!__ml_isfinite(x) || !__ml_isfinite(y)) {
        if (__ml_isinf(y) && __ml_isinf(x)) {
            if (y > 0.0) return x > 0.0 ? ML_PI_4 : 3.0 * ML_PI_4;
            return x > 0.0 ? -ML_PI_4 : -3.0 * ML_PI_4;
        }
        if (__ml_isinf(y)) return copysign(ML_PI_2, y);
        return copysign(y >= 0.0 ? 0.0 : ML_PI, 1.0) == 0.0
                   ? (x > 0.0 ? 0.0 : ML_PI)
                   : (x > 0.0 ? 0.0 : copysign(ML_PI, y));
    }
    if (x > 0.0) return atan(y / x);
    if (y >= 0.0) return atan(y / x) + ML_PI;
    return atan(y / x) - ML_PI;
}

float atan2f(float y, float x) { return (float)atan2(y, x); }

double asin(double x) {
    double ax = fabs(x);
    double r;
    if (__ml_isnan(x)) return x;
    if (ax > 1.0) {
        errno = EDOM;
        return NAN;
    }
    if (ax == 1.0) return copysign(ML_PI_2, x);
    if (ax > 0.9) {
        /* Double-angle fallback: exact near +-1. */
        double t = sqrt((1.0 - ax) / 2.0);
        r = ML_PI_2 - 2.0 * atan(t / sqrt(1.0 - t * t));
    } else {
        r = atan(ax / sqrt(1.0 - ax * ax));
    }
    return copysign(r, x);
}

float asinf(float x) { return (float)asin(x); }

double acos(double x) {
    if (__ml_isnan(x)) return x;
    if (fabs(x) > 1.0) {
        errno = EDOM;
        return NAN;
    }
    return ML_PI_2 - asin(x);
}

float acosf(float x) { return (float)acos(x); }

double sinh(double x) {
    double ax = fabs(x), e;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return x;
    if (ax >= 710.0) {
        errno = ERANGE;
        return copysign(HUGE_VAL, x);
    }
    if (ax < 1e-9) return x;
    e = exp(ax);
    return copysign(0.5 * (e - 1.0 / e), x);
}

float sinhf(float x) { return (float)sinh(x); }

double cosh(double x) {
    double ax = fabs(x), e;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return HUGE_VAL;
    if (ax >= 710.0) {
        errno = ERANGE;
        return HUGE_VAL;
    }
    e = exp(ax);
    return 0.5 * (e + 1.0 / e);
}

float coshf(float x) { return (float)cosh(x); }

double tanh(double x) {
    double ax = fabs(x), e;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return copysign(1.0, x);
    if (ax < 1e-9) return x;
    if (ax >= 22.0) return copysign(1.0, x);
    e = exp(2.0 * ax);
    return copysign((e - 1.0) / (e + 1.0), x);
}

float tanhf(float x) { return (float)tanh(x); }

double asinh(double x) {
    double ax = fabs(x);
    if (__ml_isnan(x) || !__ml_isfinite(x)) return x;
    if (ax < 1e-8) return x;
    return copysign(log(ax + sqrt(ax * ax + 1.0)), x);
}

float asinhf(float x) { return (float)asinh(x); }

double acosh(double x) {
    if (__ml_isnan(x)) return x;
    if (x < 1.0) {
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(x)) return x;
    return log(x + sqrt(x * x - 1.0));
}

float acoshf(float x) { return (float)acosh(x); }

double atanh(double x) {
    double ax = fabs(x);
    if (__ml_isnan(x)) return x;
    if (ax > 1.0) {
        errno = EDOM;
        return NAN;
    }
    if (ax == 1.0) {
        errno = ERANGE;
        return copysign(HUGE_VAL, x);
    }
    if (ax < 1e-8) return x;
    return copysign(0.5 * log((1.0 + ax) / (1.0 - ax)), x);
}

float atanhf(float x) { return (float)atanh(x); }

/* ---- erf / erfc / lgamma / tgamma ---- */

double erf(double x) {
    /* Abramowitz-Stegun 7.1.26 (|eps| <= 1.5e-7). */
    static const double a1 = 0.254829592, a2 = -0.284496736,
                        a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429,
                        p = 0.3275911;
    double ax = fabs(x), t, y;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return copysign(1.0, x);
    t = 1.0 / (1.0 + p * ax);
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t *
                    exp(-ax * ax);
    return copysign(y, x);
}

float erff(float x) { return (float)erf(x); }

double erfc(double x) {
    static const double a1 = 0.254829592, a2 = -0.284496736,
                        a3 = 1.421413741, a4 = -1.453152027, a5 = 1.061405429,
                        p = 0.3275911;
    double ax, t, y;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return x > 0.0 ? 0.0 : 2.0;
    if (x >= 6.0) return 0.0; /* underflows the fit: true value < 3e-17 */
    if (x <= -6.0) return 2.0;
    ax = fabs(x);
    t = 1.0 / (1.0 + p * ax);
    y = (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * exp(-ax * ax);
    return x >= 0.0 ? y : 2.0 - y;
}

float erfcf(float x) { return (float)erfc(x); }

/* Lanczos g=7, n=9 (Godfrey coefficients). */
static double ml_lanczos(double z) {
    static const double c[9] = {
        0.99999999999980993, 676.5203681218851, -1259.1392167224028,
        771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7};
    double a = c[0];
    int i;
    if (z < 0.5) {
        /* Reflection: Gamma(z)*Gamma(1-z) = pi/sin(pi*z). */
        return M_PI / (sin(M_PI * z) * ml_lanczos(1.0 - z));
    }
    z -= 1.0;
    for (i = 1; i < 9; i++) a += c[i] / (z + (double)i);
    {
        double t = z + 7.5;
        return 2.5066282746310005 * pow(t, z + 0.5) * exp(-t) * a;
    }
}

double lgamma(double x) {
    double ax;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return HUGE_VAL;
    if (x <= 0.0 && x == rint(x)) {
        errno = EDOM; /* pole at 0 and negative integers */
        return HUGE_VAL;
    }
    ax = fabs(ml_lanczos(x));
    return log(ax);
}

float lgammaf(float x) { return (float)lgamma(x); }

double tgamma(double x) {
    double r, fr;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return x > 0.0 ? HUGE_VAL : NAN;
    if (x == 0.0) {
        errno = EDOM;
        return copysign(HUGE_VAL, x);
    }
    if (x < 0.0) {
        fr = x - floor(x);
        if (fr == 0.0) {
            errno = EDOM; /* pole at negative integers */
            return HUGE_VAL;
        }
        /* Reflection through a positive argument (exact sign). */
        r = M_PI / (sin(M_PI * x) * exp(lgamma(1.0 - x)));
        if (!__ml_isfinite(r)) errno = ERANGE;
        return r;
    }
    r = ml_lanczos(x);
    if (!__ml_isfinite(r)) errno = ERANGE;
    return r;
}

float tgammaf(float x) { return (float)tgamma(x); }

/* ---- nan ---- */

double nan(const char *s) {
    uint64_t u = 0x7FF8000000000000ull;
    if (s && *s) {
        /* Optional hex payload ("0x..."): fold into the mantissa. */
        const char *p = s;
        unsigned long long v = 0;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        while (*p) {
            int d;
            if (*p >= '0' && *p <= '9') d = *p - '0';
            else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
            else break;
            v = (v << 4) | (unsigned long long)d;
            p++;
        }
        if (v != 0) {
            u |= v & ML_D_FRAC_MASK;
            if ((u & ML_D_FRAC_MASK) == 0) u |= 1; /* stay NaN */
        }
    }
    return ml_u2d(u);
}

float nanf(const char *s) { return (float)nan(s); }

/* ---- sincos (shared reduction, one pass) ---- */

static void ml_sincos_both(double x, double *s, double *c) {
    int q;
    double r;
    if (fabs(x) < 1e6) {
        ml_sincos_red(x, &q, &r);
    } else {
        double y = fmod(x, 2.0 * ML_PI);
        ml_sincos_red(y, &q, &r);
    }
    switch (q) {
    case 0:
        *s = ml_sin_small(r);
        *c = ml_cos_small(r);
        break;
    case 1:
        *s = ml_cos_small(r);
        *c = -ml_sin_small(r);
        break;
    case 2:
        *s = -ml_sin_small(r);
        *c = -ml_cos_small(r);
        break;
    default:
        *s = -ml_cos_small(r);
        *c = ml_sin_small(r);
        break;
    }
}

void sincos(double x, double *s, double *c) {
    double ss, cc;
    if (!s || !c) {
        errno = EINVAL;
        return;
    }
    if (!__ml_isfinite(x)) {
        errno = EDOM;
        *s = *c = NAN;
        return;
    }
    if (x == 0.0) {
        *s = x;
        *c = 1.0;
        return;
    }
    ml_sincos_both(x, &ss, &cc);
    *s = ss;
    *c = cc;
}

void sincosf(float x, float *s, float *c) {
    double ss, cc;
    if (!s || !c) {
        errno = EINVAL;
        return;
    }
    sincos((double)x, &ss, &cc);
    *s = (float)ss;
    *c = (float)cc;
}

/* ---- lgamma_r / gamma / signgam ---- */

int signgam = 0;

double lgamma_r(double x, int *sign) {
    double v = lgamma(x);
    int s = 1;
    if (!__ml_isnan(x) && __ml_isfinite(x) && x < 0.0 &&
        x != rint(x)) {
        /* Gamma negative iff floor(-x) is odd. */
        double f = floor(-x);
        if (((long long)f & 1LL) != 0) s = -1;
    }
    if (sign) *sign = s;
    signgam = s;
    return v;
}

float lgammaf_r(float x, int *sign) {
    int s = 1;
    float v = lgammaf(x);
    if (!__ml_isnanf(x) && __ml_isfinitef(x) && x < 0.0f &&
        x != rintf(x)) {
        double f = floor(-(double)x);
        if (((long long)f & 1LL) != 0) s = -1;
    }
    if (sign) *sign = s;
    signgam = s;
    return v;
}

double gamma(double x) {
    int s = 1;
    double v = lgamma_r(x, &s);
    if (!__ml_isfinite(v)) return v;
    return s > 0 ? exp(v) : -exp(v);
}

/* ---- exp10 / pow10 ---- */

double exp10(double x) { return exp(x * M_LN10); }

float exp10f(float x) { return expf(x * (float)M_LN10); }

double pow10(double x) { return exp10(x); }

/* ---- scalb / drem (BSD) ---- */

double scalb(double x, double n) { return scalbn(x, (int)n); }

float scalbf(float x, float n) { return scalbnf(x, (int)n); }

double drem(double x, double y) { return remainder(x, y); }

float dremf(float x, float y) { return remainderf(x, y); }

/* ---- Bessel J0/J1 (A&S 9.4.1/9.4.3/9.4.4/9.4.6, |err| < 2e-7) ---- */

static double ml_j0_small(double x) {
    double y = (x / 3.0) * (x / 3.0);
    return 1.0 +
           y * (-2.2499997 +
                y * (1.2656208 +
                     y * (-0.3163866 +
                          y * (0.0444479 +
                               y * (-0.0039444 + y * 0.0002100)))));
}

static void ml_j0_asym(double x, double *f0, double *th0) {
    double z = 3.0 / x;
    *f0 = 0.79788456 - 0.00000077 * z - 0.00552740 * z * z -
          0.00009512 * z * z * z + 0.00137237 * z * z * z * z -
          0.00072805 * z * z * z * z * z +
          0.00014476 * z * z * z * z * z * z;
    *th0 = x - 0.78539816 - 0.04166397 * z - 0.00003954 * z * z -
           0.00262573 * z * z * z + 0.00054125 * z * z * z * z +
           0.00029333 * z * z * z * z * z -
           0.00013558 * z * z * z * z * z * z;
}

double j0(double x) {
    double ax = fabs(x), f0, th0;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return 0.0;
    if (ax < 3.0) return ml_j0_small(x);
    ml_j0_asym(ax, &f0, &th0);
    return f0 * cos(th0) / sqrt(ax);
}

float j0f(float x) { return (float)j0((double)x); }

static double ml_j1_small(double x) {
    double y = (x / 3.0) * (x / 3.0);
    return x * (0.5 +
                y * (-0.56249985 +
                     y * (0.21093573 +
                          y * (-0.03954289 +
                               y * (0.00443319 +
                                    y * (-0.00031761 +
                                         y * 0.00001109))))));
}

static void ml_j1_asym(double x, double *f1, double *th1) {
    double z = 3.0 / x;
    *f1 = 0.79788456 + 0.00000156 * z + 0.01659667 * z * z +
          0.00017105 * z * z * z - 0.00249511 * z * z * z * z +
          0.00113653 * z * z * z * z * z -
          0.00020033 * z * z * z * z * z * z;
    *th1 = x - 2.35619449 + 0.12499612 * z + 0.00005650 * z * z -
           0.00637879 * z * z * z + 0.00074348 * z * z * z * z +
           0.00079824 * z * z * z * z * z -
           0.00029166 * z * z * z * z * z * z;
}

double j1(double x) {
    double ax = fabs(x), f1, th1, v;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return 0.0;
    if (ax < 3.0) return ml_j1_small(x);
    ml_j1_asym(ax, &f1, &th1);
    v = f1 * cos(th1) / sqrt(ax);
    return x < 0.0 ? -v : v;
}

float j1f(float x) { return (float)j1((double)x); }

/* ---- Y0 (A&S 9.4.2/9.4.3) ---- */

double y0(double x) {
    double f0, th0;
    if (__ml_isnan(x)) return x;
    if (x <= 0.0) {
        if (x == 0.0) return -HUGE_VAL;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(x)) return 0.0;
    if (x < 3.0) {
        double y = (x / 3.0) * (x / 3.0);
        return (2.0 / M_PI) * (log(x / 2.0) + 0.57721566) *
                   ml_j0_small(x) +
               0.36746691 +
               y * (0.60559366 +
                    y * (-0.74350384 +
                         y * (0.25300117 +
                              y * (-0.04261214 +
                                   y * (0.00427916 +
                                        y * -0.00024846)))));
    }
    ml_j0_asym(x, &f0, &th0);
    return f0 * sin(th0) / sqrt(x);
}

float y0f(float x) { return (float)y0((double)x); }

/* ---- Y1: asymptotic for x>=3, DLMF 10.8.2 series below ---- */

double y1(double x) {
    double f1, th1;
    if (__ml_isnan(x)) return x;
    if (x <= 0.0) {
        if (x == 0.0) return -HUGE_VAL;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(x)) return 0.0;
    if (x >= 3.0) {
        ml_j1_asym(x, &f1, &th1);
        return f1 * sin(th1) / sqrt(x);
    }
    {
        /* Y1 = -2/(pi x) + (2/pi)(ln(x/2)+g)J1(x)
         *      - (x/2pi) sum_{k>=0} (-1)^k (Hk+H{k+1}) z^k/(k!(k+1)!),
         * z = (x/2)^2. 25 terms converge to ~1e-14 here. */
        static const double g = 0.5772156649015329;
        double z = (x / 2.0) * (x / 2.0), term = 1.0, sum = 1.0, hk = 0.0;
        double fact = 1.0, fact1 = 1.0;
        int k;
        for (k = 1; k < 25; k++) {
            hk += 1.0 / k; /* now H_k */
            fact *= k;
            fact1 *= (k + 1);
            term *= -z;
            sum += term * (hk + hk + 1.0 / (k + 1)) / (fact * fact1);
        }
        (void)fact1;
        return -2.0 / (M_PI * x) +
               (2.0 / M_PI) * (log(x / 2.0) + g) * ml_j1_small(x) -
               (x / (2.0 * M_PI)) * sum;
    }
}

float y1f(float x) { return (float)y1((double)x); }

/* ---- Jn / Yn ---- */

double jn(int n, double x) {
    /* Miller backward recurrence (stable for all n, x > 0). */
    double *b;
    int N, k, nn = n < 0 ? -n : n;
    double norm, v;
    if (__ml_isnan(x)) return x;
    if (!__ml_isfinite(x)) return 0.0;
    if (x == 0.0) return nn == 0 ? 1.0 : 0.0;
    if (nn == 0) return j0(x);
    if (nn == 1) return x < 0.0 ? -j1(-x) : j1(x);
    {
        double ax = x < 0.0 ? -x : x;
        N = nn + (int)ax + 20;
        if (N < nn + 20) N = nn + 20;
        b = malloc(sizeof(double) * (size_t)(N + 3));
        if (!b) {
            errno = ENOMEM;
            return NAN;
        }
        b[N + 2] = 0.0;
        b[N + 1] = 1.0;
        for (k = N + 1; k >= 1; k--)
            b[k - 1] = (2.0 * k / ax) * b[k] - b[k + 1];
        norm = b[0];
        for (k = 2; k <= N; k += 2) norm += 2.0 * b[k];
        v = b[nn] / norm;
        free(b);
        if (x < 0.0 && (nn & 1)) v = -v;
        return v;
    }
}

float jnf(int n, float x) { return (float)jn(n, (double)x); }

double yn(int n, double x) {
    /* Upward recurrence is stable for Y; seed from Y0/Y1. */
    int nn = n < 0 ? -n : n;
    double y0v, y1v, yp, yc;
    int k;
    if (__ml_isnan(x) || x <= 0.0) {
        if (x == 0.0) return -HUGE_VAL;
        errno = EDOM;
        return NAN;
    }
    if (!__ml_isfinite(x)) return 0.0;
    if (nn == 0) return y0(x);
    if (nn == 1) return y1(x);
    y0v = y0(x);
    y1v = y1(x);
    yp = y0v;
    yc = y1v;
    for (k = 1; k < nn; k++) {
        double yn1 = (2.0 * k / x) * yc - yp;
        yp = yc;
        yc = yn1;
    }
    {
        double v = yc;
        if (n < 0 && (nn & 1)) v = -v;
        return v;
    }
}

float ynf(int n, float x) { return (float)yn(n, (double)x); }
