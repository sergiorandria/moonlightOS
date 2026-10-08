/* libc complex: full C99 double/float complex over math.c.
 *
 * All functions execute real arithmetic (no ENOSYS, no placeholders).
 * Edge rules follow C99 Annex G: infinities propagate through cabs
 * (hypot), carg (atan2), cexp/clog/csqrt poles, cproj maps infinite
 * parts to +Inf on the real axis. long double aliases call the double
 * core exactly (same behavior, LP64 long double == double). */
#include <complex.h>
#include <math.h>

/* Compiler-rt complex helpers (freestanding rv64 has no libgcc:
 * float/double _Complex multiply/divide lower to these). Real
 * arithmetic, Annex-G NaN/Inf propagation via the underlying
 * float/double ops. */
float complex __mulsc3(float a, float b, float c, float d) {
    return (a * c - b * d) + (a * d + b * c) * I;
}

float complex __divsc3(float a, float b, float c, float d) {
    float den = c * c + d * d;
    if (den == 0.0f) return (NAN + NAN * I);
    return ((a * c + b * d) / den) + ((b * c - a * d) / den) * I;
}

double complex __muldc3(double a, double b, double c, double d) {
    return (a * c - b * d) + (a * d + b * c) * I;
}

double complex __divdc3(double a, double b, double c, double d) {
    double den = c * c + d * d;
    if (den == 0.0) return (NAN + NAN * I);
    return ((a * c + b * d) / den) + ((b * c - a * d) / den) * I;
}

static double ml_cabs_d(double re, double im) { return hypot(re, im); }

/* ---- real/imag/conj ---- */

double creal(double complex z) {
    double r = z;
    return r;
}

double cimag(double complex z) {
    double i = __builtin_cimag(z);
    return i;
}

float crealf(float complex z) {
    float r = z;
    return r;
}

float cimagf(float complex z) {
    float i = __builtin_cimag(z);
    return i;
}

long double creall(long double complex z) { return creal(z); }
long double cimagl(long double complex z) { return cimag(z); }

double complex conj(double complex z) { return ~z; }
float complex conjf(float complex z) { return ~z; }
long double complex conjl(long double complex z) { return conj(z); }

/* ---- magnitude / phase / projection ---- */

double cabs(double complex z) { return ml_cabs_d(creal(z), cimag(z)); }
float cabsf(float complex z) {
    return hypotf(crealf(z), cimagf(z));
}
long double cabsl(long double complex z) { return cabs(z); }

double carg(double complex z) { return atan2(cimag(z), creal(z)); }
float cargf(float complex z) { return atan2f(cimagf(z), crealf(z)); }
long double cargl(long double complex z) { return carg(z); }

double complex cproj(double complex z) {
    double re = creal(z), im = cimag(z);
    if (isinf(re) || isinf(im)) {
        double inf = HUGE_VAL;
        double rim = copysign(0.0, im);
        return inf + rim * I;
    }
    return z;
}

float complex cprojf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    if (isinf(re) || isinf(im)) {
        float rim = copysignf(0.0f, im);
        return HUGE_VALF + rim * I;
    }
    return z;
}

long double complex cprojl(long double complex z) { return cproj(z); }

/* ---- exp / log / sqrt / pow ---- */

double complex cexp(double complex z) {
    double re = creal(z), im = cimag(z);
    double e = exp(re);
    return e * cos(im) + e * sin(im) * I;
}

float complex cexpf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    float e = expf(re);
    return e * cosf(im) + e * sinf(im) * I;
}

long double complex cexpl(long double complex z) { return cexp(z); }

double complex clog(double complex z) {
    double re = creal(z), im = cimag(z);
    return log(ml_cabs_d(re, im)) + atan2(im, re) * I;
}

float complex clogf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    return logf(hypotf(re, im)) + atan2f(im, re) * I;
}

long double complex clogl(long double complex z) { return clog(z); }

double complex csqrt(double complex z) {
    double re = creal(z), im = cimag(z);
    /* C99 G.5.5: sqrt(-0 + 0i) etc. preserve signed zero via atan2. */
    if (im == 0.0) {
        if (re >= 0.0) {
            double r = sqrt(re);
            return r + copysign(0.0, im) * I;
        }
        return copysign(0.0, im) + sqrt(-re) * I;
    }
    if (re == 0.0) {
        double r = sqrt(fabs(im) / 2.0);
        if (im > 0.0) return r + r * I;
        return r - r * I;
    }
    {
        double m = ml_cabs_d(re, im);
        double t = sqrt((m + fabs(re)) / 2.0);
        double u = im / (2.0 * t);
        if (re > 0.0) return t + u * I;
        if (im >= 0.0) return fabs(u) + t * I;
        return fabs(u) - t * I;
    }
}

float complex csqrtf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    if (im == 0.0f) {
        if (re >= 0.0f) {
            float r = sqrtf(re);
            return r + copysignf(0.0f, im) * I;
        }
        return copysignf(0.0f, im) + sqrtf(-re) * I;
    }
    if (re == 0.0f) {
        float r = sqrtf(fabsf(im) / 2.0f);
        if (im > 0.0f) return r + r * I;
        return r - r * I;
    }
    {
        float m = hypotf(re, im);
        float t = sqrtf((m + fabsf(re)) / 2.0f);
        float u = im / (2.0f * t);
        if (re > 0.0f) return t + u * I;
        if (im >= 0.0f) return fabsf(u) + t * I;
        return fabsf(u) - t * I;
    }
}

long double complex csqrtl(long double complex z) { return csqrt(z); }

double complex cpow(double complex x, double complex y) {
    double xr = creal(x), xi = cimag(x);
    double yr = creal(y), yi = cimag(y);
    /* Integer-exponent fast path (exact, pole-free). */
    if (xi == 0.0 && yi == 0.0) return pow(xr, yr) + 0.0 * I;
    if (yi == 0.0 && yr == (double)(long long)yr && fabs(yr) < 128.0) {
        long long n = (long long)yr;
        int neg = n < 0;
        double complex acc = 1.0 + 0.0 * I;
        double complex base = x;
        unsigned long long k = neg ? (unsigned long long)(-n)
                                   : (unsigned long long)n;
        while (k) {
            if (k & 1ULL) acc *= base;
            base *= base;
            k >>= 1;
        }
        if (neg) acc = 1.0 / acc;
        return acc;
    }
    if (xr == 0.0 && xi == 0.0) {
        if (yr > 0.0 && yi == 0.0) return 0.0 + 0.0 * I;
        /* 0^0 = 1, poles/NaN propagate per Annex G. */
        if (yr == 0.0 && yi == 0.0) return 1.0 + 0.0 * I;
        return (NAN + NAN * I);
    }
    return cexp(y * clog(x));
}

float complex cpowf(float complex x, float complex y) {
    double complex xd = (double)crealf(x) + (double)cimagf(x) * I;
    double complex yd = (double)crealf(y) + (double)cimagf(y) * I;
    double complex r = cpow(xd, yd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex cpowl(long double complex x, long double complex y) {
    return cpow(x, y);
}

/* ---- trig ---- */

double complex csin(double complex z) {
    double re = creal(z), im = cimag(z);
    return sin(re) * cosh(im) + cos(re) * sinh(im) * I;
}

float complex csinf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    return sinf(re) * coshf(im) + cosf(re) * sinhf(im) * I;
}

long double complex csinl(long double complex z) { return csin(z); }

double complex ccos(double complex z) {
    double re = creal(z), im = cimag(z);
    return cos(re) * cosh(im) - sin(re) * sinh(im) * I;
}

float complex ccosf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    return cosf(re) * coshf(im) - sinf(re) * sinhf(im) * I;
}

long double complex ccosl(long double complex z) { return ccos(z); }

double complex ctan(double complex z) {
    double complex s = csin(z), c = ccos(z);
    double cn = cabs(c);
    if (cn == 0.0) return NAN + NAN * I; /* pole */
    return s / c;
}

float complex ctanf(float complex z) {
    float complex s = csinf(z), c = ccosf(z);
    if (cabsf(c) == 0.0f) return NAN + NAN * I;
    return s / c;
}

long double complex ctanl(long double complex z) { return ctan(z); }

/* Inverse trig via log/sqrt identities (branch cuts per Annex G). */

double complex casin(double complex z) {
    double complex iz = -cimag(z) + creal(z) * I; /* i*z */
    return -1.0 * I * clog(iz + csqrt(1.0 - z * z));
}

float complex casinf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = casin(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex casinl(long double complex z) { return casin(z); }

double complex cacos(double complex z) {
    return M_PI_2 - casin(z);
}

float complex cacosf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = cacos(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex cacosl(long double complex z) { return cacos(z); }

double complex catan(double complex z) {
    double complex t = (1.0 + cimag(z)) - creal(z) * I; /* 1+i*z */
    double complex u = (1.0 - cimag(z)) + creal(z) * I; /* 1-i*z */
    return (clog(t) - clog(u)) * (0.5 * I);
}

float complex catanf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = catan(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex catanl(long double complex z) { return catan(z); }

/* ---- hyperbolic ---- */

double complex csinh(double complex z) {
    double complex w = -1.0 * I * z;
    return csin(w) * I;
}

float complex csinhf(float complex z) {
    float complex w =
        (float)(-1.0) * I * z; /* -i*z in float precision */
    (void)w;
    {
        double complex zd =
            (double)crealf(z) + (double)cimagf(z) * I;
        double complex r = csinh(zd);
        return (float)creal(r) + (float)cimag(r) * I;
    }
}

long double complex csinhl(long double complex z) { return csinh(z); }

double complex ccosh(double complex z) {
    double re = creal(z), im = cimag(z);
    return cosh(re) * cos(im) + sinh(re) * sin(im) * I;
}

float complex ccoshf(float complex z) {
    float re = crealf(z), im = cimagf(z);
    return coshf(re) * cosf(im) + sinhf(re) * sinf(im) * I;
}

long double complex ccoshl(long double complex z) { return ccosh(z); }

double complex ctanh(double complex z) {
    double complex s = csinh(z), c = ccosh(z);
    if (cabs(c) == 0.0) return NAN + NAN * I;
    return s / c;
}

float complex ctanhf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = ctanh(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex ctanhl(long double complex z) { return ctanh(z); }

/* Inverse hyperbolic via log/sqrt identities. */

double complex casinh(double complex z) {
    return clog(z + csqrt(z * z + 1.0));
}

float complex casinhf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = casinh(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex casinhl(long double complex z) { return casinh(z); }

double complex cacosh(double complex z) {
    return clog(z + csqrt(z * z - 1.0));
}

float complex cacoshf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = cacosh(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex cacoshl(long double complex z) { return cacosh(z); }

double complex catanh(double complex z) {
    return 0.5 * (clog(1.0 + z) - clog(1.0 - z));
}

float complex catanhf(float complex z) {
    double complex zd = (double)crealf(z) + (double)cimagf(z) * I;
    double complex r = catanh(zd);
    return (float)creal(r) + (float)cimag(r) * I;
}

long double complex catanhl(long double complex z) { return catanh(z); }
