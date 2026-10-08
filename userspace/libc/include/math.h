/* Moonlight libc - math (C99, soft-float friendly).
 *
 * Every declaration below is implemented in src/math.c; there are no
 * placeholders. Algorithms are self-contained (bit tricks, Newton
 * iteration, range reduction + minimax polynomials) so the freestanding
 * rv64 build needs no libm. Accuracy target is ~1e-12 relative for the
 * transcendentals on finite inputs; edge cases (NaN/Inf/zero/pole)
 * follow C99 Annex F. long double is double on this target, so the l
 * variants are exact aliases with the same behavior.
 *
 * erf/erfc use the Abramowitz-Stegun 7.1.26 rational fit (1e-7);
 * lgamma/tgamma use the Lanczos g=7 approximation.
 */
#pragma once

/* ---- constants ---- */
#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALF (__builtin_huge_valf())
#define HUGE_VALL (__builtin_huge_vall())
#define INFINITY (__builtin_huge_valf())
#define NAN (__builtin_nanf(""))

/* BSD extensions (always available here). */
#define M_E 2.7182818284590452354
#define M_LOG2E 1.4426950408889634074
#define M_LOG10E 0.43429448190325182765
#define M_LN2 0.69314718055994530942
#define M_LN10 2.30258509299404568402
#define M_PI 3.14159265358979323846
#define M_PI_2 1.57079632679489661923
#define M_PI_4 0.78539816339744830962
#define M_1_PI 0.31830988618379067154
#define M_2_PI 0.63661977236758134308
#define M_2_SQRTPI 1.12837916709551257390
#define M_SQRT2 1.41421356237309504880
#define M_SQRT1_2 0.70710678118654752440

/* ---- classification (real bit inspection, see math.c) ---- */
#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4

int __ml_fpclassify(double x);
int __ml_fpclassifyf(float x);
int __ml_isnan(double x);
int __ml_isnanf(float x);
int __ml_isinf(double x);
int __ml_isinff(float x);
int __ml_isfinite(double x);
int __ml_isfinitef(float x);
int __ml_isnormal(double x);
int __ml_isnormalf(float x);
int __ml_signbit(double x);
int __ml_signbitf(float x);

#define fpclassify(x) \
    (sizeof(x) == sizeof(float) ? __ml_fpclassifyf(x) : __ml_fpclassify(x))
#define isnan(x) \
    (sizeof(x) == sizeof(float) ? __ml_isnanf(x) : __ml_isnan(x))
#define isinf(x) \
    (sizeof(x) == sizeof(float) ? __ml_isinff(x) : __ml_isinf(x))
#define isfinite(x) \
    (sizeof(x) == sizeof(float) ? __ml_isfinitef(x) : __ml_isfinite(x))
#define isnormal(x) \
    (sizeof(x) == sizeof(float) ? __ml_isnormalf(x) : __ml_isnormal(x))
#define signbit(x) \
    (sizeof(x) == sizeof(float) ? __ml_signbitf(x) : __ml_signbit(x))
#define isunordered(x, y) (isnan(x) || isnan(y))

/* ---- basic ---- */
double fabs(double x);
float fabsf(float x);
double copysign(double x, double y);
float copysignf(float x, float y);
double fmax(double x, double y);
float fmaxf(float x, float y);
double fmin(double x, double y);
float fminf(float x, float y);
double fdim(double x, double y);
float fdimf(float x, float y);
double fma(double x, double y, double z);
float fmaf(float x, float y, float z);
double nextafter(double x, double y);
float nextafterf(float x, float y);

/* ---- rounding / remainder ---- */
double floor(double x);
float floorf(float x);
double ceil(double x);
float ceilf(float x);
double trunc(double x);
float truncf(float x);
double round(double x);
float roundf(float x);
long lround(double x);
long lroundf(float x);
long long llround(double x);
long long llroundf(float x);
double rint(double x);
float rintf(float x);
double nearbyint(double x);
float nearbyintf(float x);
double fmod(double x, double y);
float fmodf(float x, float y);
double remainder(double x, double y);
float remainderf(float x, float y);
double remquo(double x, double y, int *quo);
float remquof(float x, float y, int *quo);

/* ---- exponentiation / logarithms ---- */
double sqrt(double x);
float sqrtf(float x);
double cbrt(double x);
float cbrtf(float x);
double hypot(double x, double y);
float hypotf(float x, float y);
double pow(double x, double y);
float powf(float x, float y);
double exp(double x);
float expf(float x);
double exp2(double x);
float exp2f(float x);
double expm1(double x);
float expm1f(float x);
double log(double x);
float logf(float x);
double log2(double x);
float log2f(float x);
double log10(double x);
float log10f(float x);
double log1p(double x);
float log1pf(float x);
double frexp(double x, int *e);
float frexpf(float x, int *e);
double ldexp(double x, int e);
float ldexpf(float x, int e);
double modf(double x, double *i);
float modff(float x, float *i);
double scalbn(double x, int n);
float scalbnf(float x, int n);
int ilogb(double x);
int ilogbf(float x);
double logb(double x);
float logbf(float x);

/* ---- trigonometry ---- */
double sin(double x);
float sinf(float x);
double cos(double x);
float cosf(float x);
double tan(double x);
float tanf(float x);
double asin(double x);
float asinf(float x);
double acos(double x);
float acosf(float x);
double atan(double x);
float atanf(float x);
double atan2(double y, double x);
float atan2f(float y, float x);
double sinh(double x);
float sinhf(float x);
double cosh(double x);
float coshf(float x);
double tanh(double x);
float tanhf(float x);
double asinh(double x);
float asinhf(float x);
double acosh(double x);
float acoshf(float x);
double atanh(double x);
float atanhf(float x);

/* ---- special functions ---- */
double erf(double x);
float erff(float x);
double erfc(double x);
float erfcf(float x);
double lgamma(double x);
float lgammaf(float x);
double tgamma(double x);
float tgammaf(float x);

/* ---- misc ---- */
double nan(const char *s);
float nanf(const char *s);

/* ---- GNU/BSD extras (all implemented in math.c) ---- */
void sincos(double x, double *s, double *c);
void sincosf(float x, float *s, float *c);
double lgamma_r(double x, int *sign);
float lgammaf_r(float x, int *sign);
extern int signgam;
double gamma(double x);
double exp10(double x);
float exp10f(float x);
double pow10(double x);
double scalb(double x, double n);
float scalbf(float x, float n);
double drem(double x, double y);
float dremf(float x, float y);
double j0(double x);
float j0f(float x);
double j1(double x);
float j1f(float x);
double jn(int n, double x);
float jnf(int n, float x);
double y0(double x);
float y0f(float x);
double y1(double x);
float y1f(float x);
double yn(int n, double x);
float ynf(int n, float x);
