/* Moonlight libc - tgmath (C99 type-generic, real macros).
 * Dispatches on the operand type to the float/double core in
 * math.c/complex.c. long double is double here, so l-variants
 * alias the double entry points. */
#pragma once

#include <math.h>
#include <complex.h>

#define __ML_TG1(fn, x) \
    (sizeof(x) == sizeof(float) ? fn##f(x) : fn(x))
#define __ML_TG2(fn, x, y) \
    (sizeof((x) + (y)) == sizeof(float) ? fn##f(x, y) : fn(x, y))

#define sqrt(x) __ML_TG1(sqrt, x)
#define cbrt(x) __ML_TG1(cbrt, x)
#define fabs(x) __ML_TG1(fabs, x)
#define exp(x) __ML_TG1(exp, x)
#define exp2(x) __ML_TG1(exp2, x)
#define expm1(x) __ML_TG1(expm1, x)
#define log(x) __ML_TG1(log, x)
#define log2(x) __ML_TG1(log2, x)
#define log10(x) __ML_TG1(log10, x)
#define log1p(x) __ML_TG1(log1p, x)
#define sin(x) __ML_TG1(sin, x)
#define cos(x) __ML_TG1(cos, x)
#define tan(x) __ML_TG1(tan, x)
#define asin(x) __ML_TG1(asin, x)
#define acos(x) __ML_TG1(acos, x)
#define atan(x) __ML_TG1(atan, x)
#define sinh(x) __ML_TG1(sinh, x)
#define cosh(x) __ML_TG1(cosh, x)
#define tanh(x) __ML_TG1(tanh, x)
#define asinh(x) __ML_TG1(asinh, x)
#define acosh(x) __ML_TG1(acosh, x)
#define atanh(x) __ML_TG1(atanh, x)
#define erf(x) __ML_TG1(erf, x)
#define erfc(x) __ML_TG1(erfc, x)
#define lgamma(x) __ML_TG1(lgamma, x)
#define tgamma(x) __ML_TG1(tgamma, x)
#define floor(x) __ML_TG1(floor, x)
#define ceil(x) __ML_TG1(ceil, x)
#define trunc(x) __ML_TG1(trunc, x)
#define round(x) __ML_TG1(round, x)
#define rint(x) __ML_TG1(rint, x)
#define nearbyint(x) __ML_TG1(nearbyint, x)

#define pow(x, y) __ML_TG2(pow, x, y)
#define hypot(x, y) __ML_TG2(hypot, x, y)
#define fmod(x, y) __ML_TG2(fmod, x, y)
#define remainder(x, y) __ML_TG2(remainder, x, y)
#define fmax(x, y) __ML_TG2(fmax, x, y)
#define fmin(x, y) __ML_TG2(fmin, x, y)
#define fdim(x, y) __ML_TG2(fdim, x, y)
#define atan2(y, x) __ML_TG2(atan2, y, x)
#define copysign(x, y) __ML_TG2(copysign, x, y)
#define nextafter(x, y) __ML_TG2(nextafter, x, y)
#define fma(x, y, z) \
    (sizeof((x) + (y) + (z)) == sizeof(float) ? fmaf(x, y, z) \
                                             : fma(x, y, z))
