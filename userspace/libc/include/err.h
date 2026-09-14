/* Moonlight libc - err (BSD error reporting).
 * Real implementation over stderr + exit: err/errx exit with the
 * given status, warn/warnx return. Formats are rendered with the
 * real vdprintf engine. No stubs. */
#pragma once

#include <stdarg.h>

void err(int status, const char *fmt, ...);
void verr(int status, const char *fmt, va_list ap);
void errx(int status, const char *fmt, ...);
void verrx(int status, const char *fmt, va_list ap);
void warn(const char *fmt, ...);
void vwarn(const char *fmt, va_list ap);
void warnx(const char *fmt, ...);
void vwarnx(const char *fmt, va_list ap);
