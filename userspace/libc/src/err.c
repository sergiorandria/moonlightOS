/* libc err: real BSD error reporting over stderr + exit.
 * err/errx exit(status); warn/warnx return. Message is
 * "prog: fmt: strerror(errno)" (err/warn) or "prog: fmt" (x). */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

extern char **environ;

char *__progname = "app";

static void ml_err_head(int use_errno) {
    dprintf(2, "%s: ", __progname ? __progname : "app");
    (void)use_errno;
}

void verr(int status, const char *fmt, va_list ap) {
    int e = errno;
    ml_err_head(1);
    if (fmt) vdprintf(2, fmt, ap);
    dprintf(2, ": %s\n", strerror(e));
    exit(status);
}

void err(int status, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    verr(status, fmt, ap);
    va_end(ap);
}

void verrx(int status, const char *fmt, va_list ap) {
    ml_err_head(0);
    if (fmt) vdprintf(2, fmt, ap);
    dprintf(2, "\n");
    exit(status);
}

void errx(int status, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    verrx(status, fmt, ap);
    va_end(ap);
}

void vwarn(const char *fmt, va_list ap) {
    int e = errno;
    ml_err_head(1);
    if (fmt) vdprintf(2, fmt, ap);
    dprintf(2, ": %s\n", strerror(e));
}

void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
}

void vwarnx(const char *fmt, va_list ap) {
    ml_err_head(0);
    if (fmt) vdprintf(2, fmt, ap);
    dprintf(2, "\n");
}

void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
