/* libc syslog: severity mask + ident, emitted to stderr (PERROR or
 * cons fallback) with priority tags. */
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static const char *ml_log_ident = 0;
static int ml_log_options = 0;
static int ml_log_facility = LOG_USER;
static int ml_log_mask = LOG_UPTO(LOG_DEBUG);

static const char *ml_prio_name(int prio) {
    switch (prio & 7) {
    case LOG_EMERG:
        return "EMERG";
    case LOG_ALERT:
        return "ALERT";
    case LOG_CRIT:
        return "CRIT";
    case LOG_ERR:
        return "ERR";
    case LOG_WARNING:
        return "WARNING";
    case LOG_NOTICE:
        return "NOTICE";
    case LOG_INFO:
        return "INFO";
    default:
        return "DEBUG";
    }
}

void openlog(const char *ident, int options, int facility) {
    ml_log_ident = ident;
    ml_log_options = options;
    ml_log_facility = facility;
}

void vsyslog(int prio, const char *fmt, __builtin_va_list ap) {
    char msg[512];
    int p = prio & 7;
    if (!(LOG_MASK(p) & ml_log_mask)) return;
    vsnprintf(msg, sizeof(msg), fmt, ap);
    if (ml_log_options & LOG_PERROR) {
        if (ml_log_ident) dprintf(2, "%s: ", ml_log_ident);
        dprintf(2, "%s: %s\n", ml_prio_name(prio), msg);
    } else {
        /* Cons fallback: same bytes to stderr (no /dev/log daemon). */
        if (ml_log_ident) dprintf(2, "%s[%s]: ", ml_log_ident,
                                  ml_prio_name(prio));
        else dprintf(2, "[%s]: ", ml_prio_name(prio));
        dprintf(2, "%s\n", msg);
    }
    (void)ml_log_facility;
}

void syslog(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio, fmt, ap);
    va_end(ap);
}

void closelog(void) {
    ml_log_ident = 0;
    ml_log_options = 0;
    ml_log_mask = LOG_UPTO(LOG_DEBUG);
}

int setlogmask(int mask) {
    int old = ml_log_mask;
    if (mask != 0) ml_log_mask = mask;
    return old;
}

/* ---- facility/priority name tables (CODE from syslog.h) ---- */

CODE prioritynames[] = {
    {"alert", 1},   {"crit", 2},     {"debug", 7}, {"emerg", 0},
    {"err", 3},     {"error", 3},    {"info", 6},  {"none", 8},
    {"notice", 5},  {"warning", 4},  {0, -1},
};

CODE facilitynames[] = {
    {"auth", 32},   {"authpriv", 80}, {"cron", 72},   {"daemon", 24},
    {"ftp", 88},    {"kern", 0},      {"local0", 128}, {"local1", 136},
    {"local2", 144}, {"local3", 152}, {"local4", 160}, {"local5", 168},
    {"local6", 176}, {"local7", 184}, {"lpr", 48},    {"mail", 16},
    {"news", 56},   {"syslog", 40},   {"user", 8},    {"uucp", 64},
    {0, -1},
};
