/* libc fmtmsg: real formatted-message writer. Severity text
 * follows the fmtmsg table; MM_PRINT writes "LABEL: TEXT\n" to
 * stderr, MM_CONSOLE the same (no separate console device). */
#include <fmtmsg.h>
#include <stdio.h>
#include <string.h>

static const char *ml_sev_text(int sev) {
    switch (sev) {
    case MM_HALT: return "HALT";
    case MM_ERROR: return "ERROR";
    case MM_WARNING: return "WARNING";
    case MM_INFO: return "INFO";
    default: return 0;
    }
}

int fmtmsg(long classification, const char *label, int severity,
           const char *text, const char *action, const char *tag) {
    const char *sev;
    int rc = MM_OK;
    (void)classification;
    if (severity != MM_NOSEV) {
        sev = ml_sev_text(severity);
        if (!sev) return MM_NOTOK;
    } else {
        sev = 0;
    }
    if (!text || !*text) return MM_NOMSG;
    if (!(classification & (MM_PRINT | MM_CONSOLE))) return MM_NOCON;
    if (label && label != MM_NULLLBL) dprintf(2, "%s: ", label);
    if (sev) dprintf(2, "%s: ", sev);
    dprintf(2, "%s\n", text);
    if (action && action != MM_NULLACT) dprintf(2, "TO FIX: %s\n", action);
    if (tag && tag != MM_NULLTAG) dprintf(2, "%s\n", tag);
    (void)rc;
    return MM_OK;
}
