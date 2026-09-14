/* Moonlight libc - fmtmsg.h (formatted message output). */
#pragma once

#define MM_HARD 1
#define MM_SOFT 2
#define MM_FIRM 4
#define MM_APPL 8
#define MM_UTIL 16
#define MM_OPSYS 32
#define MM_PRINT 256
#define MM_CONSOLE 512

#define MM_HALT 1
#define MM_ERROR 2
#define MM_WARNING 3
#define MM_INFO 4

#define MM_NOSEV 0
#define MM_NULLLBL ((char *)0)
#define MM_NULLSEV 0
#define MM_NULLMC 0L
#define MM_NULLTXT ((char *)0)
#define MM_NULLACT ((char *)0)
#define MM_NULLTAG ((char *)0)

#define MM_NOTOK -1
#define MM_OK 0
#define MM_NOMSG 1
#define MM_NOCON 4

int fmtmsg(long classification, const char *label, int severity,
           const char *text, const char *action, const char *tag);
