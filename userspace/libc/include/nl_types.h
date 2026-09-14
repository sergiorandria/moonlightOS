/* Moonlight libc - nl_types (POSIX message catalogs).
 * Real implementation: catopen maps "name" to a VFS file of
 * "set msg: text" lines; catgets looks the message up; catclose
 * frees the table. No stubs. */
#pragma once

typedef int nl_catd;

#define NL_CAT_LOCALE 1
#define NL_SETD 0

nl_catd catopen(const char *name, int oflag);
char *catgets(nl_catd catd, int set, int msg, const char *dflt);
int catclose(nl_catd catd);
