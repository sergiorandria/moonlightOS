/* Moonlight libc - grp (see pwd.h: shares the two-row database). */
#pragma once

#include <pwd.h>

struct group *getgrent(void);
void setgrent(void);
void endgrent(void);
int getgrouplist(const char *user, gid_t group, gid_t *groups,
                 int *ngroups);
