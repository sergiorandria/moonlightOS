/* Moonlight libc - sys/param (BSD misc limits).
 * Real constants matching the flat VFS / LP64 target. */
#pragma once

#include <limits.h>
#include <sys/types.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif
#ifndef MAXNAMLEN
#define MAXNAMLEN 31
#endif
#ifndef NBBY
#define NBBY 8
#endif
#ifndef NGROUPS
#define NGROUPS 16
#endif
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define roundup(x, y) ((((x) + ((y)-1)) / (y)) * (y))
#define powerof2(x) ((((x)-1) & (x)) == 0)
