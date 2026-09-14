/* Moonlight libc - pwd/grp. /etc/passwd + /etc/group are parsed
 * when present; root + nobody are built-in fallback rows. */
#pragma once

#include <sys/types.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};

struct group {
    char *gr_name;
    char *gr_passwd;
    gid_t gr_gid;
    char **gr_mem;
};

struct passwd *getpwnam(const char *name);
struct passwd *getpwuid(uid_t uid);
struct passwd *getpwent(void);
void setpwent(void);
void endpwent(void);
int getpwnam_r(const char *name, struct passwd *pw, char *buf, unsigned n,
               struct passwd **res);
int getpwuid_r(uid_t uid, struct passwd *pw, char *buf, unsigned n,
               struct passwd **res);
struct group *getgrnam(const char *name);
struct group *getgrgid(gid_t gid);
int getgrnam_r(const char *name, struct group *g, char *buf, unsigned n,
               struct group **res);
int getgrgid_r(gid_t gid, struct group *g, char *buf, unsigned n,
               struct group **res);
