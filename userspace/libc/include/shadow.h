/* Moonlight libc - shadow.h (shadow password database;
 * parsed from /etc/shadow with a static fallback, like pwdgrp). */
#pragma once

#include <stddef.h>
#include <stdio.h>

struct spwd {
    char *sp_namp;
    char *sp_pwdp;
    long sp_lstchg;
    long sp_min;
    long sp_max;
    long sp_warn;
    long sp_inact;
    long sp_expire;
    unsigned long sp_flag;
};

struct spwd *getspnam(const char *name);
struct spwd *getspent(void);
void setspent(void);
void endspent(void);
int getspnam_r(const char *name, struct spwd *sp, char *buf, size_t n,
               struct spwd **result);
int getspent_r(struct spwd *sp, char *buf, size_t n, struct spwd **result);
int sgetspent(const char *s, struct spwd *sp, char *buf, size_t n);
int fgetspent(FILE *fp, struct spwd *sp, char *buf, size_t n);
