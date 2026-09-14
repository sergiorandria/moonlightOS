/* Moonlight libc - ndbm.h (disk hash database; implemented
 * in src/ndbm.c with fcntl locking). */
#pragma once

#include <stddef.h>

typedef struct {
    char *dptr;
    size_t dsize;
} datum;

typedef struct DBM DBM;

#define PBLKSIZ 4096
#define DBLKSIZ 4096

DBM *dbm_open(const char *file, int flags, int mode);
void dbm_close(DBM *db);
datum dbm_fetch(DBM *db, datum key);
int dbm_store(DBM *db, datum key, datum content, int flags);
int dbm_delete(DBM *db, datum key);
datum dbm_firstkey(DBM *db);
datum dbm_nextkey(DBM *db);
int dbm_error(DBM *db);
int dbm_clearerr(DBM *db);
int dbm_dirfno(DBM *db);
int dbm_pagfno(DBM *db);
long dbm_forder(DBM *db, datum key);

#define DBM_INSERT 0
#define DBM_REPLACE 1
