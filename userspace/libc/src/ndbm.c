/* libc ndbm: single-file hash database.
 *
 * File layout: header page (magic + bucket count + count), then fixed
 * 512-byte buckets holding up to 8 slots each (hash, key/value offsets
 * into the trailing data area). Keys/values are length-prefixed blobs.
 * All mutating ops take an exclusive fcntl lock, readers a shared one.
 */
#include <ndbm.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#define ML_DBM_MAGIC 0x44424D31u /* "DBM1" */
#define ML_DBM_BUCKET 512
#define ML_DBM_SLOTS 8
#define ML_DBM_NBUCKETS 64

typedef struct {
    uint32_t magic;
    uint32_t nbuckets;
    uint32_t count;
    uint32_t seq;
} ml_dbm_hdr_t;

typedef struct {
    uint32_t hash;
    uint32_t koff;
    uint32_t klen;
    uint32_t voff;
    uint32_t vlen;
    uint8_t used;
    uint8_t pad[3];
} ml_dbm_slot_t;

typedef struct {
    ml_dbm_slot_t slots[ML_DBM_SLOTS];
    uint8_t data[ML_DBM_BUCKET - ML_DBM_SLOTS * sizeof(ml_dbm_slot_t)];
} ml_dbm_bucket_t;

struct DBM {
    int fd;
    int err;
    uint32_t iter_b;
    uint32_t iter_s;
    datum cur;
};

static uint32_t ml_dbm_hash(const char *p, size_t n) {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h *= 16777619u;
    }
    return h ? h : 1;
}

static int ml_dbm_lock(DBM *db, short type) {
    struct flock fl;
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    return fcntl(db->fd, F_SETLKW, &fl);
}

static int ml_dbm_unlock(DBM *db) {
    struct flock fl;
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    return fcntl(db->fd, F_SETLK, &fl);
}

static int ml_hdr(DBM *db, ml_dbm_hdr_t *h) {
    if (lseek(db->fd, 0, SEEK_SET) < 0) return -1;
    if (read(db->fd, h, sizeof(*h)) != (ssize_t)sizeof(*h)) return -1;
    if (h->magic != ML_DBM_MAGIC || h->nbuckets == 0) return -1;
    return 0;
}

static off_t ml_bpos(uint32_t b) {
    return (off_t)sizeof(ml_dbm_hdr_t) + (off_t)b * ML_DBM_BUCKET;
}

static int ml_bread(DBM *db, uint32_t b, ml_dbm_bucket_t *bk) {
    if (lseek(db->fd, ml_bpos(b), SEEK_SET) < 0) return -1;
    if (read(db->fd, bk, sizeof(*bk)) != (ssize_t)sizeof(*bk))
        return -1;
    return 0;
}

static int ml_bwrite(DBM *db, uint32_t b, const ml_dbm_bucket_t *bk) {
    if (lseek(db->fd, ml_bpos(b), SEEK_SET) < 0) return -1;
    if (write(db->fd, bk, sizeof(*bk)) != (ssize_t)sizeof(*bk))
        return -1;
    return 0;
}

DBM *dbm_open(const char *file, int flags, int mode) {
    DBM *db;
    char path[256];
    ml_dbm_hdr_t h;
    size_t n;
    if (!file) {
        errno = EINVAL;
        return 0;
    }
    n = strlen(file);
    if (n + 4 >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(path, file, n);
    memcpy(path + n, ".db", 4);
    db = calloc(1, sizeof(*db));
    if (!db) return 0;
    db->fd = open(path, flags | O_RDWR | O_CREAT, mode);
    if (db->fd < 0) {
        free(db);
        return 0;
    }
    if (ml_dbm_lock(db, F_WRLCK) != 0) {
        close(db->fd);
        free(db);
        return 0;
    }
    if (ml_hdr(db, &h) != 0) {
        /* Fresh file: write header + zero buckets. */
        ml_dbm_bucket_t zero;
        uint32_t b;
        memset(&h, 0, sizeof(h));
        h.magic = ML_DBM_MAGIC;
        h.nbuckets = ML_DBM_NBUCKETS;
        memset(&zero, 0, sizeof(zero));
        if (lseek(db->fd, 0, SEEK_SET) < 0 ||
            write(db->fd, &h, sizeof(h)) != (ssize_t)sizeof(h)) {
            ml_dbm_unlock(db);
            close(db->fd);
            free(db);
            return 0;
        }
        for (b = 0; b < h.nbuckets; b++)
            if (ml_bwrite(db, b, &zero) != 0) {
                ml_dbm_unlock(db);
                close(db->fd);
                free(db);
                return 0;
            }
    }
    ml_dbm_unlock(db);
    db->err = 0;
    return db;
}

void dbm_close(DBM *db) {
    if (!db) return;
    close(db->fd);
    free(db->cur.dptr);
    free(db);
}

static int ml_find(DBM *db, uint32_t hash, const char *key, size_t klen,
                   ml_dbm_bucket_t *bk, int *slot_out) {
    ml_dbm_hdr_t h;
    uint32_t b, i;
    if (ml_hdr(db, &h) != 0) return -1;
    b = hash % h.nbuckets;
    if (ml_bread(db, b, bk) != 0) return -1;
    for (i = 0; i < ML_DBM_SLOTS; i++) {
        ml_dbm_slot_t *s = &bk->slots[i];
        if (!s->used || s->hash != hash || s->klen != klen) continue;
        if (s->koff + s->klen > sizeof(bk->data)) continue;
        if (memcmp((char *)bk->data + s->koff, key, klen) == 0) {
            *slot_out = (int)i;
            return (int)b;
        }
    }
    *slot_out = -1;
    return (int)b;
}

datum dbm_fetch(DBM *db, datum key) {
    datum r = {0, 0};
    ml_dbm_bucket_t bk;
    int slot;
    uint32_t hash;
    if (!db || !key.dptr) {
        if (db) db->err = EINVAL;
        errno = EINVAL;
        return r;
    }
    if (ml_dbm_lock(db, F_RDLCK) != 0) {
        db->err = errno;
        return r;
    }
    hash = ml_dbm_hash(key.dptr, key.dsize);
    if (ml_find(db, hash, key.dptr, key.dsize, &bk, &slot) < 0 || slot < 0) {
        ml_dbm_unlock(db);
        return r;
    }
    {
        ml_dbm_slot_t *s = &bk.slots[slot];
        char *p = malloc(s->vlen ? s->vlen : 1);
        if (!p) {
            db->err = ENOMEM;
            ml_dbm_unlock(db);
            return r;
        }
        memcpy(p, (char *)bk.data + s->voff, s->vlen);
        r.dptr = p;
        r.dsize = s->vlen;
    }
    ml_dbm_unlock(db);
    db->err = 0;
    return r;
}

int dbm_store(DBM *db, datum key, datum content, int flags) {
    ml_dbm_bucket_t bk;
    int slot, b;
    uint32_t hash, i, doff;
    if (!db || !key.dptr || !content.dptr) {
        errno = EINVAL;
        return -1;
    }
    if (key.dsize + content.dsize + 8 > sizeof(bk.data)) {
        errno = E2BIG;
        return -1;
    }
    if (ml_dbm_lock(db, F_WRLCK) != 0) {
        db->err = errno;
        return -1;
    }
    hash = ml_dbm_hash(key.dptr, key.dsize);
    b = ml_find(db, hash, key.dptr, key.dsize, &bk, &slot);
    if (b < 0) {
        db->err = EIO;
        ml_dbm_unlock(db);
        return -1;
    }
    if (slot >= 0) {
        if (flags == DBM_INSERT) {
            errno = EEXIST;
            ml_dbm_unlock(db);
            return 1;
        }
        /* Replace: clear old slot, compact by rewrite. */
        memset(&bk.slots[slot], 0, sizeof(bk.slots[slot]));
    }
    /* Find a free slot and trailing data space. */
    slot = -1;
    for (i = 0; i < ML_DBM_SLOTS; i++) {
        if (!bk.slots[i].used) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        errno = ENOSPC;
        ml_dbm_unlock(db);
        return -1;
    }
    /* Data area: append after the highest used end. */
    doff = 0;
    for (i = 0; i < ML_DBM_SLOTS; i++) {
        ml_dbm_slot_t *s = &bk.slots[i];
        if (!s->used) continue;
        {
            uint32_t end = s->koff + s->klen;
            uint32_t vend = s->voff + s->vlen;
            if (end > doff) doff = end;
            if (vend > doff) doff = vend;
        }
    }
    if (doff + key.dsize + content.dsize > sizeof(bk.data)) {
        errno = ENOSPC;
        ml_dbm_unlock(db);
        return -1;
    }
    memcpy((char *)bk.data + doff, key.dptr, key.dsize);
    memcpy((char *)bk.data + doff + key.dsize, content.dptr,
           content.dsize);
    bk.slots[slot].used = 1;
    bk.slots[slot].hash = hash;
    bk.slots[slot].koff = doff;
    bk.slots[slot].klen = (uint32_t)key.dsize;
    bk.slots[slot].voff = doff + (uint32_t)key.dsize;
    bk.slots[slot].vlen = (uint32_t)content.dsize;
    if (ml_bwrite(db, (uint32_t)b, &bk) != 0) {
        db->err = EIO;
        ml_dbm_unlock(db);
        return -1;
    }
    ml_dbm_unlock(db);
    db->err = 0;
    return 0;
}

int dbm_delete(DBM *db, datum key) {
    ml_dbm_bucket_t bk;
    int slot, b;
    uint32_t hash;
    if (!db || !key.dptr) {
        errno = EINVAL;
        return -1;
    }
    if (ml_dbm_lock(db, F_WRLCK) != 0) {
        db->err = errno;
        return -1;
    }
    hash = ml_dbm_hash(key.dptr, key.dsize);
    b = ml_find(db, hash, key.dptr, key.dsize, &bk, &slot);
    if (b < 0 || slot < 0) {
        ml_dbm_unlock(db);
        return -1;
    }
    memset(&bk.slots[slot], 0, sizeof(bk.slots[slot]));
    if (ml_bwrite(db, (uint32_t)b, &bk) != 0) {
        db->err = EIO;
        ml_dbm_unlock(db);
        return -1;
    }
    ml_dbm_unlock(db);
    db->err = 0;
    return 0;
}

static datum ml_key_at(DBM *db, uint32_t b, uint32_t s, datum *store) {
    ml_dbm_bucket_t bk;
    datum r = {0, 0};
    if (ml_bread(db, b, &bk) != 0) return r;
    if (s >= ML_DBM_SLOTS || !bk.slots[s].used) return r;
    {
        ml_dbm_slot_t *sl = &bk.slots[s];
        char *p = malloc(sl->klen ? sl->klen : 1);
        if (!p) return r;
        memcpy(p, (char *)bk.data + sl->koff, sl->klen);
        free(store->dptr);
        store->dptr = p;
        store->dsize = sl->klen;
        r = *store;
    }
    return r;
}

datum dbm_firstkey(DBM *db) {
    datum r = {0, 0};
    ml_dbm_hdr_t h;
    uint32_t b, s;
    if (!db) {
        errno = EINVAL;
        return r;
    }
    if (ml_dbm_lock(db, F_RDLCK) != 0) return r;
    if (ml_hdr(db, &h) != 0) {
        ml_dbm_unlock(db);
        return r;
    }
    for (b = 0; b < h.nbuckets; b++) {
        for (s = 0; s < ML_DBM_SLOTS; s++) {
            r = ml_key_at(db, b, s, &db->cur);
            if (r.dptr) {
                db->iter_b = b;
                db->iter_s = s;
                ml_dbm_unlock(db);
                return r;
            }
        }
    }
    ml_dbm_unlock(db);
    return r;
}

datum dbm_nextkey(DBM *db) {
    datum r = {0, 0};
    ml_dbm_hdr_t h;
    uint32_t b, s;
    if (!db) {
        errno = EINVAL;
        return r;
    }
    if (ml_dbm_lock(db, F_RDLCK) != 0) return r;
    if (ml_hdr(db, &h) != 0) {
        ml_dbm_unlock(db);
        return r;
    }
    b = db->iter_b;
    s = db->iter_s + 1;
    for (; b < h.nbuckets; b++, s = 0) {
        for (; s < ML_DBM_SLOTS; s++) {
            r = ml_key_at(db, b, s, &db->cur);
            if (r.dptr) {
                db->iter_b = b;
                db->iter_s = s;
                ml_dbm_unlock(db);
                return r;
            }
        }
    }
    ml_dbm_unlock(db);
    return r;
}

int dbm_error(DBM *db) { return db ? db->err : 0; }

int dbm_clearerr(DBM *db) {
    if (!db) {
        errno = EINVAL;
        return -1;
    }
    db->err = 0;
    return 0;
}

int dbm_dirfno(DBM *db) {
    if (!db) {
        errno = EINVAL;
        return -1;
    }
    return db->fd;
}

int dbm_pagfno(DBM *db) {
    if (!db) {
        errno = EINVAL;
        return -1;
    }
    return db->fd;
}

long dbm_forder(DBM *db, datum key) {
    ml_dbm_bucket_t bk;
    int slot;
    uint32_t hash;
    long off;
    if (!db || !key.dptr) {
        errno = EINVAL;
        return -1;
    }
    hash = ml_dbm_hash(key.dptr, key.dsize);
    if (ml_find(db, hash, key.dptr, key.dsize, &bk, &slot) < 0 ||
        slot < 0)
        return -1;
    off = (long)(hash % ML_DBM_NBUCKETS);
    return off * ML_DBM_BUCKET + slot;
}
