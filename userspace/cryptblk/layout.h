/* userspace/cryptblk/layout.h - on-disk layout for the encrypted volume.
 * Pure C99, stdint.h + ../crypt headers only (NO string.h: hand loops with
 * bounds, freestanding-safe like the S3 ELFs built with -fno-builtin).
 * Every loop carries a bound comment. All parse/decode paths are
 * length-checked before any dereference. LE encode/decode is explicit.
 *
 * Header image (568B used, zero-padded to the caller buffer, fits in
 * HEADER_SECTORS x SECTOR):
 *   magic u64 LE | version u32 LE | nslots u32 LE | iters u32 LE |
 *   reserved u32 LE | salt[32] | 8 x slot(48B wrapped + 8B salt +
 *   iters u32 LE + label u32 LE).
 * Tag region: one 16B tag per 4K data sector, packed 256 per 4K tag
 * sector. 512B x 8 glue: legacy 512B sub-sector k lives at byte k*512
 * inside the 4K sector. */
#ifndef MOONLIGHT_CRYPTBLK_LAYOUT_H
#define MOONLIGHT_CRYPTBLK_LAYOUT_H

#include <stdint.h>

#include "../crypt/crypt_util.h"

/* Exact constants (brief + test use these names). */
#define CRYPT_MAGIC ((uint64_t)0x43525950544D4F4EUL) /* "CRYPTMON" LE */
#define CRYPT_VERSION 1
#define SECTOR 4096
#define TAG 16
#define TAGS_PER_SECTOR 256
#define MAX_SLOTS 8
#define SLOT_WRAPPED 48 /* 32B wrapped-VMK + 16B Poly1305 tag */
#define HEADER_SECTORS 2
#define KDF_ITERS_DEFAULT 600000UL
#define MAX_INODES 1024
#define MAX_EXTENTS 64
#define VFS_NAME_MAX 27

/* LAYOUT_-prefixed mirrors (Tasks 3-5 may use either spelling). */
#define LAYOUT_MAGIC CRYPT_MAGIC
#define LAYOUT_VERSION CRYPT_VERSION
#define LAYOUT_SECTOR SECTOR
#define LAYOUT_TAG TAG
#define LAYOUT_TAGS_PER_SECTOR TAGS_PER_SECTOR
#define LAYOUT_MAX_SLOTS MAX_SLOTS
#define LAYOUT_SLOT_WRAPPED SLOT_WRAPPED
#define LAYOUT_HEADER_SECTORS HEADER_SECTORS
#define LAYOUT_KDF_ITERS_DEFAULT KDF_ITERS_DEFAULT
#define LAYOUT_MAX_INODES MAX_INODES
#define LAYOUT_MAX_EXTENTS MAX_EXTENTS
#define LAYOUT_VFS_NAME_MAX VFS_NAME_MAX

/* CRYPT_-prefixed mirrors for the geometry names. */
#define CRYPT_SECTOR SECTOR
#define CRYPT_TAG TAG
#define CRYPT_TAGS_PER_SECTOR TAGS_PER_SECTOR
#define CRYPT_MAX_SLOTS MAX_SLOTS
#define CRYPT_SLOT_WRAPPED SLOT_WRAPPED
#define CRYPT_HEADER_SECTORS HEADER_SECTORS
#define CRYPT_KDF_ITERS_DEFAULT KDF_ITERS_DEFAULT
#define CRYPT_MAX_INODES MAX_INODES
#define CRYPT_MAX_EXTENTS MAX_EXTENTS
#define CRYPT_VFS_NAME_MAX VFS_NAME_MAX

/* Codec sizes. */
#define LAYOUT_HEADER_USED 568UL /* 24 + 32 + 8*64 */
#define LAYOUT_DIRENT_SIZE 32UL  /* 28B name + u32 ino */
#define LAYOUT_EXTENT_SIZE 16UL  /* u64 start + u64 len */

/* Inode types. */
#define LAYOUT_INODE_FILE 1
#define LAYOUT_INODE_DIR 2

/* ---- Explicit LE helpers. ---- */

static inline uint32_t layout_ld32le(const uint8_t *p)
{
    return (uint32_t)(((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
                      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static inline void layout_st32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t layout_ld64le(const uint8_t *p)
{
    unsigned i;
    uint64_t v = 0;
    for (i = 0; i < 8; i++) /* bound: 8 */
        v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static inline void layout_st64le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) /* bound: 8 */
        p[i] = (uint8_t)(v >> (8 * i));
}

/* ---- On-disk structs (host + freestanding shared view). ---- */

typedef struct {
    uint8_t wrapped[SLOT_WRAPPED]; /* ct[32] || tag[16] */
    uint8_t salt[8];               /* per-wrap slot salt */
    uint32_t iters;                /* KDF work factor guard, never 0 */
    uint32_t label;                /* slot identity, bound into nonce+AD */
} layout_slot_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t nslots;
    uint32_t iters;
    uint32_t reserved;
    uint8_t salt[32];
    layout_slot_t slots[MAX_SLOTS];
} vol_header_t;

typedef struct {
    uint64_t start;
    uint64_t len;
} layout_extent_t;

typedef struct {
    unsigned long base; /* arena start sector */
    unsigned long len;  /* arena length in sectors */
    unsigned long nused;
    layout_extent_t used[MAX_EXTENTS];
} layout_alloc_t;

typedef struct {
    uint8_t name[VFS_NAME_MAX + 1]; /* bytes + NUL pad */
    uint32_t ino;
} layout_dirent_t;

typedef struct {
    uint32_t type; /* LAYOUT_INODE_FILE / LAYOUT_INODE_DIR */
    uint32_t owner;
    uint64_t size;
    uint32_t nextents;
    layout_extent_t extents[MAX_EXTENTS];
} layout_inode_t;

/* ---- Header codec. Encode serializes all MAX_SLOTS records and zeroes
 * the caller tail past LAYOUT_HEADER_USED. Parse validates magic,
 * version and nslots and requires len >= LAYOUT_HEADER_USED before
 * touching any byte. Returns 0 ok, -1 on bad args / truncation /
 * validation failure. ---- */

static inline int layout_encode(const vol_header_t *h, uint8_t *out,
                                unsigned long outlen)
{
    unsigned long i, j, off;
    if (!h || !out)
        return -1;
    if (outlen < LAYOUT_HEADER_USED)
        return -1;
    if (h->nslots > MAX_SLOTS)
        return -1;
    layout_st64le(out, h->magic);
    layout_st32le(out + 8, h->version);
    layout_st32le(out + 12, h->nslots);
    layout_st32le(out + 16, h->iters);
    layout_st32le(out + 20, h->reserved);
    for (i = 0; i < 32; i++) /* bound: 32 */
        out[24 + i] = h->salt[i];
    off = 56;
    for (i = 0; i < MAX_SLOTS; i++) { /* bound: 8 */
        for (j = 0; j < SLOT_WRAPPED; j++) /* bound: 48 */
            out[off + j] = h->slots[i].wrapped[j];
        off += SLOT_WRAPPED;
        for (j = 0; j < 8; j++) /* bound: 8 */
            out[off + j] = h->slots[i].salt[j];
        off += 8;
        layout_st32le(out + off, h->slots[i].iters);
        off += 4;
        layout_st32le(out + off, h->slots[i].label);
        off += 4;
    }
    for (i = off; i < outlen; i++) /* bound: caller outlen tail */
        out[i] = 0;
    return 0;
}

static inline int layout_parse(const uint8_t *buf, unsigned long len,
                               vol_header_t *out)
{
    unsigned long i, j, off;
    uint32_t nslots;
    if (!buf || !out)
        return -1;
    if (len < LAYOUT_HEADER_USED)
        return -1;
    /* Length-checked: len >= 568, every access below is at < 568. */
    if (layout_ld64le(buf) != CRYPT_MAGIC)
        return -1;
    if (layout_ld32le(buf + 8) != (uint32_t)CRYPT_VERSION)
        return -1;
    nslots = layout_ld32le(buf + 12);
    if (nslots > MAX_SLOTS)
        return -1;
    out->magic = layout_ld64le(buf);
    out->version = layout_ld32le(buf + 8);
    out->nslots = nslots;
    out->iters = layout_ld32le(buf + 16);
    out->reserved = layout_ld32le(buf + 20);
    for (i = 0; i < 32; i++) /* bound: 32 */
        out->salt[i] = buf[24 + i];
    off = 56;
    for (i = 0; i < MAX_SLOTS; i++) { /* bound: 8 */
        for (j = 0; j < SLOT_WRAPPED; j++) /* bound: 48 */
            out->slots[i].wrapped[j] = buf[off + j];
        off += SLOT_WRAPPED;
        for (j = 0; j < 8; j++) /* bound: 8 */
            out->slots[i].salt[j] = buf[off + j];
        off += 8;
        out->slots[i].iters = layout_ld32le(buf + off);
        off += 4;
        out->slots[i].label = layout_ld32le(buf + off);
        off += 4;
    }
    return 0;
}

/* ---- Tag-region math: data sector s -> tag sector s/256, slot s%256. ---- */

static inline int layout_tag_loc(unsigned long sector,
                                 unsigned long *tag_sector,
                                 unsigned long *slot)
{
    if (!tag_sector || !slot)
        return -1;
    *tag_sector = sector / TAGS_PER_SECTOR;
    *slot = sector % TAGS_PER_SECTOR;
    return 0;
}

/* ---- 512B x 8 glue: sub-sector k -> byte offset k*512; k >= 8 fails. ---- */

static inline int layout_blk_off(unsigned k, unsigned long *off)
{
    if (!off)
        return -1;
    if (k >= 8)
        return -1;
    *off = (unsigned long)k * 512UL;
    return 0;
}

/* ---- Extent allocator: first-fit over a sorted used-run list inside
 * [base, base+len). Free requires an exact (start,len) run match (no
 * partial frees). Cap MAX_EXTENTS runs. Returns 0 ok, -1 on bad args,
 * no-fit, unknown run, or length mismatch. ---- */

static inline int layout_alloc_init(layout_alloc_t *a, unsigned long base,
                                    unsigned long len)
{
    unsigned long i;
    if (!a)
        return -1;
    if (len == 0)
        return -1;
    a->base = base;
    a->len = len;
    a->nused = 0;
    for (i = 0; i < MAX_EXTENTS; i++) /* bound: 64 */
        a->used[i].start = 0, a->used[i].len = 0;
    return 0;
}

static inline int layout_alloc(layout_alloc_t *a, unsigned long need,
                               unsigned long *start)
{
    unsigned long cand, end, i, k;
    if (!a || !start)
        return -1;
    if (need == 0)
        return -1;
    if (a->nused >= MAX_EXTENTS)
        return -1;
    if (need > a->len)
        return -1;
    end = a->base + a->len;
    if (end < a->base)
        return -1; /* arena overflow */
    cand = a->base;
    for (i = 0; i < a->nused; i++) { /* bound: nused <= 64 */
        unsigned long us = (unsigned long)a->used[i].start;
        unsigned long ul = (unsigned long)a->used[i].len;
        unsigned long uend;
        if (ul == 0)
            continue;
        uend = us + ul;
        if (uend < us)
            return -1; /* corrupt state */
        if (cand <= us) {
            unsigned long gap = us - cand;
            if (need <= gap)
                break; /* first-fit hole before used[i] */
        }
        if (uend > cand)
            cand = uend;
        if (cand > end)
            return -1;
    }
    if (cand > end)
        return -1;
    if (need > end - cand)
        return -1;
    *start = cand;
    k = a->nused; /* default: append */
    for (i = 0; i < a->nused; i++) { /* bound: nused <= 64 */
        if (cand < (unsigned long)a->used[i].start) {
            k = i;
            break;
        }
    }
    for (i = a->nused; i > k; i--) /* bound: 64 */
        a->used[i] = a->used[i - 1];
    a->used[k].start = (uint64_t)cand;
    a->used[k].len = (uint64_t)need;
    a->nused++;
    return 0;
}

static inline int layout_free(layout_alloc_t *a, unsigned long start,
                              unsigned long len)
{
    unsigned long i, j;
    if (!a)
        return -1;
    if (len == 0)
        return -1;
    for (i = 0; i < a->nused; i++) /* bound: nused <= 64 */
        if ((unsigned long)a->used[i].start == start &&
            (unsigned long)a->used[i].len == len)
            break;
    if (i == a->nused)
        return -1; /* unknown run or length mismatch */
    for (j = i; j + 1 < a->nused; j++) /* bound: 64 */
        a->used[j] = a->used[j + 1];
    a->nused--;
    a->used[a->nused].start = 0;
    a->used[a->nused].len = 0;
    return 0;
}

/* ---- Dirent: 1..27B names, ino < MAX_INODES. 32B codec is
 * name[28] || ino u32 LE. ---- */

static inline int layout_dirent_set(layout_dirent_t *d, const uint8_t *name,
                                    unsigned long namelen, uint32_t ino)
{
    unsigned long i;
    if (!d || !name)
        return -1;
    if (namelen == 0 || namelen > VFS_NAME_MAX)
        return -1;
    if (ino >= MAX_INODES)
        return -1;
    for (i = 0; i < namelen; i++) /* bound: namelen <= 27 */
        d->name[i] = name[i];
    for (i = namelen; i < sizeof(d->name); i++) /* bound: 28 */
        d->name[i] = 0;
    d->ino = ino;
    return 0;
}

static inline int layout_dirent_encode(const layout_dirent_t *d, uint8_t *out,
                                       unsigned long outlen)
{
    unsigned long i;
    if (!d || !out)
        return -1;
    if (outlen < LAYOUT_DIRENT_SIZE)
        return -1;
    for (i = 0; i < 28; i++) /* bound: 28 */
        out[i] = d->name[i];
    layout_st32le(out + 28, d->ino);
    return 0;
}

static inline int layout_dirent_decode(const uint8_t *buf, unsigned long len,
                                       layout_dirent_t *d)
{
    unsigned long i;
    if (!buf || !d)
        return -1;
    if (len < LAYOUT_DIRENT_SIZE)
        return -1;
    /* Length-checked: len >= 32, every access below is at < 32. */
    for (i = 0; i < 28; i++) /* bound: 28 */
        d->name[i] = buf[i];
    d->ino = layout_ld32le(buf + 28);
    return 0;
}

/* ---- Inode validator: type range + extent-count cap. ---- */

static inline int layout_inode_valid(const layout_inode_t *n)
{
    if (!n)
        return -1;
    if (n->type != LAYOUT_INODE_FILE && n->type != LAYOUT_INODE_DIR)
        return -1;
    if (n->nextents > MAX_EXTENTS)
        return -1;
    return 0;
}

/* ---- Extent codec: 16B start u64 LE || len u64 LE. ---- */

static inline int layout_extent_encode(const layout_extent_t *e, uint8_t *out,
                                       unsigned long outlen)
{
    if (!e || !out)
        return -1;
    if (outlen < LAYOUT_EXTENT_SIZE)
        return -1;
    layout_st64le(out, e->start);
    layout_st64le(out + 8, e->len);
    return 0;
}

static inline int layout_extent_decode(const uint8_t *buf, unsigned long len,
                                       layout_extent_t *e)
{
    if (!buf || !e)
        return -1;
    if (len < LAYOUT_EXTENT_SIZE)
        return -1;
    /* Length-checked: len >= 16, every access below is at < 16. */
    e->start = layout_ld64le(buf);
    e->len = layout_ld64le(buf + 8);
    return 0;
}

#endif /* MOONLIGHT_CRYPTBLK_LAYOUT_H */
