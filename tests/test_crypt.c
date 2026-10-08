/* tests/test_crypt.c - layout + slot model tests for the cryptblk headers.
 * CHECK idiom + bound comments follow tests/test_aead.c. Every test buffer
 * is initialized to a fixed pattern first (never uninitialized). The DRBG is
 * used only with an explicit seed to derive deterministic slot salts in-test
 * (production salt discipline: fresh drbg_next bytes per wrap, see slot.h). */
#include <stdio.h>
#include <string.h>
/* Single DRBG owner for the host test: exactly one TU per program defines
 * CRYPT_DRBG_DEFINE (see kdf.h); this TU is it. */
#define CRYPT_DRBG_DEFINE
#include "../userspace/crypt/sha256.h"
#include "../userspace/crypt/aead.h"
#include "../userspace/crypt/kdf.h"
#include "../userspace/cryptblk/layout.h"
#include "../userspace/cryptblk/slot.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

/* Accumulated-diff zero check (same idiom as crypt_ct_eq). */
static int is_zero(const uint8_t *b, unsigned long n)
{
    unsigned diff = 0;
    unsigned long i;
    for (i = 0; i < n; i++) /* bound: caller len */
        diff |= b[i];
    return diff == 0;
}

int main(void)
{
    /* Header: accept a well-formed image built field-by-field in-test. */
    {
        vol_header_t h, back;
        uint8_t buf[8192];
        uint8_t magic_le[8];
        uint8_t zero64[64];
        unsigned long i;
        for (i = 0; i < sizeof(buf); i++) /* bound: 8192 */
            buf[i] = 0xA5;
        for (i = 0; i < sizeof(zero64); i++) /* bound: 64 */
            zero64[i] = 0;
        h.magic = CRYPT_MAGIC;
        h.version = CRYPT_VERSION;
        h.nslots = 2;
        h.iters = KDF_ITERS_DEFAULT;
        h.reserved = 0;
        for (i = 0; i < 32; i++) /* bound: 32 */
            h.salt[i] = (uint8_t)(i * 17 + 3);
        for (i = 0; i < MAX_SLOTS; i++) { /* bound: 8 */
            unsigned long j;
            for (j = 0; j < SLOT_WRAPPED; j++) /* bound: 48 */
                h.slots[i].wrapped[j] = (uint8_t)(i * 41 + j * 3 + 1);
            for (j = 0; j < 8; j++) /* bound: 8 */
                h.slots[i].salt[j] = (uint8_t)(i * 7 + j + 9);
            h.slots[i].iters = KDF_ITERS_DEFAULT;
            h.slots[i].label = (uint32_t)(6 + i);
        }
        CHECK(layout_encode(&h, buf, sizeof(buf)) == 0);
        /* Magic hits disk LE, byte-exact. */
        layout_st64le(magic_le, CRYPT_MAGIC);
        CHECK(memcmp(buf, magic_le, sizeof(magic_le)) == 0);
        CHECK(layout_parse(buf, sizeof(buf), &back) == 0);
        CHECK(back.magic == CRYPT_MAGIC);
        CHECK(back.version == CRYPT_VERSION);
        CHECK(back.nslots == 2);
        CHECK(back.iters == KDF_ITERS_DEFAULT);
        CHECK(memcmp(back.salt, h.salt, 32) == 0);
        CHECK(memcmp(back.slots[0].wrapped, h.slots[0].wrapped, SLOT_WRAPPED) == 0);
        CHECK(memcmp(back.slots[1].salt, h.slots[1].salt, 8) == 0);
        CHECK(back.slots[0].iters == KDF_ITERS_DEFAULT);
        CHECK(back.slots[1].label == 7);
        /* Trailing pad past the used region is zeroed by encode. */
        CHECK(is_zero(buf + 568, sizeof(buf) - 568));
    }

    /* Header: rejects (bad magic / version / slot-count / truncated / NULL). */
    {
        vol_header_t h, back;
        uint8_t buf[8192];
        uint8_t bad[8192];
        unsigned long i;
        for (i = 0; i < sizeof(buf); i++) /* bound: 8192 */
            buf[i] = 0;
        h.magic = CRYPT_MAGIC;
        h.version = CRYPT_VERSION;
        h.nslots = 1;
        h.iters = KDF_ITERS_DEFAULT;
        h.reserved = 0;
        for (i = 0; i < 32; i++) /* bound: 32 */
            h.salt[i] = (uint8_t)(i + 1);
        for (i = 0; i < MAX_SLOTS; i++) { /* bound: 8 */
            unsigned long j;
            for (j = 0; j < SLOT_WRAPPED; j++) /* bound: 48 */
                h.slots[i].wrapped[j] = (uint8_t)(j + i);
            for (j = 0; j < 8; j++) /* bound: 8 */
                h.slots[i].salt[j] = (uint8_t)(j + 2 * i);
            h.slots[i].iters = KDF_ITERS_DEFAULT;
            h.slots[i].label = 6;
        }
        CHECK(layout_encode(&h, buf, sizeof(buf)) == 0);
        memcpy(bad, buf, sizeof(bad));
        bad[0] ^= 0x01; /* bad magic */
        CHECK(layout_parse(bad, sizeof(bad), &back) == -1);
        memcpy(bad, buf, sizeof(bad));
        bad[8] = 2; bad[9] = 0; bad[10] = 0; bad[11] = 0; /* version 2 */
        CHECK(layout_parse(bad, sizeof(bad), &back) == -1);
        memcpy(bad, buf, sizeof(bad));
        bad[8] = 0; bad[9] = 0; bad[10] = 0; bad[11] = 0; /* version 0 */
        CHECK(layout_parse(bad, sizeof(bad), &back) == -1);
        memcpy(bad, buf, sizeof(bad));
        bad[12] = 9; bad[13] = 0; bad[14] = 0; bad[15] = 0; /* nslots 9 > 8 */
        CHECK(layout_parse(bad, sizeof(bad), &back) == -1);
        CHECK(layout_parse(buf, 100, &back) == -1); /* truncated */
        CHECK(layout_parse(buf, 567, &back) == -1); /* one short of used */
        CHECK(layout_parse((const uint8_t *)0, sizeof(buf), &back) == -1);
        CHECK(layout_parse(buf, sizeof(buf), (vol_header_t *)0) == -1);
        CHECK(layout_encode((const vol_header_t *)0, buf, sizeof(buf)) == -1);
        CHECK(layout_encode(&h, (uint8_t *)0, sizeof(buf)) == -1);
        CHECK(layout_encode(&h, buf, 100) == -1); /* output too small */
    }

    /* tag_index spot values (TAGS_PER_SECTOR 256). */
    {
        unsigned long ts, sl, last;
        CHECK(layout_tag_loc(0, &ts, &sl) == 0);
        CHECK(ts == 0 && sl == 0);
        CHECK(layout_tag_loc(255, &ts, &sl) == 0);
        CHECK(ts == 0 && sl == 255);
        CHECK(layout_tag_loc(256, &ts, &sl) == 0);
        CHECK(ts == 1 && sl == 0);
        last = 268435456UL / 4096UL - 1; /* last sector of the 256M disk */
        CHECK(last == 65535);
        CHECK(layout_tag_loc(last, &ts, &sl) == 0);
        CHECK(ts == 255 && sl == 255);
        CHECK(layout_tag_loc(0, (unsigned long *)0, &sl) == -1);
        CHECK(layout_tag_loc(0, &ts, (unsigned long *)0) == -1);
    }

    /* 512B x 8 glue: sub-sector k -> byte k*512; k >= 8 rejected. */
    {
        unsigned k;
        for (k = 0; k < 8; k++) { /* bound: 8 */
            unsigned long off = 0xA5A5A5A5UL;
            CHECK(layout_blk_off(k, &off) == 0);
            CHECK(off == (unsigned long)k * 512UL);
        }
        {
            unsigned long off = 0;
            CHECK(layout_blk_off(8, &off) == -1);
            CHECK(layout_blk_off(0, (unsigned long *)0) == -1);
        }
    }

    /* Slot wrap -> unwrap round-trip; wrong KEK / tamper fail; wipe zeroes. */
    {
        uint8_t kek[32], wrong[32], vmk[32], out[32];
        uint8_t salt[8], seed[32];
        layout_slot_t rec;
        uint8_t zeros[64];
        unsigned long i;
        for (i = 0; i < sizeof(kek); i++) /* bound: 32 */
            kek[i] = (uint8_t)(i * 31 + 7);
        for (i = 0; i < sizeof(vmk); i++) /* bound: 32 */
            vmk[i] = (uint8_t)(i * 13 + 5);
        for (i = 0; i < sizeof(seed); i++) /* bound: 32 */
            seed[i] = (uint8_t)(i * 3 + 1);
        for (i = 0; i < sizeof(zeros); i++) /* bound: 64 */
            zeros[i] = 0;
        memcpy(wrong, kek, sizeof(wrong));
        wrong[0] ^= 0x01;
        drbg_seed(seed, sizeof(seed));
        drbg_next(salt, sizeof(salt));
        for (i = 0; i < sizeof(out); i++) /* bound: 32 */
            out[i] = 0xA5;
        CHECK(slot_wrap(kek, vmk, salt, 6, KDF_ITERS_DEFAULT, &rec) == 0);
        CHECK(memcmp(rec.salt, salt, sizeof(salt)) == 0);
        CHECK(rec.label == 6 && rec.iters == KDF_ITERS_DEFAULT);
        CHECK(slot_unwrap(kek, &rec, out) == 0);
        CHECK(memcmp(out, vmk, sizeof(vmk)) == 0);
        /* Nonce separation: same KEK+VMK, fresh salt ==> different wrapped. */
        {
            layout_slot_t rec2;
            uint8_t salt2[8];
            int diff = 0;
            drbg_next(salt2, sizeof(salt2));
            CHECK(slot_wrap(kek, vmk, salt2, 6, KDF_ITERS_DEFAULT, &rec2) == 0);
            for (i = 0; i < SLOT_WRAPPED; i++) /* bound: 48 */
                diff |= (rec.wrapped[i] ^ rec2.wrapped[i]);
            CHECK(diff != 0);
            crypt_wipe(&rec2, sizeof(rec2));
        }
        /* Wrong KEK fails AND zeroes the output. */
        for (i = 0; i < sizeof(out); i++) /* bound: 32 */
            out[i] = 0xA5;
        CHECK(slot_unwrap(wrong, &rec, out) == -1);
        CHECK(is_zero(out, sizeof(out)));
        /* Tampered wrapped bytes (ct half and tag half) fail. */
        {
            layout_slot_t tam = rec;
            tam.wrapped[0] ^= 0x01;
            CHECK(slot_unwrap(kek, &tam, out) == -1);
            tam = rec;
            tam.wrapped[40] ^= 0x01;
            CHECK(slot_unwrap(kek, &tam, out) == -1);
            crypt_wipe(&tam, sizeof(tam));
        }
        /* Transplant across labels fails (label is in nonce + AD). */
        {
            layout_slot_t tam = rec;
            tam.label = 7;
            CHECK(slot_unwrap(kek, &tam, out) == -1);
            crypt_wipe(&tam, sizeof(tam));
        }
        /* iters == 0 rejected on both paths (public metadata guard). */
        CHECK(slot_wrap(kek, vmk, salt, 6, 0, &rec) == -1);
        {
            layout_slot_t tam = rec;
            tam.iters = 0;
            CHECK(slot_unwrap(kek, &tam, out) == -1);
            crypt_wipe(&tam, sizeof(tam));
        }
        /* Wipe zeroes the record; unwrap-after-wipe fails. */
        slot_wipe(&rec);
        CHECK(memcmp(&rec, zeros, sizeof(rec)) == 0);
        CHECK(slot_unwrap(kek, &rec, out) == -1);
        /* Guards. */
        CHECK(slot_wrap((const uint8_t *)0, vmk, salt, 6, KDF_ITERS_DEFAULT, &rec) == -1);
        CHECK(slot_wrap(kek, (const uint8_t *)0, salt, 6, KDF_ITERS_DEFAULT, &rec) == -1);
        CHECK(slot_wrap(kek, vmk, (const uint8_t *)0, 6, KDF_ITERS_DEFAULT, &rec) == -1);
        CHECK(slot_wrap(kek, vmk, salt, 6, KDF_ITERS_DEFAULT, (layout_slot_t *)0) == -1);
        CHECK(slot_unwrap((const uint8_t *)0, &rec, out) == -1);
        CHECK(slot_unwrap(kek, (const layout_slot_t *)0, out) == -1);
        CHECK(slot_unwrap(kek, &rec, (uint8_t *)0) == -1);
        crypt_wipe(kek, sizeof(kek)); /* key-bearing locals wiped */
        crypt_wipe(wrong, sizeof(wrong));
        crypt_wipe(vmk, sizeof(vmk));
        crypt_wipe(out, sizeof(out));
    }

    /* Extents: first-fit (alloc 3, free middle, realloc fits) + 64-cap. */
    {
        layout_alloc_t a;
        unsigned long s0, s1, s2, s3, s4;
        CHECK(layout_alloc_init(&a, 2, 1000) == 0);
        CHECK(layout_alloc(&a, 10, &s0) == 0 && s0 == 2);
        CHECK(layout_alloc(&a, 10, &s1) == 0 && s1 == 12);
        CHECK(layout_alloc(&a, 10, &s2) == 0 && s2 == 22);
        CHECK(layout_free(&a, s1, 10) == 0);
        CHECK(layout_alloc(&a, 5, &s3) == 0 && s3 == 12); /* first-fit, not bump */
        CHECK(layout_free(&a, s3, 5) == 0);
        CHECK(layout_alloc(&a, 10, &s4) == 0 && s4 == 12); /* hole coalesced */
        CHECK(layout_free(&a, 999999, 1) == -1); /* unknown run */
        CHECK(layout_free(&a, s0, 11) == -1); /* length mismatch: no partial */
        CHECK(layout_alloc(&a, 1001, &s4) == -1); /* bigger than the arena */
        CHECK(layout_alloc(&a, 0, &s4) == -1);
        CHECK(layout_alloc((layout_alloc_t *)0, 1, &s4) == -1);
        CHECK(layout_alloc(&a, 1, (unsigned long *)0) == -1);
        CHECK(layout_free((layout_alloc_t *)0, 2, 1) == -1);
        CHECK(layout_alloc_init((layout_alloc_t *)0, 0, 100) == -1);
        CHECK(layout_alloc_init(&a, 0, 0) == -1);
    }
    {
        layout_alloc_t a;
        unsigned long s, i, fails = 0;
        CHECK(layout_alloc_init(&a, 0, 100000) == 0);
        for (i = 0; i < 64; i++) { /* bound: 64 */
            CHECK(layout_alloc(&a, 1, &s) == 0);
            CHECK(s == i);
        }
        CHECK(layout_alloc(&a, 1, &s) == -1); /* 65th run: over-64 fail */
        CHECK(a.nused == MAX_EXTENTS);
        (void)fails;
    }

    /* Dirent: 27 ok / 28 rejected; ino range; 32B codec round-trip. */
    {
        layout_dirent_t d, back;
        uint8_t name27[27], name28[28], enc[32];
        unsigned long i;
        for (i = 0; i < sizeof(name27); i++) /* bound: 27 */
            name27[i] = (uint8_t)('a' + (i % 26));
        for (i = 0; i < sizeof(name28); i++) /* bound: 28 */
            name28[i] = (uint8_t)('a' + (i % 26));
        CHECK(layout_dirent_set(&d, name27, sizeof(name27), 42) == 0);
        CHECK(memcmp(d.name, name27, sizeof(name27)) == 0);
        CHECK(d.name[27] == 0 && d.ino == 42);
        CHECK(layout_dirent_encode(&d, enc, sizeof(enc)) == 0);
        CHECK(layout_dirent_decode(enc, sizeof(enc), &back) == 0);
        CHECK(memcmp(back.name, name27, sizeof(name27)) == 0);
        CHECK(back.ino == 42);
        CHECK(layout_dirent_set(&d, name27, sizeof(name27), 1023) == 0);
        CHECK(layout_dirent_set(&d, name28, sizeof(name28), 1) == -1);
        CHECK(layout_dirent_set(&d, name27, 0, 1) == -1); /* empty name */
        CHECK(layout_dirent_set(&d, name27, sizeof(name27), 1024) == -1);
        CHECK(layout_dirent_set((layout_dirent_t *)0, name27, sizeof(name27), 1) == -1);
        CHECK(layout_dirent_set(&d, (const uint8_t *)0, sizeof(name27), 1) == -1);
        CHECK(layout_dirent_encode(&d, enc, 31) == -1);
        CHECK(layout_dirent_decode(enc, 31, &back) == -1);
        CHECK(layout_dirent_encode((const layout_dirent_t *)0, enc, sizeof(enc)) == -1);
        CHECK(layout_dirent_decode((const uint8_t *)0, sizeof(enc), &back) == -1);
    }

    /* Inode validator: type range + extent-count cap. */
    {
        layout_inode_t n;
        unsigned long i;
        n.type = LAYOUT_INODE_FILE;
        n.owner = 6;
        n.size = 100;
        n.nextents = 0;
        for (i = 0; i < MAX_EXTENTS; i++) { /* bound: 64 */
            n.extents[i].start = 0;
            n.extents[i].len = 0;
        }
        CHECK(layout_inode_valid(&n) == 0);
        n.type = 9;
        CHECK(layout_inode_valid(&n) == -1);
        n.type = LAYOUT_INODE_DIR;
        n.nextents = 65;
        CHECK(layout_inode_valid(&n) == -1);
        CHECK(layout_inode_valid((const layout_inode_t *)0) == -1);
    }

    /* Extent codec: 16B round-trip + truncated decode. */
    {
        layout_extent_t e, back;
        uint8_t enc[16];
        e.start = 12345;
        e.len = 67;
        CHECK(layout_extent_encode(&e, enc, sizeof(enc)) == 0);
        CHECK(layout_extent_decode(enc, sizeof(enc), &back) == 0);
        CHECK(back.start == 12345 && back.len == 67);
        CHECK(layout_extent_decode(enc, 8, &back) == -1);
        CHECK(layout_extent_encode((const layout_extent_t *)0, enc, sizeof(enc)) == -1);
        CHECK(layout_extent_encode(&e, (uint8_t *)0, sizeof(enc)) == -1);
        CHECK(layout_extent_decode((const uint8_t *)0, sizeof(enc), &back) == -1);
        CHECK(layout_extent_decode(enc, sizeof(enc), (layout_extent_t *)0) == -1);
    }

    printf("PASS: test_crypt\n");
    return 0;
}
