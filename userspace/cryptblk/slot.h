/* userspace/cryptblk/slot.h - passphrase-slot wrap/unwrap/wipe over aead.h.
 * Pure C99, stdint.h + ../crypt headers only (NO string.h: hand loops
 * with bounds, freestanding-safe like the S3 ELFs built with -fno-builtin).
 * Every loop carries a bound comment. crypt_wipe (from
 * ../crypt/crypt_util.h via aead.h) clears key-bearing locals and outputs
 * before every failure return.
 *
 * AEAD nonce discipline for slots (unique-(slot,salt) construction):
 * the 12B ChaCha20-Poly1305 nonce is salt[8] || label-u32-LE, and the
 * associated data is "SLOT" || label-u32-LE || iters-u32-LE. Fresh
 * production-DRBG salt per wrap makes every wrapped record
 * distinct even for the same KEK+VMK (the test seeds the DRBG explicitly
 * and checks two wraps differ); the label in BOTH nonce and AD means a
 * record transplanted across labels fails authentication. iters == 0 is
 * rejected on both paths as a public-metadata guard.
 *
 * Single-DRBG-owner rule: this header never defines CRYPT_DRBG_DEFINE;
 * the test TU (or exactly one TU per later ELF) owns the
 * kdf_production.h DRBG state.
 * Wrapped layout: rec.wrapped = ct[32] || tag[16] (SLOT_WRAPPED 48). */
#ifndef MOONLIGHT_CRYPTBLK_SLOT_H
#define MOONLIGHT_CRYPTBLK_SLOT_H

#include <stdint.h>

#include "../crypt/aead.h"
#include "layout.h"

static inline int slot_wrap(const uint8_t *kek, const uint8_t *vmk,
                            const uint8_t *salt, uint32_t label,
                            uint32_t iters, layout_slot_t *rec)
{
    uint8_t nonce[12];
    uint8_t ad[12];
    unsigned long i;
    int rc;
    if (!kek || !vmk || !salt || !rec)
        return -1;
    if (iters == 0)
        return -1;
    for (i = 0; i < 8; i++) /* bound: 8 */
        nonce[i] = salt[i];
    layout_st32le(nonce + 8, label);
    ad[0] = (uint8_t)'S';
    ad[1] = (uint8_t)'L';
    ad[2] = (uint8_t)'O';
    ad[3] = (uint8_t)'T';
    layout_st32le(ad + 4, label);
    layout_st32le(ad + 8, iters);
    rc = aead_seal(kek, nonce, ad, sizeof(ad), vmk, 32,
                   rec->wrapped, rec->wrapped + 32);
    crypt_wipe(nonce, sizeof(nonce));
    crypt_wipe(ad, sizeof(ad));
    if (rc != 0) {
        crypt_wipe(rec->wrapped, sizeof(rec->wrapped));
        return -1;
    }
    for (i = 0; i < 8; i++) /* bound: 8 */
        rec->salt[i] = salt[i];
    rec->iters = iters;
    rec->label = label;
    return 0;
}

static inline int slot_unwrap(const uint8_t *kek, const layout_slot_t *rec,
                              uint8_t *out)
{
    uint8_t nonce[12];
    uint8_t ad[12];
    unsigned long i;
    int rc;
    if (!kek || !rec || !out)
        return -1;
    if (rec->iters == 0) {
        crypt_wipe(out, 32);
        crypt_wipe(nonce, sizeof(nonce));
        crypt_wipe(ad, sizeof(ad));
        return -1;
    }
    for (i = 0; i < 8; i++) /* bound: 8 */
        nonce[i] = rec->salt[i];
    layout_st32le(nonce + 8, rec->label);
    ad[0] = (uint8_t)'S';
    ad[1] = (uint8_t)'L';
    ad[2] = (uint8_t)'O';
    ad[3] = (uint8_t)'T';
    layout_st32le(ad + 4, rec->label);
    layout_st32le(ad + 8, rec->iters);
    rc = aead_open(kek, nonce, ad, sizeof(ad),
                   rec->wrapped, 32, rec->wrapped + 32, out);
    crypt_wipe(nonce, sizeof(nonce));
    crypt_wipe(ad, sizeof(ad));
    if (rc != 0) {
        /* aead_open already wiped out; belt-and-braces. */
        crypt_wipe(out, 32);
        return -1;
    }
    return 0;
}

static inline void slot_wipe(layout_slot_t *rec)
{
    if (!rec)
        return;
    crypt_wipe(rec, sizeof(*rec));
}

#endif /* MOONLIGHT_CRYPTBLK_SLOT_H */
