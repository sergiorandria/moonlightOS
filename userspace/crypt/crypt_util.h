/* userspace/crypt/crypt_util.h - shared wipe helper for the crypt headers.
 * Pure C99, stdint.h/stddef.h only: host-testable and freestanding-safe.
 * No malloc, no host calls. Included by aead.h and kdf.h (no cycles:
 * this header includes nothing project-local). */
#ifndef MOONLIGHT_CRYPT_UTIL_H
#define MOONLIGHT_CRYPT_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Volatile wipe so key-material zeroing survives optimization.
 * Call before returning out of any function whose stack held secrets. */
static inline void crypt_wipe(void *p, unsigned long n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    unsigned long i;
    for (i = 0; i < n; i++) /* bound: caller len */
        v[i] = 0;
}

#endif /* MOONLIGHT_CRYPT_UTIL_H */
