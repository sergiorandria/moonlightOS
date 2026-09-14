/* libc random: getrandom/getentropy over the kernel PRNG +
 * arc4random family on top. */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <bits/ml_sys.h>

long __ml_ret(long r);

ssize_t getrandom(void *buf, size_t n, unsigned flags) {
    long r;
    if (!buf) {
        errno = EFAULT;
        return -1;
    }
    if (flags & ~3u) {
        errno = EINVAL;
        return -1;
    }
    r = __ml_call6(LX_SYS_getrandom, (long)buf, (long)n, (long)flags,
                   0, 0, 0);
    return (ssize_t)__ml_ret(r);
}

int getentropy(void *buf, size_t n) {
    ssize_t r;
    if (n > 256) {
        errno = EIO;
        return -1;
    }
    r = getrandom(buf, n, 0);
    return r < 0 ? -1 : 0;
}

static uint64_t ml_arc4_state[2] = {0x8a5cd789635d2d2full,
                                    0x9e3779b97f4a7c15ull};
static int ml_arc4_seeded = 0;

static void ml_arc4_seed(void) {
    char tmp[32];
    size_t i;
    if (ml_arc4_seeded) return;
    if (getrandom(tmp, sizeof(tmp), 0) == (ssize_t)sizeof(tmp)) {
        for (i = 0; i < 8; i++) {
            ml_arc4_state[0] =
                ml_arc4_state[0] * 6364136223846793005ull +
                (uint64_t)(unsigned char)tmp[i];
            ml_arc4_state[1] ^= (uint64_t)(unsigned char)tmp[8 + i]
                                << (8 * (i % 8));
        }
    }
    if (ml_arc4_state[0] == 0 && ml_arc4_state[1] == 0)
        ml_arc4_state[1] = 0x9e3779b97f4a7c15ull;
    ml_arc4_seeded = 1;
}

uint32_t arc4random(void) {
    uint64_t x, y;
    ml_arc4_seed();
    x = ml_arc4_state[0];
    y = ml_arc4_state[1];
    x ^= x << 23;
    x ^= x >> 17;
    x ^= y ^ (y >> 26);
    ml_arc4_state[0] = y;
    ml_arc4_state[1] = x;
    return (uint32_t)(x + y);
}

void arc4random_buf(void *buf, size_t n) {
    size_t i;
    char *p = buf;
    if (!buf) return;
    for (i = 0; i < n; i++) {
        if ((i & 3) == 0) {
            uint32_t v = arc4random();
            memcpy(p + i, &v, n - i >= 4 ? 4 : n - i);
            i += (n - i >= 4 ? 4 : n - i) - 1;
        }
    }
}

uint32_t arc4random_uniform(uint32_t bound) {
    /* Rejection sampling (unbiased). */
    uint32_t m = -bound % bound, v;
    if (bound < 2) return 0;
    do {
        v = arc4random();
    } while (v < m);
    return v % bound;
}
