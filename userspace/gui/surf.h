/* userspace/gui/surf.h - S4b surface math. Portable C99, stdint.h only. */
#ifndef GUI_SURF_H
#define GUI_SURF_H
#include <stdint.h>
#include "rect.h"
#define SURF_N 4
#define SURF_W 40
#define SURF_H 30
#define SURF_MAX (SURF_W*SURF_H*4u)
#define CHROME_H 20
static inline int surf_wh_ok(uint32_t wh) {
    uint32_t w = (wh >> 16) & 0xFFFFu;
    uint32_t h = wh & 0xFFFFu;
    if (w == 0u || h == 0u) return 0;
    if (w > (uint32_t)SURF_W || h > (uint32_t)SURF_H) return 0;
    return 1;
}
static inline int surf_fill_ok(uint32_t sid, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    if (sid >= (uint32_t)SURF_N) return 0;
    if (w == 0u || h == 0u) return 0;
    if (x >= (uint32_t)SURF_W || y >= (uint32_t)SURF_H) return 0;
    { uint32_t xe = x + w; if (xe < x || xe > (uint32_t)SURF_W) return 0; }
    { uint32_t ye = y + h; if (ye < y || ye > (uint32_t)SURF_H) return 0; }
    return 1;
}
static inline uint32_t surf_px(uint32_t sid, uint32_t x, uint32_t y) {
    (void)sid; return y * (uint32_t)SURF_W + x;
}
#endif
