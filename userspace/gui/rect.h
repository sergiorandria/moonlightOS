/* userspace/gui/rect.h - pixel math for the 800x600x32 framebuffer.
 * Portable C99, freestanding-safe: stdint.h only, static inline, no malloc,
 * no host calls. All arithmetic wrap-safe (overflow checked BEFORE compare).
 * Fail closed: invalid inputs yield a sentinel (rect_off) or 0 (fill_ok). */

#ifndef GUI_RECT_H
#define GUI_RECT_H

#include <stdint.h>

#define GUI_W 800
#define GUI_H 600
#define GUI_BPP 4
#define GUI_STRIDE (800*4)
#define GUI_FB_MAX (800*600*4)

/* rect_off: row-major pixel index of (x, y). Fail closed: out-of-bounds
 * coordinates return 0xFFFFFFFFu, never a valid index (max valid index is
 * 599*800+799 = 479999). The in-bounds multiply cannot overflow (y < 600). */
static inline uint32_t rect_off(uint32_t x, uint32_t y) {
    if (x >= (uint32_t)GUI_W || y >= (uint32_t)GUI_H) {
        return 0xFFFFFFFFu;
    }
    return y * (uint32_t)GUI_W + x;
}

/* rect_fill_ok: nonzero rectangle [x,x+w) x [y,y+h) lies inside the frame.
 * Wrap-safe: x+w / y+h overflow is rejected BEFORE the bounds compare. */
static inline int rect_fill_ok(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    uint32_t xe, ye, last, end;
    if (w == 0u || h == 0u) {
        return 0;
    }
    if (x >= (uint32_t)GUI_W || y >= (uint32_t)GUI_H) {
        return 0;
    }
    xe = x + w;
    if (xe < x || xe > (uint32_t)GUI_W) {
        return 0; /* wrap-around, then right-edge overhang */
    }
    ye = y + h;
    if (ye < y || ye > (uint32_t)GUI_H) {
        return 0; /* wrap-around, then bottom-edge overhang */
    }
    /* stride-overflow: the end byte of the last touched pixel must sit
     * inside the framebuffer. Bounds above give last <= 480000, so neither
     * multiply below can wrap; the checks stay as fail-closed guards. */
    last = (ye - 1u) * (uint32_t)GUI_W + xe;
    if (last > (uint32_t)GUI_W * (uint32_t)GUI_H) {
        return 0;
    }
    end = last * (uint32_t)GUI_BPP;
    if (end < last || end > (uint32_t)GUI_FB_MAX) {
        return 0;
    }
    return 1;
}

#endif /* GUI_RECT_H */
