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
     * inside the framebuffer. Bounds above give last <= 479999, so neither
     * multiply below can wrap; the checks stay as fail-closed guards. */
    last = (ye - 1u) * (uint32_t)GUI_W + (xe - 1u);
    if (last > (uint32_t)GUI_W * (uint32_t)GUI_H) {
        return 0;
    }
    end = last * (uint32_t)GUI_BPP;
    if (end < last || end > (uint32_t)GUI_FB_MAX) {
        return 0;
    }
    return 1;
}

/* rect_clip_fill: clip [x,x+w) x [y,y+h) to the 800x600 frame.
 * Wrap-safe (xe/ye checked before compare, like rect_fill_ok). Returns 1
 * with *cx,*cy,*cw,*ch clipped; 0 when empty/out-of-bounds. Lets fb_fill
 * clip once so its inner loop runs unchecked. Ref: Bochs VGA 800x600x32. */
static inline int rect_clip_fill(uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                                 uint32_t *cx, uint32_t *cy, uint32_t *cw, uint32_t *ch) {
    uint32_t xe, ye;
    if (!cx || !cy || !cw || !ch) {
        return 0;
    }
    if (w == 0u || h == 0u) {
        return 0;
    }
    if (x >= (uint32_t)GUI_W || y >= (uint32_t)GUI_H) {
        return 0;
    }
    xe = x + w;
    if (xe < x) {
        return 0;
    }
    if (xe > (uint32_t)GUI_W) {
        xe = (uint32_t)GUI_W;
    }
    ye = y + h;
    if (ye < y) {
        return 0;
    }
    if (ye > (uint32_t)GUI_H) {
        ye = (uint32_t)GUI_H;
    }
    if (xe <= x || ye <= y) {
        return 0;
    }
    *cx = x;
    *cy = y;
    *cw = xe - x;
    *ch = ye - y;
    return 1;
}

/* scroll_region_n: single-pass shift for N text lines.
 * line_h = 16, fb_h = 600. Returns rows to move + bottom clear rect, so
 * N scroll lines cost one pass, not N full-frame copies. Over-tall N
 * clamps to full-frame clear. Returns 0 when n == 0. */
static inline int scroll_region_n(uint32_t n, uint32_t line_h, uint32_t fb_h,
                                  uint32_t *move_rows, uint32_t *clear_y, uint32_t *clear_h) {
    uint64_t shift;
    if (!move_rows || !clear_y || !clear_h) {
        return 0;
    }
    if (n == 0u || line_h == 0u || fb_h == 0u || fb_h > 600u) {
        return 0;
    }
    shift = (uint64_t)n * (uint64_t)line_h;
    if (shift >= (uint64_t)fb_h) {
        *move_rows = 0u;
        *clear_y = 0u;
        *clear_h = fb_h;
        return 1;
    }
    *move_rows = fb_h - (uint32_t)shift;
    *clear_y = fb_h - (uint32_t)shift;
    *clear_h = (uint32_t)shift;
    return 1;
}

/* glyph_cell_ok: dispatch precondition for unchecked glyph paint.
 * col < cols && row < rows (100x37). Checked once in dispatch; the
 * 8x16 inner loop then skips per-pixel bounds tests. */
static inline int glyph_cell_ok(uint32_t col, uint32_t row, uint32_t cols, uint32_t rows) {
    if (cols == 0u || rows == 0u) {
        return 0;
    }
    if (col >= cols || row >= rows) {
        return 0;
    }
    return 1;
}

#endif /* GUI_RECT_H */
