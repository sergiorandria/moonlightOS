/* userspace/gui/wm.h - Window-manager math stub (S4b+). Pure C.
 * Surfaces stay in surf.h; this names on-screen windows. No LFB touch:
 * the gui ELF (tid 10) is the only compositor that may paint. */
#ifndef GUI_WM_H
#define GUI_WM_H

#include <stdint.h>
#include "rect.h"
#include "surf.h"

#define WM_N 4
#define WM_TITLE_H CHROME_H

static inline int wm_id_ok(uint32_t id)
{
    return id < (uint32_t)WM_N;
}

static inline int wm_place_ok(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (w == 0u || h == 0u)
        return 0;
    if (y < (uint32_t)WM_TITLE_H)
        return 0; /* chrome is server-only */
    if (!rect_fill_ok(x, y, w, h))
        return 0;
    return 1;
}

static inline uint32_t wm_z_clamp(uint32_t z)
{
    if (z >= (uint32_t)WM_N)
        return (uint32_t)WM_N - 1u;
    return z;
}

#endif /* GUI_WM_H */
