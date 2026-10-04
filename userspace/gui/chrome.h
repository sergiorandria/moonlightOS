/* userspace/gui/chrome.h - Trusted chrome band. Server-only paint math. */
#ifndef GUI_CHROME_H
#define GUI_CHROME_H

#include <stdint.h>
#include "surf.h"
#include "rect.h"

#define CHROME_BG 0x00202830u
#define CHROME_FG 0x00E8EEF4u

static inline int chrome_y_ok(uint32_t y)
{
    return y < (uint32_t)CHROME_H;
}

/* Clients must not FILL the chrome strip. */
static inline int chrome_client_fill_ok(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (y < (uint32_t)CHROME_H)
        return 0;
    return rect_fill_ok(x, y, w, h);
}

#endif /* GUI_CHROME_H */
