/* userspace/gui/cursor.h - Pointer clamp. No LFB stores. */
#ifndef GUI_CURSOR_H
#define GUI_CURSOR_H

#include <stdint.h>
#include "rect.h"

#define CURSOR_HOT_X 0
#define CURSOR_HOT_Y 0

static inline uint32_t cursor_clamp_x(int32_t x)
{
    if (x < 0)
        return 0;
    if (x >= (int32_t)GUI_W)
        return (uint32_t)GUI_W - 1u;
    return (uint32_t)x;
}

static inline uint32_t cursor_clamp_y(int32_t y)
{
    if (y < 0)
        return 0;
    if (y >= (int32_t)GUI_H)
        return (uint32_t)GUI_H - 1u;
    return (uint32_t)y;
}

#endif /* GUI_CURSOR_H */
