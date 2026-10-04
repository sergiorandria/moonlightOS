/* userspace/gui/compositor.c - Compositor stub. No kernel mapping.
 * Real compose lives in the gui ELF (surf.h + FILL/COMPOSE on EP10).
 * This object only proves the next-layer API compiles. */
#include "wm.h"

static uint8_t wm_used[WM_N];

int wm_create(uint32_t id, uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (!wm_id_ok(id) || wm_used[id])
        return -1;
    if (!wm_place_ok(x, y, w, h))
        return -1;
    wm_used[id] = 1;
    return 0;
}

int wm_destroy(uint32_t id)
{
    if (!wm_id_ok(id) || !wm_used[id])
        return -1;
    wm_used[id] = 0;
    return 0;
}

int wm_compose_stub(void)
{
    int i, n = 0;
    for (i = 0; i < WM_N; i++)
    { /* bound: WM_N */
        if (wm_used[i])
            n++;
    }
    return n;
}
