/* userspace/gui/compositor.h - Next-layer WM API (userspace only). */
#ifndef GUI_COMPOSITOR_H
#define GUI_COMPOSITOR_H

#include "wm.h"

int wm_create(uint32_t id, uint32_t x, uint32_t y, uint32_t w, uint32_t h);
int wm_destroy(uint32_t id);
int wm_compose_stub(void);

#endif
