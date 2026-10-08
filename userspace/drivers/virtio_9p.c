/* virtio-9p stub — userspace fs transport. Not spawned (no tid). */
#include <stdbool.h>
#include "stub_mmio.h"

#define P9_MIN_LEN 0x1000u
#define VIRTIO_DEV_9P 9u

static stub_mmio_caps_t p9_caps;
static stub_mmio_stats_t p9_st;
static bool p9_up;

bool p9_driver_init(stub_mmio_caps_t c)
{
    p9_up = false;
    if (!stub_mmio_caps_ok(c, P9_MIN_LEN)) {
        p9_st.rejects++;
        return false;
    }
    p9_caps = c;
    p9_up = true;
    p9_st.inits++;
    return true;
}

int p9_driver_walk(void)
{
    if (!p9_up) {
        p9_st.rejects++;
        return -1;
    }
    p9_st.ops++;
    return -1;
}

void p9_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = p9_st;
}

void p9_driver_reboot(void)
{
    p9_up = false;
    p9_st.inits = 0;
    p9_st.rejects = 0;
    p9_st.ops = 0;
}

unsigned p9_virtio_id(void)
{
    return VIRTIO_DEV_9P;
}
