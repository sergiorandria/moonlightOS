/* virtio-balloon stub — userspace memory balloon. Not spawned. */
#include <stdbool.h>
#include "stub_mmio.h"

#define BALLOON_MIN_LEN 0x1000u
#define VIRTIO_DEV_BALLOON 5u

static stub_mmio_caps_t balloon_caps;
static stub_mmio_stats_t balloon_st;
static bool balloon_up;

bool balloon_driver_init(stub_mmio_caps_t c)
{
    balloon_up = false;
    if (!stub_mmio_caps_ok(c, BALLOON_MIN_LEN)) {
        balloon_st.rejects++;
        return false;
    }
    balloon_caps = c;
    balloon_up = true;
    balloon_st.inits++;
    return true;
}

int balloon_driver_inflate(void)
{
    if (!balloon_up) {
        balloon_st.rejects++;
        return -1;
    }
    balloon_st.ops++;
    return -1;
}

void balloon_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = balloon_st;
}

void balloon_driver_reboot(void)
{
    balloon_up = false;
    balloon_st.inits = 0;
    balloon_st.rejects = 0;
    balloon_st.ops = 0;
}

unsigned balloon_virtio_id(void)
{
    return VIRTIO_DEV_BALLOON;
}
