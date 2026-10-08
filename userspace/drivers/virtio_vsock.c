/* virtio-vsock stub — userspace guest CID. Not spawned. */
#include <stdbool.h>
#include "stub_mmio.h"

#define VSOCK_MIN_LEN 0x1000u
#define VIRTIO_DEV_VSOCK 19u

static stub_mmio_caps_t vsock_caps;
static stub_mmio_stats_t vsock_st;
static bool vsock_up;

bool vsock_driver_init(stub_mmio_caps_t c)
{
    vsock_up = false;
    if (!stub_mmio_caps_ok(c, VSOCK_MIN_LEN)) {
        vsock_st.rejects++;
        return false;
    }
    vsock_caps = c;
    vsock_up = true;
    vsock_st.inits++;
    return true;
}

int vsock_driver_connect(void)
{
    if (!vsock_up) {
        vsock_st.rejects++;
        return -1;
    }
    vsock_st.ops++;
    return -1;
}

void vsock_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = vsock_st;
}

void vsock_driver_reboot(void)
{
    vsock_up = false;
    vsock_st.inits = 0;
    vsock_st.rejects = 0;
    vsock_st.ops = 0;
}

unsigned vsock_virtio_id(void)
{
    return VIRTIO_DEV_VSOCK;
}
