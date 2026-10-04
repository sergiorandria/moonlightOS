/* virtio-console stub — userspace virtio console. Live console is EP IPC. */
#include <stdbool.h>
#include "stub_mmio.h"

#define VCON_MIN_LEN 0x1000u
#define VIRTIO_DEV_CONSOLE 3u

static stub_mmio_caps_t vcon_caps;
static stub_mmio_stats_t vcon_st;
static bool vcon_up;

bool vcon_driver_init(stub_mmio_caps_t c)
{
    vcon_up = false;
    if (!stub_mmio_caps_ok(c, VCON_MIN_LEN)) {
        vcon_st.rejects++;
        return false;
    }
    vcon_caps = c;
    vcon_up = true;
    vcon_st.inits++;
    return true;
}

int vcon_driver_putc(int c)
{
    (void)c;
    if (!vcon_up) {
        vcon_st.rejects++;
        return -1;
    }
    vcon_st.ops++;
    return -1;
}

void vcon_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = vcon_st;
}

void vcon_driver_reboot(void)
{
    vcon_up = false;
    vcon_st.inits = 0;
    vcon_st.rejects = 0;
    vcon_st.ops = 0;
}

unsigned vcon_virtio_id(void)
{
    return VIRTIO_DEV_CONSOLE;
}
