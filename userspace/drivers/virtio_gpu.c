/* virtio-gpu stub — alternate display path. Live GUI uses bochs (tid 10).
 * This driver is not mapped; gpu would be a second display server, never
 * in-kernel. */
#include <stdbool.h>
#include "stub_mmio.h"

#define GPU_MIN_LEN 0x1000u
#define VIRTIO_DEV_GPU 16u

static stub_mmio_caps_t gpu_caps;
static stub_mmio_stats_t gpu_st;
static bool gpu_up;

bool gpu_driver_init(stub_mmio_caps_t c)
{
    gpu_up = false;
    if (!stub_mmio_caps_ok(c, GPU_MIN_LEN)) {
        gpu_st.rejects++;
        return false;
    }
    gpu_caps = c;
    gpu_up = true;
    gpu_st.inits++;
    return true;
}

int gpu_driver_flush(void)
{
    if (!gpu_up) {
        gpu_st.rejects++;
        return -1;
    }
    gpu_st.ops++;
    return -1;
}

void gpu_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = gpu_st;
}

void gpu_driver_reboot(void)
{
    gpu_up = false;
    gpu_st.inits = 0;
    gpu_st.rejects = 0;
    gpu_st.ops = 0;
}

unsigned gpu_virtio_id(void)
{
    return VIRTIO_DEV_GPU;
}
