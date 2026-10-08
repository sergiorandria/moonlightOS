/* virtio-fs stub — userspace virtiofs. Not spawned (no tid). */
#include <stdbool.h>
#include "stub_mmio.h"

#define FS_MIN_LEN 0x1000u
#define VIRTIO_DEV_FS 26u

static stub_mmio_caps_t fs_caps;
static stub_mmio_stats_t fs_st;
static bool fs_up;

bool virtio_fs_driver_init(stub_mmio_caps_t c)
{
    fs_up = false;
    if (!stub_mmio_caps_ok(c, FS_MIN_LEN)) {
        fs_st.rejects++;
        return false;
    }
    fs_caps = c;
    fs_up = true;
    fs_st.inits++;
    return true;
}

int virtio_fs_driver_lookup(void)
{
    if (!fs_up) {
        fs_st.rejects++;
        return -1;
    }
    fs_st.ops++;
    return -1;
}

void virtio_fs_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = fs_st;
}

void virtio_fs_driver_reboot(void)
{
    fs_up = false;
    fs_st.inits = 0;
    fs_st.rejects = 0;
    fs_st.ops = 0;
}

unsigned virtio_fs_id(void)
{
    return VIRTIO_DEV_FS;
}
