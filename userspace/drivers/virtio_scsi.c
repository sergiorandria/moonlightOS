/* virtio-scsi stub — userspace compartment. Kernel maps no SCSI leaf yet
 * (no tid). Init validates caps only; submit is ENOSYS until spawn. */
#include <stdbool.h>
#include "stub_mmio.h"
#include "virtio_mmio.h"

#define SCSI_MIN_LEN 0x1000u
#define VIRTIO_DEV_SCSI 8u

static stub_mmio_caps_t scsi_caps;
static stub_mmio_stats_t scsi_st;
static bool scsi_up;

bool scsi_driver_init(stub_mmio_caps_t c)
{
    scsi_up = false;
    if (!stub_mmio_caps_ok(c, SCSI_MIN_LEN)) {
        scsi_st.rejects++;
        return false;
    }
    scsi_caps = c;
    scsi_up = true;
    scsi_st.inits++;
    return true;
}

int scsi_driver_submit(void)
{
    if (!scsi_up) {
        scsi_st.rejects++;
        return -1;
    }
    scsi_st.ops++;
    return -1; /* stub: no command ring */
}

void scsi_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = scsi_st;
}

void scsi_driver_reboot(void)
{
    scsi_up = false;
    scsi_st.inits = 0;
    scsi_st.rejects = 0;
    scsi_st.ops = 0;
}

unsigned scsi_virtio_id(void)
{
    return VIRTIO_DEV_SCSI;
}
