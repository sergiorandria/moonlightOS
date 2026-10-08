/* virtio-sound stub — userspace audio. Not spawned (no tid). */
#include <stdbool.h>
#include "stub_mmio.h"

#define SOUND_MIN_LEN 0x1000u
#define VIRTIO_DEV_SOUND 25u

static stub_mmio_caps_t snd_caps;
static stub_mmio_stats_t snd_st;
static bool snd_up;

bool sound_driver_init(stub_mmio_caps_t c)
{
    snd_up = false;
    if (!stub_mmio_caps_ok(c, SOUND_MIN_LEN)) {
        snd_st.rejects++;
        return false;
    }
    snd_caps = c;
    snd_up = true;
    snd_st.inits++;
    return true;
}

int sound_driver_play(void)
{
    if (!snd_up) {
        snd_st.rejects++;
        return -1;
    }
    snd_st.ops++;
    return -1;
}

void sound_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = snd_st;
}

void sound_driver_reboot(void)
{
    snd_up = false;
    snd_st.inits = 0;
    snd_st.rejects = 0;
    snd_st.ops = 0;
}

unsigned sound_virtio_id(void)
{
    return VIRTIO_DEV_SOUND;
}
