/* GPIO stub — MMIO compartment. No kernel GPIO driver. */
#include <stdbool.h>
#include "stub_mmio.h"

#define GPIO_MIN_LEN 0x1000u
#define GPIO_BASE_EXPECT 0x10060000u

static stub_mmio_caps_t gpio_caps;
static stub_mmio_stats_t gpio_st;
static bool gpio_up;

bool gpio_driver_init(stub_mmio_caps_t c)
{
    gpio_up = false;
    if (!stub_mmio_caps_ok(c, GPIO_MIN_LEN)) {
        gpio_st.rejects++;
        return false;
    }
#if !defined(__riscv)
    if (c.mmio_base != GPIO_BASE_EXPECT) {
        gpio_st.rejects++;
        return false;
    }
#endif
    gpio_caps = c;
    gpio_up = true;
    gpio_st.inits++;
    return true;
}

int gpio_driver_set(unsigned pin, unsigned val)
{
    (void)pin;
    (void)val;
    if (!gpio_up) {
        gpio_st.rejects++;
        return -1;
    }
    gpio_st.ops++;
    return -1;
}

void gpio_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = gpio_st;
}

void gpio_driver_reboot(void)
{
    gpio_up = false;
    gpio_st.inits = 0;
    gpio_st.rejects = 0;
    gpio_st.ops = 0;
}
