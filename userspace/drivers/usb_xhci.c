/* USB xHCI stub — userspace HCI. Kernel maps no USB leaf (no tid). */
#include <stdbool.h>
#include "stub_mmio.h"

#define USB_MIN_LEN 0x1000u
#define USB_BASE_EXPECT 0x11000000u

static stub_mmio_caps_t usb_caps;
static stub_mmio_stats_t usb_st;
static bool usb_up;

bool usb_driver_init(stub_mmio_caps_t c)
{
    usb_up = false;
    if (!stub_mmio_caps_ok(c, USB_MIN_LEN)) {
        usb_st.rejects++;
        return false;
    }
#if !defined(__riscv)
    if (c.mmio_base != USB_BASE_EXPECT) {
        usb_st.rejects++;
        return false;
    }
#endif
    usb_caps = c;
    usb_up = true;
    usb_st.inits++;
    return true;
}

int usb_driver_poll(void)
{
    if (!usb_up) {
        usb_st.rejects++;
        return -1;
    }
    usb_st.ops++;
    return -1;
}

void usb_driver_stats(stub_mmio_stats_t *out)
{
    if (out)
        *out = usb_st;
}

void usb_driver_reboot(void)
{
    usb_up = false;
    usb_st.inits = 0;
    usb_st.rejects = 0;
    usb_st.ops = 0;
}
