/* tests/test_stub_drivers.c - placeholder driver init/reject. */
#include <stdio.h>
#include "../userspace/drivers/gpio.c"
#include "../userspace/drivers/virtio_gpu.c"
#include "../userspace/drivers/usb_xhci.c"
#include "../userspace/drivers/virtio_balloon.c"

#define CHECK(c)                                                               \
    do                                                                         \
    {                                                                          \
        if (!(c))                                                              \
        {                                                                      \
            printf("FAIL line %d: %s\n", __LINE__, #c);                        \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void)
{
    stub_mmio_caps_t bad = {0, 0, 0};
    stub_mmio_caps_t gpio = {0x10060000u, 0x1000u, 0};
    stub_mmio_caps_t gpu = {0x10001000u, 0x1000u, 1};
    stub_mmio_stats_t st;
    CHECK(!gpio_driver_init(bad));
    CHECK(gpio_driver_init(gpio));
    CHECK(gpio_driver_set(0, 1) < 0);
    gpio_driver_stats(&st);
    CHECK(st.inits == 1 && st.ops == 1);
    CHECK(gpu_driver_init(gpu));
    CHECK(gpu_driver_flush() < 0);
    CHECK(gpu_virtio_id() == 16u);
    CHECK(usb_driver_init(gpio) == false); /* wrong base on host */
    gpio.mmio_base = 0x11000000u;
    CHECK(usb_driver_init(gpio));
    CHECK(usb_driver_poll() < 0);
    CHECK(balloon_driver_init(gpu));
    CHECK(balloon_driver_inflate() < 0);
    CHECK(balloon_virtio_id() == 5u);
    puts("PASS: test_stub_drivers");
    return 0;
}
