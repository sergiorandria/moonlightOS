/* test_console - host-sim for serial/VGA routing (console.h + flush.c).
 * Mirror (default): output hits UART/putchar either way on host (no VGA).
 * Split: flag only, output path unchanged on host. kbd_is_present() is 0
 * on host (no virtio-mmio); the target proves the split path in QEMU.
 */
#include <stdio.h>
#include <assert.h>

#include "../kernel/include/console.h"
#include "../kernel/include/kbd.h"

static int fails;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else { printf("PASS: %s\n", msg); } \
} while (0)

int main(void) {
    CHECK(console_is_split() == 0, "mirror by default");
    CHECK(kbd_is_present() == 0, "no keyboard on host");

    console_set_split(1);
    CHECK(console_is_split() == 1, "split sets");
    console_putc('~'); /* must not crash; newline keeps log tidy */
    console_putc('\n');

    console_set_split(0);
    CHECK(console_is_split() == 0, "split clears");
    console_putc('~');
    console_putc('\n');

    console_set_split(5); /* nonzero normalizes to 1 */
    CHECK(console_is_split() == 1, "nonzero normalizes");
    console_set_split(0);

    kbd_init();
    CHECK(kbd_is_present() == 0, "still absent after init");

    if (fails) {
        printf("CONSOLE TESTS: %d FAILURES\n", fails);
        return 1;
    }
    printf("ALL CONSOLE TESTS PASS\n");
    return 0;
}
