/* tests/test_gui.c - KATs for gui/rect.h + gui/pci.h. */
#include <stdio.h>
#include <string.h>
#include "../userspace/gui/rect.h"
#include "../userspace/gui/pci.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    /* rect_off: origin, last pixel, stride. */
    CHECK(rect_off(0, 0) == 0);
    CHECK(rect_off(799, 599) == (599u * 800u + 799u));
    /* fill_ok: in-bounds, edge-exact, zero-size reject, oob reject,
     * wrap-around reject (x+w < x), stride-overflow reject. */
    CHECK(rect_fill_ok(0, 0, 800, 600));
    CHECK(rect_fill_ok(0, 0, 1, 1));
    CHECK(!rect_fill_ok(0, 0, 0, 1));       /* zero width */
    CHECK(!rect_fill_ok(800, 0, 1, 1));     /* x edge */
    CHECK(!rect_fill_ok(0, 600, 1, 1));     /* y edge */
    CHECK(!rect_fill_ok(799, 599, 2, 2));   /* corner overhang */
    CHECK(!rect_fill_ok(0xFFFFFF00u, 0, 0x200u, 1)); /* wrap */
    /* pci_cfg_off: bus0/dev31/fn7 exact offset. */
    CHECK(pci_cfg_off(0, 31, 7) == (31u * 2048u + 7u * 256u));
    CHECK(pci_cfg_off(1, 0, 0) == (1u * 1048576u));
    /* pci_bar_ok: 16M LFB ok, 0 reject, >64M reject, unaligned reject. */
    CHECK(pci_bar_ok(0x40000000u, 0x1000000u));
    CHECK(!pci_bar_ok(0x40000000u, 0));
    CHECK(!pci_bar_ok(0x40000000u, 0x8000000u));
    CHECK(!pci_bar_ok(0x40000001u, 0x1000u));
    printf("PASS: test_gui\n");
    return 0;
}
