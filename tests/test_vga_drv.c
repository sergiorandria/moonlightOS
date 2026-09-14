#include "../kernel/include/cap.h"
#include "../kernel/include/cheri.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Host test for the userspace VGA text driver (bounded framebuffer). */
#include "../userspace/drivers/vga.c"

static CHERI_CAP mk_fb(uintptr_t base, size_t len) {
    CHERI_CAP c;
    memset(&c, 0, sizeof(c));
    c.base = base;
    c.top = base + len;
    c.addr = base;
    c.perms = CHERI_PERM_LOAD | CHERI_PERM_STORE;
    c.tag = 1;
    c.sealed = 0;
    return c;
}

int main(void) {
    printf("=== vga userspace driver tests ===\n");
    uintptr_t fb_base = 0x40000000u;
    size_t fb_len = (size_t)800 * 600 * 4;

    /* init validation */
    CHERI_CAP bad = mk_fb(fb_base, fb_len);
    bad.tag = 0;
    assert(vga_drv_init(bad, fb_base, fb_len) == -1);
    CHERI_CAP wrong_base = mk_fb(fb_base + 0x1000, fb_len);
    assert(vga_drv_init(wrong_base, fb_base, fb_len) == -1);
    CHERI_CAP short_cap = mk_fb(fb_base, 4096);
    assert(vga_drv_init(short_cap, fb_base, 4096) == -1);
    printf("PASS: init rejects bad caps\n");

    CHERI_CAP fb = mk_fb(fb_base, fb_len);
    assert(vga_drv_init(fb, fb_base, fb_len) == 0);
    printf("PASS: init OK\n");

    /* clear fills the framebuffer */
    vga_drv_clear(0x11223344u);
    vga_drv_stats_t st = {0};
    vga_drv_stats(&st);
    assert(st.clears == 1);
    assert(st.pixels_written == (uint64_t)800 * 600);
    assert(vga_host_fb[0] == 0x11223344u);
    assert(vga_host_fb[800 * 600 - 1] == 0x11223344u);
    printf("PASS: clear fills %lu pixels\n", (unsigned long)st.pixels_written);

    /* puts draws glyphs: pixels change, counter grows */
    vga_drv_clear(0x00000000u);
    int n = vga_drv_puts("Hi", 0, 0);
    assert(n == 2);
    vga_drv_stats(&st);
    assert(st.chars_drawn == 2);
    int nonzero = 0;
    for (int i = 0; i < 8 * 16 * 2; i++)
        if (vga_host_fb[(size_t)i % (800 * 600)] != 0) { nonzero = 1; break; }
    assert(nonzero == 1);
    printf("PASS: puts draws 2 glyphs\n");

    /* different chars render different pixels */
    vga_drv_clear(0x00000000u);
    vga_drv_putc_at('A', 0, 0, 0x00FFFFFFu, 0x00000000u);
    uint32_t snap0[8 * 16];
    for (int r = 0; r < 16; r++)
        for (int c = 0; c < 8; c++)
            snap0[r * 8 + c] = vga_host_fb[(size_t)r * 800 + c];
    vga_drv_clear(0x00000000u);
    vga_drv_putc_at('B', 0, 0, 0x00FFFFFFu, 0x00000000u);
    int diff = 0;
    for (int i = 0; i < 8 * 16; i++)
        if (vga_host_fb[i] != snap0[i]) { diff = 1; break; }
    assert(diff == 1);
    printf("PASS: glyphs differ per char\n");

    /* OOB origin rejected, framebuffer untouched */
    vga_drv_clear(0x00000000u);
    assert(vga_drv_puts("X", 1000, 0) == -1);
    assert(vga_drv_puts("X", 0, 1000) == -1);
    assert(vga_drv_puts("X", -1, 0) == -1);
    assert(vga_drv_putc_at('X', 1000, 0, 0xFFFFFFFFu, 0) == -1);
    vga_drv_stats(&st);
    assert(st.oob_rejects >= 4);
    assert(vga_host_fb[0] == 0x00000000u);
    printf("PASS: OOB puts rejected\n");

    /* newline + wrap stay inside the framebuffer */
    vga_drv_clear(0x00000000u);
    n = vga_drv_puts("AB\nCD", 98, 35);
    assert(n == 4);
    printf("PASS: newline/wrap clipped in bounds\n");

    printf("ALL VGA DRV TESTS PASS\n");
    return 0;
}
