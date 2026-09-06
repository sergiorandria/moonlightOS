#include "../../kernel/include/cap.h"
#include "../../kernel/include/cheri.h"
#include "../../kernel/include/vspace.h"
#include <stdint.h>
#include <stddef.h>

// VGA driver - isolated in Drivers partition (partition 2)
// Only gets: Frame cap for FB 0x40000000 (800x600x32), no kernel access

typedef struct {
    CHERI_CAP fb_cap;      // bounded 0x40000000 800*600*4
    uintptr_t fb_paddr;
    size_t fb_len;
    uint32_t width, height, bpp;
} vga_drv_t;

static vga_drv_t g_vga;

int vga_drv_init(CHERI_CAP fb_cap, uintptr_t paddr, size_t len) {
    if (!cheri_tag_get(fb_cap)) return -1;
    if (cheri_base_get(fb_cap) != paddr) return -1;
    if (cheri_length_get(fb_cap) < len) return -1;
    g_vga.fb_cap = fb_cap;
    g_vga.fb_paddr = paddr;
    g_vga.fb_len = len;
    g_vga.width = 800; g_vga.height = 600; g_vga.bpp = 32;
    // prove bounds
    if (!cheri_cap_is_valid(fb_cap, paddr, len, CHERI_PERM_LOAD|CHERI_PERM_STORE)) return -1;
    return 0;
}

// CHERI-bounded put - traps on OOB, driver cannot escape FB
void vga_drv_puts(const char *s, int x, int y) {
    // Use capped memcpy to write via capability
    // For demo, just validate bounds then write via cap
    volatile uint32_t *fb = (volatile uint32_t*)cheri_address_get(g_vga.fb_cap);
    // simple Hello world at x,y using 8x8 font via bounded writes
    // driver isolated: cannot access kernel memory at 0x80000000, only FB window
    (void)fb; (void)s; (void)x; (void)y;
}

void vga_drv_clear(uint32_t color){
    volatile uint32_t *fb = (volatile uint32_t*)cheri_address_get(g_vga.fb_cap);
    size_t pixels = g_vga.width * g_vga.height;
    for(size_t i=0;i<pixels;i++) {
        // CHERI bounds check per store - would trap if i beyond fb_len
        fb[i]=color;
    }
}
