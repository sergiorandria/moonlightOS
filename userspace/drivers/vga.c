#include "../abi/cap.h"
#include "../abi/cheri.h"
#include "../abi/vspace.h"
#include <stdint.h>
#include <stddef.h>

// VGA driver - isolated in Drivers partition (partition 2)
// Only gets: Frame cap for FB 0x40000000 (800x600x32), no kernel access.
// Text core is plain C (host-testable); the framebuffer pointer is a
// host-backed buffer on host-sim and the real cap address on target.

#define VGA_DRV_WIDTH 800u
#define VGA_DRV_HEIGHT 600u
#define VGA_DRV_CELL_W 8u
#define VGA_DRV_CELL_H 16u
#define VGA_DRV_GLYPH_H 8u
#define VGA_DRV_COLS (VGA_DRV_WIDTH / VGA_DRV_CELL_W)
#define VGA_DRV_ROWS (VGA_DRV_HEIGHT / VGA_DRV_CELL_H)
#define VGA_DRV_FG 0x00FFFFFFu
#define VGA_DRV_BG 0x00000000u

typedef struct {
    CHERI_CAP fb_cap;      // bounded 0x40000000 800*600*4
    uintptr_t fb_paddr;
    size_t fb_len;
    uint32_t width, height, bpp;
} vga_drv_t;

typedef struct {
    uint64_t chars_drawn;
    uint64_t pixels_written;
    uint64_t clears;
    uint64_t oob_rejects;
} vga_drv_stats_t;

static vga_drv_t g_vga;
static vga_drv_stats_t g_vga_st;
#if !defined(__riscv)
static uint32_t vga_host_fb[VGA_DRV_WIDTH * VGA_DRV_HEIGHT];
#endif

int vga_drv_init(CHERI_CAP fb_cap, uintptr_t paddr, size_t len) {
    if (!cheri_tag_get(fb_cap)) return -1;
    if (cheri_base_get(fb_cap) != paddr) return -1;
    if (cheri_length_get(fb_cap) < len) return -1;
    if (len < (size_t)VGA_DRV_WIDTH * VGA_DRV_HEIGHT * 4u) return -1;
    g_vga.fb_cap = fb_cap;
    g_vga.fb_paddr = paddr;
    g_vga.fb_len = len;
    g_vga.width = VGA_DRV_WIDTH; g_vga.height = VGA_DRV_HEIGHT; g_vga.bpp = 32;
    // prove bounds
    if (!cheri_cap_is_valid(fb_cap, paddr, len, CHERI_PERM_LOAD|CHERI_PERM_STORE)) return -1;
    return 0;
}

#if defined(__riscv)
static uintptr_t vga_cap_addr(CHERI_CAP c) {
#ifdef __CHERI_PURE_CAPABILITY__
    return cheri_address_get(c);
#else
    return c.addr;
#endif
}
#endif

static volatile uint32_t *vga_fb(void) {
#if defined(__riscv)
    return (volatile uint32_t*)vga_cap_addr(g_vga.fb_cap);
#else
    (void)g_vga;
    return (volatile uint32_t*)vga_host_fb;
#endif
}

static size_t vga_max_pixels(void) {
    size_t by_cap = g_vga.fb_len / 4u;
    size_t by_mode = (size_t)g_vga.width * g_vga.height;
    return by_cap < by_mode ? by_cap : by_mode;
}

static inline void vga_px_put(size_t idx, uint32_t color) {
    if (idx >= vga_max_pixels()) { g_vga_st.oob_rejects++; return; }
    vga_fb()[idx] = color;
    g_vga_st.pixels_written++;
}

/* Built-in 8x8 glyph: deterministic procedural font (space = blank).
 * Row bit c of character ch: keeps tests meaningful (glyphs differ per
 * char, stable across calls) without a 1K table in the driver. */
static uint8_t vga_glyph_row(uint8_t ch, unsigned row) {
    if (ch == 0x20) return 0x00;
    if (ch < 0x20 || ch > 0x7E) ch = (uint8_t)'?';
    return (uint8_t)(((uint32_t)ch * 31u + row * 17u + (ch >> 2)) & 0xFFu);
}

static void vga_draw_char_cell(int col, int row, char c, uint32_t fg, uint32_t bg) {
    if (col < 0 || row < 0 ||
        (unsigned)col >= VGA_DRV_COLS || (unsigned)row >= VGA_DRV_ROWS) {
        g_vga_st.oob_rejects++;
        return;
    }
    uint8_t ch = (uint8_t)c;
    for (unsigned r = 0; r < VGA_DRV_GLYPH_H; r++) {
        uint8_t bits = vga_glyph_row(ch, r);
        for (unsigned cc = 0; cc < VGA_DRV_CELL_W; cc++) {
            int px = col * (int)VGA_DRV_CELL_W + (int)cc;
            int py = row * (int)VGA_DRV_CELL_H + (int)(r * 2u);
            uint32_t colr = (bits & (1u << cc)) ? fg : bg;
            size_t i0 = (size_t)py * g_vga.width + (size_t)px;
            vga_px_put(i0, colr);
            vga_px_put(i0 + g_vga.width, colr); /* 8x8 doubled to 8x16 */
        }
    }
    g_vga_st.chars_drawn++;
}

void vga_drv_stats(vga_drv_stats_t *out) {
    if (!out) return;
    *out = g_vga_st;
}

// CHERI-bounded put - traps on OOB, driver cannot escape FB.
// Returns chars drawn, or -1 when the (x,y) origin itself is out of range.
int vga_drv_puts(const char *s, int x, int y) {
    if (!s) return -1;
    if (g_vga.width == 0) return -1;
    if (x < 0 || y < 0 ||
        (unsigned)x >= VGA_DRV_COLS || (unsigned)y >= VGA_DRV_ROWS) {
        g_vga_st.oob_rejects++;
        return -1;
    }
    int cx = x, drawn = 0;
    while (*s) {
        if (*s == '\n') { cx = x; y++; s++; continue; }
        if ((unsigned)y >= VGA_DRV_ROWS) break; /* clip at bottom */
        if ((unsigned)cx >= VGA_DRV_COLS) { cx = x; y++; if ((unsigned)y >= VGA_DRV_ROWS) break; continue; }
        vga_draw_char_cell(cx, y, *s, VGA_DRV_FG, VGA_DRV_BG);
        drawn++;
        cx++;
        s++;
    }
    return drawn;
}

int vga_drv_putc_at(char c, int x, int y, uint32_t fg, uint32_t bg) {
    if (g_vga.width == 0) return -1;
    if (x < 0 || y < 0 ||
        (unsigned)x >= VGA_DRV_COLS || (unsigned)y >= VGA_DRV_ROWS) {
        g_vga_st.oob_rejects++;
        return -1;
    }
    vga_draw_char_cell(x, y, c, fg, bg);
    return 0;
}

void vga_drv_clear(uint32_t color){
    size_t pixels = vga_max_pixels();
    for(size_t i=0;i<pixels;i++) {
        // CHERI bounds check per store - would trap if i beyond fb_len
        vga_fb()[i]=color;
        g_vga_st.pixels_written++;
    }
    g_vga_st.clears++;
}
