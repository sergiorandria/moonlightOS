#pragma once
#include <stdint.h>
#include <stddef.h>
#include "types.h"
#include "vspace.h"

// VGA / Framebuffer driver - CHERI-bounded, isolated per partition
// RISC-V virt: framebuffer at 0x40000000 (800x600x32) via vspace_map

#define VGA_FB_BASE 0x40000000
#define VGA_WIDTH 800
#define VGA_HEIGHT 600
#define VGA_BPP 32

kerror_t vga_init(vspace_t *vs);
void vga_clear(uint32_t color);
void vga_puts(const char *s);
void vga_puts_at(const char *s, int x, int y, uint32_t fg, uint32_t bg);
void vga_draw_hello(void);
void vga_render_text(const char *text, int x, int y, uint32_t fg, uint32_t bg);
void vga_console_clear(void);
void vga_console_putc(char c);
void vga_console_puts(const char *s);
int vga_is_initialized(void);
