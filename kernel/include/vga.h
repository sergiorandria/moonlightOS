#pragma once
#include <stdint.h>
#include <stddef.h>
#include "types.h"
#include "vspace.h"

// VGA / Framebuffer driver - CHERI-bounded, isolated per partition
// RISC-V virt: ramfb at 0x40000000 (800x600x32) via vspace_map
// x86_64: text mode at 0xB8000 (80x25)

#ifdef __x86_64__
#define VGA_TEXT_BASE 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#else
#define VGA_FB_BASE 0x40000000
#define VGA_WIDTH 800
#define VGA_HEIGHT 600
#define VGA_BPP 32
#endif

kerror_t vga_init(vspace_t *vs);
void vga_clear(uint32_t color);
void vga_puts(const char *s);
void vga_puts_at(const char *s, int x, int y, uint32_t fg, uint32_t bg);
void vga_draw_hello(void);
