/*
 * gui_hw.c - GUI Hardware Driver (Production Microkernel Version)
 *
 * Thread 10: owns the framebuffer (Bochs VGA), VirtIO keyboard and mouse.
 * Does NOT perform shell logic or line discipline — those belong to the shell
 * (thread 1) and TTY service (thread 4) respectively.
 *
 * Display pipeline (microkernel IPC):
 *   keyboard IRQ → GUI (thread 10) → Console service (thread 3) → TTY (thread 4) → Shell (thread 1)
 *
 * In the interim boot phase (before Console/TTY are connected) the GUI thread
 * directly renders characters to the framebuffer so the user can see output
 * in the QEMU window immediately. Once the IPC pipeline is live the
 * gui_process_messages() loop takes over.
 *
 * Key bug fixes applied here:
 *   1. PCI ECAM scan: use (dev*2048 + fn*256) byte offsets, not dword indices.
 *      Previously `ecam[dev * 512]` skipped the right device.
 *   2. Vendor/device byte order: PCI id word is vendor=low16, device=high16.
 *      0x1234 | (0x1111<<16) = 0x11111234 — the comparison was correct but
 *      the scan missed the device due to bug 1.
 *   3. Real 8×16 VGA bitmap font instead of solid-colour blocks.
 *   4. Input init is fail-soft: if kbd or mouse is absent the GUI continues
 *      rather than parking forever.
 */

#include "input.h"
#include "pci.h"
#include "rect.h"
#include "services/ipc_helpers.h"
#include "services/ipc_protocol.h"
#include "virtio_input.h"
#include <stdint.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

/* ---- V2 syscalls ------------------------------------------------------- */
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_WAIT 6

/* ---- display geometry -------------------------------------------------- */
#define GUI_TID 10
#define GUI_U_BASE 0x80800000UL
#define GUI_LFB_UVA 0x80C00000UL  /* framebuffer (Bochs BAR0) */
#define GUI_ECAM_UVA 0x80E00000UL /* PCI config space (bus 0) */
/* KBD_MMIO_UVA / MOUSE_MMIO_UVA from virtio_input.h */

#define FB_WIDTH 800
#define FB_HEIGHT 600
#define FB_PIXELS (FB_WIDTH * FB_HEIGHT)

/* ---- IRQ notify bits --------------------------------------------------- */
#define KBD_IRQ_BIT 0x4UL
#define MOUSE_IRQ_BIT 0x8UL

/* ---- syscall wrappers -------------------------------------------------- */
static long u_ecall3(long sys, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2) : "r"(r_a7) : "memory");
    return r_a0;
}

static void u_putc(char c)
{
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}
static void u_puts(const char *s)
{
    while (*s)
        u_putc(*s++);
}
static long u_wait(void)
{
    return u_ecall3(V2_WAIT, 0, 0, 0);
}

/* ---- 8×16 VGA bitmap font (identical to kernel/fbconsole.h) ----------- *
 * Each entry: 16 bytes, one per scanline, bit7 = leftmost pixel.          */
static const uint8_t gui_font8x16[128][16] = {
    /* 0x00-0x1F: control characters, rendered as blank */
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    /* 0x20 SPC */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x21 !   */ {0x00, 0x00, 0x18, 0x3C, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x22 "   */ {0x00, 0x00, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x23 #   */ {0x00, 0x00, 0x36, 0x36, 0x7F, 0x36, 0x36, 0x36, 0x7F, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x24 $   */ {0x00, 0x18, 0x18, 0x3E, 0x63, 0x61, 0x60, 0x3E, 0x03, 0x43, 0x63, 0x3E, 0x18, 0x18, 0x00, 0x00},
    /* 0x25 %   */ {0x00, 0x00, 0x00, 0x00, 0x61, 0x63, 0x06, 0x0C, 0x18, 0x33, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x26 &   */ {0x00, 0x00, 0x1C, 0x36, 0x36, 0x1C, 0x3B, 0x6E, 0x66, 0x66, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x27 '   */ {0x00, 0x00, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x28 (   */ {0x00, 0x00, 0x0C, 0x18, 0x18, 0x30, 0x30, 0x30, 0x30, 0x18, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00},
    /* 0x29 )   */ {0x00, 0x00, 0x30, 0x18, 0x18, 0x0C, 0x0C, 0x0C, 0x0C, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00},
    /* 0x2A *   */ {0x00, 0x00, 0x00, 0x00, 0x99, 0x5A, 0x3C, 0xFF, 0x3C, 0x5A, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x2B +   */ {0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x2C ,   */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00},
    /* 0x2D -   */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x2E .   */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x2F /   */ {0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x30 0   */ {0x00, 0x00, 0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x31 1   */ {0x00, 0x00, 0x18, 0x38, 0x58, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x32 2   */ {0x00, 0x00, 0x3C, 0x66, 0x06, 0x06, 0x0C, 0x18, 0x30, 0x66, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x33 3   */ {0x00, 0x00, 0x3C, 0x66, 0x06, 0x06, 0x1C, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x34 4   */ {0x00, 0x00, 0x06, 0x0E, 0x1E, 0x36, 0x66, 0x7F, 0x06, 0x06, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x35 5   */ {0x00, 0x00, 0x7E, 0x60, 0x60, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x36 6   */ {0x00, 0x00, 0x1C, 0x30, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x37 7   */ {0x00, 0x00, 0x7F, 0x63, 0x03, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x38 8   */ {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x39 9   */ {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0C, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3A :   */ {0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3B ;   */ {0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3C <   */ {0x00, 0x00, 0x00, 0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3D =   */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3E >   */ {0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x3F ?   */ {0x00, 0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x40 @   */ {0x00, 0x00, 0x3E, 0x63, 0x6F, 0x69, 0x6F, 0x60, 0x60, 0x62, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x41 A   */ {0x00, 0x00, 0x08, 0x1C, 0x36, 0x63, 0x63, 0x7F, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x42 B   */ {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x43 C   */ {0x00, 0x00, 0x1E, 0x33, 0x61, 0x60, 0x60, 0x60, 0x61, 0x33, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x44 D   */ {0x00, 0x00, 0x78, 0x6C, 0x66, 0x63, 0x63, 0x63, 0x66, 0x6C, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x45 E   */ {0x00, 0x00, 0x7F, 0x60, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x46 F   */ {0x00, 0x00, 0x7F, 0x60, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x47 G   */ {0x00, 0x00, 0x1E, 0x33, 0x61, 0x60, 0x60, 0x6F, 0x63, 0x37, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x48 H   */ {0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x7F, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x49 I   */ {0x00, 0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4A J   */ {0x00, 0x00, 0x1F, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4B K   */ {0x00, 0x00, 0x63, 0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4C L   */ {0x00, 0x00, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4D M   */ {0x00, 0x00, 0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4E N   */ {0x00, 0x00, 0x63, 0x73, 0x7B, 0x7F, 0x6F, 0x67, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x4F O   */ {0x00, 0x00, 0x1C, 0x36, 0x63, 0x63, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x50 P   */ {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x51 Q   */ {0x00, 0x00, 0x1C, 0x36, 0x63, 0x63, 0x63, 0x6B, 0x6F, 0x36, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x52 R   */ {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x53 S   */ {0x00, 0x00, 0x3C, 0x66, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x54 T   */ {0x00, 0x00, 0x7E, 0x5A, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x55 U   */ {0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x56 V   */ {0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x1C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x57 W   */ {0x00, 0x00, 0x63, 0x63, 0x63, 0x63, 0x6B, 0x6B, 0x7F, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x58 X   */ {0x00, 0x00, 0x63, 0x63, 0x36, 0x1C, 0x1C, 0x1C, 0x36, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x59 Y   */ {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5A Z   */ {0x00, 0x00, 0x7F, 0x63, 0x06, 0x0C, 0x18, 0x30, 0x63, 0x63, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5B [   */ {0x00, 0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5C \   */ {0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5D ]   */ {0x00, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5E ^   */ {0x00, 0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x5F _   */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x60 `   */ {0x00, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x61 a   */ {0x00, 0x00, 0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x62 b   */ {0x00, 0x00, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x63 c   */ {0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x64 d   */ {0x00, 0x00, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x65 e   */ {0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x66, 0x7E, 0x60, 0x60, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x66 f   */ {0x00, 0x00, 0x0E, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x67 g   */ {0x00, 0x00, 0x00, 0x00, 0x3B, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x68 h   */ {0x00, 0x00, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x69 i   */ {0x00, 0x00, 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x6A j   */ {0x00, 0x00, 0x06, 0x00, 0x0E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00},
    /* 0x6B k   */ {0x00, 0x00, 0x60, 0x60, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x6C l   */ {0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x6D m   */ {0x00, 0x00, 0x00, 0x00, 0x66, 0x7F, 0x6B, 0x6B, 0x6B, 0x6B, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x6E n   */ {0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x6F o   */ {0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x70 p   */ {0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x71 q   */ {0x00, 0x00, 0x00, 0x00, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x72 r   */ {0x00, 0x00, 0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x73 s   */ {0x00, 0x00, 0x00, 0x00, 0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x74 t   */ {0x00, 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x75 u   */ {0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x76 v   */ {0x00, 0x00, 0x00, 0x00, 0x63, 0x63, 0x36, 0x36, 0x1C, 0x1C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x77 w   */ {0x00, 0x00, 0x00, 0x00, 0x63, 0x63, 0x6B, 0x6B, 0x7F, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x78 x   */ {0x00, 0x00, 0x00, 0x00, 0x63, 0x36, 0x1C, 0x1C, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x79 y   */ {0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7A z   */ {0x00, 0x00, 0x00, 0x00, 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7B {   */ {0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7C |   */ {0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7D }   */ {0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7E ~   */ {0x00, 0x00, 0x3B, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 0x7F DEL */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

/* ---- framebuffer helpers ---------------------------------------------- */
#define FONT_W 8
#define FONT_H 16
#define CON_COLS (FB_WIDTH / FONT_W)  /* 100 */
#define CON_ROWS (FB_HEIGHT / FONT_H) /* 37  */

static volatile uint32_t *fb = (volatile uint32_t *)GUI_LFB_UVA;

/* Per-pixel write — bounds-checked */
static inline void fb_pix(uint32_t x, uint32_t y, uint32_t rgb)
{
    if (x < FB_WIDTH && y < FB_HEIGHT)
        fb[y * FB_WIDTH + x] = 0xFF000000u | rgb;
}

/* Rectangle fill: clip once via rect_clip_fill, then unchecked inner.
 * Dispatch/FILL paths already validate, but boot/header callers pass
 * raw pixels — clipping here keeps one safe entry point. Inner writes
 * skip per-pixel bounds tests (clip guarantees x+w<=800, y+h<=600).
 * Ref: Bochs VGA 800x600x32 linear LFB. */
static inline void fb_fill(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb)
{
    uint32_t cx, cy, cw, ch, r, c;
    uint32_t v = 0xFF000000u | rgb;
    if (!rect_clip_fill(x, y, w, h, &cx, &cy, &cw, &ch))
        return;
    for (r = 0; r < ch; r++) /* bound: 600 */
        for (c = 0; c < cw; c++) /* bound: 800 */
            fb[(cy + r) * FB_WIDTH + (cx + c)] = v;
}

/* Console default background (COLOR_BLUE -> 0x0000AA). Must match
 * console.c COLOR_BLUE/vga_palette[4]=0xFF0000AA: CLEAR and the
 * scrolled-in bottom line clear to bg, not black, or "clear resets
 * background" (Linux fbcon clears with current bg; BusyBox clear keeps
 * attributes). fb_pix ORs 0xFF000000, so raw 0x0000AA. */
#define GUI_BG_BLUE 0x0000AAu

/* Scroll N text lines up in one pass (shift by N*16 rows).
 * Uses scroll_region_n so N lines cost one 480k-word pass, not N passes.
 * Overlapping copy runs top-down (dest < src): forward copy is safe.
 * Bottom N lines clear to console bg (BLUE). Ref: VGA text pane. */
static void fb_scroll_n(uint32_t n)
{
    uint32_t move_rows, clear_y, clear_h, i;
    uint32_t v = 0xFF000000u | GUI_BG_BLUE;
    if (n == 0u)
        return;
    if (n > (uint32_t)CON_ROWS)
        n = (uint32_t)CON_ROWS;
    if (!scroll_region_n(n, FONT_H, FB_HEIGHT, &move_rows, &clear_y, &clear_h))
        return;
    for (i = 0; i < move_rows * FB_WIDTH; i++) /* bound: 480000 */
        fb[i] = fb[i + (FB_HEIGHT - move_rows) * FB_WIDTH];
    for (i = 0; i < clear_h * FB_WIDTH; i++) /* bound: 480000 */
        fb[(clear_y * FB_WIDTH) + i] = v;
}

/* Scroll one text line up (boot-path wrapper over fb_scroll_n). */
static void fb_scroll(void)
{
    fb_scroll_n(1u);
}

/* Draw one glyph, unchecked fast path (cell pre-validated).
 * Precondition: glyph_cell_ok(col,row,CON_COLS,CON_ROWS). Then
 * x0+8<=800, y0+16<=600, so inner writes skip per-pixel bounds tests.
 * Ref: IBM VGA 8x16 ROM font, bit7 = leftmost. */
static inline void fb_glyph_fast(char c, uint32_t col, uint32_t row, uint32_t fg, uint32_t bg)
{
    unsigned idx = (unsigned)(unsigned char)c;
    const uint8_t *glyph;
    uint32_t x0 = col * (uint32_t)FONT_W;
    uint32_t y0 = row * (uint32_t)FONT_H;
    uint32_t gy, gx;
    if (idx >= 128u)
        idx = 0u;
    glyph = gui_font8x16[idx];
    for (gy = 0; gy < (uint32_t)FONT_H; gy++) /* bound: 16 */
    {
        uint8_t bits = glyph[gy];
        volatile uint32_t *dst = &fb[(y0 + gy) * FB_WIDTH + x0];
        for (gx = 0; gx < (uint32_t)FONT_W; gx++) /* bound: 8 */
            dst[gx] = (0xFF000000u | ((((bits & (0x80u >> gx)) != 0u) ? (fg & 0x00FFFFFFu) : (bg & 0x00FFFFFFu))));
    }
}

/* Draw one glyph at character cell (col, row), checked entry. */
static void fb_glyph(char c, uint32_t col, uint32_t row, uint32_t fg, uint32_t bg)
{
    if (!glyph_cell_ok(col, row, (uint32_t)CON_COLS, (uint32_t)CON_ROWS))
        return;
    fb_glyph_fast(c, col, row, fg, bg);
}

/* ---- simple framebuffer console state ---------------------------------- */
static uint32_t con_col = 0;
static uint32_t con_row = 0;

static void fb_putc(char c)
{
    if (c == '\n')
    {
        con_col = 0;
        con_row++;
    }
    else if (c == '\r')
    {
        con_col = 0;
    }
    else if (c == '\b')
    {
        if (con_col > 0)
        {
            con_col--;
            fb_glyph(' ', con_col, con_row, 0xFFFFFF, 0x000000);
        }
    }
    else
    {
        fb_glyph(c, con_col, con_row, 0xFFFFFF, 0x000000);
        con_col++;
        if (con_col >= CON_COLS)
        {
            con_col = 0;
            con_row++;
        }
    }
    if (con_row >= CON_ROWS)
    {
        fb_scroll();
        con_row = CON_ROWS - 1;
    }
}

static void fb_puts(const char *s)
{
    while (*s)
        fb_putc(*s++);
}

static void fb_cursor(void)
{
    /* Simple underline cursor at current position */
    uint32_t x0 = con_col * FONT_W;
    uint32_t y0 = con_row * FONT_H + FONT_H - 2;
    for (uint32_t x = x0; x < x0 + FONT_W && x < FB_WIDTH; x++)
    {
        fb_pix(x, y0, 0xFFFFFF);
        fb_pix(x, y0 + 1, 0xFFFFFF);
    }
}

/* Positioned cursor for console CURSOR RPCs (cell coords).
 * Tracks last position to erase the old underline first: without this
 * every newline leaves a permanent white ghost (old cursor never
 * repainted), which reads as "rendering breaks". Erase fills the old
 * 2px underline with console bg (BLUE). */
static uint32_t last_cur_x = 0xFFFFFFFFu;
static uint32_t last_cur_y = 0xFFFFFFFFu;
static void fb_cursor_erase(void)
{
    uint32_t x0, y0, x;
    if (last_cur_x == 0xFFFFFFFFu)
        return;
    if (last_cur_x >= (uint32_t)CON_COLS || last_cur_y >= (uint32_t)CON_ROWS)
        return;
    x0 = last_cur_x * FONT_W;
    y0 = last_cur_y * FONT_H + FONT_H - 2;
    for (x = x0; x < x0 + FONT_W && x < FB_WIDTH; x++)
    {
        fb_pix(x, y0, GUI_BG_BLUE);
        fb_pix(x, y0 + 1, GUI_BG_BLUE);
    }
    last_cur_x = 0xFFFFFFFFu;
}
static void fb_cursor_at(uint32_t col, uint32_t row)
{
    uint32_t x0, y0, x;
    if (col >= (uint32_t)CON_COLS || row >= (uint32_t)CON_ROWS)
        return;
    fb_cursor_erase();
    x0 = col * FONT_W;
    y0 = row * FONT_H + FONT_H - 2;
    for (x = x0; x < x0 + FONT_W && x < FB_WIDTH; x++)
    {
        fb_pix(x, y0, 0xFFFFFF);
        fb_pix(x, y0 + 1, 0xFFFFFF);
    }
    last_cur_x = col;
    last_cur_y = row;
}

/* Blocking 4-word RECV on our own endpoint (GUI_TID). Call only when
 * the level-triggered queued bit (0x10) is set: this thread is the
 * sole consumer, so exactly one blocking RECV is race-free. */
static long gui_render_recv(uint64_t *w)
{
    register long r_a0 asm("a0") = (long)GUI_TID;
    register long r_a1 asm("a1") = (long)w;
    register long r_a2 asm("a2") = 4L;
    register long r_a7 asm("a7") = 4L; /* V2_RECV */
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1) : "r"(r_a2), "r"(r_a7) : "memory");
    return r_a0;
}

static uint32_t gui_rw(const uint64_t *m, unsigned o)
{
    const uint8_t *b = (const uint8_t *)m;
    return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) | ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}

/* VGA 16-color palette for PUTS indices. Authority: console.h
 * vga_palette — keep in sync (mismatch paints wrong colors, not garble).
 * PUTC carries raw RGB and never touches this table. */
static const uint32_t gui_palette[16] = {
    0xFF000000, /* 0: Black */
    0xFFAA0000, /* 1: Red */
    0xFF00AA00, /* 2: Green */
    0xFFAAAA00, /* 3: Yellow */
    0xFF0000AA, /* 4: Blue */
    0xFFAA00AA, /* 5: Magenta */
    0xFF00AAAA, /* 6: Cyan */
    0xFFAAAAAA, /* 7: White */
    0xFF555555, /* 8: Bright Black (Gray) */
    0xFFFF5555, /* 9: Bright Red */
    0xFF55FF55, /* 10: Bright Green */
    0xFFFFFF55, /* 11: Bright Yellow */
    0xFF5555FF, /* 12: Bright Blue */
    0xFFFF55FF, /* 13: Bright Magenta */
    0xFF55FFFF, /* 14: Bright Cyan */
    0xFFFFFFFF, /* 15: Bright White */
};

/* Paint one console render RPC (MSG_CONSOLE_* tags, cell coords for
 * PUTC/CURSOR, pixels + raw RGB for FILL). Unknown tags drop. */
static void gui_render_dispatch(const uint64_t *m)
{
    uint32_t tag = gui_rw(m, 0);
    if (tag == 0x2000u) /* MSG_CONSOLE_PUTC */
    {
        uint32_t x = gui_rw(m, 8), y = gui_rw(m, 12);
        if (glyph_cell_ok(x, y, (uint32_t)CON_COLS, (uint32_t)CON_ROWS))
            fb_glyph_fast((char)(gui_rw(m, 16) & 0xFFu), x, y, gui_rw(m, 20), gui_rw(m, 24));
    }
    else if (tag == 0x2001u) /* MSG_CONSOLE_FILL */
    {
        uint32_t fx = gui_rw(m, 8), fy = gui_rw(m, 12);
        uint32_t fw = gui_rw(m, 16), fh = gui_rw(m, 20);
        fb_fill(fx, fy, fw, fh, gui_rw(m, 24));
        /* Full-screen FILL wipes the cursor pixels: drop tracking so the
         * next CURSOR does not erase (BLUE-fill) over fresh text. */
        if (fx == 0 && fy == 0 && fw == FB_WIDTH && fh == FB_HEIGHT)
            last_cur_x = 0xFFFFFFFFu;
    }
    else if (tag == 0x2002u) /* MSG_CONSOLE_SCROLL: full-screen lines */
    {
        uint32_t n = gui_rw(m, 8);
        uint32_t scrolled;
        if (n > (uint32_t)CON_ROWS)
            n = (uint32_t)CON_ROWS;
        scrolled = n;
        if (scrolled > 0u)
            fb_scroll_n(scrolled);
        /* Pixels (including the old cursor underline) moved up: follow
         * the tracking so the next erase hits the scrolled position,
         * not stale text. Scrolled-off cursors invalidate. */
        if (last_cur_x != 0xFFFFFFFFu)
        {
            if (last_cur_y < scrolled)
                last_cur_x = 0xFFFFFFFFu;
            else
                last_cur_y -= scrolled;
        }
    }
    else if (tag == 0x2003u) /* MSG_CONSOLE_CURSOR */
    {
        if (gui_rw(m, 16))
            fb_cursor_at(gui_rw(m, 8), gui_rw(m, 12));
        else
        {
            /* Hidden cursor: erase old underline, drop tracking. */
            fb_cursor_erase();
        }
    }
    else if (tag == 0x2005u) /* MSG_CONSOLE_PUTS: row run, xy=(x<<16)|y */
    {
        uint32_t xy = gui_rw(m, 8), lenpal = gui_rw(m, 12);
        uint32_t x = (xy >> 16) & 0xFFFFu, y = xy & 0xFFFFu;
        uint32_t len = lenpal & 0xFFu, pal = (lenpal >> 8) & 0xFFFFu;
        uint32_t fg = gui_palette[pal & 0xFu];
        uint32_t bg = gui_palette[(pal >> 4) & 0xFu];
        const uint8_t *b = (const uint8_t *)m + 16;
        uint32_t i;
        if (len > 16)
            len = 16;
        if (y >= (uint32_t)CON_ROWS)
            return;
        for (i = 0; i < len; i++)
        {
            if (x + i >= (uint32_t)CON_COLS)
                break;
            fb_glyph((char)b[i], x + i, y, fg, bg);
        }
        /* The run end is the cursor: drawing it here saves one CURSOR
         * RPC per chunk on the hot path (explicit CURSOR still covers
         * jumps, switches, and repaints). */
        fb_cursor_at(x + len, y);
    }
    else if (tag == 0x2004u) /* MSG_CONSOLE_CLEAR: keep console bg (BLUE) */
    {
        fb_fill(0, 0, FB_WIDTH, FB_HEIGHT, GUI_BG_BLUE);
        last_cur_x = 0xFFFFFFFFu;
    }
}

/* ---- header bar -------------------------------------------------------- */
static void fb_draw_header(void)
{
    /* Cyan bar across the top 16 px */
    fb_fill(0, 0, FB_WIDTH, FONT_H, 0x006080);
    /* "MoonlightOS" title in the header */
    const char *title = "  MoonlightOS v2  |  RISC-V S-mode microkernel";
    uint32_t cx = 0;
    for (const char *p = title; *p && cx < CON_COLS; p++, cx++)
        fb_glyph(*p, cx, 0, 0xFFFFFF, 0x006080);
    /* Separator line */
    fb_fill(0, FONT_H, FB_WIDTH, 1, 0x00A0C0);
    /* Skip header row for console output */
    con_row = 1;
    con_col = 0;
}

/* ---- PCI Bochs display bind ------------------------------------------- *
 * Correct ECAM scan: each PCI function occupies 256 bytes, each device    *
 * 8 functions = 2048 bytes.  The 32-bit ID register is at offset 0.       *
 * Bochs VGA: vendor = 0x1234, device = 0x1111.                            *
 * BAR0 (LFB) is already programmed by the kernel; we just verify.         */
static int gui_bind_display(void)
{
    volatile uint32_t *ecam = (volatile uint32_t *)GUI_ECAM_UVA;
    for (uint32_t dev = 0; dev < 32; dev++)
    {
        for (uint32_t fn = 0; fn < 8; fn++)
        {
            /* Byte offset into ECAM, then divide by 4 for dword index */
            uint32_t dword_off = (dev * 2048u + fn * 256u) / 4u;
            uint32_t id = ecam[dword_off]; /* vendor | (device << 16) */
            if (id == 0xFFFFFFFFu)
                continue;
            /* vendor=0x1234 at bits[15:0], device=0x1111 at bits[31:16] */
            if ((id & 0xFFFFu) != 0x1234u)
                continue;
            if ((id >> 16) != 0x1111u)
                continue;
            u_puts("GUI: Bochs VGA found (dev=");
            u_putc('0' + (char)dev);
            u_puts(")\n");
            return 1;
        }
    }
    /* No Bochs device — framebuffer is still mapped by the kernel at
     * GUI_LFB_UVA.  The kernel already programmed the BAR.  We return
     * success so the console still works (the buffer was cleared to black
     * by the kernel's fbcon_clear()).  Writes to GUI_LFB_UVA are safe. */
    u_puts("GUI: Bochs VGA not found via ECAM, using pre-mapped LFB\n");
    return 1; /* non-fatal: LFB leaf is pre-wired by kernel */
}

/* ---- VirtIO input ------------------------------------------------------ */
static virtio_input_ring_t kbd_ring __attribute__((aligned(4096)));
static virtio_input_ring_t mouse_ring __attribute__((aligned(4096)));
static kbd_modifiers_t kbd_mods;
static mouse_state_t mouse;

/* Scan VirtIO transports for input devices (device ID 18).
 * Returns (mouse in *m, kbd in *k); either may be NULL if not found.     */
static void gui_find_input(volatile uint32_t **m, volatile uint32_t **k)
{
    int found = 0;
    *m = (volatile uint32_t *)0;
    *k = (volatile uint32_t *)0;
    for (int ti = 0; ti < 8 && found < 2; ti++)
    {
        volatile uint32_t *tr = (volatile uint32_t *)(KBD_MMIO_UVA + (unsigned long)ti * 0x1000UL);
        if (tr[0] != 0x74726976u || tr[1] != 2u || tr[2] != 18u)
            continue;
        if (found == 0)
        {
            *m = tr;
            found++;
        }
        else
        {
            *k = tr;
            found++;
        }
    }
}

/* ---- keyboard event handler ------------------------------------------- */
static void gui_handle_key(uint16_t code, uint32_t value)
{
    int pressed = (value != 0); /* 2 is the Linux input repeat value */
    update_modifiers(&kbd_mods, code, pressed);

    /* Build modifier flags for IPC message */
    uint32_t mod_flags = 0;
    if (kbd_mods.shift)
        mod_flags |= KEY_MOD_SHIFT;
    if (kbd_mods.ctrl)
        mod_flags |= KEY_MOD_CTRL;
    if (kbd_mods.alt)
        mod_flags |= KEY_MOD_ALT;

    /* Get ASCII character (0 if non-printable) */
    char ch = keycode_to_ascii(code, &kbd_mods);

    /* Forward key event to Console service via IPC */
    gui_send_key_event(code, (uint32_t)(uint8_t)ch, mod_flags, pressed ? 1 : 0);

    /* No local echo: the TTY layer echoes through the console render
     * path at the authoritative cursor. A local echo here races it at
     * a stale cursor (text appears lines above, overwriting output). */
}

/* ---- main entry point -------------------------------------------------- */
void gui_main(void)
{
    u_puts("GUI: thread 10 starting\n");

    /* 1. Bind the Bochs display (fail-soft) */
    gui_bind_display();

    /* 2. Clear framebuffer and draw header */
    fb_fill(0, 0, FB_WIDTH, FB_HEIGHT, 0x000000);
    fb_draw_header();
    fb_puts("MoonlightOS booted.  Type below:\n");
    fb_cursor();

    u_puts("GUI: framebuffer initialised\n");

    /* 3. Discover VirtIO input devices */
    volatile uint32_t *kbd_mmio_ptr;
    volatile uint32_t *mouse_mmio_ptr;
    gui_find_input(&mouse_mmio_ptr, &kbd_mmio_ptr);

    int kbd_ok = 0;
    int mouse_ok = 0;

    if (kbd_mmio_ptr)
    {
        kbd_ok = virtio_input_init(kbd_mmio_ptr, &kbd_ring, 16);
        if (kbd_ok)
            u_puts("GUI: keyboard ready\n");
        else
            u_puts("GUI: keyboard init failed\n");
    }
    else
    {
        u_puts("GUI: no keyboard transport found\n");
    }

    if (mouse_mmio_ptr)
    {
        mouse_ok = virtio_input_init(mouse_mmio_ptr, &mouse_ring, 16);
        if (mouse_ok)
            u_puts("GUI: mouse ready\n");
        else
            u_puts("GUI: mouse init failed\n");
    }
    else
    {
        u_puts("GUI: no mouse transport found\n");
    }

    kbd_modifiers_init(&kbd_mods);
    mouse_init(&mouse);

    fb_puts("Keyboard: ");
    fb_puts(kbd_ok ? "OK" : "N/A");
    fb_puts("  Mouse: ");
    fb_puts(mouse_ok ? "OK" : "N/A");
    fb_puts("\n");
    fb_cursor();

    /* 4. Event loop: WAIT for IRQ notify bits, poll rings */
    for (;;)
    {
        long notify = u_wait();

        if (notify & KBD_IRQ_BIT && kbd_ok)
        {
            __asm__ volatile("fence iorw,iorw" ::: "memory");
            int recycled = 0;
            int queue_error = 0;
            for (;;)
            {
                uint16_t desc_id;
                int state = virtio_input_next(&kbd_ring, 16, &desc_id);
                if (state == 0)
                    break;
                if (state < 0)
                {
                    queue_error = 1;
                    break;
                }
                volatile struct virtio_input_event *ev = &kbd_ring.events[desc_id];
                if (ev->type == EV_KEY)
                    gui_handle_key(ev->code, ev->value);
                if (!virtio_input_recycle(&kbd_ring, 16, desc_id))
                {
                    queue_error = 1;
                    break;
                }
                recycled++;
            }
            __asm__ volatile("fence iorw,iorw" ::: "memory");
            if (queue_error)
            {
                kbd_mmio_ptr[VIRTIO_MMIO_STATUS / 4] |= VIRTIO_STATUS_FAILED;
                kbd_ok = 0;
            }
            else if (recycled)
            {
                virtio_input_notify(kbd_mmio_ptr);
            }
            else
            {
                virtio_input_ack(kbd_mmio_ptr);
            }
        }

        if (notify & MOUSE_IRQ_BIT && mouse_ok)
        {
            __asm__ volatile("fence iorw,iorw" ::: "memory");
            int recycled = 0;
            int queue_error = 0;
            for (;;)
            {
                uint16_t desc_id;
                int state = virtio_input_next(&mouse_ring, 16, &desc_id);
                if (state == 0)
                    break;
                if (state < 0)
                {
                    queue_error = 1;
                    break;
                }
                volatile struct virtio_input_event *ev = &mouse_ring.events[desc_id];
                if (ev->type == EV_REL)
                {
                    if (ev->code == REL_X)
                        mouse_move(&mouse, (int32_t)ev->value, 0);
                    if (ev->code == REL_Y)
                        mouse_move(&mouse, 0, (int32_t)ev->value);
                }
                else if (ev->type == EV_KEY)
                {
                    mouse_button(&mouse, ev->code, ev->value != 0);
                }
                if (!virtio_input_recycle(&mouse_ring, 16, desc_id))
                {
                    queue_error = 1;
                    break;
                }
                recycled++;
            }
            __asm__ volatile("fence iorw,iorw" ::: "memory");
            if (queue_error)
            {
                mouse_mmio_ptr[VIRTIO_MMIO_STATUS / 4] |= VIRTIO_STATUS_FAILED;
                mouse_ok = 0;
            }
            else if (recycled)
            {
                virtio_input_notify(mouse_mmio_ptr);
            }
            else
            {
                virtio_input_ack(mouse_mmio_ptr);
            }
        }
        /* Render drain: console posts FILL/PUTC/PUTS/CURSOR/SCROLL here and
         * never RECVs, so consume while queued (WAIT returns instantly
         * while our endpoint has backlog: 0x10 = queued). Only this
         * thread RECVs ep 10, so draining here is race-free; unknown
         * tags drop silently. */
        if ((unsigned long)notify & 0x10UL)
        {
            uint64_t m[4] = {0, 0, 0, 0};
            if (gui_render_recv(m) == 4)
                gui_render_dispatch(m);
        }
    }
}
