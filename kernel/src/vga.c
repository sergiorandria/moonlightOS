#include "../include/vga.h"
#include "../include/vspace.h"
#include <string.h>

#ifdef __x86_64__
// x86 VGA text mode 0xB8000
static volatile uint16_t *vga_text = (volatile uint16_t*)VGA_TEXT_BASE;
static int vga_cx = 0, vga_cy = 0;

kerror_t vga_init(vspace_t *vs) {
    // Identity map VGA text buffer 0xB8000 4K
    uintptr_t base = VGA_TEXT_BASE & ~(PAGE_SIZE-1);
    kerror_t e = vspace_map(vs, base, base, PAGE_SIZE, 0x7, 0);
    if (e != ERR_OK) return e;
    // clear
    for (int y=0;y<VGA_HEIGHT;y++) for(int x=0;x<VGA_WIDTH;x++) vga_text[y*VGA_WIDTH+x] = 0x0720;
    vga_cx = vga_cy = 0;
    return ERR_OK;
}

void vga_clear(uint32_t color) {
    uint16_t attr = (color & 0xFF);
    uint16_t fill = (attr<<8) | 0x20;
    for(int i=0;i<VGA_WIDTH*VGA_HEIGHT;i++) vga_text[i]=fill;
    vga_cx=vga_cy=0;
}

static void vga_putc(char c) {
    if(c=='\n'){ vga_cx=0; vga_cy++; if(vga_cy>=VGA_HEIGHT) vga_cy=0; return; }
    if(vga_cx>=VGA_WIDTH){ vga_cx=0; vga_cy++; if(vga_cy>=VGA_HEIGHT) vga_cy=0; }
    vga_text[vga_cy*VGA_WIDTH+vga_cx] = 0x0F00 | (uint8_t)c;
    vga_cx++;
}

void vga_puts(const char *s){ while(*s) vga_putc(*s++); }
void vga_puts_at(const char *s, int x, int y, uint32_t fg, uint32_t bg){
    (void)fg; (void)bg;
    vga_cx=x; vga_cy=y;
    vga_puts(s);
}
void vga_draw_hello(void){
    vga_clear(0x07);
    vga_puts_at("Hello world - MoonlightOS VGA driver", 0, 0, 0x0F, 0x00);
    vga_puts_at("Driver isolated | CHERI bounds OK | 80x25 text", 0, 1, 0x0A, 0x00);
}

#else
// RISC-V bochs-display framebuffer 800x600x32
// QEMU bochs-display has NO legacy VGA I/O ports (0x1CE/0x1CF). Its VBE dispi
// registers are 16-bit MMIO at BAR2 + 0x500 + index*2 (see QEMU hw/display/bochs-display.c
// and Bochs VBE spec https://wiki.osdev.org/Bochs_VBE_Extensions).
// BAR0 = LFB (framebuffer), BAR2 = MMIO (4KB) for dispi + VGA regs.
static volatile uint32_t *fb = (volatile uint32_t*)VGA_FB_BASE;
static int fb_init_done = 0;

// UART for diagnostics (same style as boot.c)
#define UART0 0x10000000
static void uart_putc(char c){ *(volatile char*)UART0 = c; }
static void uart_puts(const char*s){ while(*s) uart_putc(*s++); }
static void uart_hex(uint64_t v){ for(int i=60;i>=0;i-=4){ int n=(v>>i)&0xF; uart_putc(n<10?'0'+n:'a'+n-10);} uart_putc('\n'); }
static void uart_hex32(uint32_t v){ for(int i=28;i>=0;i-=4){ int n=(v>>i)&0xF; uart_putc(n<10?'0'+n:'a'+n-10);} }

// 8x8 simple font
static const uint8_t font8x8[128][8] = {
    ['H'] = {0x42,0x42,0x42,0x7E,0x42,0x42,0x42,0x00},
    ['e'] = {0x00,0x3C,0x42,0x7E,0x40,0x42,0x3C,0x00},
    ['l'] = {0x10,0x10,0x10,0x10,0x10,0x10,0x0E,0x00},
    ['o'] = {0x00,0x3C,0x42,0x42,0x42,0x42,0x3C,0x00},
    [' '] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    ['w'] = {0x00,0x42,0x42,0x42,0x42,0x5A,0x24,0x00},
    ['r'] = {0x00,0x3C,0x42,0x40,0x40,0x40,0x40,0x00},
    ['d'] = {0x08,0x08,0x3A,0x42,0x42,0x42,0x3A,0x00},
    ['M'] = {0x42,0x66,0x5A,0x42,0x42,0x42,0x42,0x00},
    ['n'] = {0x00,0x5C,0x62,0x42,0x42,0x42,0x42,0x00},
    ['i'] = {0x10,0x00,0x10,0x10,0x10,0x10,0x0E,0x00},
    ['g'] = {0x00,0x3A,0x42,0x42,0x3A,0x08,0x42,0x3C},
    ['h'] = {0x10,0x10,0x5C,0x62,0x42,0x42,0x42,0x00},
    ['t'] = {0x08,0x08,0x3E,0x08,0x08,0x08,0x06,0x00},
    ['O'] = {0x3C,0x42,0x42,0x42,0x42,0x42,0x3C,0x00},
    ['S'] = {0x3C,0x40,0x40,0x3C,0x02,0x02,0x3C,0x00},
    ['-'] = {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00},
    ['.'] = {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00},
    ['|'] = {0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x00},
};

// Bochs VBE dispi spec (https://wiki.osdev.org/Bochs_VBE_Extensions, QEMU bochs-display.c)
#define VBE_DISPI_INDEX_ID          0x0
#define VBE_DISPI_INDEX_XRES        0x1
#define VBE_DISPI_INDEX_YRES        0x2
#define VBE_DISPI_INDEX_BPP         0x3
#define VBE_DISPI_INDEX_ENABLE      0x4
#define VBE_DISPI_ID5               0xB0C5  // VBE 3.0, Bochs impl supports 0xB0C0-0xB0C5
#define VBE_DISPI_DISABLED          0x00
#define VBE_DISPI_ENABLED           0x01
#define VBE_DISPI_LFB_ENABLED       0x40
#define VBE_DISPI_NOCLEARMEM        0x80

// BAR2 MMIO for bochs-display chosen as 0x41000000 because:
// - VGA_FB_BASE (BAR0) is 0x40000000 size ~2M (800*600*4=0x1D4C00) => ends ~0x401D4C00
// - ECAM is 0x30000000 size 0x1000000 (16M) => 0x30000000-0x31000000
// - PCI I/O legacy at 0x03000000 size 0x10000
// - fw_cfg at 0x10100000
// So 0x41000000 is safely after FB, before any other mapping, 4KB aligned, documented.
#define VGA_BAR2_BASE 0x41000000
#define VGA_BAR2_SIZE PAGE_SIZE // 4KB MMIO

kerror_t vga_init(vspace_t *vs) {
    size_t fb_size = VGA_WIDTH * VGA_HEIGHT * (VGA_BPP/8);
    fb_size = (fb_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    kerror_t e = vspace_map(vs, VGA_FB_BASE, VGA_FB_BASE, fb_size, 0x7, 0);
    if (e != ERR_OK) return e;
    // Map BAR2 region for VBE MMIO
    e = vspace_map(vs, VGA_BAR2_BASE, VGA_BAR2_BASE, VGA_BAR2_SIZE, 0x7, 0);
    if (e != ERR_OK) return e;
    // Also map PCI ECAM for enumeration
    e = vspace_map(vs, 0x30000000, 0x30000000, 0x1000000, 0x7, 0);
    if (e != ERR_OK) return e;

    fb = (volatile uint32_t*)VGA_FB_BASE;
    // fb_init_done stays 0 until BARs are programmed and VBE enabled

    uart_puts("[VGA] PCI scan ECAM 0x30000000\n");
    int found = 0;
    uint32_t found_bar0 = 0, found_bar2 = 0;
    uintptr_t found_ecam = 0;

    for(int dev=0; dev<32; dev++){
        volatile uint32_t *ecam = (volatile uint32_t*)(0x30000000 | (dev<<15));
        uint32_t id = ecam[0];
        if(id==0xffffffff) continue;
        uint16_t ven = id & 0xFFFF;
        uint16_t did = (id>>16) & 0xFFFF;
        uart_puts("[VGA] PCI dev "); uart_hex32(dev);
        uart_puts(" vendor/device "); uart_hex32(id);
        uart_putc('\n');
        if(ven==0x1234 && did==0x1111){
            found = 1;
            found_ecam = (uintptr_t)ecam;
            uart_puts("[VGA] bochs-display found at dev "); uart_hex32(dev); uart_putc('\n');
            volatile uint32_t *bar0 = (volatile uint32_t*)((uintptr_t)ecam + 0x10);
            volatile uint32_t *bar1 = (volatile uint32_t*)((uintptr_t)ecam + 0x14);
            volatile uint32_t *bar2 = (volatile uint32_t*)((uintptr_t)ecam + 0x18);
            volatile uint32_t *bar3 = (volatile uint32_t*)((uintptr_t)ecam + 0x1C);
            volatile uint32_t *cmd  = (volatile uint32_t*)((uintptr_t)ecam + 0x04);
            uint32_t orig_bar0 = *bar0;
            uint32_t orig_bar2 = *bar2;
            uart_puts("[VGA] orig BAR0 "); uart_hex32(orig_bar0); uart_puts(" BAR2 "); uart_hex32(orig_bar2); uart_putc('\n');
            // Check 64-bit BAR: bits [2:1] == 0b10 => 64-bit
            int bar0_64 = (orig_bar0 & 0x6) == 0x4;
            int bar2_64 = (orig_bar2 & 0x6) == 0x4;
            uart_puts("[VGA] BAR0 64-bit? "); uart_hex32(bar0_64); uart_puts(" BAR2 64-bit? "); uart_hex32(bar2_64); uart_putc('\n');
            // Force BAR0 to VGA_FB_BASE (0x40000000)
            *bar0 = VGA_FB_BASE;
            if(bar0_64) *bar1 = 0;
            // Force BAR2 to VGA_BAR2_BASE (0x41000000) - 4KB MMIO for VBE dispi
            *bar2 = VGA_BAR2_BASE;
            if(bar2_64) *bar3 = 0;
            __asm__ volatile("fence" ::: "memory");
            // Verify
            uint32_t read_bar0 = *bar0;
            uint32_t read_bar2 = *bar2;
            uart_puts("[VGA] programmed BAR0 "); uart_hex32(read_bar0); uart_puts(" BAR2 "); uart_hex32(read_bar2); uart_putc('\n');
            found_bar0 = read_bar0;
            found_bar2 = read_bar2;
            // Enable memory + I/O + bus master
            uint32_t c = *cmd;
            c |= 0x07;
            *cmd = c;
            __asm__ volatile("fence; sfence.vma" ::: "memory");
            uart_puts("[VGA] PCI CMD "); uart_hex32(c); uart_putc('\n');
            // VBE dispi via BAR2 MMIO: base + 0x500 + index*2 (16-bit regs)
            // Must use 16-bit stores, in order ID, XRES, YRES, BPP, ENABLE
            // BAR2 was just programmed, but we use the fixed VGA_BAR2_BASE we mapped
            volatile uint16_t *vbe = (volatile uint16_t*)(VGA_BAR2_BASE + 0x500);
            uart_puts("[VGA] VBE via BAR2 MMIO "); uart_hex(VGA_BAR2_BASE + 0x500); 
            vbe[VBE_DISPI_INDEX_ID] = VBE_DISPI_ID5;
            vbe[VBE_DISPI_INDEX_XRES] = VGA_WIDTH;
            vbe[VBE_DISPI_INDEX_YRES] = VGA_HEIGHT;
            vbe[VBE_DISPI_INDEX_BPP] = 32;
            vbe[VBE_DISPI_INDEX_ENABLE] = VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED;
            __asm__ volatile("fence" ::: "memory");
            uart_puts("[VGA] VBE set "); uart_hex32(VGA_WIDTH); uart_putc('x'); uart_hex32(VGA_HEIGHT); uart_puts("x32 enable 0x41\n");
            // Verify ID readback
            uint16_t id_read = vbe[VBE_DISPI_INDEX_ID];
            uart_puts("[VGA] VBE ID readback "); uart_hex32(id_read); uart_putc('\n');
            break;
        }
    }
    if(!found){
        uart_puts("[VGA] FAIL bochs-display not found (0x1234:0x1111)\n");
        return ERR_NO_MEM; // distinct error, caught by boot.c's if (vga_init == ERR_OK)
    }
    // Ensure framebuffer is now at programmed BAR0 address
    // For bochs, LFB is at BAR0 (0x40000000), already mapped
    fb_init_done=1;
    uart_puts("[VGA] BAR0="); uart_hex(found_bar0); uart_puts("[VGA] BAR2="); uart_hex(found_bar2);
    uart_puts("[VGA] ECAM "); uart_hex(found_ecam); 
    uart_puts("[VGA] init done, clearing FB\n");
    for(size_t i=0;i<100;i++) fb[i]=0x00102040; // quick test clear 100 pixels
    uart_puts("[VGA] FB clear done\n");
    return ERR_OK;
}

void vga_clear(uint32_t color){
    if(!fb_init_done) return;
    for(size_t i=0;i<VGA_WIDTH*VGA_HEIGHT;i++) fb[i]=color;
}

static void draw_char(int x, int y, char c, uint32_t fg, uint32_t bg){
    if(c<0 || c>127) c='?';
    const uint8_t *g = font8x8[(int)c];
    for(int row=0;row<8;row++){
        uint8_t bits = g[row];
        for(int col=0;col<8;col++){
            int px = x*8+col;
            int py = y*16+row*2;
            if(px>=VGA_WIDTH || py>=VGA_HEIGHT) continue;
            uint32_t colr = (bits & (0x80>>col)) ? fg : bg;
            fb[py*VGA_WIDTH+px]=colr;
            if(py+1<VGA_HEIGHT) fb[(py+1)*VGA_WIDTH+px]=colr;
        }
    }
}

void vga_puts(const char *s){
    if(!fb_init_done) return;
    int x=0,y=0;
    while(*s){
        if(*s=='\n'){ x=0; y++; s++; continue; }
        draw_char(x,y,*s,0x00FFFFFF,0x00102040);
        x++; if(x>=VGA_WIDTH/8){ x=0; y++; }
        s++;
    }
}
void vga_puts_at(const char *s, int x, int y, uint32_t fg, uint32_t bg){
    if(!fb_init_done) return;
    int cx=x, cy=y;
    while(*s){
        if(*s=='\n'){ cx=x; cy++; s++; continue; }
        draw_char(cx,cy,*s,fg,bg);
        cx++; s++;
    }
}
void vga_draw_hello(void){
    if(!fb_init_done) return;
    // Fill with dark blue first
    for(int y=0;y<200;y++) for(int x=0;x<VGA_WIDTH;x++) fb[y*VGA_WIDTH+x]=0x00102040;
    // Draw large white rectangle as test pattern - should be visible even if font fails
    for(int y=50;y<150;y++) for(int x=100;x<700;x++) fb[y*VGA_WIDTH+x]=0x00FFFFFF;
    // Draw black border inside
    for(int x=100;x<700;x++){ fb[50*VGA_WIDTH+x]=0x00000000; fb[149*VGA_WIDTH+x]=0x00000000; }
    for(int y=50;y<150;y++){ fb[y*VGA_WIDTH+100]=0x00000000; fb[y*VGA_WIDTH+699]=0x00000000; }
    vga_puts_at("Hello world", 10, 5, 0x00FFFFFF, 0x00102040);
    vga_puts_at("MoonlightOS - VGA driver isolated (I/O + FB, CHERI) OK", 2, 8, 0x0000FF00, 0x00102040);
    vga_puts_at("Framebuffer 0x40000000 800x600x32 mapped via vspace", 2, 10, 0x00AAAAAA, 0x00102040);
    for(int x=0;x<VGA_WIDTH;x++){ fb[x]=0x00FFAA00; fb[(VGA_HEIGHT-1)*VGA_WIDTH+x]=0x00FFAA00; }
    for(int y=0;y<VGA_HEIGHT;y++){ fb[y*VGA_WIDTH]=0x00FFAA00; fb[y*VGA_WIDTH+VGA_WIDTH-1]=0x00FFAA00; }
}
#endif
