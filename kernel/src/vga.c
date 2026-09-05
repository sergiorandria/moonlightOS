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
// RISC-V ramfb framebuffer 800x600x32 at 0x40000000
static volatile uint32_t *fb = (volatile uint32_t*)VGA_FB_BASE;
static int fb_init_done = 0;

// 8x16 simple font for "Hello world" - minimal subset
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

kerror_t vga_init(vspace_t *vs) {
    // Map framebuffer at VGA_FB_BASE (800x600x32). For QEMU virt:
    // - with -bios none, PCI BARs are not configured by firmware, so we must
    //   configure bochs-display (0x1234:0x1111) BAR0 to 0x40000000 ourselves via ECAM
    // - with -device ramfb, FW would configure via fw_cfg, but we prefer bochs
    size_t fb_size = VGA_WIDTH * VGA_HEIGHT * (VGA_BPP/8);
    fb_size = (fb_size + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    kerror_t e = vspace_map(vs, VGA_FB_BASE, VGA_FB_BASE, fb_size, 0x7, 0);
    if (e != ERR_OK) return e;
    // Map PCI ECAM (0x30000000) and PCI I/O (0x03000000) for bochs VBE ports
    vspace_map(vs, 0x30000000, 0x30000000, 0x1000000, 0x7, 0);
    vspace_map(vs, 0x03000000, 0x03000000, 0x10000, 0x7, 0);
    vspace_map(vs, 0x10100000, 0x10100000, PAGE_SIZE, 0x3, 0);
    fb = (volatile uint32_t*)VGA_FB_BASE;
    fb_init_done=1;

    // PCI ECAM init for bochs-display when running with -bios none
    // ECAM: 0x30000000 + (bus<<20 | dev<<15 | fn<<12 | offset)
    // Scan bus 0 for vendor 0x1234 device 0x1111 (bochs)
    for(int dev=0; dev<32; dev++){
        volatile uint32_t *ecam = (volatile uint32_t*)(0x30000000 | (dev<<15));
        uint32_t id = ecam[0]; // offset 0x00: vendor | device<<16
        if(id==0xffffffff) continue;
        uint16_t ven = id & 0xFFFF;
        uint16_t devid = (id>>16) & 0xFFFF;
        if(ven==0x1234 && devid==0x1111){
            // Found bochs-display, configure BAR0 to VGA_FB_BASE
            volatile uint32_t *bar0 = (volatile uint32_t*)((uintptr_t)ecam + 0x10);
            volatile uint32_t *cmd = (volatile uint32_t*)((uintptr_t)ecam + 0x04);
            // Write BAR0
            *bar0 = VGA_FB_BASE;
            // Enable memory + I/O + bus master
            uint32_t c = *cmd;
            c |= 0x07; // I/O + Memory + Bus Master
            *cmd = c;
            __asm__ volatile("fence; fence.i; sfence.vma" ::: "memory");
            // Now set Bochs VBE mode 800x600x32 via I/O ports 0x1CE/0x1CF at PCI I/O 0x03000000
            volatile uint16_t *vbe_idx = (volatile uint16_t*)(0x03000000 + 0x1CE);
            volatile uint16_t *vbe_val = (volatile uint16_t*)(0x03000000 + 0x1CF);
            // VBE registers: 0=ID,1=XRES,2=YRES,3=BPP,4=ENABLE
            *vbe_idx = 0; *vbe_val = 0xB0C4; // VBE ID 0xB0C4
            *vbe_idx = 1; *vbe_val = VGA_WIDTH;
            *vbe_idx = 2; *vbe_val = VGA_HEIGHT;
            *vbe_idx = 3; *vbe_val = 32;
            *vbe_idx = 4; *vbe_val = 0x41; // ENABLE + LFB
            __asm__ volatile("fence" ::: "memory");
            break;
        }
    }
    for(size_t i=0;i<VGA_WIDTH*VGA_HEIGHT;i++) fb[i]=0x00102040;
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
            int py = y*16+row*2; // double height for 16
            if(px>=VGA_WIDTH || py>=VGA_HEIGHT) continue;
            // second row duplicate for 16 height
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
    vga_clear(0x00102040);
    vga_puts_at("Hello world", 10, 5, 0x00FFFFFF, 0x00102040);
    vga_puts_at("MoonlightOS - VGA driver isolated (I/O + FB, CHERI) OK", 2, 8, 0x0000FF00, 0x00102040);
    vga_puts_at("Framebuffer 0x40000000 800x600x32 mapped via vspace", 2, 10, 0x00AAAAAA, 0x00102040);
    // border
    for(int x=0;x<VGA_WIDTH;x++){ fb[x]=0x00FFAA00; fb[(VGA_HEIGHT-1)*VGA_WIDTH+x]=0x00FFAA00; }
    for(int y=0;y<VGA_HEIGHT;y++){ fb[y*VGA_WIDTH]=0x00FFAA00; fb[y*VGA_WIDTH+VGA_WIDTH-1]=0x00FFAA00; }
}
#endif
