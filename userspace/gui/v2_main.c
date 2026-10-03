/* userspace/gui/v2_main.c - L1 display server (qube 8, tid 10).
 * Owns the ONLY display path: ECAM scan, bochs bind, LFB leaf use,
 * FILL service on EP10. Paints NOTHING itself: every pixel arrives
 * through a validated FILL (layered: L2 client drives the pattern).
 * Fill tag FILL=6 (T_KEY 8 / T_KEY_ACK 10 live elsewhere); replies
 * R_OK 0 / R_DENY -1 (call/response discipline).
 * 
 * S4c additions: VirtIO keyboard/mouse input, text console rendering.
 * Input IRQs arrive via V2_WAIT (KBD_IRQ_BIT/MOUSE_IRQ_BIT notify bits).
 * Console: 100×37 character grid, 8×16 VGA font, direct LFB rendering. */
#include <stdint.h>

#include "rect.h"
#include "pci.h"
#include "virtio_input.h"
#include "console.h"
#include "input.h"

#define GUI_TID 10
#define GUI_QUBE 8
#define GUI_EP 10
#define FILL 6
#define R_OK 0L
#define R_DENY (-1L)

/* V2 UABI numbers (kernel/kboot.c; vault/firewall precedent). No INVOKE:
 * the LFB/ECAM leaves are kernel-mapped (Task 3); this ELF only loads
 * and stores through the pre-mapped VAs below. S4c adds WAIT for input IRQs. */
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_WAIT 6

/* WANT (Task 3 implements): the kernel pre-maps these windows into the
 * tid-10 tables ONLY (per-thread l1_t[10][i]; BLK precedent l1_t[9][6]).
 * LFB: GUI_LFB_UVA 0x80C00000 = VPN[1] index 6, window >= GUI_FB_MAX
 * covering the 800*600*4 frame (0x80C00000 reuses the BLK leaf index in
 * TID-10-ONLY tables: every thread owns its l1_t, so no alias). ECAM:
 * GUI_ECAM_UVA 0x80E00000 = VPN[1] index 7 (fresh index), window >= 64KB
 * covering the bus-0 config range (32 dev x 2KB). The ECAM leaf must be
 * RW: the BAR mask probe below writes all-ones and restores.
 * S4c: KBD_MMIO_UVA/MOUSE_MMIO_UVA (VPN[1] indices 9,10) map VirtIO input. */
#define GUI_LFB_UVA 0x80C00000UL
#define GUI_ECAM_UVA 0x80E00000UL

/* S4c input IRQ notify bits (kernel sets these in s_trap_handler, tid 10 reads via WAIT) */
#define KBD_IRQ_BIT 0x4UL
#define MOUSE_IRQ_BIT 0x8UL

/* PCI config-space dwords (ECAM offset from the function base). */
#define PCI_CFG_ID 0x00u
#define PCI_CFG_BAR0 0x10u
#define PCI_CFG_BAR1 0x14u

static long u_ecall3(long sys, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
}

static void u_putc(char c)
{
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}

static void u_puts(const char *s)
{
    while (*s) /* bound: NUL-terminated rodata literal */
        u_putc(*s++);
}

static long u_send(unsigned long ep, const uint64_t *p, unsigned long n)
{
    return u_ecall3(V2_SEND, (long)ep, (long)p, (long)n);
}

static long u_wait(void)
{
    return u_ecall3(V2_WAIT, 0, 0, 0);
}

/* RECV returns words-written in a0, kernel-stamped sender in a1,
 * sender qube in a2, truncation flag in a3 (explicit, never silent). */
static long u_recv(unsigned long ep, uint64_t *buf, unsigned long cap,
                   unsigned long *sender, unsigned long *qube,
                   unsigned long *ovf)
{
    register long r_a0 asm("a0") = (long)ep;
    register long r_a1 asm("a1") = (long)buf;
    register long r_a2 asm("a2") = (long)cap;
    register long r_a3 asm("a3") = 0;
    register long r_a7 asm("a7") = V2_RECV;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    *sender = (unsigned long)r_a1;
    *qube = (unsigned long)r_a2;
    *ovf = (unsigned long)r_a3;
    return r_a0;
}

static void u_reply(unsigned long dst, long v)
{
    uint64_t resp[1];
    resp[0] = (uint64_t)v;
    u_send(dst, resp, 1);
}

static void u_park(void)
{
    u_ecall3(V2_PARK, 0, 0, 0);
    for (;;) /* bound: inf - parked, never rescheduled */
        u_ecall3(V2_PARK, 0, 0, 0);
}

static uint32_t mmio_read32(unsigned long addr)
{
    volatile uint32_t *p = (volatile uint32_t *)addr;
    return *p;
}

static void mmio_write32(unsigned long addr, uint32_t v)
{
    volatile uint32_t *p = (volatile uint32_t *)addr;
    *p = v;
}

/* Bind the bochs-display VGA function on bus 0 and validate its LFB BAR.
 * Fetched, never recalled: QEMU hw/display/bochs-display.c binds vendor
 * PCI_VENDOR_ID_QEMU / device PCI_DEVICE_ID_QEMU_VGA (include/hw/pci/pci.h:
 * 0x1234 / 0x1111) and registers BAR 0 as the prefetchable 32-bit vram
 * LFB (default 16MiB) with BAR 2 as the register MMIO window — so BAR0
 * (cfg 0x10) is the LFB base and BAR1 (cfg 0x14) is its high word, which
 * must read 0 (nonzero = 64-bit BAR outside the uint32 model). Size comes
 * from the standard BAR mask probe (write all-ones, read mask, restore);
 * no LFB access happens before the restore (the fill loop starts after
 * bind). The window must then pass pci_bar_ok and cover GUI_FB_MAX.
 * Returns 1 bound, 0 fail-closed (caller parks marker-free). */
static int gui_bind_lfb(void)
{
    unsigned long dev;
    unsigned long fn;
    for (dev = 0; dev < 32UL; dev++) { /* bound: 32 (bus-0 devices) */
        for (fn = 0; fn < 8UL; fn++) { /* bound: 8 (functions per device) */
            uint32_t off = pci_cfg_off(0u, (uint32_t)dev, (uint32_t)fn);
            unsigned long cfg;
            uint32_t id;
            uint32_t b0;
            uint32_t b1;
            uint32_t mask;
            uint32_t base;
            uint32_t size;
            if (off == 0xFFFFFFFFu)
                continue; /* unreachable under bus-0 bounds; fail-closed */
            /* bound: off <= 31*2KB+7*256 < 64KB, so cfg cannot wrap */
            cfg = GUI_ECAM_UVA + (unsigned long)off;
            id = mmio_read32(cfg + (unsigned long)PCI_CFG_ID);
            if (id == 0xFFFFFFFFu)
                continue; /* empty slot: no device */
            if ((id & 0xFFFFu) != (uint32_t)BOCHS_VEN)
                continue;
            if ((id >> 16) != (uint32_t)BOCHS_DEV)
                continue;
            b0 = mmio_read32(cfg + (unsigned long)PCI_CFG_BAR0);
            b1 = mmio_read32(cfg + (unsigned long)PCI_CFG_BAR1);
            if ((b0 & 0x1u) != 0u)
                return 0; /* I/O BAR: not an MMIO framebuffer */
            if (((b0 >> 1) & 0x3u) == 0x2u)
                return 0; /* 64-bit BAR type: high word required */
            if (b1 != 0u)
                return 0; /* nonzero high word: outside the uint32 model */
            base = b0 & 0xFFFFFFF0u;
            mmio_write32(cfg + (unsigned long)PCI_CFG_BAR0, 0xFFFFFFFFu);
            mask = mmio_read32(cfg + (unsigned long)PCI_CFG_BAR0);
            mmio_write32(cfg + (unsigned long)PCI_CFG_BAR0, b0);
            size = (~(mask & 0xFFFFFFF0u)) + 1u;
            if (!pci_bar_ok(base, size))
                return 0;
            if (size < (uint32_t)GUI_FB_MAX)
                return 0; /* window too small for 800*600*4 */
            return 1;
        }
    }
    return 0;
}

/* S4c VirtIO input device initialization: minimal virtqueue setup for eventq.
 * VirtIO-input spec (v1.1 section 5.8): device provides two queues:
 *   queue 0 (eventq): device→driver event stream (EV_KEY, EV_REL, etc.)
 *   queue 1 (statusq): driver→device LED/force-feedback (not used here)
 * Minimal setup: single-descriptor ring (16 slots), no indirect, no packed.
 * Production virtio drivers use dynamic multi-descriptor chains + indirect
 * descriptors for scatter-gather; S4c uses statically allocated flat rings. */

/* VirtIO eventq ring state (kbd and mouse each have independent rings) */
typedef struct {
    virtq_desc_t desc[16];  /* Descriptor ring (16 slots) */
    virtq_avail_t avail;    /* Available ring (driver→device) */
    virtq_used_t used;      /* Used ring (device→driver) */
    struct virtio_input_event events[16]; /* Event buffer (one per descriptor) */
    uint16_t last_used_idx; /* Last processed used.idx (for polling) */
} virtio_input_ring_t;

static virtio_input_ring_t kbd_ring;
static virtio_input_ring_t mouse_ring;

/* S4c input arming flag (Task 1: 0 = dormant). File scope + non-const so
 * the compiler keeps the init/poll/render path in the binary (a const or
 * function-local flag folds at -O2 and silently drops the audited S4c
 * code, shrinking .text/.bss and voiding the budget measurement below).
 * Zero-init keeps it in .bss (see the .data-alignment note at
 * surf_owner). Task 2 flips this to 1 alongside the l1_t[10][9]/[10]
 * leaf wiring; the short-circuit in gui_main then arms the probe. */
int input_armed = 0;

/* Initialize one VirtIO input device: reset, feature negotiation, queue setup.
 * Returns 1 on success, 0 on failure (device not responding or malformed).
 * Fail-closed: the presence probe below performs NO writes before the
 * device answers MAGIC/VERSION/DEVICE_ID, so a wrong/absent transport is
 * never reset and the caller can skip input and stay on the S4b path. */
static int virtio_input_init(volatile uint32_t *mmio, virtio_input_ring_t *ring) {
    /* Step 0: Presence probe (reads only — no STATUS write yet).
     * MAGIC must read "virt" (0x74726976), VERSION 2 (modern MMIO
     * transport), DEVICE_ID 18 (input). Any mismatch -> return 0. */
    if (mmio[VIRTIO_MMIO_MAGIC / 4] != 0x74726976u)
        return 0; /* No VirtIO transport here */
    if (mmio[VIRTIO_MMIO_VERSION / 4] != 2u)
        return 0; /* Legacy transport: outside the S4c driver model */
    if (mmio[VIRTIO_MMIO_DEVICE_ID / 4] != 18u)
        return 0; /* Transport holds a different device (net/blk/rng) */

    /* Step 1: Device reset (VIRTIO_MMIO_STATUS = 0) */
    mmio[VIRTIO_MMIO_STATUS / 4] = 0;
    
    /* Step 2: Acknowledge device (STATUS |= ACKNOWLEDGE) */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE;
    
    /* Step 3: Driver ready (STATUS |= DRIVER) */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
    
    /* Step 4: Feature negotiation (S4c: no features required, accept defaults) */
    mmio[VIRTIO_MMIO_DRIVER_FEATURES_SEL / 4] = 0;
    mmio[VIRTIO_MMIO_DRIVER_FEATURES / 4] = 0;
    
    /* Step 5: Features OK (STATUS |= FEATURES_OK) */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE | 
                                    VIRTIO_STATUS_DRIVER | 
                                    VIRTIO_STATUS_FEATURES_OK;
    
    /* Verify FEATURES_OK stuck (device accepted our feature set) */
    if ((mmio[VIRTIO_MMIO_STATUS / 4] & VIRTIO_STATUS_FEATURES_OK) == 0)
        return 0; /* Device rejected features */
    
    /* Step 6: Queue setup (queue 0 = eventq) */
    mmio[VIRTIO_MMIO_QUEUE_SEL / 4] = 0; /* Select queue 0 */
    
    uint32_t qmax = mmio[VIRTIO_MMIO_QUEUE_NUM_MAX / 4];
    if (qmax < 16) return 0; /* Need at least 16 slots */
    
    mmio[VIRTIO_MMIO_QUEUE_NUM / 4] = 16; /* Use 16 slots */
    
    /* Program queue physical addresses (guest-physical = user virtual in S4c) */
    uint64_t desc_pa = (uint64_t)(uintptr_t)ring->desc;
    uint64_t avail_pa = (uint64_t)(uintptr_t)&ring->avail;
    uint64_t used_pa = (uint64_t)(uintptr_t)&ring->used;
    
    mmio[VIRTIO_MMIO_QUEUE_DESC_LOW / 4] = (uint32_t)desc_pa;
    mmio[VIRTIO_MMIO_QUEUE_DESC_HIGH / 4] = (uint32_t)(desc_pa >> 32);
    mmio[VIRTIO_MMIO_QUEUE_DRIVER_LOW / 4] = (uint32_t)avail_pa;
    mmio[VIRTIO_MMIO_QUEUE_DRIVER_HIGH / 4] = (uint32_t)(avail_pa >> 32);
    mmio[VIRTIO_MMIO_QUEUE_DEVICE_LOW / 4] = (uint32_t)used_pa;
    mmio[VIRTIO_MMIO_QUEUE_DEVICE_HIGH / 4] = (uint32_t)(used_pa >> 32);
    
    /* Initialize descriptor ring: all slots point to event buffers (write-only) */
    for (int i = 0; i < 16; i++) { /* bound: 16 */
        ring->desc[i].addr = (uint64_t)(uintptr_t)&ring->events[i];
        ring->desc[i].len = sizeof(struct virtio_input_event);
        ring->desc[i].flags = VIRTQ_DESC_F_WRITE; /* Device writes */
        ring->desc[i].next = 0;
    }
    
    /* Initialize available ring: make all 16 descriptors available */
    ring->avail.flags = 0;
    ring->avail.idx = 16; /* Wrapped at 65536; device sees 16 available */
    for (int i = 0; i < 16; i++) { /* bound: 16 */
        ring->avail.ring[i] = (uint16_t)i;
    }
    
    /* Initialize used ring tracking */
    ring->last_used_idx = 0;
    
    /* Queue ready */
    mmio[VIRTIO_MMIO_QUEUE_READY / 4] = 1;
    
    /* Step 7: Driver OK (STATUS |= DRIVER_OK) */
    mmio[VIRTIO_MMIO_STATUS / 4] = VIRTIO_STATUS_ACKNOWLEDGE | 
                                    VIRTIO_STATUS_DRIVER | 
                                    VIRTIO_STATUS_FEATURES_OK | 
                                    VIRTIO_STATUS_DRIVER_OK;
    
    return 1;
}

/* Poll VirtIO input eventq: process all pending events in used ring.
 * Returns number of events processed. Updates last_used_idx.
 * Bound: each iteration consumes one used-ring slot (last_used_idx++),
 * so trips <= 65536 (uint16 wrap distance); desc_id is validated < 16
 * before indexing events[]. */
static int virtio_input_poll(volatile uint32_t *mmio, virtio_input_ring_t *ring,
                             kbd_modifiers_t *kbd_mods, mouse_state_t *mouse,
                             console_t *con) {
    int n = 0;
    
    /* Check if new events available (used.idx advanced) */
    while (ring->last_used_idx != ring->used.idx) { /* bound: <=65536 (uint16 wrap) */
        /* Get completed descriptor */
        uint16_t idx = ring->last_used_idx % 16;
        uint32_t desc_id = ring->used.ring[idx].id;
        
        if (desc_id >= 16) break; /* Invalid descriptor ID */
        
        struct virtio_input_event *ev = &ring->events[desc_id];
        
        /* Process event based on type */
        if (ev->type == EV_KEY) {
            /* Keyboard or mouse button event */
            int pressed = (ev->value == 1); /* 1=press, 0=release, 2=repeat */
            
            /* Update modifiers first */
            update_modifiers(kbd_mods, ev->code, pressed);
            
            /* Convert to ASCII on press (ignore release and repeat) */
            if (pressed && ev->value == 1) {
                char ch = keycode_to_ascii(ev->code, kbd_mods);
                if (ch != 0) {
                    console_putc(con, ch);
                }
            }
            
            /* Mouse buttons */
            mouse_button(mouse, ev->code, pressed);
            
        } else if (ev->type == EV_REL) {
            /* Mouse relative motion */
            if (ev->code == REL_X) {
                mouse_move(mouse, (int)ev->value, 0);
            } else if (ev->code == REL_Y) {
                mouse_move(mouse, 0, (int)ev->value);
            }
        }
        /* EV_SYN ignored (synchronization marker) */
        
        /* Re-add descriptor to available ring for device reuse */
        uint16_t avail_idx = ring->avail.idx % 16;
        ring->avail.ring[avail_idx] = (uint16_t)desc_id;
        ring->avail.idx++;
        
        ring->last_used_idx++;
        n++;
    }
    
    /* Notify device if we processed events (kick device to refill) */
    if (n > 0) {
        mmio[VIRTIO_MMIO_QUEUE_NOTIFY / 4] = 0; /* Notify queue 0 */
        
        /* Acknowledge IRQ (clear INTERRUPT_STATUS) */
        uint32_t isr = mmio[VIRTIO_MMIO_INTERRUPT_STATUS / 4];
        if (isr != 0) {
            mmio[VIRTIO_MMIO_INTERRUPT_ACK / 4] = isr;
        }
    }
    
    return n;
}

/* First-valid marker: .bss flag (v2_user.ld provides .data/.bss RW,
 * lines 18-19: *(.data*) *(.got*) *(.sdata*), *(.bss*) *(COMMON)). */
static int gui_announced = 0;

#include "surf.h"
#define SURF_CREATE 7
#define SURF_DESTROY 8
#define COMPOSE 9
static uint32_t surf[SURF_N][SURF_W*SURF_H];
static uint8_t surf_owner[SURF_N]; /* 0xFF = free; zero-init keeps .data empty so .bss stays page-aligned (loader rejects unaligned PT_LOAD); set to 0xFF at runtime before the service loop */
static uint8_t surf_dirty[SURF_N] = {0,0,0,0};
static uint8_t surf_has[11] = {0}; /* indexed by snd tid; 1 = owns a surface */
static uint8_t surf_id_of[11] = {0};
static int gui_composed = 0;

void gui_main(void)
{
    unsigned long snd;
    unsigned long sqb;
    unsigned long ovf;
    uint64_t buf[4];
    long n;
    uint32_t xy;
    uint32_t wh;
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t color;
    uint32_t row;
    uint32_t col;
    
    /* S4c: Console and input state. console_mode defaults to 0 (surface
     * mode) so the S4b FILL/COMPOSE path is live; Task 3 legs rely on it. */
    static console_t console;
    static kbd_modifiers_t kbd_mods;
    static mouse_state_t mouse;
    int input_ready = 0;
    int console_mode = 0; /* 0=surface mode, 1=console mode (toggle with F1) */
    
    if (!gui_bind_lfb())
        u_park(); /* fail closed, marker-free: no "GUI: up" */
    u_puts("GUI: up\n");
    
    /* S4c input gate (Task 1: dormant). Task 2 has not mapped
     * KBD/MOUSE_MMIO_UVA yet (l1_t[10][9]/[10] are zero on the S4b
     * kernel), and U-mode cannot safely probe an unmapped window: ANY
     * load/store there raises a fault that parks this thread, killing
     * the S4b service loop below. So the init calls stay off
     * (input_armed = 0): input_ready stays 0, the u_wait() leg in the
     * service loop is skipped, and FILL/COMPOSE keep serving. Task 2
     * flips input_armed to 1 alongside the leaf wiring; from then on
     * any init-0 (probe mismatch above) still skips input and falls
     * through here — input init never parks this thread. */
    volatile uint32_t *kbd_mmio = (volatile uint32_t *)KBD_MMIO_UVA;
    volatile uint32_t *mouse_mmio = (volatile uint32_t *)MOUSE_MMIO_UVA;

    if (input_armed &&
        virtio_input_init(kbd_mmio, &kbd_ring) &&
        virtio_input_init(mouse_mmio, &mouse_ring))
        input_ready = 1;

    if (input_ready) {
        console_init(&console);
        kbd_modifiers_init(&kbd_mods);
        mouse_init(&mouse);
        u_puts("INPUT: kbd and mouse ready\n");
        console_puts(&console, "MoonlightOS S4c Console\n");
        console_puts(&console, "Type to test keyboard, move mouse for cursor.\n");
        console_puts(&console, "F1: toggle surface/console mode\n\n");
    }
    
    for (uint32_t i = 0; i < (uint32_t)SURF_N; i++) /* bound: SURF_N */
        surf_owner[i] = 0xFF; /* all slots free before first RECV */
    for (;;) { /* bound: inf - service loop */
        /* S4c input leg: skipped unless input_ready (dormant in Task 1,
         * so the S4b path below stays live). Task 3 note: V2_WAIT blocks
         * when notify is empty, so this leg must not starve the RECV
         * below — poll input only when notified, then always fall
         * through to RECV. */
        if (input_ready) {
            long notify_bits = u_wait();
            
            if (notify_bits & KBD_IRQ_BIT) {
                virtio_input_poll(kbd_mmio, &kbd_ring, &kbd_mods, &mouse, &console);
            }
            if (notify_bits & MOUSE_IRQ_BIT) {
                virtio_input_poll(mouse_mmio, &mouse_ring, &kbd_mods, &mouse, &console);
            }
            
            /* Render console if in console mode */
            if (console_mode) {
                volatile uint32_t *fb = (volatile uint32_t *)GUI_LFB_UVA;
                console_render_with_cursor(&console, fb);
                cursor_render(fb, mouse.x, mouse.y);
            }
        }
        
        snd = 0;
        sqb = 0;
        ovf = 0;
        n = u_recv(GUI_EP, buf, 4, &snd, &sqb, &ovf);
        /* Defense in depth: kernel gate is holder-based (any QX holder
         * passes qube_raw_ok), so enforce qube0-only here. Non-qube-0
         * sender -> DENY, zero pixels touched (S4b will add per-qube
         * surfaces; this stage is output-only for qube 0). */
        if (ovf != 0) { u_reply(snd, R_DENY); continue; }
        if (sqb != 0) {
            u_reply(snd, R_DENY);
            continue;
        }
        if (n < 1)
            continue; /* not ours: silent drop, no reply (no waiter) */
        if (n >= 2 && buf[0] == (uint64_t)SURF_CREATE) { /* [7, sid, wh, flags] */
            uint32_t sid = (uint32_t)buf[1]; uint32_t wh = (n >= 3) ? (uint32_t)buf[2] : 0u;
            if (n != 4 || sid >= (uint32_t)SURF_N || !surf_wh_ok(wh) || surf_owner[sid] != 0xFF || surf_has[snd]) { u_reply(snd, R_DENY); continue; }
            surf_owner[sid] = (uint8_t)snd; surf_has[snd] = 1; surf_id_of[snd] = (uint8_t)sid; surf_dirty[sid] = 0;
            u_reply(snd, R_OK); continue;
        }
        if (n == 2 && buf[0] == (uint64_t)SURF_DESTROY) {
            uint32_t sid = (uint32_t)buf[1];
            if (sid >= (uint32_t)SURF_N || surf_owner[sid] != (uint8_t)snd) { u_reply(snd, R_DENY); continue; }
            surf_owner[sid] = 0xFF; surf_has[snd] = 0; surf_dirty[sid] = 0;
            u_reply(snd, R_OK); continue;
        }
        if (n == 1 && buf[0] == (uint64_t)COMPOSE) {
            /* bound: SURF_N * SURF_H * SURF_W */
            for (uint32_t s = 0; s < (uint32_t)SURF_N; s++) { /* bound: SURF_N */
                if (!surf_dirty[s]) continue;
                /* full-surface blit at fixed slot origin (s*40 % 800, 20 + s*30 % 430) */
                uint32_t ox = (s * 40u) % 800u; uint32_t oy = 20u + (s * 30u) % 430u;
                for (uint32_t r = 0; r < (uint32_t)SURF_H; r++) /* bound: SURF_H */
                    for (uint32_t c = 0; c < (uint32_t)SURF_W; c++) { /* bound: SURF_W */
                        uint32_t idx = rect_off(ox + c, oy + r);
                        if (idx == 0xFFFFFFFFu) continue;
                        *(volatile uint32_t *)(GUI_LFB_UVA + (unsigned long)(idx * 4u)) = surf[s][r * SURF_W + c];
                    }
                surf_dirty[s] = 0;
            }
            /* chrome strip: top 20px solid qube color */
            for (uint32_t y = 0; y < 20u; y++) /* bound: 20 */
                for (uint32_t x = 0; x < 800u; x++) { /* bound: 800 */
                    uint32_t idx = rect_off(x, y);
                    *(volatile uint32_t *)(GUI_LFB_UVA + (unsigned long)(idx * 4u)) = 0x00112233u;
                }
            if (!gui_composed) { u_puts("GUI: composed ok\n"); gui_composed = 1; }
            u_reply(snd, R_OK); continue;
        }
        if (n < 4 || buf[0] != (uint64_t)FILL) {
            u_reply(snd, R_DENY);
            continue;
        }
        xy = (uint32_t)buf[1];
        wh = (uint32_t)buf[2];
        color = (uint32_t)buf[3];
        x = (xy >> 16) & 0xFFFFu;
        y = xy & 0xFFFFu;
        w = (wh >> 16) & 0xFFFFu;
        h = wh & 0xFFFFu;
        if (surf_has[snd]) {
            uint32_t sid = surf_id_of[snd];
            if (surf_owner[sid] != (uint8_t)snd || !surf_fill_ok(sid, x, y, w, h)) { u_reply(snd, R_DENY); continue; }
            for (row = 0; row < h; row++) /* bound: SURF_H */
                for (col = 0; col < w; col++) /* bound: SURF_W */
                    surf[sid][(y+row)*SURF_W + (x+col)] = color;
            surf_dirty[sid] = 1;
            u_reply(snd, R_OK); continue;
        }
        if (!rect_fill_ok(x, y, w, h)) {
            u_reply(snd, R_DENY);
            continue;
        }
        if (y < 20u) { u_reply(snd, R_DENY); continue; }
        /* bound: GUI_W*GUI_H total (rows <= GUI_H, cols <= GUI_W; the
         * validated rect gives w*h <= 800*600, and x+col < 800 /
         * y+row < 600, so rect_off below never hits its sentinel). */
        for (row = 0; row < h; row++) { /* bound: GUI_H */
            for (col = 0; col < w; col++) { /* bound: GUI_W */
                uint32_t idx = rect_off(x + col, y + row); /* pixel index */
                /* rect_off returns a PIXEL index: scale by GUI_BPP (4)
                 * for the byte offset (idx < 480000, so idx*4 cannot
                 * wrap; the store is volatile MMIO through the LFB). */
                *(volatile uint32_t *)(GUI_LFB_UVA +
                    (unsigned long)(idx * (uint32_t)GUI_BPP)) = color;
            }
        }
        if (!gui_announced) {
            u_puts("GUI: fill ok\n");
            gui_announced = 1;
        }
        u_reply(snd, R_OK);
    }
}
