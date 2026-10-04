/* v2 S-mode kernel (Stage 2): Sv39 U-bit tables, stvec traps, SBI console,
 * timer-preemptive round-robin scheduler (mirrors V2_A.sched_step),
 * two U-mode threads, blocking rendezvous IPC on addressed endpoints
 * (EP i owned by tid i) + notifications (mirrors V2_C: c_send/c_recv/c_notify/c_wait), fault
 * containment. No PMP changes (firmware owns); SUM toggled only inside
 * copy_from/to_user after range validation (S never touches U pages
 * otherwise: stacks filled pre-MMU, console via SBI-forward). */
#include "../userspace/firewall/fw.h" /* S3 demo drives fw_decide (header-only, pure C) */
#include "caps.h"
#include "elf.h"
#include "fbconsole.h" /* S4a kernel framebuffer console output */
#include "initrd.h"
#include "ipc.h"
#include "dev.h"
#include "dev_leaves.h"
#include "irq.h"
#include "qube.h"
#include "services.h"
#include "virtio_ident.h"
#include <stdint.h>

/* ---- SBI (legacy EIDs; OpenSBI serves M-mode) ---- */
#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1

static long sbi_ecall(long eid, long fid, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a6 asm("a6") = fid;
    register long r_a7 asm("a7") = eid;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1) : "r"(r_a2), "r"(r_a6), "r"(r_a7) : "memory");
    return r_a0;
}

static void sbi_putchar(char c)
{
    sbi_ecall(SBI_CONSOLE_PUTCHAR, 0, (long)(unsigned char)c, 0, 0);
}

static void sbi_set_timer(uint64_t stime)
{
    sbi_ecall(SBI_SET_TIMER, 0, (long)stime, (long)(stime >> 32), 0);
}

/* Boot-time logging flag: when 1, print all debug messages.
 * Set to 0 after services spawn to silence runtime IPC/invoke chatter. */
static int boot_log_enabled = 1;
static void kputhex(uint64_t v);
static void kputdec(unsigned long v);

static void kputs(const char *s)
{
    while (*s)
    {
        sbi_putchar(*s);
        fbcon_putc(*s); /* mirror to framebuffer if initialised */
        s++;
    }
}

/* Debug logging (IPC, invoke, scheduler): only printed during boot */
static void klog(const char *s)
{
    if (boot_log_enabled)
    {
        kputs(s);
    }
}

static void klog_char(char c)
{
    if (boot_log_enabled)
    {
        sbi_putchar(c);
    }
}

static void klog_dec(unsigned long v)
{
    if (boot_log_enabled)
    {
        kputdec(v);
    }
}

static void klog_hex(uint64_t v)
{
    if (boot_log_enabled)
    {
        kputhex(v);
    }
}

static void kputhex(uint64_t v)
{
    for (int i = 60; i >= 0; i -= 4)
    {
        int n = (v >> i) & 0xF;
        sbi_putchar(n < 10 ? '0' + n : 'a' + n - 10);
    }
}

static void kputdec(unsigned long v)
{
    char buf[24];
    int i = 0;
    if (v == 0)
    {
        sbi_putchar('0');
        return;
    }
    while (v > 0 && i < 23)
    {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i-- > 0)
        sbi_putchar(buf[i]);
}

/* ---- Sv39 ---- */
#define PTE_V (1UL << 0)
#define PTE_R (1UL << 1)
#define PTE_W (1UL << 2)
#define PTE_X (1UL << 3)
#define PTE_U (1UL << 4)
#define PTE_A (1UL << 6)
#define PTE_D (1UL << 7)

/* Real physical backing for v2 frames: QEMU virt 256M RAM (base 0x80000000),
 * free region above the image (< 0x80800000). S-only identity map via
 * l0_frames, wired at l1_t[t][8] (VPN[1] of 0x81000000) in every VSpace. */
#define V2_FRAME_PHYS_BASE 0x81000000UL
/* Pool window (Task 4): 32x4K = 128K, trivially inside both the l0_frames
 * identity map (512 pages = 2M) and the free region above the image. */
_Static_assert((unsigned long)V2_FRAMES_MAX * 4096UL <= 512UL * 4096UL,
               "frame pool must fit the l0_frames identity map");
#define NTHREADS 11 /* bound for all thread loops (<= V2_CAP_THREADS) */
/* Threads: 0 A, 1 B, 2 mem_server, 3 qrexec, 4 AdminVM, 5 firewall,
 * 6 net, 7 CAP stub, 8 vault, 9 cryptblk, 10 gui. Growing NTHREADS
 * forces WCET/table re-analysis: threads[], qube_of[], u_sp[] size with
 * it; root_pt_t/l1_t/l0_u_t cover V2_CAP_THREADS. NTHREADS == 11 ==
 * V2_CAP_THREADS: the thread table is full — the next thread forces a
 * V2_CAP_THREADS bump + proof replay (S4b). */
_Static_assert(NTHREADS <= V2_CAP_THREADS, "NTHREADS must fit the caps model + page tables");

/* S3 Phase-2 NIC: virtio-net on an MMIO transport (riscv-virt standard
 * layout: 8 transports at 0x10001000+i*0x1000, IRQ 1+i). Measured on the
 * pinned QEMU: transports default to legacy mode (fixed with
 * -global virtio-mmio.force-legacy=off on the QEMU cmdline) and backends
 * attach last-first, so the NIC is NOT assumed at transport 0: kboot
 * scans for the modern (version-2) net device (device id 1) and records
 * its IRQ, and the tid-6 U-leaf maps all 8 transport pages (only tid 6).
 * PLIC regs below name both hart-0 context sets (M + S); the S-context
 * set signals S-mode directly (the path that delivers on the pinned
 * QEMU), the M-context set is programmed identically as a fallback.
 * Constants live in platform.h (PLIC, virtio IDs, notify bits). */
static uint32_t net_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
static uint32_t blk_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
/* S4c input IRQs: Task 3 discovery fills these (first dev-18 = mouse, second
 * = kbd); the Task 3 handler + PLIC setup are the real consumers. */
static uint32_t kbd_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
static uint32_t mouse_virtio_irq = VIRTIO_IRQ_NOT_FOUND;

/* V2_INV_WRITE/READ move exactly one 64-bit word: the caps.h model is
 * word-per-frame (fdata[f] = val), so the real store/load mirrors exactly
 * what the model records and fdata can never diverge from the
 * real frame (Write-Through Mirror). This bounds every new copy loop and
 * keeps every frame access within the pool region (frame <
 * V2_FRAMES_MAX, max offset (V2_FRAMES_MAX-1)*4096 + V2_WORD_BYTES). */
#define V2_WORD_BYTES 8 /* bound: bytes per WRITE/READ invoke (one word) */

/* Per-thread Sv39 VSpaces. root_pt_t = root (index VPN[2]), l1_t = level-1
 * (index VPN[1]), l0_u_t = per-thread frame window (VPN[1] of 0x80800000).
 * l1_m (UART), l0_k (kernel image) and l0_frames (frame region) are shared
 * and referenced by every thread's tables. */
static uint64_t root_pt_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l1_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l0_u_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l1_m[512] __attribute__((aligned(4096)));
static uint64_t l0_k[512] __attribute__((aligned(4096)));
static uint64_t l0_frames[512] __attribute__((aligned(4096)));
/* Phase-2 NIC U-leaf: single page table mapping the 8 VIRTIO0 transport
 * pages for tid 6 only (wired at l1_t[6][5]; every other l1_t[t][5] stays
 * 0, asserted at boot). Zero-initialized except [0..7]: the transport
 * pages, RW, never X. */
static uint64_t l0_netmmio[512] __attribute__((aligned(4096)));
/* FDE block U-leaf: same single-leaf pattern as the NIC, for tid 9 only
 * (wired at l1_t[9][6] = UVA 0x80C00000; every other l1_t[t][6] stays 0,
 * asserted at boot). The 8 transport pages, RW, never X. */
static uint64_t l0_blkmmio[512] __attribute__((aligned(4096)));
/* RNG U-leaf: same single-leaf pattern as NET/BLK, for tid 8 only
 * (wired at l1_t[8][5] = UVA 0x80A00000; reuses the NET leaf INDEX in
 * tid-8-only tables — every thread owns its l1_t, so no alias with
 * l1_t[6][5]. The 8 transport pages, RW, never X. Exclusivity asserted
 * at boot ("RNGMMIO"), with the NETMMIO gate tolerating tid 8. */
static uint64_t l0_rngmmio[512] __attribute__((aligned(4096)));
/* S4c Input U-leaves: keyboard and mouse MMIO transports for tid 10 only.
 * kbd at l1_t[10][9] = UVA 0x81200000 (VPN[1] index 9, fresh: GUI uses 6/7).
 * mouse at l1_t[10][10] = UVA 0x81400000 (VPN[1] index 10, fresh). Each maps
 * 8 virtio-mmio transport pages (0x10001000+i*0x1000), RW never X. Presence
 * + exclusivity asserted at boot (extended "GUIMMIO" gate below). */
#define KBD_MMIO_UVA 0x81200000UL
#define MOUSE_MMIO_UVA 0x81400000UL
static uint64_t l0_kbdmmio[512] __attribute__((aligned(4096)));
static uint64_t l0_mousemmio[512] __attribute__((aligned(4096)));
/* S4a GUI configuration: Resolution and display parameters.
 * Current: 800×600×32 (XRGB, matches QEMU bochs-display default).
 * Future: Runtime negotiation via VBE/EDID (S4b). */
#define GUI_WIDTH 800
#define GUI_HEIGHT 600
#define GUI_BPP 32                             /* bits per pixel: 32-bit XRGB */
#define GUI_STRIDE (GUI_WIDTH * (GUI_BPP / 8)) /* bytes per scanline */
#define GUI_FB_SIZE (GUI_HEIGHT * GUI_STRIDE)  /* total framebuffer bytes */

/* S4a GUI leaves (Task-2 VAs, kernel maps / ELF scans):
 * - LFB U-leaf l0_guifb: 512 pages (2MB window) at GUI_LFB_PHYS, wired at
 *   l1_t[10][6] = UVA 0x80C00000. Reuses the BLK leaf INDEX in tid-10-only
 *   tables (every thread owns its l1_t, so no alias with l1_t[9][6]).
 *   Covers the GUI_FB_SIZE frame (469 pages) inside the programmed BAR.
 * - ECAM U-leaf l0_guiecam: bus-0 config range (64KB = 16 pages) at
 *   GUI_ECAM_PHYS, wired at l1_t[10][7] = UVA 0x80E00000 (fresh index).
 *   RW: the ELF's BAR mask probe writes all-ones and restores.
 * Both RW, never X (W^X). Exclusivity asserted at boot ("GUIMMIO"). */
#define GUI_LFB_UVA 0x80C00000UL
#define GUI_ECAM_UVA 0x80E00000UL
#define GUI_ECAM_PHYS 0x30000000UL /* virt-machine ECAM base (fixed) */
#define GUI_LFB_PHYS 0x40000000UL  /* kernel-assigned BAR0 (PCI low-MMIO window, 64M-aligned) */
#define GUI_VBE_PHYS 0x44000000UL  /* kernel-assigned BAR2 (Bochs VBE registers) */
#define GUI_VBE_VA 0x30400000UL    /* S-mode alias via l1_m[386] */
#define GUI_VBE_BAR_OFFSET 0x500u
#define GUI_ECAM_PAGES 16                                   /* bound: bus-0 config range 64KB (32 dev x 2KB) */
#define GUI_LFB_PAGES 512                                   /* bound: one l0 table (2MB window >= 469-page frame) */
#define GUI_PCI_VEN 0x1234u                                 /* bochs-display vendor (QEMU include/hw/pci/pci.h) */
#define GUI_PCI_DEV 0x1111u                                 /* bochs-display device (QEMU hw/display/bochs-display.c) */
#define GUI_LFB_MAX 0x4000000u                              /* largest BAR the kernel assigns (64M, ELF re-validates) */
#define GUI_FB_MIN (GUI_WIDTH * GUI_HEIGHT * (GUI_BPP / 8)) /* smallest usable LFB */
static uint64_t l0_guifb[512] __attribute__((aligned(4096)));
static uint64_t l0_guiecam[512] __attribute__((aligned(4096)));

static uint64_t pte_leaf(uint64_t paddr, uint64_t flags)
{
    return ((paddr >> 12) << 10) | flags | PTE_V;
}

static uint64_t pte_table(uint64_t *tab)
{
    return (((uint64_t)tab >> 12) << 10) | PTE_V;
}

static void pagetable_init(void)
{
    extern char _stext[], _erx[];
    uintptr_t text_start = (uintptr_t)_stext & ~0xFFFUL;
    uintptr_t text_end = ((uintptr_t)_erx + 0xFFFUL) & ~0xFFFUL;
    for (int i = 0; i < 512; i++)
    {
        uintptr_t pa = 0x80200000UL + (uintptr_t)i * 4096;
        uint64_t f = PTE_R | PTE_W | PTE_A | PTE_D;
        if (pa >= text_start && pa < text_end)
            f = PTE_R | PTE_X | PTE_A;
        l0_k[i] = pte_leaf(pa, f);
    }
    for (int i = 0; i < 512; i++) /* bound: 512 */
        l0_frames[i] = pte_leaf(V2_FRAME_PHYS_BASE + (uintptr_t)i * 4096, PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[128] = pte_leaf(0x10000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC: S-only RW leaves for the PLIC region
     * (0x0c000000-0x0c3fffff: priority/pending/enable + hart-0
     * threshold/claim), mirroring the l1_m[128] UART line. */
    l1_m[96] = pte_leaf(0x0c000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[97] = pte_leaf(0x0c200000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* S4a GUI ECAM S-leaf: 2MB megapage at VPN[1] 384 covering
     * 0x30000000-0x301FFFFF (buses 0-1). S-only (no U bit): the kernel's
     * BAR programming below runs in S-mode post-MMU through it; the ELF
     * never sees this VA (it uses the l0_guiecam U-leaf instead). */
    l1_m[384] = pte_leaf(GUI_ECAM_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* S4a GUI LFB S-leaf: 2MB megapage at VPN[1] 385 covering
     * 0x40000000-0x401FFFFF (GUI framebuffer). S-only (no U bit): the kernel
     * can write boot messages here post-MMU; the ELF uses its own l0_guifb U-leaf. */
    l1_m[385] = pte_leaf(GUI_LFB_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Bochs VBE registers: BAR2 is assigned GUI_VBE_PHYS below and reached
     * through this S-only alias. */
    l1_m[386] = pte_leaf(GUI_VBE_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC U-leaf: all 8 transport pages for tid 6 (NET_UVA +
     * i*0x1000, VPN[1] 5, VPN[0] 0..7: the driver scans for the NIC
     * because QEMU attaches backends last-first). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_netmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* FDE block U-leaf: the same 8 transport pages for tid 9 (BLK_UVA
     * 0x80C00000 = VPN[1] 6, VPN[0] 0..7: the driver scans for the
     * virtio-blk device, never assuming a transport). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_blkmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* RNG U-leaf: the same 8 transport pages for tid 8 (same shape as
     * NET/BLK above: the vault ELF scans for the virtio-rng device,
     * never assuming a transport). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_rngmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* S4c Input U-leaves: kbd and mouse transport pages for tid 10 only.
     * Same shape as NET/BLK/RNG: 8 transport pages, RW never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_kbdmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_mousemmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* S4a GUI U-leaves (contents fixed pre-MMU; the BAR programming in
     * kboot() assigns this same GUI_LFB_PHYS, so leaf and BAR agree by
     * construction). W^X: RW, never X. */
    for (int k = 0; k < GUI_LFB_PAGES; k++) /* bound: GUI_LFB_PAGES (512) */
        l0_guifb[k] = pte_leaf(GUI_LFB_PHYS + (unsigned long)k * 4096UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    for (int k = 0; k < GUI_ECAM_PAGES; k++) /* bound: GUI_ECAM_PAGES (16) */
        l0_guiecam[k] = pte_leaf(GUI_ECAM_PHYS + (unsigned long)k * 4096UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* Per-thread VSpaces: shared kernel/leaf/frame/UART regions are wired
     * through each thread's own l1_t; the per-thread frame window
     * (l0_u_t) stays zero until Task 3 maps frames. */
    for (int t = 0; t < NTHREADS; t++)
    { /* bound: NTHREADS */
        l1_t[t][1] = pte_table(l0_k);
        l1_t[t][2] = pte_leaf(0x80400000UL, PTE_R | PTE_X | PTE_U | PTE_A);
        l1_t[t][3] = pte_leaf(0x80600000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        l1_t[t][4] = pte_table(l0_u_t[t]);
        l1_t[t][8] = pte_table(l0_frames);
        /* Phase-2 NIC: the transport U-leaf exists ONLY in tid 6's tables
         * (NET_UVA 0x80A00000 = VPN[1] 5). Every other l1_t[t][5] stays 0
         * except tid 8 (RNG leaf: same INDEX, different thread's tables —
         * asserted at boot: "NETMMIO: tid=6 only" + "RNGMMIO"). */
        if (t == 6)
            l1_t[t][5] = pte_table(l0_netmmio);
        /* FDE block: the transport U-leaf exists ONLY in tid 9's tables
         * (BLK_UVA 0x80C00000 = VPN[1] 6). Every other l1_t[t][6] stays 0
         * except tid 10 (GUI LFB: same INDEX, different thread's tables —
         * asserted at boot: "BLKMMIO: tid=9 only" + "GUIMMIO"). */
        if (t == 9)
            l1_t[t][6] = pte_table(l0_blkmmio);
        /* RNG: the transport U-leaf exists ONLY in tid 8's tables
         * (RNG_UVA 0x80A00000 = VPN[1] 5, fresh for tid 8: its frame
         * window is index 4, GUI/BLK use 6/7). Every other l1_t[t][5]
         * stays 0 except tid 6 (NET: same INDEX, different thread's
         * tables — asserted at boot: "RNGMMIO: tid=8 only" + "NETMMIO"). */
        if (t == 8)
            l1_t[t][5] = pte_table(l0_rngmmio);
        /* S4a GUI + S4c Input: LFB + ECAM + kbd + mouse U-leaves exist ONLY
         * in tid 10's tables (GUI_LFB_UVA 0x80C00000 = VPN[1] 6, GUI_ECAM_UVA
         * 0x80E00000 = VPN[1] 7, KBD_MMIO_UVA 0x81200000 = VPN[1] 9,
         * MOUSE_MMIO_UVA 0x81400000 = VPN[1] 10). Exclusivity asserted at
         * boot: "GUIMMIO" / "KBDMMIO" / "MOUSEMMIO" gates. */
        if (t == 10)
        {
            l1_t[t][6] = pte_table(l0_guifb);
            l1_t[t][7] = pte_table(l0_guiecam);
            l1_t[t][9] = pte_table(l0_kbdmmio);
            l1_t[t][10] = pte_table(l0_mousemmio);
        }
        root_pt_t[t][0] = pte_table(l1_m);
        root_pt_t[t][2] = pte_table(l1_t[t]);
    }
}

/* ---- Frame pool (bitmap, 1=free, 0=in-use) ----
 * Frame 0 stays kernel-reserved (its page tables live in kernel RAM, not
 * in the v2 frame region). Frames 1..V2_FRAME_TOTAL-1 map to real physical
 * pages at V2_FRAME_PHYS_BASE + f*4096. */
#define V2_FRAME_TOTAL (V2_FRAMES_MAX)
uint8_t frame_bitmap[V2_FRAME_TOTAL]; /* 1=free, 0=used */

/* Forward declaration for frame_free */
static void frame_zero(int f);

static void frame_pool_init(void)
{
    /* Initialize all frames as free, then reserve frame 0 for kernel */
    for (int i = 0; i < V2_FRAME_TOTAL; i++) /* bound: V2_FRAME_TOTAL */
        frame_bitmap[i] = 1;
    frame_bitmap[0] = 0; /* frame 0: kernel-reserved (page tables in kernel RAM) */
}

static int frame_alloc(void)
{
    /* Scan from frame 1 (skip kernel-reserved frame 0) */
    for (int i = 1; i < V2_FRAME_TOTAL; i++)
    { /* bound: V2_FRAME_TOTAL */
        if (frame_bitmap[i])
        {
            frame_bitmap[i] = 0;
            return i;
        }
    }
    /* Frame pool exhausted: diagnostic message for debugging */
    kputs("[frame_alloc] EXHAUSTED: all ");
    kputdec((unsigned long)(V2_FRAME_TOTAL - 1));
    kputs(" usable frames in use\n");
    return -1;
}

static void frame_free(int f)
{
    if (f >= 0 && f < V2_FRAME_TOTAL)
    {
        /* Double-free protection: fail-closed if already free */
        if (frame_bitmap[f] != 0)
        {
            kputs("[frame_free] WARNING: double-free detected for frame ");
            kputdec((unsigned long)f);
            kputs(" (ignoring)\n");
            return;
        }
        frame_zero(f); /* Security: zero frame data before returning to pool */
        frame_bitmap[f] = 1;
    }
}

/* Zero the 4096-byte real physical page backing frame f. Runs in S-mode
 * with Sv39 on: the write hits VA == PA 0x81000000.. via the S-only
 * l0_frames identity map (l1_t[t][8]); volatile so the memset is never
 * optimized away. */
static void frame_zero(int f)
{
    volatile uint64_t *p = (volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)f * 4096);
    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
        p[i] = 0;
}

/* frame_release is defined beside the caps table below (it needs
 * caps + v2_pte_clear + v2_sfence_all): kernel-authority teardown. */

/* ---- PTE install/clear for the per-thread frame window ----
 * l0_u_t[t][vpn] is thread t's level-0 entry for the frame window at
 * user VA 0x80800000 + vpn*4096 (l1_t[t][4] -> l0_u_t[t], VPN[1]=4).
 * These are kernel-enforcement helpers: they run ONLY after the caps.h
 * model op returned V2_OK, so they never make a PTE state change on a
 * rejected op (fail closed). W^X: X is set only for execute segments;
 * W+X is rejected by the model and dropped defensively here.
 *
 * A 0-rights mapping is skipped (the slot stays 0 = unmapped), the
 * faithful hardware image of "no access": a leaf PTE with V=1 and
 * R=W=X=0 is a reserved table-pointer encoding that at level 0 can
 * never resolve and always faults (carried review finding, T3). */

/* bound: t < V2_CAP_THREADS && vpn < V2_VPN_SLOTS — defensive guard: a
 * miss here means an internal invariant has been broken, fail silently. */
static void v2_pte_install(unsigned long t, unsigned long vpn, unsigned long frame, unsigned long rights)
{
    uint64_t flags;
    if (t >= (unsigned long)V2_CAP_THREADS || vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    if (rights == 0)
        return;      /* R=W=X=0 leaf is the reserved table-pointer encoding */
    rights &= 0x7UL; /* mask: QX (IPC-gate bit) never reaches hardware flags */
    /* W^X: X is installed for execute segments; W+X can never arrive here
     * (rejected by mint/map/ELF validation), and is dropped defensively. */
    flags = PTE_U | PTE_A | ((rights & V2_RIGHT_W) ? (PTE_W | PTE_D) : 0) | ((rights & V2_RIGHT_R) ? PTE_R : 0) |
            (((rights & V2_RIGHT_X) && !(rights & V2_RIGHT_W)) ? PTE_X : 0);
    l0_u_t[t][vpn] = pte_leaf(V2_FRAME_PHYS_BASE + frame * 4096UL, flags);
}

/* bound: t < V2_CAP_THREADS && vpn < V2_VPN_SLOTS (see v2_pte_install) */
static void v2_pte_clear(unsigned long t, unsigned long vpn)
{
    if (t >= (unsigned long)V2_CAP_THREADS || vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    l0_u_t[t][vpn] = 0;
}

static void v2_sfence_all(void)
{
    asm volatile("sfence.vma" ::: "memory");
}

/* ---- Real frame backing copy (Write-Through Mirror) ----
 * WRITE/READ drive the real 4096-byte frame page at PA
 * V2_FRAME_PHYS_BASE + frame*4096, identity-mapped S-only via l0_frames
 * (l1_t[t][8]). fdata stays the caps.h model shadow: v2_write/v2_read
 * still update it first, so host-side coherence holds. These helpers run
 * ONLY after the model op returned V2_OK (fail closed), never cross the
 * pool region (frame < V2_FRAMES_MAX; len <= V2_WORD_BYTES <= 4096),
 * and are byte-accurate through volatile pointers so the copy is never
 * optimized away. */
static void v2_real_write(unsigned long frame, const uint8_t *src, size_t len)
{
    volatile uint8_t *dst;
    if (frame >= (unsigned long)V2_FRAMES_MAX || !src)
        return;
    dst = (volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096UL);
    for (size_t i = 0; i < len; i++) /* bound: V2_WORD_BYTES */
        dst[i] = src[i];
}

static void v2_real_read(unsigned long frame, uint8_t *dst, size_t len)
{
    const volatile uint8_t *src;
    if (frame >= (unsigned long)V2_FRAMES_MAX || !dst)
        return;
    src = (const volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096UL);
    for (size_t i = 0; i < len; i++) /* bound: V2_WORD_BYTES */
        dst[i] = src[i];
}

/* REVOKE capture buffer: one (thread, vpn) pair per possible mapping
 * (V2_CAP_THREADS threads x V2_VPN_SLOTS slots). The scan that fills it
 * and the drain loop that clears from it are both hard-bounded to this
 * size, so it can never overflow. */
typedef struct
{
    unsigned long t;
    unsigned long vpn;
} v2_revoke_pair_t;
static v2_revoke_pair_t v2_revoke_pairs[V2_CAP_THREADS * V2_VPN_SLOTS];

/* PT_ALLOC: allocate a zeroed frame and mint a cap to it. Returns cap slot
 * index in a0, or V2_ERR_OVERFLOW if no frames available. */
int frame_alloc_slot(v2_caps_t *caps, unsigned long tid)
{
    int f = frame_alloc();
    if (f < 0)
        return V2_ERR_OVERFLOW;
    frame_zero(f);
    /* Find an empty cap slot and mint a RW cap to the frame */
    for (int i = 0; i < V2_CAP_SLOTS; i++)
    { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid)
        {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i; /* return cap slot index, not V2_OK */
        }
    }
    frame_free(f);
    return V2_ERR_OVERFLOW;
}

/* Mint a cap to an already-allocated frame for tid (COW-break path:
 * the frame came from raw frame_alloc, not frame_alloc_slot, so no cap
 * names it yet). Returns the slot, or -1 when the table is full (caller
 * fails closed: frame freed, fault becomes park-like). Mirrors the mint
 * half of frame_alloc_slot. */
static int frame_mint_slot(v2_caps_t *caps, unsigned long tid, unsigned long frame)
{
    for (int i = 0; i < V2_CAP_SLOTS; i++)
    { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid)
        {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = frame;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i;
        }
    }
    return -1;
}

/* ---- Threads (round-robin from the currently running TID) ---- */
typedef struct
{
    uint64_t regs[32];
    uint64_t sepc;
    int state; /* 0 = Runnable, 1 = Parked, 2 = Blocked (IPC), 3 = Dead (QDESTROY) */
    /* IPC (mirrors V2_C wk/sendq/recvq): RECV-blocked threads park their
     * validated (ptr, cap) here for later copy-out; queued senders live
     * in eps[ep].sendq (kernel memory, no U pointers retained -> no TOCTOU). */
    uintptr_t ipc_ptr;
    uint64_t ipc_cap;
    uint64_t notify;          /* pending signal bits (OR-accumulate) */
    int wait_kind;            /* V2_WK_* : what this thread is blocked in */
    uint64_t vspace_root_ppn; /* satp value (mode 8 | root PPN); see v2_satp_of */
} uctx_t;

#define T_RUNNABLE 0
#define T_PARKED 1
#define T_DEAD 3 /* distinct from T_BLOCKED since deferred-C: slot-reuse scans key on state alone */
#define T_BLOCKED 2

static uctx_t threads[NTHREADS];
static uint8_t qube_of[NTHREADS];   /* qube label per thread (qube.h) */
static unsigned long qube_next = 2; /* next fresh label; 0/1 taken at boot */
static int cur = 0;
static unsigned long tick __attribute__((unused)) = 0; /* Timer ticks (debug only) */

static v2_ep_t eps[V2_NEP];
_Static_assert(V2_NEP <= V2_CAP_THREADS, "endpoint count rides the thread cap (EP i owned by tid i)");
static v2_caps_t caps;

/* frame_release: kernel-authority teardown of one frame (satisfies the
 * caps.h contract). Revoke every non-root cap + every mapping
 * system-wide, clear any hardware PTE still naming the frame, scrub the
 * page and return it to the pool. No-op on frame 0 / out-of-range /
 * already-free frames (fail-closed: never double-frees, never scrubs a
 * live frame). EVERY free path funnels through here (ELF rollback, EXEC,
 * REVOKE-adjacent teardown) so a freed frame is never reachable via a
 * stale cap, mapping, or PTE: use-after-free across fork+exec would be
 * an isolation break, while a leak would only exhaust the pool.
 * NOTE: intentionally NOT owner-checked: the kernel is the authority
 * (mirrors v2_revoke_frame, not v2_revoke). Ownership audits use
 * v2_frames_next_owned on the frames.h side.
 * ROOTS SURVIVE: v2_revoke_frame preserves thread-0 root caps by design
 * (allocator authority, so the mem_server can re-issue). A root still
 * names a freed+reallocated frame — roots are authority, NOT ownership:
 * thread 0 must never be attacker-controlled, and no path may hand a
 * root cap to an untrusted thread (MINT clears root on every copy).
 * SHARED FRAMES: frame_release is system-wide and must ONLY be called
 * for frames with no other live references (fresh loader pages). For
 * frames that may be COW-shared, use frame_teardown_owned below, which
 * drops one thread's side and frees only when unshared. */
void frame_release(unsigned long frame)
{
    unsigned long u;
    int i;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Clear every hardware PTE still naming this frame BEFORE the model
     * forgets the (thread, vpn) pairs. bound: threads x vpn slots. */
    for (u = 0; u < (unsigned long)NTHREADS; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
                v2_pte_clear(u, caps.vm[u][i].vpn);
        }
    }
    v2_revoke_frame(&caps, frame); /* drops non-root caps + all mappings */
    v2_sfence_all();
    frame_free((int)frame); /* bitmap was 0 (used): zeroes, no double-free warn */
}

/* frame_teardown_owned: drop ONE thread's side of a frame, freeing the
 * frame only when nothing references it anymore. The revoke in
 * frame_release is system-wide: calling it on a COW-shared frame would
 * destroy live siblings' mappings (then free under their stale PTEs).
 * So: drop owner's mappings + PTEs + non-root caps first, then free only
 * if no valid mapping AND no valid non-root cap survives anywhere (a
 * granted-but-unmapped live cap must also block the free, or a later
 * realloc lets it map somebody else's page). Dead co-owners are handled
 * by processing order (each dead side drops in turn; the last one frees).
 * Roots are never cleared here (mirror v2_revoke). No-op on frame 0 /
 * out-of-range / already-free / bad owner (fail closed). */
static void frame_teardown_owned(unsigned long owner, unsigned long frame)
{
    unsigned long u;
    int i, live;
    if (owner >= (unsigned long)NTHREADS)
        return;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Drop owner's mappings + PTEs for this frame. bound: V2_VPN_SLOTS. */
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[owner][i].valid && caps.vm[owner][i].frame == frame)
        {
            v2_pte_clear(owner, caps.vm[owner][i].vpn);
            caps.vm[owner][i].valid = 0;
        }
    }
    /* Drop owner's non-root caps for this frame. bound: V2_CAP_SLOTS. */
    for (i = 0; i < V2_CAP_SLOTS; i++)
    {
        v2_capslot_t *c = &caps.caps[owner][i];
        if (c->valid && !c->root && c->obj == frame)
            c->valid = 0;
    }
    /* Free only when no valid mapping AND no valid non-root cap survives
     * anywhere (roots exempt: allocator authority). bound: threads x slots. */
    live = 0;
    for (u = 0; u < (unsigned long)NTHREADS && !live; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
            {
                live = 1;
                break;
            }
        }
        for (i = 0; i < V2_CAP_SLOTS && !live; i++)
        {
            const v2_capslot_t *c = &caps.caps[u][i];
            if (c->valid && !c->root && c->obj == frame)
                live = 1;
        }
    }
    if (!live)
        frame_release(frame); /* full revoke (stragglers) + scrub + free */
    else
        v2_sfence_all(); /* owner's PTE clears above need fencing */
}

uctx_t *cur_ctx; /* read by trap.S */
uintptr_t trap_stack_top;

/* S4c live input (Task 4): post-halt IRQ traps must not save over a live
 * thread. The trap entry stores into cur_ctx unconditionally, but in halt
 * cur is a stale victim (its regs hold that thread's BLOCKED resume
 * state) — saving halt regs there would destroy it, and the woken thread
 * could never resume. So halt points cur_ctx here (cur itself stays a
 * valid tid: fault paths index threads[cur]). Zero-init BSS, written
 * only by trap entry from halt. */
static uctx_t halt_ctx;

static uint8_t kstack[16384] __attribute__((aligned(16)));
uint8_t *kstack_top = kstack + sizeof(kstack);
static uint8_t trap_stack[4096] __attribute__((aligned(16)));

void user_a_main(void);
void user_b_main(void);
void mem_server_main(void);
void test_cap_thread(void);
void user_stacks_init(void);
extern uintptr_t ustack_a_top, ustack_b_top, ustack_m_top, ustack_cap_top;
extern uintptr_t ustack_qrexec_top, ustack_adminvm_top;
extern uintptr_t ustack_fw_top, ustack_net_top;
extern uintptr_t ustack_vault_top, ustack_crypt_top;
extern uintptr_t ustack_gui_top;
__attribute__((noreturn)) void u_enter(uctx_t *ctx);

static uint64_t u_sp[NTHREADS]; /* stashed pre-MMU: S must not read U pages */

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
/* V2_GET_KBOOT_BUF removed - violates microkernel principles */
#define V2_SEND 3 /* (ep, u_ptr, len): copy IN, block unless waiter; a0 = 0 / -ERR */
#define V2_RECV                                                                                                        \
    4 /* (ep, u_buf, cap): copy OUT, block unless queued; a0 = words, a1 = sender, a2 = sender_qube, a3 = ovf */
#define V2_NOTIFY 5 /* (target, bits): OR-accumulate + wake waiters only; a0 = 0 / -ERR */
#define V2_WAIT 6   /* (): take pending bits (a0) or block; a0 = bits */
#define V2_INVOKE 7
#define V2_INV_MINT 1
#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_PT_ALLOC 6
#define V2_INV_ELF_CHECK 7
#define V2_INV_ELF_MAP 8
#define V2_INV_SPAWN 9
#define V2_INV_FORK 10
#define V2_INV_EXEC 11
#define V2_INV_WRITE 12
#define V2_INV_READ 13
#define V2_INV_FRAME_PA 16 /* (vpn,0,0,0): PA of the frame mapped at vpn; reserved!=0 -> INVALID */

/* ---- User copy (both directions, V2_DESIGN Sec.4): validate-then-copy.
 * S runs with SUM=0; the window is opened only for the bounded copy loop
 * after the range check passed. Raw dereference of a user pointer
 * anywhere else is a bug. SEND needs R (whole U range), RECV needs W
 * (data region: text is RX, enforced by v2_recv_range_ok). */
static void sum_on(void)
{
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 18) : "memory");
}

static void sum_off(void)
{
    asm volatile("csrc sstatus, %0" ::"r"(1UL << 18) : "memory");
}

/* bound: len (caller-checked <= V2_MSG_MAX for IN; <= stored len for OUT) */
static void u_copy_in(uint64_t *kd, uintptr_t us, unsigned long len)
{
    sum_on();
    for (unsigned long i = 0; i < len; i++)
        kd[i] = ((const volatile uint64_t *)us)[i];
    sum_off();
}

/* bound: n (<= stored msg len <= V2_MSG_MAX) */
static void u_copy_out(uintptr_t ud, const uint64_t *ks, unsigned long n)
{
    sum_on();
    for (unsigned long i = 0; i < n; i++)
        ((volatile uint64_t *)ud)[i] = ks[i];
    sum_off();
}

static uint64_t rdtime(void)
{
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
}

static int pick_next(void)
{
    for (int offset = 1; offset <= NTHREADS; offset++)
    { /* bound: NTHREADS */
        int i = (cur + offset) % NTHREADS;
        if (threads[i].state == T_RUNNABLE)
            return i;
    }
    return -1;
}

/* QX grant check: does tid hold any valid cap carrying V2_RIGHT_QX?
 * Bounded scan of the thread's own cap table; fail-closed (bad tid = 0). */
static int qube_has_qx(unsigned long tid)
{
    int s;
    if (tid >= (unsigned long)NTHREADS)
        return 0;
    for (s = 0; s < V2_CAP_SLOTS; s++)
    { /* bound: V2_CAP_SLOTS */
        if (caps.caps[tid][s].valid && (caps.caps[tid][s].rights & V2_RIGHT_QX))
            return 1;
    }
    return 0;
}

/* Sync hardware PTEs with the caps model for thread t: (re)install every
 * valid mapping into l0_u_t[t] and fence once. ELF loads record model
 * mappings without touching PTEs, so every load path calls this before
 * the thread can run. Reinstalling existing entries is idempotent.
 * bound: V2_VPN_SLOTS. */
static void v2_pte_sync(unsigned long t)
{
    int i;
    if (t >= (unsigned long)V2_CAP_THREADS)
        return;
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[t][i].valid)
            v2_pte_install(t, caps.vm[t][i].vpn, caps.vm[t][i].frame, caps.vm[t][i].rights);
    }
    v2_sfence_all();
}

/* satp value (mode 8 / Sv39 + root PPN) for thread t's tables. The
 * uctx_t.vspace_root_ppn field always holds this full satp encoding
 * (not a bare PPN); enter_thread loads it straight into satp. */
static uint64_t v2_satp_of(unsigned long t)
{
    return (8UL << 60) | ((((uintptr_t)root_pt_t[t] >> 12) & 0xFFFFFFFFFFFUL));
}

/* Build child VSpace: wire the child's tables exactly like pagetable_init
 * wires each thread's tables (shared kernel image, shared frame window,
 * shared UART; the child's OWN l0_u for its user window), and return the
 * child's satp value (0 on bad tid). The child's l0_u starts zeroed; the
 * caller installs mappings (v2_pte_sync) afterwards.
 * bound: fixed 512-entry table loops. */
static unsigned long build_child_vspace(unsigned long parent_tid, unsigned long child_tid)
{
    if (child_tid >= (unsigned long)NTHREADS || parent_tid >= (unsigned long)NTHREADS)
        return 0;

    /* Zero child's tables */
    for (int i = 0; i < 512; i++)
        l1_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        l0_u_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        root_pt_t[child_tid][i] = 0;

    /* Mirror pagetable_init's per-thread wiring (same indices, same
     * pte_table encoding): root[0] -> shared UART, root[2] -> own l1. */
    l1_t[child_tid][1] = l1_t[parent_tid][1];          /* l0_k: kernel image */
    l1_t[child_tid][8] = l1_t[parent_tid][8];          /* l0_frames: frame pool */
    l1_t[child_tid][4] = pte_table(l0_u_t[child_tid]); /* own user window */
    root_pt_t[child_tid][0] = pte_table(l1_m);         /* shared UART */
    root_pt_t[child_tid][2] = pte_table(l1_t[child_tid]);

    return v2_satp_of(child_tid);
}

/* COW write-protect: drop PTE_W from every W-mapping's hardware PTE in
 * BOTH parent and child tables (the caps model keeps W rights on both
 * sides and stays the authority). A later store faults (R-only PTE) and
 * the fault handler consults the model to authorize the break. No flag
 * bits are hidden in PTEs or rights, so there is nothing that can collide
 * with legitimate RX execute pages.
 * bound: V2_VPN_SLOTS. */
static void v2_cow_write_protect(unsigned long parent_tid, unsigned long child_tid)
{
    for (int i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[parent_tid][i].valid && (caps.vm[parent_tid][i].rights & V2_RIGHT_W))
        {
            unsigned long vpn = caps.vm[parent_tid][i].vpn;
            if (vpn >= (unsigned long)V2_VPN_SLOTS)
                continue;
            l0_u_t[parent_tid][vpn] &= ~(PTE_W | PTE_D);
            l0_u_t[child_tid][vpn] &= ~(PTE_W | PTE_D);
        }
    }
    v2_sfence_all();
}

static void enter_thread(int id)
{
    uint64_t active_satp;
    uint64_t target_satp = threads[id].vspace_root_ppn;
    cur = id;
    cur_ctx = &threads[id];
    /* Same-thread preemption/yield keeps its translations; flush only on
     * an actual address-space switch. Mapping changes fence at their sites. */
    asm volatile("csrr %0, satp" : "=r"(active_satp));
    if (active_satp != target_satp)
    {
        asm volatile("csrw satp, %0" ::"r"(target_satp) : "memory");
        asm volatile("sfence.vma" ::: "memory");
    }
    u_enter(&threads[id]);
    __builtin_unreachable();
}

/* Terminal park: nothing runnable and nothing can make progress: parked
 * threads never wake; blocked threads wake only via a matching IPC op,
 * which requires a runnable peer. (No timeout yet: Stage 4 time.) */
static void halt_no_runnable(void)
{
    kputs("no runnable left; parking cpu\n");
    /* Park-timer hygiene: the periodic tick is still armed, so a pending
     * timer would wake WFI, print "[tick ...]" spam after the marker, and
     * re-arm (repeating forever). Push stimecmp to the end of time and
     * clear STIE BEFORE the loop so the marker prints exactly once and
     * the CPU truly parks. */
    sbi_set_timer(~0UL);
    asm volatile("csrc sie, %0" ::"r"(1UL << 5) : "memory"); /* clear STIE */
    /* S4c live input (Task 4): traps clear sstatus.SIE on entry, so a halt
     * reached from any trap context parks with SIE=0 — post-park IRQs
     * (input) would pend forever with no trap and no wake. Re-enable SIE
     * so WFI still traps (STIE stays cleared + timer maxed: no tick spam,
     * marker still prints once per entry). Point cur_ctx at the halt
     * save area (never a live thread: entry would clobber its BLOCKED
     * resume state) and sscratch at the trap stack (stale user-sp would
     * fault the entry store under SUM=0). */
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 1) : "memory"); /* SIE */
    cur_ctx = &halt_ctx;
    asm volatile("csrw sscratch, %0" ::"r"(trap_stack_top) : "memory");
    for (;;)
        asm volatile("wfi");
    __builtin_unreachable();
}

/* Trap dispatch. Switch cases call u_enter (noreturn); plain cases return
 * to the trap.S epilogue which restores cur_ctx and srets.
 * TRAP_DEBUG: burst-race evidence log (spec 2026-10-04 §4.1). 1 enables a
 * per-entry (scause, SPP, SIE) print: SPP=1 means the trap was taken from
 * S-mode (nested/idle-wake, H1), SIE=1 means an interrupt window is open
 * in-handler (H2). Default 0: the log floods the transcript at burst rate.
 * Commit policy: evidence runs only; never ship with 1. */
#define TRAP_DEBUG 0
void s_trap_handler(uint64_t cause, uctx_t *ctx)
{
    int is_int = (cause >> 63) & 1;
    uint64_t code = cause & ~(1UL << 63);
    (void)ctx;
#if TRAP_DEBUG
    {
        uint64_t sstatus = 0;
        asm volatile("csrr %0, sstatus" : "=r"(sstatus));
        kputs("[trapdbg] cause=");
        kputhex(cause);
        kputs(" spp=");
        sbi_putchar((char)('0' + ((sstatus >> 8) & 1UL)));
        kputs(" sie=");
        sbi_putchar((char)('0' + ((sstatus >> 1) & 1UL)));
        sbi_putchar('\n');
    }
#endif
    if (is_int)
    {
        if (code == 5)
        { /* S-mode timer */
            sbi_set_timer(rdtime() + TICK_DELTA);
            /* tick++; */ /* Unused - debug only */
            /* Timer preemption: rotate from the current TID so runnable
             * peers receive a turn before this thread is selected again. */
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        if (code == 9)
        { /* S-mode external: virtio IRQ via PLIC claim */
            uint32_t s = *(volatile uint32_t *)PLIC_CLAIM_S;
            uint32_t m = *(volatile uint32_t *)PLIC_CLAIM_M;
            uint32_t src = 0;
            int blk = 0;
            /* Either context may carry the delivery (measured: S does);
             * one marker per trap even if both fired. Net and blk are
             * handled independently so one trap can serve both devices. */
            if (s == net_virtio_irq)
                src = s;
            else if (m == net_virtio_irq)
                src = m;
            if (s == blk_virtio_irq || m == blk_virtio_irq)
                blk = 1;
            if (src != 0)
            {
                threads[6].notify |= NET_IRQ_BIT;
                /* Wake only genuine WAIT waiters (NOTIFY discipline);
                 * unknown sources never wake anyone. */
                if (threads[6].state == T_BLOCKED && threads[6].wait_kind == V2_WK_WAIT)
                {
                    threads[6].state = T_RUNNABLE;
                    threads[6].wait_kind = V2_WK_NONE;
                }
                kputs("NET: irq ok\n");
            }
            if (blk)
            {
                /* No per-IRQ print: a 4K sector op raises up to 8 blk
                 * IRQs, so a print here would flood the transcript; the
                 * ELF's badge check after WAIT is the delivery proof. */
                threads[9].notify |= BLK_IRQ_BIT;
                if (threads[9].state == T_BLOCKED && threads[9].wait_kind == V2_WK_WAIT)
                {
                    threads[9].state = T_RUNNABLE;
                    threads[9].wait_kind = V2_WK_NONE;
                }
            }
            /* S4c VirtIO input IRQs: keyboard and mouse for GUI qube (tid 10).
             * Delivered independently; one trap can serve both if they fire
             * together (QEMU can queue IRQs). Notify bits are or'd so the
             * WAIT badge check detects either source. No per-IRQ print: typing
             * generates high-frequency IRQs that would flood the transcript;
             * the ELF's event poll after WAIT is the delivery proof. */
            int input_irq = 0;
            int input_woke = 0;
            if (s == kbd_virtio_irq || m == kbd_virtio_irq)
            {
                threads[10].notify |= KBD_IRQ_BIT;
                input_irq = 1;
            }
            if (s == mouse_virtio_irq || m == mouse_virtio_irq)
            {
                threads[10].notify |= MOUSE_IRQ_BIT;
                input_irq = 1;
            }
            if (input_irq)
            {
                if (threads[10].state == T_BLOCKED && threads[10].wait_kind == V2_WK_WAIT)
                {
                    threads[10].state = T_RUNNABLE;
                    threads[10].wait_kind = V2_WK_NONE;
                    /* Wake-delivery (NOTIFY precedent): a thread woken
                     * from WAIT resumes past the ecall with stale a0, so
                     * pre-deliver the pending bits as its WAIT return;
                     * pending stays set, so a re-WAIT still collects. */
                    threads[10].regs[10] = threads[10].notify;
                    input_woke = 1;
                }
            }
            if (src == 0 && !blk && !input_irq)
            {
                uint8_t kind = IRQ_KIND_NONE;
                int stub = 0;
                if (irq_lookup(s, 0, &kind, 0) && kind == IRQ_KIND_STUB)
                    stub = 1;
                else if (irq_lookup(m, 0, &kind, 0) && kind == IRQ_KIND_STUB)
                    stub = 1;
                if (!stub)
                    kputs("IRQ: unexpected\n");
            }
            if (s != 0)
                *(volatile uint32_t *)PLIC_CLAIM_S = s;
            if (m != 0)
                *(volatile uint32_t *)PLIC_CLAIM_M = m;
            /* S4c live input (Task 4): a post-halt wake leaves nobody
             * scheduled (halt is not a thread) — run the woken server
             * now (SEND-handoff precedent: enter_thread from handler).
             * Pre-park this only fires for a WAIT-blocked input server
             * and is a no-op for everyone else. */
            if (input_woke)
            {
                int n = pick_next();
                if (n >= 0)
                    enter_thread(n);
            }
            /* Halt-context return guard: if this trap was taken from
             * halt (cur_ctx == &halt_ctx: idle wfi, S-origin), the
             * trap.S epilogue would restore the zeroed halt save area
             * (sepc=0, sp=0) and sret into a fault — then re-trap from
             * S-mode and corrupt the entry swap (burst-race signature).
             * Never return from a halt entry: schedule a woken thread,
             * or re-park (halt_no_runnable re-arms the halt protocol:
             * cur_ctx, sscratch, SIE, timer-max). */
            if (cur_ctx == &halt_ctx)
            {
                int n = pick_next();
                if (n >= 0)
                    enter_thread(n);
                halt_no_runnable();
            }
            return;
        }
        kputs("[trap] unexpected interrupt\n");
        for (;;)
            asm volatile("wfi");
    }
    switch (code)
    {
    case 8: {                                 /* U-mode ecall */
        uint64_t sys = threads[cur].regs[17]; /* a7 */
        if (sys == V2_YIELD)
        {
            threads[cur].sepc += 4;
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_PUTC)
        {
            /* Forward through real SBI (M-mode): U prints via SBI. */
            sbi_putchar((char)threads[cur].regs[10]); /* a0 */
            threads[cur].sepc += 4;
            return;
        }
        else if (sys == V2_PARK)
        {
            /* Blocking primitive (mirrors V2_B UPark): park self.
             * Exit convention: a0==1 means "terminate" (Unix exit()).
             * The slot becomes T_DEAD and reusable by SPAWN/FORK/QCREATE
             * (slot selection scans on state alone); anything else parks.
             * a0 was previously ignored, so this is backward compatible.
             * WITHOUT an exit path every thread lives forever and dynamic
             * creation is dead (first SPAWN always OVERFLOWs). The exiting
             * thread's frames are NOT freed here — the reusing SPAWN (or
             * QDESTROY) reclaims them; see the reuse block in V2_INV_SPAWN.
             * qube_of is left stamped: reuse re-stamps (SPAWN/FORK inherit,
             * QCREATE mints fresh), so no stale-label window. */
            threads[cur].sepc += 4;
            if (threads[cur].regs[10] == 1)
            {
                threads[cur].state = T_DEAD;
                threads[cur].wait_kind = V2_WK_NONE;
                threads[cur].ipc_ptr = 0;
                threads[cur].ipc_cap = 0;
                threads[cur].notify = 0;
                klog("[sched] exited ");
            }
            else
            {
                threads[cur].state = T_PARKED;
                klog("[sched] parked ");
            }
            klog_char('0' + cur);
            klog_char('\n');
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_SEND)
        {
            /* SEND (mirrors V2_C c_send): validate (ep -> range) -> copy
             * IN -> handoff to oldest waiter or queue + block. */
            unsigned long ep = (unsigned long)threads[cur].regs[10];
            uintptr_t up = (uintptr_t)threads[cur].regs[11];
            unsigned long ln = (unsigned long)threads[cur].regs[12];
            uint64_t kb[V2_MSG_MAX];
            unsigned long r;
            threads[cur].sepc += 4;
            if (!v2_ep_ok(ep) || !v2_send_range_ok(up, ln))
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            if (ep >= (unsigned long)NTHREADS)
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
            u_copy_in(kb, up, ln);
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Cross-qube handoff needs QX on the sender. */
            if (e->recv_len > 0)
            {
                unsigned long peek = e->recvq[e->recv_head];
                if (peek >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS, (unsigned long)cur, peek,
                                 qube_has_qx((unsigned long)cur)))
                {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_waiter(e, &r) == V2_OK && r < (unsigned long)NTHREADS)
            {
                unsigned long cap = (unsigned long)threads[r].ipc_cap;
                unsigned long nw = ln < cap ? ln : cap;
                unsigned long ovf = ln > cap ? 1 : 0;
                u_copy_out(threads[r].ipc_ptr, kb, nw);
                threads[r].regs[10] = (uint64_t)nw;
                threads[r].regs[11] = (uint64_t)cur; /* kernel-stamped */
                threads[r].regs[12] = (uint64_t)qube_of[cur];
                threads[r].regs[13] = (uint64_t)ovf;
                threads[r].state = T_RUNNABLE;
                threads[r].wait_kind = V2_WK_NONE;
                threads[cur].regs[10] = (uint64_t)V2_OK;
                klog("[ipc] send tcb=");
                klog_char('0' + cur);
                klog(" -> ");
                klog_char('0' + (char)r);
                klog(" ep=");
                klog_dec(ep);
                klog(" len=");
                klog_dec((unsigned long)nw);
                klog(" ovf=");
                klog_char(ovf ? '1' : '0');
                klog_char('\n');
                enter_thread((int)r);
            }
            if (v2_q_send(e, (unsigned long)cur, kb, ln) != V2_OK)
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
                return;
            }
            /* Flow control: notify sender if queue exceeds threshold */
            if (e->send_len == V2_FLOW_CONTROL_THRESHOLD + 1) {
                /* Just crossed threshold - notify sender */
                threads[cur].notify |= (1UL << 0); /* Use bit 0 for flow control */
            }
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_SEND;
            klog("[ipc] send tcb=");
            klog_char('0' + cur);
            klog(" queued ep=");
            klog_dec(ep);
            klog(" len=");
            klog_dec(ln);
            klog_char('\n');
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_RECV)
        {
            /* RECV (mirrors V2_C c_recv): validate -> deliver oldest
             * queued send (resume sender, stamp sender id, flag
             * truncation) or park (ptr, cap) + block. */
            unsigned long ep = (unsigned long)threads[cur].regs[10];
            uintptr_t up = (uintptr_t)threads[cur].regs[11];
            unsigned long cap = (unsigned long)threads[cur].regs[12];
            v2_slot_t slot;
            threads[cur].sepc += 4;
            if (!v2_ep_ok(ep) || !v2_recv_range_ok(up, cap))
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            if (ep != (unsigned long)cur)
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Queued sends gate at delivery: the destination is
             * unknown at send time, so the sender's qube is derived here
             * via qube_of[slot.sender] (v2_slot_t stays as-is). */
            if (e->send_len > 0)
            {
                unsigned long psrc = e->sendq[e->send_head].sender;
                if (psrc >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS, psrc, (unsigned long)cur, qube_has_qx(psrc)))
                {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_send(e, &slot) == V2_OK)
            {
                unsigned long nw = slot.len < cap ? slot.len : cap;
                unsigned long ovf = slot.len > cap ? 1 : 0;
                unsigned long sq = slot.sender < (unsigned long)NTHREADS ? (unsigned long)qube_of[slot.sender] : 0;
                u_copy_out(up, slot.words, nw);
                threads[cur].regs[10] = (uint64_t)nw;
                threads[cur].regs[11] = (uint64_t)slot.sender;
                threads[cur].regs[12] = (uint64_t)sq;
                threads[cur].regs[13] = (uint64_t)ovf;
                
                /* Flow control: notify sender if queue drops below threshold */
                if (e->send_len == V2_FLOW_CONTROL_THRESHOLD - 1 && slot.sender < (unsigned long)NTHREADS) {
                    threads[slot.sender].notify |= (1UL << 0); /* Use bit 0 for flow control */
                }
                
                if (slot.sender < (unsigned long)NTHREADS)
                {
                    threads[slot.sender].state = T_RUNNABLE;
                    threads[slot.sender].wait_kind = V2_WK_NONE;
                    threads[slot.sender].regs[10] = (uint64_t)V2_OK;
                }
                klog("[ipc] recv tcb=");
                klog_char('0' + cur);
                klog(" from=");
                klog_char('0' + (char)slot.sender);
                klog(" len=");
                klog_dec((unsigned long)nw);
                klog(" ovf=");
                klog_char(ovf ? '1' : '0');
                klog_char('\n');
                return;
            }
            threads[cur].ipc_ptr = up;
            threads[cur].ipc_cap = cap;
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_RECV;
            if (v2_q_wait(e, (unsigned long)cur) != V2_OK)
            {
                /* Practically unreachable at NTHREADS=11 (recvq would
                 * need 11 waiters on one ep); fail closed rather than
                 * lose the waiter. */
                threads[cur].state = T_RUNNABLE;
                threads[cur].wait_kind = V2_WK_NONE;
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
                return;
            }
            klog("[ipc] recv tcb=");
            klog_char('0' + cur);
            klog(" blocked ep=");
            klog_dec(ep);
            klog_char('\n');
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_NOTIFY)
        {
            /* NOTIFY (mirrors V2_C c_notify): OR-accumulate, wake only
             * genuine waiters (wk == WAIT); rendezvous blocks untouched. */
            unsigned long t = (unsigned long)threads[cur].regs[10];
            uint64_t bits = threads[cur].regs[11];
            int woke = 0;
            threads[cur].sepc += 4;
            if (t >= (unsigned long)NTHREADS)
            {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            threads[t].notify |= bits;
            if (threads[t].state == T_BLOCKED && threads[t].wait_kind == V2_WK_WAIT)
            {
                threads[t].state = T_RUNNABLE;
                threads[t].wait_kind = V2_WK_NONE;
                /* Wake-delivery: a thread woken from WAIT resumes past
                 * the ecall with whatever a0 it blocked with (stale).
                 * Pre-deliver the pending bits as its WAIT return
                 * (UABI: a0 = bits); pending is preserved, so a
                 * re-WAIT still collects — level-triggered parties
                 * (admin loop) observe zero behavior change. Without
                 * this, the first woken-WAIT consumer (thread A live
                 * legs, Task 5) sees a stale return and parks. */
                threads[t].regs[10] = threads[t].notify;
                woke = 1;
            }
            threads[cur].regs[10] = (uint64_t)V2_OK;
            klog("[ipc] notify ");
            klog_char('0' + cur);
            klog(" -> ");
            klog_char('0' + (char)t);
            klog(" bits=");
            klog_hex(bits);
            klog(" wake=");
            klog_char(woke ? '1' : '0');
            klog_char('\n');
            return;
        }
        else if (sys == V2_WAIT)
        {
            /* WAIT (mirrors V2_C c_wait): take bits or block. */
            threads[cur].sepc += 4;
            if (threads[cur].notify != 0)
            {
                threads[cur].regs[10] = threads[cur].notify;
                threads[cur].notify = 0;
                threads[cur].wait_kind = V2_WK_NONE;
                klog("[ipc] wait tcb=");
                klog_char('0' + cur);
                klog(" bits=");
                klog_hex(threads[cur].regs[10]);
                klog_char('\n');
                return;
            }
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_WAIT;
            klog("[ipc] wait tcb=");
            klog_char('0' + cur);
            klog(" blocked\n");
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_INVOKE)
        {
            uint64_t op = threads[cur].regs[10]; /* a0 */
            uint64_t a1 = threads[cur].regs[11];
            uint64_t a2 = threads[cur].regs[12];
            uint64_t a3 = threads[cur].regs[13];
            threads[cur].sepc += 4;
            /* long: FRAME_PA returns a full PA (0x81000000+ exceeds int);
             * all other ops assign small ints/negatives, so the epilogue
             * regs[10] = (uint64_t)rc is bit-identical for them. */
            long rc = V2_ERR_INVALID;
            switch (op)
            {
            case V2_INV_MINT:
                rc = v2_mint(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_GRANT:
                rc = v2_grant(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_MAP: {
                /* vpn must index a real l0_u_t[t][vpn] slot: guard before
                 * the model call so rc stays V2_ERR_INVALID for vpn >=
                 * V2_VPN_SLOTS (the model itself does not bound vpn). The
                 * model call stays authoritative: on V2_OK the mapping is
                 * recorded in caps.vm, then we install the real leaf PTE. */
                int m; /* bound: vpn < V2_VPN_SLOTS (checked below) */
                if (a2 < (uint64_t)V2_VPN_SLOTS)
                    rc = v2_map(&caps, (unsigned long)cur, a1, a2);
                if (rc == V2_OK)
                {
                    m = v2_vm_find(&caps, (unsigned long)cur, a2);
                    if (m >= 0)
                    { /* model recorded it: must be findable */
                        v2_pte_install((unsigned long)cur, a2, caps.vm[cur][m].frame, caps.vm[cur][m].rights);
                        v2_sfence_all();
                    }
                }
                break;
            }
            case V2_INV_UNMAP:
                rc = v2_unmap(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK)
                { /* model validated the mapping exists */
                    v2_pte_clear((unsigned long)cur, a1);
                    v2_sfence_all();
                }
                break;
            case V2_INV_REVOKE: {
                /* Revoke drops every mapping to the frame system-wide; the
                 * model clears caps.vm but not hardware PTEs. Capture the
                 * affected (t, vpn) pairs BEFORE the model destroys them,
                 * clear them only if the model approves (fail closed). */
                unsigned long f = 0;
                unsigned long npair = 0;
                int have_f = 0;
                if (a1 < (uint64_t)V2_CAP_SLOTS && caps.caps[cur][a1].valid)
                {
                    f = caps.caps[cur][a1].obj;
                    have_f = 1;
                }
                if (have_f)
                {
                    for (unsigned long u = 0; u < caps.nthreads; u++)
                        /* bound: V2_CAP_THREADS */
                        for (int i = 0; i < V2_VPN_SLOTS; i++)
                        {
                            /* bound: V2_VPN_SLOTS */
                            if (caps.vm[u][i].valid && caps.vm[u][i].frame == f &&
                                npair < (unsigned long)(V2_CAP_THREADS * V2_VPN_SLOTS))
                            {
                                v2_revoke_pairs[npair].t = u;
                                v2_revoke_pairs[npair].vpn = caps.vm[u][i].vpn;
                                npair++;
                            }
                        }
                }
                rc = v2_revoke(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK)
                {
                    for (unsigned long i = 0; i < npair; i++)
                    {
                        /* bound: V2_CAP_THREADS * V2_VPN_SLOTS */
                        if (v2_revoke_pairs[i].t < (unsigned long)NTHREADS)
                            v2_pte_clear(v2_revoke_pairs[i].t, v2_revoke_pairs[i].vpn);
                    }
                    v2_sfence_all();
                }
                break;
            }
            case V2_INV_PT_ALLOC:
                rc = frame_alloc_slot(&caps, (unsigned long)cur);
                break;
            case V2_INV_ELF_CHECK:
                rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
                break;
            case V2_INV_ELF_MAP: {
                /* ELF_MAP (a1=initrd index, a2/a3 reserved):
                 * Load an initrd ELF into the caller's VSpace.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns entry point in rc (a0 on return).
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
                if (rc == V2_OK)
                {
                    v2_pte_sync((unsigned long)cur);
                    rc = (int)entry; /* return entry point as rc */
                }
                break;
            }
            case V2_INV_SPAWN: {
                /* SPAWN (a1=initrd index, a2/a3 reserved):
                 * Create a new thread, allocate its VSpace, load an
                 * initrd ELF into it.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns child tid in rc on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Find a free thread slot (threads[] has NTHREADS entries;
                 * V2_CAP_THREADS is the model's bound, not ours). */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * clear them so the load starts fresh (fail closed). The
                 * child inherits the spawner's qube: without this a slot
                 * recycled by QDESTROY (label cleared to 0) silently lands
                 * the new thread in the ambient qube — or keeps a stale
                 * non-zero label — and the raw gate decides on the wrong
                 * labels. Set before any failure break below. */
                qube_of[child] = qube_of[cur];
                /* Reclaim the previous life's frames first: dropping caps
                 * without freeing leaks the pool into OVERFLOW over spawn
                 * cycles. Snapshot-then-teardown (EXEC precedent): shared
                 * frames are unmapped on this slot's side only, never
                 * freed under a live sibling. */
                {
                    unsigned long reuse_frames[V2_VPN_SLOTS];
                    int reuse_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            reuse_frames[reuse_n++] = caps.vm[child][i].frame;
                    }
                    for (int i = 0; i < reuse_n; i++)
                        frame_teardown_owned((unsigned long)child, reuse_frames[i]);
                }
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i].valid = 0;
                /* Build child's VSpace: copy current thread's page tables for kernel mappings,
                 * allocate fresh l0_u for user mappings */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = 0;
                threads[child].state = T_RUNNABLE;

                /* Load ELF into child's VSpace */
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0)
                {
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    rc = child; /* return child tid */
                }
                else
                {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_FORK: {
                /* FORK (no args):
                 * Create a child thread with a COW copy of the parent's
                 * VSpace and caps. The caps model keeps full rights on
                 * both sides (it stays the authority); only the hardware
                 * PTEs lose W (see v2_cow_write_protect), so the first
                 * store to a shared page faults and the handler breaks
                 * the share for the faulting thread only.
                 * Returns child tid to parent, 0 to child.
                 * FAIL CLOSED: any error -> V2_ERR_INVALID/V2_ERR_OVERFLOW. */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* The child inherits the parent's qube (same reason as
                 * SPAWN above: a recycled T_DEAD slot must not keep a
                 * cleared (0) or stale label). Set before any failure
                 * break below. */
                qube_of[child] = qube_of[cur];
                /* Reclaim the slot's previous life first (same leak as
                 * SPAWN-reuse had: overwriting caps/vm orphans frames).
                 * Shared frames are spared by teardown_owned. */
                {
                    unsigned long fork_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int fork_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            fork_frames[fork_n++] = caps.vm[child][i].frame;
                    }
                    for (int s = 0; s < V2_CAP_SLOTS; s++)
                    {
                        if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                            fork_frames[fork_n++] = caps.caps[child][s].obj;
                    }
                    for (int i = 0; i < fork_n; i++)
                        frame_teardown_owned((unsigned long)child, fork_frames[i]);
                }
                /* Copy parent's caps table. The child must not inherit
                 * allocator authority: root bits stay with the parent. */
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                {
                    caps.caps[child][s] = caps.caps[cur][s];
                    caps.caps[child][s].root = 0;
                }
                /* Copy parent's mappings verbatim (rights intact: the
                 * model is the COW authority, not a rights bit). */
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i] = caps.vm[cur][i];
                /* Build child tables, install the shared mappings, then
                 * write-protect both sides in hardware. */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                {
                    if (caps.vm[child][i].valid)
                        v2_pte_install((unsigned long)child, caps.vm[child][i].vpn, caps.vm[child][i].frame,
                                       caps.vm[child][i].rights);
                }
                v2_cow_write_protect((unsigned long)cur, (unsigned long)child);
                /* Fresh IPC/notify state for the new life. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                threads[child].state = T_RUNNABLE;
                threads[child].regs[2] = u_sp[child];
                threads[child].sepc = threads[cur].sepc + 4; /* return after ecall */
                /* Copy registers (parent's a0..a7, sp, etc.) */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = threads[cur].regs[r];
                threads[child].regs[10] = 0;   /* child returns 0 in a0 */
                threads[child].regs[11] = cur; /* child gets parent tid in a1 */
                rc = child;                    /* parent returns child tid in a0 */
                break;
            }
            case V2_INV_EXEC: {
                /* EXEC (a1=initrd index, a2/a3 reserved):
                 * Replace current thread's image: unmap all user mappings, free frames,
                 * clear user caps, load a new initrd ELF.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns 0 on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Tear down all user mappings and reclaim their frames.
                 * Snapshot first (teardown mutates later aliasing slots).
                 * Shared-with-sibling frames (COW fork child) are unmapped
                 * on our side only and NOT freed — a system-wide release
                 * here would destroy the sibling's live mappings. */
                unsigned long exec_frames[V2_VPN_SLOTS];
                int exec_nframes = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                {
                    if (caps.vm[cur][i].valid)
                        exec_frames[exec_nframes++] = caps.vm[cur][i].frame;
                }
                for (int i = 0; i < exec_nframes; i++)
                    frame_teardown_owned((unsigned long)cur, exec_frames[i]);
                v2_sfence_all();
                /* Clear user caps (slots 0..V2_CAP_SLOTS-1, keep root caps) */
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                {
                    if (!caps.caps[cur][s].root)
                        caps.caps[cur][s].valid = 0;
                }
                /* Load new ELF into current VSpace */
                {
                    uint64_t entry = 0, brk = 0;
                    rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
                    if (rc == V2_OK && entry != 0)
                    {
                        v2_pte_sync((unsigned long)cur);
                        threads[cur].regs[2] = u_sp[cur];
                        threads[cur].sepc = entry;
                        /* Reset registers to clean state */
                        for (int r = 0; r < 32; r++)
                            threads[cur].regs[r] = 0;
                        threads[cur].regs[2] = u_sp[cur];
                        rc = 0; /* return 0 on success */
                    }
                    else if (rc == V2_OK)
                    {
                        rc = V2_ERR_INVALID;
                    }
                }
                break;
            }
            case V2_INV_WRITE: {
                /* WRITE (a1=vpn, a2=u_src): one 8-byte word. Range-check +
                 * copy the user word into a kernel temp, run the model
                 * write on fdata (rights gate + shadow), then — only on
                 * V2_OK — store that same word into the real frame PA
                 * (Write-Through Mirror: real memory and fdata stay
                 * identical). FAIL CLOSED: real memory is never touched
                 * on model error. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_send_range_ok((uintptr_t)a2, 1))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                u_copy_in(kbuf, (uintptr_t)a2, 1);
                rc = v2_write(&caps, (unsigned long)cur, a1, kbuf[0]);
                if (rc == V2_OK)
                {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m >= 0) /* model wrote it: mapping must be findable */
                        v2_real_write(caps.vm[cur][m].frame, (const uint8_t *)kbuf, V2_WORD_BYTES);
                }
                break;
            }
            case V2_INV_READ: {
                /* READ (a1=vpn, a2=u_dst): mirror of WRITE. Run the model
                 * read first (rights gate + shadow), then — only on V2_OK —
                 * load the real 8-byte word from the frame PA into a kernel
                 * temp and copy it out to the validated user destination.
                 * FAIL CLOSED: the user destination is touched only on
                 * model + range success. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_recv_range_ok((uintptr_t)a2, 1))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_read(&caps, (unsigned long)cur, a1, &kbuf[0]);
                if (rc == V2_OK)
                {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m < 0)
                    { /* model read succeeded: must be findable */
                        rc = V2_ERR_INVALID;
                        break;
                    }
                    v2_real_read(caps.vm[cur][m].frame, (uint8_t *)kbuf, V2_WORD_BYTES);
                    u_copy_out((uintptr_t)a2, kbuf, 1);
                }
                break;
            }
            case V2_INV_QCREATE: {
                /* QCREATE (a1=initrd index, a2/a3 reserved=0): new thread
                 * in a fresh qube label. Mirrors SPAWN's slot setup, then
                 * stamps the fresh label. FAIL CLOSED: any validation
                 * error -> V2_ERR_INVALID/OVERFLOW with no partial state. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry = 0, brk = 0;
                int child = -1;
                if (!(a2 == 0 && a3 == 0))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (qube_next >= (unsigned long)V2_QUBES_MAX)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * reclaim frames first (same leak SPAWN-reuse had), then
                 * clear so the load starts fresh (fail closed). Shared
                 * frames are spared by teardown_owned. */
                {
                    unsigned long qc_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int qc_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            qc_frames[qc_n++] = caps.vm[child][i].frame;
                    }
                    for (int s = 0; s < V2_CAP_SLOTS; s++)
                    {
                        if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                            qc_frames[qc_n++] = caps.caps[child][s].obj;
                    }
                    for (int i = 0; i < qc_n; i++)
                        frame_teardown_owned((unsigned long)child, qc_frames[i]);
                }
                for (int s = 0; s < V2_CAP_SLOTS; s++) /* bound: V2_CAP_SLOTS */
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++) /* bound: V2_VPN_SLOTS */
                    caps.vm[child][i].valid = 0;
                {
                    unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                    if (!child_root)
                    {
                        rc = V2_ERR_OVERFLOW;
                        break;
                    }
                    threads[child].vspace_root_ppn = child_root;
                }
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++) /* bound: 32 */
                    threads[child].regs[r] = 0;
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0)
                {
                    threads[child].state = T_RUNNABLE;
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    qube_of[child] = (uint8_t)qube_next++;
                    kputs("QUB: qube");
                    kputdec((unsigned long)qube_of[child]);
                    kputs(" up\n");
                    rc = V2_OK;
                }
                else
                {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_QDESTROY: {
                /* QDESTROY (a1=label, a2/a3 reserved=0): park every thread
                 * in the qube, drop their queued IPC, revoke-drain their
                 * caps + clear hardware PTEs, reclaim unshared frames.
                 * Label 0 (base system) can never be destroyed. FAIL CLOSED.
                 * POLICY (deliberate, not an oversight):
                 * - No caller-authority check: V2 has no privilege levels.
                 *   QCREATE/QDESTROY/SPAWN are all unprivileged by design;
                 *   isolation comes from qube labels on the data plane,
                 *   management is cooperative. Revisit if threat model grows.
                 * - Live BLOCKED survivors stay blocked: a live SENDer queued
                 *   for a dead waiter (or RECV waiter for dead senders) keeps
                 *   T_BLOCKED with its queue entry intact. Waking them with
                 *   an error would break open-ended rendezvous (a future
                 *   peer may still arrive), so park-forever is the policy
                 *   until timeouts/cancellation land. */
                unsigned long label = (unsigned long)a1;
                int found = 0;
                if (!(a2 == 0 && a3 == 0))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (label == 0 || label >= (unsigned long)V2_QUBES_MAX)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    if (qube_of[t] == (uint8_t)label)
                        found = 1;
                }
                if (!found)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Drop queued IPC entries owned by the qube (compact both
                 * queues in place; other qubes' entries are preserved). */
                {
                    for (int e = 0; e < V2_NEP; e++)
                    { /* bound: V2_NEP (11) */
                        v2_ep_t *ep = &eps[e];
                        int w = 0;
                        for (int i = 0; i < ep->send_len; i++)
                        { /* bound: V2_IPC_Q */
                            int idx = (ep->send_head + i) % V2_IPC_Q;
                            unsigned long s = ep->sendq[idx].sender;
                            if (s < (unsigned long)NTHREADS && qube_of[s] == (uint8_t)label)
                                continue; /* drop: sender dies below */
                            if (w != i)
                            {
                                int dst = (ep->send_head + w) % V2_IPC_Q;
                                ep->sendq[dst] = ep->sendq[idx];
                            }
                            w++;
                        }
                        ep->send_len = w;
                        w = 0;
                        for (int i = 0; i < ep->recv_len; i++)
                        { /* bound: V2_IPC_Q */
                            int idx = (ep->recv_head + i) % V2_IPC_Q;
                            unsigned long tid = ep->recvq[idx];
                            if (tid < (unsigned long)NTHREADS && qube_of[tid] == (uint8_t)label)
                                continue; /* drop: waiter dies below */
                            if (w != i)
                            {
                                int dst = (ep->recv_head + w) % V2_IPC_Q;
                                ep->recvq[dst] = ep->recvq[idx];
                            }
                            w++;
                        }
                        ep->recv_len = w;
                    }
                }
                /* Tear down each dying thread via frame_teardown_owned:
                 * SHARED frames (COW sibling in a live qube) lose only the
                 * dead side — the old code called v2_revoke per slot,
                 * which is system-wide and destroyed live siblings'
                 * mappings before the live-check could see them (then freed
                 * under their stale PTEs). UNSHARED frames are fully
                 * revoked + scrubbed + freed (no QCREATE/QDESTROY pool
                 * leak). Dead co-owners resolve by processing order. */
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    unsigned long dying_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int dying_n = 0;
                    int s;
                    if (qube_of[t] != (uint8_t)label)
                        continue;
                    /* Snapshot every frame this thread names (mappings +
                     * caps; teardown is idempotent so no dedupe needed). */
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    { /* bound: V2_VPN_SLOTS */
                        if (caps.vm[t][i].valid)
                            dying_frames[dying_n++] = caps.vm[t][i].frame;
                    }
                    for (s = 0; s < V2_CAP_SLOTS; s++)
                    { /* bound: V2_CAP_SLOTS */
                        if (caps.caps[t][s].valid && !caps.caps[t][s].root)
                            dying_frames[dying_n++] = caps.caps[t][s].obj;
                    }
                    for (int i = 0; i < dying_n; i++)
                        frame_teardown_owned((unsigned long)t, dying_frames[i]);
                    for (int vpn = 0; vpn < V2_VPN_SLOTS; vpn++) /* bound: V2_VPN_SLOTS */
                        v2_pte_clear((unsigned long)t, (unsigned long)vpn);
                    threads[t].state = T_DEAD;
                    threads[t].wait_kind = V2_WK_NONE;
                    threads[t].ipc_ptr = 0;
                    threads[t].ipc_cap = 0;
                    threads[t].notify = 0;
                    qube_of[t] = 0;
                }
                v2_sfence_all();
                kputs("QUB: qube");
                kputdec(label);
                kputs(" dead\n");
                rc = V2_OK;
                break;
            }
            case V2_INV_FRAME_PA: {
                /* FRAME_PA (a1=vpn, a2/a3 reserved=0): return the physical
                 * address of the frame mapped at vpn in the caller's VSpace.
                 * Pure address math (V2_FRAME_PHYS_BASE + frame*4096): no
                 * state change, no copy. Miss or nonzero reserved -> INVALID. */
                int m; /* bound: V2_VPN_SLOTS (v2_vm_find scan) */
                if (a2 != 0 || a3 != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                m = v2_vm_find(&caps, (unsigned long)cur, a1);
                if (m < 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = (long)(V2_FRAME_PHYS_BASE + caps.vm[cur][m].frame * 4096UL);
                break;
            }
            default:
                rc = V2_ERR_INVALID;
                break;
            }
            threads[cur].regs[10] = (uint64_t)rc;
            klog("[invoke] tcb=");
            klog_char('0' + cur);
            klog(" op=");
            klog_dec(op);
            klog(" rc=");
            klog_dec((unsigned long)rc);
            klog_char('\n');
            return;
        }
        threads[cur].sepc += 4;
        return;
    }
    case 9: /* S-mode ecall: our own SBI calls return via M, never here. */
        threads[cur].sepc += 4;
        return;
    case 13:   /* Load page fault */
    case 15: { /* Store page fault: may be a COW break */
        uint64_t fault_addr;
        asm volatile("csrr %0, stval" : "=r"(fault_addr));
        /* COW break, S-mode authority rule: the caps model is the ONLY
         * authority. A store fault inside the frame window whose model
         * mapping still carries W is a COW share (hardware PTE is R-only
         * after v2_cow_write_protect); anything else — RX execute page,
         * R-only data, unmapped address — falls through to containment.
         * PTE bits are never trusted as COW flags, so this cannot
         * misclassify a legitimate RX page. */
        if (code == 15 && fault_addr >= V2_U_END && fault_addr < V2_U_END + (uint64_t)V2_VPN_SLOTS * 4096UL)
        {
            unsigned long t = (unsigned long)cur;
            unsigned long vpn = (unsigned long)((fault_addr - V2_U_END) >> 12);
            int m = v2_vm_find(&caps, t, vpn);
            if (m >= 0 && (caps.vm[t][m].rights & V2_RIGHT_W))
            {
                unsigned long old_frame = caps.vm[t][m].frame;
                int new_frame = frame_alloc();
                if (new_frame >= 0 && old_frame != 0 && old_frame < (unsigned long)V2_FRAMES_MAX)
                {
                    /* Copy via physical addresses (S-mode, SUM=0: the
                     * faulting U VA is NOT dereferenced). */
                    volatile uint64_t *dst = (volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)new_frame * 4096);
                    const volatile uint64_t *src =
                        (const volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)old_frame * 4096);
                    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
                        dst[i] = src[i];
                    /* The word-model shadow follows the break so later
                     * WRITE/READ word ops stay coherent with real memory. */
                    caps.fdata[new_frame] = caps.fdata[old_frame];
                    /* The new frame needs a cap: WITHOUT it v2_find_wcap
                     * fails and every later word op on this vpn returns
                     * INVALID (and fork children inherit the capless
                     * mapping). Table-full fails closed like exhaustion:
                     * give the frame back, fall through to park. */
                    if (frame_mint_slot(&caps, t, (unsigned long)new_frame) < 0)
                    {
                        /* Table full: give the frame back and fall through
                         * to default below (park offender). No break here:
                         * break would exit the switch past default and
                         * resume the faulting store into a fault loop. */
                        frame_free(new_frame);
                    }
                    else
                    {
                        caps.vm[t][m].frame = (unsigned long)new_frame;
                        /* Reinstall THIS thread's PTE only (the other sharer
                         * keeps its R-only PTE until it faults in turn). */
                        v2_pte_install(t, vpn, (unsigned long)new_frame, caps.vm[t][m].rights);
                        v2_sfence_all();
                        return; /* Resume the faulting store */
                    }
                }
            }
            /* Not a COW share (or no frame left) - fall through to default */
        }
    } /* close case 15 block: execution falls through to default */
    default: { /* fault: park the offender, keep the rest running */
        klog("[fault] tcb=");
        klog_char('0' + cur);
        klog(" cause=");
        klog_hex(code);
        klog(" epc=");
        klog_hex(threads[cur].sepc);
        klog("\n parked; others continue\n");
        threads[cur].state = T_PARKED;
        int n = pick_next();
        if (n < 0)
            halt_no_runnable();
        enter_thread(n);
    }
    }
}

void kboot(void)
{
    irq_init();
    if (v2_dev_leaves_mapped_count() <= 0)
        kputs("DEVLEAF: none live\n");
    kputs("v2 stage2: S-mode entry (OpenSBI)\n");
    for (int e = 0; e < V2_NEP; e++) /* bound: V2_NEP (11) */
        v2_ep_init(&eps[e]);
    frame_pool_init();
    qube_init(qube_of, (unsigned long)NTHREADS); /* all threads start in qube 0 */
    initrd_init();
    v2_caps_init(&caps, NTHREADS);
    kputs("[caps] init: thread 0 has root caps to all frames\n");
    user_stacks_init(); /* pre-MMU: U stacks need no SUM games */
    u_sp[0] = (uint64_t)ustack_a_top;
    u_sp[1] = (uint64_t)ustack_b_top;
    u_sp[2] = (uint64_t)ustack_m_top;
    u_sp[3] = (uint64_t)ustack_qrexec_top; /* 8KB: policy frame (user.c) */
    u_sp[4] = (uint64_t)ustack_adminvm_top;
    u_sp[5] = (uint64_t)ustack_fw_top;
    u_sp[6] = (uint64_t)ustack_net_top;
    u_sp[7] = (uint64_t)ustack_cap_top;
    u_sp[8] = (uint64_t)ustack_vault_top;
    u_sp[9] = (uint64_t)ustack_crypt_top; /* Task 4 spawn reads it */
    u_sp[10] = (uint64_t)ustack_gui_top;  /* S4a spawn reads it */
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt_t[0];
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" ::"r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" ::"r"((1UL << 18) | (1UL << 19)) : "memory");
    /* Activate kernel framebuffer console: GUI_LFB_PHYS is now reachable via
     * the S-only l1_m[385] megapage (mapped pre-MMU in pagetable_init).
     * Every subsequent kputs() call mirrors to both UART and the display. */
    fbcon_clear();
    kputs("MoonlightOS v2 kernel\n");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");
    /* Phase-2 NIC discovery: transports live at VIRTIO0_BASE+i*0x1000
     * (S-only UART megapage, pre-MMU-mapped). QEMU attaches backends
     * last-first, so scan for the modern net device instead of assuming
     * transport 0. A found IRQ gets priority 1 + its enable bit with
     * threshold 0 (any priority-1 IRQ fires); none found leaves
     * net_virtio_irq at 0xFFFFFFFF (handler matches nothing, fail closed). */
    for (int ti = 0; ti < VIRTIO_NTRANSPORTS; ti++)
    { /* bound: 8 */
        volatile uint32_t *tr = (volatile uint32_t *)(VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        if (virtio_ident_match(tr[0], tr[1], tr[2], (uint32_t)VIRTIO_DEV_NET))
        {
            net_virtio_irq = (uint32_t)(1 + ti);
            break;
        }
    }
    if (net_virtio_irq != VIRTIO_IRQ_NOT_FOUND)
    {
        irq_plic_enable(net_virtio_irq);
        (void)irq_bind(net_virtio_irq, (uint8_t)T_NET, IRQ_KIND_NET, NET_IRQ_BIT);
    }
    /* FDE block discovery: same scan-then-bind as the NIC above, keyed on
     * the virtio-blk device id (never a hardcoded transport: QEMU
     * attaches backends last-first). A found IRQ gets priority 1 + its
     * enable bit with threshold 0 (any priority-1 IRQ fires); none found
     * leaves blk_virtio_irq at 0xFFFFFFFF (handler matches nothing, the
     * ELF parks fail-closed at probe, never spins). */
    for (int ti = 0; ti < VIRTIO_NTRANSPORTS; ti++)
    { /* bound: 8 */
        volatile uint32_t *tr = (volatile uint32_t *)(VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        if (virtio_ident_match(tr[0], tr[1], tr[2], (uint32_t)VIRTIO_DEV_BLK))
        {
            blk_virtio_irq = (uint32_t)(1 + ti);
            break;
        }
    }
    if (blk_virtio_irq != VIRTIO_IRQ_NOT_FOUND)
    {
        irq_plic_enable(blk_virtio_irq);
        (void)irq_bind(blk_virtio_irq, (uint8_t)T_CRYPTBLK, IRQ_KIND_BLK, BLK_IRQ_BIT);
    }
    /* S4c VirtIO input discovery: mouse (first dev-18) and keyboard
     * (second dev-18). VirtIO-input spec uses device ID 18 for all input
     * devices; the subtype (config.subsel) distinguishes keyboard=1 vs
     * mouse=2 vs tablet=3. QEMU virtio-keyboard-device and
     * virtio-mouse-device both present as dev-18. Simplified discovery:
     * QEMU attaches backends last-first, so in scan order the LAST-listed
     * input device comes first: with `-device ...keyboard... -device
     * ...mouse...` the mouse is the first dev-18 and the keyboard the
     * second (Task 4 measured: keypresses claim 1+ti of the SECOND
     * dev-18; a config.subsel read would remove the order assumption).
     * IRQ = 1+ti as usual; none found leaves kbd/mouse_virtio_irq at
     * 0xFFFFFFFF (handler matches nothing, fail-closed: no input but
     * boot proceeds). */
    {
        int input_found = 0;
        for (int ti = 0; ti < VIRTIO_NTRANSPORTS && input_found < 2; ti++)
        { /* bound: 8 */
            volatile uint32_t *tr = (volatile uint32_t *)(VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
            if (virtio_ident_match(tr[0], tr[1], tr[2], (uint32_t)VIRTIO_DEV_INPUT))
            {
                if (mouse_virtio_irq == VIRTIO_IRQ_NOT_FOUND)
                {
                    mouse_virtio_irq = (uint32_t)(1 + ti);
                    input_found++;
                }
                else if (kbd_virtio_irq == VIRTIO_IRQ_NOT_FOUND)
                {
                    kbd_virtio_irq = (uint32_t)(1 + ti);
                    input_found++;
                }
            }
        }
    }
    if (kbd_virtio_irq != VIRTIO_IRQ_NOT_FOUND)
    {
        irq_plic_enable(kbd_virtio_irq);
        (void)irq_bind(kbd_virtio_irq, (uint8_t)T_GUI, IRQ_KIND_INPUT, KBD_IRQ_BIT);
        kputs("INPUT: kbd found\n");
    }
    if (mouse_virtio_irq != VIRTIO_IRQ_NOT_FOUND)
    {
        irq_plic_enable(mouse_virtio_irq);
        (void)irq_bind(mouse_virtio_irq, (uint8_t)T_GUI, IRQ_KIND_INPUT, MOUSE_IRQ_BIT);
        kputs("INPUT: mouse found\n");
    }
    /* Known-but-unowned virtio devices: record a STUB route so a stray
     * IRQ completes without waking anyone. Do not PLIC-enable and do not
     * map a U-leaf — no owner tid until V2_CAP_THREADS grows. */
    {
        int ti;
        for (ti = 0; ti < VIRTIO_NTRANSPORTS; ti++)
        { /* bound: 8 */
            volatile uint32_t *tr = (volatile uint32_t *)(VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
            uint32_t irq = virtio_ident_irq((unsigned)ti);
            uint32_t id;
            if (!virtio_ident_present(tr[0], tr[1]))
                continue;
            id = tr[2];
            if (!v2_virtio_dev_known(id) || v2_virtio_owner_tid(id) >= 0)
                continue;
            (void)irq_bind(irq, 0, IRQ_KIND_STUB, 0);
        }
    }
    /* S4a GUI PCI bind: QEMU leaves PCI BARs unprogrammed (no firmware
     * enumeration under OpenSBI), so the kernel assigns BAR0 before the
     * ELF's bind probe runs. Mechanics only (raw dword offsets, no PCI
     * structs, no pixel math): scan bus 0 for the bochs-display function,
     * size BAR0 with the standard mask probe (save / write all-ones /
     * read / restore), assign GUI_LFB_PHYS when the size is sane, enable
     * MEM + bus-master in the command register. The l0_guifb U-leaf
     * (wired pre-MMU in pagetable_init) maps this same GUI_LFB_PHYS, so
     * leaf and BAR agree by construction. S-mode ECAM access runs through
     * the l1_m[384] leaf (post-MMU, SUM=0: no U pages touched).
     * Fail-closed: no match / absurd size leaves BAR0 untouched and the
     * ELF parks marker-free (no "GUI: up", smoke gate misses it). */
    {
        int gui_found = 0;
        for (int dev = 0; dev < 32 && !gui_found; dev++)
        { /* bound: 32 (bus-0 devices) */
            for (int fn = 0; fn < 8 && !gui_found; fn++)
            { /* bound: 8 (functions) */
                volatile uint32_t *cfg =
                    (volatile uint32_t *)(GUI_ECAM_PHYS + (unsigned long)dev * 2048UL + (unsigned long)fn * 256UL);
                uint32_t id = cfg[0]; /* offset 0x00: vendor/device */
                uint32_t b0, b1, mask, size, cmd;
                uint32_t b2, mask2, size2;
                volatile uint16_t *vbe;
                if (id == 0xFFFFFFFFu)
                    continue; /* empty slot: no device */
                if ((id & 0xFFFFu) != GUI_PCI_VEN)
                    continue;
                if ((id >> 16) != GUI_PCI_DEV)
                    continue;
                b0 = cfg[4]; /* offset 0x10: BAR0 (LFB base) */
                if ((b0 & 0x1u) != 0u)
                    continue; /* I/O BAR: not an MMIO framebuffer */
                if (((b0 >> 1) & 0x3u) == 0x2u)
                    continue; /* 64-bit BAR type: outside the uint32 model */
                b1 = cfg[5];  /* offset 0x14: BAR0 high word */
                if (b1 != 0u)
                    continue; /* nonzero high word: outside the uint32 model */
                cfg[4] = 0xFFFFFFFFu;
                mask = cfg[4];
                cfg[4] = b0; /* restore before any sizing decision */
                size = (~(mask & 0xFFFFFFF0u)) + 1u;
                if (size == 0u || size > GUI_LFB_MAX || size < GUI_FB_MIN)
                    continue; /* absurd/small size: leave BAR0 untouched (must cover 800x600x32) */
                if ((size & (size - 1u)) != 0u)
                    continue; /* BAR sizes are powers of two */
                if ((GUI_LFB_PHYS & (size - 1u)) != 0u)
                    continue; /* assigned base must be aligned to size */
                b2 = cfg[6];  /* offset 0x18: Bochs VBE register BAR */
                if ((b2 & 0x1u) != 0u || ((b2 >> 1) & 0x3u) == 0x2u)
                    continue; /* only a 32-bit MMIO BAR is supported */
                cfg[6] = 0xFFFFFFFFu;
                mask2 = cfg[6];
                cfg[6] = b2;
                size2 = (~(mask2 & 0xFFFFFFF0u)) + 1u;
                if (size2 < 0x1000u || size2 > 0x200000u || (size2 & (size2 - 1u)) != 0u ||
                    (GUI_VBE_PHYS & (size2 - 1u)) != 0u)
                    continue; /* BAR2 must fit its mapped 2MB window */
                cfg[4] = (uint32_t)GUI_LFB_PHYS;
                cfg[6] = (uint32_t)GUI_VBE_PHYS;
                cmd = cfg[1];        /* offset 0x04: command register */
                cfg[1] = cmd | 0x6u; /* MEM space + bus master */
                vbe = (volatile uint16_t *)(GUI_VBE_VA + GUI_VBE_BAR_OFFSET);
                vbe[4] = 0; /* disable before changing mode */
                vbe[1] = 800;
                vbe[2] = 600;
                vbe[3] = 32;
                vbe[4] = 0x41; /* enabled + linear framebuffer */
                asm volatile("fence iorw,iorw" ::: "memory");
                gui_found = 1;
                kputs("GUI: bochs 800x600x32\n");
            }
        }
        if (!gui_found)
            kputs("GUI: no bochs; leaves wired, server will park\n");
    }

    for (int i = 0; i < NTHREADS; i++)
    { /* bound: NTHREADS */
        for (int r = 0; r < 32; r++)
            threads[i].regs[r] = 0;
        threads[i].sepc = 0;
        threads[i].state = T_PARKED;
        threads[i].ipc_ptr = 0;
        threads[i].ipc_cap = 0;
        threads[i].notify = 0;
        threads[i].wait_kind = V2_WK_NONE;
        threads[i].vspace_root_ppn = (8UL << 60) | (((uintptr_t)root_pt_t[i] >> 12) & 0xFFFFFFFFFFFUL);
    }
    /* A valid trap target must exist BEFORE interrupts are enabled: a stale
     * firmware timer can pend and fire at SIE-enable, while cur_ctx is still
     * NULL -> entry faults loading ctx -> fault loop. Parked + mapped is
     * always safe (handler prints and halts). */
    cur = 0;
    cur_ctx = &threads[0];
    trap_stack_top = (uintptr_t)(trap_stack + sizeof(trap_stack));
    asm volatile("csrw sscratch, %0" ::"r"(trap_stack_top) : "memory");
    /* Arm our timer BEFORE enabling: reprograms stimecmp, de-asserting any
     * stale firmware pending bit. */
    sbi_set_timer(rdtime() + TICK_DELTA);
    /* Phase-2 NIC PLIC setup lives in the discovery block above (priority
     * + enable for the found IRQ, threshold 0 on the claimed context). */
    asm volatile("csrs sie, %0" ::"r"((1UL << 5) | (1UL << 9)) : "memory"); /* STIE + SEIE */
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 1) : "memory");            /* SIE */

    /* Thread 0: parked (was test thread A, not needed for production microkernel) */
    threads[0].regs[2] = u_sp[0];
    threads[0].sepc = (uint64_t)user_a_main;
    threads[0].state = T_RUNNABLE;
    threads[1].regs[2] = u_sp[1];
    threads[1].sepc = (uint64_t)user_b_main;
    threads[1].state = T_RUNNABLE;
    threads[2].regs[2] = u_sp[2];
    threads[2].sepc = (uint64_t)mem_server_main;
    threads[2].state = T_RUNNABLE;
    /* Thread 7 is the scratch slot: it keeps the in-kernel capability demo
     * (CAP/OK/DU/NP markers) that thread 3 ran before the S2 brokers took
     * threads 3-4 (and the S3 packet plane takes threads 5-6). */
    threads[7].regs[2] = u_sp[7];
    threads[7].sepc = (uint64_t)test_cap_thread;
    threads[7].state = T_RUNNABLE;
    /* Stage 3: boot the userspace mem_server from initrd index 0 into
     * thread 2's VSpace. On success thread 2 enters the ELF image and
     * prints MEM-SRV from U-mode; on failure it keeps the in-kernel
     * stub above, and the missing MEM-SRV marker fails the smoke loudly. */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(0, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 2, &entry, &brk) == V2_OK && entry != 0)
        {
            v2_pte_sync(2);
            threads[2].sepc = entry;
            kputs("[spawn] mem_server ELF ok\n");
        }
        else
        {
            kputs("[spawn] mem_server ELF FAIL; stub\n");
        }
    }
    /* Production Microkernel Services (Stage 3):
     * Load services in the correct order:
     *   - Shell (moonsh) from index 1 into thread 1
     *   - Console service from index 3 into thread 3
     *   - TTY service from index 4 into thread 4
     *   - GUI service from index 10 into thread 10
     * Index 2 is unused (was adminvm). Indices 5-9 are reserved for future services. */

    /* Shell: moonsh from initrd index 1 into thread 1 */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(1, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 1, &entry, &brk) == V2_OK && entry != 0)
        {
            v2_pte_sync(1);
            threads[1].regs[2] = u_sp[1];
            threads[1].sepc = entry;
            threads[1].state = T_RUNNABLE;
            kputs("[spawn] shell ELF ok\n");
        }
        else
        {
            kputs("[spawn] shell ELF FAIL; parked\n");
        }
    }

    /* Console service from initrd index 3 into thread 3 */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(3, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 3, &entry, &brk) == V2_OK && entry != 0)
        {
            v2_pte_sync(3);
            threads[3].regs[2] = u_sp[3];
            threads[3].sepc = entry;
            threads[3].state = T_RUNNABLE;
            kputs("[spawn] console ELF ok\n");
        }
        else
        {
            kputs("[spawn] console ELF FAIL; parked\n");
        }
    }

    /* TTY service from initrd index 4 into thread 4 */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(4, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 4, &entry, &brk) == V2_OK && entry != 0)
        {
            v2_pte_sync(4);
            threads[4].regs[2] = u_sp[4];
            threads[4].sepc = entry;
            threads[4].state = T_RUNNABLE;
            kputs("[spawn] tty ELF ok\n");
        }
        else
        {
            kputs("[spawn] tty ELF FAIL; parked\n");
        }
    }

    /* Threads 5-9: reserved for future services (deferred), remain parked */

    /* GUI service from initrd index 10 into thread 10 */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(10, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 10, &entry, &brk) == V2_OK && entry != 0)
        {
            v2_pte_sync(10);
            threads[10].regs[2] = u_sp[10];
            threads[10].sepc = entry;
            threads[10].state = T_RUNNABLE;
            kputs("[spawn] gui ELF ok\n");
        }
        else
        {
            kputs("[spawn] gui ELF FAIL; parked\n");
        }
    }

    /* Production microkernel boot complete: all services loaded */

    /* Qube assignments (production microkernel - all services in qube 0):
     * For the production microkernel, all services run in qube 0 (system qube)
     * to allow free IPC communication without qube security barriers.
     * - Thread 0: kernel (qube 0)
     * - Thread 1: shell/moonsh (qube 0)
     * - Thread 2: mem_server (qube 0)
     * - Thread 3: console (qube 0)
     * - Thread 4: tty (qube 0)
     * - Threads 5-9: reserved (parked)
     * - Thread 10: gui (qube 0)
     */
    qube_of[1] = 0;  /* Shell */
    qube_of[2] = 0;  /* mem_server */
    qube_of[3] = 0;  /* console */
    qube_of[4] = 0;  /* tty */
    qube_of[10] = 0; /* gui */
    qube_next = 1;   /* Next available qube for future isolation */

    kputs("Services: mem+console+tty+gui up\n");

    /* Disable verbose runtime logging now that boot is complete */
    boot_log_enabled = 0;

    /* Boot complete - enter scheduler at thread 2 (mem_server) */
    kputs("v2: entering U-mode\n");
    enter_thread(2);
}
