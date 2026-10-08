/* device.c - virtio device discovery + GUI PCI bind (SRP: device management).
 *
 * Split out of kboot.c (SOLID Sprint 1): net/blk/input transport
 * discovery, STUB routes for unowned devices, and the S4a GUI PCI BAR
 * assignment live here. kboot() keeps orchestration only. */
#include <stdint.h>

#include "blk_hal.h"
#include "dev.h"
#include "dev_leaves.h"
#include "irq.h"
#include "kinternal.h"
#include "platform.h"
#include "services.h"
#include "virtio_ident.h"

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
uint32_t net_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
uint32_t blk_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
/* S4c input IRQs: Task 3 discovery fills these (first dev-18 = mouse, second
 * = kbd); the Task 3 handler + PLIC setup are the real consumers. */
uint32_t kbd_virtio_irq = VIRTIO_IRQ_NOT_FOUND;
uint32_t mouse_virtio_irq = VIRTIO_IRQ_NOT_FOUND;

/* Phase-2 NIC U-leaf: single page table mapping the 8 VIRTIO0 transport
 * pages for tid 6 only (wired at l1_t[6][5]; every other l1_t[t][5] stays
 * 0, asserted at boot). Zero-initialized except [0..7]: the transport
 * pages, RW, never X. */
uint64_t l0_netmmio[512] __attribute__((aligned(4096)));
/* FDE block U-leaf: same single-leaf pattern as the NIC, for tid 9 only
 * (wired at l1_t[9][6] = UVA 0x80C00000; every other l1_t[t][6] stays 0,
 * asserted at boot). The 8 transport pages, RW, never X. */
uint64_t l0_blkmmio[512] __attribute__((aligned(4096)));
/* RNG U-leaf: same single-leaf pattern as NET/BLK, for tid 8 only
 * (wired at l1_t[8][5] = UVA 0x80A00000; reuses the NET leaf INDEX in
 * tid-8-only tables — every thread owns its l1_t, so no alias with
 * l1_t[6][5]. The 8 transport pages, RW, never X. Exclusivity asserted
 * at boot ("RNGMMIO"), with the NETMMIO gate tolerating tid 8. */
uint64_t l0_rngmmio[512] __attribute__((aligned(4096)));
/* S4c Input U-leaves: keyboard and mouse MMIO transports for tid 10 only.
 * kbd at l1_t[10][9] = UVA 0x81200000 (VPN[1] index 9, fresh: GUI uses 6/7).
 * mouse at l1_t[10][10] = UVA 0x81400000 (VPN[1] index 10, fresh). Each maps
 * 8 virtio-mmio transport pages (0x10001000+i*0x1000), RW never X. Presence
 * + exclusivity asserted at boot (extended "GUIMMIO" gate below). */
uint64_t l0_kbdmmio[512] __attribute__((aligned(4096)));
uint64_t l0_mousemmio[512] __attribute__((aligned(4096)));
uint64_t l0_guifb[512] __attribute__((aligned(4096)));
uint64_t l0_guiecam[512] __attribute__((aligned(4096)));

/* device_init: virtio transport discovery + IRQ routing + GUI PCI bind.
 * Runs after MMU-on in kboot(); fail-closed on every discovery miss. */
void device_init(void)
{
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
/* FDE block discovery via HAL (blk_hal.h): scan VIRTIO0 transports for
 * a modern virtio-blk device (identity-read only: magic/version/dev-id).
 * The HAL fills blk_transport with the IRQ; blk_hal_bind_irq enables the
 * PLIC line and registers the route to T_CRYPTBLK (tid 9) with BLK_IRQ_BIT.
 * On no device: blk_virtio_irq stays VIRTIO_IRQ_NOT_FOUND → handler matches
 * nothing, the ELF parks fail-closed at probe (never spins).
 *
 * Microkernel HAL contract: the kernel reads only identity registers here.
 * Queue setup, feature negotiation, DMA, and sector I/O are ALL in the
 * userspace cryptblk compartment (tid 9 via BLK_HAL_MMIO_UVA leaf). */
{
    blk_hal_transport_t blk_transport;
    if (blk_hal_discover(&blk_transport))
    {
        blk_virtio_irq = blk_transport.irq;
        if (blk_hal_bind_irq(blk_virtio_irq))
        {
            kputs("BLK-HAL: virtio-blk found, IRQ bound to T_CRYPTBLK\n");
        }
        else
        {
            kputs("BLK-HAL: IRQ bind failed; block driver will park\n");
        }
    }
    else
    {
        kputs("BLK-HAL: no virtio-blk transport found (diskless boot)\n");
    }
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
}
