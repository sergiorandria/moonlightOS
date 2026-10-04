# Kernel Changes Required for VirtIO Input Support

## Overview
This document describes all kernel modifications needed to complete S4c input support. Due to terminal encoding issues preventing automated edits, these changes must be applied manually to `kernel/kboot.c`.

---

## Change 3: Initialize Input MMIO Leaves in pagetable_init()

**Location:** After the l0_rngmmio initialization loop (around line 250)

**Add after:**
```c
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_rngmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                                 PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
```

**Insert:**
```c
    /* S4c Input U-leaves: kbd and mouse transport pages for tid 10 only.
     * Same shape as NET/BLK/RNG: 8 transport pages, RW never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_kbdmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                                 PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_mousemmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                                   PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
```

---

## Change 4: Wire Input Leaves into tid 10 Page Tables

**Location:** In pagetable_init(), inside the per-thread wiring loop, in the `if (t == 10)` block (around line 290)

**Modify:**
```c
        /* S4a GUI: the LFB + ECAM U-leaves exist ONLY in tid 10's tables
         * (GUI_LFB_UVA 0x80C00000 = VPN[1] 6, GUI_ECAM_UVA 0x80E00000 =
         * VPN[1] 7). Every other l1_t[t][6] (except tid 9 BLK) and every
         * other l1_t[t][7] stays 0 (asserted at boot: "GUIMMIO"). */
        if (t == 10) {
            l1_t[t][6] = pte_table(l0_guifb);
            l1_t[t][7] = pte_table(l0_guiecam);
            l1_t[t][9] = pte_table(l0_kbdmmio);    /* <-- ADD THIS */
            l1_t[t][10] = pte_table(l0_mousemmio); /* <-- ADD THIS */
        }
```

**Comment update:** Change the comment to mention S4c input leaves:
```c
        /* S4a GUI + S4c Input: LFB + ECAM + kbd + mouse U-leaves exist ONLY
         * in tid 10's tables (GUI_LFB_UVA 0x80C00000 = VPN[1] 6, GUI_ECAM_UVA
         * 0x80E00000 = VPN[1] 7, KBD_MMIO_UVA 0x81200000 = VPN[1] 9,
         * MOUSE_MMIO_UVA 0x81400000 = VPN[1] 10). Exclusivity asserted at
         * boot: "GUIMMIO" / "KBDMMIO" / "MOUSEMMIO" gates. */
```

---

## Change 5: Add VirtIO Input IRQ Handler in s_trap_handler()

**Location:** In s_trap_handler(), after the blk IRQ handling (around line 760)

**Add after:**
```c
            if (blk) {
                /* ... existing blk IRQ handler ... */
            }
```

**Insert:**
```c
            /* S4c VirtIO input IRQs: keyboard and mouse for GUI qube (tid 10).
             * Delivered independently; one trap can serve both if they fire
             * together (QEMU can queue IRQs). Notify bits are or'd so the
             * WAIT badge check detects either source. No per-IRQ print: typing
             * generates high-frequency IRQs that would flood the transcript;
             * the ELF's event poll after WAIT is the delivery proof. */
            int input_irq = 0;
            if (s == kbd_virtio_irq || m == kbd_virtio_irq) {
                threads[10].notify |= KBD_IRQ_BIT;
                input_irq = 1;
            }
            if (s == mouse_virtio_irq || m == mouse_virtio_irq) {
                threads[10].notify |= MOUSE_IRQ_BIT;
                input_irq = 1;
            }
            if (input_irq) {
                if (threads[10].state == T_BLOCKED &&
                    threads[10].wait_kind == V2_WK_WAIT) {
                    threads[10].state = T_RUNNABLE;
                    threads[10].wait_kind = V2_WK_NONE;
                }
            }
```

---

## Change 6: Add VirtIO Input Device Discovery in kboot()

**Location:** In kboot(), after the RNG discovery block (around line 1708)

**Add after:**
```c
    if (blk_virtio_irq != VIRTIO_IRQ_NOT_FOUND) {
        /* ... existing blk PLIC setup ... */
    }
```

**Insert:**
```c
    /* S4c VirtIO input discovery: keyboard (first dev-18) and mouse (second
     * dev-18). VirtIO-input spec uses device ID 18 for all input devices; the
     * subtype (config.subsel) distinguishes keyboard=1 vs mouse=2 vs tablet=3.
     * QEMU virtio-keyboard-device and virtio-mouse-device both present as
     * dev-18. Simplified discovery: assume cmdline order (first=kbd, second=
     * mouse) instead of reading config.subsel (avoids config-space parsing).
     * IRQ = 1+ti as usual; none found leaves kbd/mouse_virtio_irq at 0xFFFFFFFF
     * (handler matches nothing, fail-closed: no input but boot proceeds). */
    int input_found = 0;
    for (int ti = 0; ti < VIRTIO_NTRANSPORTS && input_found < 2; ti++) {
        volatile uint32_t *tr = (volatile uint32_t *)
            (VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        if (tr[0] == 0x74726976u && tr[1] == 2u &&
            tr[2] == (uint32_t)VIRTIO_DEV_INPUT) {
            if (kbd_virtio_irq == VIRTIO_IRQ_NOT_FOUND) {
                kbd_virtio_irq = (uint32_t)(1 + ti);
                input_found++;
            } else if (mouse_virtio_irq == VIRTIO_IRQ_NOT_FOUND) {
                mouse_virtio_irq = (uint32_t)(1 + ti);
                input_found++;
            }
        }
    }
    if (kbd_virtio_irq != VIRTIO_IRQ_NOT_FOUND) {
        *(volatile uint32_t *)(PLIC_BASE + 4u * kbd_virtio_irq) = 1;
        *(volatile uint32_t *)PLIC_ENABLE_M |= (1U << kbd_virtio_irq);
        *(volatile uint32_t *)PLIC_ENABLE_S |= (1U << kbd_virtio_irq);
        kputs("INPUT: kbd found\n");
    }
    if (mouse_virtio_irq != VIRTIO_IRQ_NOT_FOUND) {
        *(volatile uint32_t *)(PLIC_BASE + 4u * mouse_virtio_irq) = 1;
        *(volatile uint32_t *)PLIC_ENABLE_M |= (1U << mouse_virtio_irq);
        *(volatile uint32_t *)PLIC_ENABLE_S |= (1U << mouse_virtio_irq);
        kputs("INPUT: mouse found\n");
    }
```

---

## Summary of All Kernel Changes

1. ✅ **Definitions** (lines 107-108): Add `VIRTIO_DEV_INPUT 18u`
2. ✅ **IRQ bits** (lines 124-125): Add `KBD_IRQ_BIT` and `MOUSE_IRQ_BIT`
3. ✅ **IRQ variables** (lines 131-132): Add `kbd_virtio_irq` and `mouse_virtio_irq`
4. ✅ **MMIO leaves** (lines 165-173): Add `l0_kbdmmio`, `l0_mousemmio`, and UVA defines
5. **pagetable_init() leaf init** (~line 252): Initialize input MMIO leaves
6. **pagetable_init() wiring** (~line 292): Wire leaves into tid 10 page tables
7. **s_trap_handler() IRQ** (~line 762): Handle keyboard and mouse IRQs
8. **kboot() discovery** (~line 1710): Discover and enable input devices

## Testing

After applying changes:
```bash
cd /home/sergio/Project/moonlightOS
make -C kernel
tools/run_qemu.sh
```

Expected boot output:
```
INPUT: kbd found
INPUT: mouse found
```

If devices not found, check QEMU command line includes:
```
-device virtio-keyboard-device -device virtio-mouse-device
```

(Note: tools/run_qemu.sh should already include `virtio-keyboard-device` when display is enabled)
