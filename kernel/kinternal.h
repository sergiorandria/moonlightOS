/* kernel/kinternal.h - shared kernel internals (SOLID Sprint 1 split).
 *
 * Single home for the cross-module glue that used to be file-static in
 * kboot.c: thread/scheduler state, device tables, PTE helpers, syscall
 * numbers, and the console/copy primitives. Included by kboot.c,
 * device.c, sched.c, syscall.c, and elf_loader.c. NOT the user ABI
 * (userspace/abi) and NOT the verified model (caps.h / ipc.h / qube.h). */
#ifndef V2_KINTERNAL_H
#define V2_KINTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "caps.h"
#include "ipc.h"
#include "qube.h"

/* ---- Threads: 0 A, 1 B, 2 mem_server, 3 console, 4 tty, 5-6 (reserved),
 * 7 CAP stub, 8 vault, 9 cryptblk, 10 gui. NTHREADS == V2_CAP_THREADS ==
 * V2_NEP: the table is full; the next thread forces a V2_CAP_THREADS
 * bump + proof replay (S4b). */
#define NTHREADS 11 /* bound for all thread loops (<= V2_CAP_THREADS) */

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

/* V2_INV_WRITE/READ move exactly one 64-bit word: the caps.h model is
 * word-per-frame (fdata[f] = val), so the real store/load mirrors exactly
 * what the model records and fdata can never diverge from the
 * real frame (Write-Through Mirror). This bounds every new copy loop and
 * keeps every frame access within the pool region (frame <
 * V2_FRAMES_MAX, max offset (V2_FRAMES_MAX-1)*4096 + V2_WORD_BYTES). */
#define V2_WORD_BYTES 8 /* bound: bytes per WRITE/READ invoke (one word) */

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */

/* ---- User ABI: syscall numbers (a7) and INVOKE sub-ops (a0).
 * Single home (moved out of syscall.c, Sprint 1b); userspace mirrors
 * these numbers in its own ABI headers. */
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

/* Pool window: 32x4K, inside the l0_frames identity map (512 pages). */
#define V2_FRAME_TOTAL (V2_FRAMES_MAX)

/* S4c input MMIO user addresses (VPN[1] 9/10, tid 10 only). */
#define KBD_MMIO_UVA 0x81200000UL
#define MOUSE_MMIO_UVA 0x81400000UL

/* S4a GUI geometry + kernel-assigned PCI addresses (leaf + BAR agree). */
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

typedef struct
{
    unsigned long t;
    unsigned long vpn;
} v2_revoke_pair_t;

/* ---- Shared globals (defined in the owning module) ---- */
/* sched.c */
extern uctx_t threads[NTHREADS];
extern uint8_t qube_of[NTHREADS];
extern unsigned long qube_next;
extern int cur;
extern unsigned long tick;
extern v2_ep_t eps[V2_NEP];
extern v2_caps_t caps;
extern uctx_t *cur_ctx; /* read by trap.S */
extern uintptr_t trap_stack_top; /* read by trap.S */
extern uctx_t halt_ctx;
extern uint8_t kstack[16384];
extern uint8_t *kstack_top; /* read by start.S */
extern uint8_t trap_stack[4096];
extern uint64_t u_sp[NTHREADS];
/* device.c */
extern uint32_t net_virtio_irq;
extern uint32_t blk_virtio_irq;
extern uint32_t kbd_virtio_irq;
extern uint32_t mouse_virtio_irq;
extern uint64_t l0_netmmio[512];
extern uint64_t l0_blkmmio[512];
extern uint64_t l0_rngmmio[512];
extern uint64_t l0_kbdmmio[512];
extern uint64_t l0_mousemmio[512];
extern uint64_t l0_guifb[512];
extern uint64_t l0_guiecam[512];
/* kboot.c */
extern uint64_t root_pt_t[V2_CAP_THREADS][512];
extern uint64_t l1_t[V2_CAP_THREADS][512];
extern uint64_t l0_u_t[V2_CAP_THREADS][512];
extern uint64_t l1_m[512];
extern uint64_t l0_k[512];
extern uint64_t l0_frames[512];
extern uint8_t frame_bitmap[V2_FRAME_TOTAL];
extern v2_revoke_pair_t v2_revoke_pairs[V2_CAP_THREADS * V2_VPN_SLOTS];
extern int boot_log_enabled;

/* ---- Console + timer (kboot.c) ---- */
void sbi_putchar(char c);
void sbi_set_timer(uint64_t stime);
void kputs(const char *s);
void kputhex(uint64_t v);
void kputdec(unsigned long v);
void klog(const char *s);
void klog_char(char c);
void klog_dec(unsigned long v);
void klog_hex(uint64_t v);
uint64_t rdtime(void);

/* ---- VM helpers (kboot.c) ---- */
void pagetable_init(void);
void frame_pool_init(void);
void sched_tick(void);
void irq_trap(void);
void sys_yield(void);
void sys_putc(void);
void sys_park(void);
void sys_send(void);
void sys_recv(void);
void sys_notify(void);
void sys_wait(void);
int syscall_cap_handles(uint64_t op);
long syscall_cap_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3);
int syscall_mem_handles(uint64_t op);
long syscall_mem_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3);
int syscall_proc_handles(uint64_t op);
long syscall_proc_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3);
int syscall_qube_handles(uint64_t op);
long syscall_qube_invoke(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3);
int frame_alloc(void);
void frame_free(int f);
void v2_pte_install(unsigned long t, unsigned long vpn,
                      unsigned long frame, unsigned long rights);
void v2_pte_clear(unsigned long t, unsigned long vpn);
void v2_sfence_all(void);
void v2_real_write(unsigned long frame, const uint8_t *src, size_t len);
void v2_real_read(unsigned long frame, uint8_t *dst, size_t len);
int frame_mint_slot(v2_caps_t *caps, unsigned long tid, unsigned long frame);
void frame_teardown_owned(unsigned long owner, unsigned long frame);

/* ---- Scheduler (sched.c) ---- */
int pick_next(void);
void enter_thread(int id);
void halt_no_runnable(void);
__attribute__((noreturn)) void u_enter(uctx_t *ctx); /* trap.S */

/* ---- Syscalls (syscall.c) ---- */
void u_copy_in(uint64_t *kd, uintptr_t us, unsigned long len);
void u_copy_out(uintptr_t ud, const uint64_t *ks, unsigned long n);
int qube_has_qx(unsigned long tid);
void v2_pte_sync(unsigned long t);
uint64_t v2_satp_of(unsigned long t);
unsigned long build_child_vspace(unsigned long parent_tid,
                                 unsigned long child_tid);
void v2_cow_write_protect(unsigned long parent_tid,
                           unsigned long child_tid);
void s_trap_handler(uint64_t cause, uctx_t *ctx);

/* ---- Device discovery (device.c) ---- */
void device_init(void);

/* ---- ELF spawning (elf_loader.c) ---- */
int elf_loader_spawn(const char *name, unsigned index, unsigned tid,
                     const char *fail);

/* ---- Boot orchestrator (kboot.c) ---- */
void kboot(void);

#endif /* V2_KINTERNAL_H */
