/* kernel/kernel.h - internal interfaces shared by the kernel's translation
 * units. NOT the user ABI (that is the V2_* numbers below, mirrored by the
 * userspace headers) and NOT the verified model (caps.h / ipc.h / qube.h /
 * elf.h / frames.h are pure C and host-tested; this header is the glue that
 * binds them to hardware).
 *
 * Module map (each file owns one concern; nothing here is a service):
 *   console.c  SBI console + timer, kpanic
 *   vm.c       Sv39 tables, frame pool, user copy windows, PTE <-> model sync
 *   sched.c    thread table, scheduler, kernel object state
 *   irq.c      PLIC + virtio IRQ -> notify routing (no device logic)
 *   syscall.c  IPC / capability / thread-lifecycle syscalls
 *   trap.c     trap dispatch, COW fault authorization, S-mode panic
 *   kboot.c    boot sequence: tables, ELF spawns, labels, boot grants
 *   selftest.c in-kernel model transcript (V2_SELFTEST builds only)
 *
 * Microkernel invariant: this kernel contains mechanism only (address
 * spaces, capabilities, IPC, scheduling, IRQ->notification). Policy lives
 * in qrexec/adminvm/firewall, drivers in net/cryptblk/gui/vault. */
#ifndef V2_KERNEL_H
#define V2_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#include "caps.h"
#include "frames.h"
#include "ipc.h"
#include "platform.h"
#include "qube.h"

#define NORETURN __attribute__((noreturn))

/* ---- Threads ------------------------------------------------------------
 * 0 A, 1 B, 2 mem_server, 3 qrexec, 4 AdminVM, 5 firewall, 6 net,
 * 7 CAP stub, 8 vault, 9 cryptblk, 10 gui. NTHREADS == V2_CAP_THREADS ==
 * V2_NEP: the table is full; the next thread forces a bump + proof replay. */
#define NTHREADS 11
_Static_assert(NTHREADS <= V2_CAP_THREADS, "NTHREADS must fit the caps model + page tables");
_Static_assert(V2_NEP <= V2_CAP_THREADS, "endpoint count rides the thread cap (EP i owned by tid i)");
_Static_assert(V2_NEP <= NTHREADS, "every endpoint needs an owning thread slot");

#define T_RUNNABLE 0
#define T_PARKED 1
#define T_BLOCKED 2 /* in IPC (see wait_kind) */
#define T_DEAD 3    /* qube destroyed / spawn failed; slot is reusable */

/* Saved context. Layout is shared with trap.S: regs[i] at i*8 (x0 slot
 * unused), sepc at 256. */
typedef struct {
    uint64_t regs[32];
    uint64_t sepc;
    int state;
    uintptr_t ipc_ptr;  /* RECV-blocked: validated user buffer (copy-out target) */
    uint64_t ipc_cap;   /* RECV-blocked: buffer capacity in words */
    uint64_t notify;    /* pending signal bits (OR-accumulate) */
    int wait_kind;      /* V2_WK_*: what a T_BLOCKED thread is blocked in */
    uint64_t satp;      /* full satp encoding (mode 8 | root PPN) */
} uctx_t;
_Static_assert(offsetof(uctx_t, sepc) == 256, "trap.S assumes sepc at offset 256");

#define REG_SP 2
#define REG_A0 10
#define REG_A1 11
#define REG_A2 12
#define REG_A3 13
#define REG_A7 17

/* ---- User ABI: syscall numbers (a7) and INVOKE sub-ops (a0) ---- */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3   /* (ep, u_ptr, len): copy IN; handoff to waiter or queue + block */
#define V2_RECV 4   /* (ep, u_buf, cap): copy OUT; a0=words a1=sender a2=sender qube a3=ovf */
#define V2_NOTIFY 5 /* (target, bits): OR-accumulate, wake WAIT-ers only */
#define V2_WAIT 6   /* (): take pending bits or block; a0 = bits */
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
/* 14 QCREATE / 15 QDESTROY: qube.h */
#define V2_INV_FRAME_PA 16

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */

/* ---- Kernel stacks. One struct so the layout is exactly
 * [guard|kstack|guard|trap|guard|panic|guard]: the guard pages are
 * unmapped in vm_init(), so an overflow faults into kpanic instead of
 * silently corrupting the neighbouring stack or kernel data. ---- */
#define KSTACK_SIZE 16384
#define TRAP_STACK_SIZE 8192
#define PANIC_STACK_SIZE 4096
struct kstacks {
    uint8_t guard0[4096];
    uint8_t kstack[KSTACK_SIZE];
    uint8_t guard1[4096];
    uint8_t trap[TRAP_STACK_SIZE];
    uint8_t guard2[4096];
    uint8_t panic[PANIC_STACK_SIZE];
    uint8_t guard3[4096];
} __attribute__((aligned(4096)));
extern struct kstacks kstk;

/* ---- console.c ---- */
void kputc(char c);
void kputs(const char *s);
void kputhex(uint64_t v);
void kputdec(unsigned long v);
void kputsdec(long v);
void sbi_set_timer(uint64_t stime);
uint64_t rdtime(void);
NORETURN void kpanic(const char *msg);

/* ---- sched.c: thread table + global kernel object state ---- */
extern uctx_t threads[NTHREADS];
extern uctx_t halt_ctx;          /* trap-entry save area while the CPU is parked */
extern uctx_t *cur_ctx;          /* read by trap.S */
extern uintptr_t trap_stack_top; /* read by trap.S */
extern uintptr_t panic_stack_top;
extern uint8_t *kstack_top;      /* read by start.S */
extern int cur;
extern unsigned long tick;
extern v2_caps_t kcaps;
extern v2_ep_t eps[V2_NEP];
extern uint8_t qube_of[NTHREADS];

int pick_next(void);
NORETURN void enter_thread(int id);
NORETURN void schedule(void);        /* pick_next() or halt */
NORETURN void halt_no_runnable(void);
void thread_wake_wait(unsigned t);   /* WAIT -> runnable, bits pre-delivered in a0 */
void sched_tick(void);               /* timer interrupt body (noreturn in practice) */
int thread_find_dead(void);          /* first T_DEAD slot, or -1 */
NORETURN void u_enter(uctx_t *ctx);  /* trap.S */

/* ---- vm.c ---- */
enum vm_leaf { VM_LEAF_VIRTIO, VM_LEAF_GUIFB, VM_LEAF_GUIECAM };

void vm_init(void);                              /* pre-MMU: build shared tables */
void vm_wire_thread(unsigned t, int with_utext); /* (re)build t's tables, no device leaves */
void vm_dev_leaf(unsigned t, unsigned l1_idx, enum vm_leaf which);
uint64_t vm_dev_leaf_pte(unsigned t, unsigned l1_idx); /* l1 entry, for the exclusivity gates */
uint64_t vm_satp(unsigned t);
void vm_sfence(void);
void vm_pte_install(unsigned long t, unsigned long vpn, unsigned long frame, unsigned long rights);
void vm_pte_clear(unsigned long t, unsigned long vpn);
void vm_pte_sync(unsigned long t);               /* model mappings -> hardware PTEs */
void vm_cow_write_protect(unsigned parent, unsigned child);

/* Private U stacks: each thread maps only its own stack window. */
void vm_ustack_register(unsigned t, uintptr_t base, uintptr_t size); /* boot, pre-MMU */
uintptr_t vm_ustack_top(unsigned t);
uintptr_t vm_ustack_size(unsigned t);
void vm_ustack_scrub(unsigned t);
int vm_ustack_fork(unsigned parent, unsigned child, uint64_t *child_sp, uint64_t parent_sp);

/* User copies go through a kernel-only alias of the U data region, never
 * through U pages: SUM stays 0 for the kernel's whole life. A buffer must
 * lie entirely inside the *caller's own* stack window (uaccess_ok), which
 * also keeps one thread from steering a copy into another's memory. */
int uaccess_ok(unsigned t, uintptr_t ua, unsigned long nwords);
void u_copy_in(uint64_t *kd, unsigned t, uintptr_t ua, unsigned long n);
void u_copy_out(unsigned t, uintptr_t ua, const uint64_t *ks, unsigned long n);

/* Frame pool (owner-tracked: frames.h) */
void frame_pool_init(void);
int frame_alloc(unsigned long owner);
void frame_reclaim(unsigned long f);                 /* revoke everywhere, scrub, free */
void frame_reclaim_owned(unsigned long tid);
void frame_drop_by(unsigned long t, unsigned long f); /* t no longer uses f (exec) */
int frame_mapped_by_other(unsigned long t, unsigned long f);
void vm_revoke_frame(unsigned long f);               /* kernel-authority revoke + PTE clear */
unsigned long frame_free_count(void);
void frame_real_write(unsigned long frame, const uint64_t *src);
void frame_real_read(unsigned long frame, uint64_t *dst);
void frame_copy(unsigned long dst, unsigned long src);

/* ---- irq.c ---- */
void irq_init(void);
int irq_dispatch(void); /* claims, routes, completes; returns 1 if a thread woke */

/* ---- syscall.c ---- */
void syscall_dispatch(void);
int qube_has_qx(unsigned long tid);
/* Tear down every thread of a qube (shared with the selftest-free boot
 * path): returns V2_OK / V2_ERR_*. */
long qube_destroy(unsigned long label);

/* ---- trap.c ---- */
void s_trap_handler(uint64_t cause, uctx_t *ctx);

/* ---- selftest.c (V2_SELFTEST) ---- */
void selftest_run(void);

#endif /* V2_KERNEL_H */
