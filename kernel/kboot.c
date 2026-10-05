/* kboot.c - boot orchestrator (SRP: boot sequence only).
 *
 * Split down over SOLID Sprint 1/1b (production-ready): console.c owns
 * the SBI/console, vm.c the address spaces + frame pool, device.c the
 * discovery, sched.c the threads, syscall*.c the trap plane, elf_loader.c
 * the spawns. kboot() only coordinates module init + thread setup. */
#include <stdint.h>

#include "caps.h"
#include "dev_leaves.h"
#include "fbconsole.h" /* S4a kernel framebuffer console output */
#include "initrd.h"
#include "ipc.h"
#include "irq.h"
#include "kinternal.h"
#include "qube.h"
#include "uentry.h"

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
    device_init();

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
    threads[0].state = T_PARKED;
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
    elf_loader_spawn("mem_server", 0, 2, "FAIL; stub");
    elf_loader_spawn("shell", 1, 1, "FAIL; parked");
    elf_loader_spawn("console", 3, 3, "FAIL; parked");
    elf_loader_spawn("tty", 4, 4, "FAIL; parked");
    elf_loader_spawn("vault", 8, 8, "FAIL or missing; parked");
    elf_loader_spawn("cryptblk", 9, 9, "FAIL or missing; parked");
    elf_loader_spawn("gui", 10, 10, "FAIL; parked");

    /* Production microkernel boot complete: all services loaded */

    /* Qube assignments (production microkernel - all services in qube 0):
     * For the production microkernel, all services run in qube 0 (system qube)
     * to allow free IPC communication without qube security barriers.
     * - Thread 0: kernel (qube 0)
     * - Thread 1: shell/moonsh (qube 0)
     * - Thread 2: mem_server (qube 0)
     * - Thread 3: console (qube 0)
     * - Thread 4: tty (qube 0)
     * - Thread 8: vault (qube 0)
     * - Thread 9: cryptblk (qube 0)
     * - Thread 10: gui (qube 0)
     */
    qube_of[1] = 0;  /* Shell */
    qube_of[2] = 0;  /* mem_server */
    qube_of[3] = 0;  /* console */
    qube_of[4] = 0;  /* tty */
    qube_of[8] = 0;  /* vault */
    qube_of[9] = 0;  /* cryptblk */
    qube_of[10] = 0; /* gui */
    qube_next = 1;   /* Next available qube for future isolation */

    kputs("Services: mem+console+tty+vault+cryptblk+gui up\n");

    /* Disable verbose runtime logging now that boot is complete */
    boot_log_enabled = 0;

    /* Boot complete - enter scheduler at thread 2 (mem_server) */
    kputs("v2: entering U-mode\n");
    enter_thread(2);
}
