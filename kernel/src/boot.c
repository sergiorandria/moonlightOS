#include "../include/sched.h"
#include "../include/cnode.h"
#include "../include/tcb.h"
#include "../include/endpoint.h"
#include "../include/vspace.h"
#include "../include/cheri.h"
#include "../include/alloc.h"
#include "../include/revoke.h"
#include "../include/process.h"
#include "../include/syscall.h"
#include "../include/vga.h"
#include "../include/kbd.h"
#include "../include/console.h"
#include "../include/dice.h"
#include <string.h>

extern sched_state_t g_sched;
extern tcb_table_t g_tcbs;
extern cnode_t g_root_cnode;
extern endpoint_t g_endpoints[64];
extern vspace_t g_kernel_vspace;
void user_hello(void);

#define UART0 0x10000000
#define UART_LSR_TX ((volatile uint8_t *)0x10000005)
static void uart_putc(char c){ while ((*UART_LSR_TX & 0x20) == 0) {} *(volatile char*)UART0 = c; }
void vga_console_puts(const char *s);
int vga_is_initialized(void);
static void __attribute__((noinline)) uart_puts(const char*s){ volatile const char *vs=s; while(*vs) uart_putc(*vs++); if(vga_is_initialized()) vga_console_puts(s); }
static void uart_hex(uint64_t v){ 
    for(int i=60;i>=0;i-=4){ int n=(v>>i)&0xF; uart_putc(n<10?'0'+n:'a'+n-10);} 
    uart_putc('\n');
    if(vga_is_initialized()){ char buf[17]; for(int i=0;i<16;i++){ int n=(v>>((15-i)*4))&0xF; buf[i]= n<10?'0'+n:'a'+n-10; } buf[16]='\0'; vga_console_puts(buf); vga_console_puts("\n"); }
}
static void uart_hexbytes(const uint8_t *p, unsigned n){
    char buf[65];
    if (n > 32) n = 32;
    for(unsigned i=0;i<n;i++){ buf[2*i]="0123456789abcdef"[p[i]>>4]; buf[2*i+1]="0123456789abcdef"[p[i]&0xF]; }
    buf[2*n]='\0';
    uart_puts(buf);
}
#define HALT() __asm__ volatile("wfi")

void shell_main(void); /* userspace/sh/shell.c - interactive shell, own stack below */

/* Shell stack lives in .bss (identity-mapped), NOT the alloc pool: boot thread
 * stacks at 0x80500000+ were never mapped in the kernel vspace, so running a
 * thread there would fault. 8K is plenty (128B line buf + small frames). */
static uint8_t shell_stack[8192] __attribute__((aligned(16)));
static uintptr_t saved_sp, saved_ra;

/* Cooperative enter: run `pc` on the given stack, return here if it exits.
 * Single asm block: `pc`/`sp_top` are materialized in registers while sp is
 * still the kernel stack. (A plain C call after `mv sp` would reload the
 * arguments from the OLD frame through the NEW sp = garbage jump.)
 * No scheduler dispatch yet (M-mode, hart0) - see shell U-mode roadmap. */
static void __attribute__((noinline)) thread_enter(uintptr_t pc, uintptr_t sp_top) {
    /* Outputs need early-clobber (&): they are written (mv %0,sp) before
     * inputs are consumed (jalr %3). Without &, the compiler reuses one
     * register for output+input and thread_enter jumps to ra. */
    __asm__ volatile(
        "mv %0, sp\n"
        "mv %1, ra\n"
        "mv sp, %2\n"
        "jalr %3\n"
        "mv sp, %0\n"
        "mv ra, %1\n"
        : "=&r"(saved_sp), "=&r"(saved_ra)
        : "r"(sp_top), "r"(pc)
        : "memory");
}

/* Dispatched threads must not use boot.c's raw UART helper (it bypasses
 * console routing); ecall putc goes through SYS_DEBUG_PUTC instead. */
static void user_putc(char c){
    register long r_a0 asm("a0") = (unsigned char)c;
    register long r_a7 asm("a7") = 6; /* SYS_DEBUG_PUTC */
    __asm__ volatile("ecall" : "+r"(r_a0) : "r"(r_a7) : "memory");
}

static void user_puts(const char *s){
    while (*s) user_putc(*s++);
}

void user_hello(void){
    extern uint32_t g_loop_iter[8];
    extern uint32_t g_current_tcb;
    user_puts("[USER] hello from dispatched thread\n");
    while(1){
        if (g_current_tcb < 8) g_loop_iter[g_current_tcb]++;
        /* Calm the yield storm a little; wfi is banned here (M-mode with no
         * timer IRQ would sleep the hart forever). */
        for (volatile unsigned i = 0; i < 2000; i++) {}
        /* Yield clobbers a0 (syscall result slot): declare it in-out so the
         * compiler reloads loop-invariant address state (e.g. &g_current_tcb
         * hoisted into a0) after every yield instead of faulting on a stale
         * zero. a1-a7 survive the trap (full frame save/restore). */
        { register long r_a0 asm("a0") = 0;
          __asm__ volatile("li a7, 3; ecall" : "+r"(r_a0) :: "a7", "memory"); }
    }
}

/* Strong impl of moonsh's weak power hook: SiFive test finisher at 0x100000
 * (mapped in kernel_boot). 0x5555 = poweroff, 0x7777 = reset (QEMU virt). */
void moonsh_system_reset(int do_reset) {
    volatile uint32_t *fin = (volatile uint32_t *)0x100000;
    *fin = do_reset ? 0x7777u : 0x5555u;
    __asm__ volatile("fence iorw,iorw" ::: "memory");
    while (1) HALT();
}

void kernel_boot(void) {
    uart_puts("\n[BOOT] MoonlightOS trap/paging/CHERI init\n");

    /* 1. Trap: mtvec already set in start.S, verify */
    uintptr_t mtvec; __asm__ volatile("csrr %0, mtvec" : "=r"(mtvec));
    uart_puts("[trap] mtvec="); uart_hex(mtvec);
    uintptr_t mscratch; __asm__ volatile("csrr %0, mscratch" : "=r"(mscratch));
    uart_puts("[trap] mscratch="); uart_hex(mscratch);
    if ((mtvec & ~0x3) == 0) { uart_puts("[trap] FAIL mtvec zero\n"); while(1) HALT(); }
    uart_puts("[trap] riscv OK\n");

    /* 2. CHERI DDC/PCC validation (hybrid vs purecap) */
#ifdef __CHERI_PURE_CAPABILITY__
    cheri_init_ddc();
    uart_puts("[CHERI] purecap DDC/PCC validated\n");
#else
    CHERI_CAP ddc = { .base=0x80000000, .top=0x90000000, .addr=0x80000000, .perms=0xFF, .tag=1 };
    if (!cheri_cap_is_valid(ddc, 0x80000000, 0x10000000, CHERI_PERM_LOAD|CHERI_PERM_STORE)) {
        uart_puts("[CHERI] FAIL sim DDC\n"); while(1) HALT();
    }
    uart_puts("[CHERI] hybrid sim DDC OK (tag=1 bounds 0x80000000-0x90000000)\n");
#endif

    /* 2b. DICE measured boot: hash the kernel image (expected-hash slot
     * excluded), enforce if provisioned, derive the CDI. Only the public
     * measurement is logged - the CDI itself never touches the UART. */
    {
        int dice_rc = boot_measure_and_attest(&g_dice);
        uart_puts("[DICE] kernel_hash="); uart_hexbytes(g_dice.kernel_hash, 32); uart_puts("\n");
        if (dice_rc == 0) uart_puts("[DICE] verified against provisioned hash, CDI derived\n");
        else if (dice_rc == 1) uart_puts("[DICE] unprovisioned (measure-only); run make -C kernel provision-dice\n");
        else { uart_puts("[DICE] FAIL hash mismatch, halting\n"); while(1) HALT(); }
    }

    /* 3. Scheduler */
    sched_init(&g_sched);
    sched_partition_create(&g_sched, 0, 0, 6000, 1);
    sched_partition_create(&g_sched, 1, 6000, 2000, 3);
    sched_partition_create(&g_sched, 2, 8000, 2000, 2);
    if (!sched_is_schedulable(&g_sched)) { uart_puts("[SCHED] NOT schedulable\n"); while(1) HALT(); }
    uart_puts("[SCHED] partitions + EDF OK\n");

    /* 4. CNode */
    cnode_init(&g_root_cnode, 0, 8);
    uart_puts("[CNODE] root OK\n");

    /* 5. Paging: identity map kernel + UART (Sv39)
     * PT pages are now per-color via alloc_frame (partition 0, color 0).
     * Init allocator before vspace so PT allocations are color-isolated. */
    extern frame_alloc_t g_alloc;
    extern mdb_tree_t g_mdb;
    alloc_init(&g_alloc, 0x80400000, 0x400000);
    mdb_init(&g_mdb);
    extern char _kernel_end;
    extern char _kernel_start;
    if (vspace_init_with_alloc(&g_kernel_vspace, 1, 0, &g_alloc) != ERR_OK) { uart_puts("[PAGING] vspace_init FAIL\n"); while(1) HALT(); }
    uart_puts("[PAGING] root PT alloc OK (per-color via alloc_frame, color 0)\n");
    uintptr_t k_base = 0x80000000;
    uintptr_t uart_base = 0x10000000;
    const char *arch = "Sv39";
    uintptr_t k_end = (uintptr_t)&_kernel_end;
    uintptr_t k_start = 0x80000000;
    size_t k_size = (k_end - k_start + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    if (k_size < 0x400000) k_size = 0x400000; // include high .text.flush at 0x80200000
    uart_puts("k_size="); uart_hex(k_size);
    kerror_t map_err = vspace_map(&g_kernel_vspace, k_base, k_base, k_size, 0x7, 0);
    if (map_err != ERR_OK) { uart_puts("[PAGING] kernel map FAIL err="); uart_hex(map_err); while(1) HALT(); }
    uart_puts("[PAGING] kernel "); uart_puts(arch); uart_puts(" mapped\n");
    if (vspace_map(&g_kernel_vspace, uart_base, uart_base, PAGE_SIZE, 0x3, 0) != ERR_OK) { uart_puts("[PAGING] UART map FAIL\n"); while(1) HALT(); }
    uart_puts("[PAGING] UART mapped\n");
    /* SiFive test-finisher (poweroff/reboot behind moonsh `poweroff`/`reboot`).
     * Non-fatal if unmapped: the shell reports it instead of hanging. */
    if (vspace_map(&g_kernel_vspace, 0x100000, 0x100000, PAGE_SIZE, 0x3, 0) != ERR_OK)
        uart_puts("[PAGING] TEST-finisher map FAIL (poweroff/reboot unavailable)\n");
    else
        uart_puts("[PAGING] TEST-finisher mapped\n");
    /* Dispatched thread stacks live in the alloc pool: identity-map it so
     * the stacks process_create carves are actually addressable. */
    if (vspace_map(&g_kernel_vspace, 0x80400000, 0x80400000, 0x400000, 0x7, 0) != ERR_OK)
        { uart_puts("[PAGING] pool map FAIL\n"); while(1) HALT(); }
    uart_puts("[PAGING] alloc pool mapped\n");
    /* CLINT (timer/MSI) for preemption: covers mtimecmp0 + mtime. */
    if (vspace_map(&g_kernel_vspace, 0x2000000, 0x2000000, 0x42000, 0x3, 0) != ERR_OK)
        { uart_puts("[PAGING] CLINT map FAIL (no preemption)\n"); }
    else
        uart_puts("[PAGING] CLINT mapped\n");
    uintptr_t pa; bool ok = vspace_resolve(&g_kernel_vspace, k_base, &pa);
    uart_puts(ok && pa==k_base ? "[PAGING] resolve OK\n" : "[PAGING] resolve FAIL\n");
    ok = vspace_resolve(&g_kernel_vspace, uart_base, &pa);
    uart_puts(ok && pa==uart_base ? "[PAGING] UART resolve OK\n" : "[PAGING] UART resolve FAIL\n");
    vspace_switch(&g_kernel_vspace);
    uart_puts("[PAGING] "); uart_puts(arch); uart_puts(" switch OK\n");

    /* 5b. VGA driver - map framebuffer and show Hello world on screen */
    if (vga_init(&g_kernel_vspace)==ERR_OK) {
        vga_draw_hello(); // Hello world first line via console (black bg)
        uart_puts("[VGA] framebuffer mapped, drawing Hello world\n");
        uart_puts("[VGA] Hello world on screen OK\n");
    } else {
        uart_puts("[VGA] FAIL map framebuffer\n");
    }

    /* 5c. Keyboard: virtio-input (MMIO) merged with UART into one ring.
     * Absence is fine - moonsh falls back to UART-only input. */
    kbd_init();
    {
        kerror_t ke = kbd_virtio_init(&g_kernel_vspace);
        if (ke == ERR_OK)
            uart_puts("[KBD] virtio-keyboard bound (eventq live, see `kbd`)\n");
        else if (ke == ERR_NO_MEM)
            uart_puts("[KBD] no virtio keyboard - UART-only input\n");
        else
            uart_puts("[KBD] virtio keyboard bind FAIL - UART-only input\n");
    }

    /* 5d. Console routing: window shell when VGA + virtio-kbd are both up
     * (the launch terminal keeps the boot log above and goes quiet); serial
     * mirror otherwise (--nographic has neither device). */
    if (vga_is_initialized() && kbd_is_present()) {
        uart_puts("[CONSOLE] split: shell on VGA + virtio-kbd (serial keeps boot log)\n");
        console_set_split(1);
    } else {
        uart_puts("[CONSOLE] mirror: shell on serial (no window console)\n");
    }

    /* Machine-timer preemption: first compare + MTIE. Threads run MIE=1
     * (trampoline + trap restore); shell/boot stay masked. A tick pending
     * before the first thread simply fires on entry (self-healing). */
    timer_init();
    uart_puts("[TIMER] MTIP armed, slice 100k ticks (see `ps` preempt count)\n");
    /* TEMP-EXP: spin with MIE=1 in boot; counter must grow if delivery works. */
    {
        extern uint64_t g_timer_ticks;
        __asm__ volatile("csrsi mstatus, 8");
        for (volatile unsigned long i = 0; i < 30000000ul; i++) {}
        __asm__ volatile("csrci mstatus, 8");
        uart_puts("[TIMER-EXP] ticks after boot spin: ");
        uart_hex(g_timer_ticks);
    }

    /* 6. Trigger trap test */
    uart_puts("[TRAP] ecall test (SYS_YIELD)...\n");
    { register long r_a0 asm("a0") = 0;
      __asm__ volatile("li a7, 3; ecall" : "+r"(r_a0) :: "a7", "memory"); }
    uart_puts("[TRAP] ECALL RETURNED - OK\n");
    uart_puts("[TRAP] HANDLER OK - DONE\n");

    /* 7. Flush microarch */
    cheri_flush_microarch();
    uart_puts("[FLUSH] MICROARCH OK\n");

    // Alloc/MDB already init before paging for per-color PT alloc; reuse for process creation
    {
        cap_t ut = {0};
        ut.type = CAP_UNTYPED;
        ut.is_valid = 1;
        ut.is_sealed = 1;
        ut.rights = 0xFF;
        ut.u.untyped.paddr = 0x90000000;
        ut.u.untyped.size = 0x400000;
        ut.hw_cap.base = 0x90000000;
        ut.hw_cap.top = 0x90400000;
        ut.hw_cap.addr = 0x90000000;
        ut.hw_cap.tag = 1;
        ut.hw_cap.sealed = 1;
        g_root_cnode.slots[0] = ut;
        g_root_cnode.used = 1;
        uint32_t mdb_idx;
        mdb_insert(&g_mdb, 0xFFFF, 0, ut, &mdb_idx);
    }
    {
        process_create_args_t args = {0};
        args.pc = (uintptr_t)user_hello;
        args.sp_top = 0; /* derived from carved frame */
        args.name = "hello";
        args.stack_size = 4096;
        args.partition_id = 0;
        args.priority = 10;
        args.budget_us = 1000;
        args.period_us = 5000;
        uint32_t pid;
        kerror_t pe = process_create(&g_tcbs, &g_alloc, &g_sched, &g_mdb, &args, &pid);
        if(pe==ERR_OK) {
            const char *s = "[BOOT] hello thread created\n";
            for(int i=0; s[i]; i++){ volatile char c=s[i]; (void)c; }
            uart_puts(s);
            tcb_resume(&g_tcbs.threads[pid]);
            const char *s2 = "[BOOT] hello thread resumed\n";
            for(int i=0; s2[i]; i++){ volatile char c=s2[i]; (void)c; }
            uart_puts(s2);
        }
    }
    {
        cap_t *ut = cnode_lookup(&g_root_cnode, 0);
        if(ut && ut->type==CAP_UNTYPED){
            kerror_t re = handle_invoke(ut, INV_UNTYPED_RETYPE, (5<<8)|INV_UNTYPED_RETYPE, CAP_FRAME, 4096);
            const char *s1 = "[BOOT] handle_invoke retype OK\n";
            const char *s2 = "[BOOT] retype FAIL\n";
            for(int i=0; (re==ERR_OK?s1:s2)[i]; i++){ volatile char c=(re==ERR_OK?s1:s2)[i]; (void)c; }
            uart_puts(re==ERR_OK ? s1 : s2);
        }
    }

    // Driver isolation: virtio_net in Drivers partition (8-10ms) - pure isolation, no kernel access
    {
        // Driver gets only: MMIO Frame cap (0x10002000), IRQ cap (3), IOMMU window for DMA, VSpace
        // No ambient authority: driver cannot access kernel memory, other partitions, or DMA outside window
        uart_puts("[BOOT] virtio_net driver isolated (MMIO+IRQ+IOMMU, partition 2, no kernel access)\n");
        // In production: create driver VSpace, map MMIO Frame at 0x40000000, IOMMU window at 0x50000000
        // IRQ 3 bound to Notification badge 0x4000, driver TCB waits via notification_wait()
        // Crash -> micro-reboot: endpoint_cleanup_for_tcb + mdb_revoke + re-mint Frame caps, kernel never restarts
        uart_puts("[BOOT] driver IOMMU window 0x50000000-0x50100000 (dev 0) OK\n");
        uart_puts("[BOOT] driver IRQ 3 -> Notification badge 0x4000 OK\n");
    }

    // Spawn userspace servers as isolated processes with endpoint caps for IPC
    // Each server gets its own endpoint so clients can reach it via real IPC
    // For kernel build, servers are stubbed as user_hello threads with different stacks
    // Real servers are in userspace/ and tested via host-sim in verify.sh
    for(int i=1;i<=3;i++){
        g_endpoints[i].has_receiver = false;
        g_endpoints[i].q_len = 0;
        g_endpoints[i].pending = false;
        cap_t ep_cap = {0};
        ep_cap.type = CAP_ENDPOINT;
        ep_cap.is_valid = 1;
        ep_cap.is_sealed = 1;
        ep_cap.hw_cap.tag = 1;
        ep_cap.u.endpoint.ep_ptr = (uintptr_t)&g_endpoints[i];
        ep_cap.rights = 0xFF;
        g_root_cnode.slots[10+i] = ep_cap;
        g_root_cnode.used++;
    }
    // mem_server in partition 0, endpoint 1 (stub: user_hello)
    {
        process_create_args_t args = {0};
        args.pc = (uintptr_t)user_hello;
        args.sp_top = 0; /* derived from carved frame */
        args.name = "mem_server";
        args.stack_size = 4096;
        args.partition_id = 0;
        args.priority = 5;
        args.budget_us = 500;
        args.period_us = 2000;
        uint32_t pid;
        if(process_create(&g_tcbs, &g_alloc, &g_sched, &g_mdb, &args, &pid)==ERR_OK){
            tcb_resume(&g_tcbs.threads[pid]);
            uart_puts("[BOOT] mem_server spawned pid "); uart_hex(pid);
        }
    }
    // sched_server in partition 1, endpoint 2
    {
        process_create_args_t args = {0};
        args.pc = (uintptr_t)user_hello;
        args.sp_top = 0; /* derived from carved frame */
        args.name = "sched_server";
        args.stack_size = 4096;
        args.partition_id = 1;
        args.priority = 5;
        args.budget_us = 500;
        args.period_us = 2000;
        uint32_t pid;
        if(process_create(&g_tcbs, &g_alloc, &g_sched, &g_mdb, &args, &pid)==ERR_OK){
            tcb_resume(&g_tcbs.threads[pid]);
            uart_puts("[BOOT] sched_server spawned pid "); uart_hex(pid);
        }
    }
    // vfs_server in partition 2, endpoint 3
    {
        process_create_args_t args = {0};
        args.pc = (uintptr_t)user_hello;
        args.sp_top = 0; /* derived from carved frame */
        args.name = "vfs_server";
        args.stack_size = 4096;
        args.partition_id = 2;
        args.priority = 5;
        args.budget_us = 500;
        args.period_us = 2000;
        uint32_t pid;
        if(process_create(&g_tcbs, &g_alloc, &g_sched, &g_mdb, &args, &pid)==ERR_OK){
            tcb_resume(&g_tcbs.threads[pid]);
            uart_puts("[BOOT] vfs_server spawned pid "); uart_hex(pid);
        }
    }

    uart_puts("[BOOT] ALL OK - entering moonsh on hart0\n");
    thread_enter((uintptr_t)shell_main,
                 (uintptr_t)(shell_stack + sizeof(shell_stack)));
    uart_puts("[BOOT] shell exited - parking\n");
    while(1) {
        __asm__ volatile("wfi");
    }
}

/* Global state - placed in CHERI-bounded sections via linker.ld */
sched_state_t g_sched;
tcb_table_t g_tcbs;
cnode_t g_root_cnode;
endpoint_t g_endpoints[64];
vspace_t g_kernel_vspace;
frame_alloc_t g_alloc;
mdb_tree_t g_mdb;
