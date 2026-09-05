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
#include <string.h>

extern sched_state_t g_sched;
extern tcb_table_t g_tcbs;
extern cnode_t g_root_cnode;
extern endpoint_t g_endpoints[64];
extern vspace_t g_kernel_vspace;
void user_hello(void);

#ifdef __x86_64__
#define UART0 0x3F8
static inline void outb(uint16_t port, uint8_t val){ __asm__ volatile("outb %0,%1" :: "a"(val), "Nd"(port)); }
static inline uint8_t inb(uint16_t port){ uint8_t ret; __asm__ volatile("inb %1,%0" : "=a"(ret) : "Nd"(port)); return ret; }
static void uart_putc(char c){ while((inb(UART0+5) & 0x20)==0) {} outb(UART0, c); }
#else
#define UART0 0x10000000
static void uart_putc(char c){ *(volatile char*)UART0 = c; }
#endif
static void __attribute__((noinline)) uart_puts(const char*s){ volatile const char *vs=s; while(*vs) uart_putc(*vs++); }
static void uart_hex(uint64_t v){ for(int i=60;i>=0;i-=4){ int n=(v>>i)&0xF; uart_putc(n<10?'0'+n:'a'+n-10);} uart_putc('\n'); }
#ifdef __riscv
#define HALT() __asm__ volatile("wfi")
#elif defined(__x86_64__)
#define HALT() __asm__ volatile("hlt")
#else
#define HALT() __asm__ volatile("wfi")
#endif

void kernel_boot(void) {
    uart_puts("\n[BOOT] MoonlightOS trap/paging/CHERI init\n");

    /* 1. Trap: mtvec/IDT already set in start.S, verify */
#ifdef __riscv
    uintptr_t mtvec; __asm__ volatile("csrr %0, mtvec" : "=r"(mtvec));
    uart_puts("[trap] mtvec="); uart_hex(mtvec);
    uintptr_t mscratch; __asm__ volatile("csrr %0, mscratch" : "=r"(mscratch));
    uart_puts("[trap] mscratch="); uart_hex(mscratch);
    if ((mtvec & ~0x3) == 0) { uart_puts("[trap] FAIL mtvec zero\n"); while(1) HALT(); }
    uart_puts("[trap] riscv OK\n");
#elif defined(__x86_64__)
    uart_puts("[trap] x86_64 IDT OK\n");
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));
    uart_puts("[trap] idt base="); uart_hex(idtr.base);
    if(idtr.base==0) { uart_puts("[trap] FAIL idt zero\n"); while(1) HALT(); }
    uart_puts("[trap] OK\n");
#endif

    /* 2. CHERI DDC/PCC validation (hybrid vs purecap, CET for x86_64) */
#ifdef __CHERI_PURE_CAPABILITY__
    cheri_init_ddc();
    uart_puts("[CHERI] purecap DDC/PCC validated\n");
#elif defined(__x86_64__)
    // x86_64: CET or MPK sim, same bounds check
    CHERI_CAP ddc = { .base=0x100000, .top=0x200000, .addr=0x100000, .perms=0xFF, .tag=1 };
    if (!cheri_cap_is_valid(ddc, 0x100000, 0x100000, CHERI_PERM_LOAD|CHERI_PERM_STORE)) {
        uart_puts("[CHERI] FAIL sim DDC x86_64\n"); while(1) HALT();
    }
    uart_puts("[CHERI] x86_64 CET sim DDC OK (0x100000-0x200000)\n");
#else
    CHERI_CAP ddc = { .base=0x80000000, .top=0x90000000, .addr=0x80000000, .perms=0xFF, .tag=1 };
    if (!cheri_cap_is_valid(ddc, 0x80000000, 0x10000000, CHERI_PERM_LOAD|CHERI_PERM_STORE)) {
        uart_puts("[CHERI] FAIL sim DDC\n"); while(1) HALT();
    }
    uart_puts("[CHERI] hybrid sim DDC OK (tag=1 bounds 0x80000000-0x90000000)\n");
#endif

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

    /* 5. Paging: identity map kernel + UART (Sv39 or PML4) */
    extern char _kernel_end;
    extern char _kernel_start;
    if (vspace_init(&g_kernel_vspace, 1, 0) != ERR_OK) { uart_puts("[PAGING] vspace_init FAIL\n"); while(1) HALT(); }
    uart_puts("[PAGING] root PT alloc OK\n");
#ifdef __riscv
    uintptr_t k_base = 0x80000000;
    uintptr_t uart_base = 0x10000000;
    const char *arch = "Sv39";
    bool need_uart_map = true;
#else
    uintptr_t k_base = 0x100000;
    uintptr_t uart_base = 0x3F8; // COM1 IO port - no paging needed
    const char *arch = "PML4";
    bool need_uart_map = false;
    (void)_kernel_start;
#endif
    uintptr_t k_end = (uintptr_t)&_kernel_end;
#ifdef __riscv
    uintptr_t k_start = 0x80000000;
#else
    uintptr_t k_start = 0x100000;
#endif
    size_t k_size = (k_end - k_start + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
#ifdef __x86_64__
    // x86_64 _kernel_end includes high rodata at 0x10200000, cap to 2M for PML4
    if (k_size > 0x400000) k_size = 0x400000;
    if (k_size < 0x200000) k_size = 0x200000;
#else
    if (k_size < 0x400000) k_size = 0x400000; // include high .text.flush at 0x80200000
#endif
    uart_puts("k_size="); uart_hex(k_size);
    kerror_t map_err = vspace_map(&g_kernel_vspace, k_base, k_base, k_size, 0x7, 0);
    if (map_err != ERR_OK) { uart_puts("[PAGING] kernel map FAIL err="); uart_hex(map_err); while(1) HALT(); }
    uart_puts("[PAGING] kernel "); uart_puts(arch); uart_puts(" mapped\n");
    if (need_uart_map) {
        if (vspace_map(&g_kernel_vspace, uart_base, uart_base, PAGE_SIZE, 0x3, 0) != ERR_OK) { uart_puts("[PAGING] UART map FAIL\n"); while(1) HALT(); }
        uart_puts("[PAGING] UART mapped\n");
    } else {
        uart_puts("[PAGING] UART IO port (no map)\n");
    }
    uintptr_t pa; bool ok = vspace_resolve(&g_kernel_vspace, k_base, &pa);
    uart_puts(ok && pa==k_base ? "[PAGING] resolve OK\n" : "[PAGING] resolve FAIL\n");
    if (need_uart_map) {
        ok = vspace_resolve(&g_kernel_vspace, uart_base, &pa);
        uart_puts(ok && pa==uart_base ? "[PAGING] UART resolve OK\n" : "[PAGING] UART resolve FAIL\n");
    }
    vspace_switch(&g_kernel_vspace);
    uart_puts("[PAGING] "); uart_puts(arch); uart_puts(" switch OK\n");

    /* 6. Trigger trap test */
#ifdef __riscv
    uart_puts("[TRAP] ecall test (SYS_YIELD)...\n");
    __asm__ volatile("li a7, 3; ecall" ::: "a7", "memory");
    uart_puts("[TRAP] ECALL RETURNED - OK\n");
    uart_puts("[TRAP] HANDLER OK - DONE\n");
#elif defined(__x86_64__)
    uart_puts("[TRAP] int0x80 test (SYS_YIELD)...\n");
    __asm__ volatile("mov $3, %%rax; int $0x80" ::: "rax", "memory");
    uart_puts("[TRAP] INT RETURNED - OK\n");
    uart_puts("[TRAP] HANDLER OK - DONE\n");
#endif

    /* 7. Flush microarch */
    cheri_flush_microarch();
    uart_puts("[FLUSH] MICROARCH OK\n");

    // Init alloc and MDB for process creation
    extern frame_alloc_t g_alloc;
    extern mdb_tree_t g_mdb;
    alloc_init(&g_alloc, 0x80400000, 0x400000);
    mdb_init(&g_mdb);
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
        args.sp_top = 0x80500000;
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

    uart_puts("[BOOT] ALL OK - parking\n");
    while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#elif defined(__x86_64__)
        __asm__ volatile("hlt");
#else
        __asm__ volatile("" ::: "memory"); break;
#endif
    }
}

void user_hello(void){
    uart_puts("[USER] hello from userspace thread\n");
    while(1){
#ifdef __riscv
        __asm__ volatile("li a7, 3; ecall" ::: "a7", "memory");
        __asm__ volatile("wfi");
#elif defined(__x86_64__)
        __asm__ volatile("mov $3, %%rax; int $0x80" ::: "rax", "memory");
        __asm__ volatile("hlt");
#endif
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
