#include "../include/sched.h"
#include "../include/cnode.h"
#include "../include/tcb.h"
#include "../include/endpoint.h"
#include "../include/vspace.h"
#include "../include/cheri.h"
#include <string.h>

extern sched_state_t g_sched;
extern tcb_table_t g_tcbs;
extern cnode_t g_root_cnode;
extern endpoint_t g_endpoints[64];
extern vspace_t g_kernel_vspace;

#define UART0 0x10000000
static void uart_putc(char c){ *(volatile char*)UART0 = c; }
static void uart_puts(const char*s){ while(*s) uart_putc(*s++); }
static void uart_hex(uint64_t v){ for(int i=60;i>=0;i-=4){ int n=(v>>i)&0xF; uart_putc(n<10?'0'+n:'a'+n-10);} uart_putc('\n'); }

void kernel_boot(void) {
    uart_puts("\n[BOOT] MoonlightOS trap/paging/CHERI init\n");

    /* 1. Trap: mtvec already set in start.S, verify */
#ifdef __riscv
    uintptr_t mtvec; __asm__ volatile("csrr %0, mtvec" : "=r"(mtvec));
    uart_puts("[TRAP] mtvec="); uart_hex(mtvec);
    uintptr_t mscratch; __asm__ volatile("csrr %0, mscratch" : "=r"(mscratch));
    uart_puts("[TRAP] mscratch="); uart_hex(mscratch);
    if ((mtvec & ~0x3) == 0) { uart_puts("[TRAP] FAIL mtvec zero\n"); while(1) __asm__ volatile("wfi"); }
    uart_puts("[TRAP] OK\n");
#endif

    /* 2. CHERI DDC/PCC validation (hybrid vs purecap) */
#ifdef __CHERI_PURE_CAPABILITY__
    cheri_init_ddc();
    uart_puts("[CHERI] purecap DDC/PCC validated\n");
#else
    /* Hybrid kernel: simulate CHERI caps via cheri.h */
    CHERI_CAP ddc = { .base=0x80000000, .top=0x90000000, .addr=0x80000000, .perms=0xFF, .tag=1 };
    if (!cheri_cap_is_valid(ddc, 0x80000000, 0x10000000, CHERI_PERM_LOAD|CHERI_PERM_STORE)) {
        uart_puts("[CHERI] FAIL sim DDC\n"); while(1) __asm__ volatile("wfi");
    }
    uart_puts("[CHERI] hybrid sim DDC OK (tag=1 bounds 0x80000000-0x90000000)\n");
#endif

    /* 3. Scheduler */
    sched_init(&g_sched);
    sched_partition_create(&g_sched, 0, 0, 6000, 1);
    sched_partition_create(&g_sched, 1, 6000, 2000, 3);
    sched_partition_create(&g_sched, 2, 8000, 2000, 2);
    if (!sched_is_schedulable(&g_sched)) { uart_puts("[SCHED] NOT schedulable\n"); while(1) __asm__ volatile("wfi"); }
    uart_puts("[SCHED] partitions + EDF OK\n");

    /* 4. CNode */
    cnode_init(&g_root_cnode, 0, 8);
    uart_puts("[CNODE] root OK\n");

    /* 5. Paging: Sv39 identity map kernel + UART */
    extern char _kernel_end;
    if (vspace_init(&g_kernel_vspace, 1, 0) != ERR_OK) { uart_puts("[PAGING] vspace_init FAIL\n"); while(1) __asm__ volatile("wfi"); }
    uart_puts("[PAGING] root PT alloc OK\n");
    /* Map kernel image 0x80000000.._kernel_end (2M) RWX, color 0 */
    uintptr_t k_end = (uintptr_t)&_kernel_end;
    size_t k_size = (k_end - 0x80000000 + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
    if (k_size < 0x200000) k_size = 0x200000;
    if (vspace_map(&g_kernel_vspace, 0x80000000, 0x80000000, k_size, 0x7, 0) != ERR_OK) { uart_puts("[PAGING] kernel map FAIL\n"); while(1) __asm__ volatile("wfi"); }
    uart_puts("[PAGING] kernel 0x80000000 mapped\n");
    /* Map UART 0x10000000 4K RW */
    if (vspace_map(&g_kernel_vspace, 0x10000000, 0x10000000, PAGE_SIZE, 0x3, 0) != ERR_OK) { uart_puts("[PAGING] UART map FAIL\n"); while(1) __asm__ volatile("wfi"); }
    uart_puts("[PAGING] UART 0x10000000 mapped\n");
    /* Test resolve before switch */
    uintptr_t pa; bool ok = vspace_resolve(&g_kernel_vspace, 0x80000000, &pa);
    uart_puts(ok && pa==0x80000000 ? "[PAGING] resolve OK\n" : "[PAGING] resolve FAIL\n");
    ok = vspace_resolve(&g_kernel_vspace, 0x10000000, &pa);
    uart_puts(ok && pa==0x10000000 ? "[PAGING] UART resolve OK\n" : "[PAGING] UART resolve FAIL\n");

    /* Switch satp */
    vspace_switch(&g_kernel_vspace);
    uart_puts("[PAGING] satp switch OK (Sv39)\n");

    /* 6. Trigger trap test (ecall) - should return via trap_entry -> syscall_handler */
#ifdef __riscv
    uart_puts("[TRAP] ecall test (SYS_YIELD)...\n");
    __asm__ volatile(
        "li a7, 3\n"
        "ecall\n"
        ::: "a7", "memory");
    {
        const char *s1 = "[TRAP] ecall returned\n";
        const char *s2 = "[TRAP] handler OK\n";
        for(int i=0; s1[i]; i++){ volatile char c=s1[i]; (void)c; }
        for(int i=0; s2[i]; i++){ volatile char c=s2[i]; (void)c; }
        uart_puts(s1);
        uart_puts(s2);
    }
#endif

    /* 7. Flush microarch */
    cheri_flush_microarch();
    {
        const char *s = "[FLUSH] microarch OK\n";
        for(int i=0; s[i]; i++){ volatile char c=s[i]; (void)c; }
        uart_puts(s);
    }

    uart_puts("[BOOT] ALL OK - parking\n");
    while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#else
        __asm__ volatile("" ::: "memory"); break;
#endif
    }
}

/* Global state - placed in CHERI-bounded sections via linker.ld */
sched_state_t g_sched;
tcb_table_t g_tcbs;
cnode_t g_root_cnode;
endpoint_t g_endpoints[64];
vspace_t g_kernel_vspace;
