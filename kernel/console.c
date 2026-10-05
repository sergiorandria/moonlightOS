/* console.c - SBI console + timer + boot logging (SRP: console).
 *
 * Split out of kboot.c (SOLID Sprint 1b, production-ready).
 * Matches kernel.h's console.c. */
#include <stdint.h>

#include "kinternal.h"

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

void sbi_putchar(char c)
{
    sbi_ecall(SBI_CONSOLE_PUTCHAR, 0, (long)(unsigned char)c, 0, 0);
}

void sbi_set_timer(uint64_t stime)
{
    sbi_ecall(SBI_SET_TIMER, 0, (long)stime, (long)(stime >> 32), 0);
}

/* Boot-time logging flag: when 1, print all debug messages.
 * Set to 0 after services spawn to silence runtime IPC/invoke chatter. */
int boot_log_enabled = 1;
void kputhex(uint64_t v);
void kputdec(unsigned long v);

void kputs(const char *s)
{
    while (*s)
    {
        sbi_putchar(*s);
        s++;
    }
}

/* Debug logging (IPC, invoke, scheduler): only printed during boot */
void klog(const char *s)
{
    if (boot_log_enabled)
    {
        kputs(s);
    }
}

void klog_char(char c)
{
    if (boot_log_enabled)
    {
        sbi_putchar(c);
    }
}

void klog_dec(unsigned long v)
{
    if (boot_log_enabled)
    {
        kputdec(v);
    }
}

void klog_hex(uint64_t v)
{
    if (boot_log_enabled)
    {
        kputhex(v);
    }
}

void kputhex(uint64_t v)
{
    for (int i = 60; i >= 0; i -= 4)
    {
        int n = (v >> i) & 0xF;
        sbi_putchar(n < 10 ? '0' + n : 'a' + n - 10);
    }
}

void kputdec(unsigned long v)
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

uint64_t rdtime(void)
{
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
}
