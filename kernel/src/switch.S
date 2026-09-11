    .section .text
    .align 2
    .global context_switch
    .global thread_trampoline
# void context_switch(sw_ctx_t *cur /*a0*/, sw_ctx_t *next /*a1*/)
# Layout (kernel/include/tcb.h): 0:ra 8:sp 16+8*i:s[i].
# Saves cur callee-saved regs, loads next's, returns into next.
# Caller-saved regs (t*, a*) do NOT survive: sched_dispatch() keeps only
# volatile locals + globals live across the call (documented in sched.h).
context_switch:
    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 16(a0)
    sd s1, 24(a0)
    sd s2, 32(a0)
    sd s3, 40(a0)
    sd s4, 48(a0)
    sd s5, 56(a0)
    sd s6, 64(a0)
    sd s7, 72(a0)
    sd s8, 80(a0)
    sd s9, 88(a0)
    sd s10, 96(a0)
    sd s11, 104(a0)
    ld ra, 0(a1)
    ld sp, 8(a1)
    ld s0, 16(a1)
    ld s1, 24(a1)
    ld s2, 32(a1)
    ld s3, 40(a1)
    ld s4, 48(a1)
    ld s5, 56(a1)
    ld s6, 64(a1)
    ld s7, 72(a1)
    ld s8, 80(a1)
    ld s9, 88(a1)
    ld s10, 96(a1)
    ld s11, 104(a1)
    ret

# First entry into a fresh thread: s[11] holds the entry pc (preset by
# process_create; s-regs survive the switch). Threads run preemptible
# (MIE=1); the shell/boot stay masked. On return, park via C.
thread_trampoline:
    csrsi mstatus, 8
    mv t0, s11
    jalr t0
    call thread_exit
.Ltramp_halt:
    j .Ltramp_halt
