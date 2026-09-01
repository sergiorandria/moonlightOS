    .section .text
    .align 4
    .global trap_entry
    .global trap_entry_purecap
trap_entry:
    # Hybrid trap entry - saves all regs, validates CHERI tags, dispatches to C
    csrrw sp, mscratch, sp
    addi sp, sp, -256
    sd ra, 0(sp)
    sd t0, 8(sp)
    sd t1, 16(sp)
    sd a0, 24(sp)
    sd a1, 32(sp)
    sd a2, 40(sp)
    sd a3, 48(sp)
    sd a4, 56(sp)
    sd a5, 64(sp)
    sd a6, 72(sp)
    sd a7, 80(sp)
    # CHERI: save PCC and DDC
#ifdef __CHERI_PURE_CAPABILITY__
    csc csp, 88(sp)
    csc cpcc, 104(sp)
#endif
    csrr t0, mcause
    csrr t1, mepc
    sd t0, 120(sp)
    sd t1, 128(sp)
    mv a0, sp
    # a1 = current TCB id from mscratch
    csrr a1, mscratch
    call syscall_handler
    ld t1, 128(sp)
    csrw mepc, t1
    ld ra, 0(sp)
    ld a0, 24(sp)
#ifdef __CHERI_PURE_CAPABILITY__
    clc csp, 88(sp)
#endif
    addi sp, sp, 256
    csrrw sp, mscratch, sp
    mret

trap_entry_purecap:
    # Purecap variant - CHERI checks on every load via capability
    cincoffset csp, csp, -256
    csc cra, 0(csp)
    csc ct0, 8(csp)
    csc ca0, 16(csp)
    csc ca1, 24(csp)
    csc ca7, 32(csp)
    csrr ct0, mcause
    csc ct0, 40(csp)
    move ca0, csp
    cjal syscall_handler
    clc cra, 0(csp)
    cincoffset csp, csp, 256
    mret
