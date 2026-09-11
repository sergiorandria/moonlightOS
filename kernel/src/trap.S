    .section .text
    .align 4
    .global trap_entry
    .global trap_entry_purecap
trap_entry:
    csrrw sp, mscratch, sp
    addi sp, sp, -272
    sd ra, 0(sp)
    sd t0, 32(sp)
    sd t1, 40(sp)
    sd t2, 48(sp)
    sd t3, 56(sp)
    sd t4, 64(sp)
    sd t5, 72(sp)
    sd t6, 80(sp)
    sd a0, 88(sp)
    sd a1, 96(sp)
    sd a2, 104(sp)
    sd a3, 112(sp)
    sd a4, 120(sp)
    sd a5, 128(sp)
    sd a6, 136(sp)
    sd a7, 144(sp)
    sd s0, 152(sp)
    sd s1, 160(sp)
    sd s2, 168(sp)
    sd s3, 176(sp)
    sd s4, 184(sp)
    sd s5, 192(sp)
    sd s6, 200(sp)
    sd s7, 208(sp)
    sd s8, 216(sp)
    sd s9, 224(sp)
    sd s10, 232(sp)
    sd s11, 240(sp)
    csrr t0, mscratch
    sd t0, 8(sp)   # user sp
    sd gp, 16(sp)
    sd tp, 24(sp)
    csrr t0, mcause
    csrr t1, mepc
    sd t1, 248(sp) # pc
    sd t0, 256(sp) # cause
    # Nested-trap stacks: point mscratch at THIS frame so a trap taken
    # while suspended here (cooperative switch-out, future IRQ) lands its
    # frame below instead of clobbering this one. 32K holds ~120 deep.
    csrw mscratch, sp
    mv a0, sp
    csrr t0, mcause
    # Proper async interrupt: timer/snapshot path (mepc NOT advanced).
    bltz t0, .Lirq
    # Ecalls always run the syscall path - even with a tick pending (it fires
    # right after mret). Routing ecalls by MTIP would eat thread syscalls.
    li t2, 11
    beq t0, t2, .Lsyscall
    li t2, 8
    beq t0, t2, .Lsyscall
    li t2, 9
    beq t0, t2, .Lsyscall
    # Sync non-ecall: this QEMU delivers MTIP without the interrupt bit (sync
    # code 7, desc m_timer), so gate on the pending bit, not mcause. A real
    # store fault racing a pending tick just looks like one extra preemption
    # (no mepc advance either way); without MTIP it falls through to the
    # fault path below (invalid syscall, no advance: same as before).
    csrr t2, mip
    andi t2, t2, 0x80
    bnez t2, .Lirq
.Lsyscall:
    # cur_tcb: the dispatcher tracks who is on hart (TCB_NONE = shell/idle).
    # medany: auipc+lw is position-independent in-image.
    la t0, g_current_tcb
    lw a1, 0(t0)
    call syscall_handler
    j .Ltrap_restore
.Lirq:
    la t2, g_trap_irq
    lw t0, 0(t2)
    addi t0, t0, 1
    sw t0, 0(t2)
    call timer_handler
.Ltrap_restore:
    ld t0, 256(sp)
    ld t1, 248(sp)
    li t2, 8
    blt t0, t2, .Lno_adv
    li t2, 12
    bge t0, t2, .Lno_adv
    addi t1, t1, 4
.Lno_adv:
    # Threads run preemptible: restore MPIE=1 so the timer can fire again
    # (shell traps with MIE=0 and must stay that way). lw zero-extends, so
    # sign-extend for the TCB_NONE (-1) compare.
    la t2, g_current_tcb
    lw t2, 0(t2)
    addiw t2, t2, 0
    li t0, -1
    beq t2, t0, .Ltie_mepc
    li t0, 0x80
    csrs mstatus, t0
.Ltie_mepc:
    csrw mepc, t1
    sfence.vma
    fence.i
    ld ra, 0(sp)
    ld t0, 32(sp)
    ld t1, 40(sp)
    ld t2, 48(sp)
    ld t3, 56(sp)
    ld t4, 64(sp)
    ld t5, 72(sp)
    ld t6, 80(sp)
    ld a0, 88(sp)
    ld a1, 96(sp)
    ld a2, 104(sp)
    ld a3, 112(sp)
    ld a4, 120(sp)
    ld a5, 128(sp)
    ld a6, 136(sp)
    ld a7, 144(sp)
    ld s0, 152(sp)
    ld s1, 160(sp)
    ld s2, 168(sp)
    ld s3, 176(sp)
    ld s4, 184(sp)
    ld s5, 192(sp)
    ld s6, 200(sp)
    ld s7, 208(sp)
    ld s8, 216(sp)
    ld s9, 224(sp)
    ld s10, 232(sp)
    ld s11, 240(sp)
    ld gp, 16(sp)
    ld tp, 24(sp)
    ld t0, 8(sp)   # pre-trap sp (saved at entry)
    addi sp, sp, 272
    csrw mscratch, sp  # restore the outer top for the next/outer trap
    mv sp, t0          # resume pre-trap sp (no swap: mscratch already set)
    mret

#ifdef __CHERI_PURE_CAPABILITY__
trap_entry_purecap:
    cincoffset csp, csp, -272
    csc cra, 0(csp)
    csc ct0, 32(csp)
    csc ct1, 40(csp)
    csc ca0, 88(csp)
    csc ca1, 96(csp)
    csc ca7, 144(csp)
    csrr ct0, mcause
    csc ct0, 256(csp)
    csrr ct1, mepc
    csc ct1, 248(csp)
    move ca0, csp
    cjal syscall_handler
    clc cra, 0(csp)
    cincoffset csp, csp, 272
    mret
#endif
