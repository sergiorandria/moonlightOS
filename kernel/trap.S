    /* v2 S-mode trap entry. ctx layout (mirrors uctx_t in kboot.c):
     * regs[0..31] at i*8 (x0 slot unused), sepc at 256. Frame = thread ctx
     * itself (cur_ctx): save in place, C handler edits, restore or switch.
     * sscratch holds the trap-stack top on entry, user sp inside. */
    .section .text, "ax", @progbits
    .align 2
    .global s_trap_entry
    .type s_trap_entry, @function
s_trap_entry:
    csrrw sp, sscratch, sp
    addi sp, sp, -16
    sd t0, 0(sp)                    /* stash user t0 */
    la t0, cur_ctx
    ld t0, 0(t0)                    /* t0 = ctx */
    sd ra, 8(t0)
    sd gp, 24(t0)
    /* x2 (sp) saved from sscratch below */
    sd tp, 32(t0)
    sd t1, 48(t0)
    sd t2, 56(t0)
    sd s0, 64(t0)
    sd s1, 72(t0)
    sd a0, 80(t0)
    sd a1, 88(t0)
    sd a2, 96(t0)
    sd a3, 104(t0)
    sd a4, 112(t0)
    sd a5, 120(t0)
    sd a6, 128(t0)
    sd a7, 136(t0)
    sd s2, 144(t0)
    sd s3, 152(t0)
    sd s4, 160(t0)
    sd s5, 168(t0)
    sd s6, 176(t0)
    sd s7, 184(t0)
    sd s8, 192(t0)
    sd s9, 200(t0)
    sd s10, 208(t0)
    sd s11, 216(t0)
    sd t3, 224(t0)
    sd t4, 232(t0)
    sd t5, 240(t0)
    sd t6, 248(t0)
    csrr t1, sscratch
    sd t1, 16(t0)                   /* user sp -> x2 slot */
    ld t1, 0(sp)
    sd t1, 40(t0)                   /* user t0 -> x5 slot */
    csrr t1, sepc
    sd t1, 256(t0)
    addi sp, sp, 16
    csrr a0, scause
    mv a1, t0
    call s_trap_handler             /* (cause, ctx); returns or switches */
    /* Non-switch return: restore from cur_ctx. */
    la t0, cur_ctx
    ld t0, 0(t0)
    ld t1, 256(t0)
    csrw sepc, t1
    ld t1, 16(t0)
    csrw sscratch, t1               /* user sp back to sscratch */
    ld ra, 8(t0)
    ld gp, 24(t0)
    ld tp, 32(t0)
    ld t1, 48(t0)
    ld t2, 56(t0)
    ld s0, 64(t0)
    ld s1, 72(t0)
    ld a0, 80(t0)
    ld a1, 88(t0)
    ld a2, 96(t0)
    ld a3, 104(t0)
    ld a4, 112(t0)
    ld a5, 120(t0)
    ld a6, 128(t0)
    ld a7, 136(t0)
    ld s2, 144(t0)
    ld s3, 152(t0)
    ld s4, 160(t0)
    ld s5, 168(t0)
    ld s6, 176(t0)
    ld s7, 184(t0)
    ld s8, 192(t0)
    ld s9, 200(t0)
    ld s10, 208(t0)
    ld s11, 216(t0)
    ld t3, 224(t0)
    ld t4, 232(t0)
    ld t5, 240(t0)
    ld t6, 248(t0)
    ld t0, 40(t0)
    csrrw sp, sscratch, sp
    sret

    /* u_enter(ctx): enter/switch to a U thread, noreturn.
     * a0 = ctx. Works from kboot (sp=kstack) and from handler (sp=trap). */
    .global u_enter
    .type u_enter, @function
u_enter:
    ld t0, 256(a0)
    csrw sepc, t0
    li t0, (1 << 5)
    csrs sstatus, t0                /* SPIE=1 */
    li t0, (1 << 8)
    csrc sstatus, t0                /* SPP=0 (U-mode) */
    la t1, trap_stack_top
    ld t1, 0(t1)
    csrw sscratch, t1
    ld t1, 16(a0)
    mv sp, t1                       /* new user sp */
    ld ra, 8(a0)
    ld gp, 24(a0)
    ld tp, 32(a0)
    ld t1, 48(a0)
    ld t2, 56(a0)
    ld s0, 64(a0)
    ld s1, 72(a0)
    ld a1, 88(a0)
    ld a2, 96(a0)
    ld a3, 104(a0)
    ld a4, 112(a0)
    ld a5, 120(a0)
    ld a6, 128(a0)
    ld a7, 136(a0)
    ld s2, 144(a0)
    ld s3, 152(a0)
    ld s4, 160(a0)
    ld s5, 168(a0)
    ld s6, 176(a0)
    ld s7, 184(a0)
    ld s8, 192(a0)
    ld s9, 200(a0)
    ld s10, 208(a0)
    ld s11, 216(a0)
    ld t3, 224(a0)
    ld t4, 232(a0)
    ld t5, 240(a0)
    ld t6, 248(a0)
    ld t0, 40(a0)
    ld a0, 80(a0)
    sret
