/* libc setjmp.S: context capture/restore (naked, no C frame).
 *
 * rv64 (LP64, soft-float: integer regs are the whole context):
 *   regs[0]=ra 1=sp 2..13=s0..s11
 * x86_64 (SysV: callee-saved only, the rest is caller-saved):
 *   regs[0]=rbx 1=rbp 2=rsp 3=r12 4=r13 5=r14 6=r15 7=rip
 */
#if defined(__riscv)

    .text
    .globl setjmp
    .type setjmp, @function
setjmp:
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
    li a0, 0
    ret
    .size setjmp, .-setjmp

    .globl longjmp
    .type longjmp, @function
longjmp:
    /* a0=env, a1=val (0 -> 1, per C). */
    beqz a1, .Llj1
    ld ra, 0(a0)
    ld sp, 8(a0)
    ld s0, 16(a0)
    ld s1, 24(a0)
    ld s2, 32(a0)
    ld s3, 40(a0)
    ld s4, 48(a0)
    ld s5, 56(a0)
    ld s6, 64(a0)
    ld s7, 72(a0)
    ld s8, 80(a0)
    ld s9, 88(a0)
    ld s10, 96(a0)
    ld s11, 104(a0)
    mv a0, a1
    ret
.Llj1:
    li a1, 1
    ld ra, 0(a0)
    ld sp, 8(a0)
    ld s0, 16(a0)
    ld s1, 24(a0)
    ld s2, 32(a0)
    ld s3, 40(a0)
    ld s4, 48(a0)
    ld s5, 56(a0)
    ld s6, 64(a0)
    ld s7, 72(a0)
    ld s8, 80(a0)
    ld s9, 88(a0)
    ld s10, 96(a0)
    ld s11, 104(a0)
    mv a0, a1
    ret
    .size longjmp, .-longjmp

    .globl siglongjmp
    .type siglongjmp, @function
siglongjmp:
    /* a0=env, a1=val. Spill both, restore the soft mask when the
     * env asked for it, then tail-jump to longjmp (which never
     * returns, so this frame is safely abandoned). */
    addi sp, sp, -24
    sd ra, 16(sp)
    sd a0, 8(sp)
    sd a1, 0(sp)
    lw t0, 128(a0)   /* env->mask_saved (regs[16] = 128 bytes) */
    beqz t0, 1f
    lw a0, 132(a0)   /* env->mask */
    call __ml_sigmask_set
1:
    ld a0, 8(sp)
    ld a1, 0(sp)
    ld ra, 16(sp)
    addi sp, sp, 24
    j longjmp
    .size siglongjmp, .-siglongjmp

#elif defined(__x86_64__)

    .text
    .globl setjmp
    .type setjmp, @function
setjmp:
    movq %rbx, 0(%rdi)
    movq %rbp, 8(%rdi)
    leaq 8(%rsp), %rax
    movq %rax, 16(%rdi)
    movq %r12, 24(%rdi)
    movq %r13, 32(%rdi)
    movq %r14, 40(%rdi)
    movq %r15, 48(%rdi)
    movq (%rsp), %rax
    movq %rax, 56(%rdi)
    xorl %eax, %eax
    ret
    .size setjmp, .-setjmp

    .globl longjmp
    .type longjmp, @function
longjmp:
    testl %esi, %esi
    jnz .Llj_ok
    movl $1, %esi
.Llj_ok:
    movq 0(%rdi), %rbx
    movq 8(%rdi), %rbp
    movq 24(%rdi), %r12
    movq 32(%rdi), %r13
    movq 40(%rdi), %r14
    movq 48(%rdi), %r15
    movq 56(%rdi), %rcx
    movq 16(%rdi), %rsp
    movl %esi, %eax
    jmp *%rcx
    .size longjmp, .-longjmp

    .globl siglongjmp
    .type siglongjmp, @function
siglongjmp:
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movl %esi, %r12d
    cmpl $0, 128(%rdi)  /* env->mask_saved? (regs[16]=128 bytes) */
    je .Lslj_go
    movl 132(%rdi), %edi  /* env->mask */
    call __ml_sigmask_set
.Lslj_go:
    movq %rbx, %rdi
    movl %r12d, %esi
    popq %r12
    popq %rbx
    jmp longjmp
    .size siglongjmp, .-siglongjmp

#else
#error "setjmp.S: unsupported arch (need raw context switch)"
#endif
