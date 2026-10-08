    /* DEAD CODE (kept for reference): every shipping ELF now enters
     * via lib/v2_start.S, which calls mem_server_main directly. This
     * file's `jalr a0` convention is incompatible with V2 SPAWN/EXEC
     * (regs are zeroed, so a0==0 faults), and no Makefile rule links it.
     * Do NOT revive without porting to the V2 entry convention. */
    .section .text.user_start, "ax", @progbits
    .align 2
    .global user_start
    .type user_start, @function
user_start:
    .option push
    .option norelax
    la gp, __user_global_pointer$
    .option pop
    /* a0 holds entry main on first call convention from thread_enter */
    jalr a0
.Luser_hang:
    li a7, 2          /* V2_PARK (was V1 SYS_YIELD=3, now V2_SEND: must not send) */
    ecall
    j .Luser_hang
