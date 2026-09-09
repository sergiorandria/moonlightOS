    /* userspace entry: kernel (or thread_enter) jumps here with sp set.
     * No libc: clear our BSS, then run main. shell_main never returns;
     * hello_main returns into an infinite yield loop. */
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
    li a7, 3          /* SYS_YIELD */
    ecall
    j .Luser_hang
