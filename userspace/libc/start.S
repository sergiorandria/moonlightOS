    /* Linux-app entry: _start(bundle .text.start first via user.ld).
     * a0 = main (unused here: real main), argc/argv synthesized on the
     * stack (argc=1, argv={"app"}), then exit(main(...)). gp from the
     * user image base (see user.ld PROVIDE). */
    .section .text.user_start, "ax", @progbits
    .align 2
    .global _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la gp, __user_global_pointer$
    .option pop
    addi sp, sp, -32
    sd zero, 24(sp)          /* argv[1] = NULL */
    la t0, .Largv0
    sd t0, 16(sp)            /* argv[0] */
    sd zero, 8(sp)
    li a0, 1                 /* argc */
    addi a1, sp, 16          /* argv */
    mv a2, zero              /* envp = NULL */
    call main
    /* exit(code): Linux exit_group (94). */
    mv a0, a0
    li a7, 94
    ecall
.Lhang:
    j .Lhang
    .section .rodata
.Largv0:
    .string "app"
