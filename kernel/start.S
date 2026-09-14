    /* v2 S-mode entry. OpenSBI: a0=hartid, a1=dtb, mode=S. */
    .section .text.start, "ax", @progbits
    .align 2
    .global _start
    .type _start, @function
_start:
    mv t0, a0
    bnez t0, .Lpark            /* hart0 only */
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la t0, kstack_top
    ld sp, 0(t0)
    la t0, _bss
    la t1, _bss_end
    beq t0, t1, .Lbss_done
.Lbss_clear:
    sd zero, 0(t0)
    addi t0, t0, 8
    bltu t0, t1, .Lbss_clear
.Lbss_done:
    la t0, s_trap_entry
    csrw stvec, t0
    mv s0, a1                  /* dtb, reserved */
    call kboot
.Lpark:
    wfi
    j .Lpark
