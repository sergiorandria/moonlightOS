    /* qrexec_server ELF entry: the kernel SPAWNs the initrd image by setting
     * sepc=e_entry with sp already installed. No a0 convention (unlike the
     * v1 user_start which jalr's a0): set our own gp, call the C main,
     * park forever on return. */
    .section .text._v2_start, "ax", @progbits
    .align 2
    .global _v2_start
    .type _v2_start, @function
_v2_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    call qrexec_main
.Lv2_park:
    li a7, 2          /* V2_PARK */
    ecall
    j .Lv2_park
