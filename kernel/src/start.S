    .section .text.start, "ax", @progbits
    .align 2
    .global _start
_start:
    # hart 0 only
    csrr t0, mhartid
    bnez t0, .Lpark

    # setup gp for medany (linker defines __global_pointer$)
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    # set up kernel stack
    la sp, _stack_top

    # clear BSS + stack + pt_pool (linker provides _bss .. _kernel_end)
    la t0, _bss
    la t1, _kernel_end
    beq t0, t1, .Lbss_done
.Lbss_clear:
    sd zero, 0(t0)
    addi t0, t0, 8
    bltu t0, t1, .Lbss_clear
.Lbss_done:

    # set trap vector (direct mode)
    la t0, trap_entry
    csrw mtvec, t0

    # set mscratch to trap stack top (separate from thread stack)
    la t0, _trap_stack_top
    csrw mscratch, t0

    # delegate no traps to S-mode, stay in M-mode
    csrw medeleg, zero
    csrw mideleg, zero

    # enable FPU / vector if present, set mstatus
    li t0, (1 << 13) | (1 << 15)  # FS | XS
    csrs mstatus, t0

    # invalidate TLB/BTB before enabling paging
    sfence.vma
    fence.i

    # CHERI DDC/PCC check is done in C (boot.c) - hybrid kernel keeps DDC wide
#ifdef __CHERI_PURE_CAPABILITY__
    # In purecap mode PCC/DDC are capabilities; validate tag via C
    jal cheri_init_ddc
#endif

    call kernel_boot

.Lpark:
    wfi
    j .Lpark

    .section .bss
    .align 3
_stack_bottom_dummy:
