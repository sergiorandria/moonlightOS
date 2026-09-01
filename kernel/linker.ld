OUTPUT_ARCH(riscv)
ENTRY(kernel_boot)
SECTIONS {
    . = 0x80200000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    /* CHERI-bounded stacks - each 4K with guard */
    .stack : ALIGN(4096) { *(.stack) }
}
