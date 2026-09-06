OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS {
    text PT_LOAD;
    rodata PT_LOAD;
    bss PT_LOAD;
    high PT_LOAD;
}
SECTIONS {
    . = 0x80000000;
    /* Keep original 0x80200000 alias for OpenSBI builds */
    .text : { *(.text.start) *(.text) } :text
    .rodata : { *(.rodata) } :rodata
    .data : { *(.data*) } :rodata
    _bss = .;
    .bss : { *(.bss*) *(COMMON) }
    . = ALIGN(4096);
    _bss_end = .;
    PROVIDE(__global_pointer$ = . + 0x800);
    . = 0x80100000;
    .rodata.trap_high : ALIGN(4096) {
        KEEP(*(.rodata.trap))
    } :high
    . = _bss_end;
    PROVIDE(__global_pointer$ = . + 0x800);
    /* CHERI-bounded stacks - each 4K with guard */
    .stack : ALIGN(4096) {
        _stack_bottom = .;
        . += 32768;
        _stack_top = .;
    } :bss
    .trap_stack : ALIGN(4096) {
        _trap_stack_bottom = .;
        . += 32768;
        _trap_stack_top = .;
    } :bss
    .pt_pool : ALIGN(4096) {
        _pt_pool_start = .;
        *(.pt_pool)
        . += 0; /* keep size from input */
        _pt_pool_end = .;
    } :bss
    _kernel_end = .;
}
