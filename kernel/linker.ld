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
    _text_start = .;
    /* Keep original 0x80200000 alias for OpenSBI builds */
    /* Wildcards catch clang subsections (.text.*, .rodata.str1.1, .rodata.cst8):
     * orphans would otherwise land inside [_bss, _bss_end) and be wiped by
     * the start.S BSS clear (that bug cost all kernel text output). */
    .text : { *(.text.start) *(.text*) } :text
    .rodata : { *(.rodata*) } :rodata
    .data : { *(.data*) } :rodata
    /* DICE expected-hash slot: 32 bytes supplied by build/expected_hash.o
     * (`make provision-dice`). The measurement in kernel/src/dice.c hashes
     * [_text_start,_dice_expected_start) + [_dice_expected_end,_bss), i.e.
     * everything file-backed EXCEPT this slot - so provisioning is a fixed
     * point reached in a single rebuild. KEEP: an unreferenced const would
     * otherwise be GC'd and the symbols would go undefined. */
    .dice_expected : ALIGN(4) {
        _dice_expected_start = .;
        KEEP(*(.dice_expected))
        _dice_expected_end = .;
    } :rodata
    _bss = .;
    .bss : { *(.bss*) *(COMMON) }
    . = ALIGN(4096);
    _bss_end = .;
    /* Single gp definition (ld PROVIDE keeps the first; a duplicate lived
     * here and silently shadowed edits to the second). */
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
