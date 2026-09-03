OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    note PT_NOTE FLAGS(4);
}
SECTIONS {
    . = 0x100000; /* 1M multiboot load */
    .note.Xen : { *(.note.Xen) } :note
    .text : {
        *(.multiboot)
        *(.text.start*)
        *(.text*)
    } :text
    .rodata : { *(.rodata*) } :text
    .data : { *(.data*) } :text
    _bss = .;
    .bss : { *(.bss*) *(COMMON) } :text
    . = ALIGN(4096);
    _bss_end = .;
    .stack : ALIGN(16) {
        _stack_bottom = .;
        . += 32768;
        _stack_top = .;
    } :text
    .trap_stack : ALIGN(16) {
        _trap_stack_bottom = .;
        . += 32768;
        _trap_stack_top = .;
    } :text
    .pt_pool : ALIGN(4096) {
        _pt_pool_start = .;
        *(.pt_pool)
        _pt_pool_end = .;
    } :text
    . = 0x10200000;
    .rodata.posttrap : ALIGN(4096) {
        KEEP(*(.rodata.flush))
        KEEP(*(.rodata.boot))
        KEEP(*(.rodata.trap))
    } :text
    _kernel_end = .;
    /* CHERI/CET bounded stacks */
    _bss_end = _kernel_end;
}
