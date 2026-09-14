OUTPUT_ARCH(riscv)
ENTRY(_start)
KBASE = 0x80200000;
UBASE_TEXT = 0x80400000;
UBASE_DATA = 0x80600000;
SECTIONS {
    . = KBASE;
    _stext = .;
    .text : { *(.text.start) *(.text*) }
    .rodata : { *(.rodata*) }
    _erx = .;
    .data : { *(.data*) }
    _bss = .;
    .bss : { *(.bss*) *(COMMON) }
    . = ALIGN(4096);
    _bss_end = .;
    PROVIDE(__global_pointer$ = KBASE + 0x800);
    /* U-mode image: separate sections so page tables can split perms. */
    . = UBASE_TEXT;
    .utext : { *(.utext*) }
    . = UBASE_DATA;
    .udata : { *(.udata*) *(.ustack*) }
    _user_end = .;
}
