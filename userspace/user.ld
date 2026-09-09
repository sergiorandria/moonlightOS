/* Userspace ELF layout: loaded at 0x81000000, clear of the kernel
 * (0x80000000 + <=0x400000 identity map), the alloc pool (0x80400000),
 * and boot thread stacks (0x80500000-0x80800000). One VSpace per process
 * maps this region + its stack + shared IPC page (future). */
OUTPUT_ARCH(riscv)
ENTRY(user_start)
BASE = 0x81000000;
SECTIONS {
    . = BASE;
    .text : { *(.text.user_start) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    PROVIDE(__user_global_pointer$ = BASE + 0x800);
    _user_end = .;
}
