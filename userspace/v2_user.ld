/* v2 userspace ELF layout: runs in the per-thread frame window
 * (U VA 0x80800000 + vpn*4096, 32 slots). The kernel ELF loader maps
 * p_vaddr - BASE as the vpn, so the image must be linked at BASE with all
 * PT_LOADs inside the 32-page window. .text/.rodata are RX, .data/.bss RW
 * (page-aligned split so no segment is ever W+X). */
OUTPUT_ARCH(riscv)
ENTRY(_v2_start)
BASE = 0x80800000;
SECTIONS {
    . = BASE;
    .text : { *(.text._v2_start) *(.text*) }
    /* Page-align every PT_LOAD: the kernel loader maps whole pages keyed by
     * (p_vaddr - BASE) >> 12 and rejects unaligned segments (fail closed),
     * so a .text of any size must never push .rodata off alignment. */
    . = ALIGN(4096);
    .rodata : { *(.rodata*) }
    . = ALIGN(4096);
    .data : { *(.data*) *(.got*) *(.sdata*) }
    .bss : { *(.bss*) *(COMMON) }
    PROVIDE(__global_pointer$ = BASE + 0x800);
    _v2_end = .;
}
