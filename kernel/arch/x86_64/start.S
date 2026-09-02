/* x86-64 start.S - Multiboot + GDT/IDT, purecap userspace via CET sim */
.section .note.Xen, "a", @note
.align 4
.long 4, 4, 18
.asciz "Xen"
.align 4
.long 0x100000  /* PHYS32_ENTRY */

.section .text
.code32
.align 4
/* Multiboot2 header for QEMU -kernel and GRUB */
multiboot_header:
    .long 0xE85250D6
    .long 0
    .long multiboot_end - multiboot_header
    .long -(0xE85250D6 + 0 + (multiboot_end - multiboot_header))
    .word 0
    .word 0
    .long 8
multiboot_end:

.global _start
_start:
    cli
    /* QEMU -kernel loads 64-bit ELF directly in long mode if ELF is 64-bit.
       If loaded in 32-bit, we need to switch to long mode. Detect via CS.
       For now, assume QEMU jumps in 64-bit long mode when -kernel is 64-bit ELF.
       Fallback: if in 32-bit, set up GDT and jump to long mode. */
    mov $stack_top, %esp
    /* Check if already in long mode by trying to use 64-bit register */
    /* Simple: set up GDT for 64-bit */
    lgdt gdt_ptr
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    /* Far jump to 64-bit code segment */
    ljmp $0x08, $long_mode

.code64
long_mode:
    mov $stack_top, %rsp
    /* Clear BSS */
    lea _bss(%rip), %rdi
    lea _bss_end(%rip), %rcx
    sub %rdi, %rcx
    shr $3, %rcx
    xor %rax, %rax
    rep stosq
    /* Set up IDT */
    lea idt_ptr(%rip), %rax
    lidt (%rax)
    /* Enable SSE */
    mov %cr0, %rax
    and $~4, %rax
    or $2, %rax
    mov %rax, %cr0
    mov %cr4, %rax
    or $0x600, %rax
    mov %rax, %cr4
    /* Call kernel_boot (x86_64 System V) */
    call kernel_boot
.Lpark:
    hlt
    jmp .Lpark

.section .rodata
.align 8
gdt:
    .quad 0x0000000000000000 /* null */
    .quad 0x00AF9A000000FFFF /* code 64 */
    .quad 0x00CF92000000FFFF /* data */
gdt_ptr:
    .word gdt_end - gdt - 1
    .quad gdt
gdt_end:

.section .bss
.align 16
.space 32768
stack_top:
.space 32768
trap_stack_top:
