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
    mov $stack_top, %esp

    /* 1. Build minimal identity-mapped page tables (PML4->PDPT->PD, 2MB pages, 0-1GB) */
    /* Zero PML4 */
    lea pml4_table, %edi
    xor %eax, %eax
    mov $1024, %ecx
    rep stosl
    /* PML4[0] -> PDPT */
    lea pml4_table, %eax
    lea pdpt, %ebx
    or $0x03, %ebx /* P | W */
    mov %ebx, (%eax)
    /* PDPT[0] -> PD */
    lea pdpt, %eax
    lea pd, %ebx
    or $0x03, %ebx
    mov %ebx, (%eax)
    /* PD[0..511] -> 2MB identity pages 0x00000000, 0x00200000, ... */
    lea pd, %edi
    mov $512, %ecx
    xor %eax, %eax
.Lpd_fill:
    mov %eax, %ebx
    shl $21, %ebx
    or $0x83, %ebx /* P | W | PS | A | D */
    mov %ebx, (%edi)
    add $8, %edi
    add $0x200000, %eax
    dec %ecx
    jnz .Lpd_fill

    /* 2. Load CR3 with PML4 physical address */
    lea pml4_table, %eax
    mov %eax, %cr3

    /* 3. Enable PAE */
    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4

    /* 4. Set EFER.LME */
    mov $0xC0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr

    /* 5. Enable paging (activates long mode) */
    mov %cr0, %eax
    or $0x80000000, %eax
    mov %eax, %cr0

    lgdt gdt_ptr
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    /* Far jump to 64-bit code segment - now L=1 is valid */
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
.align 4096
pml4_table:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096
.align 16
.space 32768
stack_top:
.space 32768
trap_stack_top:
