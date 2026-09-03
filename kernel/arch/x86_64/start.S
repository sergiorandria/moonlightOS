/* x86-64 start.S - Multiboot + GDT/IDT, purecap userspace via CET sim */
.section .note.Xen, "a", @note
.align 4
.long 4, 4, 18
.asciz "Xen"
.align 4
.long _start  /* PHYS32_ENTRY - must match ELF entry */

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

    /* 0. Clear BSS (includes page tables below) BEFORE building page tables.
       This must run before the paging structures are populated: the old
       code cleared BSS a second time AFTER CR3 was loaded and paging
       enabled, wiping the live PML4/PDPT/PD tables out from under the CPU
       and causing an immediate #PF -> #DF -> triple fault right after
       entering long mode (before any UART output). */
    lea _bss, %edi
    lea _bss_end, %ecx
    sub %edi, %ecx
    shr $2, %ecx
    xor %eax, %eax
    rep stosl

    /* 1. Build minimal identity-mapped page tables (PML4->PDPT->PD, 2MB pages, 0-1GB) */
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
    /* BSS already cleared in 32-bit mode before page tables were built -
       do NOT clear it again here, it would wipe the live PML4/PDPT/PD
       that CR3 currently points to and fault on the next access. */
    /* Populate IDT gate descriptors before loading it - lidt only loads the
       table *pointer*, it does not construct entries. idt[] starts as all
       zero (Present=0 for every vector), so without this step any trap,
       including the deliberate int $0x80 self-test below, immediately
       #GP-faults on the absent gate and the CPU triple-faults. */
    call build_idt
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

/* Build one 64-bit interrupt-gate descriptor: selector 0x08 (our CS64),
   IST=0, type=0x8E (Present | DPL0 | 64-bit interrupt gate). */
.macro SET_GATE vec, handler
    lea \handler(%rip), %rax
    lea idt(%rip), %rbx
    add $(\vec*16), %rbx
    mov %ax, (%rbx)
    movw $0x08, 2(%rbx)
    movb $0, 4(%rbx)
    movb $0x8E, 5(%rbx)
    mov %rax, %rcx
    shr $16, %rcx
    mov %cx, 6(%rbx)
    mov %rax, %rcx
    shr $32, %rcx
    mov %ecx, 8(%rbx)
    movl $0, 12(%rbx)
.endm

.global build_idt
build_idt:
    SET_GATE 0, trap_0
    SET_GATE 8, trap_8
    SET_GATE 13, trap_13
    SET_GATE 14, trap_14
    SET_GATE 32, trap_32
    SET_GATE 33, trap_33
    SET_GATE 0x80, trap_syscall
    ret

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
