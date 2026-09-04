/* x86-64 trap.S - IDT handlers, purecap via CET sim */
.section .text
.code64
.global trap_entry
.global idt
.global idt_ptr

.macro TRAP_HANDLER n
.global trap_\n
trap_\n:
    push $0
    push $\n
    jmp trap_common
.endm
.macro TRAP_HANDLER_ERR n
.global trap_\n
trap_\n:
    push $\n
    jmp trap_common
.endm

TRAP_HANDLER 0
TRAP_HANDLER_ERR 8  /* double fault has error */
TRAP_HANDLER_ERR 13 /* GP has error */
TRAP_HANDLER_ERR 14 /* PF has error */
TRAP_HANDLER 32 /* IRQ0 */
TRAP_HANDLER 33
/* Syscall int 0x80 - no error code, push dummy */
.global trap_syscall
trap_syscall:
    push $0
    push $0x80
    jmp trap_common

trap_common:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, %rdi  /* frame */
    xor %esi, %esi  /* cur_tcb 0 */
    call syscall_handler
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    add $16, %rsp /* vector + error */
    pop %rax
    iretq

.section .data
.align 16
idt:
    .rept 256
    .quad 0,0
    .endr
idt_ptr:
    .word 256*16-1
    .quad idt

/* IDT init called from start.S */
.global idt_init
idt_init:
    ret
