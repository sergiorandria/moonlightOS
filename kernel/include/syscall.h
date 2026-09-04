#pragma once
#include "types.h"
#include "cap.h"

#ifdef __x86_64__
typedef struct trap_frame {
    uintptr_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uintptr_t r8,r9,r10,r11,r12,r13,r14,r15;
    uintptr_t vector, error;
    uintptr_t rip;
    uint64_t cause;
    uintptr_t a0,a1,a2,a3,a4,a5,a6,a7; // for syscall compat
} trap_frame_t;
#else
typedef struct trap_frame {
    uintptr_t ra, sp, gp, tp;
    uintptr_t t0,t1,t2,t3,t4,t5,t6;
    uintptr_t a0,a1,a2,a3,a4,a5,a6,a7;
    uintptr_t s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11;
    uintptr_t pc;
    uint64_t cause;
} trap_frame_t;
#endif

/* Complete mediation: every syscall checks cap + rights + partition + CHERI tag */
kerror_t syscall_handler(trap_frame_t *frame, uint32_t cur_tcb);
kerror_t handle_invoke(cap_t *cap, invoke_op_t op, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
