/* userspace/shell_exec.h - Program launcher for MoonlightOS shell.
 * High-level API wrapping V2_INV_SPAWN, V2_INV_FORK, V2_INV_EXEC syscalls.
 * Provides: spawn(initrd_idx) -> child_tid, fork() -> child_tid/0,
 *           exec(initrd_idx) -> never_returns.
 *
 * Design: Minimal freestanding implementation (no libc).
 * Error handling: Return negative on failure, positive (tid) on success.
 * Entry point is shell.c which calls these functions to run programs.
 */

#ifndef SHELL_EXEC_H
#define SHELL_EXEC_H

#include <stdint.h>

/* V2 syscall numbers (must match kernel/kboot.c) */
#define V2_INVOKE 7
#define V2_INV_SPAWN 9
#define V2_INV_FORK 10
#define V2_INV_EXEC 11

/* Inline assembly syscall wrappers (riscv target only; host-sim below
 * returns an error so unit tests link and fail closed). */
#ifdef __riscv
static inline long shell_ecall4(long sys, long a0, long a1, long a2, long a3)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a3 asm("a3") = a3;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3) : "r"(r_a7) : "memory");
    return r_a0;
}
#else
static inline long shell_ecall4(long sys, long a0, long a1, long a2, long a3)
{
    (void)sys;
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    return -1;
}
#endif

/* Invoke a V2 INVOKE operation */
static inline long shell_invoke(long op, long a1, long a2, long a3)
{
    return shell_ecall4(V2_INVOKE, op, a1, a2, a3);
}

/* SPAWN: Create new thread and load initrd ELF at index idx.
 * Returns child tid (>= 0) on success, negative on failure.
 * Child is scheduled but may not have run yet (non-deterministic delay). */
static inline int shell_spawn(unsigned int idx)
{
    long rc = shell_invoke(V2_INV_SPAWN, (long)idx, 0, 0);
    return (int)rc;
}

/* FORK: Duplicate current thread's VSpace (COW).
 * Parent returns child tid (> 0), child returns 0.
 * On error, parent returns negative, child never created.
 * Child's registers are copies of parent (including a0); child gets a0=0 explicitly.
 * Typical usage:
 *   int child = fork();
 *   if (child > 0) {
 *       // Parent code: child is tid 'child'
 *       int status = wait_for_child(child);
 *   } else if (child == 0) {
 *       // Child code: exec() to replace image
 *       exec(new_prog_idx);
 *   } else {
 *       // Error: child < 0
 *   } */
static inline int shell_fork(void)
{
    long rc = shell_invoke(V2_INV_FORK, 0, 0, 0);
    return (int)rc;
}

/* EXEC: Replace current thread's image with initrd ELF at index idx.
 * On success: NEVER RETURNS (new image takes over from entry point).
 * On failure: Returns negative error code, current image preserved (can try again).
 * Common pattern: after fork(), child calls exec() to run new program.
 *
 * Semantics: Unmap all user pages, free frames, drop user caps, load new ELF.
 * Stack pointer (a2/sp) and entry point are set from new ELF header.
 * Registers zeroed except sp (stack is fresh for new image).
 * IPC/notify state cleared (new image starts clean). */
static inline int shell_exec(unsigned int idx)
{
    long rc = shell_invoke(V2_INV_EXEC, (long)idx, 0, 0);
    return (int)rc;
}

/* Wait for child thread to complete. Simple busy-wait polling.
 * Production systems would use IPC notifications (V2_WAIT + badge).
 * For shell, children typically park themselves (V2_PARK) when done,
 * so a polling loop can check if threads[child].state == T_PARKED.
 * Since userspace cannot read kernel thread state, this is a stub for now.
 * Real implementation would use: SEND(child_reply_ep, status) or IPC gate. */
static inline int shell_wait_child(int child_tid, int *status_out)
{
    (void)child_tid;
    (void)status_out;
    /* Placeholder: In production, use IPC to receive child's exit code. */
    return 0;
}

#endif /* SHELL_EXEC_H */
