#pragma once
/* Linux personality layer: rv64 Linux syscalls translated onto Moonlight
 * primitives (console, VFS server, static heap/file arenas). See
 * docs/LINUX.md for the supported set and the documented limits.
 *
 * Threading model: each M-mode thread is a "process" (getpid = TCB id).
 * fds 0/1/2 are the console; fds >= 3 map to that caller's VFS fds
 * (linux_fd - 3). The heap/mmap arena and the file-data pool are static
 * (always mapped, no boot ordering): no ambient authority beyond the
 * caller's own VFS tables, no device mapping, no reclaim.
 */
#include "linux_abi.h"
#include "syscall.h"

/* Direct dispatcher for host unit tests (no trap frame): nr + 6 args +
 * caller TCB id (or TCB_NONE for the shell slot). Returns the Linux
 * result (negative errno on failure). f == NULL here; the frame wrapper
 * below adds exit/yield parking on target. */
long linux_syscall_nr(long nr, uintptr_t a0, uintptr_t a1, uintptr_t a2,
                      uintptr_t a3, uintptr_t a4, uintptr_t a5,
                      uint32_t caller);

/* Trap-frame wrapper for kernel/src/syscall.c. Sets frame->a0 to the
 * Linux result and returns true when the frame stays live (normal case).
 * Returns false when the call parked the caller (exit/yield): the frame
 * was recycled by sched_coop_switch and must not be touched. */
int linux_syscall_frame(trap_frame_t *frame, uint32_t cur, long *result_out);

/* Last exit code (for ps/inspection hooks). */
extern int linux_last_exit_code;
extern int linux_exit_count;
