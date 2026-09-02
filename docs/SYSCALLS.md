# Syscalls (6 Only, Production)

All via `ecall`, dispatch `kernel/src/syscall.c:14` `syscall_handler(trap_frame_t *frame, uint32_t cur_tcb)`.

| # | Name | a7 | a0 | a1 | a2 | Returns | Checks |
|---|---|---|---|---|---|---|---|
|0| `SYS_CALL` |0| ep_cptr | msg_len | - | `ERR_OK` | `cap_has_right READ|WRITE`, `CAP_ENDPOINT`, `partition budget`, `WCET 5us` |
|1| `SYS_REPLY_RECV` |1| ep_cptr | - | - | `ERR_OK` | `CAP_ENDPOINT`, blocks `TCB_BLOCKED_RECV` |
|2| `SYS_SEND` |2| ep_cptr | msg_len | - | `ERR_OK` | `CAP_ENDPOINT` |
|3| `SYS_YIELD` |3| - | - | - | `ERR_OK` | always allowed, even if `!runnable` |
|4| `SYS_SEAL` |4| cap | otype | - | `ERR_OK` | CHERI `seal` with `OTYPE_*` |
|5| `SYS_INVOKE` |5| cap | op | arg2 | `ERR_OK` | `cap_is_valid` + `handle_invoke` |

`handle_invoke` ops (`kernel/include/types.h:46`):

```
INV_UNTYPED_RETYPE (0) -> cap_can_retype
INV_CNODE_COPY (1), MINT (2), MOVE (3), DELETE (4)
INV_TCB_CONFIGURE (5), RESUME (6), SUSPEND (7)
INV_VSPACE_MAP (8) -> CAP_VSPACE, INV_VSPACE_UNMAP (9)
INV_FRAME_MAP (10), INV_SCHED_BIND (11)
```

Example (userspace `lib/moonlight.h:12`):

```c
int moonlight_call(uint32_t ep, void *msg){
  register long a0 asm("a0") = ep;
  register long a1 asm("a1") = (long)msg;
  register long a7 asm("a7") = 0;
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a7) : "memory");
  return a0; // kerror_t
}
```

WCET: entry `rdtime` at `syscall.c:18`, `wcet_check(entry_us)` at `:92` returns `ERR_WCET_EXCEEDED` if `>5000` ticks.

Temporal isolation: `g_sched.contexts[tcb->sched_context].remaining_us==0` → `ERR_WCET_EXCEEDED`.

All paths constant-time, no secret branches.

