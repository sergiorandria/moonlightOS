# Net TCP TIME_WAIT Linger — Design (2026-10-11)

## 1. Intent (agreed)
Add a 2MSL TIME_WAIT linger to the single-TCB TCP close paths (approach A:
TCB-held linger). Grounded in RFC 793 §3.5 (TIME-WAIT state) and the
existing retry/waiter machinery in `userspace/net/tcp.h` / `sock.c` /
`v2_main.c`. No new threads/endpoints (NTHREADS=11 full). TDD with host
vectors. Bounded loops. Tags and 32-byte IPC unchanged.

What was said vs assumed:
- Said: TIME_WAIT covering both close paths with one shared 2MSL.
- Agreed: Sec 1 states+transitions, Sec 2 timer/waiter/port-reuse below.
  No multi-TCB in this slice.
- Assumed: 2MSL Henry-spaced from `NET_IRQ_TIMEOUT_TICKS` timebase (exact
  ticks fixed in the implementation plan); duplicate-ACK replies reuse
  the parked-ACK path. Correct me if wrong.

Success = host suite green on linger vectors; duplicates during linger
get duplicate-ACKs and the port stays reserved until expiry.

## 2. States + transitions (Sec 1, approved)
- New state `TIME_WAIT`, entered from both graceful completions: our FIN
  ACKed covering `snd_nxt` (active path) and LAST_ACK covering-ACK close
  (passive path). Entry parks no new frame.
- Duplicate data/FIN segments in TIME_WAIT get duplicate-ACKs; they never
  re-close, never re-deliver, never re-arm retry.
- RST anywhere → CLOSED immediately with no linger, disarm unchanged.
- `S_SEND` in TIME_WAIT answers `S_ERR`; drained `S_RECV` answers
  `S_EMPTY`. Second concurrent open still fails closed (single TCB).
- Files: `userspace/net/tcp.h` (state + legs), `userspace/net/sock.c`
  (close/send gates).

## 3. Timer/waiter/port-reuse semantics (Sec 2, approved)
- The linger reuses `retry_deadline`/`retry_count`: entry stamps
  `now + 2MSL`; the loop pass that already checks retry fires expiry
  (wrap-safe unsigned compare). No retransmits run in TIME_WAIT.
- New `S_OPEN` on the lingering port fails closed until expiry frees the
  TCB to CLOSED. Waiters never arm in TIME_WAIT; any waiter left armed
  across entry wakes once with `S_ERR` then clears (exactly-once,
  dead-owner gate unchanged).
- Tests in `tests/test_net_stack.c` + `tests/test_tcp.c`: both paths
  enter linger; duplicates re-ACKed without state change; expiry frees
  port for rebind; RST skips linger; waiter `S_ERR` on entry; full suite
  green + riscv build. QEMU proof manual. Kernel untouched.

## 4. Risks
- Single TCB stays single; linger blocks the only TCB, so back-to-back
  connections on one port serialize through 2MSL.
- 2MSL length trades duplicate protection against port-reuse latency;
  exact ticks belong in the plan.
- Off-window validation follows the simplified-close discipline;
  full window tracking stays a follow-up.
