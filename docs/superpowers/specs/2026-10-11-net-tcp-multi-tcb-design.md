# Net TCP Multi-TCB Table — Design (2026-10-11)

## 1. Intent (agreed)
Grow the single TCB into a 4-entry per-socket table (approach A). Grounded
in RFC 793 (one state machine per connection) and the existing
`net_sock_tcp` seam in `userspace/net/sock.c`. No new threads/endpoints
(NTHREADS=11 full). TDD with host vectors. Bounded loops. Tags and 32-byte
IPC unchanged.

What was said vs assumed:
- Said: 4 TCBs, one per TCP socket.
- Agreed: Sec 1 table+binding, Sec 2 retry/linger/waiter per entry below.
  Fair-share (4 concurrent opens) bounds the table, so no eviction.
- Assumed: port uniqueness stays table-wide across kinds; MSS 536, retry
  `~2s × 5`, 2MSL 600M ticks unchanged per entry. Correct me if wrong.

Success = host suite green with two live ESTABLISHED sockets holding
independent seq; 5th TCP open still fails closed.

## 2. Table + binding (Sec 1, approved)
- Replace singleton `net_tcb`/`net_tcb_sock` with `net_tcbs[4]`, each bound
  to its socket id. At most 4 TCP sockets open concurrently under
  existing fair-share, so the array never overflows — no LRU, no steal.
- `net_sock_tcp(id)` indexes by socket; `S_CLOSE` frees only its entry;
  RST aborts only its entry. Port uniqueness stays table-wide.
- Files: `userspace/net/sock.c`, `userspace/net/tcp.h` (legs stay pure),
  `userspace/net/v2_main.c` (loop iterates entries).

## 3. Retry/linger/waiter per entry (Sec 2, approved)
- Each entry runs its own retry countdown and TIME_WAIT linger on the
  existing loop pass (4 × current bounded cost). Duplicate-ACK,
  exhaustion RST, and waiter wakeups ride the per-socket waiter table
  unchanged once indexed by entry. Exhaustion/close on one entry never
  touches the others; dead-owner and exactly-once gates unchanged.
- Tests in `tests/test_net_stack.c` + `tests/test_tcp.c`: two concurrent
  ESTABLISHED with independent seq/ack, close of one leaves the other
  live, independent retry clocks, per-entry duplicate-ACK isolation,
  waiter `S_ERR` only on the aborted entry, 5th open rejected, full suite
  green + riscv build. QEMU proof manual. Kernel untouched.

## 4. Risks
- 4 × TCB + Combine buffers raise net ELF `.bss`; stays within the 2MB
  per-thread window, verified at link.
- Loop pass cost ×4; still bounded and far under the tick budget.
- TIME_WAIT on one entry no longer blocks unrelated ports (strict-block
  becomes per-entry) — intended, pinned by test.
