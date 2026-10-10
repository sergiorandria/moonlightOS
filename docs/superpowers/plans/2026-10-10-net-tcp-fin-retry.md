# Net TCP Active-FIN + Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add active-close FIN_WAIT plus bounded SYN/data/FIN retransmit to the single-TCB TCP seam, tick-driven in the service loop.

**Architecture:** TCB in `tcp.h` gains FIN_WAIT + retry deadlines; the seam in `sock.c` maps S_CLOSE to FIN and gates sends; the existing `v2_main.c` loop fires due retries and closes on peer ACK. No new threads/endpoints.

**Tech Stack:** Freestanding C99 (riscv64 clang, `-Werror`), host gcc vectors, RFC 793 + lwIP single-TCB shape.

**Spec:** `docs/superpowers/specs/2026-10-10-net-tcp-fin-retry-design.md`

## Global Constraints
- No new threads/endpoints (NTHREADS=11 full).
- TDD with host vectors; every task red-green before commit.
- Path-scoped commits (only the task's files).
- Bounded loops with `/* bound: N */` comments; `.clang-format` kept.
- 32-byte IPC and existing tags unchanged.
- TCP payload per segment capped at 536, total frame <= 1514.
- Retry spacing ~2s (`NET_IRQ_TIMEOUT_TICKS`), at most 5 retries, then RST-abort.

## Review Focus
- FIN retransmit colliding with a concurrent S_SEND is rejected with S_ERR, never interleaves bytes — pinned in Task 2.
- Peer FIN-ACK arriving before our FIN is ACKed still closes exactly once — pinned in Task 3.
- Retry counter surviving across close-then-reopen without leaking the old deadline — pinned in Task 1.
- Zero-length S_SEND in FIN_WAIT answers S_ERR without touching snd_nxt — pinned in Task 2.
- rdtime wrap during a pending retry still fires (unsigned compare) — pinned in Task 2.

---

### Task 1: FIN_WAIT state + close mapping

**Files:**
- Modify: `userspace/net/tcp.h`
- Modify: `userspace/net/sock.c`
- Test: `tests/test_tcp.c`

**Interfaces:**
- Consumes: existing `struct net_tcp_conn` (`state, iss, irs, snd_nxt, rcv_nxt, lport, rport, rip`).
- Produces: `NET_TCP_FIN_WAIT` state; TCB fields `uint64_t retry_deadline; unsigned retry_count;`; `S_CLOSE`-on-ESTABLISHED enters FIN_WAIT (seam in `sock.c`); RST aborts to CLOSED and disarms.

- [ ] **Step 1: Write the failing test** in `tests/test_tcp.c`: ESTABLISHED `S_CLOSE` equivalent enters FIN_WAIT; RST returns CLOSED; reopened socket starts with `retry_count == 0`.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (no FIN_WAIT state).

- [ ] **Step 3: Implement** `NET_TCP_FIN_WAIT`, timer fields, and close mapping in `userspace/net/tcp.h` + `userspace/net/sock.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/tcp.h userspace/net/sock.c tests/test_tcp.c
git commit -m "feat(net): FIN_WAIT state and close mapping"
```

### Task 2: Retry timers + resend loop

**Files:**
- Modify: `userspace/net/sock.c`
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Task 1 TCB fields; `u_rdtime()` ticks; `NET_IRQ_TIMEOUT_TICKS`.
- Produces: per-pass due check resending the parked frame verbatim (SYN, unacked PSH, FIN); exhaustion RST-aborts and wakes waiter once with `S_ERR`; `S_SEND` in FIN_WAIT answers `S_ERR`.

- [ ] **Step 1: Write the failing test** in `tests/test_net_stack.c`: armed retry past deadline resends identical bytes; 5th expiry aborts; zero-length send in FIN_WAIT rejected; wrap-around deadline fires.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack -v`
Expected: FAIL (no retry deadlines).

- [ ] **Step 3: Implement** deadline arming on TX, loop-pass due check with verbatim resend, RST on exhaustion in `userspace/net/sock.c` + `userspace/net/v2_main.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/sock.c userspace/net/v2_main.c tests/test_net_stack.c
git commit -m "feat(net): bounded TCP retransmit loop"
```

### Task 3: Peer-ACK close + waiter errors + full green

**Files:**
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_tcp.c`, `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Tasks 1-2; waiter `net_waiter_arm/match/expire/clear`; `S_DATA/S_TIMEOUT/S_ERR` rendezvous.
- Produces: peer ACK or FIN-ACK of our FIN closes exactly once; duplicate FIN drops; idempotent close; waiter `S_ERR` on abort; dead owner clears without SEND.

- [ ] **Step 1: Write the failing test**: FIN->ACK closes, FIN->FIN-ACK closes, duplicate FIN drops with no second close, early FIN-ACK (before our FIN acked) still closes once, waiter gets one `S_ERR` on abort.
- [ ] **Step 2: Run tests to verify they fail**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (peer-ACK close missing).

- [ ] **Step 3: Implement** peer-ACK close path + idempotent close + waiter `S_ERR` in `userspace/net/v2_main.c`.
- [ ] **Step 4: Run full suite green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp && gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack && clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c && /tmp/test_v2ipc 2>&1 | tail -n 2`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/v2_main.c tests/test_tcp.c tests/test_net_stack.c
git commit -m "feat(net): peer-ACK close and waiter errors"
```
