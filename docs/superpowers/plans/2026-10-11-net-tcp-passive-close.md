# Net TCP Passive Close Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add graceful passive close (CLOSE_WAIT + LAST_ACK) to the single-TCB TCP seam, reusing the active path's retry and waiter discipline.

**Architecture:** New close legs live in the `tcp.h` seam beside the FIN_WAIT leg; `sock.c` gates close/send per state; `v2_main.c` routes ESTABLISHED FIN frames to the seam and reuses parked-frame retry. No new threads/endpoints.

**Tech Stack:** Freestanding C99 (riscv64 clang, `-Werror`), host gcc vectors, RFC 793 §3.5.

**Spec:** `docs/superpowers/specs/2026-10-11-net-tcp-passive-close-design.md`

## Global Constraints
- No new threads/endpoints (NTHREADS=11 full).
- TDD with host vectors; every task red-green before commit.
- Path-scoped commits (only the task's files).
- Bounded loops with `/* bound: N */` comments; `.clang-format` kept.
- 32-byte IPC and existing tags unchanged (`S_OPEN=8 S_SEND=9 S_TRYRECV=10 S_CLOSE=11 S_OK=12 S_DATA=13 S_EMPTY=14 S_ERR=15 S_RECV=16`); drained `S_RECV` on CLOSE_WAIT answers `S_EMPTY` (FIN-pending surfaced by subsequent `S_CLOSE` semantics, no new tags).
- TCP payload per segment capped at 536, total frame <= 1514.
- Retry spacing ~2s (`NET_IRQ_TIMEOUT_TICKS`), at most 5 retries, then RST-abort.

## Review Focus
- Peer FIN with out-of-window seq closes anyway (simplified close) — pinned in Task 1 (documents bore-or-close behavior).
- Duplicate peer FIN re-ACKs without re-closing or double waiter wake — pinned in Task 3.
- S_SEND racing the FIN arrival is rejected once CLOSE_WAIT holds — pinned in Task 1.
- LAST_ACK retry exhaustion RST-aborts and wakes waiter once — pinned in Task 2.
- Drained S_RECV on CLOSE_WAIT answers S_EMPTY (never hangs, never fabricates data) — pinned in Task 3.

---

### Task 1: CLOSE_WAIT entry + data preservation

**Files:**
- Modify: `userspace/net/tcp.h`
- Modify: `userspace/net/sock.c`
- Test: `tests/test_tcp.c`

**Interfaces:**
- Consumes: existing `struct net_tcp_conn` + `net_tcp_input` FIN_WAIT leg; `NET_TCP_ESTABLISHED 2`, `NET_TCP_FIN_WAIT 3`.
- Produces: `NET_TCP_CLOSE_WAIT 4`; in-order peer FIN in ESTABLISHED enters CLOSE_WAIT, `rcv_nxt + 1`, queued bytes intact, peer FIN ACKed; `S_SEND` in CLOSE_WAIT answers `-1`.

- [ ] **Step 1: Write the failing test** in `tests/test_tcp.c`: ESTABLISHED + in-order FIN with 5 data bytes → CLOSE_WAIT, bytes deliverable intact, immediate ACK parked; `net_sock_send` in CLOSE_WAIT returns -1 with `snd_nxt` untouched.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (no CLOSE_WAIT state).

- [ ] **Step 3: Implement** `NET_TCP_CLOSE_WAIT`, the ESTABLISHED FIN leg, and the send gate in `userspace/net/tcp.h` + `userspace/net/sock.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/tcp.h userspace/net/sock.c tests/test_tcp.c
git commit -m "feat(net): CLOSE_WAIT entry with data preserved"
```

### Task 2: LAST_ACK close via S_CLOSE + retry reuse

**Files:**
- Modify: `userspace/net/sock.c`
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Task 1 CLOSE_WAIT; existing retry arming/poll (`retry_deadline`, 5 max) and `net_sock_fin_close`-shaped FIN builder.
- Produces: `NET_TCP_LAST_ACK 5`; `S_CLOSE` in CLOSE_WAIT sends header-only `FIN|ACK` → LAST_ACK with retry armed; peer ACK of our FIN → CLOSED; idempotent close; exhaustion RST-aborts.

- [ ] **Step 1: Write the failing test** in `tests/test_net_stack.c`: CLOSE_WAIT close emits FIN and enters LAST_ACK; covering ACK closes exactly once; duplicate close answers `S_OK` without second FIN; exhaustion aborts.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack -v`
Expected: FAIL (no LAST_ACK state).

- [ ] **Step 3: Implement** `NET_TCP_LAST_ACK`, close mapping, and retry reuse in `userspace/net/sock.c` + `userspace/net/v2_main.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/sock.c userspace/net/v2_main.c tests/test_net_stack.c
git commit -m "feat(net): LAST_ACK close via S_CLOSE"
```

### Task 3: ESTABLISHED FIN routing + waiter errors + full green

**Files:**
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_tcp.c`, `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Tasks 1-2; waiter `net_waiter_arm/match/expire/clear`; `S_DATA/S_TIMEOUT/S_ERR` rendezvous; dead-owner gate.
- Produces: ESTABLISHED FIN frames routed to the seam (not the data queue); duplicate FIN re-ACKs without re-close; drained `S_RECV` on CLOSE_WAIT answers `S_EMPTY`; waiter wakes once (`S_ERR` on abort); RST anywhere aborts.

- [ ] **Step 1: Write the failing test**: peer FIN with queued data invisible to UDP carve; duplicate FIN drops with single close; drained recv answers `S_EMPTY`; abort waiter gets one `S_ERR`.
- [ ] **Step 2: Run tests to verify they fail**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (FIN frames never reach the seam).

- [ ] **Step 3: Implement** FIN routing + duplicate handling + waiter errors in `userspace/net/v2_main.c`.
- [ ] **Step 4: Run full suite green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp && gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack && clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c && /tmp/test_v2ipc 2>&1 | tail -n 2`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/v2_main.c tests/test_tcp.c tests/test_net_stack.c
git commit -m "feat(net): route ESTABLISHED FIN to seam"
```
