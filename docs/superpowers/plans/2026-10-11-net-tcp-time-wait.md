# Net TCP TIME_WAIT Linger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TCB-held TIME_WAIT linger to both graceful close completions with duplicate-ACKs and port reservation until expiry.

**Architecture:** New `TIME_WAIT` state in `tcp.h` entered from both close paths; `sock.c` gates sends/recv/rebind per state; the existing `v2_main.c` loop pass fires linger expiry and duplicate-ACK replies. No new threads/endpoints.

**Tech Stack:** Freestanding C99 (riscv64 clang, `-Werror`), host gcc vectors, RFC 793 §3.5.

**Spec:** `docs/superpowers/specs/2026-10-11-net-tcp-time-wait-design.md`

## Global Constraints
- No new threads/endpoints (NTHREADS=11 full).
- TDD with host vectors; every task red-green before commit.
- Path-scoped commits (only the task's files).
- Bounded loops with `/* bound: N */` comments; `.clang-format` kept.
- 32-byte IPC and existing tags unchanged (`S_OPEN=8 S_SEND=9 S_TRYRECV=10 S_CLOSE=11 S_OK=12 S_DATA=13 S_EMPTY=14 S_ERR=15 S_RECV=16`); drained `S_RECV` on TIME_WAIT answers `S_EMPTY`, no new tags.
- TCP payload per segment capped at 536, total frame <= 1514.
- Linger duration `NET_TCP_TIME_WAIT_TICKS 600000000UL` (~60s at 10MHz rdtime); RST skips linger.

## Review Focus
- Data segment arriving in TIME_WAIT is ACKed but never queued or delivered — pinned in Task 3.
- RST during linger aborts immediately with no further ACKs — pinned in Task 3.
- S_OPEN on the lingering port fails while a different free port still opens — pinned in Task 2.
- Waiter armed across close entry gets exactly one S_ERR, never data — pinned in Task 3.
- Expiry exactly at the deadline frees (one tick before does not) — pinned in Task 2.

---

### Task 1: TIME_WAIT state + entry from both closes

**Files:**
- Modify: `userspace/net/tcp.h`
- Modify: `userspace/net/sock.c`
- Test: `tests/test_tcp.c`

**Interfaces:**
- Consumes: existing close completions (FIN-ACK covering `snd_nxt`, LAST_ACK covering ACK).
- Produces: `NET_TCP_TIME_WAIT 6`; both close paths enter TIME_WAIT with `retry_deadline = now + NET_TCP_TIME_WAIT_TICKS`; `S_SEND` in TIME_WAIT answers `-1`.

- [ ] **Step 1: Write the failing test** in `tests/test_tcp.c`: FIN-ACK close and LAST_ACK covering-ACK close both land in TIME_WAIT (not CLOSED); `net_sock_send` in TIME_WAIT returns -1 with `snd_nxt` untouched.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (no TIME_WAIT state).

- [ ] **Step 3: Implement** `NET_TCP_TIME_WAIT`, entry legs, and send gate in `userspace/net/tcp.h` + `userspace/net/sock.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/tcp.h userspace/net/sock.c tests/test_tcp.c
git commit -m "feat(net): TIME_WAIT entry from both closes"
```

### Task 2: Linger timer + duplicate-ACK + port reserve

**Files:**
- Modify: `userspace/net/sock.c`
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Task 1 TIME_WAIT entry; `u_rdtime()` ticks; `NET_TCP_TIME_WAIT_TICKS 600000000UL`.
- Produces: loop-pass expiry to CLOSED freeing the port (wrap-safe compare); duplicate data/FIN in TIME_WAIT re-ACKed without state change; `S_OPEN` on lingering port fails, other ports open.

- [ ] **Step 1: Write the failing test** in `tests/test_net_stack.c`: expiry one tick before deadline holds, at deadline frees for rebind; duplicate FIN re-ACKs with state held; `S_OPEN` on lingering port fails while another port opens.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack -v`
Expected: FAIL (no linger expiry).

- [ ] **Step 3: Implement** expiry check, duplicate-ACK path, and port reservation in `userspace/net/sock.c` + `userspace/net/v2_main.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/sock.c userspace/net/v2_main.c tests/test_net_stack.c
git commit -m "feat(net): TIME_WAIT linger timer and port reserve"
```

### Task 3: Waiter errors + RST skip + full green

**Files:**
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_tcp.c`, `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Tasks 1-2; waiter `net_waiter_arm/match/expire/clear`; `S_DATA/S_TIMEOUT/S_ERR` rendezvous; dead-owner gate.
- Produces: waiter armed across close entry wakes once with `S_ERR`; RST in TIME_WAIT aborts to CLOSED silently with no further ACKs; drained `S_RECV` answers `S_EMPTY`.

- [ ] **Step 1: Write the failing test**: waiter armed pre-close gets exactly one `S_ERR` on entry; RST during linger closes with no ACK parked; drained recv answers `S_EMPTY`.
- [ ] **Step 2: Run tests to verify they fail**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (waiter never woken on entry).

- [ ] **Step 3: Implement** entry-time waiter wake, RST skip, and drained-recv rule in `userspace/net/v2_main.c`.
- [ ] **Step 4: Run full suite green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp && gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack && clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c && /tmp/test_v2ipc 2>&1 | tail -n 2`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/v2_main.c tests/test_tcp.c tests/test_net_stack.c
git commit -m "feat(net): TIME_WAIT waiter errors and RST skip"
```
