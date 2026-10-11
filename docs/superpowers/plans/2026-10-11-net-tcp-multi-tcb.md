# Net TCP Multi-TCB Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the singleton TCB with a 4-entry per-socket table so four TCP connections run independent state, retry, and linger.

**Architecture:** `sock.c` owns a `net_tcbs[4]` array bound by socket id; the pure `tcp.h` legs take an entry pointer as today; the `v2_main.c` loop iterates entries for retry-fire and RX feed. No new threads/endpoints.

**Tech Stack:** Freestanding C99 (riscv64 clang, `-Werror`), host gcc vectors, RFC 793 one-machine-per-connection.

**Spec:** `docs/superpowers/specs/2026-10-11-net-tcp-multi-tcb-design.md`

## Global Constraints
- No new threads/endpoints (NTHREADS=11 full).
- TDD with host vectors; every task red-green before commit.
- Path-scoped commits (only the task's files).
- Bounded loops with `/* bound: N */` comments; `.clang-format` kept.
- 32-byte IPC and existing tags unchanged.
- At most 4 concurrent TCP opens (fair-share); 5th fails closed.
- Port uniqueness stays table-wide across kinds; MSS 536/frame 1514; retry `~2s × 5`; linger 600M ticks.

## Review Focus
- Two sockets ESTABLISHED with same peer IP but different ports keep independent snd_nxt — pinned in Task 1.
- Retry expiry on entry A resends only A's frame while entry B holds — pinned in Task 2.
- Duplicate-ACK for A never disarms B's retry — pinned in Task 2.
- Close of A to CLOSED/TIME_WAIT leaves B ESTABLISHED with waiter intact — pinned in Task 3.
- 5th concurrent TCP open fails closed with no TCB touched — pinned in Task 1.

---

### Task 1: Table array + binding

**Files:**
- Modify: `userspace/net/sock.h`
- Modify: `userspace/net/sock.c`
- Test: `tests/test_tcp.c`

**Interfaces:**
- Consumes: existing `net_sock_open/close/demux/owned` (8 slots, fair-share 4); `struct net_tcp_conn` fields.
- Produces: `net_tcbs[4]` bound by socket id; `struct net_tcp_conn *net_sock_tcp(int id)` per-entry; `int net_sock_tcp_bound(void)` returns first live entry or -1; 5th TCP open fails closed.

- [ ] **Step 1: Write the failing test** in `tests/test_tcp.c`: open TCP 8080 + 8081, both ESTABLISHED with independent `snd_nxt`; close of one leaves the other live with waiter intact; 5th concurrent TCP open fails.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (singleton has no second entry).

- [ ] **Step 3: Implement** the 4-entry array + per-socket binding in `userspace/net/sock.h` + `userspace/net/sock.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/sock.h userspace/net/sock.c tests/test_tcp.c
git commit -m "feat(net): per-socket TCB table"
```

### Task 2: Retry + linger per entry

**Files:**
- Modify: `userspace/net/sock.c`
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Task 1 table; `retry_deadline`, `retry_count` per entry; `NET_TCP_TIME_WAIT_TICKS 600000000UL`.
- Produces: per-entry retry arming/poll/exhaustion and TIME_WAIT linger; duplicate-ACK scoped to its entry; loop iterates all 4 entries per pass.

- [ ] **Step 1: Write the failing test** in `tests/test_net_stack.c`: entry A expiry resends only A's frame while B holds; duplicate-ACK for A never disarms B; lingering entry blocks only its own port.
- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack -v`
Expected: FAIL (single retry clock shared).

- [ ] **Step 3: Implement** per-entry retry/linger + loop iteration in `userspace/net/sock.c` + `userspace/net/v2_main.c`.
- [ ] **Step 4: Run tests to verify green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/sock.c userspace/net/v2_main.c tests/test_net_stack.c
git commit -m "feat(net): per-entry retry and linger"
```

### Task 3: RX demux + close paths + full green

**Files:**
- Modify: `userspace/net/v2_main.c`
- Test: `tests/test_tcp.c`, `tests/test_net_stack.c`

**Interfaces:**
- Consumes: Tasks 1-2; waiter `net_waiter_arm/match/expire/clear`; `S_DATA/S_TIMEOUT/S_ERR` rendezvous; dead-owner gate.
- Produces: RX demuxed to the owning entry by dport; RST/FIN/ACK legs run per entry; close of one entry leaves others live with waiters intact; drained `S_RECV` rules unchanged per entry.

- [ ] **Step 1: Write the failing test**: two live entries, RST for A aborts only A with one `S_ERR` while B stays ESTABLISHED; FIN for B closes only B.
- [ ] **Step 2: Run tests to verify they fail**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp -v`
Expected: FAIL (RST aborts the singleton).

- [ ] **Step 3: Implement** per-entry RX feed + close paths in `userspace/net/v2_main.c`.
- [ ] **Step 4: Run full suite green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_tcp tests/test_tcp.c && /tmp/test_tcp && gcc -Wall -Wextra -Werror -o /tmp/test_net_stack tests/test_net_stack.c && /tmp/test_net_stack && clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c && /tmp/test_v2ipc 2>&1 | tail -n 2`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add userspace/net/v2_main.c tests/test_tcp.c tests/test_net_stack.c
git commit -m "feat(net): per-entry RX demux and close"
```
