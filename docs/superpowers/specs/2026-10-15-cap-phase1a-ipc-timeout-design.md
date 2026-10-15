# CAP Phase 1a — Bounded IPC Timeouts — Design

Date: 2026-10-15. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 5c broker gate; `verify.sh` green. Decomposed from ROADMAP
CAP Phase 1 (Weeks 13–14): this spec covers hung-IPC timeouts only; health
monitoring, restart, and async queuing are separate spec cycles
(ASEND already covers fire-and-forget async).

## 1. Outcome and scope

Blocking SEND/RECV gain tick-budgeted variants that fail with
`V2_ERR_TIMEOUT` instead of parking forever. Legacy SEND/RECV paths are
byte-untouched.

Locked decisions (chat-approved): hung-IPC pain first; approach A (new
timeout syscall variants, explicit and auditable).

Explicitly out of scope: per-thread timeout attributes, userspace-composed
timeouts, health/restart work, any change to legacy blocking semantics.

## 2. Architecture

New `V2_SEND_TIMEOUT(ep, ptr, len, ticks)` / `V2_RECV_TIMEOUT` beside
SEND/RECV (new `a7` numbers above today's max). Expiry returns
`V2_ERR_TIMEOUT` with the thread runnable and queues untouched — the
fail-closed shape of today's OVERFLOW path. The timer-tick handler wakes
expired waiters through existing preemption machinery; no new interrupts.

Constraints honored: NTHREADS=11, all IPC bounds unchanged; WCET-neutral
(flagged waiter scan, never a full-table scan).

## 3. Components

1. Tick-budgeted waiter records — existing waiter entries gain an
   expiry-tick field (zero = infinite, preserving legacy behavior bit-for-bit).
2. Two dispatch arms in `syscall_ipc.c` (+ `V2_*` numbers in `kinternal.h`),
   mirroring SEND/RECV with the budget plumbed through.
3. `tests/test_ipc_timeout.c` — expiry ordering, zero/infinite budgets,
   snapshot no-change, wrap arithmetic, max clamp, mutants — plus a
   tick-advance harness.

## 4. Data flow

Call: budget queued as expiry stamp (`rdtime()` + ticks), or fast-path
direct delivery ignoring budget (as today). Tick: scheduler scans only
timeout-parked threads and wakes expired ones with `V2_ERR_TIMEOUT`. No
cross-thread state, no new queues.

## 5. Error handling (fail-closed)

- Expiry changes nothing (neither queue touched — snapshot vectors).
- Zero budget = immediate try-once, never parks.
- Tick wrap immune via signed half-range expiry comparison.
- Oversized budgets clamp to `V2_TIMEOUT_MAX`, never overflow the stamp.
- Only new code: `V2_ERR_TIMEOUT`; no other new codes.

## 6. Testing, gates, and proofs

- Host: `test_ipc_timeout.c` + existing IPC KATs unchanged.
- `verify.sh [1f]`: compile + run the new KAT.
- QEMU: new `TIMEOUT:` expiry markers + byte-identical legacy transcript.
- Proofs: `V2_C` timeout transitions for both ops (rendezvous-with-deadline)
  + integrity preservation; KAT names the new lemmas.

## 7. Risks

- Tick granularity (100ms) too coarse for some callers: budgets are minimum
  guarantees, documented; finer timers are future work, not a gap here.
- Expiry thundering (many waiters, one tick): flagged-only scan keeps it
  linear in timeout-parked threads, bounded by NTHREADS.
