# MINIX IPC Alignment — Detailed Description

Date: 2026-10-05 · Status: **description only, no code changed** ·
Branch: `feature/solid-sprint1-kernel-modularization`

Supersedes the seL4 direction (`2026-10-05-sel4-ipc-alignment-design.md`,
kept for reference): seL4's capability-addressed endpoints, badges, and
proof-driven minimalism would reshape our ABI and exile the in-flight
monitor/deadlock work. MINIX 3 is the suitable reference — its IPC is
structurally adjacent to ours (endpoint is a process number, fixed-size
messages, rendezvous + coalescing notifies, **in-kernel deadlock
detection**), so alignment is mostly renaming-and-placement rather than
reinvention. Same document shape as the seL4 one for comparability:
*MINIX shape → ours today → what full alignment means → impact*.

Reference read in full: MINIX `minix/kernel/proc.c` (`do_sync_ipc`,
`do_ipc`, `deadlock`, `mini_send`, `mini_receive`, `mini_notify`,
`mini_senda`/`try_one`, `has_pending_notify`, `delivermsg`,
`BuildNotifyMessage`) and `minix/include/minix/ipc.h` (fixed 56-byte
messages, `mess_*` typed union, `mess_notify`, grants).

---

## 1. MINIX IPC architecture (reference)

**Endpoints are process numbers.** An `endpoint_t` names a process
slot (plus generation); there are no capabilities. The kernel traps
are `SEND`, `RECEIVE`, `SENDREC`, `NOTIFY`, `SENDNB` (non-blocking),
`SENDA` (async batch) — dispatched by one function, `do_sync_ipc`,
which enforces, in order: known call number, valid endpoint
(`EDEADSRCDST`), per-caller IPC mask (`may_send_to`,
`ECALLDENIED`), per-caller trap mask (`ETRAPDENIED`).

**Rendezvous, threads queue — never messages.** `mini_send`: if the
destination `WILLRECEIVE`, copy the message into the receiver's
staged buffer and unblock it; else park the *sender* on the
destination's caller queue (`p_caller_q`). Payloads live in the
sender (`p_sendmsg`) until a receiver takes them. There is no stored
message queue. `mini_receive` drains in priority order: pending
notifications first, then async (`try_async`), then the caller queue,
else blocks (`RTS_RECEIVING`) — after a `deadlock()` check that
returns `ELOCKED`.

**Notifications coalesce in bitmaps.** `mini_notify`: waiter ready →
assemble a `NOTIFY_MESSAGE` (`BuildNotifyMessage`: zeroed message +
timestamp + pending-interrupt/signal sets) and deliver; else set the
caller's bit in the destination's `s_notify_pending` bitmap. No
payload, no blocking, no failure (except dead endpoint).

**Deadlock detection is in-kernel.** `deadlock()` walks the
`P_BLOCKEDON` chain before blocking; a cycle is `ELOCKED`, except the
benign 2-party SEND↔RECEIVE pairing. Detection runs at block time,
not on a timer.

**Messages are fixed-size and typed.** Every message is exactly 56
bytes (`_ASSERT_MSG_SIZE` enforced at compile time); `ipc.h` is a
typed union (`mess_u32`, `mess_vfs_readwrite`, `mess_notify`, …) so
each service speaks a named struct, never raw words.

**Delivery is deferred out of the trap path.** A received message
goes to a staged kernel buffer (`p_delivermsg` + `MF_DELIVERMSG`);
the copy to userspace happens at context-switch time
(`delivermsg()` in `switch_to_user`), where a fault suspends to the
VM server (`vm_suspend`) instead of nesting inside the trap. The trap
path itself never touches user pages on failure paths. `DEBUG_IPC_HOOK`
provides no-op-by-default observability call sites.

---

## 2. MoonlightOS IPC today

Same table as the seL4 doc, repeated for self-containment: `ipc.h`
(191 lines, `v2_ep_t` with `sendq[32]` message slots + `recvq[32]`,
`V2_MSG_MAX=4` words, `V2_NEP=11`, EP *i* owned by tid *i*);
`syscall_ipc.c` (398: `sys_send/recv/notify/wait` + yield/putc/park);
per-thread `notify` bits; `(sender_tid, sender_qube, ovf)` stamped
reply regs; in-flight `ipc_monitor.*` + `ipc_deadlock.*`;
park-forever stranded-waiter policy; `V2_C.thy` validity +
boundedness over the queued model; `verify.sh` gates. Copies run
**inside** the trap via `u_copy_in/out` under a SUM window after
range checks (`v2_send_range_ok`, `v2_recv_range_ok`).

---

## 3. Dimension-by-dimension alignment

### M1 — Function layout (lowest risk, do first)

- *MINIX:* `do_sync_ipc` (validate + dispatch) → `mini_send` /
  `mini_receive` / `mini_notify`, plus `mini_senda` batch. One file,
  `proc.c`, syscall-shaped names.
- *Ours:* `syscall.c` trap shell → `sys_send/recv/notify/wait` in
  `syscall_ipc.c`. Nearly identical already.
- *Full alignment means:* rename to the MINIX verbs
  (`mini_send/mini_receive/mini_notify`, `do_sync_ipc` for the
  dispatch shell) and move the WILLRECEIVE/CANRECEIVE gate
  conditions into named predicate helpers instead of inline
  `if`-chains. Pure rename + predicate extraction; zero semantics.
- *Impact:* None on behaviour/ABI/proofs. Touches the same lines
  the in-flight monitor hooks sit on — coordinate, don't collide.

### M2 — Fixed, typed messages

- *MINIX:* 56 bytes always, compile-time asserted; per-service
  structs in one header (`mess_vfs_readwrite`,
  `mess_linputdriver_input_event`, `mess_notify`, …).
- *Ours:* 4 raw words; `ipc_protocol.h` carries *all* message types
  for *all* services (the ISP violation in `SOLID_ANALYSIS.md`).
- *Full alignment means:* freeze the wire size (keep 4 words =
  32 bytes; no reason to adopt 56), add `_ASSERT_MSG_SIZE`-style
  static asserts, and split the protocol header per service with
  named structs (`msg_tty_write_t` exists in spirit — finish the
  job). This *is* Sprint 3 (IPC Protocol Modularization) with
  MINIX as its template.
- *Impact:* Service headers churn; kernel unchanged (it already
  moves opaque words). No proof impact (model is word-based).
  Recommended early: unblocks everything else.

### M3 — Address model and error taxonomy

- *MINIX:* endpoint validity (`isokendpt`), `ANY` receive-only,
  per-caller trap masks + IPC masks, and a real taxonomy:
  `EDEADSRCDST ECALLDENIED ETRAPDENIED ELOCKED ENOTREADY EINVAL`.
- *Ours:* `v2_ep_ok`, `ep != cur` self-check, qube/QX gating, and
  two errors (`V2_ERR_INVALID`, `V2_ERR_OVERFLOW`) plus ad-hoc
  park paths.
- *Full alignment means:* adopt the taxonomy
  (`EDEADSRCDST` for bad EP, `ECALLDENIED` for qube/mask denial
  instead of overloading INVALID, `ELOCKED` from the deadlock
  check instead of silent park, `ENOTREADY` for would-block
  receives), add per-thread trap masks (least-authority, mirrors
  `may_send_to` and composes with qubes), keep `ANY`-style receive
  semantics where they already exist.
- *Impact:* New error ABI (all servers' IPC loops updated in one
  flag day); proofs gain denial-case lemmas. Medium risk, high
  debuggability payoff — today's INVALID conflates four causes.

### M4 — Rendezvous + waiter queues (no stored messages)

- *MINIX:* sync IPC stores no messages; senders queue on the
  destination (`p_caller_q`), payloads stay in senders. Burst
  traffic uses the *separate* async batch path (`SENDA` +
  pending bitmaps), never the rendezvous path.
- *Ours:* `sendq[32]` stores messages (raised 16→32 "for burst
  tolerance"); the same structure serves sync and burst traffic.
- *Full alignment means:* the same decision as seL4-D3 with a
  MINIX-flavoured alternative: either delete `sendq` (pure
  rendezvous, burst via a new batch primitive), or keep `sendq`
  explicitly as the async path with rendezvous preferred on
  waiter-present (documented, not accidental). The honest
  description: our current code is already "rendezvous-first,
  queue-on-absence" — alignment renames that policy and (optionally)
  splits the structures so the two paths stop sharing one queue.
- *Impact:* Same blast radius as seL4-D3 if `sendq` is deleted
  (all servers, proofs, transcript markers). The split-without-
  delete variant is low risk and clarifies the active machine-fault
  surface (see M8).

### M5 — Notifications

- *MINIX:* per-privilege pending bitmaps, `BuildNotifyMessage`
  (timestamp + interrupt/signal sets), waiter-direct fast path,
  `has_pending_notify` checked first in `mini_receive`.
- *Ours:* per-thread bits, take-and-clear WAIT, wake-WAIT-only.
- *Full alignment means:* per-sender pending bits (so WAIT can
  select a source, like `has_pending_notify`), a
  `BuildNotifyMessage`-equivalent stamp (monotonic tick + source
  id instead of wall timestamp), and checking pending signals
  before waiter queues in `sys_recv` (MINIX order:
  notify → async → queue). Our second-in-line step after M1.
- *Impact:* Low–medium. Extends the WAIT ABI (source-select);
  restate WAIT lemmas. No queue-model change.

### M6 — In-kernel deadlock detection (validates in-flight work)

- *MINIX:* `deadlock()` chain walk at block time, `ELOCKED` on
  cycles, explicit 2-party SEND↔RECEIVE exception. ~60 lines,
  synchronous, no timers, no graph allocation.
- *Ours (in-flight):* wait-for graph (`edges[121]`), DFS + timeout
  ticks, larger state, async-flavoured.
- *Full alignment means:* keep detection in-kernel (MINIX
  legitimizes this against the seL4-doc's exile option), but adopt
  the chain-walk core: walk `blocked-on` links from the caller,
  `ELOCKED` on cycle-back, exempt direct 2-party pairing. Keep the
  graph/DFS only if it buys something the walk can't (it currently
  doesn't — walk is O(threads), DFS is O(edges), same bound here).
  Return `ELOCKED` to the caller instead of parking into a cycle.
- *Impact:* Shrinks the in-flight implementation toward the proven
  shape; converts silent parks into debuggable errors (M3
  taxonomy). Requires the other session's agreement — frame as
  convergence, not replacement.

### M7 — Deferred delivery out of the trap path (fault-relevant)

- *MINIX:* `MF_DELIVERMSG` — the trap stages the message in the
  kernel and returns; the user copy happens at switch time, where
  a fault suspends to VM instead of nesting. Trap path never
  deadlocks-or-faults on user memory.
- *Ours:* `u_copy_in/out` run *inside* `s_trap_handler` under SUM.
  A fault there nests inside the trap (entry re-entered with
  swapped `sscratch`), which matches the observed machine-fault
  signature (constant entry-`epc`, U-valued `stval`) currently
  under investigation.
- *Full alignment means:* stage-then-deliver: validate in-trap,
  stash `(dst, words, len)` in the endpoint/thread record, perform
  the user copy at `enter_thread`/`switch` time, and on copy fault
  park the *destination* with an error instead of nesting. Direct
  handoff keeps its fast path (copy while both peers are known
  runnable) but gains a fault guard that converts a nested trap
  into a parked peer + error code.
- *Impact:* Touches the hottest path (every IPC). Proof-positive
  (removes the nesting hazard class); behaviour identical on
  success paths. **Do only after the active fault is root-caused**
  — this changes the exact code under investigation. Highest
  value, highest care.

### M8 — Observability hooks

- *MINIX:* `DEBUG_IPC_HOOK` (`hook_ipc_msgsend/msgrecv`) —
  compiled-out by default, zero cost, zero state in kernel.
- *Ours (in-flight):* always-on counters/graphs in kernel memory.
- *Full alignment means:* keep the hook *call sites* (they mark
  exactly the right places), but put the state behind a
  compile-time flag defaulting off, mirroring `DEBUG_IPC_HOOK`,
  until the D7-style consumer story (trace server vs in-kernel)
  is decided with the other session.
- *Impact:* Near-zero risk (preprocessor + init gating); removes
  hot-path cost and uninitialized-state risk from production
  builds while keeping the instrumentation available.

---

## 4. What stays (no MINIX counterpart)

- **Qube labels + QX grants**: our isolation model; composes with
  masks (M3), never replaced.
- **Static initrd spawn, frame-word model, EP==tid wiring**:
  boot/memory design, out of scope.
- **`sendq` depth policy**: kept until M4 is explicitly decided.

---

## 5. Risk register

| # | Risk | Dimensions | Mitigation |
|---|---|---|---|
| 1 | In-flight collision (monitor/deadlock/format sessions) | M1, M6, M8 | Shared hook-point contract first; frame M6/M8 as convergence |
| 2 | M7 changes code under active fault investigation | M7 | Root-cause first; M7 lands after, verified against the same repro |
| 3 | Error-ABI flag day across servers | M3 | Single commit with all servers + markers, like D4 in seL4 doc |
| 4 | `sendq` removal liveness regressions | M4 | Host burst tests → QEMU load markers before deleting |
| 5 | Over-alignment (SENDA batch, VM server, privileges) | all | Explicitly out: no async-batch primitive, no VM server, no priv structures (§4 analogues) |

---

## 6. Phased adoption sketch

1. **M1 verbs + predicates** — rename-only, proves the map.
2. **M2 typed messages** — is Sprint 3 with a template.
3. **M5 notifications** — cheap fidelity win.
4. **M3 errors + masks** — flag day with servers.
5. **M6 deadlock convergence** — with the other session.
6. **M8 hook flags** — any time, near-zero risk.
7. **M4 queue decision** — load-tested before deleting.
8. **M7 deferred delivery** — last, after the fault is closed.

---

## 7. Open questions

1. `sendq`: delete (rendezvous-only), split (async path), or keep?
2. M6/M8 vs the in-flight session: converge now or document-deviate?
3. Badge/word for sender identity — keep the `(tid, qube, ovf)`
   triple or compress (cf. seL4-doc D4)?
4. M7 sequencing relative to the active machine-fault hunt?
5. Error numbers: adopt MINIX negatives (`-ELOCKED`) or extend
   `V2_ERR_*` positives?
