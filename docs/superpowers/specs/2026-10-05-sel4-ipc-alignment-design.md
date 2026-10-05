# Full seL4 IPC Alignment — Detailed Description

Date: 2026-10-05 · Status: **description only, no code changed** ·
Branch: `feature/solid-sprint1-kernel-modularization`

This document describes what *full* alignment of MoonlightOS kernel IPC
with the seL4 microkernel's IPC design would entail. It is a reference
target, not an implementation plan: every dimension below is specified
as *seL4 shape → ours today → what full alignment means → impact*.
Dimensions with proof, ABI, or in-flight-work impact are flagged as such.
Nothing here authorizes code changes; see §8 (Open questions) and the
phased sketch in §7 before anyone schedules work.

Reference read in full for this document: seL4 `src/object/endpoint.c`
(`sendIPC`, `receiveIPC`, `cancelIPC`, `cancelAllIPC`,
`cancelBadgedSends`), `src/object/notification.c` (`sendSignal`,
`receiveSignal`, `cancelSignal`, `completeSignal`, bind/unbind), both at
upstream `master`, plus the seL4 whitepaper object model (10 object
types; capabilities as the only invocation path).

---

## 1. seL4 IPC architecture (reference)

**Objects, not syscalls.** Userspace never calls "the IPC subsystem";
it invokes *capabilities* to kernel objects. The two IPC objects:

- **Endpoint** (`endpoint.c`). States `Idle/Send/Recv`. An endpoint
  stores **no messages** — only a queue of blocked *threads* (TCB
  queue, head/tail). `sendIPC`: if a receiver waits (`Recv`), dequeue
  it and `doIPCTransfer` immediately (direct handoff, sender→receiver
  registers); else, if blocking, park the sender ON the endpoint
  (`BlockedOnSend`, state → `Send`). `receiveIPC`: symmetric, parks as
  `BlockedOnReceive` (state → `Recv`). `Call` = send + block-for-reply
  with a reply capability; `ReplyRecv` answers through it.
- **Notification** (`notification.c`). States `Idle/Waiting/Active`.
  Each thread may have one *bound* notification. `sendSignal`:
  waiting receiver → dequeue, deliver badge, run; no waiter →
  `Active` with **OR-accumulated badge** (signals coalesce, count is
  lost by design). `receiveSignal` on an `Active` object collects the
  badge and returns to `Idle`. No message payload, ever.
- **Badges.** The sender's identity arrives as a *badge word* minted
  per endpoint capability (plus `canGrant` rights for capability
  transfer). The receiver learns *who* without trusting the sender.
- **Cancellation.** `cancelIPC` (unblock one thread, dequeue, state →
  `Inactive`), `cancelAllIPC` (drain an endpoint, all waiters →
  `Restart`), `cancelBadgedSends`. Thread destroy always unwinds IPC
  state; nothing parks forever.
- **Scheduling.** State changes go through `setThreadState` +
  `possibleSwitchTo` (priority scheduler, immediate switch to a woken
  higher-priority thread). IPC *is* scheduling: rendezvous hands off.
- **Kernel minimalism.** No statistics, no deadlock tracker, no
  timeouts in the non-MCS kernel. Observability (benchmarks, traces)
  lives outside the kernel. The Haskell model + C + Isabelle proofs
  are kept in sync by CI gates (`Proof Sync`, C-parser checks); a
  kernel change without its model update fails the build.

---

## 2. MoonlightOS IPC today

| Piece | Files | Shape |
|---|---|---|
| Queue model (Isabelle `V2_C`) | `kernel/ipc.h` (191 lines, header-inline, host-tested) | `v2_ep_t`: `sendq[32]` message slots + `recvq[32]` waiter slots, `send_len/recv_len`, head indices; `v2_q_send/recv/wait/take_*` inline fns; `V2_MSG_MAX=4` words, `V2_IPC_Q=32`, `V2_NEP=11` (EP *i* owned by tid *i*) |
| Rendezvous dispatch | `kernel/syscall_ipc.c` (364): `sys_send/recv/notify/wait` (+yield/putc/park) | Validation → direct handoff to waiter (`u_copy_out` to stashed `ipc_ptr`) or queue + block (`T_BLOCKED`, `V2_WK_SEND/RECV`); woken peer entered directly (`enter_thread`) |
| Signals | same file (`sys_notify/sys_wait`) | Per-thread `notify` bits (OR-accumulate), `WAIT` takes-and-clears; wakes only `V2_WK_WAIT` sleepers (NOTIFY discipline) |
| Sender identity | stamped reply regs | Receiver gets `sender tid` (a1) + `sender qube` (a2) + `ovf` (a3); cross-qube gating via `qube_raw_ok` + `QX` grants |
| Monitoring (in-flight, other session) | `kernel/ipc_monitor.{h,c}` | Per-EP depth/counters/errors/flow/latency stats, `ep_stats[11]`, called from `sys_*` hot paths |
| Deadlock tracking (in-flight, other session) | `kernel/ipc_deadlock.{h,c}` | Wait-for graph (`edges[121]`), DFS cycle check, timeout ticks; `wait_begin/end` in `sys_*` |
| Lifecycle policy | `syscall_qube.c` QDESTROY comment | Park-forever for stranded waiters (no cancellation primitive) |
| Proofs | `kernel/isabelle/V2_C.thy` | `ipc_send/recv/notify/wait` validity + **boundedness** + integrity over the queued model |
| Gates | `tools/verify.sh` | Host model tests, `-Werror` build, ≤500-line module budget, QEMU transcript markers |

---

## 3. Dimension-by-dimension alignment

### D1 — File layout (lowest risk, do first)

- *seL4:* `src/object/endpoint.c` + `include/object/endpoint.h`
  (rendezvous), `src/object/notification.c` + `notification.h`
  (signals), dispatch in `src/api/syscall.c` + `src/kernel/thread.c`.
- *Ours:* mechanism split across `ipc.h` (model), `syscall_ipc.c`
  (policy+dispatch), `syscall.c` (trap shell).
- *Full alignment means:* `kernel/ipc_endpoint.{h,c}` owns the
  rendezvous mechanism (waiter queues, direct handoff, queue ops);
  `kernel/ipc_notify.{h,c}` owns signal bits, WAIT collection, and
  wake discipline; `syscall_ipc.c` shrinks to validation + dispatch
  into those two; `ipc.h` keeps only types/constants. The Isabelle
  model stays header-inline (proofs untouched); the `.c` files are
  policy relocation, byte-preserving.
- *Impact:* None on semantics/ABI/proofs. Mild collision risk with
  the in-flight monitor/deadlock hooks (they call into these paths;
  coordinate hook placement).

### D2 — Explicit endpoint state machine

- *seL4:* `EPState_Idle/Send/Recv` stored on the object; every
  transition asserts the legal predecessor (the `Haskell error`
  comments are proof obligations).
- *Ours:* state is *derived* (`send_len>0` ⇒ senders waiting,
  `recv_len>0` ⇒ waiters waiting); both queues can be non-empty
  simultaneously (queued messages + queued waiters coexist).
- *Full alignment means:* store one `ep_state` per endpoint,
  transition it on every enqueue/dequeue/drain, and assert
  predecessor states. As a consequence both-queues-nonempty becomes
  unrepresentable: a send rendez-vous with a waiter, else queues.
- *Impact:* **Proof impact** — `V2_C.thy` boundedness/integrity
  lemmas are stated over the two-queue model and must be restated.
  Behavioural: senders can no longer queue behind messages when
  waiters exist (today they can). All userspace servers that rely on
  queue-while-waiting must be re-audited (console/tty/gui/vault).

### D3 — Rendezvous-only transfer (no stored messages)

- *seL4:* endpoints never store payloads. If no peer waits, a
  blocking sender parks *itself* on the endpoint; a non-blocking
  send fails. Message data lives in transit (sender regs → receiver
  regs) or not at all.
- *Ours:* `sendq[32]` stores up to 32×4-word messages per endpoint
  (raised 16→32 "for burst tolerance"); receivers drain later.
- *Full alignment means:* delete `sendq`/`send_len`. `sys_send`
  becomes: waiter present → direct handoff; else block-on-send or
  fail (`V2_ERR_WOULDBLOCK`-class — new error, ABI addition).
  `sys_recv` becomes: sender present → take it; else block or fail.
  The `ovf`/truncation path disappears (no truncation without
  storage); flow-control threshold/notify-bit machinery goes with it.
- *Impact:* **Largest blast radius in this document.** Every
  userspace server is written against queued async delivery
  (fire-and-continue sends to TTY/console/GUI); all become
  rendezvous, changing liveness behaviour under load. The
  burst-tolerance design note is explicitly reversed. `V2_C`
  boundedness lemmas become vacuous and are replaced by
  rendezvous-safety lemmas (no lost wakeup, no double delivery).
  QEMU transcript markers that observe queueing change. Do last.

### D4 — Badges and sender identity

- *seL4:* receiver gets a `badge` word (per-endpoint minted identity)
  in the badge register + optional granted caps; `canGrant`
  distinguishes delegatable send rights.
- *Ours:* receiver gets `(sender_tid, sender_qube, ovf)` stamped by
  the kernel in a1–a3; cross-qube send rights via `QX` capability
  grants checked at both ends.
- *Full alignment means:* replace the triple with a single badge
  word whose high bits encode `(qube, tid)` and low bits a
  per-relationship nonce minted at grant time; move the qube check
  fully onto grant possession (QX ⇒ right to stamp that badge).
  Keep the qube label itself — seL4 has no counterpart; it is our
  isolation innovation, carried *in* the badge, not replaced by it.
- *Impact:* ABI break (a1–a3 contract changes for every server);
  proofs restated over badge unforgeability instead of stamp
  correctness. Medium risk, high clarity payoff. Requires the new
  error/ABI freeze to land with all servers at once (flag day).

### D5 — Notifications as bound objects

- *seL4:* one bound notification per thread, three states,
  OR-accumulated badge, `receiveSignal` collects-and-idles,
  `sendSignal` to a `BlockedOnReceive` thread completes it directly.
- *Ours:* very close already — per-thread `notify` bits,
  OR-accumulate, take-and-clear WAIT, wake-WAIT-only discipline.
- *Full alignment means:* reify the bits as `v2_ntfn_t` objects with
  `Idle/Waiting/Active`, one bound per thread, badge accumulate on
  signal, collect-and-idle on wait; `sendSignal`-style fast path
  that completes a `BlockedOnReceive` waiter instead of parking a
  bit for later collection. Our `notify` field becomes the object's
  `badge` storage.
- *Impact:* Low–medium. Semantics are already equivalent, so this is
  mostly D1-style relocation plus the bound-object invariant
  (one ntfn per thread) enforced at bind time. Proofs: restate WAIT
  lemmas over object states. This is the recommended *second* step
  after D1 (cheap, high fidelity).

### D6 — Cancellation primitives

- *seL4:* `cancelIPC` / `cancelAllIPC` / `cancelBadgedSends`;
  destroying a thread or endpoint always unwinds waiter state to
  `Restart`/`Inactive`. Nothing parks forever.
- *Ours:* documented park-forever policy for stranded waiters
  (`syscall_qube.c` QDESTROY comment); no cancel path; thread slots
  are reused with stale waiters drained only at reuse time.
- *Full alignment means:* add `ipc_cancel(tid)` (dequeue from
  whatever EP/ntfn it blocks on, state → parked-with-error) and
  `ipc_cancel_all(ep)` (drain on QDESTROY), wire both into
  QDESTROY and slot reuse, return a `V2_ERR_CANCELLED`-class error
  to woken waiters instead of leaving them stranded.
- *Impact:* New ABI error + new wakeup path in every server's IPC
  loop (all must handle cancellation). Proof addition (no stranded
  waiter invariant). Medium risk; unlocks safe dynamic
  spawn/destroy (Sprint 2's service registry needs this).

### D7 — Kernel minimalism (monitor/deadlock placement)

- *seL4:* zero in-kernel statistics/tracking; observability is a
  userspace trace consumer; the kernel's job ends at mechanism.
  Rationale: every kernel byte is trusted + proven; stats are
  neither.
- *Ours (in-flight):* per-EP stats arrays, wait-for graph + DFS +
  timeout ticks *inside* the kernel, on hot paths.
- *Full alignment means:* move both out: the kernel emits a minimal
  lock-free trace record per IPC event (or nothing — counters can be
  reconstructed), and a userspace trace server (e.g. in the vault or
  a new `trace` service) owns aggregation, deadlock detection, and
  reporting. Kernel keeps only hook *points* (already the
  `ipc_monitor_*` call shape — repurpose as trace emission).
- *Impact:* **Process, not just code:** another session is building
  these in-kernel *right now*. Full alignment reverses that
  direction — requires their agreement, or a joint decision to keep
  counters in-kernel as a documented deviation (§6). Do not start
  without that conversation. Proof impact is positive (smaller
  trusted base), service impact is a new consumer + trace ABI.

### D8 — Scheduling interface

- *seL4:* `setThreadState` + `possibleSwitchTo` (priority-ordered
  direct switch on wakeup).
- *Ours:* `threads[t].state/wait_kind` + `pick_next()` round-robin +
  `enter_thread()` direct switch (see `sched.c`, `syscall_ipc.c`
  handoff sites). Already structurally identical; only the policy
  (priority vs round-robin) differs, which is out of scope for IPC
  alignment.
- *Full alignment means:* nothing to change. Note the correspondence
  and move on.

### D9 — Verification sync

- *seL4:* Haskell model + C + Isabelle advance in lockstep; CI
  (`Proof Sync`, C-parser) rejects model-skewed changes.
- *Ours:* `V2_C.thy` + host model tests + `-Werror` + QEMU markers +
  (new) module-budget gate — but nothing ties an `ipc.h` change to
  its proof update.
- *Full alignment means:* a `verify.sh` (or CI) gate that fails when
  `kernel/ipc*.{h,c}` changes without the matching `V2_C.thy`
  diff — at minimum a checksum/prompt gate, ideally a
  proof-replay step. This is process, ships with any D2–D6 work.
- *Impact:* Process-only. No code risk.

---

## 4. What stays (no seL4 counterpart)

- **Qube labels + QX grants** (`qube.h`, `V2_C` qube lemmas): our
  isolation model; carried inside badges (D4), never removed.
- **Static initrd spawn at boot** (`elf_loader.c`, tids 1–10): seL4
  boots via an initial thread + CapDL/untyped retype; ours is
  static. Out of scope for IPC alignment.
- **Frame-word model** (`caps.h` fdata, `WRITE/READ` ops): memory
  model, not IPC. Untouched.
- **Bounded-queue burst tolerance**: a deliberate deviation kept
  *unless* D3 is explicitly adopted (flag day with proof replay).

---

## 5. Risk register

| # | Risk | Dimensions | Mitigation |
|---|---|---|---|
| 1 | `V2_C.thy` invalidation (validity/boundedness over queues) | D2, D3 | Restate-then-replay per phase; never land code ahead of lemmas (D9 gate) |
| 2 | ABI break across all servers (a1–a3, new errors, rendezvous liveness) | D3, D4, D6 | Single flag-day per dimension with all servers rebuilt; QEMU markers updated in the same commit |
| 3 | Collision with in-flight monitor/deadlock session | D1, D7 | Agree direction (in-kernel deviation vs trace-server move) BEFORE layout work; shared hook-point contract in the meantime |
| 4 | Queue-removal liveness regressions under burst load | D3 | Reproduce burst tests on host model first (`test_v2ipc` burst cases), then QEMU load markers, before deleting `sendq` |
| 5 | Transcript-gate churn (markers encode current semantics) | D2–D6 | Update `verify.sh` markers in the same commit as each semantic change; keep a `PROOF-SYNC`-style checklist in the spec PR |
| 6 | Over-alignment (copying MCS/sched-context/VM-async machinery) | all | Explicitly out of scope: no MCS, no SMP, no reply objects beyond `Call`-equivalent, no x86/ARM-VM paths (§4, §6) |

---

## 6. Deliberate deviations (adopted unless decided otherwise)

1. **Bounded queues stay until D3's flag day** — burst tolerance is
   load-bearing for console/TTY/GUI today.
2. **Monitor/deadlock placement is undecided** — in-kernel until the
   joint decision in D7; the hook-point shape is kept stable either way.
3. **No capability-addressed endpoints** — EP *i* owned by tid *i*
   stays; seL4-style CNodes/lookup are a different project (Sprint 5
   capability work may revisit).
4. **No priority scheduler** — round-robin `pick_next` stays (D8).

---

## 7. Phased adoption sketch (reference order, not scheduled)

1. **D1 layout** — move-only, zero semantics; proves the file map.
2. **D5 notifications** — closest semantics, cheap fidelity win.
3. **D9 gates** — lock model/proof sync before semantics move.
4. **D6 cancellation** — needs D1; unblocks dynamic lifecycle.
5. **D4 badges** — flag day with all servers.
6. **D2 states** — restate V2_C over explicit states.
7. **D3 rendezvous-only** — last: delete `sendq`, replay proofs,
   reload-tested under burst.

D7 is a parallel conversation, not a phase.

---

## 8. Open questions

1. Is D3 (queue removal) actually desired, or is bounded queueing a
   permanent MoonlightOS deviation? (Recommends explicit decision.)
2. D7 direction: in-kernel stats as documented deviation, or
   trace-server move — needs the other session's input.
3. Badge width/encoding (D4): 64-bit `(qube, tid, nonce)`?
4. Should `Call`-equivalence reuse SEND+RECV pairs or gain a reply
   primitive (D3/D6 interplay)?
5. Timing: align with Sprint 2 (service registry needs D6) or later?
