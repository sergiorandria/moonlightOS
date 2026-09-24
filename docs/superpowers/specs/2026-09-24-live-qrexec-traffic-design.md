# Addressed endpoints + live qrexec traffic (S2/S3 deferred-A, rev 2)

**Status:** Rev 2 (2026-09-24): rev 1 assumed EP0 delivery; exploration
proved EP0 unaddressed (SEND hands to oldest waiter — mem_server would
eat thread A's `T_CALL`). Phase 1 builds addressed endpoints; Phase 2
drives the live legs on top. Approved direction A1; spec awaiting
re-review before implementation plan.
**Depends on:** S1 BUILT (raw gate, `Qubes_B`), Stage 2 BUILT (V2_C IPC
integrity, `ipc.h`/`test_v2ipc.c`), S2/S3/FDE servers + Qubes_C/D
**Decides:** per-thread endpoints (`V2_NEP` = 10, EP i owned by tid i);
RECV restricted to own EP; SEND validated + raw-gated to dst EP;
broker `svc_of_qube` table; V2_C endpoint-indexed with separation
theorem; then thread-A live ask+deny legs
**Constraints (binding):** microkernel intact; NTHREADS stays 10;
Qubes isolation intact; `verify.sh` single entry (new markers in
`[4/4]`, no new SKIP); C subset (bound comments, no float/fptr);
fail closed everywhere

---

## 0. Why Phase 1 exists (the EP0 finding)

`kernel/ipc.h` implements ONE static endpoint: `v2_q_send` appends to a
shared sendq, `v2_q_take_waiter` takes the oldest RECV waiter —
regardless of tags. `kboot.c` holds a single `static v2_ep_t ep0`.
Consequences, each verified against source:

1. Thread A SENDing `T_CALL` post-`W1` hands to thread 2 (mem_server,
   first to RECV-block), which consumes it as `REQ_ALLOC`. Wrong
   consumer, lost replies, eventual marker-free park.
2. The FDE `T_KEY`/`T_ASK` SENDs have the same latent misdelivery —
   masked today only because cryptblk derives TEST_KEYS locally and
   vault sits in RECV: the handoff SENDs never actually run.
3. No schedule ordering fixes this: every server RECV-blocks from
   boot, and pairing ignores message content.

The FDE spec referenced "ADDRESSED endpoints (§4.5)" — never written,
never built. This spec builds it.

---

## Phase 1 — Addressed endpoints

### 1. Goal

One endpoint per thread. A thread receives only on its own EP; anyone
may SEND to any EP subject to the existing raw gate (sender qube vs
owner qube + QX). Cross-endpoint delivery becomes unstatable: the
separation theorem says ops on EP i never touch EP j.

**Theorems (V2_C delta, all falsifiable):** existing integrity
theorems lifted per-EP (deliveries ⊆ same-EP sends, explicit
truncation) PLUS `ep_separation` (a send/recv on EP i leaves every
EP j≠i bit-identical) and `no_cross_deliver` (a RECV on EP j can only
return bytes queued on EP j). Mutants: cross-EP snoop (RECV on EP 5
with bytes queued on EP 3 returns nothing), foreign-EP RECV rejection
at the handler level (tested host-side + smoke, modeled as a guard).

### 2. Architecture

```
Endpoint i  <=>  thread i  (V2_NEP = 10 = V2_CAP_THREADS; EP count
rides the thread cap: any NTHREADS growth re-analyzes both together)

RECV(ep, ...):  require ep == cur tid, else V2_ERR_INVALID (no ambient
                receives; fail closed, no state change).
SEND(ep, ...):  require ep < V2_NEP (else INVALID) + existing raw gate
                with d = ep (qube_of[cur] vs qube_of[ep] + QX holder
                check, unchanged semantics) + existing copy discipline.
```

Syscall arity UNCHANGED: `V2_SEND (ep, u_ptr, len)` and `V2_RECV (ep,
u_buf, cap)` already take ep — only `v2_ep_ok` widens (`== 0` →
`< V2_NEP`) and the handlers index `eps[ep]`. QDESTROY sweeps all EPs
(existing per-EP sweep loop × `V2_NEP`, bound comment).

EP assignment (== boot tids, no table needed kernel-side):
A0 B1 mem2 qrexec3 admin4 fw5 net6 capscratch7 vault8 cryptblk9.
A↔B ping-pong migrates: A SENDs dst=1 / RECVs ep=0; B SENDs dst=0 /
RECVs ep=1. Same bytes, same markers (`B00pn`, `A10pg`, `W1` byte-
identical). Broker SENDs `T_DELIVER`/`T_ASK` to dst service EPs (see
§3); every server RECVs its own tid EP (one-constant edits).

### 3. Broker `svc_of_qube` table (U-mode, qrexec-owned)

The broker knows the dst *qube* (policy) but SEND needs a dst *tid*.
Table (mirrors boot wiring; each non-demo qube has exactly one
thread, so lowest-tid == only-tid == service):

```
svc_of_qube[8] = {0, 2, 3, 4, 5, 6, 8, 9}
                   ^  ^  ^  ^  ^  ^  ^  ^
                 q0 q1 q2 q3 q4 q5 q6 q7
```

q0 (demo qube) maps to 0 and is never a deliver target (no allow/ask
row has dst qube 0 — reviewer checks the row tables in
`qrexec_server`, `qube.h` boot policy, and the FDE rows 7–9).
`T_DELIVER` SENDs to `svc_of_qube[dst]`; out-of-range dst (≥8) or
q0-targeted deliver ⇒ INVALID + deny-audit, no SEND. `T_ASK` SENDs to
the admin EP (4) directly (unchanged constant, now addressed).

Kernel alternative (Invoke op resolving qube→svc tid) REJECTED:
U-mode table is 8 words, reviewed against boot wiring; a new syscall
for test-harness convenience violates YAGNI.

### 4. V2_C model delta (exact)

- State: `sendq`/`recvq` become per-EP lists. Minimal-diff form:
  `esendq :: "nat ⇒ (nat × nat list) list"`,
  `erecvq :: "nat ⇒ nat list"`, `max_eps = 10`; `c_send s dst m st`
  and `c_recv r own bl st` take EP indices with guards
  (`dst < max_eps`, `own = r` modeled as a guard premise).
- Every existing lemma replays with one extra index (same proofs +
  `max_eps_def`); new: `ep_separation`, `no_cross_deliver`,
  `recv_foreign_none` (RECV on EP j with empty EP-j queue returns
  none even when EP i is full — the snoop mutant), eval pins
  (same-EP round-trip, cross-EP invisibility, foreign RECV none).
- `Qubes_B/C/D` import `V2_C` for policy/queue shapes only — expected
  no changes; the build decides (bound-ripple rule from FDE Task 5:
  touch A/B/C only if the build breaks, minimal diffs).
- Anti-vacuity as usual: 0 sorry, no True-defs, mutant per new
  invariant, Allow+Deny still pinned.

### 5. Error handling (Phase 1, fail closed)

| Case | Behavior |
|---|---|
| SEND ep ≥ V2_NEP | `V2_ERR_INVALID`, no queue change |
| RECV ep ≠ cur tid | `V2_ERR_INVALID`, no waiter registered |
| SEND cross-qube w/o QX (d = dst EP) | existing raw-gate deny path, unchanged |
| Queue full (per-EP 16) | existing `V2_ERR_OVERFLOW`, unchanged |
| QDESTROY member with queued sends/waiters | existing sweep per EP (loop EPs, bound `V2_NEP`) |
| Broker dst qube ≥8 or q0 | INVALID + deny-audit, no SEND (U-mode guard) |

### 6. Testing (Phase 1)

- Host (`tests/test_v2ipc.c`, extended): EP isolation — SEND on EP3
  invisible on EP5 (RECV returns empty); waiter pairing per-EP
  (oldest waiter OF THAT EP); queue-full on one EP leaves others
  working; ownership-guard model (foreign RECV rejected).
- Smoke: existing transcript BYTE-IDENTICAL (A↔B migration proves
  addressing changed nothing observable) — same `[4/4]` markers, zero
  new markers in Phase 1. Any marker drift = defect in migration.
- Isabelle: `isabelle build` clean incl. replayed `V2_C` (+ ripple);
  anti-vacuity gates.

---

## Phase 2 — Live legs on addressed EPs (rev-1 design, adapted)

Client: thread A (qube 0) + one boot-minted QX grant (qube 0 →
qrexec), same S3/FDE grant shape, asserted fail-closed. No bound
changes. Legs: `keys.sign` ask → `T_DELIVER` to vault EP8 → vault
prints `VAULT: live ok` (rpc==1-gated; boot unlock uses rpc 7);
`clipboard` → DENY → `AUD: deny rpc=2`. User.c constraint honored:
no literals/globals in thread A (legs print nothing; immediates
only). Vault deliver-switch: 1 → marker, 7 → handoff, else INVALID
(rpc constants from the existing row tables).

Deadlock re-check under addressing (the rev-1 hole, now closed):
- A SENDs T_CALL→EP3: broker may not wait yet → queues + A blocks.
  Broker RECVs EP3 → takes it. No other consumer can see EP3.
- Broker SENDs T_ASK→EP4: admin may still be pre-registration.
  Admin startup change (REQUIRED, was implicit before): admin RECVs
  FIRST (blocks), takes T_ASK, THEN SENDs HELLO (broker RECVs EP3,
  registers, `QREXEC: admin registered` still prints — grep-gated,
  order-insensitive), then processes the already-held ask → SENDs
  `T_DECIDE`→EP3 → broker delivers → vault EP8 → marker. No cycle:
  each SEND has exactly one eventual waiter; single-flight.
- Broker `u_notify(admin_tid)` pre-registration: guarded by
  existing `admin_known` check (skipped, harmless — admin is already
  RECV-waiting by construction).
- Clipboard leg: broker DENYs with no SEND; A gets `R_DENY`, parks.
- Vault second-handoff: keys.sign deliver does NOT enter the handoff
  (rpc-switch) — re-entrancy question dissolves.

Markers/gates (`verify.sh [4/4]`, +2 lines): `VAULT: live ok`,
`AUD: deny rpc=2`. Missing ⇒ FAIL. In-kernel model demo untouched.

---

## 7. Non-goals (both phases)

Audit-cap modeling (B), lifecycle alias (C), demo-robustness (D),
prompter console, new RPCs/rows/threads/qubes beyond the one QX
grant, live allow leg, RX-from-wire, SMP, kernel Invoke-op for
qube→tid resolution.

---

## 8. Exit criteria

- [ ] Phase 1: `eps[V2_NEP]` + ownership/gate guards + QDESTROY sweep;
      A↔B migrated with byte-identical transcript; `test_v2ipc`
      EP-isolation green; `V2_C` replayed (+ separation theorems,
      mutants, evals) with 0 sorry; full suite green, no new markers,
      no new SKIP.
- [ ] Phase 2: one QX grant; thread-A legs live; `VAULT: live ok` +
      `AUD: deny rpc=2` gated; admin RECV-first + lazy registration;
      vault rpc-switch; full suite green, zero FAIL, no new SKIP.
- [ ] Docs: `V2_DESIGN.md` §9 / `QUBES_ISOLATION_PLAN.md` §11 deferred
      list shrinks (A flips to BUILT with paths + markers + lemma
      names); B/C/D stay listed with owners.
