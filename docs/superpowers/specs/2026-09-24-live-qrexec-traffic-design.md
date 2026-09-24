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
theorem; then thread-A live ask+deny legs synchronized by an
admin→A NOTIFY handshake (HELLO-first preserved)
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

### 3. Broker routing: rpc→service tables (rev 4 — collapsed-dst retired)

The S2-era convention (all rows `dst = QREXEC_QUBE = 1`, "collapsed-dst")
is stale: qube 1 is mem's qube today, so `svc_of_qube[1] = 2` routes
approved delivers to mem_server — the vault marker would be
unreachable. Retired and replaced (single source of truth per RPC):

- Rows carry the SERVICE qube as dst (keys.sign → 6 vault;
  clipboard → 6 vault with DENY; unwrap/rewrap → 6; format → 7
  cryptblk; net.send → 5; filter.reload → 4 — exact ids from the
  boot tables, reviewer checks each).
- New `rpc_svc[]` table (rpc → service qube, indexed by rpc id with a
  `<10` bounds-check else INVALID; AS-BUILT values verified against
  the broker's own rpc defines — an earlier draft misnumbered two
  entries):
```
rpc_svc[10] = {0, 6, 6, 5, 0, 4, 0, 6, 6, 7}
```
  (0 unused; 1 keys.sign→vault(6); 2 clipboard→vault(6)+DENY row;
  3 net.send→net(5); 4 INVALID — wire tag, no row; 5
  filter.reload→fw(4); 6 INVALID — wire tag, no row; 7 unwrap→vault;
  8 rewrap→vault; 9 format→cryptblk(7)). The broker looks up
  `qube_decide(pol, stamped_src, rpc_svc[rpc], rpc)` — the PROVEN
  lookup, unchanged call shape, so `Qubes_B` (`c_decide_eq`,
  `c_q_call_refines`) still models the C exactly — and delivers to
  `svc_of_qube[rpc_svc[rpc]]`. Audit records the resolved service dst
  (honest audit, not the collapsed constant).
- `QREXEC_QUBE` deleted if unreferenced after the switch (reviewer
  confirms), else left with a stale-convention comment ban.
- `T_ASK` SEND→EP4 and `T_DELIVER` SEND→resolved EP unchanged.

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

Ground truth from the 2026-09-24 boot transcript (rev-2 correction):
`QREXEC: admin registered` NEVER prints today — admin's HELLO SEND is
raw-gate DENIED (admin qube 3 holds no QX; `QUB: xread denied` right
after `ADMIN: up`), admin blocks in WAIT forever, and the broker,
vault, firewall, net servers sit RECV-blocked. The live broker path
has never run at all. Consequences pinned for this phase:

- TWO new QX grants (holder-based gate needs QX on every cross-qube
  sender): qube0 → qrexec (thread A's `T_CALL`s; A holds QX via the
  existing qube0 slot-9 root augment) and qube0 → admin (HELLO +
  `T_DECIDE`, tid 4 slot 9). Broker/vault/cryptblk/firewall/net keep
  their S3/FDE grants. No bound changes.
- HELLO-first is PRESERVED (no admin loop redesign): with addressing,
  admin SENDs HELLO→EP3 and either pairs with the waiting broker or
  queues + blocks until it RECVs — both orders work. The old deadlock
  (broker-SENDs-T_ASK vs admin-SENDs-HELLO) cannot recur: nothing SENDs
  until A calls, and by then admin is registered (see handshake).
- HANDSHAKE (rev 4 — call/response + admin RECV, corrects the
  `usend`-returns-reply error): `usend` returns `V2_OK` (0) on
  handoff, never the broker's reply code — replies are separate
  SENDs the client must RECV. So each leg is SEND (expect 0, park on
  nonzero) + RECV EP0 for the one-word reply (`[1]` = R_PENDING,
  `[-1]` = R_DENY; anything else → park marker-free). After printing
  `W1`, A WAITs a second time; admin SENDs HELLO→EP3, then RECVs EP4
  for the broker's `[R_OK]` reply (this closes a real deadlock: the
  broker's HELLO-reply SEND would otherwise embrace admin's WAIT
  forever); on `[0]` admin `NOTIFY`s tid 0 bit 2 (new 5-line NOTIFY
  wrapper) and enters the WAIT loop, else it falls into WAIT without
  notifying (A never wakes → FAIL, fail closed). A must not call
  before the NOTIFY (else the broker's `T_ASK` SEND has no waiter
  while admin is pre-registration). If admin never registers, A
  parks marker-free → gate FAILs.
- Vault deliver-switch (unchanged from rev 1): rpc==1 → print
  `VAULT: live ok`, no state change, no handoff; rpc==7 → existing
  handoff; else INVALID. Boot unlock uses rpc 7, so the marker is
  honest. Admin's cooperative put-back arm stays (dead but harmless —
  minimal diff; it can only trigger on EP4 misdelivery, which Phase 1
  makes unstatable).
- User.c constraint honored: thread A prints nothing new (immediates
  only, no literals); legs assert on SEND return (0) then RECV'd
  reply words (`[1]` after ask-enqueue, `[-1]` after clipboard) and
  park marker-free on any deviation. NOTE: never check the broker's
  reply in `usend`'s return — it carries only `V2_OK`/error.

Markers/gates (`verify.sh [4/4]`, +3 lines): `QREXEC: admin registered`
(now genuinely live — the first honest print of the broker path),
`VAULT: live ok`, `AUD: deny rpc=2`. Missing ⇒ FAIL. In-kernel model
demo untouched.

### Phase 2 error handling (fail closed)

| Case | Behavior |
|---|---|
| A calls before admin registers | Impossible by construction (A WAITs for the NOTIFY handshake) |
| Admin never registers / never NOTIFYs | A WAITs forever → parks marker-free → gate FAILs |
| New QX grants fail at boot | `[demo] FAIL` (S3/FDE shape), gate misses later markers → FAIL |
| Ask queue full (shouldn't be: single-flight) | Broker replies `R_DENY`, A parks marker-free → FAIL |
| `T_DECIDE` hash mismatch / bad idx | Broker deny-audits, no deliver, A parks marker-free → FAIL |
| Vault receives rpc≠1/7 deliver | INVALID, no print, no state change |
| Clipboard leg delivers (mustn't) | Defect by review (deny arm sends no forward; existing `test_qube_policy` deny pins); gate has no allow-marker so silence is the signal |
| Reply code mismatch at A (`R_PENDING`≠1, `R_DENY`≠-1) | A parks marker-free → FAIL |

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
- [ ] Phase 2: two QX grants (qube0→qrexec reused from FDE line for
      tid 3 + new qube0→admin tid 4), asserted fail-closed; admin
      HELLO→EP3, RECV EP4 for `[R_OK]`, NOTIFY(tid 0, bit 2), then
      WAIT loop; thread-A WAIT-post-`W1` then SEND+RECV legs
      (V2_OK-checked sends, `[1]`/`[-1]`-checked replies, marker-free
      park on deviation); broker `rpc_svc` routing (collapsed-dst
      retired, rows carry service dsts, audit honest); vault
      rpc-switch; `QREXEC: admin registered` + `VAULT: live ok`
      + `AUD: deny rpc=2` gated; full suite green, zero FAIL, no new
      SKIP.
- [ ] Docs: `V2_DESIGN.md` §9 / `QUBES_ISOLATION_PLAN.md` §11 deferred
      list shrinks (A flips to BUILT with paths + markers + lemma
      names); B/C/D stay listed with owners.
