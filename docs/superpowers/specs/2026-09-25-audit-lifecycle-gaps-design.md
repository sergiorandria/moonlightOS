# Audit-cap + lifecycle-alias gap closure (deferred-B/C/D)

**Status:** Design approved 2026-09-25, awaiting implementation plan
**Depends on:** S1/S2 BUILT (qube.h policy/audit, `Qubes_A/B`), live-qrexec
BUILT (addressed EPs, broker arms, `V2_C` indexed, Hsiao 44/44 smoke)
**Decides:** (B) fail-closed allow — no ALLOW without an audit record,
DENY needs none; (C) `T_DEAD` disambiguated to 3 with every state
comparison audited; (D) sweep of the 9 deferred minors
**Constraints (binding):** microkernel intact; NTHREADS=10,
V2_QUBES_MAX=8, V2_FRAMES_MAX=32, V2_NEP=10, V2_AUDIT_MAX=64 all
unchanged; `verify.sh` single entry (one new marker in `[4/4]`, no new
SKIP); C subset (bound comments, no float/fptr); fail closed;
`user.c` no-literals rule untouched (no user.c changes in this stage)

---

## 1. Goal

Close the two honest semantic gaps left open by prior stages plus the
9 deferred minors — no new features, no new threads/rows/RPCs.

**Theorems:** `audit_full_blocks_allow` (allow transitions require
audit room), deny-still-proceeds, preservation over the capped audit,
plus mutants/evals — in `Qubes_A` (model) with C-mirrors in `Qubes_B`.
`V2_A/B` impact assessed at build (expected none: abstract
runnability has no DEAD).

---

## 2. B — audit fail-closed allow

Today `qube_audit` returns OVERFLOW past 64 entries and every caller
ignores it: allows proceed unaudited. The spec audit lists are
unbounded, so model and C disagree silently.

### Components

- `kernel/qube.h`: helper pair beside `qube_audit`
  (single comparison each, header style, bound-free):
  `qube_audit_room(q)` = nonzero iff `q && naudit < V2_AUDIT_MAX`;
  `qube_audit_allow(q, s, d, r)` = room-check-then-append (OVERFLOW
  with zero state change when full, else the allow record). Split
  rationale: the allow-forward arm needs check-AND-append (replaces
  its `qube_audit(...,1)` — no double record), while the approve arm
  needs room-check WITHOUT appending (`qube_decide_idx` appends
  itself).
- Broker (`userspace/qrexec_server/v2_main.c`), exactly the two
  allow-actuating arms: allow-forward swaps its allow-record call for
  the helper — nonzero → existing deny-shape print
  (`AUD: deny rpc=`), `R_DENY` reply, no `T_DELIVER` SEND;
  approve-deliver checks room BEFORE `qube_decide_idx` — no room →
  `qube_decide_idx(idx, 0)` (dequeue, deny-record best-effort),
  deny-shape print, no SEND, no reply (decider never waits).
  Deny arms unchanged.
- kboot in-kernel self-test (S2-demo precedent, local `demo`
  struct): fill `naudit` to 64 via `qube_audit`, assert the 65th
  returns OVERFLOW with entries intact, assert helper refuses →
  print `AUD: full ok` (gated in `[4/4]`). Fail-closed legs print
  marker-free `[demo] FAIL` on deviation (existing discipline).

### Error handling

| Case | Behavior |
|---|---|
| Allow with full audit (live) | DENY reply, no delivery, no record (history stays complete by refusing to extend it silently) |
| Deny with full audit (live) | Denial proceeds; record attempt best-effort (safe direction) |
| Helper on null/edge | OVERFLOW/fail-closed (unreachable in practice — the broker always passes `&pol`; denial is the safe direction either way) |

### Testing (B)

- Host (`tests/test_qube_policy.c`, extended): fill-to-64, overflow
  preserves entries, helper refuses at cap, helper appends below cap.
- Smoke: `AUD: full ok` gated (model self-test); live full-audit
  denial is review-covered (demo holds ~5 entries — the path cannot
  trigger in 2-leg traffic by construction).
- Isabelle (`Qubes_A` + `Qubes_B` mirrors): `max_audit = 64`,
  `q_call`/`c_q_call` allow arms require room, deny arms don't;
  `audit_full_blocks_allow`, deny-still-proceeds, preservation,
  mutants (full-blocks-allow, drop-attempt-changes-nothing), evals.
  0 sorry, anti-vacuity as usual.

---

## 3. C — disambiguate T_DEAD

`T_DEAD == T_BLOCKED == 2` is safe today only through a
triple-conjunction (`state` + `wait_kind==NONE` + `ptr==0` + `cap==0`)
at 3 SPAWN/QDESTROY scan sites — one dropped conjunct in a future
edit reuses a live blocked server's slot.

### Components

- `kernel/kboot.c`: `#define T_DEAD 3`. Audit every `state ==`
  comparison in the file (enumerated by grep `T_BLOCKED|T_DEAD|state
  ==|state !=`): scheduler skip (DEAD skips like BLOCKED),
  halt-no-runnable detection (DEAD counts non-runnable), the 3 scan
  sites SIMPLIFIED to `state == T_DEAD` alone (the disambiguation's
  whole point — the conjunction becomes redundant), trap paths
  (verified read-only), WAIT/NOTIFY wake paths (verified `wait_kind`
  keyed, untouched unless the audit finds a state read).
- Proof impact assessed at `isabelle build`: `V2_A/B` model abstract
  runnability; if any lemma names the concrete values, replay
  minimally (bound-ripple rule). Expected: no theory change.

### Testing (C)

- Full `verify.sh` with a BYTE-IDENTICAL transcript gate: the
  existing `[4/4]` suite passing unchanged proves the value change
  altered nothing observable. Any marker drift = defect.
- Host: none (kboot not host-compiled). Isabelle: build clean or
  minimal replay per above.

---

## 4. D — minors sweep (deferred list, all may-ride)

1. `tests/test_v2ipc.c` bound comments on 4 loops (`:72,:75,:120`)
   + `kernel/ipc.h:102` (`/* bound: V2_IPC_Q */`).
2. `kernel/kboot.c` QDESTROY sweep re-indent under outer EP loop.
3. Stale "cooperative EP0"/"one static endpoint" comments
   (`adminvm`, server headers, `kboot.c:3`) → addressed-EP wording.
4. `docs/V2_DESIGN.md` S3 deferred "over EP0" → "over addressed EPs".
5. `V2_C.thy` duplicate `ipc_demo_same_ep` → delete or differentiate.
6. `V2_C.thy` snoop lemma: assert `ok1` (or `_`).
7. Broker T_DECIDE invalid-dst branch: add `qube_audit(...,0)` for
   consistency with the ALLOW arm.
8. Empty-take reply edge: REJECTED on implementation (correctly —
   the path is reachable: zero-length SEND is legal per `v2_len_ok`,
   RECV can return 0 with a live stamped sender, and bare `continue`
   would drop the reply and hang a rendezvous waiter). Current
   queuing behavior STANDS; no change.
9. `V2_C.thy` double-notify eval pins (take-and-clear, second WAIT
   re-blocks) — UABI wake-delivery KAT for the `regs[10]=pending`
   fix.

Each item is reviewable independently; none changes observable
behavior (item 8 provably unreachable — reviewer confirms or rejects
it out of the sweep).

---

## 5. Non-goals

S4 GUI, Stage 4 time/console, USB/RX-from-wire, prompter console, new
RPCs/rows/threads/qubes/endpoints, ring-overwrite audit, audit export
format, model changes beyond the audit cap + any DEAD-value replay.

---

## 6. Exit criteria

- [ ] B: helper + 2 broker arms + self-test marker `AUD: full ok`
      gated; host overflow tests green; `Qubes_A/B` cap model +
      theorems green, 0 sorry.
- [ ] C: `T_DEAD 3`, all state comparisons audited, scans
      simplified, transcript byte-identical, full suite green.
- [ ] D: all 9 items addressed or explicitly rejected with reviewer
      sign-off; full suite green, zero FAIL, no new SKIP.
- [ ] Docs: `V2_DESIGN.md` §9 + `QUBES_ISOLATION_PLAN.md` §11
      deferred-B/C → BUILT (paths + markers + lemma names); B/C/D
      leave the open list; no aspirational text.
