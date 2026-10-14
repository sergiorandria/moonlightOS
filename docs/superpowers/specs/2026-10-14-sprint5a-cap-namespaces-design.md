# Sprint 5a — Capability Namespaces as Policy Discipline — Design

Date: 2026-10-14. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 4 proxy seam; `verify.sh` green modulo the known shell-build
environment reds. Decomposed from ROADMAP Sprint 5 (Weeks 11–12): this spec
covers namespaces only; introspection, brokers, and proof updates are separate
spec cycles.
ROADMAP Sprint 5 goal carried: flexible permission management with proofs
passing — met by changing no proven behavior.

## 1. Outcome and scope

Per-service capability namespaces implemented as views over the single MDB in
`kernel/caps.h`, plus an attenuation rule in the derive path. The MDB layout,
revoke paths, and `V2_*` op numbers are untouched, so the Isabelle model
still describes the code and no proof replays.

Locked decisions (chat-approved): namespaces-only slice; policy discipline
(views + attenuation), not a structural table split; approach A (kernel-side
mask/view helpers, KAT-pinned).

Explicitly out of scope: structural MDB changes, revoke-path behavior
changes, new error codes, introspection queries, broker processes, proof
edits.

## 2. Architecture

`caps.h` gains `cap_ns_view(tid)` (visible set: own `caps[tid]` slots plus
slots reachable via explicit QX grants) and a derive-path attenuation rule
(QX drops on derive unless the caller holds QX with grant right — extending
the existing `V2_RIGHT_MEM_MASK`/`V2_RIGHT_IPC_GATE` split that already
separates the two meanings of `0x8UL`).

## 3. Components

1. `cap_ns_view()` + `cap_ns_grant()` in `caps.h` — pure, host-testable,
   bounded scans with `/* bound: */` comments.
2. Derive-path attenuation hook — 3 lines where rights are masked today
   (`caps.h:134` area).
3. `tests/test_capns.c` (new, host) — isolation (no cross-service visibility
   without grant), attenuation (derived caps lose QX), grant-chain
   transitivity, plus mutant rows per invariant.

## 4. Data flow

Build: header-only, no Makefile edits, no new translation units. Boot and
runtime: `kboot`'s grant sequence runs unchanged; over-scoped grants fail
closed with existing codes at existing call sites. The view is read-only over
the MDB (no allocation, no mutation, bounded time) — WCET reasoning
unaffected.

## 5. Error handling (fail-closed)

- Out-of-namespace access → existing `V2_ERR_INVALID`; no new codes or paths.
- Attenuation drops QX silently (W^X defensive-drop precedent), never fails
  the derive.
- Grants naming nonexistent namespaces fail at the existing bounds check.

## 6. Testing and gates

- Host: `test_capns.c` + all existing caps/qube KATs unchanged.
- `verify.sh [1f]`: compile + run the new KAT.
- QEMU: byte-identical transcript (views restrict nothing boot exercises).
- Isabelle: zero theory changes; the KAT names the `V2_D` lemma each rule
  mirrors, so future structural work knows what to replay.

## 7. Risks

- View/implementation drift (views promise what derive doesn't enforce):
  closed by testing attenuation and views in one KAT against shared helpers.
- Future structural work invalidating the no-replay claim: the KAT's lemma
  citations make the replay scope explicit when that day comes.
