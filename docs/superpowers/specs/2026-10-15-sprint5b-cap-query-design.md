# Sprint 5b — Capability Introspection (read-only query ops) — Design

Date: 2026-10-15. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 5a namespaces (views + attenuation); `verify.sh` green.
Decomposed from ROADMAP Sprint 5 (Weeks 11–12): this spec covers query +
validate only; audit (append-only log, new state) is a separate spec cycle.
First spec in this line to touch the proof model.

## 1. Outcome and scope

Two read-only INVOKE ops exposing the MDB to userspace, which cannot map it
directly: `V2_INV_QUERY` (own slot → rights/obj/valid) and `V2_INV_CHAIN`
(slot → root derivation walk with depth). Both reuse existing gates, write no
state, and extend the `V2_D` model with read-only transitions.

Locked decisions (chat-approved): new query ops (not broker-side views);
approach A (query + validate now, audit deferred); numbers above today's max,
clear of qube 14/15.

Explicitly out of scope: audit log, broker processes, write paths, new error
codes, capacity changes, any change to MINT/GRANT/revoke behavior.

## 2. Architecture

New `V2_INV_*` numbers (above current max, avoiding 14/15) threaded through
`syscall_cap.c`'s `handles()` + dispatch. `V2_INV_QUERY` answers only own
slots — foreign slots return `V2_ERR_INVALID`, never contents.
`V2_INV_CHAIN` reports single-level lineage (the MDB stores no parent
pointers — only the `root` bit — so depth is 0 for roots, 1 for derived,
`-1` for invalid slots; capped by construction, never walked).

## 3. Components

1. `cap_query_slot()` + `cap_chain_depth()` pure helpers in `caps.h`
   (host-testable, bounded scans, fail-closed on bad holder/slot).
2. Two dispatch arms in `syscall_cap.c` (+ `handles()` cases).
3. `tests/test_capquery.c` — own-query contents, foreign denial, chain depth
   on granted/minted/attenuated chains, over-long termination, mutants.

## 4. Data flow

Build: two op numbers + arms, no ABI break for existing ops. Runtime: query
returns `(rights, obj, valid)` for own slots; chain reports 0/1/-1 as above.
Both reject foreign slots before touching them.

## 5. Error handling (fail-closed)

- Foreign slots → existing `V2_ERR_INVALID`; bad holder/slot → existing
  gates; over-long chains truncate explicitly, never loop.
- No new error codes; nothing written on any path, including failure.

## 6. Testing, gates, and proofs

- Host: `test_capquery.c` + existing caps/qube KATs unchanged.
- `verify.sh [1f]`: compile + run the new KAT.
- QEMU: new query/chain smoke markers + byte-identical legacy transcript.
- Proofs: `V2_D` read-only transition specs + refinement lemmas for both ops;
  the KAT names the exact new lemmas so replay scope stays explicit.

## 7. Risks

- Query oracle abuse (probing slot existence by error timing): both denials
  return the same code on the same path; no content-dependent timing
  introduced (constant-shape arms).
- Future audit work reinterpreting these transitions: read-only status is
  pinned by the refinement lemmas (no state change to build on).
