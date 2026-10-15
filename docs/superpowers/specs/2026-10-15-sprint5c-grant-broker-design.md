# Sprint 5c — Capability Broker Gate (QX grant policy) — Design

Date: 2026-10-15. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 5a namespaces, Sprint 5b query ops; `verify.sh` green.
Decomposed from ROADMAP Sprint 5 (Weeks 11–12): this spec covers broker
policy mediation only; audit-log persistence (if ever wanted) is a separate
spec cycle. Last spec of the Sprint 5 decomposition (namespaces, query, broker).

## 1. Outcome and scope

Cross-namespace capability grants become policy-mediated and audited: when
granter/grantee qubes differ and requested rights carry QX, `v2_grant`
consults a static allow-matrix (default-deny) and records allows in a bounded
audit ring. Same-qube and non-QX grants flow verbatim.

Locked decisions (chat-approved): kernel gate (not cooperative broker);
approach A (QX-gated + audited, qube-policy shape).

Explicitly out of scope: broker suspension/ASK flows, audit persistence
across boot, new syscalls or error codes, capacity changes, any change to
MINT/revoke/query behavior.

## 2. Architecture

`v2_grant` gains the policy gate before the copy: cross-qube + QX grants
check `grant_policy.h` (first-match-wins, default-deny, bounded at 32 rows);
allows append a 64-entry audit record (fail-closed deny when full — the
audited-allow discipline); denies return `V2_ERR_INVALID` with no state
change. The `V2_D` model gains the gate condition + audit preservation; no
new syscalls.

Constraints honored: the all-qube-0 boot is behavior-identical (gate never
fires); NTHREADS=11 and all caps bounds unchanged.

## 3. Components

1. `grant_policy.h` (new, host-testable) — allow-matrix type, `grant_decide()`
   first-match evaluation, bounded audit ring with `audit_room`/`audit_allow`
   split mirroring `qube.h`.
2. `v2_grant` gate hook — policy check + audit append atop the existing
   validation sequence, ~10 lines.
3. `tests/test_grant_policy.c` (new, host) — allow/deny matrix, default-deny,
   audit-full fail-closed, same-qube passthrough, mutants.

## 4. Data flow

Build: header-only policy + hook, no new translation units, no ABI change
(same op, args, reply shape). Runtime: every grant passes the gate first;
the audit ring is per-boot volatile. Policy rows are compiled in — updates
ship with the kernel image, never at runtime.

## 5. Error handling (fail-closed)

- Denied grants → existing `V2_ERR_INVALID`, zero state change; denials are
  best-effort recorded (qube deny-arm precedent).
- Full audit ring → deny (never silent allow).
- Malformed policy rows → build-time static assert, never a runtime surprise.

## 6. Testing, gates, and proofs

- Host: `test_grant_policy.c` + existing caps/qube KATs unchanged.
- `verify.sh [1f]`: compile + run the new KAT.
- QEMU: new `GRANT:` allow/deny smoke markers + byte-identical legacy transcript.
- Proofs: `V2_D` gate condition on the grant transition + audit-boundedness
  preservation (allow implies record; full ring blocks allow).

## 7. Risks

- Policy expressiveness (static matrix vs future dynamic needs): compiled-in
  rows cover the fixed 11-thread/9-qube system; dynamic policy is a future
  spec, not a gap in this one.
- Audit-ring pressure under grant bursts: 64 entries with fail-closed deny
  degrades to denial, never to unaudited allow — the safe direction.
