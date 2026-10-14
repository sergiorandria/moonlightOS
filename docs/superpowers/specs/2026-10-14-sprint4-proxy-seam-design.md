# Sprint 4 — Service Interface Abstraction (proxy seam) — Design

Date: 2026-10-14. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 3 + follow-ups (protocol headers, constructors, registry,
`msg_valid`); `verify.sh` green modulo the known shell-build environment reds.
ROADMAP: Phase 3, Weeks 9–10 (Sprint 4 — Service Interface Abstraction),
scoped to approach B (proxy seam) per decision below.

## 1. Outcome and scope

Formalize the IPC boundary as a proxy seam: one generic `svc_proxy_t` +
`svc_call()`/`svc_cast()` in `lib/`, all lib-linked clients migrated to it,
host mocks behind the same seam. Goal is substitutability with testability:
swap a mock transport without touching call-site logic.

Locked decisions (chat-approved): full abstraction via approach B (proxy in
`lib/`); freestanding `v2_main.c` servers keep raw ecalls; no COM-style
factories/registries.

Explicitly out of scope: kernel changes, new threads/endpoints, capacity
bumps, Isabelle theory changes, versioned interfaces, `dlopen`-style
dynamics (non-goal per V2_DESIGN §1).

## 2. Architecture

`userspace/include/services/svc_proxy.h` defines `svc_proxy_t { unsigned ep;
const char *svc; }`, `svc_call()` (validate via `msg_valid` → SEND → block
for the kernel-stamped reply → payload or negative error) and `svc_cast()`
(validate → ASEND fire-and-forget). Both `static inline` over the existing
`moonlight_*` primitives. Host tests point the proxy at a mock dispatch table
with identical tag logic and canned replies; QEMU runs use real endpoints.
Wire bytes never change.

Constraints honored: NTHREADS=11, V2_NEP=11, V2_QUBES_MAX=9 — no bumps, no new
threads, no WCET re-analysis.

## 3. Components

1. `svc_proxy.h` — struct, `svc_call`, `svc_cast`, all header-inline.
2. Client migration — console/tty/gui/shell call sites move to the proxy, one
   service per commit, exact wire behavior preserved.
3. `tests/test_svc_proxy.c` (new, host) — call/reply matching (incl. message
   IDs), validation rejects, error propagation, mock canned replies per tag.

## 4. Data flow

Build: header-only, ships with `lib/`, no new translation units, no Makefile
changes. Runtime: typed constructors fill words → `svc_call()` validates →
SEND → stamped reply → payload/error; async paths use `svc_cast()`. Tests run
host-side against mocks; QEMU transcript byte-identical. Migration is
client-by-client; tree green throughout.

## 5. Error handling (fail-closed)

- Validation failure returns `-1` before any SEND; SEND errors propagate as
  negative codes (existing convention).
- Reply discipline unchanged (block for the stamped reply, no silent
  defaults); mock-vs-real divergence closed by construction (same
  constructors, same validator, transport endpoint differs only).

## 6. Testing and gates

- Host: `test_svc_proxy.c` + all existing KATs unchanged.
- `verify.sh [1f]`: compile + run the new KAT.
- `verify.sh [4/4]`: QEMU byte-identical (wire bytes unchanged).
- Isabelle: zero theory changes; anti-vacuity unaffected.

## 7. Risks

- Proxy/harness semantic drift (mock replies diverge from real servers):
  closed by driving mocks from the same constructors + validator.
- Partial migration (mixed direct/proxy call sites): each service migrates
  atomically per commit; KATs pin behavior at every step.
