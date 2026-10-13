# Sprint 2 — Boot-Time Service Registry (manifest-generated) — Design

Date: 2026-10-13. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 1 merged to dev (modular kernel, `verify.sh` green).
ROADMAP: Phase 2, Weeks 5–6 (Sprint 2 — Dynamic Service Registration), scoped
per decisions below.

## 1. Outcome and scope

Replace qrexec's hand-maintained routing tables (`svc_of_qube[8]`,
`rpc_svc[10]` in `userspace/qrexec_server/v2_main.c`) with a table generated
at build time from the initrd pack order. Adding a service becomes packing an
ELF — no table edits, no drift.

Locked decisions (chat-approved):
- Registry lives in userspace (qrexec broker). Kernel untouched.
- Boot-time catalog, immutable after boot (`.rodata`). No runtime
  registration RPC in this stage.
- Approach A (manifest-generated header).

Explicitly out of scope: kernel endpoint allocator / new INVOKE ops,
service migration, runtime register/unregister, `kernel/services.h`
unification (Sprint 1 banner stands until Sprint 2 follow-up).

## 2. Architecture

`tools/mkinitrd.sh` is already the single source of pack order (index → ELF).
It gains a manifest emitter writing
`userspace/qrexec_server/services_manifest.h`: one row per packed ELF as
`{name, initrd_index, tid, ep, qube}` (ep mirrors tid under the current
EP_OF_TID identity; carried as a separate field so the consumer never
re-derives it). qrexec includes the manifest instead of
its hand tables; broker policy and `T_DELIVER` paths are byte-identical in
behavior. `kernel/services.h` tid defines stay authoritative; a host KAT
asserts manifest tids equal them on every `verify.sh` run.

Constraints honored: NTHREADS=11 full, V2_NEP=11, V2_QUBES_MAX=9 — no bumps,
no new threads/endpoints, no WCET re-analysis, Isabelle theories unchanged.

## 3. Components

1. `tools/mkinitrd.sh` + manifest emitter. Reads the existing pack list,
   writes the header, fails closed (nonzero exit, no partial file) on
   duplicate names or tid >= V2_CAP_THREADS.
2. `userspace/qrexec_server/v2_main.c`. Deletes hand tables, includes the
   manifest. Policy logic untouched.
3. `tests/test_manifest.c` (new, host). Parses the emitted header; asserts
   row count == packed services, tid/EP/qube in bounds, names unique, tids
   match `kernel/services.h`, qubes <= V2_QUBES_MAX. Gated in `verify.sh [1f]`.

## 4. Data flow

Build: `make -C userspace` → `mkinitrd.sh` packs ELFs in fixed order →
manifest written → qrexec ELF compiles against it (Makefile dependency:
stale manifest triggers qrexec rebuild automatically).
Boot: kernel SPAWNs tids in pack order (unchanged); qrexec resolves dst
through the generated table over the existing addressed-EP path.

## 5. Error handling (fail-closed)

- Build: duplicate name / tid overflow aborts packing with nonzero exit.
- Boot/runtime: unknown RPC name takes the existing INVALID/no-row path
  (deny-shape print + `R_DENY`, never SEND).
- Schema drift (manifest vs `services.h`): KAT fails before QEMU runs.
- No new kernel error paths.

## 6. Testing and gates

- Host: `test_manifest.c` KATs + `test_qargs` round-trip unchanged.
- `verify.sh [1f]`: compile + run `test_manifest`.
- `verify.sh [4/4]`: QEMU transcript byte-identical (same tables, new
  provenance — broker behavior unchanged).
- Isabelle: zero theory changes; anti-vacuity gate unaffected.

## 7. Risks

- Build coupling: qrexec now depends on `mkinitrd.sh` output. Closed by the
  Makefile dependency + KAT.
- `services.h` drift: manifest tids vs kernel tid defines. Closed by KAT
  equality assert (same class as `test_abi_sync`).
