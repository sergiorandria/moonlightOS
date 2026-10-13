# Sprint 3 — IPC Protocol Modularization (boot-time registry) — Design

Date: 2026-10-13. Status: DESIGN (approved in chat §1–§5).
Depends on: Sprint 2 (service registry) merged; `verify.sh` green.
ROADMAP: Phase 2, Weeks 7–8 (Sprint 3 — IPC Protocol Modularization), full
scope per decision below.

## 1. Outcome and scope

Unify the scattered IPC message tags (`T_CALL`/`T_DELIVER`/`R_OK` today
re-`#define`d in qrexec, vault, cryptblk, firewall, …; `RPC_*` ids duplicated
across qrexec+firewall) into per-service protocol headers plus one shared
envelope header, enforced at runtime by a boot-time `{service, tag, max_len}`
registry with a shared `msg_valid(tag, len)` gate on every SEND/RECV path.

Locked decisions (chat-approved):
- Full Sprint 3 (headers + registry + helper refactor + all services migrated).
- Approach B: boot-time registry table (Sprint 2 manifest pattern), no runtime
  registration RPC, no broker-policed mutable surface.

Explicitly out of scope: kernel changes (no syscalls, no capacity bumps),
runtime tag registration, Isabelle theory changes, `services.h` tid-name
cleanup.

## 2. Architecture

`userspace/include/services/` gains one header per live service
(`qrexec_protocol.h`, `vault_protocol.h`, `cryptblk_protocol.h`,
`firewall_protocol.h`, `net_protocol.h`, `gui_protocol.h`,
`console_protocol.h`, `tty_protocol.h`) plus `ipc_tags.h` for the shared
envelope (`T_CALL`, `T_DELIVER`, `R_OK`/`R_PENDING`/`R_DENY`). A
build-emitted `msg_registry.h` (co-emitted by `tools/mkinitrd.sh`, same
generator pattern as Sprint 2's manifest) lists every `{service, tag,
max_len}` triple. `msg_valid(tag, len)` in `userspace/lib/` gates every SEND
site; unknown tag or oversize length fails closed before the ecall.

Constraints honored: NTHREADS=11, V2_NEP=11, V2_QUBES_MAX=9 — no bumps, no new
threads/endpoints, no WCET re-analysis.

## 3. Components

1. Per-service protocol headers — pure tag/arity constants plus `static inline`
   typed message constructors, each header including `ipc_tags.h`, owned by
   its service's directory.
2. Registry emitter — ~30 lines appended to the Sprint 2 emitter, reading a
   static hand-authored `TAGLIST` per service (tag meaning is policy, so the
   list is authored next to each server's `v2_main.c`, not derived).
3. `msg_valid` in `userspace/lib/ipc_helpers.c` — table scan with
   `/* bound: MSG_REGISTRY_LEN */`, nonzero only on exact tag + len-ok.
4. `tests/test_msg_registry.c` (new, host) — no tag collisions across
   services, every server tag registered, every registry row's service packed.

## 4. Data flow

Build: `mkinitrd.sh` emits manifest + registry → each server ELF compiles
against its protocol header + the shared registry → `msg_valid` linked from
`lib/`. Runtime: client builds via typed constructor → `msg_valid(tag, len)`
→ SEND; server RECV path re-validates before dispatch (compromised client
can't smuggle unregistered tags past either end). Servers migrate one at a
time (qrexec → vault/cryptblk → firewall/net → gui/console/tty); unmigrated
servers keep local defines, tree stays green throughout.

## 5. Error handling (fail-closed)

- Unknown tag / oversize length: rejected before SEND and before dispatch;
  existing deny-shape replies preserved, no new kernel paths.
- Registry/emitter failure: nonzero `mkinitrd.sh` exit, no partial header.
- KAT failure blocks `verify.sh` before QEMU.

## 6. Testing and gates

- Host: `test_msg_registry.c` (collision, registration, packed-service, and
  `msg_valid` accept/reject/boundary matrix).
- `verify.sh [1f]`: compile + run the KAT.
- `verify.sh [4/4]`: QEMU transcript byte-identical (validation rejects only
  traffic that never legitimately flows).
- Isabelle: zero theory changes; anti-vacuity unaffected.

## 7. Risks

- TAGLIST drift (hand-authored per service): closed by the KAT (every server
  tag registered, every row packed).
- Half-migrated tree: closed by per-server migration order with local defines
  intact until each server's task lands.
