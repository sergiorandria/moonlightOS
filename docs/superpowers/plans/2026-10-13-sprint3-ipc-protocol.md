# Sprint 3 IPC Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify scattered IPC tags into per-service headers enforced by a generated boot-time registry with a shared `msg_valid` gate.

**Architecture:** Per-service `protocol_tags.def` files feed an `mkinitrd.sh` co-emitter writing `msg_registry.h`; a header-inline validator serves freestanding servers and a `lib/` wrapper serves linked services. Kernel, proofs, capacities untouched.

**Tech Stack:** Bash (emitter), freestanding rv64 C (headers/servers), host C99 KAT, `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-13-sprint3-ipc-protocol-design.md`

## Global Constraints

- No kernel changes, no Isabelle theory changes, no capacity bumps (NTHREADS=11, V2_NEP=11, V2_QUBES_MAX=9).
- Tags are EP-scoped: the same numeric tag on different services NEVER collides (different endpoints). Registry uniqueness is on `(service, tag)` pairs only.
- Small-tag space stays `< 0x1000`; `MSG_*` space stays `>= 0x1000` (disjoint by construction, KAT-pinned).
- All C compiles `-Werror`-clean; every new C loop carries a `/* bound: N */` comment.
- Freestanding-safe: `v2_main.c` servers include headers only, never libc-backed code.
- Fail-closed: unknown tag / oversize length denied before SEND and before dispatch.
- Path-scoped commits; generated `msg_registry.h` is an untracked build artifact like `services_manifest.h`.

## Review Focus

- Same numeric tag meaning different things on one service (e.g. a future `6` on firewall besides `T_FWD`): pinned by the per-service uniqueness KAT (Task 1), which rejects duplicate `(service, tag)` rows.
- Small-tag/MSG-space overlap (a small tag `>= 0x1000` or MSG below it): pinned by the space-disjointness KAT (Task 1).
- Unregistered tag sent at runtime: pinned by the `msg_valid` reject matrix (Task 2).
- Oversize length (`> V2_MSG_MAX` 4 words): pinned by the boundary KAT (Task 2).
- Stale registry consumed after TAGLIST edit: pinned by emission-before-build ordering in `verify.sh` plus the Makefile dependency (Tasks 1–2), mirroring the Sprint 2 manifest ordering fix.

## File Structure

- Create: `userspace/<svc>/protocol_tags.def` for qrexec_server, vault, cryptblk, firewall, net, adminvm, gui (one `NAME VALUE MAXWORDS` per line; console/tty/shell/mem use the `MSG_*` space via `ipc_protocol.h` and need no TAGLIST unless Task 1 inventory proves otherwise).
- Create: `userspace/include/services/ipc_tags.h` (shared envelope: `T_CALL 1`, `T_DELIVER 5`, `R_OK 0`, `R_PENDING 1`, `R_DENY -1`, plus `static inline msg_valid_inline`).
- Create: per-service `<svc>_protocol.h` headers beside each `v2_main.c` (tag defines + `static inline` constructors, including `ipc_tags.h`).
- Modify: `tools/mkinitrd.sh` (registry co-emitter), `userspace/lib/ipc_helpers.c` + `userspace/include/services/ipc_helpers.h` (`msg_valid` wrapper).
- Create: `tests/test_msg_registry.c`. Modify: `tools/verify.sh`, `userspace/Makefile` (deps).

Refinements vs spec (deliberate): (a) uniqueness is per `(service, tag)`, not global — tags are EP-scoped; (b) `msg_valid` core is header-inline (freestanding servers can't link `lib/`), `lib/` holds a wrapper only; (c) `RPC_*` ids stay policy inside qrexec/firewall (payload, not tags — same argument as Sprint 2's `rpc_svc` ruling).

---

### Task 1: TAGLISTs + registry emitter + failing-first KAT

**Files:**
- Create: `userspace/{qrexec_server,vault,cryptblk,firewall,net,adminvm,gui}/protocol_tags.def`
- Modify: `tools/mkinitrd.sh` (append co-emitter)
- Create: `tests/test_msg_registry.c`
- Modify: `tools/verify.sh` (run emitter before consumers + `[1f]` KAT block)
- Test: `tests/test_msg_registry.c`

**Interfaces:**
- Consumes: inventoried tag sets (qrexec 1-5; vault/cryptblk 1,5,8,10; firewall 1,5,6,7; net 6,7; adminvm 2,3,4; gui 6 FILL,9 COMPOSE — all MAXWORDS ≤ 4)
- Produces: `userspace/include/services/msg_registry.h` with `msg_reg_entry_t { const char *svc; unsigned tag, max_words; }`, `msg_registry[]`, `msg_registry_len`; ephemerally generated, never committed

- [ ] **Step 1: Confirm inventory, author TAGLISTs**
  Run: `grep -hn "#define T_[A-Z_]* " userspace/{qrexec_server,vault,cryptblk,firewall,net,adminvm}/v2_main.c userspace/gui/display.h`
  Expected: the sets above. For each service create `protocol_tags.def` with one `NAME VALUE MAXWORDS` line per tag (MAXWORDS from the message-shape comments: 4 unless the row documents fewer). If inventory shows extra tags, add rows; if a listed service has none, record why in the commit message and skip its file.

- [ ] **Step 2: Write the failing KAT**
  Create `tests/test_msg_registry.c`: includes the (absent) `../userspace/include/services/msg_registry.h`; asserts len nonzero, every row `tag < 0x1000`, `max_words` 1..4, pairwise `(svc,tag)` uniqueness (`/* bound: msg_registry_len */` loops), nonzero exit via CHECK macro, prints exact `PASS: test_msg_registry`.

- [ ] **Step 3: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_msg_registry tests/test_msg_registry.c`
  Expected: FAIL with `msg_registry.h: No such file`.

- [ ] **Step 4: Implement the co-emitter in `tools/mkinitrd.sh`**
  After the manifest block: for each `protocol_tags.def`, emit rows into `userspace/include/services/msg_registry.h` via staged tmp + `mv` (fail-closed: nonzero exit, no partial file, on dup `(svc,tag)`, `tag >= 0x1000`, `max_words` outside 1..4, or bad lines).

- [ ] **Step 5: Run emitter + KAT to verify pass**
  Run: `tools/mkinitrd.sh && gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_msg_registry tests/test_msg_registry.c && /tmp/test_msg_registry`
  Expected: `PASS: test_msg_registry`.

- [ ] **Step 6: Wire into `tools/verify.sh` with emission-before-build ordering**
  Emission must precede every consumer build (Sprint 2 ordering lesson): run `tools/mkinitrd.sh || { echo "FAIL: msg registry"; exit 1; }` before the qrexec build line in `[1e]`; add the KAT compile+run with `|| echo "FAIL: test_msg_registry"` idiom in `[1f]`.
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 7: Commit**
  ```bash
  git add tools/mkinitrd.sh tests/test_msg_registry.c tools/verify.sh userspace/*/protocol_tags.def
  git commit -m "feat(ipc): registry emitter + test_msg_registry KAT"
  ```

### Task 2: Shared headers + `msg_valid` both worlds

**Files:**
- Create: `userspace/include/services/ipc_tags.h`
- Create: per-service `<svc>_protocol.h` for the 7 TAGLIST services
- Modify: `userspace/lib/ipc_helpers.c`, `userspace/include/services/ipc_helpers.h`
- Test: `tests/test_msg_registry.c` (extended reject matrix)

**Interfaces:**
- Consumes: Task 1's `msg_registry.h` (row shape, `msg_registry_len`)
- Produces: `static inline int msg_valid_inline(const char *svc, unsigned tag, unsigned nwords)` (header, freestanding-safe, `/* bound: msg_registry_len */` scan, nonzero only on exact `(svc,tag)` + `nwords <= max_words`); `int msg_valid(...)` wrapper in `lib/` with identical semantics

- [ ] **Step 1: Write the failing reject-matrix extension**
  Append to `tests/test_msg_registry.c`: `msg_valid_inline("vault", 8, 4)` nonzero; `msg_valid_inline("vault", 99, 4)` zero; `msg_valid_inline("vault", 8, 5)` zero; `msg_valid_inline("nope", 1, 1)` zero. Include `../userspace/include/services/ipc_tags.h`.
  Run: KAT compile FAIL (`ipc_tags.h: No such file`). Expected: FAIL for that reason.

- [ ] **Step 2: Implement `ipc_tags.h` + per-service headers**
  `ipc_tags.h`: envelope defines (`T_CALL 1`, `T_DELIVER 5`, `R_OK 0`, `R_PENDING 1`, `R_DENY -1`) + `msg_valid_inline` over `msg_registry.h` (include it; stdint only). Each `<svc>_protocol.h`: its TAGLIST values as defines + `static inline` constructors + `#include "ipc_tags.h"`. Values verbatim from TAGLISTs.

- [ ] **Step 3: Add the `lib/` wrapper**
  Declare `int msg_valid(const char *svc, unsigned tag, unsigned nwords);` in `ipc_helpers.h`; define it in `ipc_helpers.c` as `return msg_valid_inline(svc, tag, nwords);`.

- [ ] **Step 4: Run KAT + `-Werror` builds to verify pass**
  Run: KAT chain from Task 1 Step 5 (expect `PASS: test_msg_registry`) and `make -C userspace build/qrexec.elf build/vault.elf build/cryptblk.elf`
  Expected: zero warnings, all ELFs link.

- [ ] **Step 5: Commit**
  ```bash
  git add userspace/include/services/ipc_tags.h userspace/*/*_protocol.h userspace/lib/ipc_helpers.c userspace/include/services/ipc_helpers.h tests/test_msg_registry.c
  git commit -m "feat(ipc): shared tags + msg_valid header-inline and lib wrapper"
  ```
  (Stage only the listed paths; never the generated registry.)

### Task 3: Migrate SEND/RECV sites per service

**Files:**
- Modify: each service `v2_main.c` (+ `display.h` consumers for gui) in order qrexec → vault/cryptblk → firewall/net → gui/console/tty
- Test: `tests/test_msg_registry.c` (unchanged) + QEMU smoke markers per service

**Interfaces:**
- Consumes: Task 2 headers + `msg_valid_inline`
- Produces: every SEND site gated by `msg_valid_inline`, every RECV dispatch re-validated; local tag defines deleted as each server migrates

- [ ] **Step 1: Migrate qrexec SEND + RECV dispatch**
  Replace local `T_*`/`R_*` defines with the protocol header include; gate both `u_send` call sites with `msg_valid_inline`; re-validate tag after RECV before dispatch. Keep `rpc_svc` policy untouched.
  Run: `make -C userspace build/qrexec.elf` (`-Werror` clean) + KAT still PASS.

- [ ] **Step 2: Migrate vault + cryptblk**
  Same pattern (tags 1,5,8,10; `T_KEY`/`T_KEY_ACK` grant-adjacent paths keep their semantics — gate validates, never bypasses).
  Run: both ELFs `-Werror` clean + KAT PASS.

- [ ] **Step 3: Migrate firewall + net, then gui/console/tty**
  Same pattern per service; gui covers `GUI_RPC_FILL`/`COMPOSE`; console/tty/shell already on `MSG_*` via `ipc_helpers` — switch their call sites to the `msg_valid` wrapper without changing message shapes.
  Run: `make -C userspace` (all + drivers) zero-warning.

- [ ] **Step 4: QEMU parity per service**
  Run: the stage-`[4/4]` QEMU block of `tools/verify.sh`
  Expected: transcript byte-identical to pre-migration baseline (validation rejects only traffic that never legitimately flows).

- [ ] **Step 5: Commit per service-group**
  One commit per group (`qrexec`, `vault+cryptblk`, `firewall+net`, `gui+console+tty`), each message `feat(ipc): migrate <group> to msg_valid gating`.

### Task 4: Full verification + review + merge-prep

**Files:**
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 1–3
- Produces: green baseline ready for merge

- [ ] **Step 1: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0; zero `^FAIL` lines; `PASS: test_msg_registry`; QEMU byte-identical; Isabelle PASS.

- [ ] **Step 2: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task range before merging. Fix Critical/Important findings first.

- [ ] **Step 3: Merge-prep (no merge without explicit approval)**
  Confirm worktree clean except untracked generated headers; report branch ready. Do not merge or push.
