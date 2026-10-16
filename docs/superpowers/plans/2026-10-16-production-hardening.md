# MoonlightOS Production Hardening — Phased Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn MoonlightOS from an unverified prototype into a system whose core guarantees (isolation, liveness, security policy, correctness) are actually enforced and actually tested.

**Architecture:** Six phases, ordered by dependency. Phase 0 makes the verification gate capable of failing, because every later phase must be *provable*. Phase 1 enforces kernel isolation (the property the docs already claim). Phase 2 makes the capability/qube security model functional. Phase 3 fixes cross-cutting correctness bugs. Phase 4 removes facades and dead duplicates. Phase 5 hardens process (CI, static analysis, proof/model linkage). Each phase ships working, testable software on its own.

**Tech Stack:** RISC-V RV64 (`rv64imac`), freestanding C, clang + lld, QEMU `virt` + OpenSBI, Isabelle/HOL, bash test harness.

**Spec:** `docs/PRODUCTION_READINESS.md` (findings + requirements `R#.#`). The plan argues from that spec; executors read both.

## Global Constraints

- Kernel C is `--target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -Wall -Wextra -Werror`.
- Every S-mode kernel TU ≤ 500 lines; `kboot.c` ≤ 200. Derive the checked list from `SRC_C`, never hand-maintain it.
- No new threads/endpoints without a capacity review (`NTHREADS=11` is full today). Adding a service tid means editing `mkinitrd.sh`, `caps.h`, `vm.c`, and the gate together.
- Never dereference a user pointer in S-mode without an explicit range/alignment check (`V2_INV_ELF_CHECK` currently violates this).
- Host-compilable test vectors are mandatory for every kernel-adjacent change (TDD). Ground protocol/mechanism changes in the upstream reference (RFC, VirtIO spec, EL List) and cite it in the comment.
- One concern per commit; conventional-commit messages; path-scoped (`git add <file>`), never `git add -A`.
- The single gate is `tools/verify.sh`. It MUST be able to fail. A change is not done until the gate is green *and* a deliberate fault is shown to make it red.
- Docs and comments MUST NOT claim a property the code does not implement.

## Review Focus

The five input classes / failure modes most likely to bite a user or reviewer, each pinned to the task that owns its test:

1. **A host test that fails while the gate exits 0** → Task 0.1 (gate fail-aggregation).
2. **One U-mode thread reading/writing another thread's stack** → Task 1.1 (`test_v2ipc` per-thread-stack isolation vector).
3. **A padded 60-byte TCP frame (bare ACK) at the socket seam** → Task 3.6 (`test_tcp` padded-frame vector).
4. **An oversized attacker-controlled IPC `len` delivered to console/tty** → Task 3.8 (`test_console_gui_layout` / a new tty vector).
5. **A huge allocation size `malloc(SIZE_MAX - k)`** → Task 3.2 (`test_libc` overflow vector).

## Execution model

Phase 0 is specified below at full TDD task/step granularity. Phases 1–5 are specified as
task lists with the exact test that proves each requirement; **each phase MUST be expanded
into its own `docs/superpowers/plans/…-phaseN-*.md` before it is executed** (per the
writing-plans scoping rule — they are independent subsystems). Requirement IDs in each
phase header map to the spec.

---

## Phase 0 — A gate that can fail (keystone)

**Implements:** R0.1–R0.7. **Why first:** every later phase is proven by this gate.

**Files:** `tools/verify.sh`, `tools/mkinitrd.sh`, `kernel/Makefile`, `kernel/kboot.c`, `kernel/elf_loader.c`.

### Task 0.1 — Fail-aggregation for host tests

**Files:** Modify `tools/verify.sh` (§1a–§1f).

**Interfaces:**
- Produces: shell helpers `run_test <label> <cmd...>` and `run_optional <label> <cmd...>`; a `FAILED` counter; the script exits non-zero if `FAILED > 0`.

- [ ] **Step 1: Reproduce the bug.** Run `bash -c 'set -e; false || echo "FAIL"; echo reached'` → prints `FAIL` then `reached`. Confirm `tools/verify.sh` uses this pattern (`verify.sh:12-57`).
- [ ] **Step 2: Harden the shell.** Change line 2 to `set -euo pipefail`. Replace every `gcc … && /tmp/x || echo "FAIL: x"` with `run_test x gcc -o /tmp/x … && /tmp/x` (function records failure + `FAILED=$((FAILED+1))`, never masks). **All host tests are fatal** — including `test_vfs` (verified: every currently-masked test passes today). `run_optional` is for environment-optional stages only (the `command -v clang`-guarded `make` steps), which print `SKIP`.
- [ ] **Step 3: Aggregate.** Before the summary block, `if [ "$FAILED" -ne 0 ]; then echo "FAILED=$FAILED"; exit 1; fi`.
- [ ] **Step 4: Prove it fails.** Inject a fault: add the line `run_test _probe false` under §1b, run `tools/verify.sh`, assert it exits non-zero and prints `FAILED=1`. Revert.
- [ ] **Step 5: Prove it passes.** Run `tools/verify.sh` on the clean tree, assert exit 0.
- [ ] **Step 6: Commit** `test(gate): fail verify.sh on any host-test failure`.

### Task 0.2 — No stale-ELF pass

**Files:** Modify `tools/verify.sh` (build stage, §1f/§3).

- [ ] **Step 1: Delete artifacts first.** Before `make -C kernel`, `rm -f kernel/build/moonlight.elf`; if the build fails, the §4 QEMU block must see no ELF and report `FAIL` (not `SKIP`).
- [ ] **Step 2: Make build failure fatal.** Already delivered by Task 0.1's fix round (`make -C kernel` under `run_optional` + `pipefail`; an `ISABELLE_STATUS`/`CHERI_STATUS` of `FAIL` is fatal). Verify it is in place; do not re-implement.
- [ ] **Step 3: Prove it.** Break a kernel source line, run the gate, assert non-zero and that §4 reports `FAIL` (not a boot from a stale ELF). Revert.
- [ ] **Step 4: Commit** `test(gate): rebuild kernel from clean; fail on build error`.

### Task 0.3 — Regenerate the initrd in-gate

**Implements:** R0.6. **Files:** Modify `tools/verify.sh`, `kernel/Makefile`.

- [ ] **Step 1: Add the dependency.** In `kernel/Makefile`, make `initrd_data.c` depend on `../userspace/build/*.elf` (or add a top-level rule that runs `tools/mkinitrd.sh`), so `make -C kernel` regenerates it when an ELF changes.
- [ ] **Step 2: Staleness check in the gate.** In `verify.sh`, after building userspace, run `tools/mkinitrd.sh` and `git diff --exit-code -- kernel/initrd_data.c`; a diff sets `FAILED`.
- [ ] **Step 3: Prove it.** Touch a userspace source, rebuild, run the gate, assert it regenerates and stays green; then hand-edit one byte of `initrd_data.c` and assert the gate fails. Revert.
- [ ] **Step 4: Commit** `build(initrd): regenerate from ELFs and gate staleness`.

### Task 0.4 — Gate the code that ships

**Implements:** R0.3. **Files:** Modify `tools/verify.sh`; the commands below are verified to build and pass on the current tree.

**Interfaces:** Produces the per-test commands (all `run_test`-wrapped):
- `gcc -O2 tests/test_shell_readline.c -o /tmp/test_shell_readline && /tmp/test_shell_readline`
- `gcc -O2 -no-pie tests/test_moonsh_busybox.c -o /tmp/test_moonsh && /tmp/test_moonsh`
- `gcc -O2 tests/test_elf.c -I userspace/include -I kernel -I userspace/abi -I userspace/libc/include -I userspace/net -o /tmp/test_elf && /tmp/test_elf`
- same flag set for `test_frames`, `test_tcp`, `test_ipc_integration`, `test_qube_destroy_auth`, `test_blk_hal`, `test_console_gui_layout`.

- [ ] **Step 1: Add the commands listed above (nine suites)** to §1f, wrapped in `run_test`. The list is authoritative; verify each builds and passes with exactly those flags (adjust a suite's flags only to make it compile, and note the change).
- [ ] **Step 2: Remove the dead-shell lines.** Delete the `test_shell`/`test_shell_vfs` lines that link `userspace/sh/shell.c` (§1b). (Deleting `shell.c` itself is Phase 4.) Confirm `shell_core.h` coverage now comes from `test_moonsh_busybox` + `test_shell_readline`.
- [ ] **Step 3: Prove it.** Run the gate; assert all new tests PASS and exit 0. Then break one assertion in `test_tcp.c` and assert the gate fails. Revert.
- [ ] **Step 4: Commit** `test(gate): cover the shipping shell engine and nine ungated suites`. Track the files this task gates (`git add tests/test_blk_hal.c tests/test_console_gui_layout.c tests/test_ipc_integration.c tests/test_shell_readline.c`) so the gate does not depend on untracked files.

### Task 0.5 — Anchored, honest QEMU markers

**Implements:** R0.4. **Files:** Modify `kernel/kboot.c`, `tools/verify.sh`.

- [ ] **Step 1: Print "services up" only on success.** In `kboot.c`, capture each `elf_loader_spawn(...)` return; print `Services: … up` only if all seven returned 1, else print `Services: INCOMPLETE` and set a non-zero flag consumed by the gate.
- [ ] **Step 2: Anchor markers.** Replace `grep -q "NP"` (`verify.sh:211`) with an exact anchored match of the real negative-pass line, and anchor every other marker (`grep -qxF`). Delete the `NP` shortcut if it has no exact source line; add one if a real negative test prints it.
- [ ] **Step 3: Prove it.** Force one spawn to fail (e.g. temporarily point `mkinitrd.sh` at a missing ELF) and assert the gate reports `FAIL (services incomplete)`. Revert.
- [ ] **Step 4: Commit** `test(gate): anchored markers; services-up only on full success`.

### Task 0.6 — Per-service liveness round-trips

**Implements:** R0.5. **Files:** Modify `kernel/user.c` (or a boot self-test), `tools/verify.sh`.

- [ ] **Step 1: Add a boot-time ping.** For each spawned tid (1,3,4,8,9,10), have the shell/boot self-test send a one-word ping and require a reply word from that tid; print `LIVE: tid=N ok` per responder.
- [ ] **Step 2: Gate on it.** In `verify.sh`, require `LIVE: tid=N ok` for each service (anchored), replacing the `[spawn] X ELF ok` markers (which only prove loading).
- [ ] **Step 3: Prove it.** Temporarily make one service's main return immediately after spawn; assert the gate fails for that tid. Revert.
- [ ] **Step 4: Commit** `test(gate): per-service IPC liveness round-trip`.

### Task 0.7 — Line-count gate derives its list

**Implements:** V4 (findings). **Files:** Modify `tools/verify.sh`.

**Interfaces:** The kernel-TU line-count check reads its file list from `kernel/Makefile`'s `SRC_C`/`SRC_S`, so a newly added TU is checked automatically.

- [ ] **Step 1: Reproduce.** Add a temporary ~501-line TU to `SRC_C`, run the gate, confirm it still passes (the hard-coded check omits it) — the bug.
- [ ] **Step 2: Derive the list.** Read `SRC_C`/`SRC_S` from `kernel/Makefile` (parse the makefile; do not hand-maintain) and check every TU ≤ 500 lines (`kboot.c` ≤ 200).
- [ ] **Step 3: Prove it.** Re-add the 501-line TU; assert the gate fails. Remove it; assert green. Revert.
- [ ] **Step 4: Commit** `test(gate): derive the kernel line-count check from SRC_C`.

### Phase 0 exit criteria

`tools/verify.sh` exits non-zero on any single injected fault in: a host test, the kernel build,
the Isabelle build, the initrd staleness check, an over-long kernel TU, a missing spawn, and a
missing liveness round-trip — and exits 0 on the clean tree. The nine newly gated suites run. No
artifact can satisfy the smoke from a previous run.

---

## Phase 1 — Isolation & memory safety

**Implements:** R1.1–R1.8 (findings K1–K7, D1, D3). **Own plan required.**

**Files:** `kernel/vm.c`, `kernel/elf_loader.c`, `kernel/syscall_proc.c`, `kernel/syscall_qube.c`, `kernel/irq.c`, `kernel/kboot.c`, `kernel/linker.ld`; tests `tests/test_v2ipc.c`, `tests/test_frames.c`, `tests/test_elf.c`, new isolation vectors.

- **1.1 Per-thread stacks (R1.1, K1).** Replace the shared `.udata` megapage (`vm.c:113-114`) with a private stack per tid mapped from a pool frame (or a per-tid L0). Test: a new `test_v2ipc` vector asserting writes to `0x8060_0000..0x807F_FFFF` from tid A do not alias tid B's stack; delete the false claim in `kernel/user.c:10-12`.
- **1.2 Per-device MMIO (R1.2, K2).** Map only the discovered transport page per owner (`device.c` already knows the index). Test: `test_dev_leaves` asserts each owner's leaf covers exactly one transport.
- **1.3 Teardown revocation (R1.3, D1).** Add `irq_unbind`; clear device leaves + disable the PLIC line on QDESTROY and slot reuse. Test: `test_qube_destroy_auth` extended to assert leaves/routes cleared.
- **1.4 DMA honesty (R1.4, K3).** Implement a validated bounce window or delete `abi/iommu.h` and the "IOMMU-isolated" claims; validate descriptor addresses. Test: driver-compartment link gate + a negative vector.
- **1.5 Fault reclamation (R1.5, K6).** On fatal fault, tear down frames/caps and mark `T_DEAD`. Test: `test_frames` asserts the pool returns to baseline after N faults.
- **1.6 SPAWN reuse leak (R1.6, K7).** Snapshot cap-referenced frames on reuse. Test: spawn/free loop leaves the frame bitmap unchanged.
- **1.7 FORK (R1.7, K5).** Map the child stack; `sepc = parent` (no `+4`). Test: `test_v2ipc` FORK vector.
- **1.8 ELF_CHECK pointer (R1.8, K4).** Range/alignment-check `a2` or copy the header in. Test: `test_elf` adversarial-pointer vector.
- **Also:** delete `kernel/arch/` + `kernel/core/` (D3) or make them the single source, so there is one page-table builder.

**Exit criteria:** no two threads share writable memory (proved by an aliasing test); each driver maps one device; a destroyed thread leaves no authority; the frame pool is balanced across fault/spawn/fork cycles; the shared-`.udata` and "exclusivity asserted" comments are gone.

---

## Phase 2 — Functional security model

**Implements:** R2.1–R2.6 (K8 and the qube/caps findings from the kernel-core review). **Own plan required.**

**Files:** `kernel/caps.h`, `kernel/syscall_ipc.c`, `kernel/syscall_qube.c`, `kernel/sched.c`, `kernel/qube.h`; tests `tests/test_v2caps.c`, `tests/test_qube_policy.c`, `tests/test_ipc_production.c`.

- **2.1 QX mintable (R2.1).** Create an initial QX-bearing cap from the boot authority so cross-qube IPC can be authorized. Test: assign two labels and assert a QX send succeeds.
- **2.2 Gate the queue path (R2.2).** Apply the qube check in `sys_send`/`sys_asend`, not only handoff (`syscall_ipc.c:179`). Test: queue-then-recv from a foreign qube is denied.
- **2.3 Drop-on-deny (R2.3).** Dequeue the denied slot so the endpoint recovers (`syscall_ipc.c:264-274`). Test: attacker fills the queue; victim keeps receiving legitimate messages.
- **2.4 Notify policy (R2.4).** Quce-check `sys_notify` (`syscall_ipc.c:387`). Test: foreign notify is denied.
- **2.5 Deadlock break (R2.5, K8).** Call `ipc_deadlock_check()` from `sched_tick`, fail the cycle. Test: A↔B wait is broken with an error, not a hang.
- **2.6 Notify namespace (R2.6).** Move backpressure off bit 0 of the user notify word, or wire `ipc_flow_control_init`.

**Exit criteria:** cross-qube IPC works when authorized and is denied otherwise on *every* path (send, asend, queue, notify); a denied message cannot wedge an endpoint; a circular wait is broken; the deadlock test is gated.

---

## Phase 3 — Correctness bugs

**Implements:** R3.1–R3.8 (S1–S3, N1–N8). **Own plan required** (independent fixes; can split).

- **3.1 FDE seed (R3.1, S1).** Make the vault return fresh DRBG bytes (a granted frame or 4 reply words); cryptblk MUST fail closed unless the full seed arrives. Test: `test_crypt`/a new `test_fde` asserts two boots derive different KEKs and that a short reply is rejected.
- **3.2 Allocator (R3.2, N1, N8).** Reject overflowing sizes; add locking (or document the allocator as per-thread); handle aligned blocks in `realloc`. Test: `test_libc` vector for `malloc(SIZE_MAX-k) == NULL` and aligned-`realloc`.
- **3.3 Thread-local errno (R3.3, N3).** Test: two threads observing distinct errno.
- **3.4 Thread reap (R3.4, N4).** Reap exited detached threads; `munmap` stacks. Test: create/exit 20 detached threads and create a 21st successfully.
- **3.5 printf precision/# (R3.5, N5).** Test: `%.5d`, `%#x`, `%#o` vectors in `test_libc`.
- **3.6 TCP checksum length (R3.6, N2) — Review Focus #3.** Use IP total length in the socket seam. Test: add a 60-byte padded bare-ACK vector to `test_tcp` that currently fails.
- **3.7 UDP TTL byte (R3.7, N6).** Test: `test_net_stack` asserts byte 22 holds TTL.
- **3.8 IPC length bounds (R3.8, S2, S3) — Review Focus #4.** Clamp `len` in console/tty; bound the ANSI parser. Test: `test_console_gui_layout` + a tty vector with `len > sizeof(data)`.

**Exit criteria:** the seeded-crypto test proves boot-to-boot key divergence; the allocator vector cannot corrupt the heap; `test_tcp` includes and passes a padded-frame vector.

---

## Phase 4 — Honesty & integration

**Implements:** R4.1–R4.5 (S4, S9, P1, V7, V8). **Own plan required.**

- **4.1 Shell semantics (R4.1, S4).** Implement `true`/`false`/`printf` correctly (`shell_core.h:1809,1826`). Test: `test_moonsh_busybox` asserts `false` returns 1 and prints nothing.
- **4.2 Honest introspection (R4.2, S4).** `ps/mem/ipc/dmesg`/`/proc` report real state or "unavailable"; fix the ISA string (`shell_vfs.h:374`). Test: a vector asserting `cpuinfo` matches the build `-march`.
- **4.3 Delete dead duplicates (R4.3, P1, V8).** `kernel/kernel.h`, `kernel/arch/`, `kernel/core/`, `userspace/sh/shell.c`, the 4 v1-rot tests (`bench_ipc.c`, `fuzz_syscall.c`, `host_emul.c`, `stub_globals.c`), the committed `test_v2ipc` binary, `userspace/sh/shell.o/.d`. Test: `git grep` finds no references; the gate stays green.
- **4.4 Services (R4.4, S9).** Either wire `vfs_server`/`sched_server` into `all`+initrd (+ a tid budget review) or move unshipped services to a `staging/` area; make AdminVM refuse to auto-approve. Test: a gate check that the shipped set matches the documented set; an AdminVM deny-by-default vector.
- **4.5 Docs (R4.5, V7).** Regenerate `ARCHITECTURE.md`/`BUILD.md` from `verify.sh`'s actual markers; delete root "COMPLETE" status docs; fix non-existent paths in `TCP_DESIGN.md`/`PHASE2_PRODUCTION_PLAN.md`. Test: a script that diffs documented markers against `verify.sh`.

**Exit criteria:** no comment or doc asserts an unimplemented property; no dead duplicate of a shipping module exists; the user-facing shell and `/proc` tell the truth.

---

## Phase 5 — Process hardening

**Implements:** R5.1–R5.3 (V5). **Own plan required.**

- **5.1 Proof/model linkage (R5.1, V5).** Add a CI check that each Isabelle `max_*` constant equals its C macro (generated `_Static_assert` bridge or a parse-check); fix the four drifts. Otherwise retract the "refined C implementation" claim in `docs/ARCHITECTURE.md:8-10`.
- **5.2 Sanitizers/static analysis (R5.2).** Run host tests under `-fsanitize=address,undefined` (the banners in `test_frames.c:3`, `test_ipc_production.c:17`, `test_elf.c:6` already claim this — make it true) and `clang --analyze` on the kernel in CI.
- **5.3 Quality bar (R5.3).** Add `CONTRIBUTING.md` codifying the Global Constraints and the "gate must fail on a deliberate fault" rule.

**Exit criteria:** CI fails on a model/constant drift and on a sanitizer hit; the claims in test banners are true; the constraints are written down and enforced.

---

## Self-review (plan vs spec)

- **Spec coverage:** R0.1–R0.7 → Phase 0 tasks 0.1–0.7; R1.1–R1.8 → Phase 1 §1.1–1.8 (+ D3); R2.1–R2.6 → Phase 2 §2.1–2.6; R3.1–R3.8 → Phase 3 §3.1–3.8; R4.1–R4.5 → Phase 4 §4.1–4.5; R5.1–R5.3 → Phase 5. No requirement is unmapped. Finding V4 is owned by Task 0.7 (added in the pre-flight scan).
- **Review Focus:** items 1–5 map to Tasks 0.1, 1.1, 3.6, 3.8, 3.2 respectively — each has an explicit test vector.
- **Type/name consistency:** `run_test`/`run_optional`/`FAILED` are introduced in Task 0.1 and used by 0.2–0.7; `V2_INV_ELF_CHECK`/`sepc`/`irq_unbind` names match the reviewed source.
- **Proportion:** Phase 0 is fully specified because it is executed first and is self-contained; Phases 1–5 are scoped as independent plans by design, not transcribed here.
