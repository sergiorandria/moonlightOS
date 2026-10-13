# Sprint 2 Service Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate qrexec's service-routing table from the initrd pack order so adding a service never requires a hand table edit.

**Architecture:** `tools/mkinitrd.sh` emits `services_manifest.h` alongside `initrd.h`; qrexec compiles the manifest in place of `svc_of_qube[8]`; a host KAT pins manifest truth against kernel bounds. Kernel, proofs, and boot flow untouched.

**Tech Stack:** Bash (mkinitrd), freestanding rv64 C (qrexec ELF), host C99 KAT, `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-13-sprint2-service-registry-design.md`

## Global Constraints

- No kernel changes: no new syscalls/INVOKE ops, no `kernel/` edits except none at all.
- No capacity bumps: NTHREADS=11, V2_NEP=11, V2_QUBES_MAX=9 stay exactly.
- EP mirrors tid under `EP_OF_TID` identity; manifest carries both fields, consumer never re-derives.
- All C compiles `-Werror`-clean; every new C loop carries a `/* bound: N */` comment.
- Fail-closed everywhere: nonzero exits, deny-shape, no partial files.
- No Isabelle theory changes.
- Path-scoped commits; generated `kernel/initrd_data.c` committed only by Task 0.

## Review Focus

- Index→tid mismatch boots the WRONG image (isolation break): pinned by QEMU `[spawn] X ELF ok` markers (Task 0/3), not by the KAT.
- Stale manifest consumed by a rebuilt qrexec: pinned by the Makefile dependency (Task 2) — a person editing ELFS without rebuilding must still get a fresh manifest or a build error, never a silent stale table.
- Duplicate service names collapsing two rows into one route: pinned by the uniqueness KAT (Task 1).
- Manifest qube beyond V2_QUBES_MAX: pinned by the bounds KAT (Task 1).
- `rpc_svc` policy value pointing at a qube absent from the manifest: pinned by the policy-validation KAT (Task 2).

## File Structure

- Modify: `tools/mkinitrd.sh` (ELFS reconcile + manifest emitter).
- Create: `userspace/qrexec_server/services_manifest.h` (generated, NOT committed — gitignored? No: keep untracked build artifact beside qrexec sources; see Task 1).
- Modify: `userspace/qrexec_server/v2_main.c` (consume manifest, keep `rpc_svc` policy).
- Create: `tests/test_manifest.c` (host KAT).
- Modify: `userspace/Makefile` (qrexec depends on manifest).
- Modify: `tools/verify.sh` ([1e] build qrexec.elf; [1f] run mkinitrd + test_manifest).
- Regenerate + commit: `kernel/initrd_data.c`, `kernel/initrd.h` (Task 0 only).

Refinement vs spec §2 (deliberate, rationale): `rpc_svc[10]` (rpc→qube) is
*policy* (which service owns `keys.sign`), underivable from pack order, so it
stays hand-authored; the KAT validates every nonzero value names a manifest
qube. Only the *wiring* table (`svc_of_qube`, qube→tid) is generated. The
stale `T_*` names in `kernel/services.h` are not referenced by numeric
equality anywhere in this plan.

---

### Task 0: Reconcile initrd pack list with kboot spawn table

**Files:**
- Modify: `tools/mkinitrd.sh:32-44` (ELFS array)
- Regenerate: `kernel/initrd_data.c`, `kernel/initrd.h`
- Test: existing QEMU smoke markers (no new test)

**Interfaces:**
- Consumes: kboot spawn map (`kernel/kboot.c:102-108`: index→tid 0→2, 1→1, 3→3, 4→4, 8→8, 9→9, 10→10)
- Produces: truthful ELFS list that Task 1's emitter reads

- [ ] **Step 1: Restore vault/cryptblk rows in ELFS**
  In `tools/mkinitrd.sh`, replace the index-8 and index-9 `"UNUSED"` entries
  with `"vault.elf"  # 8 → tid 8` and `"cryptblk.elf"  # 9 → tid 9`, keeping
  index comments exact. Leave indices 2, 5, 6, 7 UNUSED with their comments.

- [ ] **Step 2: Regenerate the initrd blob**
  Run: `tools/mkinitrd.sh`
  Expected: exits 0, prints `Done:`, rewrites `kernel/initrd_data.c` + `kernel/initrd.h`.

- [ ] **Step 3: Rebuild kernel and confirm boot markers**
  Run: `make -C kernel` then the QEMU smoke block of `tools/verify.sh` (stage `[4/4]` only)
  Expected: `[spawn] vault ELF ok`, `[spawn] cryptblk ELF ok`,
  `Services: mem+console+tty+vault+cryptblk+gui up` all present.

- [ ] **Step 4: Commit**
  ```bash
  git add tools/mkinitrd.sh kernel/initrd_data.c kernel/initrd.h
  git commit -m "fix(initrd): repack vault/cryptblk at indices 8/9 to match kboot spawn table"
  ```

### Task 1: Manifest emitter + failing-first KAT

**Files:**
- Modify: `tools/mkinitrd.sh` (append emitter)
- Create: `tests/test_manifest.c`
- Modify: `tools/verify.sh:56-57` (insert `[1f]` manifest block after `test_shell_programs` line)
- Test: `tests/test_manifest.c`

**Interfaces:**
- Consumes: Task 0's truthful ELFS + index→tid map (0→2, 1→1, 3→3, 4→4, 8→8, 9→9, 10→10); qube map: every packed service → qube 0 (matches `kernel/kboot.c:124-130`)
- Produces: `userspace/qrexec_server/services_manifest.h` with
  `svc_manifest[]`, `svc_manifest_len`; ep always equals tid. The KAT asserts
  per-row validity (bounds, `ep == tid`, unique non-UNUSED names) — it does not
  assert row count, which only the emitter (single source: ELFS) can know.

- [ ] **Step 1: Write the failing KAT**
  Create `tests/test_manifest.c`: includes `../userspace/qrexec_server/services_manifest.h`,
  `../kernel/qube.h`, `../kernel/caps.h`, `../kernel/ipc.h`; asserts
  `svc_manifest_len` is nonzero and every row has `ep == tid`,
  `tid < 11`, `qube <= V2_QUBES_MAX`, with names unique and non-UNUSED
  (`/* bound: svc_manifest_len */` on every loop). Returns nonzero on first violation.

- [ ] **Step 2: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_manifest tests/test_manifest.c`
  Expected: FAIL — `services_manifest.h` does not exist.

- [ ] **Step 3: Implement the emitter in `tools/mkinitrd.sh`**
  After the `initrd.h` generation block: write `userspace/qrexec_server/services_manifest.h`
  with include guard + one row per non-UNUSED ELF (`name` = basename without `.elf`,
  `idx` = ELFS position, `tid` from the fixed index→tid map above, `ep` = tid,
  `qube` = 0). Abort nonzero with no partial file on duplicate names or tid ≥ 11.

- [ ] **Step 4: Run emitter + KAT to verify pass**
  Run: `tools/mkinitrd.sh && gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_manifest tests/test_manifest.c && /tmp/test_manifest`
  Expected: `PASS: test_manifest` (exact string the test prints).

- [ ] **Step 5: Wire into `tools/verify.sh`**
  After the `test_shell_programs` line, insert: run `tools/mkinitrd.sh` (fail-closed),
  then compile + run `test_manifest` with the `|| echo "FAIL: test_manifest"` idiom.
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 6: Commit**
  ```bash
  git add tools/mkinitrd.sh tests/test_manifest.c tools/verify.sh
  git commit -m "feat(svc): manifest emitter + test_manifest KAT"
  ```
  (Do NOT commit `services_manifest.h` — build artifact, regenerated by the gate.)

### Task 2: qrexec consumes the manifest

**Files:**
- Modify: `userspace/qrexec_server/v2_main.c:46-63`
- Modify: `userspace/Makefile:65-68` (qrexec rule deps)
- Modify: `tools/verify.sh` (`[1e]` block)
- Test: `tests/test_manifest.c` (extended) + `build/qrexec.elf` build gate

**Interfaces:**
- Consumes: Task 1's `services_manifest.h` (`svc_manifest`, `svc_manifest_len`)
- Produces: `build/qrexec.elf` whose deliver routing equals today's tables for every boot qube

- [ ] **Step 1: Extend the KAT with policy validation**
  Append to `tests/test_manifest.c`: include `../userspace/qrexec_server/v2_main.c`'s
  `rpc_svc` values? No — do not include the ELF source. Instead assert the
  *contract*: every qube number 4, 5, 6, 7 (the policy values in `rpc_svc`)
  appears in `svc_manifest` rows. Hardcode the set `{4,5,6,7}` with a comment
  citing `rpc_svc` in `v2_main.c`; FAIL naming the missing qube.
  Run: KAT passes (vault=6? No — qubes are all 0 at boot; the manifest qube
  column is 0 for every row, so `{4,5,6,7}` are ABSENT). Expected: FAIL with
  missing-qube message. This FAIL is the point: it forces Step 2's decision
  into the open — either the manifest qube map must carry the policy qubes
  (4,5,6,7) or `rpc_svc` must be re-pointed at qube 0. Implementer: re-point
  `rpc_svc` values per the boot-qube reality ONLY if qrexec is packed and
  live; if qrexec is not a boot service, keep `rpc_svc` untouched and change
  this KAT step to assert manifest self-consistency only (bounds, uniqueness,
  ep==tid). Do not invent qube labels.

- [ ] **Step 2: Replace `svc_of_qube` with manifest lookup**
  In `v2_main.c`, delete the `svc_of_qube[8]` table (lines 46–50); add
  `#include "services_manifest.h"` and a `static unsigned long svc_tid_of_qube(unsigned q)`
  scanning `svc_manifest` for `qube == q` (`/* bound: svc_manifest_len */`),
  returning 0 when absent (preserves today's qube-0→0 behavior). Replace both
  call sites (`u_send(svc_of_qube[...])`) with the lookup. Keep `rpc_svc`
  and its comment byte-identical unless Step 1 forced the documented decision.

- [ ] **Step 3: Makefile dependency + `-Werror` build**
  Change `build/qrexec.elf` prerequisites to include
  `qrexec_server/services_manifest.h`. Run: `make -C userspace build/qrexec.elf`
  Expected: builds with the existing `$(CFLAGS_V2)` (`-Werror`) and zero warnings.

- [ ] **Step 4: Gate the ELF build in `verify.sh [1e]`**
  Next to the vault/cryptblk explicit build line, add:
  `make -C userspace build/qrexec.elf ... || echo "FAIL: qrexec.elf"`.
  Run: `bash -n tools/verify.sh` → syntax OK.

- [ ] **Step 5: Commit**
  ```bash
  git add userspace/qrexec_server/v2_main.c userspace/Makefile tests/test_manifest.c tools/verify.sh
  git commit -m "feat(svc): qrexec routes from generated manifest"
  ```

### Task 3: Full verification + transcript parity

**Files:**
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 0–2
- Produces: green baseline on `dev` ready for merge

- [ ] **Step 1: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0; zero `^FAIL` lines; QEMU transcript byte-identical to the
  pre-change baseline except nothing (broker behavior unchanged); `test_manifest`
  PASS in `[1f]`; Isabelle PASS.

- [ ] **Step 2: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task
  range before merging. Fix Critical/Important findings first.

- [ ] **Step 3: Merge**
  Fast-forward merge to `dev` only with reviewer's **Ready to merge** verdict.
