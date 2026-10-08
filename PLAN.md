# MoonlightOS — Gap-Closing Plan

Generated from a direct read of the current tree (kernel/, docs/, tests/,
tools/, .github/workflows/) — not from README claims. Where the docs already
match the code, that's noted as verified; where they diverge, that's the plan.

## 0. Verified-accurate claims (no action needed)

- `kernel/Makefile` is genuinely RISC-V-only now (`riscv64-unknown-elf-clang`,
  `-march=rv64imacxcheri`, stock fallback to `rv64imac`) and `kernel/arch/` is
  empty — matches `docs/PRODUCTION.md`, which no longer mentions x86_64.
- Isabelle: 7 theories present, 11/14 theorems proved, 3 correctly listed as
  axiomatized (`Moonlight_E.ex_refines_abs`, `Refine.refinement`,
  `Refine.c_refinement`) — matches `README.md`/`PRODUCTION.md` claims.
- `tools/verify.sh` and `.github/workflows/verify.yml` genuinely run the
  listed host tests.



## 1. Real gaps found (priority order)

### 1.1 — HIGH: `boot/dice.c` is not wired into the build or boot path
`docs/REPRODUCIBLE.md` and `README.md` advertise "DICE measured boot" as a
working feature. In fact:
- `boot/dice.c` is **not** in `kernel/Makefile`'s `SRC` list — it never
  compiles into `moonlight.elf`.
- `kernel/src/boot.c`'s `kernel_boot()` never calls `boot_measure_and_attest()`
  or anything in `dice.c`.
- `boot_measure_and_attest()` itself compares the computed kernel hash against
  a hardcoded `expected[HASH_SIZE] = {0}` — the comment says "filled at build
  time via reproducible build" but nothing in `linker.ld` or the Makefile
  provides `expected_hash`. As written the check can only ever fail.
- `sha256()` is declared `extern` in `dice.c` with no implementation anywhere
  in the tree.

**Action:** either (a) wire `dice.c` into `kernel/Makefile`, implement
`sha256()`, add the `PROVIDE(expected_hash)` symbol `REPRODUCIBLE.md`
describes, and call `boot_measure_and_attest()` from `kernel_boot()`; or (b)
if attestation isn't ready, remove the "DICE measured boot" claim from
`README.md`/`docs/REPRODUCIBLE.md` until it is. Right now the docs describe a
feature that doesn't exist in the running kernel.

**Status 2026-09-12: FIXED via (a), with one design change.** `boot/dice.c`
moved to `kernel/src/dice.c` (+ new `sha256.h`/`sha256.c`/`dice.h`), both in
`SRC`, `boot_measure_and_attest()` called from `kernel_boot()` with halt-on-
mismatch. The `PROVIDE(expected_hash)` part was replaced: PROVIDE can only
supply an address, not 32 data bytes, so the slot is a generated object
(`kernel/build/expected_hash.c` -> `.dice_expected`, KEEP, 32B) filled by
`tools/measure_dice.py` via `make provision-dice`, which ends in a
re-measure MATCH gate. Measurement excludes the slot itself (two sha256
updates), so provisioning is a single-rebuild fixed point. `REPRODUCIBLE.md`
documents the change; `tests/test_dice.c` (KATs incl. hashlib-differential
0..200 + streaming, slot invariance, fail-closed) runs in `verify.sh [1b]`
and the QEMU smoke asserts the `[DICE]` boot lines.

### 1.2 — HIGH: dead x86_64 code throughout `kernel/src/boot.c`
`boot.c` still has full `#ifdef __x86_64__` branches (UART port I/O via
`inb`/`outb`, IDT/`sidt` check, x86_64 CET capability sim, PML4 vs Sv39
switch, `int $0x80` trap path). But `kernel/Makefile` has no x86_64 target,
`kernel/arch/` is empty, and every other doc has dropped x86_64 — so none of
this code path is reachable or tested. It's the one file that didn't get
cleaned up when the project committed to RISC-V-only.

**Action:** delete the `__x86_64__` branches from `boot.c` (and the
`#elif defined(__x86_64__)` in the `HALT()` macro), leaving a single
RISC-V-only boot path. This also removes a class of "looks tested, isn't"
risk — a change to the RISC-V path could silently break inside dead x86_64
code without anyone noticing.

**Status 2026-09-14: FIXED.** `kernel/src/boot.c` contains zero
`__x86_64__`/`x86` references (verified by grep); single RISC-V-only boot
path with the `HALT()` x86 branch gone.

### 1.3 — MEDIUM: `tests/test_hardening.c` referenced but doesn't exist
`tools/verify.sh` stage `[1b]` runs:
```
gcc ... tests/test_hardening.c kernel/src/hardening.c 2>/dev/null && ... || echo "SKIP: test_hardening not found"
```
The file isn't in `tests/` (confirmed via directory listing), so this stage
silently SKIPs on every run, including in CI conceptually (though
`verify.yml` doesn't even invoke `verify.sh` directly — see 1.4). `hardening.c`
(`STACK_CANARY`, `GUARD_PAGE`, `is_canonical_addr`, `HARDENING_ASSERT`) has
zero test coverage anywhere in the tree.

**Action:** write `tests/test_hardening.c` covering: canary corruption
detection, guard-page violation, `is_canonical_addr` edge cases (top/bottom
of address space, mid-range canonical break for the current VA width), and
wire it into `verify.sh`'s existing (currently dead) invocation.

**Status 2026-09-14: FIXED.** `tests/test_hardening.c` exists and covers
canary rejection, guard-page init (pattern fill on RISC-V), and
`is_canonical_addr` at 0x0 / all-ones / Sv39 break points; `verify.sh [1b]`
compiles and runs it (PASS, no SKIP).

### 1.4 — MEDIUM: `verify.yml` and `verify.sh` have drifted apart
`.github/workflows/verify.yml` re-implements a subset of `tools/verify.sh`'s
test list as individual `run:` steps instead of calling `tools/verify.sh`.
Consequences:
- CI is missing `[1a]` ABI regression check, `[1b]` hardening/ipc-trap/
  invoke-ops/mem-server/sched-server/vfs tests, and the summary PASS/FAIL
  gate that `verify.sh` computes.
- Every time `verify.sh` gains a check (as it clearly has — the "PLAN 3" ABI
  check, the vfs `FAIL`-not-`SKIP` change, etc.), CI has to be updated by hand
  in a second place, and evidently hasn't been.

**Action:** replace `verify.yml`'s host-tests job with a single
`run: tools/verify.sh` (or split verify.sh into the pieces CI already wants,
but as one source of truth) so CI and the documented local workflow can't
diverge again.

**Status 2026-09-14: FIXED.** `verify.yml`'s `host-tests` job is a single
`run: tools/verify.sh`. The separate `isabelle` container job is a deliberate
matrix extension (verify.sh SKIPs proofs without Isabelle) with a comment in
the yml marking the relationship, not a re-implementation of the test list.

### 1.5 — MEDIUM: `sched_pick_next` is an unbounded-looking linear scan under a 5µs WCET budget
`ARCHITECTURE.md` itself flags this ("`sched_pick_next` scans `prio 0..255`
(bitmap TODO)"). The implementation in `kernel/src/sched.c` is a nested loop:
256 priority levels × `MAX_SCHED_CONTEXTS`. `wcet_check()` enforces a 5µs
kernel WCET via `rdtime`, but nothing bounds `sched_pick_next`'s iteration
count against that budget as `MAX_SCHED_CONTEXTS` grows — the two aren't
connected. `Sched_Verification.thy`'s `wcet_bound` proof covers the *model*
(`wcet=1000` constant), not this concrete scan.

**Action:** either implement the priority bitmap the comment already names
(O(1) or O(bits) next-priority lookup instead of O(256×N)), or add a
compile-time bound tying `MAX_SCHED_CONTEXTS` to a value provably safe under
the 5µs budget at the current clock rate, with a comment explaining the
arithmetic.

**Status 2026-09-14: FIXED via bitmap + bound.** `sched.c` has a bitmap fast
path (≤4 words + ≤64 contexts at one prio) over the legacy full scan kept as
the correctness floor; `tests/test_sched_bitmap.c` proves bitmap == full scan
on 3000 randomized states; `_Static_assert(MAX_SCHED_CONTEXTS <= 64)` forces
WCET re-analysis if the bound ever grows.

### 1.6 — LOW: build artifacts committed to git despite `.gitignore`
`kernel/build/moonlight.elf` and `kernel/src/*.o` are present in the working
tree and appear tracked (`.gitignore` excludes `build/`, `*.o`, `*.elf`, but
they showed up in the directory listing under version control paths, not
untracked scratch). Given `docs/REPRODUCIBLE.md`'s entire pitch is
byte-reproducible builds with `SOURCE_DATE_EPOCH=0` + `sha256sum`, a stale
committed `.elf`/`.o` set sitting next to `.gitignore` rules that should have
excluded them is worth a `git status`/`git ls-files` check and, if tracked,
`git rm --cached`.

**Action:** confirm with `git ls-files kernel/build kernel/src/*.o`; if
tracked, remove from history-forward (`git rm --cached`) and verify a clean
`make -C kernel clean && make -C kernel` reproduces byte-identical output per
`REPRODUCIBLE.md`'s own recipe.

**Status 2026-09-14: VERIFIED CLEAN, nothing to do.** `git ls-files` shows no
tracked `.o`/`.elf`/`build/` paths; all are git-ignored. Stray in-source
`userspace/libc/src/string.{o,d}` leftovers (build goes to `build/`) were
deleted.

### 1.7 — LOW: verification-chain claims outrun what's actually run
`ARCHITECTURE.md` says "verified down to CHERI ISA + CompCert" and
`docs/PRODUCTION.md`'s own checklist marks both CBMC and CompCert as
unchecked boxes (`[ ]`), consistent with `kernel/Makefile`'s `cbmc`/`compcert`
targets both being manual/best-effort (`SKIP: cbmc not found`, `SKIP: ccomp
not found`) and CompCert explicitly "not pursued (no license)". The
architecture doc's framing overstates what's continuously verified versus
what's aspirational/manual.

**Action:** soften `ARCHITECTURE.md`'s "verified down to ... CompCert" line
to match `PRODUCTION.md`'s honest checklist (CompCert not pursued, CBMC
manual-only, not in CI), or actually get a CompCert CHERI-RISC-V license and
wire `cbmc` into `.github/workflows/verify.yml`.

**Status 2026-09-14: FIXED via softening.** `ARCHITECTURE.md` now reads
"verified down to CHERI ISA (CompCert binary correctness planned, not yet
pursued per `docs/PRODUCTION.md` checklist)"; `PRODUCTION.md` keeps CBMC and
CompCert as explicit unchecked boxes with reasons (no license / manual-only).

## 2. Suggested order of work

1. 1.2 (delete dead x86_64 code) — mechanical, low-risk, immediately reduces
   surface area for the other fixes.
2. 1.4 (unify verify.sh/verify.yml) — makes every subsequent fix in this list
   actually CI-checked instead of locally-only.
3. 1.3 (write test_hardening.c) — small, closes a real coverage hole.
4. 1.5 (scheduler bitmap or bound) — touches real-time correctness, do it
   with tests 1.3's harness pattern in place.
5. 1.1 (DICE) — biggest scope; decide keep-and-finish vs. cut-from-docs first,
   since it changes how much work this item is.
6. 1.6 and 1.7 — housekeeping, do whenever, before the next tagged release.
