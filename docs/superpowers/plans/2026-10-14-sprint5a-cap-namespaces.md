# Sprint 5a Namespaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add namespace views + mint attenuation to `caps.h` with zero behavior change on live paths, pinned by host KATs.

**Architecture:** Two pure helpers plus a 3-line hook in `v2_mint`; the MDB, revoke, grants, and op numbers untouched. A new host KAT proves isolation/attenuation/transitivity with mutants; existing caps/qube suites prove no regression.

**Tech Stack:** Host-testable C99 (`caps.h` is pure, no asm/SBI), host KAT, `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-14-sprint5a-cap-namespaces-design.md`

## Global Constraints

- No MDB layout change, no revoke-path change, no new syscalls/INVOKE ops, no new error codes, no Isabelle theory changes, no capacity bumps (NTHREADS=11, V2_CAP_THREADS=11, V2_CAP_SLOTS=64, V2_VPN_SLOTS=32).
- QX bit value shared: `caps.h` and `qube.h` both define `0x8UL` (see `caps.h:72-74`); never change one without the other.
- Mint attenuation drops QX silently and returns `V2_OK` (W^X defensive-drop precedent in the PTE installer — NOT the mint-time fail-closed precedent).
- Grants propagate rights verbatim including QX (existing documented design); this plan does not change `v2_grant`.
- All C compiles `-Werror`-clean; every new loop carries a `/* bound: N */` comment.
- Fail-closed: out-of-namespace → existing `V2_ERR_INVALID`; no partial slot writes.
- Path-scoped commits; live-path audit result (below) is load-bearing — re-verify it if `syscall_cap.c` changes first.

## Review Focus

- A live minter requesting QX breaks under attenuation (sole caller today is the userspace INVOKE path via `syscall_cap.c:40`; boot uses grants; no test mints QX): pinned by re-auditing callers + QEMU byte-identical transcript (Task 2).
- View false-negative hiding a thread's own valid slot: pinned by own-slots-always-visible KAT vectors (Task 1).
- View false-positive exposing foreign non-QX slots: pinned by cross-thread no-grant invisibility vectors (Task 1).
- Grant-path QX behavior silently changing: pinned by a KAT asserting `v2_grant` still propagates QX verbatim (Task 2).
- `QX` value drift between `caps.h` and `qube.h`: pinned by a KAT equality assertion on both macros (Task 2).

---

### Task 1: View + attenuate helpers + failing-first KAT

**Files:**
- Modify: `kernel/caps.h` (append helpers near `v2_cap_ok`)
- Create: `tests/test_capns.c`
- Test: `tests/test_capns.c`

**Interfaces:**
- Consumes: `v2_caps_t`, `v2_capslot_t`, `V2_CAP_SLOTS`, `V2_CAP_THREADS`, `V2_RIGHT_QX`, `V2_OK` (all existing in `caps.h`, unchanged)
- Produces: `static inline unsigned long cap_ns_attenuate(unsigned long rights)` (returns `rights & ~V2_RIGHT_QX`); `static inline int cap_ns_visible(const v2_caps_t *st, unsigned long t, unsigned long u, unsigned long r)` (nonzero iff holder-ok, slot `(u,r)` valid, and (`u == t` || slot rights include QX)) — Task 2 uses both exact signatures

- [ ] **Step 1: Write the failing KAT**
  Create `tests/test_capns.c` (host, `#include "../kernel/caps.h"`, CHECK-macro style per `tests/test_v2caps.c`): own valid slots always visible; foreign non-QX slots invisible without grant; foreign QX slots visible; `cap_ns_attenuate(RW|QX) == RW`, `cap_ns_attenuate(R) == R`; grant-chain transitivity (grant QX cap to thread B → visible from B); mutant rows (a no-QX foreign slot the view must reject; an attenuated mint the view must not see under QX).

- [ ] **Step 2: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_capns tests/test_capns.c`
  Expected: FAIL with `cap_ns_visible`/`cap_ns_attenuate` undeclared (implicit-declaration errors).

- [ ] **Step 3: Implement both helpers in `kernel/caps.h`**
  Place after `v2_cap_ok` (`caps.h:130-139`); loops bounded (`/* bound: V2_CAP_SLOTS */` where looping; the visible check itself is O(1) indexing — no loop needed except transitivity demonstration in the TEST, not the helper).

- [ ] **Step 4: Run KAT to verify pass**
  Run: same command as Step 2
  Expected: `PASS: test_capns` (exact string the test prints).

- [ ] **Step 5: Commit**
  ```bash
  git add kernel/caps.h tests/test_capns.c
  git commit -m "feat(caps): namespace view + attenuate helpers with KAT"
  ```

### Task 2: Mint hook + regression gates

**Files:**
- Modify: `kernel/caps.h` (`v2_mint` only — 3 lines)
- Modify: `tests/test_capns.c` (attenuation + grant-verbatim + macro-equality vectors)
- Test: `tests/test_capns.c`, `tests/test_v2caps.c`, plus qube suites

**Interfaces:**
- Consumes: Task 1's `cap_ns_attenuate`
- Produces: attenuated `v2_mint`; KAT vectors pinning the new behavior and the unchanged grant path

- [ ] **Step 1: Re-audit mint callers for QX**
  Run: `grep -rn "v2_mint(" kernel/ userspace/ | grep -v "caps.h:"` and `grep -n "QX" tests/test_v2caps.c`
  Expected: sole caller is `syscall_cap.c:40` (userspace-driven INVOKE); no test mints QX. If any caller mints QX-carrying rights on a boot path, STOP and report BLOCKED (plan premise broken).

- [ ] **Step 2: Add the 3-line hook in `v2_mint` (`caps.h:216`)**
  After the existing validation block and before the slot store, insert `rights = cap_ns_attenuate(rights);` with a one-line comment citing the QX-drop discipline. No other line of `v2_mint` changes; `v2_grant` untouched.

- [ ] **Step 3: Extend the KAT**
  Add vectors: mint requesting `RW|QX` from a QX cap returns `V2_OK` with derived rights exactly `RW`; mint without QX byte-identical to before; `v2_grant` still propagates QX verbatim (assert derived slot has QX); `V2_RIGHT_QX == 0x8UL` from both `caps.h` and `qube.h` (include both, `_Static_assert` or CHECK equality).

- [ ] **Step 4: Run new + existing suites**
  Run: `test_capns` (expect PASS), `test_v2caps`, plus `test_qlabels`, `test_qube_policy` (same `gcc -Wall -Wextra -Werror` + run idiom as `verify.sh [1f]`)
  Expected: all PASS, zero FAIL.

- [ ] **Step 5: Commit**
  ```bash
  git add kernel/caps.h tests/test_capns.c
  git commit -m "feat(caps): attenuate QX at mint with regression gates green"
  ```

### Task 3: Verify wiring + review + merge-prep

**Files:**
- Modify: `tools/verify.sh` (`[1f]` block only)
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 1–2
- Produces: green baseline ready for merge

- [ ] **Step 1: Wire the KAT into `verify.sh [1f]`**
  Add the Step-4 compile+run line with the `|| echo "FAIL: test_capns"` idiom beside the caps/qube suite lines.
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 2: Grep `V2_D.thy` for the mirrored lemmas and cite them**
  Run: `grep -n "mint\|grant\|confinement" kernel/isabelle/V2_D.thy | head`
  Expected: a short list; append a comment block to `tests/test_capns.c` naming the exact lemma each KAT section mirrors (no theory edit). If no mint/grant lemma exists by those names, cite the file + section honestly instead of inventing names.

- [ ] **Step 3: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0 modulo the known pre-existing shell-build reds (untracked `shell_expr.h`; document any other FAIL as new); `PASS: test_capns`; QEMU byte-identical otherwise; Isabelle PASS.

- [ ] **Step 4: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task range before merging. Fix Critical/Important findings first.

- [ ] **Step 5: Merge-prep (no merge without explicit approval)**
  Confirm worktree clean except untracked generated headers; report branch ready. Do not merge or push.
