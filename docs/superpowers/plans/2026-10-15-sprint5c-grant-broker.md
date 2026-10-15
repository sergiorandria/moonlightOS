# Sprint 5c Broker Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce audited allow-list policy on cross-qube QX grants at the GRANT syscall arm, with model specs and host KATs.

**Architecture:** Pure policy/audit helpers in a new `grant_policy.h` (decision over qubes+rights, explicit audit-ring state); a thin gate in `syscall_cap.c`'s GRANT arm that denies before calling the unchanged verbatim `v2_grant`; boot's direct `v2_grant` calls documented as trusted provisioning. `V2_D` gains the gate condition + audit preservation.

**Tech Stack:** C99 host-testable headers, RISC-V kernel dispatch, Isabelle/HOL (`V2_D.thy`), `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-15-sprint5c-grant-broker-design.md`

## Global Constraints

- Gate placement: `syscall_cap.c` GRANT arm only — `v2_grant` keeps verbatim copy semantics (boot provisioning + policy-passed grants share it); no `v2_grant` signature change.
- Policy trigger is exactly: `qube_of[from] != qube_of[to] && (rights & V2_RIGHT_QX)` — everything else flows as today.
- Audit ring: 64 entries (`GRANT_AUDIT_MAX 64`), allow appends, full ring denies without recording (audited-allow discipline); deny path writes nothing.
- Denials return existing `V2_ERR_INVALID`; no new syscalls, ops, error codes, or capacity bumps (policy table 32 rows max, `GRANT_POLICY_MAX 32`).
- Boot direct grants are trusted provisioning (pre-policy, all same-qube-0 — gate would pass); documented, not gated.
- All C compiles `-Werror`-clean; every new loop carries a `/* bound: N */` comment.
- Fail-closed: deny writes nothing (no slot, no audit consumption); full ring denies.
- Path-scoped commits.

## Review Focus

- Same-qube QX grant accidentally gated (boot + tests use qube 0 throughout — a wrong trigger breaks everything): pinned by same-qube passthrough KAT + QEMU legacy-identical transcript (Tasks 1–2).
- Non-QX cross-qube grant gated (policy must not touch it): pinned by non-QX passthrough vectors (Task 1).
- Audit-full silently allowing: pinned by fill-to-64 then allow→deny vectors with entries intact (Task 1).
- Deny path writing audit or slot state: pinned by state-snapshot vectors around denied calls (Task 1).
- Boot provisioning routed through the gate by mistake (trusted path must stay direct): pinned by code review of `kboot.c` diff (must show comment-only) + boot smoke markers (Task 2).

---

### Task 1: Policy header + failing-first KAT

**Files:**
- Create: `kernel/grant_policy.h`
- Create: `tests/test_grant_policy.c`
- Modify: `tools/verify.sh` (`[1f]` block)
- Test: `tests/test_grant_policy.c`

**Interfaces:**
- Consumes: `V2_RIGHT_QX`, `V2_QUBES_MAX` (existing, unchanged)
- Produces: `typedef struct { unsigned long src, dst; int allow; } grant_rule_t;` (plus `grant_policy_t { rules[32], nrules }`, `grant_audit_t { entries[64], n }`), `static inline int grant_decide(const grant_policy_t *p, unsigned long sq, unsigned long dq, unsigned long rights)` (first-match-wins, default-deny, nonzero only on allow), `static inline int grant_audit_allow(grant_audit_t *a, ...)` (appends or returns overflow nonzero with zero state change), `static inline int grant_gate(const uint8_t *qube_of, unsigned long nthreads, unsigned long from, unsigned long to, unsigned long rights, const grant_policy_t *p, grant_audit_t *a)` (returns 1 proceed / 0 deny; same-qube or non-QX proceeds without touching audit; cross-qube QX decides via policy and audits allows) — Task 2 wires `grant_gate` into the arm

- [ ] **Step 1: Write the failing KAT**
  Create `tests/test_grant_policy.c` (CHECK-macro style): same-qube QX proceeds with audit untouched; non-QX cross-qube proceeds untouched; cross-qube QX with allow row proceeds +1 audit entry; without row denies with zero state change (snapshot slots+audit before/after); fill-to-64 then allow→deny with entries intact; default-deny on empty policy; first-match-wins ordering; mutant rows.

- [ ] **Step 2: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_grant_policy tests/test_grant_policy.c`
  Expected: FAIL with `grant_policy.h: No such file`.

- [ ] **Step 3: Implement `kernel/grant_policy.h`**
  Pure header (stdint only): types + the three functions above, bounded loops with `/* bound: */` comments, no state besides caller-provided structs.

- [ ] **Step 4: Run KAT to verify pass**
  Run: same command as Step 2
  Expected: `PASS: test_grant_policy` (exact string the test prints).

- [ ] **Step 5: Wire into `tools/verify.sh`**
  Add the Step-4 compile+run with the `|| echo "FAIL: test_grant_policy"` idiom in `[1f]` beside the caps/qube suite lines.
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 6: Commit**
  ```bash
  git add kernel/grant_policy.h tests/test_grant_policy.c tools/verify.sh
  git commit -m "feat(caps): grant policy gate + audit with KAT"
  ```

### Task 2: Arm gate + trusted-provisioning docs + smoke

**Files:**
- Modify: `kernel/syscall_cap.c` (GRANT arm only), `kernel/kboot.c` (comment only)
- Modify: `tools/verify.sh` (`[4/4]` gate lines)
- Test: QEMU smoke markers

**Interfaces:**
- Consumes: Task 1's `grant_gate` + the kernel's live `qube_of`, policy instance, audit instance (static, zero-initialized at boot — state placement follows the `qube.h` audit precedent already in tree)

- [ ] **Step 1: Add the gate to the GRANT arm**
  In `syscall_cap.c`'s `V2_INV_GRANT` arm, after the existing source-slot validation and before the `v2_grant` call: read the source slot's rights, then `if (!grant_gate(qube_of, NTHREADS, cur, to_thread, src_rights, &grant_policy, &grant_audit)) { reply V2_ERR_INVALID; return; }` (`to_thread`/`src_rights` are the arm's already-validated destination thread and source-slot rights — grant copies rights verbatim, so there is no rights syscall arg). No other arm changes; the `v2_grant` call itself untouched.

- [ ] **Step 2: Document boot provisioning in `kboot.c`**
  Comment-only at the boot `v2_grant` call sites: trusted provisioning, pre-policy, all same-qube-0 (gate would pass). Zero code change — reviewer verifies comment-only via diff.

- [ ] **Step 3: Add `GRANT:` smoke markers**
  Print `GRANT: allow` on policy-passed cross-qube QX grants and `GRANT: deny` on denials (boot prints neither — all-qube-0 — proving the gate is dormant on live paths); gate both strings in `[4/4]`. Since boot never fires the gate, exercise both arms via a boot self-test leg (one synthetic cross-qube allow + one deny, fail-closed `[demo] FAIL` on deviation) following the established live-leg pattern.

- [ ] **Step 4: Build + smoke**
  Run: `make -C kernel` (`-Werror` clean) + the stage-`[4/4]` QEMU block
  Expected: build clean; legacy markers byte-identical; both `GRANT:` markers hit exactly via the self-test leg.

- [ ] **Step 5: Commit**
  ```bash
  git add kernel/syscall_cap.c kernel/kboot.c tools/verify.sh
  git commit -m "feat(caps): enforce grant gate at GRANT arm with smoke legs"
  ```

### Task 3: V2_D gate condition + audit preservation proofs

**Files:**
- Modify: `kernel/isabelle/V2_D.thy` (append only)
- Modify: `tests/test_grant_policy.c` (header comment: exact new lemma names)
- Test: `isabelle build -D kernel/isabelle`

**Interfaces:**
- Consumes: existing `V2_D.thy` grant transition + lemma patterns (mirror them)
- Produces: `q_grant_gate` condition + `d_grant` gate-conjuncted variant (or constrained lemma over the existing transition — follow the file's own extension idiom, never rewrite existing lemmas), audit-boundedness preservation (`allow ⇒ recorded`, full ⇒ blocked), KAT-cited lemma names

**Steps:** same TDD-at-proof-level rhythm as the Sprint 5b proof task (state lemma names in the KAT comment first, then prove):
- [ ] Mirror the file's grant-transition style for the gated variant (deny returns pre-state; allow extends audit by one).
- [ ] Prove gate-refinement + `audit_preserved_bounded` (bounded ring, allow-recorded, full-blocks-allow — same shape as the S2 audit-cap closure).
- [ ] Run: `isabelle build -D kernel/isabelle`
  Expected: clean, 0 `sorry`, 0 new axioms (gate is a condition over existing state; audit ring needs no axioms).
- [ ] Record exact new lemma names in the KAT header comment (grep-verified, never invented).
- [ ] Commit `proof(isabelle): V2_D grant gate + audit preservation`.

### Task 4: Full verification + review + merge-prep

**Files:**
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 1–3
- Produces: green baseline ready for merge

- [ ] **Step 1: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0; zero `^FAIL` lines; `PASS: test_grant_policy`; both `GRANT:` markers; legacy-identical otherwise; Isabelle PASS.

- [ ] **Step 2: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task range before merging. Fix Critical/Important findings first. Reviewer must confirm the gate placement (arm, not `v2_grant`) and the trusted-provisioning comment-only constraint on `kboot.c`.

- [ ] **Step 3: Merge-prep (no merge without explicit approval)**
  Confirm worktree clean except untracked generated headers; report branch ready. Do not merge or push.
