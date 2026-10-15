# Sprint 5b Query Ops Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only QUERY (17) and CHAIN (18) INVOKE ops over the capability MDB with model specs and host KATs.

**Architecture:** Pure helpers in `caps.h` (single-level lineage only — the MDB stores no parent pointers, so chain depth is 0/1 by construction); thin dispatch arms in `syscall_cap.c`; `V2_D` gains read-only transitions that change no state; host KAT plus QEMU smoke markers.

**Tech Stack:** C99 host-testable headers, RISC-V kernel dispatch, Isabelle/HOL (`V2_D.thy`), `tools/verify.sh` gates.

**Spec:** `docs/superpowers/specs/2026-10-15-sprint5b-cap-query-design.md`

## Global Constraints

- Lineage is single-level (`root` bit only, `caps.h:89`); no parent pointers exist and none are added — chain depth is 0 (root) or 1 (derived), never more.
- New op numbers are 17 (`V2_INV_QUERY`) and 18 (`V2_INV_CHAIN`): above max 16, clear of qube 14/15.
- Read-only: neither helper nor arm writes any state on any path; foreign slots return `V2_ERR_INVALID`, never contents.
- No MDB/revoke/grant/mint behavior change, no new error codes, no capacity bumps.
- All C compiles `-Werror`-clean; every new loop carries a `/* bound: N */` comment (helpers are O(1); no loops expected).
- Fail-closed: bad holder/slot → `V2_ERR_INVALID`; chain on invalid slot → `-1`.
- Path-scoped commits.

## Review Focus

- Multi-hop chain hallucinated where only single-level lineage exists (implementer inventing parent pointers): pinned by depth∈{0,1} KAT + the no-new-state constraint (Task 1).
- Foreign slot contents leaked through query: pinned by cross-thread denial vectors asserting `V2_ERR_INVALID` and no content (Task 1).
- Op-number collision with 1–16 or 14/15: pinned by a KAT asserting 17/18 distinct from all existing numbers (Task 1).
- Query timing oracle (valid vs invalid slots distinguishable): pinned by constant-shape arms — both paths run the same gates in the same order (Task 2, review-verified).
- Chain/revoked-slot confusion (empty slot reported as depth-0 root): pinned by invalid-slot → `-1` vectors distinct from root `0` (Task 1).

---

### Task 1: Query helpers + failing-first KAT

**Files:**
- Modify: `kernel/caps.h` (append helpers near `cap_ns_visible`)
- Create: `tests/test_capquery.c`
- Test: `tests/test_capquery.c`

**Interfaces:**
- Consumes: `v2_caps_t`, `v2_capslot_t`, `v2_has_cap`, `v2_cap_holder_ok`, `V2_ERR_INVALID`, `V2_OK` (all existing, unchanged)
- Produces: `typedef struct { unsigned long rights, obj; int valid, root; } cap_query_t;`, `static inline int cap_query_slot(const v2_caps_t *st, unsigned long t, unsigned long s, cap_query_t *out)` (`V2_OK`+fill on own valid slot, `V2_ERR_INVALID` otherwise, never writes `*out` on failure), `static inline int cap_chain_depth(const v2_caps_t *st, unsigned long t, unsigned long s)` (`-1` on bad holder/slot, else the slot's `root ? 0 : 1`) — Task 2 uses these exact signatures

- [ ] **Step 1: Write the failing KAT**
  Create `tests/test_capquery.c` (CHECK-macro style per `tests/test_v2caps.c`): own-slot contents exact (rights/obj/valid/root after mint+grant flows); foreign-slot query returns `V2_ERR_INVALID` with `out` untouched (pre-fill sentinel); bad holder/slot denial; chain depth 0 on init root, 1 on minted and granted children (incl. attenuated no-QX child reporting narrowed rights); invalid slot → `-1` distinct from root `0`; op-number distinctness (`17`/`18` differ from 1–16, 14, 15 — literal constants, cross-checked against `kinternal.h`/`qube.h`).

- [ ] **Step 2: Run it to verify it fails**
  Run: `gcc -Wall -Wextra -Werror -Ikernel -I. -o /tmp/test_capquery tests/test_capquery.c`
  Expected: FAIL with `cap_query_slot`/`cap_chain_depth` undeclared.

- [ ] **Step 3: Implement both helpers in `kernel/caps.h`**
  Place after `cap_ns_visible`; each validates via `v2_cap_holder_ok` + `v2_has_cap` first, reads one slot, returns. No loops; no state writes.

- [ ] **Step 4: Run KAT to verify pass**
  Run: same command as Step 2
  Expected: `PASS: test_capquery` (exact string the test prints).

- [ ] **Step 5: Commit**
  ```bash
  git add kernel/caps.h tests/test_capquery.c
  git commit -m "feat(caps): query helpers + KAT (single-level lineage)"
  ```

### Task 2: Dispatch arms + QEMU smoke

**Files:**
- Modify: `kernel/kinternal.h` (add `V2_INV_QUERY 17`, `V2_INV_CHAIN 18` beside existing defines), `kernel/syscall_cap.c` (`handles()` cases + two arms)
- Test: QEMU smoke markers + host KAT (unchanged)

**Interfaces:**
- Consumes: Task 1's `cap_query_slot`/`cap_chain_depth`
- Produces: live ops; QUERY returns `(rights, obj, valid)` in reply words, CHAIN returns depth; both constant-shape arms (same gates, same order, same error code on all denials)

- [ ] **Step 1: Add op numbers + `handles()` cases**
  `V2_INV_QUERY 17` / `V2_INV_CHAIN 18` in `kinternal.h` with a comment citing qube 14/15 avoidance; extend `syscall_cap_handles` switch identically.

- [ ] **Step 2: Add the two arms**
  QUERY arm: `cap_query_slot(&caps, cur, a1, &q)` → on `V2_OK` reply `(q.rights, q.obj, q.valid)`, else `V2_ERR_INVALID`. CHAIN arm: `d = cap_chain_depth(&caps, cur, a1)` → reply `d` (`-1` included — it is data, not an error path). Neither arm writes state.

- [ ] **Step 3: Build + smoke**
  Run: `make -C kernel` (`-Werror` clean) + the stage-`[4/4]` QEMU block
  Expected: build clean; legacy markers byte-identical (no behavior change on existing paths).

- [ ] **Step 4: Commit**
  ```bash
  git add kernel/kinternal.h kernel/syscall_cap.c
  git commit -m "feat(caps): QUERY/CHAIN dispatch arms (read-only)"
  ```

### Task 3: V2_D read-only transition specs + refinement lemmas

**Files:**
- Modify: `kernel/isabelle/V2_D.thy` (append only — no existing lemma touched)
- Test: `isabelle build -D kernel/isabelle`

**Interfaces:**
- Consumes: existing `V2_D.thy` mint/grant transition + lemma patterns (mirror them exactly)
- Produces: `q_query`/`q_chain` transitions (identity on state, observations only) + `*_refines` lemmas + preservation proofs; KAT header cites the new lemma names

**Steps:** same TDD rhythm at proof level (state the lemma names first in the KAT comment per Task 1's vectors, then prove):
- [ ] Mirror the file's `d_mint`/`d_grant` definition style for `q_query`/`q_chain` as pure observations (no state update on any path, including denials).
- [ ] Prove `*_refines` (C transition is an A transition — holds trivially for reads; the proof obligation is stating it) + invariant preservation over the two new ops.
- [ ] Run: `isabelle build -D kernel/isabelle`
  Expected: clean, 0 `sorry`, 0 new axioms (read-only needs none).
- [ ] Append the exact new lemma names to the `tests/test_capquery.c` header comment (replacing any provisional citation with verified names).
- [ ] Commit `proof(isabelle): V2_D read-only query transitions + refinement`.

### Task 4: Verify wiring + review + merge-prep

**Files:**
- Modify: `tools/verify.sh` (`[1f]` block only)
- Test: `tools/verify.sh` (full run)

**Interfaces:**
- Consumes: Tasks 1–3
- Produces: green baseline ready for merge

- [ ] **Step 1: Wire the KAT into `verify.sh [1f]`**
  Add the compile+run line with the `|| echo "FAIL: test_capquery"` idiom beside the caps suite lines (Isabelle already gated by the existing job — no new gate needed).
  Run: `bash -n tools/verify.sh`
  Expected: syntax OK.

- [ ] **Step 2: Run full verification**
  Run: `tools/verify.sh`
  Expected: exit 0 modulo the known pre-existing shell-build reds (untracked `shell_expr.h`; document any other FAIL as new); `PASS: test_capquery`; QEMU legacy-identical plus the two new smoke markers; Isabelle PASS.

- [ ] **Step 3: Request code review**
  Dispatch the reviewer per `superpowers:requesting-code-review` over the task range before merging. Fix Critical/Important findings first. Reviewer must confirm the single-level-lineage constraint held (no parent state smuggled in).

- [ ] **Step 4: Merge-prep (no merge without explicit approval)**
  Confirm worktree clean except untracked generated headers; report branch ready. Do not merge or push.
