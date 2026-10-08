# Audit-cap + lifecycle-alias gap closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close deferred-B (audit fail-closed allow) and deferred-C (T_DEAD disambiguation) plus the 9 deferred minors, with proofs, markers, and docs.

**Architecture:** Task 1 wires the audit room-check pair into qube.h and the broker's two allow arms plus an in-kernel self-test leg. Task 2 caps the HOL audit model identically with theorems. Task 3 renumbers T_DEAD and simplifies the scans, gated by a byte-identical transcript. Task 4 sweeps the minors. Task 5 closes docs with a full verify.

**Tech Stack:** C (freestanding rv64imac stock clang `-Werror`; host clang for unit tests), Isabelle/HOL (session V2), bash (verify.sh/run_qemu.sh).

**Spec:** `docs/superpowers/specs/2026-09-25-audit-lifecycle-gaps-design.md`

## Global Constraints

- Freestanding only for kernel/ELF code: `-ffreestanding -nostdlib -fno-builtin -Wall -Wextra -Werror`; in-tree headers only.
- C subset: no `float`, no function-pointer dispatch, no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- Fail closed: no ALLOW actuates without an audit record; missing QEMU markers flip the smoke gate to FAIL.
- Unchanged bounds: `NTHREADS=10`, `V2_QUBES_MAX=8`, `V2_FRAMES_MAX=32`, `V2_NEP=10`, `V2_AUDIT_MAX=64`, `V2_PENDING_MAX` as-is.
- `tools/verify.sh` single entry: one new marker (`AUD: full ok`) in `[4/4]`, single QEMU cmdline, no new SKIP (CHERI SKIP pre-existing).
- Proofs: zero `sorry`/`axiomatization`, no `True`-definitions, mutant per new invariant.
- Reply codes: `R_OK 0`, `R_PENDING 1`, `R_DENY -1`; broker reply sites stay verbatim (call/response discipline from the live stage).
- `make -C kernel` does NOT regenerate tracked `kernel/initrd_data.c` — run `tools/mkinitrd.sh` between userspace and kernel builds whenever ELFs change.

---

## File Map

| File | Responsibility |
|---|---|
| Modify `kernel/qube.h` | `qube_audit_room` + `qube_audit_allow` helpers beside `qube_audit`. |
| Modify `userspace/qrexec_server/v2_main.c` | Allow-forward arm: helper swap; approve-deliver arm: room check before `qube_decide_idx`. |
| Modify `kernel/kboot.c` | In-kernel audit-full self-test leg (`AUD: full ok`); `T_DEAD 2→3` + state-comparison audit + scan simplification. |
| Modify `tests/test_qube_policy.c` | Overflow + helper tests. |
| Modify `kernel/isabelle/Qubes_A.thy` | `max_audit = 64`, room-gated allow/approve appends. |
| Modify `kernel/isabelle/Qubes_B.thy` | C-mirrors of the same gating. |
| Modify `kernel/isabelle/V2_C.thy` | Two lemma touch-ups (dup + snoop assert) — minors only. |
| Modify `tests/test_v2ipc.c`, `userspace/adminvm/v2_main.c`, server headers | Comment/indentation minors (D). |
| Modify `tools/verify.sh` | `[4/4]` +1 line: `AUD: full ok`. |
| Modify `docs/V2_DESIGN.md`, `docs/QUBES_ISOLATION_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | B/C → BUILT. |

---

### Task 1: Audit fail-closed allow — code + host tests + self-test leg

**Files:**
- Modify: `kernel/qube.h` (helpers after `qube_audit`, ~line 130)
- Modify: `userspace/qrexec_server/v2_main.c` (allow-forward ~line 338, approve-deliver ~line 248)
- Modify: `tests/test_qube_policy.c` (append overflow/helper block)
- Modify: `kernel/kboot.c` (self-test leg beside the S2 demo; exact spot: after the audit-count leg that prints `AUD: N entries`)
- Modify: `tools/verify.sh` (`[4/4]`, one line after the `live deny` gate)
- Test: host `test_qube_policy` + QEMU `AUD: full ok`

**Interfaces:**
- Consumes: nothing new (existing `qube_audit`, `V2_AUDIT_MAX 64`, broker arms, S2-demo self-test pattern).
- Produces: `qube_audit_room`, `qube_audit_allow` (Task 2 models their semantics); `AUD: full ok` marker (Task 5 docs).

- [ ] **Step 1: Write the failing host tests** — append to `tests/test_qube_policy.c` (read its CHECK idiom + policy fixture first; follow it exactly):

```c
    /* Audit cap: fail-closed allow (deferred-B). Fill via qube_audit. */
    {
        v2_qpolicy_t full;
        int i, rc;
        /* build an empty policy with room for audit: reuse the file's
         * fixture constructor (same call the existing tests use). */
        ... fixture init ...
        for (i = 0; i < 64; i++)
            CHECK(qube_audit(&full, 0, 6, 1, 1) == 0);
        CHECK(full.naudit == 64);
        /* 65th drops with entries intact. */
        CHECK(qube_audit(&full, 0, 6, 1, 1) == -2);
        CHECK(full.naudit == 64);
        CHECK(full.audit[63].src == 0 && full.audit[63].rpc == 1);
        /* Helper refuses at cap, appends below cap. */
        CHECK(qube_audit_allow(&full, 0, 6, 1) == -2);
        CHECK(full.naudit == 64);
        CHECK(qube_audit_room(&full) == 0);
        full.naudit = 63;
        CHECK(qube_audit_room(&full) != 0);
        CHECK(qube_audit_allow(&full, 0, 6, 1) == 0);
        CHECK(full.naudit == 64);
    }
```

(`-2` is `V2_ERR_OVERFLOW`; if the file defines named constants for these, use them instead — read first. The `... fixture init ...` must be replaced with the file's real constructor lines; do not invent API.)

- [ ] **Step 2: Run, watch fail**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_qube_policy tests/test_qube_policy.c 2>&1 && /tmp/test_qube_policy`
Expected: FAIL — `qube_audit_room`/`qube_audit_allow` undeclared (or the overflow assertions if the header already has them).

- [ ] **Step 3: Helpers in qube.h** — directly after `qube_audit`, same style (null guard, `/* bound: */` n/a — single comparisons):

```c
/* Audit room for fail-closed allow (deferred-B): nonzero iff an
 * allow record fits. Deny paths never consult this (denial is the
 * safe direction and needs no record). */
static inline int qube_audit_room(const v2_qpolicy_t *q)
{
    return q && q->naudit < V2_AUDIT_MAX;
}

/* Check-and-append for allow arms: OVERFLOW with zero state change
 * when full (the caller must NOT actuate), else the allow record.
 * Split from room-check because qube_decide_idx appends itself. */
static inline int qube_audit_allow(v2_qpolicy_t *q, unsigned long s,
                                   unsigned long d, unsigned long r)
{
    if (!qube_audit_room(q))
        return -2; /* V2_ERR_OVERFLOW */
    return qube_audit(q, s, d, r, 1);
}
```

(Verify `-2` matches the file's `V2_ERR_OVERFLOW` spelling; use the macro if present.)

- [ ] **Step 4: Broker arms** — allow-forward: replace `qube_audit(&pol, sqb, svc, rpc, 1);` (~line 338) with:

```c
                    if (qube_audit_allow(&pol, sqb, svc, rpc) != 0) {
                        /* Audit full: deny-shape print, R_DENY, no SEND. */
                        u_puts("AUD: deny rpc=");
                        u_putdec((long)rpc);
                        u_putc('\n');
                        u_reply(snd, R_DENY);
                    } else {
```

wrapping the existing SEND + `AUD: allow rpc=` print + `u_reply(snd, R_OK)` in the `else` (keep those three lines verbatim inside). Approve-deliver: before `qube_decide_idx(&pol, idx, approve)` (~line 248), insert:

```c
                    if (!qube_audit_room(&pol)) {
                        /* Audit full: dequeue as deny (record best-effort),
                         * deny-shape print, no SEND, no reply. */
                        (void)qube_decide_idx(&pol, idx, 0);
                        u_puts("AUD: deny rpc=");
                        u_putdec((long)rpc);
                        u_putc('\n');
                    } else
```

wrapping the existing approve body in the `else` (keep verbatim; the existing `qube_decide_idx(&pol, idx, approve)` call stays inside). Deny arms: untouched.

- [ ] **Step 5: In-kernel self-test leg** — in `kernel/kboot.c` after the S2 audit-count leg (the block printing `AUD: N entries`), insert a straight-line bounded leg (S2 shape, local struct only, no loops over 64 — unroll-free fill via a bounded `for` with `/* bound: V2_AUDIT_MAX */`):

```c
        /* Audit-full self-test (deferred-B): model the cap rule on a
         * local policy — 64 appends ok, 65th OVERFLOW with entries
         * intact, helper refuses at cap and appends below it. */
        {
            v2_qpolicy_t fulltest;
            int fq;
            fulltest.nrules = 0;
            fulltest.npending = 0;
            fulltest.naudit = 0;
            for (fq = 0; fq < 64; fq++) { /* bound: V2_AUDIT_MAX */
                if (qube_audit(&fulltest, 0, 6, 1, 1) != 0)
                    kputs("[demo] FAIL audit fill\n");
            }
            if (fulltest.naudit != 64 ||
                qube_audit(&fulltest, 0, 6, 1, 1) != -2 ||
                fulltest.naudit != 64 ||
                qube_audit_allow(&fulltest, 0, 6, 1) != -2 ||
                !qube_audit_room(&fulltest) == 0) {
                kputs("[demo] FAIL audit cap\n");
            } else {
                fulltest.naudit = 63;
                if (!qube_audit_room(&fulltest) ||
                    qube_audit_allow(&fulltest, 0, 6, 1) != 0 ||
                    fulltest.naudit != 64) {
                    kputs("[demo] FAIL audit room\n");
                } else {
                    kputs("AUD: full ok\n");
                }
            }
        }
```

(Fix the `!qube_audit_room(...) == 0` awkwardness: room returns nonzero when room exists, so "refuses at cap" asserts `qube_audit_room(&fulltest) == 0`. Write it cleanly; `-2` must match `V2_ERR_OVERFLOW` — check the header spelling first. If `v2_qpolicy_t` needs fuller init (pending arrays), mirror the S2 `demo` init block above it.)

- [ ] **Step 6: Smoke gate** — in `tools/verify.sh [4/4]` after the live-deny line:

```bash
    echo "$V2LOG" | grep -q "AUD: full ok" && echo "v2 smoke: audit full" || { echo "v2 smoke: FAIL (no audit full)"; QEMU_FAIL=1; }
```

- [ ] **Step 7: Host green + targeted smoke**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_qube_policy tests/test_qube_policy.c 2>&1 && /tmp/test_qube_policy`
Expected: PASS (existing + new).
Run: `make -C userspace 2>&1 | tail -n 2 && tools/mkinitrd.sh >/dev/null 2>&1 && make -C kernel 2>&1 | tail -n 2`
Expected: clean (mkinitrd between builds is MANDATORY or QEMU boots stale ELFs).
Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke: audit full|FAIL|verify done"`
Expected: `v2 smoke: audit full` + zero FAIL. (Full 44/45 PASS comes in Task 5; here the marker + no-FAIL suffices.)

- [ ] **Step 8: Commit**

```bash
git add kernel/qube.h userspace/qrexec_server/v2_main.c tests/test_qube_policy.c kernel/kboot.c tools/verify.sh kernel/initrd_data.c kernel/initrd.h
git commit -m "gaps: audit fail-closed allow plus full-cap self-test"
```

(Include regenerated `initrd_data.c`/`initrd.h` — tracked blobs, FDE/live precedent. If `initrd.h` is untracked/generated-ignored, add only what `git status` shows as modified.)

### Task 2: Audit-cap model — Qubes_A/B + Isabelle build

**Files:**
- Modify: `kernel/isabelle/Qubes_A.thy` (`max_audit`, room-gated appends)
- Modify: `kernel/isabelle/Qubes_B.thy` (C-mirrors)
- Test: `isabelle build -D kernel/isabelle -v` + anti-vacuity greps

**Interfaces:**
- Consumes: Task 1 (helper semantics: full → unchanged + OVERFLOW; room → append).
- Produces: `audit_full_blocks_allow`, deny-still-proceeds, preservation (Task 5 docs).

- [ ] **Step 1: Qubes_A cap** — add after `max_pending`:

```isabelle
definition max_audit :: nat where
  "max_audit = 64"
```

Gate the three appending transitions on room; denial/dequeue never blocked:
- `q_call` Allow arm: `(if length (audit st) < max_audit then <existing append> else st)` — full allow = state unchanged (no record, and the broker contract says no actuation without a record).
- `q_call` Ask/Deny arms: unchanged (deny needs no record; ask-overflow arm already deny-audits — keep appending to mirror C best-effort? NO: C `qube_ask_enqueue` deny-audit also fails silently when full. Mirror exactly: appends happen via the same room rule? The C ask path calls qube_audit (not the helper) — fails silently when full. So model: Ask/Deny arms append UNCONDITIONALLY (matching C best-effort, records may... wait, model lists are unbounded — appending always succeeds in HOL. The C drops when full. To mirror C exactly, the model must also gate ALL appends on room: `audit' = if room then audit@[rec] else audit`. Then deny-still-proceeds = dequeue/state change happens, record maybe dropped. And allow: NO append possible when full AND (broker contract, outside the transition) no actuation. Hmm — but then what distinguishes allow from deny in the model? The `oallow` bit + the lemma `audit_full_blocks_allow`: full audit ⇒ no True-recorded transition. Formulate:
  - `q_call` Allow: `if room then append-True else st` (unchanged state).
  - `q_call` Ask/Deny, `q_decide`, `q_destroy`: append iff room (`audit @ (if room then [rec] else [])`), other state changes always apply.
- [ ] **Step 2: Lemmas** (names; statements must pin the rule):

```isabelle
lemma audit_full_blocks_allow: length (audit st) ≥ max_audit ⟹ q_call src dst rpc h st = st (when decision would be Allow — state the premise as find_decision ... = Allow)
lemma deny_appends_or_drops: q_call Deny-case always dequeues/applies with audit extended iff room
lemma audit_preserved_capped: q_unique/q_bounded/p_bounded preserved by all four ops (replay with room premises)
mutants: full-audit allow attempt changes nothing; drop-attempt preserves entries
evals: 64-fill model demo (build via replicate + fold — keep small: replicate 64 of one outcome, then q_call)
```

(Write evals with small numerals only; any KAT-style pin uses `simp`, never `eval` on large numbers — FDE lesson.)

- [ ] **Step 3: Qubes_B mirrors** — `c_q_call`/`c_q_destroy`/`c_decide` equivalents take the same room gating (they call the same `find_decision`/`audit` shapes — mirror the A edits arm-for-arm; `c_*bounded` lemmas gain `audit` length premises where the A proofs need them).
- [ ] **Step 4: Build + gates**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 3`
Expected: `Finished V2`, all theories 100%.
Run: `grep -rn "sorry\|axiomatization\|quick_and_dirty\|oops" kernel/isabelle/; grep -rn "equiv> True" kernel/isabelle/*.thy; echo "gate done"`
Expected: empty before `gate done`.

- [ ] **Step 5: Commit**

```bash
git add kernel/isabelle/Qubes_A.thy kernel/isabelle/Qubes_B.thy
git commit -m "gaps: audit-cap model plus allow-blocked theorems"
```

(If Qubes_C/D need ripple per the build, add with minimal diffs and name them in the message — bound-ripple rule.)

### Task 3: T_DEAD disambiguation + byte-identical verify

**Files:**
- Modify: `kernel/kboot.c` (define + all state sites + scan simplification)
- Test: full `tools/verify.sh` transcript UNCHANGED (no new markers — the gate passing as-is is the test)

**Interfaces:**
- Consumes: nothing from Tasks 1–2 (independent files; shared file kboot.c — coordinate: Task 1's self-test leg stays verbatim).
- Produces: simplified scans (Task 5 docs).

- [ ] **Step 1: Renumber** — `#define T_DEAD 2` → `#define T_DEAD 3` (keep `#define T_BLOCKED 2`, keep `T_RUNNABLE 0`/`T_PARKED 1`). Leave a comment: `/* distinct from T_BLOCKED since deferred-C: slot-reuse scans key on state alone */`.
- [ ] **Step 2: Audit every state site** — grep `T_BLOCKED|T_DEAD|state ==|state !=|state =` and disposition each (read-only verify vs edit):
  - `pick_next` RUNNABLE-count: read-only (DEAD≠RUNNABLE skips ✓).
  - `halt_no_runnable` detection: read-only (counts RUNNABLE ✓ — verify by reading).
  - IRQ wake `threads[6]/[9] == T_BLOCKED`: read-only (dead thread correctly not woken ✓).
  - `threads[cur].state = T_BLOCKED` sets (SEND/RECV/WAIT/fault park): UNCHANGED (parking semantic).
  - `threads[cur].state = T_RUNNABLE` wakes: UNCHANGED.
  - `T_PARKED` sets/inits: UNCHANGED.
  - WAIT/NOTIFY `wait_kind`-keyed paths: UNCHANGED (verified keyed, not state-read).
  - The 3 scan sites (SPAWN ×2, QDESTROY ×1): SIMPLIFY each to `if (threads[t].state == T_DEAD)` alone — delete the `wait_kind`/`ipc_ptr`/`ipc_cap` conjuncts AND the alias comments, replace with `/* deferred-C: T_DEAD is distinct; state alone frees the slot */`. A rendezvous-blocked thread is state BLOCKED(2)≠DEAD(3) and can no longer match.
  - QDESTROY `state = T_DEAD` sets: UNCHANGED (value flows from the define).
- [ ] **Step 3: Build + byte-identical smoke**

Run: `make -C kernel 2>&1 | tail -n 2` (no userspace change → no mkinitrd needed; initrd blob untouched).
Expected: clean.
Run: `tools/verify.sh 2>&1 | grep -E "FAIL|verify done"`
Expected: zero FAIL. Acceptance = the EXISTING suite (incl. `AUD: full ok` from Task 1) passes with NO verify.sh change — proves the renumber altered nothing observable.

- [ ] **Step 4: Commit**

```bash
git add kernel/kboot.c
git commit -m "gaps: disambiguate T_DEAD plus simplify reuse scans"
```

### Task 4: Deferred-minors sweep

**Files:** `tests/test_v2ipc.c`, `kernel/ipc.h`, `kernel/kboot.c` (indent only), `userspace/adminvm/v2_main.c`, server headers with stale EP0 comments, `docs/V2_DESIGN.md` (S3 reword — or leave for Task 5 docs? DO IT HERE: one-line reword, reviewed in this task), `kernel/isabelle/V2_C.thy` (dup lemma + snoop assert), `userspace/qrexec_server/v2_main.c` (T_DECIDE invalid-dst audit line), empty-take reply edge sites.
**Test:** host `test_v2ipc` + `make -C kernel` + `isabelle build` (V2_C touched) — targeted, not full verify.

- [ ] **Step 1: Mechanical items (no behavior change)** —
  - test_v2ipc.c loops + ipc.h:102: add `/* bound: V2_IPC_Q */` to the 4 `for` loops.
  - kboot.c QDESTROY sweep: re-indent inner loops under the outer EP loop (whitespace only — verify with `git diff -w` showing EMPTY for that hunk before committing... careful: `git diff -w` empty proves whitespace-only).
  - Stale comments → addressed wording: adminvm put-back arm comment, server header "EP0 protocol" lines, `kboot.c` endpoint comment. (Grep `EP0` in userspace/ + kboot header comment; rewrite each, no code change.)
  - V2_DESIGN.md S3 KNOWN DEFERRED "over EP0" → "over addressed EPs" (item stays open).
  - V2_C.thy: delete or differentiate `ipc_demo_same_ep` vs `ipc_demo_ping`; assert `ok1` in the snoop-differs lemma (or bind `_`).
- [ ] **Step 2: Behavior-adjacent items (reviewer-flagged, keep fail-closed)** —
  - qrexec T_DECIDE invalid-dst branch: add the missing `qube_audit(..., 0)` line to match the ALLOW arm's audit discipline (dead by construction — dst 4..7 only — but consistent).
  - Empty-take reply edge (mem/fw/vault/cryptblk/user.c sites from the final review): replace `u_reply(snd, ...)` / `usend(snd, ...)` on the `n < 1` path with bare `continue` (no SEND). Rationale recorded: RECV blocks rather than returning 0, so the path is unreachable; the SEND only ever queued to EP0. If ANY site's reachability is doubtful on reading, LEAVE that site untouched and report it (do not guess).
- [ ] **Step 3: V2_C double-notify eval pins** — append eval lemmas pinning take-and-clear + second-WAIT-re-blocks (UABI wake-delivery KAT for the `regs[10]=pending` fix; small constants only).
- [ ] **Step 4: Targeted verification**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_v2ipc tests/test_v2ipc.c 2>&1 && /tmp/test_v2ipc && make -C kernel 2>&1 | tail -n 1`
Expected: ALL PASS + clean build.
Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 2`
Expected: Finished V2 (V2_C lemma edits must still prove).
Run: `git diff -w --stat` vs `git diff --stat` — confirm the ONLY non-whitespace diffs are the intended ones (audit line, V2_C lemmas, comments don't count as code but DO show in -w; the check is: no unintended code hunks).

- [ ] **Step 5: Commit**

```bash
git add tests/test_v2ipc.c kernel/ipc.h kernel/kboot.c userspace/adminvm userspace/qrexec_server/v2_main.c userspace/mem_server userspace/firewall userspace/vault userspace/cryptblk kernel/user.c kernel/isabelle/V2_C.thy docs/V2_DESIGN.md
git commit -m "gaps: deferred-minors sweep plus notify KAT pins"
```

(Stage only files that actually changed — drop untouched paths from the add.)

### Task 5: Docs + full verify (stage closure)

**Files:**
- Modify: `docs/V2_DESIGN.md` (§9: B/C → BUILT + refinements + D note), `docs/QUBES_ISOLATION_PLAN.md` (§11 deferred-B/C → BUILT, D noted), `docs/ARCHITECTURE.md` (audit-cap rule + T_DEAD subsections + verification list), `docs/BUILD.md` (transcript: `AUD: full ok` line)
- Test: `tools/verify.sh` end-to-end

**Interfaces:**
- Consumes: Tasks 1–4 artifacts.

- [ ] **Step 1: Update docs** — every BUILT names test/marker/lemma/path: helper names + `test_qube_policy` + `AUD: full ok` + `audit_full_blocks_allow`/`max_audit`; `T_DEAD 3` + simplified scans + byte-identical gate; the 9 minors as a named list (each with path or reviewer sign-off for the rejected/unreachable ones); honest remainder (S4, Stage 4, USB/RX still open); closed holes named (silent audit drop, alias fragility).
- [ ] **Step 2: Full verification**

Run: `tools/verify.sh 2>&1 | tail -n 12`
Expected: host PASS (incl. extended `test_qube_policy`), gates PASS, kernel PASS, QEMU PASS with `AUD: full ok`, Isabelle PASS or pre-existing SKIP only, zero FAIL, no new SKIP.

- [ ] **Step 3: Commit**

```bash
git add docs/V2_DESIGN.md docs/QUBES_ISOLATION_PLAN.md docs/ARCHITECTURE.md docs/BUILD.md kernel/initrd_data.c kernel/initrd.h
git commit -m "gaps: docs mark B-C built with proof-test links"
```

(Include regenerated blobs per the tracked-blob convention; drop `initrd.h` if ignored/unmodified.)

---

## Self-Review

- **Spec coverage:** §2 helpers/arms/self-test → Task 1 (all three table rows owned: allow-full → DENY+no-SEND; deny-full → proceeds; null → INVALID); §2 testing (host/model/smoke) → Tasks 1–2 + Task 5 gate; §3 renumber/audit/simplify/testing → Task 3 (all state sites dispositioned: 477/591-619 read-only, 643/655 read-only, 691+ park sets unchanged, 859 keyed untouched, 3 scans simplified, QDESTROY sets flow from define); §4 nine minors → Task 4 items 1–9 one-to-one (item 8 carries the reachability opt-out); §5 non-goals → none tasked; §6 exit → Tasks 1–5 gates.
- **Placeholder scan:** no TBD/TODO/later/appropriate/edge-cases/similar-to; every code step ships concrete constants (`V2_AUDIT_MAX 64`, `T_DEAD 3`, `ADMIN`/qube/EP ids from prior stages, `R_OK 0`, reply words `[1]`/`[-1]`, marker strings), commands and expected outputs. Investigation points owned explicitly (fixture-constructor read, `-2` spelling check, `initrd.h` tracked-or-not, rpc-id re-verification for table-adjacent code — none here —, `git diff -w` check, doubtful-site opt-out).
- **Type consistency:** `qube_audit_room`/`qube_audit_allow` names match spec §2; `max_audit = 64` matches `V2_AUDIT_MAX`; `AUD: full ok` string identical in kboot leg, verify gate, docs; `T_DEAD 3` vs `T_BLOCKED 2` consistent in define + simplified scans; Task 4's `qube_audit(...,0)` addition matches the exact existing deny-shape call two lines above it.
