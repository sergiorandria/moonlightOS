# Burst-Typing Race Hunt — Investigation Spec (rev 1)

**Status:** Draft for review. Pure analysis + evidence plan; NO code changes.
No interference with in-flight sessions (read-only grounding; new file).
**Parent:** S4c KNOWN ISSUE (PARKED top remainder) — `2026-10-03-s4c-input-design.md`
§ KNOWN ISSUE, `V2_DESIGN.md:703-710`.

## 1. Recorded evidence (from S4c landing)

- Under sustained rapid typing (~1 in 3 burst runs) the guest takes a store
  page fault (`scause=0xf`) whose printed `sepc` is a trap-entry `sd` and
  whose `stval` is a U-stack address; the fault handler parks the GUI and
  input dies from there — always WITHOUT FAIL/EXHAUSTED corruption, WITHOUT
  gate impact (canary/verify/KATs deterministic green).
- Singles/paced typing 100% clean across ~1500 input IRQs (two full-green
  live VNC runs). No typing rate is required by any gate.
- Traced already: QEMU `-d int`, PLIC `xp` reads, trap disassembly. Suspect
  stayed unproven for lack of a trap-aware (GDB-level) session.

## 2. Mechanism analysis (new): nested S-trap vs `sscratch` protocol

`kernel/trap.S:10` entry swaps `sp↔sscratch`, assuming entry state is
`sp = user sp`, `sscratch = trap-stack top`. If a SECOND trap fires while
already in S-mode on the trap stack (interrupts live inside the handler —
note the S4c wake path re-enables SIE at halt, and burst typing keeps the
PLIC line asserted), entry swaps the wrong way: `sp` becomes the saved
**user-sp value** while S-mode, `sscratch` becomes a trap-stack address.
The very next `sd t0, 0(sp)` stores to a U page with `SUM=0` → store page
fault with `epc` = trap-entry `sd` and `tval` = U-stack address — EXACTLY
the recorded symptoms. The `csrr sscratch → x2 slot` save (`trap.S:45-46`)
then persists the trap address as the thread's sp, corrupting all later
returns (fault loop, park). Burst rate raises IRQ-overlap probability,
matching ~1-in-3 vs paced-clean.

## 3. Hypotheses (ordered, each with falsifier)

- **H1 — S-mode re-trap nesting (primary).** As §2. FALSIFY: log
  `sstatus.SPP` at handler entry (SPP=1 ⇔ already in S-mode ⇔ nested).
  Zero SPP=1 over 30 burst sessions rejects H1. CONFIRM: any SPP=1 entry
  immediately before a `0xf` fault with trap-entry epc.
- **H2 — SIE window too wide (variant of H1).** Some handler path leaves
  SIE set (halt-wake, WAIT-wake pre-delivery). FALSIFY: sample
  `sstatus.SIE` at 3 handler points (entry, pre-`u_enter`/return,
  post-wake); if SIE is clear at all points during bursts, the nesting
  window must come from elsewhere — back to H1's entry protocol or H3.
- **H3 — SUM/window discipline under overlap.** A `u_copy` (SUM set)
  interrupted by an input IRQ whose handler touches U memory. FALSIFY:
  faulting `tval` never falls in a copy window AND fault `epc` is always
  the entry `sd` (H1's signature) rather than a copy loop address.
- **H4 — QEMU/PLIC artifact (spurious/claim race).** FALSIFY: same
  signature on `-d int` traces showing a genuine second `scause=9/11`
  before the `0xf`; spurious claims would show claim-0/spurious patterns
  instead.

## 4. Evidence-capture plan (cheapest discriminator first)

1. **SPP spike (minutes):** debug-only `kputs` of `(scause, SPP, SIE)` at
   `s_trap_handler` entry behind a temporary flag (never committed, or
   committed behind `TRAP_DEBUG` default-off). 30 burst sessions: count
   SPP=1 entries; correlate with `0xf` faults. Decides H1.
2. **`-d int` + PLIC `xp` burst capture:** confirm second-IRQ-before-fault
   ordering; record (`sepc`, `stval`, `sscratch`-class) triples.
3. **GDB-level session** (RISC-V GDB absent in this env — provision first):
   break at `s_trap_entry`, burst-type, catch the nested entry live;
   inspect `sp`/`sscratch`/SUM at the faulting `sd`.
4. **Code audit fallback:** `trap.S` save/restore + all `csrs sstatus,SIE`
   sites + halt/wake path, against the §2 walk.

## 5. Fix directions (per hypothesis — implementer picks after evidence)

- H1 confirmed: narrow the interruptible window (clear SIE across the
  handler critical section / save-restore), or give nested S-traps their
  own entry stack with an SPP-keyed branch at `s_trap_entry`.
- H2 confirmed: move SIE enable to the exact wake point; keep it clear
  everywhere else in-handler.
- H3 confirmed: SUM-scoped copies with IRQ discipline (set/clear pairs
  that an IRQ cannot interleave into U-touching code).
- H4 confirmed: PLIC claim/spurious handling + QEMU version pin note.
- All fixes re-run: S4b markers, INPUT markers, 30/30 burst sessions,
  paced suite, KATs, `verify.sh`, Isabelle session (only if handler
  logic changes shape — comment-only/CSR-mask changes need no replay;
  state the call in the fix report).

## 6. Acceptance

- 30/30 burst-typing sessions clean (typed echo correct, no park, zero
  FAIL/EXHAUSTED), paced suite + gates still green, root cause named with
  the falsifier output that decided it, fix + regression marker committed.
- Coordinate with the in-flight kernel refactor session before touching
  `trap.S`/`kboot.c` (their REVOKE + lazy-spawn work overlaps these
  paths); rebase evidence if the tree moved.

## Non-goals

No focus/clipboard/ANSI work; no proof-shape changes beyond what a fix
requires; no QEMU version changes unless H4 confirms an artifact.
