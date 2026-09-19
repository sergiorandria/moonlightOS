# Moonlight v2 — Design: a verifiable RISC-V CHERI microkernel

Status: DESIGN + Stages 0–3 built (see §9 for per-stage BUILT notes).
Every section ends with what must exist before the next begins. Only §9
stage entries marked BUILT are claimed as built. The v2/ tree was merged
into the repo root on 2026-09-14: this repo is now the single codebase.

## 0. Why v2, and what v1 taught us

v1 (this repo) boots and runs a cooperative shell, but its structure cannot
grow into a verified system. The load-bearing lessons, each paid for in
debugging time:

1. **U-mode from day one.** v1 runs everything in M-mode (`medeleg=0`, no
   `mret`-to-user anywhere). Isolation was therefore unprovable *by
   construction*. v2 puts the kernel in **S-mode** and userspace in **U-mode**;
   M-mode holds only a minimal firmware shim (reuse OpenSBI, do not write our
   own). The privilege theorem is then statable: *U-mode code cannot execute
   privileged operations or address kernel memory*.
2. **Dispatch loop before servers.** v1's `process_create` built TCBs that
   never ran — boot ended in `wfi`. v2's Stage 1 exit criterion is a
   *preemptive round-robin that actually context-switches*, before any server
   exists.
3. **User-copy both directions from day one.** v1's IPC re-read the kernel's
   own buffer; real caller data never crossed the boundary until a late fix,
   and `REPLY_RECV` still has no copy-out. v2 specifies the copy discipline
   (in/out/both per syscall) in the abstract spec, not as an afterthought.
4. **Linker output is part of the TCB.** An orphan `.rodata.str1.1` landed
   inside `[_bss,_bss_end)` and the BSS clear wiped every string literal —
   the kernel ran blind for its whole life. v2 checks section layout in CI
   (see §8).
5. **Proofs must be non-vacuous.** v1's Isabelle theories prove tautologies:
   invariants `≡ True`, `utilization=0`, models that assume the conclusion.
   v2 adopts anti-vacuity rules (§6) — a proof that cannot fail proves nothing.
6. **No ambient authority, even for debug.** v1 grew `SYS_DEBUG_PUTC/GETC`
   as ambient syscalls and an in-kernel VGA driver. v2: early-bring-up
   polled UART exists only behind a `BRINGUP_CONSOLE` build flag, deleted
   (not deprecated) once the console server lands.
7. **One verification entry point.** v1's `verify.sh` vs CI workflow drifted.
   v2 has exactly one script; CI calls it and nothing else.

## 1. Goals / non-goals

**Goals:** S-mode microkernel, ~4k LOC C (parseable subset, §5), U-mode
purecap userspace, hardware-enforced isolation (PMP + `satp` + CHERI),
capability-based everything, machine-checked refinement spec→C for the
core state machine, shell + IPC + drivers all in userspace.

**Non-goals:** POSIX compat (a shell, not bash), SMP (hart0 only until
Stage 5), `float` in kernel, dynamic loading (`dlopen`), page swapping.

## 2. Privilege and hardware contract

```
M-mode: OpenSBI (external, audited version pin) — PMP setup, SBI ecall gate
S-mode: v2 kernel (verified) — traps via stvec, memory via satp, time via stime
U-mode: userspace, purecap — PCC/CSP bounded per thread, DDC = nothing
```

- Kernel never maps user memory with RWX; user never maps kernel memory.
- PMP: `kernel RX` (text/rodata), `kernel RW` (data/bss/stacks), per-process
  frames only in that process's VSpace. PMP config is part of the abstract
  state and part of every isolation proof.
- Interrupts: PLIC → S-mode external trap; timer via SBI `set_timer`.
  All trap paths specified (ecall/breakpoint/fault/IRQ/timer) with
  `sepc` advance rules — v1's trap.S advanced only ecall ranges; v2's spec
  enumerates every `scause`.
- CHERI: hybrid kernel, purecap userspace. Capability derivation goes
  through ONE constructor (`cap_derive`: subset check on perms AND bounds,
  tag preserved). Monotonicity is then an invariant of the constructor,
  not a lemma about a struct update (v1's mistake).

## 3. Kernel objects (closed set, as v1 — minus ambient hacks)

Untyped, CNode, TCB, VSpace, Frame, Endpoint, Notification, IRQ, IOMMU
window, SchedContext, TimePartition. No console object (console is a
*server* holding Frame+IRQ caps). Object count is frozen at 11; adding one
requires a spec change + proof replay, by rule.

## 4. Syscalls (final set — no debug ambient calls)

`Call, ReplyRecv, Send, Yield, Seal, Invoke` — v1's six, with corrected ABI:

- `Call/Send(ep, u_msg)`: `u_msg` is a user pointer; kernel copies
  header → validates `length/caps` → copies words/caps. Validation order
  is specified and tested with adversarial lengths.
- `ReplyRecv(ep, u_buf, u_len)`: blocks, and on delivery copies OUT into
  the user buffer (v1 never did this). Truncation returns `ERR_OVERFLOW`
  with bytes-written, never silent cut.
- `Invoke` ops as v1's 12, minus demo encodings: every op takes explicit
  cap slots (no `dest in high bits` hacks, no slot-0 fallbacks).
- `Yield` is a scheduling hint with no information return (constant-time,
  no data-dependent path — and this time it is *measured*, see §8).

## 5. C subset (what the prover can swallow)

- `-ffreestanding`, no libc, no `float`, no function-pointer dispatch
  (switch on object type — auditable exhaustiveness), no recursion,
  bounded loops only (each loop carries a `/* bound: N */` comment tied
  to a constant the WCET argument uses).
- Machine-dependent code (context switch, `satp`/`stvec` writes) lives in
  exactly two files (`trap.S`, `ctx.c`), each under 150 lines, each with
  a host-sim twin used by unit tests. (v1's `thread_enter` register bug
  is why: asm blocks get early-clobber review + a QEMU round-trip test.)
- `memcpy` direction rule: every kernel↔user copy goes through
  `copy_from_user` / `copy_to_user`, which validate-then-copy. Raw
  dereference of a user pointer is a CI grep failure.

## 6. Verification strategy (the point of v2)

**Refinement stack, spec-first:**
`Sail/RISC-V formal (by reference, never hand-rolled)` →
**A** abstract spec (Isabelle/HOL, functional state machine) →
**E** executable spec (deterministic, testable) →
**C** implementation (AutoCorres where feasible, manual refinement + CBMC
per-function where not).

**Theorems that must hold (each falsifiable):**
- *User isolation:* no U-mode transition reaches M/S state or kernel memory.
- *Authority confinement:* a write/grant/map affects only objects reachable
  from the caller's caps (stated over the MDB + VSpace, not `True`).
- *IPC integrity:* a received message equals a sent message (no forge,
  no splice), modulo explicit truncation signaling.
- *Temporal isolation:* partition budgets enforced on every path that
  consumes time, including the scheduler itself (v1's picker blew the
  5µs budget by its own comment).
- *Refinement:* every C transition is an A transition (the one theorem
  v1 axiomatized away).

**Anti-vacuity rules (CI-enforced):**
1. No definition `≡ True`/`= 0` in a spec file (grep gate).
2. Every invariant ships with a **mutant test**: a concrete state the
   invariant rejects (checked by `nitpick`/`quickcheck` or a unit test).
3. `sorry`-free always; axiom budget: max 3, each named, dated, and
   linked to the stage that will discharge it.
4. Proofs run in CI on every push (Isabelle build is a job, not a script
   nobody runs).

## 7. Scheduling (dispatch exists at Stage 1)

- Stage 1: preemptive round-robin, timer-driven, per-hart, O(1) bitmap
  picker (v1's 256×N scan is banned by the C-subset loop-bound rule).
- Stage 3+: EDF within static time partitions (v1's design, kept), but
  admission control lives in the sched_server while *enforcement*
  (budget decrement, overrun → preempt + fault to server) is kernel.
- WCET: measured on QEMU + bounded by construction; `wcet_check` keeps
  v1's shape but the budget constant is derived from measurement + margin,
  documented, not magic.

## 8. Build / verify workflow (one door)

- `tools/verify.sh` is the ONLY entry: stages host-unit → Isabelle →
  CBMC (from day one, per-function, in CI — v1 made it manual) → RISC-V
  build → QEMU text smoke.
- **Linker gate:** assert `_bss` > end of all PROGBITS; assert a known
  canary string's bytes at its linked address (the exact bug class v1 hit).
- **Smoke asserts text**, not just bytes: QEMU run must print the boot
  banner AND answer a console command (v1's smoke passed for months on
  hex noise + timeout-kill).
- Docs rule: any `.md` claim links to a proof name, test name, or artifact
  hash. Aspirational text lives only in this file's roadmap section.

## 9. Staged roadmap (each stage ends with proof + running demo)

- **Stage 0 — Spec skeleton.** A-state, transitions for TCB/create/switch
  on one address space, CI Isabelle build, mutant tests for each invariant.
  *Demo:* `E` runs as a host simulator stepping two threads.
  - BUILT 2026-09-09: `kernel/isabelle/V2_A.thy` (session `V2`, `isabelle build`
    clean, 0 axioms, 0 `sorry`). State = thread list + `cur`; transitions
    `tcb_create/suspend/resume` + `sched_step` (lowest-Runnable; round-robin
    fairness is Stage-1 liveness work, noted in the theory). Invariants
    `valid_ids`/`bounded` with preservation across all 4 transitions,
    `step_picks_runnable`, mutant witnesses for both, `eval` lemmas pinning
    demo values. Gated in `verify.sh [2b/2c]` + CI `isabelle` job.
- **Stage 1 — S-mode kernel + U-mode hello.** stvec/satp/PMP bring-up,
  preemptive round-robin, `Yield` + bring-up console flag only.
  *Theorem:* user isolation. *Demo:* two U-mode threads print via SBI.
  - BUILT 2026-09-09: `kernel/` (S-mode under OpenSBI, `-bios default`).
    `V2_B.thy`: modes M/S/U, `u_exec/timer_tick/s_ret`, preservation
    (`no_M`, `kw` stable), `console_correct`, `bad_traps`, concrete mutants,
    `eval` trace lemma. Implementation: Sv39 with U-bit split (2MB
    megapages for user text/data, 4K pages for kernel RX/RW split),
    stvec traps, SBI timer preemption (100ms), lowest-Runnable scheduler
    (mirrors `V2_A.sched_step`), UABI yield/putc/park, SBI-forward console,
    fault containment (B executes illegal insn, parked, A unaffected).
    Demo transcript: `A0..4`, `[sched] parked 0`, `B`, `!`,
    `[fault] tcb=1 cause=2`, `no runnable left; parking cpu`.
    REFINEMENTS vs this doc: (a) memory isolation is via U-bit, not PMP
    (base PMP cannot distinguish S from U; PMP stays firmware-owned,
    lockdown is later work); (b) scheduler is lowest-Runnable, not
    round-robin-from-cur (fairness is Stage-1-liveness vs Stage-0-safety
    split; the implementation matches the proven spec exactly);
    (c) a `V2_PARK` blocking primitive arrived early (needed so B runs;
    specified as `UPark` in `V2_B` with preservation lemmas).
    PAID DEBUGGING LESSONS: arm SBI timer before enabling SIE (stale
    firmware pending bit + NULL ctx = fault loop); trap entry needs a
    valid ctx before ANY trap can land; never validate serial output
    through `strings` (minlen 4 drops short lines -- use raw bytes).
- **Stage 2 — IPC.** Endpoints/notifications, user-copy both directions,
  blocking semantics. *Theorem:* IPC integrity. *Demo:* ping-pong between
  two U-mode processes in separate VSpaces.
  - BUILT 2026-09-14: `kernel/isabelle/V2_C.thy` (session `V2`, `isabelle build`
    clean, 0 axioms, 0 `sorry`): `c_send`/`c_recv` on one static endpoint
    (bounded words, FIFO, blocking rendezvous), `c_notify`/`c_wait`
    (OR-accumulate signal sets), `c_integrity` (deliveries ⊆ sends —
    no forge), kernel-stamped senders, explicit overflow flag (no silent
    cut), wait-kind-gated wake (notify never disturbs rendezvous);
    preservation (valid/bounded/no-M/kw/queue-bounds/integrity/senders/
    msg-bounds) across all four ops, executable ping-pong/trunc/notify/
    FIFO demos pinned by `eval`, mutants (forged audit entry, oversize
    msg, lying silent-truncation variant). Implementation: `kernel/`
    static EP0 (`ipc.h` queues + U-range validation, host-tested by
    `tests/test_v2ipc.c`: adversarial lengths, cross-region, unaligned,
    queue-full, truncation), SUM-windowed `u_copy_in`/`u_copy_out`
    (validate-then-copy; SEND needs R, RECV needs W), UABI
    yield/putc/park/send/recv/notify/wait. Demo transcript: `B00pn`
    (ping from stamped sender 0, no trunc), `A10pg`, `W1` (notify bits),
    clean park. Gated in `verify.sh [1d/1e]` + v2 smoke + CI `isabelle` job.
    REFINEMENTS vs this doc: (a) `Call`/`ReplyRecv` stay userspace-composed
    from SEND+RECV until Stage 3 reply caps exist (no syscall yet);
    (b) "separate VSpaces" is logical separation under one `satp`
    (separate stacks, RX text, all bytes via kernel copies, no shared
    writable memory) — per-process `satp` is Stage 3; (c) receiver capacity
    is range-checked, not capped at 4 words (the copy loop is still bounded
    by the stored message length; oversized spans fail closed).
- **Stage 3 — Capabilities + memory.** Retype/mint/revoke (MDB), per-process
  VSpace, ELF loader that maps PT_LOAD (no validate-only stubs).
  *Theorem:* authority confinement (`V2_D`, spec green 2026-09-14 — kernel
  side pending). *Demo:* mem_server in userspace owns
  all allocation; kernel holds no heap.
  - BUILT 2026-09-17 (initrd boot): `userspace/mem_server/v2_main.c`
    (V2-UABI freestanding ELF, `v2_user.ld` BASE = frame window
    0x80800000) packed first by `tools/mkinitrd.sh` (index 0 + TOC);
    the kernel SPAWNs index 0 into thread 2 at boot (`[spawn] mem_server
    ELF ok`, `MEM-SRV` banner, EP0 service loop). Loader fixes along the
    way: window-base vpn translation, allocator-rights specialization,
    PTE sync + X for execute segments (W^X kept); ELF_MAP/SPAWN/EXEC take
    initrd indexes; the initrd blob stays in the kernel image (no pool
    frames consumed).
  - BUILT 2026-09-18 (process ops): `V2_INV_ELF_MAP` (load initrd ELF into
    caller), `V2_INV_SPAWN` (fresh thread + VSpace + ELF, stale caps/
    mappings/IPC state cleared), `V2_INV_FORK` (COW copy: model keeps full
    rights on both sides as the authority, hardware PTEs lose W on both
    sides, first store faults and breaks the share for the faulting thread
    only; child inherits no root caps), `V2_INV_EXEC` (replace image,
    free frames, keep root caps). Reserved args (a2/a3) must be zero.
    Child VSpaces mirror `pagetable_init` wiring exactly and
    `vspace_root_ppn` always holds the full satp value. Gated by the QEMU
    smoke (`MEM-SRV`) + host caps/IPC tests.
- **Stage 4 — Time + console.** Partitions/EDF enforcement, console server
  (owns UART Frame+IRQ), `moonsh` ported as its first client, bring-up
  console flag deleted. *Theorem:* temporal isolation. *Demo:* this repo's
  moonsh session, but across isolated processes.
- **Stage 5 — Drivers + storage.** virtio_net + block in U-mode behind
  IOMMU windows, VFS, micro-reboot. SMP only if Stages 0–4 proofs replay
  cleanly — otherwise explicitly cut.
- **Qubes S1 — isolation core (qube labels + raw gate).**
  - BUILT 2026-09-19: `kernel/qube.h` (labels, `V2_RIGHT_QX=0x8UL`,
    `V2_INV_QCREATE=14`/`V2_INV_QDESTROY=15`, raw gate `qube_raw_ok`,
    ask/audit ops) wired in `kernel/kboot.c` (per-thread `qube_of[]`,
    raw gate on SEND/RECV fail-closed with `QUB: xread denied`,
    QCREATE/QDESTROY Invoke ops, RECV stamp
    `(a0=nw,a1=sender,a2=qube,a3=ovf)`). Host-tested by
    `tests/test_qlabels.c` + `tests/test_qube_policy.c` (gated in
    `verify.sh [1f]`); QEMU smoke asserts `QUB: qube0 qube1 up` and
    `QUB: xread denied`. Confinement proved in `Qubes_B.thy`
    (`raw_ok_same/cross`, `c_q_call_refines` with allow/deny/ask_suspend/
    ask_full pins, `c_q_destroy_refines`, preservation + mutants).
- **Qubes S2 — qrexec + AdminVM.**
  - BUILT 2026-09-19: `userspace/qrexec_server/v2_main.c` (typed RPC over
    EP0, boot policy work→vault `keys.sign` ask / `clipboard` deny,
    `QREXEC:`/`AUD:` transcript) + `userspace/adminvm/v2_main.c`
    (HELLO-register, T_ASK prompt, T_DECIDE verdict), both packed as
    initrd indexes 1–2 and SPAWNed at boot (`[spawn] qrexec/adminvm ELF
    ok`). QEMU smoke asserts `QREXEC: ask`, `QREXEC: allow`,
    `QREXEC: deny`, `AUD: 3 entries`; policy semantics pinned by
    `c_decide_eq` in `Qubes_B.thy`.
  - REFINEMENTS vs `QUBES_ISOLATION_PLAN.md`: (a) NTHREADS 4→6 (qrexec,
    adminvm, scratch threads); (b) RECV stamp widened to a2=qube/a3=ovf
    (UABI bump consumed verbatim by both ELFs); (c) qrexec lives in its
    own qube (open-question #2 decided: fault containment over fewer
    IPC hops); (d) H-ext stays `[TODO]` S1-deferred (open-question #1:
    VSpace+cap isolation shipped instead); (e) `v2_user.ld` gained
    `ALIGN(4096)` before `.rodata` (second LOAD of qrexec/adminvm ELFs
    was page-misaligned; loader rejects fail-closed); (f) the S2 Ask leg
    is display-only in the demo (auto-approve; no GETC in the UABI) and
    demo RPCs are arg-less (T_DECIDE forwards zeros); live
    T_CALL→ASK→DECIDE→DELIVER traffic is future work, listed in §10.
  - KNOWN DEFERRED (not built): audit-cap `V2_AUDIT_MAX=64` overflow is
    unmodeled (spec audit lists unbounded); qube-lifecycle alias
    follow-ups; demo-convention brittleness (minor).

## 10. Open questions (decided late, deliberately)

1. SBI dependency surface: OpenSBI pin vs. minimal in-house M-shim
   (verification cost vs. supply-chain trust).
2. AutoCorres availability for the CHERI-RISC-V C subset — fallback is
   manual refinement; Stage 0 must answer this before Stage 1 code.
3. Timer tick rate vs. WCET budget constant (measure in Stage 1, freeze
   in Stage 3).
4. Whether `Seal` survives as a syscall or becomes an `Invoke` op
   (spec churn only — decide in Stage 0, freeze after).
