# Moonlight v2 — Design: a verifiable RISC-V CHERI microkernel

Status: DESIGN + Stages 0–3 and S4a built (see §9 for per-stage BUILT notes).
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

- Stage 1: preemptive round-robin, timer-driven, per-hart, bounded picker.
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
    `tcb_create/suspend/resume` + `sched_step` (round-robin from `cur`, with
    a concrete three-thread rotation trace). Invariants
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
    stvec traps, SBI timer preemption (100ms), round-robin scheduler
    (mirrors `V2_A.sched_step`), UABI yield/putc/park, SBI-forward console,
    fault containment (B executes illegal insn, parked, A unaffected).
    Demo transcript: `A0..4`, `[sched] parked 0`, `B`, `!`,
    `[fault] tcb=1 cause=2`, `no runnable left; parking cpu`.
    REFINEMENTS vs this doc: (a) memory isolation is via U-bit, not PMP
    (base PMP cannot distinguish S from U; PMP stays firmware-owned,
    lockdown is later work); (b) scheduler rotates round-robin from the
    current TID, matching the executable `V2_A.sched_step` model;
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
    static endpoint (`ipc.h` queues + U-range validation, host-tested by
    `tests/test_v2ipc.c`: adversarial lengths, cross-region, unaligned,
    queue-full, truncation) — EP0 at the time, replayed per-thread
    addressed since deferred-A (separation pinned by the unconditional
    `ep_separation_send` / `ep_separation_recv` + `no_cross_deliver`
    in `V2_C.thy`), SUM-windowed `u_copy_in`/`u_copy_out`
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
    ELF ok`, `MEM-SRV` banner, endpoint service loop — addressed
    per-thread since deferred-A). Loader fixes along the
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
    addressed endpoints — EP0 at the time, per-thread since deferred-A;
    boot policy work→vault `keys.sign` ask / `clipboard` deny,
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
- **Qubes S3 — net/firewall split.**
  - BUILT 2026-09-20 (Phase 1 loopback policy + Phase 2 NIC bring-up):
    `userspace/firewall/fw.h` (first-match-wins, default-deny, IPv4/
    TCP-UDP/ports guards, reload validator) + `userspace/firewall/v2_main.c`
    (single-flight pipeline: MAP scratch vpn 8 → `fw_decide` → ALLOW grants
    R + `SEND T_FWD[6,NET_IN_SLOT,len,h]`, ASK/DENY unmap + `FW: deny`;
    `T_DONE` closes the audit trail) + `userspace/net/v2_main.c` (T_FWD
    grant chain: sender_qube==4 check, slot/len bounds, MAP, hash recheck,
    silent drop; Phase-2 virtio-net: scan 8 transports, negotiate, 2 DMA
    frames, link check, one gratuitous ARP, IRQ wait) built as
    `userspace/build/firewall.elf` + `userspace/build/net.elf`, packed as
    initrd indexes 3–4 (`tools/mkinitrd.sh` order 0–4: mem_server, qrexec,
    adminvm, firewall, net) and SPAWNed at boot (`[spawn] firewall/net ELF
    ok`, threads 5–6, qubes 4–5). Host-tested by `tests/test_qargs.c`
    (`v2_qask_t` arg0/arg1 carry) + `tests/test_netfw.c` (ruleset matrix,
    oversize/zero-len, hash-mismatch, grant-without-announcement, spoof,
    pending-full, reload atomicity), gated in `verify.sh [1f]`. Smoke
    markers `NETQ: labels ok`, `FW: allow` / `FW: deny` / `FW: up`,
    `NET: up`, `LEAK: denied`, `SPOOF: ignored`, `AUD:`,
    `NETMMIO: tid=6 only`, `NET: link up` / `NET: tx ok` / `NET: irq ok`,
    all gated in `verify.sh [4/4]`. Proved in
    `kernel/isabelle/Qubes_C.thy` (69 lemmas: `packet_integrity`,
    `deliver_allow_pins`, `net_trust_deliver` / `net_stamp_deliver`,
    `fw_default_deny_nomatch` / `fw_malformed_deny` / `fw_empty_deny`,
    `mmio_tid6_only` / `mmio_scan_covers` / `mmio_reach_exact`,
    `irq_of_index_valid` / `irq_scan_ex`, `c_decide_args_eq` /
    `args_verbatim`, `c_frame_implies_spec` / `c_packet_bounds`, mutants
    per invariant, 0 sorry, 0 axioms). Hash note: the theory reasons over
    `pkt_hash`, the byte-sum stand-in for `qube_fnv1a` (executable on
    unary nats; delivery is gated on hash equality, never on collision
    resistance, which is not modeled) — NOT the C FNV-1a itself.
  - REFINEMENTS vs `QUBES_ISOLATION_PLAN.md` / the S3 spec: (a) NTHREADS
    6→8, exactly at the `V2_CAP_THREADS` cap bound (any further growth
    forces a cap bump + WCET re-analysis + proof replay); (b)
    single-flight firewall pipeline (one RECV per loop iteration, scratch
    always UNMAPped, no cross-iteration state); (c) Ask stays display-only
    (inherited S2 discipline: auto-approve, no GETC in the UABI); (d)
    deterministic link/tx/irq smoke — one gratuitous ARP, no external
    fetch asserted, RX-from-wire stays manual-only; (e) MMIO-leaf gate
    takes the boot-print form (`NETMMIO: tid=6 only`, fail-closed
    `[demo] FAIL` on leak); (f) `v2_user.ld` untouched (no new
    LOAD-alignment issue); (g) net MMIO reach is 8 pages, tid-6-only (NOT
    the spec's single-page sketch: all 8 transports mapped for tid 6 so
    the scan never assumes transport 0); (h) IRQ source scanned 1..8
    (`net_virtio_irq = 1+ti` kernel scan, `net_find` `j < 8`; NOT
    hardcoded IRQ 1); (i) `force-legacy=off` is `-global`: it flips the
    blk transport to modern mode too — the block driver already
    probes/handles both versions (`vmm_probe` legacy flag), so no blk
    change was needed.
  - S2-(c)-CLOSED: `v2_qask_t` now carries `arg0`/`arg1` (frame+len);
    `T_DECIDE` re-attaches them and the hash is re-checked before
    forwarding (`c_decide_args_eq`, `args_verbatim` in `Qubes_C.thy`,
    `test_qargs` round-trip). Arg-less RPCs (`keys.sign`) forward zeros,
    unaffected.
  - KNOWN DEFERRED (not built): live end-to-end AppVM→firewall→net traffic
    over addressed EPs (the smoke drives the model demo + NIC self-test; `NET: fwd
    ok` is specified but ungated — no phantom assert); USB HCI + `usb`
    qube; RX-from-wire CI assertions; firewall-compromise containment
    (S6).
- **FDE — encrypted storage ("everything is an encrypted file").**
  - BUILT 2026-09-24: `userspace/crypt/sha256.h` + `aead.h`
    (ChaCha20-Poly1305) + `kdf.h` (PBKDF2-HMAC-SHA256 + ChaCha-DRBG,
    test-grade, disclosed) + `crypt_util.h` (stack wipe, single-owner
    DRBG); `userspace/cryptblk/layout.h` (`CRYPT_MAGIC` 0x43525950544D4F4E,
    `SECTOR` 4096, `TAGS_PER_SECTOR` 256, `MAX_SLOTS` 8, `HEADER_SECTORS` 2)
    + `slot.h` (wrap/unwrap/wipe); `userspace/vault/v2_main.c`
    (KEK store, per-label unwrap, `T_KEY 8` one-time handoff by GRANT to
    slot 20 — never SEND words — `T_KEY_ACK 10`, tick-bounded ack-wait
    with park + `REVOKE` + wipe on expiry) + `userspace/cryptblk/v2_main.c`
    (virtio-blk driver on the S3 net-driver pattern, sector AEAD layer,
    minimal FS, `/dev/blk0` ciphertext + `/` plaintext views) built as
    `userspace/build/vault.elf` + `userspace/build/cryptblk.elf`, packed
    as initrd indexes 8–9 (`tools/mkinitrd.sh` order 0–9: mem_server,
    qrexec, adminvm, firewall, net, moonsh, ls, cat, vault, cryptblk)
    and SPAWNed at boot (`[spawn] vault/cryptblk ELF ok`, threads 8–9,
    qubes 6–7). qrexec rows `VAULT_UNWRAP 7` / `VAULT_REWRAP 8` /
    `VOL_FORMAT 9` (`nrules` 4→7). Host-tested by `tests/test_aead.c`
    (RFC 8439 + RFC 6070 KATs, round-trip/tamper properties) +
    `tests/test_crypt.c` (header parse, tag-region math, slot
    wrap/unwrap/wipe, extents, dirents), gated in `verify.sh [1f]`.
    Smoke markers `VAULT: up`, `VAULTQ: labels ok`, `CRYPTQ: labels ok`,
    `CRYPT: up` / `locked` / `unlock ok` / `rw ok`,
    `CRYPT: wrong-key denied` / `leak denied` / `no volume`,
    `BLKMMIO: tid=9 only`, plus the idempotence pair
    `CRYPT: formatted|volume ok`, all gated in `verify.sh [4/4]`.
    Proved in `kernel/isabelle/Qubes_D.thy` (62 lemmas:
    `slot_release_only_to_label`, `ciphertext_view_independent`,
    `no_ambient_decrypt`, `c_slot_release_eq`, `q_slot_deliver` audit
    pins, preservation, 10-thread/8-qube bound lemmas, mutants per
    invariant, 0 sorry, 0 axioms). Crypto strength is
    KAT-correspondence, not an axiom: the theory reasons over opaque
    key nats + the `pkt_hash` stand-in (equality-gated delivery only);
    ChaCha20-Poly1305/PBKDF2 correctness is pinned by the host KATs.
  - REFINEMENTS vs the FDE spec/plan: (a) `T_KEY`-by-grant ratified
    (`T_KEY_ACK=10`, grant-dst slot 20 — tag 10 is free in message-tag
    space, `V2_INV_FORK=10` lives in the separate invoke-op namespace);
    (b) NTHREADS/`V2_CAP_THREADS` 8→10 with `V2_FRAMES_MAX` 16→32
    (cryptblk needs image ~5 + DMA 2 + demo 1 transient; pool still
    fits the frame window, `_Static_assert`ed) — any further growth
    forces a cap bump + WCET re-analysis + proof replay; qube_next
    ends at 8 == `V2_QUBES_MAX`; (c) format-if-absent idempotence (gate
    asserts `formatted|volume ok` since the disk persists across runs);
    (d) `no volume` leg runs as a RAM-shadow header parse (no live-disk
    mutation, no second boot); (e) TEST_KEYS vectors deleted by the RNG
    stage (vault-seeded KEK; release passphrase entry stays manual-only,
    see the RNG hardening entry below); (f) `FDE_MAGIC` pins use `simp`,
    not `eval` (giant-numeral codegen blowup: two evals ran 140s+ without
    finishing; simp closes the same goals in milliseconds).
  - KNOWN DEFERRED / honest limits (not built): stolen-disk gate is the
    KDF work factor only (PBKDF2 600k; no memory-hard KDF — Argon2
    later, `KDF:` version field reserved in the header); no
    rollback/replay protection (no monotonic counter without TPM);
    test-grade DRBG (hardware-RNG wiring is future work, disclosed in
    code + spec, never silent); filenames unencrypted (names visible
    in directory sectors); no re-encryption on revoke (revoked qubes
    lose future access; in-flight FDs keep working — LUKS-equivalent
    semantics, documented); no journaling (crash between data/tag
    writes surfaces as tag-mismatch `EIO` = detected, never silent);
    file sharing across qubes stays deny-by-default.
- **Live qrexec traffic (S2/S3 deferred-A).**
  - BUILT 2026-09-24: Phase 1 addressed endpoints + Phase 2 thread-A
    live ask+deny legs. Single entry `tools/verify.sh`: host PASS
    (incl. extended `test_v2ipc`), gates PASS, kernel PASS, Isabelle
    PASS, QEMU PASS 44/44 incl. the 3 new markers, zero FAIL, no new
    SKIP (trailer `PARTIAL` is the pre-existing CHERI-toolchain SKIP
    only).
  - Phase 1 (commits `942c2c5` addressed EP gate + isolation tests,
    `8f1e0a4` per-thread endpoint array + own-EP rule, `53367cc`
    U-mode parties onto own EPs + broker svc table, `72181e7` V2_C
    endpoint-indexed + separation proofs): one endpoint per thread —
    `V2_NEP 10` (`kernel/ipc.h`, `_Static_assert`ed against
    `V2_CAP_THREADS` in `kernel/kboot.c`), `static v2_ep_t
    eps[V2_NEP]` indexed by EP, RECV restricted to the caller's own EP
    (`ep != cur` → `V2_ERR_INVALID`, fail closed before any queue
    touch), SEND validated (`ep < V2_NEP`, `ep < NTHREADS`) + the
    existing raw gate with `d = dst EP`, QDESTROY sweeping all EPs.
    EP ids == boot tids (A0 B1 mem2 qrexec3 admin4 fw5 net6, scratch7
    unused, vault8 cryptblk9). Host-pinned by the extended
    `tests/test_v2ipc.c` (gate + cross-EP invisibility + per-EP waiter
    pairing + per-EP queue-full isolation, `verify.sh [1f]`,
    `test_v2ipc: ALL PASS`); smoke-pinned byte-identical
    (`B00pn`/`A10pg`/`W1` unchanged). Broker routing:
    `svc_of_qube[8] = {0,2,3,4,5,6,8,9}` +
    as-built `rpc_svc[10] = {0,6,6,5,0,4,0,6,6,7}` (keys.sign→vault 6,
    clipboard→vault 6 + DENY, net.send→net 5, filter.reload→fw 4,
    unwrap/rewrap→vault 6, format→cryptblk 7; rpc 4/6 INVALID with no
    row), all in `userspace/qrexec_server/v2_main.c`, with the S2-era
    collapsed-dst (`QREXEC_QUBE = 1` = mem's qube) retired and deleted.
    Proven in `kernel/isabelle/V2_C.thy` (replayed endpoint-indexed,
    0 sorry, 0 axioms): `ep_separation_send` / `ep_separation_recv`
    (ops on EP i leave every EP j≠i bit-identical) + `no_cross_deliver`
    (RECV returns only own-EP bytes), with snoop/foreign mutants +
    eval pins; all pre-existing integrity lemmas replayed with one
    extra index.
  - Phase 2 (commit `978d69e` thread-A live ask+deny legs + markers):
    grants — the thread-A T_CALL leg REUSEs the FDE tid-3 slot-9 line
    (`v2_grant` fails on an occupied dst, `kernel/caps.h`), and one
    grant is added, qube0→admin (tid 4 slot 9) (`kernel/kboot.c`,
    fail-closed `[demo] FAIL` on failure); handshake — admin
    HELLO→EP3, RECV EP4 for the broker's `[R_OK]` reply, then
    `NOTIFY(tid 0, bit 2)` and the WAIT loop (`userspace/adminvm/
    v2_main.c`, `ADMIN_LIVE_BIT 2`); legs — thread A WAITs post-`W1`
    for bit 2, then two SEND+RECV call/response pairs over EP3
    (`kernel/user.c`, immediates only, marker-free park on deviation:
    SEND must return `V2_OK`, replies `[1] = R_PENDING` after keys.sign
    and `[-1] = R_DENY` after clipboard — reply words, never the
    syscall return); vault rpc-switch (`userspace/vault/v2_main.c`:
    rpc 1 → `VAULT: live ok` with no state change and no handoff,
    rpc 7 → existing T_KEY handoff, else silent drop — honest because
    boot unlock uses rpc 7); admin put-back arm stays
    dormant-but-harmless (reachable only on EP4 misdelivery, which
    separation makes unstatable). One-line kernel fix the legs exposed:
    NOTIFY wake-delivery (`kernel/kboot.c`: `threads[t].regs[10] =
    threads[t].notify`, pending preserved — a woken WAIT now returns
    fresh bits per the UABI instead of the stale blocked-with value;
    level-triggered parties observe zero change). Gated markers in
    `verify.sh [4/4]`: `QREXEC: admin registered` (genuinely live —
    R_OK consumed + NOTIFY observed via the downstream chain) +
    `VAULT: live ok` + `AUD: deny rpc=2`.
  - CLOSED HOLES (latent, now unstatable by construction): (a) EP0
    misdelivery — every SEND paired with the oldest waiter regardless
    of destination (the S3/FDE `T_KEY`/`T_ASK` SENDs carried the same
    latent misdelivery, masked only because those handoffs never ran);
    (b) dead admin registration — HELLO raw-gate-denied, admin
    WAIT-blocked forever, the broker path never ran at all; (c)
    collapsed-dst misrouting — every deliver resolved to
    `svc_of_qube[1] = 2` = mem_server, so the vault marker was
    unreachable.
  - KNOWN DEFERRED / honest remainder: (B) audit-cap
    `V2_AUDIT_MAX=64` overflow modeling — BUILT 2026-09-25, see the
    gap-closure entry below (fail-closed allow, `max_audit` +
    `audit_full_blocks_allow`); (C) qube-lifecycle alias follow-ups —
    BUILT 2026-09-25, see below (`T_DEAD 3`, state-alone scans); (D)
    demo-convention brittleness — still open (minor; harness owner:
    `verify.sh`/`run_qemu.sh` hardening): marker-text coupling
    between ELFs and the smoke gate. Live AppVM→firewall→net
    traffic stays ungated (`NET: fwd ok` specified but no phantom
    assert — S3 entry above); RX-from-wire, USB HCI + `usb` qube, and
    §7 non-goals unchanged.
- **Audit-cap + lifecycle-alias gap closure (deferred-B/C/D).**
  - BUILT 2026-09-25 (B fail-closed allow): `kernel/qube.h` helpers
    `qube_audit_room` (nonzero iff `naudit < V2_AUDIT_MAX 64`) +
    `qube_audit_allow` (OVERFLOW `-2` with zero state change when
    full, else the allow record via `qube_audit(...,1)`); broker
    (`userspace/qrexec_server/v2_main.c`) allow-forward arm gated on
    the helper (full → deny-shape `AUD: deny rpc=` print + `R_DENY`
    reply, no `T_DELIVER` SEND) and approve-deliver arm room-checked
    before `qube_decide_idx` (full → dequeue-as-deny best-effort,
    deny-shape print, no SEND, no reply — the decider never waits);
    deny arms untouched. Host-pinned by the extended
    `tests/test_qube_policy.c` (fill-to-64, 65th OVERFLOW with entries
    intact, helper refuses at cap and appends below cap, gated in
    `verify.sh [1f]`); smoke-pinned by the in-kernel self-test leg
    (`kernel/kboot.c`, local struct, `/* bound: V2_AUDIT_MAX */`)
    printing `AUD: full ok` (gated in `verify.sh [4/4]`). Proved in
    `kernel/isabelle/Qubes_A.thy` (`max_audit = 64`, `audit_room`,
    `a_bounded`; `audit_full_blocks_allow` — full audit + Allow
    decision ⇒ `q_call` returns the state unchanged, so there is no
    actuation without a record; `deny_appends_or_drops` +
    `decide_always_dequeues` — dequeue unconditional, record iff
    room; `audit_preserved_capped` over all four ops; full-ring
    mutants + `replicate 64` simp evals) with C-mirrors in
    `kernel/isabelle/Qubes_B.thy` (`c_full_blocks_allow`, new
    `c_q_decide` + `c_q_decide_refines` + `c_decide_always_dequeues`).
    Destroy records the fitting prefix, not whole-batch-iff-room:
    `q_destroy`/`c_q_destroy` remove every matching pending entry
    while extending the audit by `take (max_audit - length audit)
    newrecs` (matches the C per-record `qube_audit` loop exactly —
    `destroy_audit_capped` in `Qubes_A.thy`, `c_destroy_filter` in
    `Qubes_B.thy`). Non-allow-arm `qube_audit` returns are
    intentionally unchecked (best-effort by design: denial is the safe
    direction and proceeds with or without a record; a full ring just
    drops the record — the same discipline as the pre-existing T_CALL
    deny arms).
  - BUILT 2026-09-25 (C T_DEAD disambiguation): `kernel/kboot.c`
    `#define T_DEAD 3` (distinct from `T_BLOCKED 2`; `T_RUNNABLE 0` /
    `T_PARKED 1` unchanged); every state site audited — scheduler
    skip, halt-no-runnable detection, IRQ-wake `T_BLOCKED` checks,
    park/wake sets, and `wait_kind`-keyed WAIT/NOTIFY paths all
    read-only or semantically unchanged; the 3 SPAWN/FORK/QCREATE
    reuse scans simplified to `state == T_DEAD` alone
    (`/* deferred-C: T_DEAD is distinct; state alone frees the slot */`
    — a rendezvous-blocked thread is `T_BLOCKED 2 ≠ 3` and can no
    longer match). Gated by the byte-identical transcript: zero
    `verify.sh` change, the existing suite (incl. `AUD: full ok`)
    passes unchanged.
  - D (9 deferred minors, addressed 2026-09-25): (1) `/* bound:
    V2_IPC_Q */` on the 4 loops (`tests/test_v2ipc.c` ×3 +
    `kernel/ipc.h:102`); (2) QDESTROY sweep re-indent, whitespace-only
    (`git diff -w` collapses to the 2 comment hunks); (3) stale EP0
    comments → addressed-EP wording (11 sites across `kernel/kboot.c`,
    `kernel/user.c`, 6 userspace servers); (4) S3 KNOWN DEFERRED "over
    EP0" → "over addressed EPs" (item stays open); (5)
    `ipc_demo_same_ep` differentiated (`[5]` vs ping's `[7,8]`) +
    `ipc_bad_snoop_differs` asserts `ok1` (`V2_C.thy`); (6) T_DECIDE
    invalid-dst arm gains the `qube_audit(...,0)` deny-record
    (`userspace/qrexec_server/v2_main.c` — dead by construction, dst
    validated 1..7 at enqueue, fail-closed regardless); (7)
    double-notify eval pins (`ipc_demo_notify_take_clears`,
    `ipc_demo_wait_reblocks` — UABI wake-delivery KAT for the
    `regs[10]=pending` fix); (8) empty-take bare-`continue` REJECTED —
    the path is reachable (zero-length SEND is legal per
    `v2_len_ok`, RECV can return 0 with a live stamped sender; bare
    `continue` would drop the reply and hang a rendezvous waiter), so
    the current queuing error replies STAND — recorded in the design
    spec §4 item 8, cited here, not relitigated; (9)
    `uctx_t.state` comment extended (`3 = Dead`). The remaining
    `ok1`-dropping warts (`ipc_bad_noguard_differs`,
    `ipc_demo_pong`) are fixed here: both now assert `ok1`
    (`V2_C.thy`, `isabelle build` clean).
  - REFINEMENTS vs the gaps spec: (a) destroy is take-prefix, not
    whole-batch-iff-room (fidelity to the C per-record loop — the
    only reading under which `a_bounded` preservation proves); (b)
    `audit_preserved_capped` closes `by metis` (16 per-op rules;
    `blast` refused the conjunction); (c) T_DECIDE invalid-dst audit
    attributes the pending entry's original src, not the decider.
  - CLOSED HOLES (both latent, now unstatable): (a) silent audit drop
    — allows proceeded unaudited past 64 entries (now fail-closed
    DENY with no record, history never silently extended); (b) alias
    fragility — `T_DEAD == T_BLOCKED` safe only via a triple
    conjunction at 3 scan sites (now a distinct value with
    state-alone scans).
  - KNOWN DEFERRED / honest remainder (not built): S4 GUI, Stage 4
    time/console, USB HCI + `usb` qube, RX-from-wire CI assertions,
    live AppVM→firewall→net traffic (`NET: fwd ok` specified but
    ungated — no phantom assert), firewall-compromise containment
    (S6), §7 non-goals unchanged; demo-convention brittleness (D,
    harness owner: `verify.sh`/`run_qemu.sh` hardening).

- **S4a — GUI bring-up (Qubes S4 partial, not Stage 4 time/console).**
  - BUILT 2026-09-25: layered display stack — `userspace/gui/rect.h`
    (`GUI_W 800`, `GUI_H 600`, `GUI_BPP 4`, `GUI_STRIDE 800*4`,
    `GUI_FB_MAX 800*600*4`, `rect_off`/`rect_fill_ok`) +
    `userspace/gui/pci.h` (`PCI_ECAM_BASE 0x30000000`,
    `pci_cfg_off`/`pci_bar_ok`, `BOCHS_VEN 0x1234`/`BOCHS_DEV 0x1111`
    fetched from QEMU source) + `userspace/gui/v2_main.c`
    (L1 display server: bus-0 ECAM scan, bochs bind, FILL service on
    EP10, `GUI_TID 10`/`GUI_QUBE 8`/`GUI_EP 10`, `FILL 6`,
    `R_OK 0`/`R_DENY -1`) + `userspace/gui/gui_start.S`
    (vault-start clone) built as `userspace/build/gui.elf`, packed as
    initrd index 10 (`tools/mkinitrd.sh` order 0–10) and SPAWNed at
    boot into tid 10 / qube 8 (`kernel/kboot.c`, `[spawn] gui ELF ok`)
    + thread-A 4 FILL legs (`kernel/user.c`: fullscreen black clear
    + 3 full-width 100px bars red y=100 / green y=250 / blue y=400,
    geometry 800×600×4, `xy=x<<16|y`/`wh=w<<16|h`, 32-bit XRGB in
    word 3 low 32 bits, each leg SEND EP10 expect 0 + RECV EP0 expect
    `[R_OK=0]`, marker-free park on deviation). Host-tested by
    `tests/test_gui.c` (`PASS: test_gui`, gated in `verify.sh [1f]`);
    smoke-pinned by `GUI: up` + `GUIMMIO: tid=10 only` +
    `GUI: fill ok` (gated in `verify.sh [4/4]`; boot also prints
    `GUI: bochs bound` + `GUIQ: labels ok`). Proved in
    `kernel/isabelle/V2_C.thy` (`max_eps = 11` replay: per-thread EPs
    incl. EP10 pinned by `ep_separation_send`/`ep_separation_recv` +
    `no_cross_deliver` (unchanged, still cited), gui reach by
    `ipc_gui_ep_fits`/`ipc_send_ep11_rejects`, PCI scan by
    `pci_cfg_exact`/`pci_scan_covers`/`pci_scan_reach_exact`/
    `pci_bus0_covers`/`pci_bus1_invisible`/`pci_bind_needs_scan`/
    `pci_bind_is_bochs`/`pci_bind_ex`/`pci_bar_gate`/
    `pci_demo_bar_ok` + scan/BAR/bus-1 mutants, 0 sorry, 0 axioms) +
    bound replay (`Qubes_B.thy` `c_max_qubes = 9`,
    `Qubes_D.thy` `FDE_C_MAX_THREADS = 11`); svc/rpc tables unchanged.
  - Layers (binding): L0 address mechanics (kernel maps leaves only,
    no display code) / L1 display server (gui ELF tid 10 qube 8: binds
    PCI, owns LFB leaf, serves FILL on EP10, replies R_OK/R_DENY) /
    L2 paint client (thread A qube 0: no hardware touch — pixels only
    via server, SENDs FILL to EP10, RECVs reply on EP0) / L3+ S4b/c
    (future ELFs via server RPCs, own bumps — not built). Invariants:
    (a) exactly one hardware path (LFB + ECAM windows ONLY in tid-10
    tables, boot-asserted `GUIMMIO: tid=10 only`; kernel holds no
    display code — no PCI structs, no pixel math — mechanics only);
    (b) all cross-layer traffic is addressed IPC with kernel-stamped
    senders (client→server FILL on EP10 via one qube0→gui QX grant,
    server→client reply to stamped snd on EP0); (c) least privilege
    per layer (client names pixels only through validated FILL rects;
    server touches no other qube's memory; S4b/c add RPCs, never
    mappings). Server-paints-nothing: every on-screen pixel arrives
    through a validated FILL (even the test pattern is client-driven;
    first-valid FILL prints `GUI: fill ok` once via `gui_announced`).
  - Bump set 11/11/9/40 (all-or-nothing): `V2_CAP_THREADS`/`NTHREADS`
    10→11, `V2_NEP`/`max_eps` 10→11 (EP10 must exist for the server's
    RECV; `_Static_assert` 11<=11 holds; `V2_MSG_MAX 4`/`V2_IPC_Q 16`/
    `V2_AUDIT_MAX 64` unchanged), `V2_QUBES_MAX` 8→9 (`qube_next`
    ends at 9), `V2_FRAMES_MAX` 32→40 (gui image ~2 pages measured;
    the LFB is MMIO-leaf range, never pool frames); next growth forces
    WCET re-analysis + proof replay. One QX grant qube0→gui (tid 10
    slot 9; covers server replies, A's FILLs ride tid-0's in-place QX
    root — S3 shape).
  - REFINEMENTS vs the S4a spec: (a) bochs-display via minimal bus-0
    PCI scan (QEMU offers bochs/ramfb/virtio-gpu; bochs chosen for the
    PCI-bar precedent matching the virtio scan; bus-0-only — QEMU
    places bochs on bus 0, full 256-bus scan is YAGNI until USB);
    (b) layer split L0/L1/L2 ratified (kernel maps, ELF scans+paints,
    thread A drives — no kernel display code by construction);
    (c) server-paints-nothing ratified (maximally layered);
    (d) `V2_NEP` bump mechanics: `kernel/ipc.h` 10→11 plus stale
    `V2_THREADS_MAX` 8→11 doc-only fix (unused, grep-verified);
    (e) U-leaf range sizing: LFB U-window is one l0 table (2 MB,
    512 pages — covers the 800×600×4 frame = 469 pages with headroom;
    fills beyond 2 MB fault fail-closed) + ECAM U-window 16 pages RW
    (BAR mask-probe writes + restore); S-side ECAM megapage stays
    S-only; `l1_t[10][6]`/`l1_t[10][7]` (`GUI_LFB_UVA 0x80C00000` /
    `GUI_ECAM_UVA 0x80E00000`, Task-2 VAs implemented verbatim);
    kernel BAR0 programming (assigns 0x40000000 + MEM/master) is
    guest PCI enumeration mechanics (QEMU leaves BARs unprogrammed,
    ELF `pci_bar_ok` rejects base 0 — accepted as mechanics, S4b may
    move it into the ELF); (f) `eval`-free proofs (`simp`/`arith`/
    `blast` only — FDE giant-numeral lesson; `pci_demo_bar_ok` simp
    on `mod` held in Isabelle2025-2 with arith fallback noted).
  - CLOSED HOLES: `userspace/drivers/vga.c` fiction stays frozen —
    untouched (shape reference for pixel math only, fixed 0x40000000
    framebuffer never mapped by the v2 kernel).
  - KNOWN DEFERRED / honest remainder (not built): S4b (surfaces,
    compositor, trusted chrome) / S4c remainder (focus, clipboard
    RPC — input/keyboard + single-qube console BUILT 2026-10-04, see
    the S4c entry below); `kbd.c` gap stays open (referenced by
    `run_qemu.sh`, file absent in-tree, owned by S4c); fallback display devices (ramfb,
    virtio-gpu — bochs-only this stage); multi-bus PCI scan (bus-0
     only); resolution assumed 800×600×32 from QEMU default, unchecked
     (explicit VBE programming deferred to S4b, no scaling); Stage 4
     time/console, USB HCI + `usb` qube,
    RX-from-wire, live AppVM→firewall→net traffic, §7 non-goals
    unchanged.
- **S4c — VirtIO keyboard/mouse input + single-qube console.**
  - BUILT 2026-10-04: gui ELF (tid 10, qube 8) binds virtio-input over
    tid-10-only U-leaves (`l1_t[10][9]` kbd / `l1_t[10][10]` mouse,
    boot-asserted `GUIMMIO: tid=10 only`; `KBD_IRQ_BIT 0x4` /
    `MOUSE_IRQ_BIT 0x8` → tid-10 notify, markers `INPUT: kbd found` /
    `INPUT: mouse found`); phase-split loop (phase 1 pristine S4b
    FILL/COMPOSE on EP10 tags 6/7/8/9 with no WAIT inside; phase 2
    WAIT-driven input, poll-only-when-notified, 100×37 console,
    `INPUT: kbd and mouse ready` + `INPUT: console live`); discovery
    takes the first dev-18 as mouse, second as keyboard (QEMU
    last-first attach, measured); queue PAs via `V2_INV_FRAME_PA` +
    `fence iorw,iorw`. Host KATs `tests/test_input.c`
    (`PASS: test_input`, gated `verify.sh [1f]`); smoke-pinned by the
    three `INPUT:` greps (`verify.sh [4/4]`, fail-closed) + device
    attach on the QEMU cmdline (`verify.sh`, conditional in
    `run_qemu.sh`); proved by the `ipc_s4c_*` / `input_*` pins in
    `V2_C.thy` (0 sorry, 0 axioms; `max_eps = 11` unchanged). No bump:
    `gui.elf` stays 9 mapped pages (max vpn 8, slot-9 QX grant; font
    trimmed to 128 glyphs with a `ch & 0x7F` render mask).
  - SCOPE-OUT (model gap, deliberate): the pins cover notify/wait
    integrity + transport ownership; the kboot post-halt wake path
    (`halt_ctx`, SIE re-enable, wake-delivery, schedule-from-handler)
    is canary/VNC-verified only — no HOL counterpart (see the
    retro-spec §5).
  - KNOWN ISSUE (PARKED, top remainder): burst-typing race — ~1 in 3
    burst runs take a store fault (`cause=0xf`, trap-entry epc) and
    park the GUI; paced typing green (~1500 IRQs); suspect unproven
    (re-trap nesting vs `sscratch`/SUM); GDB follow-up proposed
    (retro-spec §5). Further remainder: per-qube focus + keystroke
    routing, trusted input indicator, clipboard RPC, ANSI, F1 toggle,
    mouse-button actions, CP437 upper half, `config.subsel`
    discovery.
- **RNG hardening — vault-owned virtio-rng + demo hardening.**
  - BUILT 2026-10-01: vault ELF binds the virtio-rng device over its
    tid-8-only U-leaf (`RNGMMIO: tid=8 only`), mixes 32B hardware
    samples with rdtime + service-gap delta (`rng_mix_ok`, host-KATed
    in `tests/test_rng.c`), serves `RANDOM_REQ` to cryptblk qube7-only,
    and cryptblk derives its KEK from that seed (TEST_KEYS vectors
    deleted; shell/VFS demo pools replaced by invoked frames).
    Smoke-pinned by `RNG: up` + `RNGMMIO: tid=8 only` (`verify.sh
    [4/4]`, which now attaches `-device virtio-rng-device` like
    `run_qemu.sh`); proved by `rng_mmio_covers`/`rng_tid8_only`/
    `rng_mutant_leak_rejected` in `V2_C.thy` (0 sorry, 0 axioms). No
    new thread, no cap bump.
  - HONESTY (dev-grade, not production secrecy): the KEK derives from
    public wire bytes + stored header salt via PBKDF2 at smoke iters,
    so secrecy rests on future AdminVM passphrase entry (deferred);
    the DRBG stays test-grade (audit deferred). Rotation break by
    design: TEST_KEYS-era disk images no longer unlock — CI and
    developers must start fresh (`rm kernel/build/moonlight-disk.img`).

## 10. Open questions (decided late, deliberately)

1. SBI dependency surface: OpenSBI pin vs. minimal in-house M-shim
   (verification cost vs. supply-chain trust).
2. AutoCorres availability for the CHERI-RISC-V C subset — fallback is
   manual refinement; Stage 0 must answer this before Stage 1 code.
3. Timer tick rate vs. WCET budget constant (measure in Stage 1, freeze
   in Stage 3).
4. Whether `Seal` survives as a syscall or becomes an `Invoke` op
   (spec churn only — decide in Stage 0, freeze after).
5. Audit-cap modeling + qube-lifecycle aliases BUILT 2026-09-25
   (gap-closure entry in §9: fail-closed allow + `T_DEAD 3`);
   live T_CALL→ASK→DECIDE→DELIVER traffic BUILT 2026-09-24
   (deferred-A entry in §9).
