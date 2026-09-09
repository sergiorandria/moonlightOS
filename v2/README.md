# Moonlight v2 — S-mode microkernel (Stage 1)

Fresh design, see [`docs/V2_DESIGN.md`](../docs/V2_DESIGN.md). Spec-first:
`isabelle/` holds the machine-checked abstract spec, `kernel/` the S-mode
implementation. The two are kept in lockstep (scheduler policy,
trap-and-schedule discipline, park semantics all mirror named spec
definitions).

## Layout

- `isabelle/ROOT` — session `V2` (parent `HOL`)
  - `V2_A.thy` — Stage 0: TCB list + `cur`, create/suspend/resume,
    lowest-Runnable step; `valid_ids`/`bounded` preservation, mutants,
    `eval` demo lemmas
  - `V2_B.thy` — Stage 1: modes M/S/U, `u_exec` (yield/putc/park/bad-load),
    `timer_tick`, `s_ret`; M-never-arises, kernel-write stability,
    console trace correctness, mutants
- `kernel/` — S-mode kernel, runs under OpenSBI (`-bios default`)
  - `start.S` — S-mode entry (hart0, gp/sp/BSS/stvec)
  - `kboot.c` — SBI console, Sv39 tables, timer, scheduler, trap dispatch
  - `trap.S` — stvec entry, context save/restore, `u_enter` (sret)
  - `user.c` — two U-mode threads (`.utext`/`.udata`/`.ustack`)
  - `linker.ld` — kernel @ `0x80200000`, user text @ `0x80400000`,
    user data @ `0x80600000`; wildcarded `text*`/`rodata*` (orphans
    inside the BSS-clear range once blinded v1 — gated in CI)
  - `Makefile` — `make -C v2/kernel` → `build/v2.elf`

## Build and run

```bash
make -C v2/kernel          # needs: clang, lld, llvm-readelf
isabelle build -D v2/isabelle   # needs: Isabelle2025-2
qemu-system-riscv64 -M virt -m 256M -bios default \
  -kernel v2/kernel/build/v2.elf -nographic
```

Expected transcript (also asserted by `tools/verify.sh` v2 smoke):

```
v2 stage1: S-mode entry (OpenSBI)
v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0
v2: entering U-mode thread A
A0 1 2 3 4
[sched] parked 0
B
!
[fault] tcb=1 cause=0000000000000002  epc=00000000804000ca
 parked; others continue
no runnable left; parking cpu
```

## Architecture (Stage 1)

- **Privilege:** M-mode is OpenSBI (external pin); kernel is S-mode;
  userspace is U-mode. No `mret`-to-user anywhere (v1's structural flaw).
- **Memory:** one `satp`, split by U-bit — kernel RX/RW (`U=0`, 4K pages),
  user text URX + data/stacks URW (`U=1`, 2MB megapages), MMIO kernel-only.
  `SUM=0`. Base PMP cannot distinguish S from U, so PMP stays
  firmware-owned; lockdown is later work.
- **Traps:** U-ecall (yield/putc/park), S-timer preemption (100ms, SBI),
  faults park the offender and continue the rest. S-mode ecalls (our own
  SBI use) return via M and never hit `stvec`.
- **Scheduler:** lowest-numbered Runnable (exactly `V2_A.sched_step`).
  Fairness is Stage-1 liveness work, deliberately out of scope.
- **Console:** userspace prints by trapping; the S handler forwards
  through real SBI (`M-mode`). No ambient UART mapping for U (`U=0`).

## Constraints (enforced, not advised)

1. `user.c` must emit **no `.rodata`** — literals would land in `U=0`
   pages and fault. Gate: `verify.sh [1e]` compiles `user.c` and fails
   the build on any `.rodata*` section. Write immediates + stack locals
   only (Stage 3 ELF loader lifts this with per-process `gp`/rodata).
2. No `PROGBITS` inside `[_bss, _bss_end)` — gate: `verify.sh [1e]`
   parses the linked ELF and fails on overlap (the v1 blinding bug).
3. Boot order: valid parked context + `cur_ctx` exist **before** `SIE`
   is enabled; SBI timer is armed **before** `STIE`/`SIE` (stale firmware
   pending bit + NULL ctx = fault loop — debugged once, gated by review).
4. `-fno-stack-protector` is explicit (no libc canary host); paging +
   U-bit are the mechanisms until the Stage-3 C library.

## Stage map

- Stage 0: spec skeleton — BUILT (`V2_A`)
- Stage 1: this kernel + privilege spec — BUILT (`V2_B` + `v2/kernel`)
- Stage 2: endpoints/notifications, bidirectional IPC, integrity theorem
- Stage 3: capabilities, per-process VSpace, ELF loader, allocator server
- Stage 4: partitions/EDF, console server, moonsh as a client
- Stage 5: drivers, storage, SMP decision
