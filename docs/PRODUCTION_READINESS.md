# MoonlightOS — Production-Readiness Review & Requirements

**Date:** 2026-10-16
**Branch:** dev
**Scope:** `kernel/` (~25k LOC), `userspace/` (~63k LOC), `tests/` (~12.6k LOC), `tools/`, `docs/`.
The vendored `qemu/` tree is out of scope.
**Method:** five independent subsystem reviews (kernel core; kernel devices; userspace
services; net + libc; verification/build/docs). The highest-severity claims below were
independently reproduced against the source by the author; citations are `file:line`.

This document is the **spec** for the remediation plan in
`docs/superpowers/plans/2026-10-16-production-hardening.md`. Requirement IDs (`R#.#`)
are referenced by that plan.

---

## Verdict

Not all of the codebase is low quality — substantial, non-trivial components are genuinely
good. But the **system** is not production-ready, and the failures are systematic, not
random. The recurring signature is **claims outrunning enforcement**: comments and docs
assert safety properties the code never implements, real modules sit unbuilt behind stubs,
and the verification harness cannot fail.

Order-of-magnitude assessment: **Early prototype with production-grade documentation habits.**

## Severity legend

- **Critical** — security or memory-safety failure reachable by untrusted input, or a
  verification gate that reports success when the system is broken.
- **High** — breaks a core guarantee (isolation, liveness, correctness) or ships a facade.
- **Medium** — robustness/debt that will produce production incidents.
- **Low** — maintainability.

## What is genuinely solid (do not discard)

- Crypto primitives: ChaCha20-Poly1305 (`userspace/crypt/aead.h`), Argon2id
  (`userspace/crypt/kdf_production.h`), DRBG. Host tests (`test_aead`, `test_crypt`,
  `test_argon2id`) pass.
- GUI + virtio-input driver (`userspace/gui/`) — spec-faithful ring setup.
- Console ANSI renderer (`userspace/console/console.c`) and TTY line discipline
  (`userspace/tty/tty.c`) — real implementations, needing only hardening.
- VFS namespace engine (`userspace/vfs_server/server.c`) — careful, per-caller validation.
- Kernel mechanism: Sv39 paging, fail-closed syscall argument validation, a capability
  core, and non-vacuous Isabelle proofs (no `sorry`/axiomatization; mutant-killing theorems).

## Systemic patterns

- **P1 — Duplicated parallel copies, one dead.** `kernel/kernel.h` (self-labelled
  "ASPIRATIONAL", conflicting `uctx_t`) vs the live `kernel/kinternal.h`;
  `kernel/arch/riscv/riscv_hal.c` duplicates `vm.c`/`irq.c`/`console.c` and is in no
  Makefile; `userspace/sh/shell.c` (dead) vs the shipping `shell_core.h`.
- **P2 — Claims not enforced.** Comments/docs assert properties the code lacks
  (`vm.c:117-140` "Exclusivity asserted at boot"; `kernel/user.c:10-12` "share no writable
  memory"; `V2_C.thy:15` "matches `V2_IPC_Q`").
- **P3 — Facades of correctness.** Fabricated `/proc` (`shell_vfs.h:358-405`),
  `true`/`false`/`printf` mapped to help/echo (`shell_core.h:1809,1826`), auto-approving
  AdminVM, unconditional "Services … up".
- **P4 — Real work parked behind "not built."** `vfs_server`, `sched_server`,
  `qrexec_server`, `firewall`, `adminvm` are compiled on demand but never shipped; the
  shell's `ls/cat/write/rm/kill/nice` all print "TODO in this build".
- **P5 — A gate that cannot fail.** 33 of 35 host tests are wrapped `cmd || echo "FAIL"`,
  which returns 0 under `set -e`; broken builds reach `exit 0`.

---

## Findings

### A. Kernel core

| ID | Sev | Finding | Evidence |
|----|-----|---------|----------|
| K1 | **Critical** | Every thread maps the same writable 2 MB `.udata` page in a loop over all threads; service stacks live there, so any service can read/write another's stack (e.g. `gui`/`net` → `vault`). Contradicts `kernel/user.c:10-12`. | `kernel/vm.c:113-114` |
| K2 | **Critical** | Per-device MMIO isolation absent: net/blk/rng/kbd/mouse all map the *same* 8 virtio transports; a driver can seize another's device. | `kernel/vm.c:82-99,121-146` |
| K3 | **High** | No DMA confinement: `iommu_*` declared in `userspace/abi/iommu.h`, defined nowhere; cryptblk programs the device with raw physical addresses. | `cryptblk/v2_main.c:821-842` |
| K4 | **High** | `V2_INV_ELF_CHECK` dereferences an unvalidated user pointer in S-mode. | `kernel/syscall_proc.c:41` |
| K5 | **High** | `FORK` maps no child stack and sets `sepc = parent+8`, skipping an instruction; reachable from the shell. | `kernel/vm.c:379-401`, `kernel/syscall_proc.c:256-257` |
| K6 | **High** | Fault/park never reclaims frames/caps; slot reuse keys only on `T_DEAD`. ~10 parked threads exhaust the 128-frame pool → DoS. | `kernel/syscall.c:261`, `kernel/syscall_proc.c:98` |
| K7 | **High** | `SPAWN` slot reuse snapshots `caps.vm` only, then wipes `caps.caps` → cap-only frames leak. | `kernel/syscall_proc.c:122-134` |
| K8 | **High** | Deadlock detection inert: `ipc_deadlock_check()` is linked but never called; `halt_no_runnable` parks forever. One A↔B wait wedges the machine. | `kernel/ipc_deadlock.c:117`, `kernel/sched.c:96-97,220` |
| K9 | **Med** | 4 KB `trap_stack` with no guard page carries the whole syscall/spawn path. | `kernel/sched.c:49` |
| K10 | **Med** | `V2_INV_ELF_MAP` truncates the returned entry point to `int` (user VAs are ≥ `0x80000000`). | `kernel/syscall_proc.c:67` |
| K11 | **Med** | `kernel_monitor_print_summary` loops to 16 over a 10-entry name table (OOB read once subsys ≥ 10 used). | `kernel/kernel_monitor.c:217-222` |
| K12 | **Med** | `v2_real_write/read` have no `len` bound despite a comment asserting one. | `kernel/vm.c:275-293` |
| K13 | **Med** | IPC policy modules (`ipc_priority`, `ipc_flow_control`) are linked but inert; `ipc_priority` writes priority into user payload words. | `kernel/ipc_priority.c:104-118`, `ipc_flow_control.c:19-50` |
| K14 | **Med** | `kernel.h` is a stale parallel header (conflicting `uctx_t`, phantom API). | `kernel/kernel.h:7-12,57-67` |

### B. Kernel device/driver

| ID | Sev | Finding | Evidence |
|----|-----|---------|----------|
| D1 | **High** | Teardown/reboot leaks MMIO authority and IRQ ownership: QDESTROY clears only the frame window; there is no `irq_unbind`; a reused tid inherits the old device leaf + enabled PLIC line. | `kernel/syscall_qube.c:245-253` |
| D2 | **High** | Two/three competing PLIC owners (kernel `irq.c` and `userspace/drivers/plic.c`) on one claim/complete protocol. | `userspace/drivers/plic.c:20,164-223` |
| D3 | **High** | `kernel/arch/` is unbuilt, divergent dead code that cannot link with the live kernel (`NTHREADS 10` vs 11). | `kernel/arch/riscv/riscv_hal.c:69` |
| D4 | **Med** | `irq_bind` validates neither kind↔owner nor badges; failed binds are discarded. | `kernel/irq.c:101-104`, `kernel/device.c:82,149,155` |
| D5 | **Med** | Kernel programs PCI BARs and the Bochs VBE mode (device *policy* in the kernel). | `kernel/device.c:234-246` |
| D6 | **Med** | GUI maps the entire PCI ECAM (all functions) and a 2 MB LFB window. | `kernel/vm.c:103-106` |
| D7 | **Med** | cryptblk does not negotiate `VIRTIO_F_VERSION_1`. | `userspace/cryptblk/v2_main.c:799-805` |

### C. Userspace services

| ID | Sev | Finding | Evidence |
|----|-----|---------|----------|
| S1 | **Critical** | FDE root key is publicly derivable: cryptblk requests a 4-word seed but the vault replies 1 word; 3 seed words stay as the request constants (`0x9e4b,0,0`), so the KEK is a fixed function of the plaintext on-disk salt. | `cryptblk/v2_main.c:374-383`, `vault/v2_main.c:736` |
| S2 | **High** | Console ANSI parser increments `ansi_param_count` unbounded, then loops to it reading `ansi_params[8]` → OOB. | `console.c:389-397` |
| S3 | **High** | Console/TTY trust the IPC `len` field and copy `len` bytes from a 16/32-byte buffer → stack OOB read. | `console.c:242`, `tty.c:145` |
| S4 | **High** | Shipping shell maps `true`/`false`→`cmd_help` and `printf`→`cmd_echo`; fabricated `ps/mem/ipc/dmesg` and `/proc` (incl. wrong ISA string). | `shell_core.h:1809,1826`, `shell_vfs.h:374` |
| S5 | **High** | The gate tests the **dead** `shell.c`; the shipping engine `shell_core.h` has zero gate coverage. | `tools/verify.sh:14,55` |
| S6 | **Med** | `mem_server` forwards MAP/UNMAP with no ownership/caller validation. | `mem_server/v2_main.c:127-135` |
| S7 | **Med** | `vault key_release` can block forever holding the VMK frame + grant (blocking `u_recv` despite a "tick-bounded" claim). | `vault/v2_main.c:598-619` |
| S8 | **Med** | `ipc_helpers` reply matching ignores `msg_id` and permanently discards non-matching traffic; `ipc_check_flow_control` is `return 0`. | `lib/ipc_helpers.c:63-64,95-101,197-200` |
| S9 | **Med** | `vfs_server`/`sched_server`/`qrexec`/`firewall`/`adminvm` are not built/spawned; AdminVM auto-approves. | `userspace/Makefile:56`, `mkinitrd.sh:34-46` |

### D. Network stack + libc

| ID | Sev | Finding | Evidence |
|----|-----|---------|----------|
| N1 | **Critical** | `malloc` integer overflow for huge `n` → undersized block → heap overflow; allocator is not thread-safe. | `userspace/libc/src/stdlib.c:566` |
| N2 | **High** | TCP checksum computed over Ethernet wire length in the socket seam but IP total length in the demux path → padded frames (bare ACKs) silently dropped. | `net/tcp.h:325`/`net/sock.c:278` vs `net/stack.c:259` |
| N3 | **High** | `errno` is a single global while the libc provides real threads. | `userspace/libc/src/errno.c:5` |
| N4 | **High** | Detached threads never reaped (permanent `EAGAIN` after 16); stacks never `munmap`'d. | `userspace/libc/src/pthread.c:308-311` |
| N5 | **High** | `vsnprintf` ignores integer precision and `#`. | `userspace/libc/src/stdio.c:34-38` |
| N6 | **Med** | UDP builder writes the TTL macro into the IP flags byte. | `net/stack.c:353,355` |
| N7 | **Med** | `rename` is copy-then-truncate (not atomic; partial destination on failure). | `userspace/libc/src/stdio.c:1488-1506` |
| N8 | **Med** | `realloc` mishandles aligned allocations (heap corruption). | `userspace/libc/src/stdlib.c:629` |
| N9 | **Med** | `strtok`/`strsignal`/`realpath` use globals under threads; ARP seeds the gateway with our own MAC; UDP zero-checksum rejected. | `libc/src/string.c:197`, `net/arp_cache.c:122`, `net/stack.c:427` |

### E. Verification / build / docs

| ID | Sev | Finding | Evidence |
|----|-----|---------|----------|
| V1 | **Critical** | 33 of 35 host tests cannot fail the gate (`cmd && run \|\| echo "FAIL"` returns 0); kernel/Isabelle failures also reach `exit 0`. | `tools/verify.sh:12-57,241-260` |
| V2 | **Critical** | A failed kernel build leaves the stale `moonlight.elf`, which the QEMU stage then boots and passes. | `tools/verify.sh:59,136-143,153` |
| V3 | **High** | The QEMU smoke proves strings appeared: `grep -q "NP"` is unanchored; "Services … up" prints unconditionally; "[spawn] X ELF ok" proves load, not run. | `tools/verify.sh:211`, `kernel/kboot.c:133` |
| V4 | **High** | The "production gate" is a line-count check that omits 6 linked kernel TUs. | `tools/verify.sh:60-67` |
| V5 | **High** | Isabelle model constants drifted from C (threads 8 vs 11; queue 16 vs 32; frames 8 vs 128; slots 16 vs 64) and there is no refinement link. | `V2_A.thy:15-16`, `V2_C.thy:15`, `V2_D.thy:19-23` vs `kernel/caps.h:57-64`, `ipc.h:21` |
| V6 | **High** | `initrd_data.c` is tracked but regenerated by no Makefile → stale-payload risk. | `tools/mkinitrd.sh` unreferenced |
| V7 | **High** | Docs drift: `ARCHITECTURE.md` lists ~60 markers that no longer exist; `BUILD.md` initrd order is wrong; `TCP_DESIGN.md`/`PHASE2_PRODUCTION_PLAN.md` cite non-existent `net/tcp.c`. | `docs/ARCHITECTURE.md:411-431`, `docs/BUILD.md:39`, `docs/TCP_DESIGN.md:31` |
| V8 | **Med** | 11 real tests are ungated (`test_tcp`, `test_elf`, `test_frames`, `test_qube_destroy_auth`, …); 4 ungated tests include the deleted `kernel/include/` (unbuildable rot); a committed x86-64 binary `test_v2ipc` sits in the tree. | — |

---

## Requirements

### Phase 0 — Trustworthy gate (keystone)
- **R0.1** `verify.sh` MUST exit non-zero if any host test fails.
- **R0.2** `verify.sh` MUST exit non-zero if the kernel build or Isabelle build fails.
- **R0.3** `verify.sh` MUST gate the shipping shell engine (`shell_core.h`) and the 11 ungated real tests; it MUST NOT rely on the dead `shell.c`.
- **R0.4** QEMU markers MUST be exact-line anchored, and "Services … up" MUST print only if every spawn succeeded.
- **R0.5** The gate MUST prove at least one live IPC round-trip per spawned service.
- **R0.6** `initrd_data.c` MUST be regenerated from the current ELFs before the kernel build, and the gate MUST fail if it is stale.
- **R0.7** The gate MUST delete kernel build artifacts before building (no stale-ELF pass).

### Phase 1 — Isolation & memory safety
- **R1.1** Each thread MUST have a private stack; no shared writable region between threads. (K1)
- **R1.2** Each device owner MUST map only its own device's registers. (K2)
- **R1.3** Thread teardown MUST clear device leaves, unbind IRQ routes, and disable the PLIC line. (D1)
- **R1.4** No driver may program a device with an arbitrary physical address; implement a validated/bounce window, or document the limitation and delete the IOMMU claims. (K3)
- **R1.5** Fatal faults MUST reclaim the thread's frames and caps. (K6)
- **R1.6** `SPAWN` slot reuse MUST reclaim cap-referenced frames. (K7)
- **R1.7** `FORK` MUST map the child stack and resume at the correct `sepc`. (K5)
- **R1.8** `V2_INV_ELF_CHECK` MUST validate the user pointer before dereference. (K4)

### Phase 2 — Security model
- **R2.1** A QX capability MUST be mintable so cross-qube IPC is possible.
- **R2.2** The qube gate MUST apply to queued sends, not only handoff.
- **R2.3** A denied message MUST be dropped so the endpoint recovers.
- **R2.4** `sys_notify` MUST enforce qube policy.
- **R2.5** Circular waits MUST be detected and broken from `sched_tick`. (K8)
- **R2.6** IPC backpressure bits MUST not collide with the user notify namespace.

### Phase 3 — Correctness bugs
- **R3.1** The FDE KEK MUST derive from fresh CSPRNG bytes; cryptblk MUST fail closed unless the full seed arrives. (S1)
- **R3.2** `malloc` MUST reject overflowing sizes; the allocator MUST be thread-safe; `realloc` MUST handle aligned blocks. (N1, N8)
- **R3.3** `errno` MUST be thread-local. (N3)
- **R3.4** Detached threads MUST be reaped; stacks unmapped. (N4)
- **R3.5** `vsnprintf` MUST honour integer precision and `#`. (N5)
- **R3.6** The socket-seam TCP checksum MUST use IP total length. (N2)
- **R3.7** The UDP builder MUST place TTL in the TTL byte. (N6)
- **R3.8** IPC message lengths MUST be bounded on every receive side (console, tty). (S2, S3)

### Phase 4 — Honesty & integration
- **R4.1** `true`/`false`/`printf` MUST have correct semantics. (S4)
- **R4.2** `ps/mem/ipc/dmesg`/`/proc` MUST reflect real state or report "unavailable"; the ISA string MUST be correct. (S4)
- **R4.3** Dead duplicates removed: `kernel/kernel.h`, `kernel/arch/`, `kernel/core/`, `userspace/sh/shell.c`, the 4 v1-rot tests, committed binaries. (P1)
- **R4.4** Unshipped services MUST be either wired into the OS or moved to a clearly-labelled staging area; AdminVM MUST NOT auto-approve. (S9)
- **R4.5** Docs MUST be regenerated from `verify.sh`; stale status/"COMPLETE" docs removed; non-existent paths fixed. (V7)

### Phase 5 — Process hardening
- **R5.1** Isabelle model constants MUST be bridged to the C headers in CI, or the "refined C implementation" claim retracted. (V5)
- **R5.2** CI MUST run sanitizers/static analysis on host tests and the kernel.
- **R5.3** A `CONTRIBUTING`-style quality bar MUST codify the global constraints.

---

## How much the current verification proves

Bluntly: very little, and less than the docs claim. Of 35 wired host tests, 2 can abort
the script. The kernel build is best-effort (`|| echo`, `| tail`, `exit 0`). The QEMU smoke
proves a booted binary printed some strings, one of which (`NP`) is a substring match and
one of which ("Services … up") is unconditional; the only functional liveness evidence is
a single `send tcb=1 -> 4` line. The Isabelle session proves real theorems about a model
whose constants differ from the kernel by 2–16×, with no refinement link. The "production
gate" counts lines. Net: a smoke + format checker with advisory tests.
