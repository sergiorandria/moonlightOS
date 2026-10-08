# MoonlightOS

S-mode microkernel for RISC-V, built spec-first and partially verified in
Isabelle/HOL. The v2 kernel runs in **S-mode under OpenSBI** and puts
userspace in **U-mode**; M-mode hosts only OpenSBI. The design lives in
`docs/V2_DESIGN.md`; every board-verified claim is labelled BUILT there.

The v1 M-mode kernel (`kernel/src` + `kernel/include`, and the parallel
`v2/` tree) was removed on 2026-09-14: this repo is now the single v2
codebase. The v1 userspace feature set survived via the frozen ABI
headers in `userspace/abi/` and the freestanding C library.

## Quick Start

```bash
tools/verify.sh          # host tests + kernel build + Isabelle + QEMU smoke
make -C kernel           # v2 kernel -> kernel/build/moonlight.elf (S-mode)
make -C userspace        # freestanding rv64 userspace ELFs + libc
tools/run_qemu.sh        # boots under OpenSBI (-bios default)
tools/run_qemu.sh --nographic
tools/run_qemu.sh --gdb  # GDB on :1234
```

## Structure (single codebase)

- `kernel/` - v2 S-mode kernel: `kboot.c` (Sv39 U-bit tables, stvec traps,
  SBI console + timer, round-robin scheduler, blocking rendezvous IPC
  `SEND/RECV` + `NOTIFY/WAIT`, fault containment), `user.c` (U-mode ping-pong
  demo), `ipc.h`/`caps.h` (Stage-2/3 host-tested protocols), `start.S`,
  `trap.S`, `linker.ld`. Build via `make -C kernel` (stock clang, rv64imac).
- `kernel/isabelle/` - session `V2`: `V2_A` (threads/scheduler),
  `V2_B` (modes M/S/U, isolation, console, faults), `V2_C` (IPC integrity,
  notifications), `V2_D` (capability authority confinement, spec),
  `Qubes_A` (Qubes denial-of-service isolation). Built by
  `isabelle build -D kernel/isabelle -v`.
- `userspace/` - frozen v1 userspace features: `abi/` (standalone copy of the
  v1 ABI headers: types, cap, cheri, iommu, vspace, linux_abi), `lib/`
  (`moonlight.h` API), `libc/` (Linux-compatible freestanding rv64 C library)
  + `example/hello`, `example/linux_demo`, `sh/moonsh`, `mem_server`,
  `sched_server`, `vfs_server`, and the driver compartments (`uart`, `plic`,
  `timer`, `rtc`, `power`, `block`, `vga`, `virtio_net`) validated against the
  ABI headers. See `docs/BUILD.md` for the build gates.
- `tests/` - host-sim unit tests; `tools/verify.sh` is the single verification
  entry point (host unit tests, production gates, Isabelle, kernel build,
  QEMU smoke).
- `docs/` - `V2_DESIGN.md` (the live design + staged roadmap),
  `ARCHITECTURE.md`, `BUILD.md`. The v1-era docs (`CAPABILITIES.md`, `LINUX.md`,
  `PRODUCTION.md`, `REPRODUCIBLE.md`, `SECURITY.md`, `SYSCALLS.md`,
  `THREAT_MODEL.md`, `USAGE.md`) describe the removed v1 M-mode kernel and are
  kept as historical reference; their `kernel/src`/`kernel/include` paths no
  longer exist.

## What boots

`tools/run_qemu.sh` boots OpenSBI → the v2 kernel → two U-mode threads:
A SENDs "pn", B RECVs and prints it, B NOTIFYs A + SENDs "pg", A RECVs,
prints, WAITs (takes the notify), both park; the scheduler then parks the
hart. Transcript markers the smoke asserts: `satp Sv39 on`, `entering U-mode`,
`B00pn`, `A10pg`, `W1`, `no runnable left; parking cpu`.

## Verification (one door)

`tools/verify.sh` runs 4 stages: host unit tests (ABI regression, sched/vfs/
shell, driver host-sims, freestanding libc, v2 IPC/caps), production gates
(linker layout, `user.c` rodata ban), the Isabelle `V2` session with an
anti-vacuity gate, and the QEMU text smoke. CI (`verify.yml`, `cheri.yml`)
calls it plus a dedicated Isabelle job.

## Docs

- [v2 Design](docs/V2_DESIGN.md) - why v2, stage roadmap, BUILT entries
- [Architecture](docs/ARCHITECTURE.md) - current reality: kernel, proofs, userspace
- [Build](docs/BUILD.md) - host, kernel, userspace, verification, QEMU, troubleshooting