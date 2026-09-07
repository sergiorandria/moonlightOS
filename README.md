# MoonlightOS

General-purpose dynamic microkernel for **RISC-V CHERI**, partially verified in Isabelle/HOL (11/14 theorems proved, 3 axiomatized as known gaps, no `sorry` left except explicitly listed). **Production grade** - trap/paging/CHERI hybrid & purecap, QEMU window tested.

**Goals:** 3.5k LOC TCB, HW CHERI caps, proven temporal isolation, real-time EDF, CompCert binary correctness.

## Quick Start (Production)

```bash
tools/verify.sh           # host tests (no CHERI HW needed) - now fails loud if isabelle/CHERI missing (see summary)
tools/build_qemu.sh       # stock QEMU fallback (no CHERI LLVM)
make -C kernel            # CHERI: needs riscv64-unknown-elf-clang -march=rv64imacxcheri + CompCert
make -C kernel isabelle   # Isabelle2025-2 + l4v, 7 theories (no quick_and_dirty, 11 proved, 3 axiomatized)
tools/run_qemu.sh kernel/build/moonlight.elf              # autodetects QEMU, nographic or gtk window
DISPLAY=:0 tools/run_qemu.sh kernel/build/moonlight.elf   # QEMU window (GTK)
tools/run_qemu.sh --gdb   # GDB :1234
```

## Structure
- `kernel/` - 6 syscalls, 3.5k LOC, `cap/cnode/tcb/vspace/endpoint/sched/iommu/irq/alloc/revoke/process`, `start.S`/`trap.S` Sv39, `linker.ld` stacks+pt_pool
- `kernel/isabelle/` - `RISCV_CHERI, CacheColoring, IOMMU_Verification, Moonlight_A/E, Sched_Verification, Refine`
- `userspace/` - `mem_server` (color-aware), `sched_server` (EDF admission), `vfs_server` (FD caps), `drivers/virtio_net` (IOMMU-isolated), `example/hello`, `lib/moonlight.h` purecap ABI
- `docs/` - `ARCHITECTURE.md`, `THREAT_MODEL.md`, `REPRODUCIBLE.md`, `USAGE.md`, `BUILD.md`, `SYSCALLS.md`, `CAPABILITIES.md`, `PRODUCTION.md` (DICE attestation planned, `boot/dice.c` not yet wired to boot - see `docs/REPRODUCIBLE.md`)

## Proven Properties (11 proved, 3 axiomatized - see `docs/PRODUCTION.md` Verification)
- `RISCV_CHERI` `cheri_mono_perms`/`cheri_mono_bounds` proved, `CacheColoring` `color_disjoint`/`no_cache_interference` proved (with `part<8` bound), `Sched_Verification` `edf_schedulable`/`wcet_bound`/`partition_isolation_time` proved, `IOMMU_Verification` `iommu_isolation`/`dma_confinement` proved (with `iommu_wellformed` hyp)
- `Moonlight_A` `nonleakage_time`/`availability`/`integrity` proved, `Moonlight_E` `ex_refines_abs` axiomatized, `Refine` `refinement`/`c_refinement` axiomatized (AutoCorres/CompCert not set up)
- Trap: `mtvec`/`mscratch` separate stacks, `mcause`+`mepc+4`, `sfence` - verified QEMU `riscv64`/`riscv64cheristd`
- Paging: Sv39 3-level PT walk, `PTE_A|PTE_D`, `alloc_frame` per-color 64 pages (was bump `.pt_pool`), `satp` switch

## Test
`tests/test_cap.c`, `test_sched_realtime.c`, `test_revoke_process.c`, `host_emul.c`, `fuzz_syscall.c`, `bench_ipc.c`, `test_invoke_ops.c`, `test_mem/sched/vfs_server.c`, `test_vspace.c`, `test_virtio_net.c`, `test_abi.c` - see `tools/verify.sh` (4 stages: host, Isabelle, CHERI/stock QEMU, 3s smoke; `test_vfs` now `FAIL` not `SKIP`)

## Docs

- [Usage](docs/USAGE.md) - capabilities, TCB, VSpace, IPC, scheduling, full example
- [Build](docs/BUILD.md) - host, CHERI, stock QEMU, QEMU, reproducible, troubleshooting
- [Syscalls](docs/SYSCALLS.md) - 6 syscalls + 12 invoke ops
- [Capabilities](docs/CAPABILITIES.md) - sealing, otype, attenuation, coloring
- [Production](docs/PRODUCTION.md) - checklist, known gaps
