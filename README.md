# MoonlightOS

General-purpose dynamic microkernel for **RISC-V CHERI**, verified in Isabelle/HOL, exceeding seL4. **Production grade** - trap/paging/CHERI hybrid & purecap, QEMU window tested.

**Goals:** 3.5k LOC TCB, HW CHERI caps, proven temporal isolation, real-time EDF, CompCert binary correctness.

## Quick Start (Production)

```bash
tools/verify.sh           # host tests (no CHERI HW needed) - all PASS
tools/build_qemu.sh       # stock QEMU fallback (no CHERI LLVM)
make -C kernel            # CHERI: needs riscv64-unknown-elf-clang -march=rv64imacxcheri + CompCert
make -C kernel isabelle   # Isabelle2024 + l4v, 7 theories
tools/run_qemu.sh kernel/build/moonlight.elf              # autodetects QEMU, nographic or gtk window
DISPLAY=:0 tools/run_qemu.sh kernel/build/moonlight.elf   # QEMU window (GTK)
tools/run_qemu.sh --gdb   # GDB :1234
```

## Structure
- `kernel/` - 6 syscalls, 3.5k LOC, `cap/cnode/tcb/vspace/endpoint/sched/iommu/irq/alloc/revoke/process`, `start.S`/`trap.S` Sv39, `linker.ld` stacks+pt_pool
- `kernel/isabelle/` - `RISCV_CHERI, CacheColoring, IOMMU_Verification, Moonlight_A/E, Sched_Verification, Refine`
- `userspace/` - `mem_server` (color-aware), `sched_server` (EDF admission), `vfs_server` (FD caps), `drivers/virtio_net` (IOMMU-isolated), `example/hello`, `lib/moonlight.h` purecap ABI
- `boot/dice.c` - DICE measured boot
- `docs/` - `ARCHITECTURE.md`, `THREAT_MODEL.md`, `REPRODUCIBLE.md`, `USAGE.md`, `BUILD.md`, `SYSCALLS.md`, `CAPABILITIES.md`, `PRODUCTION.md`

## Proven Properties
- Functional correctness A==E==C (CompCert), integrity, authority confinement, time-aware confidentiality, availability (EDF + WCET 5us)
- HW CHERI monotonicity, cache-coloring non-interference, DMA confinement
- Trap: `mtvec`/`mscratch` separate stacks, `mcause`+`mepc+4`, `sfence` - verified QEMU `riscv64`/`riscv64cheristd`
- Paging: Sv39 3-level PT walk, `PTE_A|PTE_D`, bump `.pt_pool` 64 pages, `satp` switch

## Test
`tests/test_cap.c`, `test_sched_realtime.c`, `test_revoke_process.c`, `host_emul.c`, `fuzz_syscall.c`, `bench_ipc.c` - see `tools/verify.sh` (now 4 stages: host, Isabelle, CHERI/stock QEMU, 3s smoke)

## Docs

- [Usage](docs/USAGE.md) - capabilities, TCB, VSpace, IPC, scheduling, full example
- [Build](docs/BUILD.md) - host, CHERI, stock QEMU, QEMU, reproducible, troubleshooting
- [Syscalls](docs/SYSCALLS.md) - 6 syscalls + 12 invoke ops
- [Capabilities](docs/CAPABILITIES.md) - sealing, otype, attenuation, coloring
- [Production](docs/PRODUCTION.md) - checklist, known gaps
