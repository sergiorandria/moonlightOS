# MoonlightOS

General-purpose dynamic microkernel for RISC-V CHERI, verified in Isabelle/HOL, exceeding seL4.

**Goals:** 3.5k LOC TCB, HW CHERI caps, proven temporal isolation, real-time EDF, CompCert binary correctness.

## Quick Start
```
tools/verify.sh           # host tests (no CHERI HW needed) - all PASS
make -C kernel            # needs riscv64-unknown-elf-clang -march=rv64imacxcheri + CompCert
make -C kernel isabelle   # Isabelle2024 + l4v, checks 7 theories
tools/run_qemu.sh kernel/build/moonlight.elf  # CTSRD-CHERI QEMU
```

## Structure
- `kernel/` - 6 syscalls, 3.5k LOC, `cap/cnode/tcb/vspace/endpoint/sched/iommu/irq/alloc/revoke/process`
- `kernel/isabelle/` - `RISCV_CHERI, CacheColoring, IOMMU_Verification, Moonlight_A/E, Sched_Verification, Refine`
- `userspace/` - `mem_server`, `sched_server` (EDF admission), `drivers/virtio_net` (IOMMU-isolated), `example/hello`
- `boot/dice.c` - DICE measured boot
- `docs/` - `ARCHITECTURE.md`, `THREAT_MODEL.md`, `REPRODUCIBLE.md`

## Proven Properties
- Functional correctness A==E==C (CompCert), integrity, authority confinement, time-aware confidentiality, availability (EDF + WCET 5us)
- HW CHERI monotonicity, cache-coloring non-interference, DMA confinement

## Test
`tests/test_cap.c`, `test_sched_realtime.c`, `test_revoke_process.c`, `host_emul.c`, `fuzz_syscall.c`, `bench_ipc.c` - see `tools/verify.sh`
