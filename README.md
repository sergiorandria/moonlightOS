# MoonlightOS

General-purpose dynamic microkernel for **RISC-V CHERI + x86-64**, verified in Isabelle/HOL, exceeding seL4. **Production grade** - trap/paging/CHERI/CET, QEMU window tested on both archs.

**Goals:** 3.5k LOC TCB, HW CHERI/CET caps, proven temporal isolation, real-time EDF, CompCert binary correctness.

## Quick Start (Production)

```bash
# RISC-V CHERI (primary, QEMU 11.1.1 / CTSRD-CHERI QEMU 7.0)
tools/verify.sh           # host tests (no CHERI HW needed) - all PASS
tools/build_qemu.sh       # stock QEMU fallback (no CHERI LLVM)
make -C kernel            # CHERI: needs riscv64-unknown-elf-clang -march=rv64imacxcheri + CompCert
make -C kernel isabelle   # Isabelle2024 + l4v, 7 theories
tools/run_qemu.sh kernel/build/moonlight.elf              # autodetects QEMU, nographic or gtk window
DISPLAY=:0 tools/run_qemu.sh kernel/build/moonlight.elf   # QEMU window (GTK)
tools/run_qemu.sh --gdb   # GDB :1234

# x86-64 (Intel/AMD, QEMU q35/microvm, 11.1.1)
make -C kernel ARCH=x86_64                # clang, CET sim, no CHERI LLVM -> build/moonlight.x86_64.elf
qemu-system-x86_64 -M q35 -m 256M -kernel kernel/build/moonlight.x86_64.elf -serial mon:stdio -display gtk
# or: qemu-system-x86_64 -M microvm -m 256M -kernel kernel/build/moonlight.x86_64.elf -nographic
make -C kernel x86_64 && ls -lh kernel/build/moonlight*.elf
```

## Structure
- `kernel/` - 6 syscalls, 3.5k LOC, `cap/cnode/tcb/vspace/endpoint/sched/iommu/irq/alloc/revoke/process`, `start.S`/`trap.S` Sv39/PML4, `linker.ld`/`linker.x86_64.ld` stacks+pt_pool+CHERI/CET
- `kernel/arch/x86_64/` - `start.S` (multiboot2+PVH Xen note, GDT/IDT), `trap.S` (IDT 0x80), `paging.c` (PML4 4-level)
- `kernel/isabelle/` - `RISCV_CHERI, CacheColoring, IOMMU_Verification, Moonlight_A/E, Sched_Verification, Refine` (x86_64 CET refinement in progress)
- `userspace/` - `mem_server` (color-aware), `sched_server` (EDF admission), `vfs_server` (FD caps), `drivers/virtio_net` (IOMMU-isolated), `example/hello`, `lib/moonlight.h` purecap ABI (CHERI + CET sim)
- `boot/dice.c` - DICE measured boot
- `docs/` - `ARCHITECTURE.md`, `THREAT_MODEL.md`, `REPRODUCIBLE.md`, `USAGE.md`, `BUILD.md`, `SYSCALLS.md`, `CAPABILITIES.md`, `PRODUCTION.md`

## Proven Properties
- Functional correctness A==E==C (CompCert), integrity, authority confinement, time-aware confidentiality, availability (EDF + WCET 5us)
- HW CHERI/CET monotonicity, cache-coloring non-interference, DMA confinement
- **RISC-V:** Trap `mtvec`/`mscratch` separate stacks, `mcause`+`mepc+4`, `sfence` - verified QEMU `riscv64`/`riscv64cheristd`
- **x86-64:** Trap `IDT` `int 0x80`, `PML4` 4-level, `CR3` switch, `CET` sim `0x100000-0x200000` - verified `qemu-system-x86_64 -M microvm`
- Paging: `Sv39` 3-level / `PML4` 4-level, `PTE_A|PTE_D`, bump `.pt_pool` 64 pages, `satp`/`CR3` switch

## Test
`tests/test_cap.c`, `test_sched_realtime.c`, `test_revoke_process.c`, `host_emul.c`, `fuzz_syscall.c`, `bench_ipc.c` - see `tools/verify.sh` (now 4 stages: host, Isabelle, CHERI/stock QEMU, 3s smoke)

## Docs

- [Usage](docs/USAGE.md) - capabilities, TCB, VSpace, IPC, scheduling, full example
- [Build](docs/BUILD.md) - host, CHERI, stock QEMU, QEMU, reproducible, troubleshooting
- [Syscalls](docs/SYSCALLS.md) - 6 syscalls + 12 invoke ops
- [Capabilities](docs/CAPABILITIES.md) - sealing, otype, attenuation, coloring
- [Production](docs/PRODUCTION.md) - checklist, known gaps
