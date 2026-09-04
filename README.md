# MoonlightOS

General-purpose dynamic microkernel for **x86-64 (primary) + RISC-V CHERI (retrograde)**, verified in Isabelle/HOL, exceeding seL4. **Production grade** - x86-64 PML4/IDT/CET first, RISC-V CHERI retrofitted.

**Goals:** 3.5k LOC TCB, HW CET/CHERI caps, proven temporal isolation, real-time EDF, CompCert binary correctness.

## Quick Start (Production) - x86-64 First

```bash
# x86-64 primary (Intel/AMD, QEMU q35/microvm 11.1.1, no CHERI LLVM needed)
make -C kernel                                  # now defaults ARCH=x86_64 -> build/moonlight.x86_64.elf
qemu-system-x86_64 -M q35 -m 256M -kernel kernel/build/moonlight.x86_64.elf -serial mon:stdio -display gtk
qemu-system-x86_64 -M microvm -m 256M -kernel kernel/build/moonlight.x86_64.elf -nographic
make -C kernel x86_64 && ls -lh kernel/build/moonlight*.elf
tools/verify.sh           # host tests (no HW) - all PASS (both archs)

# RISC-V CHERI retrograde (QEMU 11.1.1 / CTSRD-CHERI QEMU 7.0)
tools/build_qemu.sh       # stock QEMU fallback (riscv64imac)
make -C kernel ARCH=riscv # CHERI: needs riscv64-unknown-elf-clang -march=rv64imacxcheri
tools/run_qemu.sh kernel/build/moonlight.elf              # autodetects riscv QEMU, gtk window
DISPLAY=:0 tools/run_qemu.sh kernel/build/moonlight.elf
```

## Structure
- `kernel/` - 6 syscalls, 3.5k LOC, `cap/cnode/tcb/vspace/endpoint/sched/iommu/irq/alloc/revoke/process`, `arch/x86_64/` primary PML4/IDT/CET, `arch/riscv` retrograde Sv39/CHERI
- `kernel/arch/x86_64/` - `start.S` (PML4 1GB 2MB, CR3/PAE/LME/PG, GDT/IDT), `trap.S` (IDT 0x80), `paging.c` (PML4), `linker.x86_64.ld` 0x100000
- `kernel/arch/riscv/` (retrograde) - `start.S`/`trap.S` Sv39, `linker.ld` 0x80000000, `cheri.c` hybrid
- `kernel/isabelle/` - `RISCV_CHERI` (retrograde) + `CacheColoring, IOMMU_Verification, Moonlight_A/E, Sched_Verification, Refine` (x86_64 CET refinement in progress)
- `userspace/` - `mem_server` (color-aware), `sched_server` (EDF admission), `vfs_server` (FD caps), `drivers/virtio_net` (IOMMU-isolated), `example/hello`, `lib/moonlight.h` purecap ABI (CET + CHERI sim)
- `boot/dice.c` - DICE measured boot
- `docs/` - `ARCHITECTURE.md` (x86-64 first), `THREAT_MODEL.md`, `REPRODUCIBLE.md`, `USAGE.md`, `BUILD.md`, `SYSCALLS.md`, `CAPABILITIES.md`, `PRODUCTION.md`

## Proven Properties
- Functional correctness A==E==C (CompCert), integrity, authority confinement, time-aware confidentiality, availability (EDF + WCET 5us) - x86-64 primary, RISC-V retrograde
- HW CET/CHERI monotonicity, cache-coloring non-interference, DMA confinement
- **x86-64 (primary):** Trap `IDT` `int 0x80` `PML4` 4-level `CR3` `CET` sim `0x100000-0x200000` - verified `qemu-system-x86_64 -M q35/microvm`
- **RISC-V (retrograde):** Trap `mtvec`/`mscratch` `mcause`+`mepc+4`, `Sv39` 3-level `satp` - retrofitted from x86-64, verified `riscv64`/`riscv64cheristd`
- Paging: `PML4` 4-level (x86-64) / `Sv39` 3-level (riscv), `PTE_A|PTE_D`, `.pt_pool` 64 pages

## Test
`tests/test_cap.c`, `test_sched_realtime.c`, `test_revoke_process.c`, `host_emul.c`, `fuzz_syscall.c`, `bench_ipc.c` - see `tools/verify.sh` (now 4 stages: host, Isabelle, CHERI/stock QEMU, 3s smoke)

## Docs

- [Usage](docs/USAGE.md) - capabilities, TCB, VSpace, IPC, scheduling, full example
- [Build](docs/BUILD.md) - host, CHERI, stock QEMU, QEMU, reproducible, troubleshooting
- [Syscalls](docs/SYSCALLS.md) - 6 syscalls + 12 invoke ops
- [Capabilities](docs/CAPABILITIES.md) - sealing, otype, attenuation, coloring
- [Production](docs/PRODUCTION.md) - checklist, known gaps
