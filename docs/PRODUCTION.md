# Production Checklist

## Build

- [x] `kernel/Makefile` includes `start.S` + `trap.S`, `fstack-protector-strong`, `Werror`
- [x] `tools/build_qemu.sh` fallback for hosts without `riscv64-unknown-elf-clang -march=rv64imacxcheri`
- [x] `kernel/linker.ld` ENTRY `_start` 0x80000000, `_bss`→`_kernel_end` clear, `.stack`/`.trap_stack` 32K each, `.pt_pool` 64 pages
- [x] `tools/run_qemu.sh` autodetects `qemu-system-riscv64cheristd` vs stock, `--nographic` vs `gtk`, `--gdb`

## Kernel

- [x] `start.S:1` hart0, `__global_pointer$`, BSS clear, `mtvec`, `mscratch`, `medeleg`, `mstatus`, `sfence`
- [x] `trap.S:5` full 272B frame matching `trap_frame_t`, `mcause 8-11` `mepc+=4`, `sfence` on return, separate trap stack
- [x] `vspace.c:5` Sv39 3-level, `PTE_A|PTE_D`, `pte_encode`, bump alloc in `.pt_pool`, `sfence` guards
- [x] `cheri.h:60` `cheri_flush` purecap `csrw 0x800` else `fence`, `cheri_init_ddc` validates PCC/DDC
- [x] `boot.c:20` UART, `mtvec` check, DDC, EDF, CNode, Sv39 map kernel+UART, `resolve` tests, `ecall` with `volatile` touch warmup
- [x] `hardening.h:1` `STACK_CANARY`, `GUARD_PAGE`, `is_canonical_addr`, `panic`, `HARDENING_ASSERT`, `fstack-protector`
- [x] `alloc.c:21` color-aware `alloc_frame`, `hw_cap` sealed, per-color free

## Verification

- [x] `tools/verify.sh` 4 stages: host unit (cap/sched/revoke/host_emul/bench/fuzz), hardening/vspace, Isabelle, CHERI/stock QEMU + 3s smoke
- [x] `kernel/isabelle` 7 theories typecheck (Isabelle2025)
- [x] QEMU window `DISPLAY=:0` GTK shows `[BOOT] ALL OK - parking` on both `riscv64` and `riscv64cheristd`
- [ ] CBMC `kernel/Makefile:cbmc` --bounds-check (manual)
- [ ] CompCert `ccomp -march rv64imacxcheri` (requires license)

## Docs

- [x] `docs/USAGE.md` capabilities, TCB, VSpace, IPC, scheduling, example
- [x] `docs/BUILD.md` host, CHERI, stock QEMU, QEMU, reproducible, Isabelle, troubleshooting
- [x] `docs/SYSCALLS.md` 6 syscalls + 12 invoke ops, WCET, temporal isolation
- [x] `docs/CAPABILITIES.md` sealing, otype, attenuation, coloring, revocation
- [x] `docs/ARCHITECTURE.md`/`THREAT_MODEL.md`/`REPRODUCIBLE.md` existing
- [ ] `docs/SECURITY.md` (planned)

## Known Gaps (post-1.0)

- `sched.c` float EDF → fixed-point int (done in `build_qemu` fallback, upstream to CHERI)
- `vspace` PT alloc should use `alloc_frame` per-color, not bump
- `userspace` drivers need IOMMU window caps wired to `vspace_map`
- `cheri` purecap needs `cheribuild.py llvm` CI
