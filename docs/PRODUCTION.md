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

- [x] `tools/verify.sh` 4 stages: host unit (cap/sched/revoke/host_emul/bench/fuzz + `test_abi` 8-byte `uintptr_t` cross-check, hardening/vspace/virtio_net, Isabelle, CHERI/stock QEMU + 3s smoke) — `kernel/include/types.h:7` `_Static_assert(sizeof(uintptr_t)==8)` fails build if reintroduced
- [x] `kernel/isabelle` 7 theories typecheck (Isabelle2025)
- [x] QEMU window `DISPLAY=:0` GTK shows `[BOOT] ALL OK - parking` on both `riscv64` and `riscv64cheristd`
- [ ] CBMC `kernel/Makefile:cbmc` --bounds-check (manual - not in CI, run locally `pacman -S cbmc && make -C kernel cbmc`; target exists and was spot-checked, no CI runner)
- [ ] CompCert `ccomp -march rv64imacxcheri` - not pursued (no license; CompCert requires commercial license for CHERI-RISC-V, verification via `tools/verify.sh` + `isabelle` instead)

## Docs

- [x] `docs/USAGE.md` capabilities, TCB, VSpace, IPC, scheduling, example
- [x] `docs/BUILD.md` host, CHERI, stock QEMU, QEMU, reproducible, Isabelle, troubleshooting
- [x] `docs/SYSCALLS.md` 6 syscalls + 12 invoke ops, WCET, temporal isolation
- [x] `docs/CAPABILITIES.md` sealing, otype, attenuation, coloring, revocation
- [x] `docs/ARCHITECTURE.md`/`THREAT_MODEL.md`/`REPRODUCIBLE.md` existing
- [x] `docs/SECURITY.md` disclosure process, supported CHERI HW, cross-ref `THREAT_MODEL.md`

## Known Gaps (post-1.0)

- [x] `sched.c` EDF is fixed-point `uint64_t` throughout (no `float`/`double`; verified `grep -r float kernel/src/sched.c` — empty; formerly noted as gap but already resolved)
- [x] `vspace` PT alloc now uses `alloc_frame` per-color (`vspace_init_with_alloc` + `alloc_color_for_partition`, `kernel/src/vspace.c:9` `alloc_pt_page` via `alloc_frame`; no `.pt_pool` bump) — 64 pages color-isolated, verified in `tests/test_vspace.c`
- [x] `userspace/drivers/virtio_net.c` now wires MMIO via `cheri_bounds_set` + DMA via `iommu_map`/`iommu_check` (`virtio_net.c:30` bounded MMIO cap, `virtio_net.c:63` `net_driver_set_iommu`/`net_driver_dma_map`/`iommu_check` hot path) — verified in `tests/test_virtio_net.c`
- `cheri` purecap needs `cheribuild.py llvm` CI

## Fixed in 2025-09-03

- `handle_invoke` wired to `cap_retype`/`cnode_copy`/`vspace_map` with `g_root_cnode` + `g_mdb` insert, `dest` via `arg1>>8` (was no-op stub)
- `boot.c` spawns `user_hello` via `process_create` + `alloc_init`/`mdb_init`, demonstrates `handle_invoke` retype, `user_hello` runs as TCB
- `tests/test_ipc_trap.c` IPC across `ecall`/`syscall_handler` (was host-direct only)
- `cap.h` proper `irq`/`iommu`/`notification` union members (was `frame.paddr` overloading)
- `tcb.c` `tcb_resume` now wakes `BLOCKED_*`, `tcb_wake_from_ipc` added
- `endpoint.c` FIFO `queue_msgs[16]` per-slot + wake `tcb_wake_from_ipc`, `sched.c` skips blocked TCBs
- `process.c` `endpoint_cleanup_for_tcb` + `cspace` zero + `mdb` fix, `revoke.c` `mdb_lookup` respects `cnode_id`
