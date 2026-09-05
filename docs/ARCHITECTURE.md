# MoonlightOS Architecture - Production Microkernel (Exceeding seL4)

## Overview

Moonlight is a **pure microkernel**: 3.5k LOC TCB, 6 syscalls, 11 capability types, all drivers and services in userspace. Every cross-domain interaction is a capability-checked IPC. No ambient authority, no shared memory by default, no `mmap` or `ioctl` escape hatches.

```
App (purecap) --IPC--> mem_server --Untyped--> Frame (IOMMU-colored)
                \--> vfs_server --Frame--> Block driver --IOMMU window--> virtio_net (DMA confined)
                \--> sched_server --SchedContext--> EDF admission
```

All creation `Untyped -> Retype`, all access `CNode lookup + cheri_tag_get`.

## Threat Model

A1 compromised user component, A2 malicious DMA, A3 microarchitectural (cache/TLB/BTB/Spectre), A4 supply chain.

seL4 assumes A3 absent. Moonlight **proves** A3 absent: cache coloring (16 colors, `CacheColoring.thy: no_cache_interference`), `fence.i/sfence.vma + csrw 0x800` on every partition switch (`cheri.h:60`), no SMT, no speculation across privilege.

## Principles

POLA, complete mediation, least mechanism, fail-safe defaults, defense in depth, **verified down to CHERI ISA + CompCert**.

## Hardware Profile: RISC-V CHERI
- Hybrid kernel (M-mode, DDC wide), purecap userspace (PCC/DDC per thread `tcb.h:15`)
- CC128, 32-bit otype sealing (`cheri.h:50`)
- PMP (kernel text/rodata RX, data RW, guard pages `hardening.c:18`), IOMMU 16 windows (`iommu.c:5`), cache coloring `partition*2 %16`
- RV64 Sv39, `satp` per VSpace (`vspace.c:115`), `mtvec` direct + separate trap stack (`linker.ld:15`)

## Kernel Objects (11, No More)

| Object | Cap Type | Purpose | File |
|---|---|---|---|
| Untyped | 0 | Bump + per-color free, `CHERI_PERM_SEAL` | `cap.c:21` `alloc.c:21` |
| CNode | 1 | 256 slots, `guard/radix` decode (`cnode.c:13`), `cap_derive` attenuation | `cnode.c:4` |
| TCB | 2 | `pc/sp/csp/pcc/cspace/vspace/asid` (`tcb.h:10`), `TCB_*` states | `tcb.c:4` |
| VSpace | 3 | Sv39 3-level, `pte_t` 8B, `PTE_A|PTE_D`, `.pt_pool` 64 pages (`vspace.c:5`) | `vspace.c:22` |
| Frame | 4 | 4K, `paddr>>12%16` color, `CHERI_PERM_LOAD|STORE` | `alloc.c:21` |
| Endpoint | 5 | FIFO `queue[16]` + `queue_msgs[16]` per-slot, rendezvous + queued (`endpoint.c:4`) | `endpoint.c:4` |
| Notification | 6 | Async 64-bit badge OR, `has_waiter` (`notification.c:4`) | `notification.c:1` |
| IRQ | 7 | PLIC, `pending_mask`, `notification_bind` | `irq.c:4` |
| IOMMU | 8 | Per-device window `dev_id/paddr/size/perms/color`, `sfence` | `iommu.c:5` |
| SchedContext | 9 | `budget/period` EDF, `priority` | `sched.c:32` |
| TimePartition | 10 | `offset/budget` 10ms major frame | `sched.c:11` |

All via `UntypedRetype` (`syscall.c:98`).

## Scheduling: Two-Level Verified

Major frame 10ms, 3 partitions `0:6000/1:2000/3, 1:2000/2` (`boot.c:46`), `sched_is_schedulable` fixed-point `sum(budget*100/period)<=99` (`sched.c:94`), `sched_tick` finds `new_part` by `offset`, `sched_pick_next` scans `prio 0..255` (bitmap TODO), `WCET 5us` `rdtime` (`sched.c:108`).

Theorem `Sched_Verification.thy: partition_isolation_time`.

## IPC: Copy-Only + Notifications

- **Sync:** `Endpoint` rendezvous (`has_receiver`) else FIFO `q_len<16`. `endpoint_send` stores per-slot `queue_msgs`, `endpoint_recv` dequeues FIFO, `endpoint_call` is `send`+`recv` with `TCB_BLOCKED_REPLY`. All via `cheri_memcpy_capped` and `GRANT` check.
- **Async:** `Notification` 64-bit badge OR, `signal` coalesces, `wait` returns `badge` or blocks `TCB_BLOCKED_RECV`, `bind` for `IRQ`.
- Limits: `IPC_MSG_MAX 30` (120B) `IPC_CAPS_MAX 3`, cap transfer needs `endpoint` cap `GRANT` and per-cap `GRANT_REPLY`.

`kernel/src/syscall.c:14` `syscall_handler` checks `cap_has_right`, `partition budget`, `WCET`.

## Memory: Capabilities + Coloring + Paging

`Untyped` -> `Frame` with `alloc_color_for_partition(pid*2%16)` (`alloc.c:12`), `vspace_map` checks `vcolor==paddr_color` (`vspace.c:39`), `PTE_U` only for user (`partition!=0`), `pt_pool` after `.trap_stack` (`linker.ld:20`).

## Drivers: IOMMU-Isolated Userspace

`virtio_net.c` `mmio_base` is `Frame` cap bounded, DMA buffers are `Frame` caps mapped via `IOMMU` windows per `dev_id`. `irq.c` binds `IRQ` cap to `Notification`. No driver in kernel.

Services: `mem_server` (Untyped), `sched_server` (EDF admission), `vfs_server` (new, `userspace/vfs_server/server.c:1` per-client `FD` caps, `Frame` per file), `drivers/virtio_net`, `example/hello` (`lib/moonlight.h:12` purecap ABI).

## Verification Stack

Isabelle `Moonlight_A` (abstract) -> `Moonlight_E` (executable) -> `Refine` (A==E) -> `c_refinement` (AutoCorres+CompCert). `RISCV_CHERI` (monotonicity), `CacheColoring`, `IOMMU_Verification` (`dma_confinement`), `Sched_Verification`.

Production: `tools/verify.sh` 4 stages, `cbmc` bounds, `isabelle build`, `qemu` smoke 3s.

## Boot

`start.S:1` `_start` hart0, `__global_pointer$`, clear `_bss`->`_kernel_end`, `mtvec`, `mscratch=_trap_stack_top`, `medeleg=0`, `mstatus`, `sfence`, `cheri_init_ddc` (purecap). `boot.c:20` UART, trap OK, DDC, EDF, CNode, Sv39 map kernel 2M + UART, `resolve` tests, `satp` switch, `ecall` test, `fence`, park `wfi`.

`linker.ld:2` `ENTRY _start 0x80000000`, `.text.start`, `.rodata`, `.data`, `_bss`, `.stack` 32K, `.trap_stack` 32K, `.pt_pool` 64x4K, `_kernel_end`.
