# MoonlightOS Architecture - Exceeding seL4

## Threat Model
A1 compromised user component, A2 malicious DMA peripheral, A3 microarchitectural side channels (cache, TLB, BTB, Spectre), A4 supply chain.

seL4 assumes A3 absent and hardware/compiler correct. Moonlight proves A3 absent by construction and verifies down to CHERI ISA + CompCert.

## Principles
POLA, complete mediation, least mechanism, fail-safe defaults, defense in depth.

## Hardware Profile: RISC-V CHERI
- Purecap userspace, hybrid kernel
- CC128 capabilities, 32-bit otype for sealing
- PMP + IOMMU + cache coloring (16 colors, partition_id % 16)
- No SMT, no speculation across privilege, flush-on-switch mandatory

## Kernel Objects (only these exist)
| Object | Cap Type | Purpose |
|---|---|---|
| Untyped | 0 | Memory from which others are retyped, CHERI-bounded |
| CNode | 1 | Table of sealed CHERI caps, guard+radix |
| TCB | 2 | Thread context, SP, PC as CHERI caps |
| VSpace | 3 | CHERI address space root |
| Frame | 4 | 4K CHERI-bounded page, colored |
| Endpoint | 5 | Synchronous rendezvous, bounded queue |
| Notification | 6 | Async semaphore |
| IRQ | 7 | Interrupt delivery cap |
| IOMMU | 8 | DMA window cap |
| SchedContext | 9 | Budget/period (EDF) |
| TimePartition | 10 | Static ARINC-653 partition |

No other object types. All creation via retype from Untyped.

## Temporal Isolation
- Major frame 10ms, static partition table verified in Isabelle.
- Two-level scheduler: partition -> EDF within partition.
- All kernel paths constant-time, WCET proven, flushed state.
- Formal theorem: `nonleakage_time == partition_isolation`.

## IPC
Copy-only, 120 byte max inline, cap transfer only if grant perm. No shared memory by default. Cap transfer requires both endpoint cap and cap being transferred.

## Verification Stack
Isabelle/HOL: `isabelle/Moonlight_A.thy` (abstract), `Moonlight_E.thy` (executable), `Refine.thy` (A==E), C refinement via AutoCorres + CompCert theorem for binary.
