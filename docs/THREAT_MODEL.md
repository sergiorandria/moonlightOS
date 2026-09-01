# Threat Model - MoonlightOS vs seL4

## Assumptions
- HW CHERI-RISC-V correctly implements CC128, PMP, IOMMU. Verified via riscv-formal.
- ROM immutable, OTP UDS unfused read-once.
- CompCert correctly compiles C to RISC-V.

## Adversaries
| ID | Capability | seL4 covers? | Moonlight |
|---|---|---|---|
| A1 | Compromised user thread tries exfiltrate via caps | Yes (authority confinement) | Yes + CHERI HW tag prevents forgery |
| A2 | Malicious DMA device | Partial (IOMMU unverified) | Proven `Iommu_Verification.thy: dma_confinement` |
| A3 | Cache/TLB/BTB timing side channel | No (assumed absent) | Proven `CacheColoring.thy: no_cache_interference` + flush-on-switch |
| A4 | Supply chain (malicious toolchain) | No | CompCert + reproducible build + DICE attestation |

## CVEs mitigated by design (vs Linux/seL4 C)
- CVE-2023-... buffer overflow -> CHERI bounds trap
- CVE-2021-... use-after-free -> capability revocation (MDB) clears tag
- CVE-2019-... TOCTOU -> complete mediation, no ambient authority
- Spectre/Meltdown -> no speculation across partitions, flush, purecap userspace cannot speculatively access sealed caps

## Temporal isolation proof sketch
`partition_isolation_time` in `Sched_Verification.thy`: cur_partition switch => flush_microarch, WCET 5us bounded, EDF schedulable => no starvation across partitions.
