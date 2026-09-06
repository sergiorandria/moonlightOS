# Security Policy - MoonlightOS

## Supported Hardware

- **CHERI-RISC-V**: Morello (ARM), CHERI-RISC-V QEMU (`riscv64cheristd`), and FPGA prototypes with CC128, PMP, and IOMMU. See `docs/THREAT_MODEL.md` for assumptions (HW correctly implements CHERI, ROM immutable, CompCert correctness).
- **Purecap userspace**: All userspace (including `virtio_net` driver) runs with CHERI capabilities; kernel is hybrid/purecap as per `kernel/include/cheri.h`.

## Vulnerability Disclosure

1. **Report**: Email `security@moonlightos.example` (or open a GitHub private security advisory). Include PoC, affected commit (`git rev-parse HEAD`), and whether `tools/verify.sh` reproduces it.
2. **Triage**: Maintainer acknowledges within 48h, reproduces via `tools/verify.sh` and QEMU (`riscv64`/`riscv64cheristd`), assigns CVSS.
3. **Fix**: Patch on `fix-isabelle-*` branch, verify with `tools/verify.sh` (4 stages) and `kernel/isabelle` proofs, then tag.
4. **Disclosure**: Coordinated 90-day disclosure; after fix, publish advisory and update `docs/THREAT_MODEL.md` with CVE mapping.

## Threat Model Cross-Reference

See `docs/THREAT_MODEL.md` for adversaries (A1-A4), assumptions, and CVEs mitigated by design (CHERI bounds, revocation, IOMMU, cache coloring, CompCert, DICE). Security claims are evidenced by `kernel/isabelle` theories and `tools/verify.sh`.

## Supported Versions

Only `main` and the latest `fix-isabelle-*` tag are supported. Older tags are not patched.

## Reporting Checklist

- [ ] `tools/verify.sh` log
- [ ] `riscv64-unknown-elf-objdump -d kernel/build/moonlight.elf` snippet if relevant
- [ ] CHERI hardware or QEMU version (`qemu-system-riscv64 --version`)
