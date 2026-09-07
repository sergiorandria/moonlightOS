# Reproducible Build + Attestation

```
make -C kernel clean && make -C kernel SOURCE_DATE_EPOCH=0
sha256sum kernel/build/moonlight.elf > build.hash
python3 tools/attest.py kernel/build/moonlight.elf build.hash
```

**Status:** `boot/dice.c` exists but is not yet wired into `kernel/Makefile` or `kernel/src/boot.c` (`boot_measure_and_attest()` never called, `expected[HASH_SIZE]={0}` not provided via `linker.ld`, `sha256()` has no implementation). The DICE chain below is the intended design, not yet running in the kernel:

DICE chain: UDS -> CDI = KDF(UDS, kernel_hash) -> attestation cert = sign(CDI, challenge). Verifier checks `tools/attest.py` + TPM quote. To wire: add `dice.c` to `SRC`, implement `sha256()`, add `PROVIDE(expected_hash)` in `linker.ld`, call from `kernel_boot()`.

CompCert: `ccomp -march rv64imacxcheri` produces binary with theorem `CompCert correctness: source semantics preserved`.

CBMC: `cbmc --bounds-check --pointer-check kernel/src/cap.c kernel/src/cnode.c` - no overflows.
