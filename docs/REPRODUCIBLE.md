# Reproducible Build + Attestation

```
make -C kernel clean && make -C kernel SOURCE_DATE_EPOCH=0
sha256sum kernel/build/moonlight.elf > build.hash
python3 tools/attest.py kernel/build/moonlight.elf build.hash
# ROM embeds expected hash at link time via linker.ld: PROVIDE(expected_hash)
```

DICE chain: UDS -> CDI = KDF(UDS, kernel_hash) -> attestation cert = sign(CDI, challenge). Verifier checks `tools/attest.py` + TPM quote.

CompCert: `ccomp -march rv64imacxcheri` produces binary with theorem `CompCert correctness: source semantics preserved`.

CBMC: `cbmc --bounds-check --pointer-check kernel/src/cap.c kernel/src/cnode.c` - no overflows.
