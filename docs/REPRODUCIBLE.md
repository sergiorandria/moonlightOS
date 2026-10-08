# Reproducible Build + Attestation

> **v1-era reference** (historical). This document describes the removed
> v1 DICE measured boot (`kernel/src/dice.c`, `kernel/src/sha256.c`).
> DICE is not present in the v2 kernel (`kernel/`). The v2 reproducibility
> goal is a deterministic build gated in `tools/verify.sh`.

```
make -C kernel clean && make -C kernel SOURCE_DATE_EPOCH=0
sha256sum kernel/build/moonlight.elf > build.hash
python3 tools/attest.py kernel/build/moonlight.elf build.hash
```

**Status (2026-09-12, was PLAN 1.1):** DICE is wired end to end.
`kernel/src/sha256.c` (freestanding, KAT-tested in `tests/test_dice.c`) +
`kernel/src/dice.c` are in `kernel/Makefile`'s `SRC`; `kernel_boot()` calls
`boot_measure_and_attest()` and logs the public `kernel_hash` (never the CDI).

Measurement design: `[_text_start,_dice_expected_start)` +
`[_dice_expected_end,_bss)` — everything file-backed **except** the 32-byte
`.dice_expected` slot itself (supplied by the generated
`kernel/build/expected_hash.c`, kept across `clean` like a `.config`).
Because the slot is excluded, provisioning is a fixed point in one rebuild:

```
make -C kernel provision-dice   # measure -> fill slot -> relink -> re-measure + MATCH gate
make -C kernel dice-unprovision # back to measure-only (unprovisioned boots continue with a warning)
```

Boot semantics: rc 0 = verified against provisioned hash; rc 1 =
unprovisioned, measure-only (continues); rc -1 = mismatch against a
provisioned hash, fail closed (`wfi` halt before the scheduler starts).
A single flipped bit in `.text` was verified to halt with
`[DICE] FAIL hash mismatch, halting` and no shell.

Two build flavors provision independently (different flags -> different
measurements): `make -C kernel` uses `kernel/build/expected_hash.c`;
`tools/build_qemu.sh` self-provisions its own slot and gates on the same
fixed-point re-measurement. `tools/measure_dice.py` reconstructs the loaded
image from `PT_LOAD` segments, zero-filling holes between segments exactly
as zeroed guest RAM reads them (a skipped-bytes bug of this kind once made
the script disagree with the hart on the QEMU flavor while still matching
itself — the boot-time verify is the backstop that catches that class).

DICE chain: UDS (zeros on QEMU — no fused OTP; silicon reads OTP read-once)
-> CDI = SHA256(UDS || kernel_hash) -> attestation cert = sign(CDI,
challenge) (`attestation_cert[512]` reserved in `dice_state_t g_dice`).
Verifier checks `tools/attest.py` + TPM quote. Note: an earlier draft of this
doc prescribed `PROVIDE(expected_hash)` in `linker.ld`; that was dropped
because PROVIDE can only supply an address, not 32 data bytes — the generated
object is the mechanism.

CompCert: `ccomp -march rv64imacxcheri` produces binary with theorem `CompCert correctness: source semantics preserved`.

CBMC: `cbmc --bounds-check --pointer-check kernel/src/cap.c kernel/src/cnode.c` - no overflows.
