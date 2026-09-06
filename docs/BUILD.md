# Build Guide (Production)

## Host Requirements

- Arch Linux, clang 22, lld, meson 1.12, ninja 1.13, Isabelle2024 (optional)
- `pacman -S clang lld meson ninja qemu-system-riscv`

## 1. Host Tests (no HW needed)

```bash
tools/verify.sh
# [1/4] Host unit tests: cap, sched, revoke, host_emul, bench, fuzz
# [1b] hardening/vspace
# [2/4] Isabelle/HOL
# [3/4] CHERI or stock QEMU build
# [4/4] QEMU smoke 3s
```

All `PASS` is required before pushing.

## 2. CHERI Build (Production, Purecap)

Needs CTSRD LLVM with `rv64imacxcheri`:

```bash
git clone https://github.com/CTSRD-CHERI/cheribuild && ./cheribuild.py llvm
export PATH=$HOME/cheri/output/sdk/bin:$PATH
riscv64-unknown-elf-clang --version # should show cheri
make -C kernel clean && make -C kernel -j
# produces kernel/build/moonlight.elf (purecap, .pt_pool, trap stacks)
ls -lh kernel/build/moonlight.elf
riscv64-unknown-elf-objdump -d kernel/build/moonlight.elf | head
```

Flags: `-march=rv64imacxcheri -mabi=l64pc128d -cheri-bounds=conservative -fstack-protector-strong` (`kernel/Makefile:2`).

## 3. Stock QEMU Fallback (Hybrid Sim, No CHERI LLVM)

For CI or hosts without CHERI LLVM:

```bash
tools/build_qemu.sh
# uses clang --target=riscv64-unknown-elf -march=rv64imac -I kernel/include
# int sched (no float), minilib, start/trap, linker 0x80000000
ls -lh kernel/build/moonlight.elf # 443K, ENTRY _start
```

This builds `kernel/src/start.S:1` + `trap.S:5` + `vspace.c:5` with `Sv39` and `mcause` handling.

## 4. QEMU

Build CHERI QEMU (once):

```bash
git clone https://github.com/CTSRD-CHERI/qemu qemu
mkdir -p /tmp/qb2 && cd /tmp/qb2
/path/to/qemu/configure --target-list=riscv64-softmmu,riscv64cheristd-softmmu --disable-werror --disable-libnfs
ninja -j$(nproc) qemu-system-riscv64 qemu-system-riscv64cheristd
```

Run:

```bash
tools/run_qemu.sh # autodetects /tmp/qb2/qemu-system-riscv64cheristd vs stock
tools/run_qemu.sh kernel/build/moonlight.elf --nographic
DISPLAY=:0 tools/run_qemu.sh kernel/build/moonlight.elf # GTK window
tools/run_qemu.sh --gdb # GDB :1234
```

Expect:
```
[BOOT] MoonlightOS trap/paging/CHERI init
[TRAP] mtvec=0x80000080 OK
[CHERI] hybrid sim DDC OK
[PAGING] satp switch OK Sv39
[TRAP] ecall returned
```

## 5. Reproducible + Attestation

```bash
make -C kernel clean && make -C kernel SOURCE_DATE_EPOCH=0
sha256sum kernel/build/moonlight.elf > build.hash
python3 tools/attest.py kernel/build/moonlight.elf build.hash
# DICE CDI = KDF(UDS, kernel_hash) see docs/REPRODUCIBLE.md
```

## 6. Isabelle

```bash
make -C kernel isabelle # needs Isabelle2024 + l4v at /opt/isabelle
isabelle build -D kernel/isabelle -v
```

## Troubleshooting

- `invalid arch xcheri` -> stock clang, use `tools/build_qemu.sh`
- `infinite exception loop` -> check `linker.ld:2` ENTRY _start and `vspace` A/D bits
- `P` -> `p` corruption after ecall -> separate trap stack (fixed in `linker.ld:15` `.trap_stack`)
- `qemu: could not load kernel` -> ELF entry must be 0x80000000, not 0x80200000 for `-bios none`
