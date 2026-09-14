# Build Guide (v2)

The repo is the single v2 codebase: the v2 kernel (`kernel/`), the frozen v1
ABI headers (`userspace/abi/`) and the userspace build (`userspace/`), the
Isabelle spec session (`kernel/isabelle`). There is no `v2/` tree and no v1
`kernel/src`/`kernel/include` anymore.

## Host Requirements

- clang + lld (kernel and userspace compile freestanding with the clang
  resource dir only — never host `/usr/include`),
- make, python3, Isabelle2025-2 (+ l4v at `/opt/isabelle`) for proofs,
- `qemu-system-riscv64` 8.x+ (must ship OpenSBI for `-bios default`).
- Arch: `pacman -S clang lld make qemu-system-riscv`. For Isabelle:
  `isabelle` in `PATH`, `ISABELLE_TOOL_JAVA_OPTIONS` as needed.

## 1. Kernel

```bash
make -C kernel
# -> kernel/build/moonlight.elf (S-mode, rv64imac, freestanding; 31K)
make -C kernel clean
```

`kernel/Makefile` is the single source of truth for flags: stock clang,
`-march=rv64imac -mabi=lp64`, `-ffreestanding -nostdlib -fno-builtin
-mcmodel=medany -mno-relax -Werror`, `-fuse-ld=lld -T linker.ld`. Sources:
`kboot.c user.c start.S trap.S`. Override the compiler with
`CC=/path/to/clang make -C kernel` (the CHERI toolchain gate in `cheri.yml`
does exactly this).

## 2. Userspace (freestanding ELFs + libc + drivers)

```bash
make -C userspace        # build/hello.elf, build/moonsh.elf, build/linux_demo.elf, libc objects
make -C userspace drivers # freestanding rv64 -Werror compile gates for the 8 driver compartments
make -C userspace clean
```

Includes come from inside the tree only: `userspace/abi/` (frozen v1 ABI:
types, cap, cheri, iommu, vspace, linux_abi) + `userspace/libc/include`.
Driver code must be `-Werror` clean and may only include the self-contained
ABI headers — a driver warning or an ambient include is a production defect.

## 3. Verification (single entry)

```bash
tools/verify.sh
```

Stages: host unit tests (ABI regression, servers + shell, driver host-sims,
freestanding libc, v2 IPC/caps) → production gates (linker layout: no
PROGBITS inside the `[_bss,_bss_end)` clear range; `user.c` rodata ban) →
Isabelle `kernel/isabelle` session (`V2` + `Qubes_A`, anti-vacuity gate) →
kernel build → QEMU text smoke. All `PASS` required before pushing
(proofs/SMOKE may SKIP if the host lacks Isabelle/QEMU).

## 4. QEMU

```bash
tools/run_qemu.sh             # boots OpenSBI -> v2 kernel, window/VNC by default
tools/run_qemu.sh --nographic # serial-only
tools/run_qemu.sh --gdb       # GDB on :1234
tools/build_qemu.sh           # alias for `make -C kernel`
```

The runner uses `-bios default` (OpenSBI) — the v2 kernel is S-mode; the v1
`-bios none` world is gone. It also attaches a 256M raw `virtio-blk` disk
(`kernel/build/moonlight-disk.img`) for the userspace block compartment;
use `--no-disk` to boot diskless. Expect:

```
v2 stage2: S-mode entry (OpenSBI)
v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0
v2: entering U-mode thread A
B00pn
A10pg
W1
no runnable left; parking cpu
```

## 5. Isabelle

```bash
isabelle build -D kernel/isabelle -v    # session V2 (V2_A .. V2_D, Qubes_A)
make -C kernel isabelle                 # same
```

Anti-vacuity gate: the theories contain no `sorry`/`axiomatization` and no
`≡ True` invariant definitions (enforced by `verify.sh`).

## 6. REPRODUCIBLE builds

```bash
make -C kernel clean && make -C kernel SOURCE_DATE_EPOCH=0
sha256sum kernel/build/moonlight.elf
```

(Measuring every output hash in CI is aspirational; the kernel builds
deterministically with `SOURCE_DATE_EPOCH`.)

## Troubleshooting

- `clang: command not found` -> install clang/LLVM first.
- `stale firmware timer fault loop` -> the kernel arms SBI timer before SIE;
  if you hand-edit `kboot.c`, keep that order (documented in source).
- `qemu: could not load kernel` -> use `-bios default` (OpenSBI) and a
  `-kernel` ELF with entry in the `0x80200000` load region; never `-bios none`.
- No user VGA window -> run with a display (`DISPLAY=:0
  tools/run_qemu.sh`) or VNC; `--nographic` keeps everything on serial.
- Isabelle `bad session` -> the container version must match
  Isabelle2025-2; see `.github/workflows/verify.yml`.