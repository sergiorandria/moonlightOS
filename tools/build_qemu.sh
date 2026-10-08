#!/bin/bash
set -e
# Build the v2 Moonlight kernel to run under QEMU (S-mode under OpenSBI).
# The kernel builds itself: stock clang, freestanding, `make -C kernel`.
# kernel/Makefile is the single source of truth for flags. Boot with:
#   tools/run_qemu.sh
if ! command -v clang >/dev/null 2>&1; then
  echo "clang not found - install LLVM/clang first"
  exit 1
fi
make -C kernel
echo "qemu build OK (v2 S-mode kernel: kernel/build/moonlight.elf; boot with -bios default)"