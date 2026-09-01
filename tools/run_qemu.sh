#!/bin/bash
set -e
ELF=${1:-kernel/build/moonlight.elf}
if [ ! -f "$ELF" ]; then
  echo "build first: make -C kernel"
  exit 1
fi
# Requires QEMU with CHERI-RISC-V: https://github.com/CTSRD-CHERI/qemu
qemu-system-riscv64 \
  -M virt,cheri=on \
  -cpu rv64,cheri=on \
  -m 256M \
  -nographic \
  -bios none \
  -kernel "$ELF" \
  -d guest_errors
