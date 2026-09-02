#!/bin/bash
set -e
# MoonlightOS QEMU runner - production grade, autodetects CHERI vs stock
ELF=${1:-kernel/build/moonlight.elf}
if [ ! -f "$ELF" ]; then
  echo "build first: make -C kernel (or tools/build_qemu.sh)"
  exit 1
fi

# Autodetect QEMU binary
QEMU=""
for cand in /tmp/qb2/qemu-system-riscv64cheristd /tmp/qb2/qemu-system-riscv64 \
            qemu-system-riscv64cheristd qemu-system-riscv64 \
            /usr/bin/qemu-system-riscv64; do
  if [ -x "$cand" ]; then QEMU="$cand"; break; fi
done
if [ -z "$QEMU" ]; then
  echo "qemu-system-riscv64 not found. Build CTSRD-CHERI/qemu: https://github.com/CTSRD-CHERI/qemu"
  echo "  mkdir -p /tmp/qb2 && cd /tmp/qb2 && /path/to/qemu/configure --target-list=riscv64-softmmu,riscv64cheristd-softmmu && ninja"
  exit 1
fi

# Detect CHERI support
if $QEMU -M help 2>&1 | grep -q "virt" && $QEMU -cpu help 2>&1 | grep -q "cheri"; then
  CHERI_ARGS="-M virt,cheri=on -cpu rv64,cheri=on"
else
  # Stock or cheristd (cheri implicit)
  CHERI_ARGS="-M virt -cpu rv64"
  if echo "$QEMU" | grep -q "cheristd"; then
    echo "Using CHERI standard QEMU: $QEMU"
  fi
fi

# Display handling: use window if DISPLAY set, else nographic
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
  if [ "$2" = "--nographic" ]; then
    DISP="-nographic"
  elif $QEMU -display help 2>&1 | grep -q "gtk"; then
    DISP="-display gtk"
  else
    DISP="-nographic"
  fi
else
  DISP="-nographic"
fi

# GDB support
if [ "$2" = "--gdb" ] || [ "$3" = "--gdb" ]; then
  echo "GDB on :1234 - connect with: riscv64-unknown-elf-gdb $ELF -ex 'target remote :1234'"
  exec $QEMU $CHERI_ARGS -m 256M -bios none -kernel "$ELF" -S -s -serial mon:stdio -d guest_errors -no-reboot -d int,cpu_reset
fi

echo "QEMU: $QEMU $CHERI_ARGS $DISP -kernel $ELF -no-reboot -d int,cpu_reset"
exec $QEMU $CHERI_ARGS -m 256M -bios none -kernel "$ELF" $DISP -serial mon:stdio -d guest_errors -no-reboot -d int,cpu_reset
