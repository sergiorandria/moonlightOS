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
for cand in /usr/bin/qemu-system-riscv64 qemu-system-riscv64 \
            /tmp/qb2/qemu-system-riscv64cheristd /tmp/qb2/qemu-system-riscv64 \
            qemu-system-riscv64cheristd; do
  if [ -x "$cand" ]; then QEMU="$cand"; break; fi
done
# If selected QEMU lacks bochs/ramfb but another has it, prefer the one with display
if ! $QEMU -device help 2>&1 | grep -qE "bochs-display|ramfb"; then
  for cand in /usr/bin/qemu-system-riscv64 /tmp/qb2/qemu-system-riscv64 qemu-system-riscv64; do
    if [ -x "$cand" ] && $cand -device help 2>&1 | grep -qE "bochs-display|ramfb"; then
      QEMU="$cand"; break;
    fi
  done
fi
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

# Display handling: use a window if DISPLAY/WAYLAND_DISPLAY is set,
# otherwise fall back to VNC so you can still SEE the framebuffer over
# SSH/headless sessions instead of silently going fully -nographic.
if [ "$2" = "--nographic" ]; then
  DISP="-nographic"
elif [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
  if $QEMU -display help 2>&1 | grep -q "gtk"; then
    DISP="-display gtk"
  elif $QEMU -display help 2>&1 | grep -q "sdl"; then
    DISP="-display sdl"
  else
    echo "No gtk/sdl backend in this QEMU build - falling back to VNC on :0 (connect with a VNC viewer to 127.0.0.1:5900)"
    DISP="-display vnc=127.0.0.1:0"
  fi
else
  echo "No DISPLAY/WAYLAND_DISPLAY set - starting VNC on :0 instead of going fully headless."
  echo "Connect with a VNC viewer to 127.0.0.1:5900 to see the framebuffer."
  DISP="-display vnc=127.0.0.1:0"
fi

# VGA framebuffer for Hello world on screen
# Always add bochs-display if available so PCI scan succeeds even in --nographic
# (needed for diagnostics via serial alone). Prefer bochs over ramfb.
VGA_ARGS=""
if $QEMU -device help 2>&1 | grep -q "bochs-display"; then
  VGA_ARGS="-device bochs-display"
elif $QEMU -device help 2>&1 | grep -q "ramfb"; then
  VGA_ARGS="-device ramfb"
elif $QEMU -device help 2>&1 | grep -q "virtio-gpu"; then
  VGA_ARGS="-device virtio-gpu-device"
fi

BIOS_ARGS="-bios none"

# GDB support
if [ "$2" = "--gdb" ] || [ "$3" = "--gdb" ]; then
  echo "GDB on :1234 - connect with: riscv64-unknown-elf-gdb $ELF -ex 'target remote :1234'"
  exec $QEMU $CHERI_ARGS -m 256M $BIOS_ARGS -kernel "$ELF" $VGA_ARGS -S -s -serial mon:stdio -d guest_errors -no-reboot -d int,cpu_reset
fi

echo "QEMU: $QEMU $CHERI_ARGS $DISP $VGA_ARGS $BIOS_ARGS -kernel $ELF -no-reboot -d int,cpu_reset"
exec $QEMU $CHERI_ARGS -m 256M $BIOS_ARGS -kernel "$ELF" $DISP $VGA_ARGS -serial mon:stdio -d guest_errors -no-reboot -d int,cpu_reset
