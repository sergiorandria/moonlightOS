#!/bin/bash
set -e
# MoonlightOS QEMU runner - v2 S-mode kernel under OpenSBI
# Usage: tools/run_qemu.sh [elf] [--nographic|--gdb|--trace-int]
# The flag may also be passed as $1 (elf defaults to kernel/build/moonlight.elf).
if [[ "${1:-}" == --* ]]; then
  ELF="kernel/build/moonlight.elf"
  # shift flag into $2 so the checks below keep working
  set -- "$ELF" "$@"
fi
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
  echo "qemu-system-riscv64 not found. Install it via your distro (e.g. apt install qemu-system-misc, 8.x+ with OpenSBI)."
  exit 1
fi

# The v2 kernel is a stock rv64imac S-mode build under OpenSBI; no CHERI
# CPU flip is wired in yet. QEMU virt defaults suffice.
CHERI_ARGS="-M virt"

# Display handling: use a window if DISPLAY/WAYLAND_DISPLAY is set,
# otherwise fall back to VNC so you can still SEE the framebuffer over
# SSH/headless sessions instead of silently going fully -nographic.
if [[ "$*" == *"--nographic"* ]]; then
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

# VGA + keyboard follow the display: with a window (gtk/sdl/vnc) the shell
# splits onto VGA + virtio-keyboard and the launch terminal keeps only the
# boot log. --nographic attaches neither device, so the kernel stays in
# mirror mode and the shell lives on serial as before.
VGA_ARGS=""
KBD_ARGS=""
MOUSE_ARGS=""
if [ "$DISP" != "-nographic" ]; then
  if $QEMU -device help 2>&1 | grep -q "bochs-display"; then
    VGA_ARGS="-device bochs-display"
  elif $QEMU -device help 2>&1 | grep -q "ramfb"; then
    VGA_ARGS="-device ramfb"
  elif $QEMU -device help 2>&1 | grep -q "virtio-gpu"; then
    VGA_ARGS="-device virtio-gpu-device"
  fi

  # Keyboard + mouse: virtio-input over MMIO (riscv-virt has no PS/2).
  # The graphical window feeds these devices; kbd.c merges kbd with the
  # UART. Absent headless: the driver logs UART-only fallback and the
  # shell stays on serial. S4c input needs both dev-18 transports for
  # kernel discovery (first=mouse, second=kbd).
  if $QEMU -device help 2>&1 | grep -q "virtio-keyboard-device"; then
    KBD_ARGS="-device virtio-keyboard-device"
  fi
  if $QEMU -device help 2>&1 | grep -q "virtio-mouse-device"; then
    MOUSE_ARGS="-device virtio-mouse-device"
  fi
fi

# S4a GUI: the display server needs its PCI display device even headless
# (--nographic leaves VGA_ARGS empty, but -display none keeps hardware:
# the device still enumerates on ECAM and the GUIMMIO/GUI markers prove
# it). Single cmdline: VGA_ARGS rides both exec lines below, so one place
# covers windowed (already set above) and headless (fallback here).
if [ -z "$VGA_ARGS" ]; then
  if $QEMU -device help 2>&1 | grep -q "bochs-display"; then
    VGA_ARGS="-device bochs-display"
  fi
fi

# The v2 kernel is S-mode: OpenSBI loads it, so QEMU must ship firmware
# (-bios default). -bios none was the v1 M-mode world and must not return.
BIOS_ARGS="-bios default"

# Phase-2 NIC (S3 Task 4): virtio-net on a virtio-mmio transport with
# QEMU user-netdev. The net ELF / kernel scan for the NIC (QEMU attaches
# backends last-first), so NET_ARGS stays ahead of DISK/VGA/KBD devices
# but no fixed transport is assumed. force-legacy=off: the pinned QEMU
# defaults virtio-mmio transports to legacy mode (Version=1); the driver
# implements the modern queue core and needs Version=2.
NET_ARGS="-device virtio-net-device,netdev=n0 -netdev user,id=n0"
RNG_ARGS="-device virtio-rng-device"
VIRTIO_MODERN="-global virtio-mmio.force-legacy=off"

# 256M virtio-blk virtual disk (raw). Microkernel separation: the kernel
# never touches the disk. The disk is owned exclusively by the userspace
# block compartment (userspace/drivers/block.c, 524288 sectors); mem_server
# mints its MMIO Frame cap + IRQ binding and the driver validates the
# slot via block_probe_slot() (no ambient MMIO scan, no kernel driver).
# Pass --no-disk to boot diskless (driver keeps the diskless fallback).
DISK="kernel/build/moonlight-disk.img"
DISK_SIZE="256M"
DISK_SECTORS=524288
DISK_ARGS=""
if [[ "$*" != *"--no-disk"* ]]; then
  if [ ! -f "$DISK" ]; then
    echo "Creating 256M virtual disk: $DISK"
    mkdir -p "$(dirname "$DISK")"
    if command -v qemu-img >/dev/null 2>&1; then
      qemu-img create -f raw "$DISK" "$DISK_SIZE"
    elif command -v truncate >/dev/null 2>&1; then
      truncate -s "$DISK_SIZE" "$DISK"
    else
      dd if=/dev/zero of="$DISK" bs=1M count=256 status=none
    fi
  fi
  if [ -f "$DISK" ]; then
    SZ=$(stat -c%s "$DISK" 2>/dev/null || stat -f%z "$DISK" 2>/dev/null || echo 0)
    if [ "$SZ" != "268435456" ]; then
      echo "WARNING: $DISK is $SZ bytes, expected 268435456 (256M, $DISK_SECTORS sectors)."
      echo "Recreate with: rm $DISK (it is re-created on next run)"
    fi
    DISK_ARGS="-drive file=$DISK,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0"
  else
    echo "WARNING: could not create $DISK - booting diskless."
  fi
fi

# Logging: -d guest_errors only by default. The moonsh idle loop polls
# SYS_DEBUG_GETC + SYS_YIELD via ecall at high frequency, so `-d int`
# floods the terminal with riscv_cpu_do_interrupt lines and hides the
# actual serial output. Opt in only when tracing traps:
#   tools/run_qemu.sh [elf] --trace-int
LOG_ARGS="-d guest_errors"
if [[ "$*" == *"--trace-int"* ]]; then
  LOG_ARGS="-d guest_errors,int,cpu_reset"
fi

# GDB support
if [[ "$*" == *"--gdb"* ]]; then
  echo "GDB on :1234 - connect with: riscv64-unknown-elf-gdb $ELF -ex 'target remote :1234'"
  # shellcheck disable=SC2086
  exec $QEMU $CHERI_ARGS -m 256M $BIOS_ARGS -kernel "$ELF" $NET_ARGS $RNG_ARGS $VIRTIO_MODERN $VGA_ARGS $KBD_ARGS $MOUSE_ARGS $DISK_ARGS -S -s -serial mon:stdio $LOG_ARGS -no-reboot
fi

echo "QEMU: $QEMU $CHERI_ARGS $DISP $VGA_ARGS $KBD_ARGS $MOUSE_ARGS $DISK_ARGS $NET_ARGS $VIRTIO_MODERN $BIOS_ARGS -kernel $ELF -no-reboot $LOG_ARGS"
if [ -n "$DISK_ARGS" ]; then
  echo "(virtio-blk disk: $DISK 256M raw, owned by the userspace block compartment; --no-disk boots diskless)"
else
  echo "(no virtio-blk disk: --no-disk given or image missing)"
fi
if [ "$DISP" = "-nographic" ]; then
  echo "(shell on serial; use a display for the window shell)"
else
  echo "(shell in the QEMU window; serial keeps the boot log)"
fi
echo "(use --trace-int to re-enable -d int logging)"
# shellcheck disable=SC2086
exec $QEMU $CHERI_ARGS -m 256M $BIOS_ARGS -kernel "$ELF" $NET_ARGS $RNG_ARGS $VIRTIO_MODERN $DISP $VGA_ARGS $KBD_ARGS $MOUSE_ARGS $DISK_ARGS -serial mon:stdio $LOG_ARGS -no-reboot
