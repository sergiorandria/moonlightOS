#!/bin/bash
set -e
# Stock QEMU build (no CHERI LLVM needed) - hybrid sim
CC="clang --target=riscv64-unknown-elf"
# Freestanding: never pull host glibc (-I/usr/include) — breaks uintptr_t
# (bits/wordsize.h falls back to 32-bit under --target=riscv64). Clang
# resource dir supplies correct freestanding <stdint.h>. Keep in sync with
# kernel/Makefile non-CHERI CFLAGS_CHERI + CFLAGS_BASE (warning suppressions).
CFLAGS="-march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -Wall -mcmodel=medany -mno-relax -fno-builtin -I$(dirname $0)/../kernel/include -I/usr/lib/clang/22/include -include stdbool.h -fno-stack-protector -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -Wno-cast-align"
SRC="cap.c cnode.c tcb.c vspace.c sched.c endpoint.c syscall.c cheri.c iommu.c irq.c alloc.c revoke.c process.c hardening.c notification.c minilib.c flush.c elf.c vga.c kbd.c sha256.c dice.c linux.c"
# DICE expected-hash slot: the QEMU build is a different flavor (different
# flags => different measurement) from `make -C kernel`, so it provisions
# ITSELF here instead of sharing kernel/build/expected_hash.c. Two passes:
# link with a zero slot -> measure (slot excluded, so this is a fixed point)
# -> fill slot -> relink -> verify MATCH.
printf '#include <stdint.h>\n__attribute__((section(".dice_expected"))) const uint8_t expected_kernel_hash[32] = {0};\n' > /tmp/expected_qemu.c
# NOTE: no stubs. sched.c is fixed-point throughout (see PRODUCTION.md) and
# minilib.c is freestanding-safe, so the QEMU build compiles the REAL kernel
# sources. A stub here once hid drift between tested and shipped code.
$CC $CFLAGS -c kernel/src/start.S -o /tmp/start_qemu.o
$CC $CFLAGS -c kernel/src/trap.S -o /tmp/trap_qemu.o
$CC $CFLAGS -c kernel/src/switch.S -o /tmp/switch_qemu.o
OBJ="/tmp/start_qemu.o /tmp/trap_qemu.o /tmp/switch_qemu.o"
for s in $SRC; do $CC $CFLAGS -c kernel/src/$s -o /tmp/${s%.c}_qemu.o; OBJ="$OBJ /tmp/${s%.c}_qemu.o"; done
$CC $CFLAGS -c kernel/src/boot.c -o /tmp/boot_qemu.o
OBJ="$OBJ /tmp/boot_qemu.o"
$CC $CFLAGS -c /tmp/expected_qemu.c -o /tmp/expected_qemu.o
OBJ="$OBJ /tmp/expected_qemu.o"
# Userspace: moonsh shell + ecall stubs (cooperative thread via thread_enter)
# + VFS server (the Linux personality calls vfs_* directly, same image)
# + bundled libc + Linux demo thread (libc headers first, minilib wins
# the 7 shared string symbols via __MOONLIGHT_KERNEL__ - mirrors the
# kernel/Makefile KLIBC rule).
$CC $CFLAGS -c userspace/sh/shell.c -o /tmp/shell_qemu.o
$CC $CFLAGS -c userspace/lib/moonlight.c -o /tmp/moonlight_qemu.o
$CC $CFLAGS -c userspace/vfs_server/server.c -o /tmp/vfs_server_qemu.o
OBJ="$OBJ /tmp/shell_qemu.o /tmp/moonlight_qemu.o /tmp/vfs_server_qemu.o"
KLIBCFLAGS="-Iuserspace/libc/include -D__MOONLIGHT_KERNEL__"
for s in $(cat userspace/libc/SRCS); do
  b=$(basename $s .c)
  $CC $KLIBCFLAGS $CFLAGS -c userspace/libc/$s -o /tmp/libc_${b}_qemu.o
  OBJ="$OBJ /tmp/libc_${b}_qemu.o"
done
$CC $KLIBCFLAGS $CFLAGS -c userspace/example/linux_demo.c -o /tmp/linux_demo_qemu.o
OBJ="$OBJ /tmp/linux_demo_qemu.o"
mkdir -p kernel/build
$CC $CFLAGS -fuse-ld=lld -T kernel/linker.ld -o kernel/build/moonlight.elf $OBJ -Wl,--no-undefined -nostdlib
# DICE self-provisioning, pass 2: measure the zero-slot image, fill the slot,
# relink, and gate on the fixed-point re-measurement.
DIGEST=$(python3 tools/measure_dice.py --digest kernel/build/moonlight.elf)
python3 tools/measure_dice.py kernel/build/moonlight.elf > /tmp/expected_qemu.c
$CC $CFLAGS -c /tmp/expected_qemu.c -o /tmp/expected_qemu.o
$CC $CFLAGS -fuse-ld=lld -T kernel/linker.ld -o kernel/build/moonlight.elf $OBJ -Wl,--no-undefined -nostdlib
python3 tools/measure_dice.py --expect "$DIGEST" kernel/build/moonlight.elf
ls -lh kernel/build/moonlight.elf
echo "qemu build OK (DICE provisioned + enforced)"
