# Userspace build: freestanding RISC-V ELFs (no libc, no host headers).
# Same toolchain discipline as kernel/Makefile: clang resource dir only.
# NOTE: plain `=` (not `?=`) - make's built-in CC=cc would otherwise win.
CC = clang
CLANG_INC := $(shell $(CC) --print-resource-dir)/include
CFLAGS_U = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
           -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
           -Wall -Wextra -I lib -I$(CLANG_INC) \
           -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS_U = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib -T user.ld

LIB = lib/moonlight.c

# Moonlight C library (Linux-compatible): freestanding rv64 objects +
# standalone demo ELF. Same discipline as drivers; the frozen v1 userspace
# ABI headers (userspace/abi) supply the syscall numbers (linux_abi.h,
# single source of truth) and cap/CHERI types.
LIBC_INC = libc/include
LIBC_KINC = abi
CFLAGS_LIBC = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
            -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
            -Wall -Wextra -I $(LIBC_INC) -I $(LIBC_KINC) -I$(CLANG_INC) \
            -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LIBC_SRCS = $(shell cat libc/SRCS)
LIBC_OBJS = $(patsubst src/%.c,build/src/%.o,$(filter %.c,$(LIBC_SRCS))) \
            $(patsubst src/%.S,build/src/%.o,$(filter %.S,$(LIBC_SRCS)))

DRIVERS = drivers/block.c drivers/virtio_net.c drivers/vga.c \
          drivers/uart.c drivers/plic.c drivers/timer.c \
          drivers/rtc.c drivers/power.c
DRV_OBJ = build/drivers/block.o build/drivers/virtio_net.o build/drivers/vga.o \
          build/drivers/uart.o build/drivers/plic.o build/drivers/timer.o \
          build/drivers/rtc.o build/drivers/power.o
# Drivers are freestanding compartments: same discipline as ELFs, plus the
# kernel headers they validate caps against. -Werror: a driver warning is a
# production defect (an OOB or sign bug here escapes the compartment).
CFLAGS_DRV = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
            -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
            -Wall -Wextra -Werror -I lib -I libc/include -I abi -I$(CLANG_INC) \
            -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast

# v2 initrd server (Stage 3): freestanding rv64 ELF on the V2 UABI, linked
# at the frame-window base via v2_user.ld. No libc, no v1 moonlight.h.
CFLAGS_V2 = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
            -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
            -Wall -Wextra -Werror -I$(CLANG_INC) \
            -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS_V2 = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib -T v2_user.ld

all: build/hello.elf build/moonsh.elf build/linux_demo.elf build/ls.elf build/cat.elf build/mem_server.elf build/qrexec.elf build/adminvm.elf build/firewall.elf build/net.elf build/vault.elf build/cryptblk.elf drivers libc

build/mem_server.elf: mem_server/v2_main.c lib/v2_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ mem_server/v2_main.c lib/v2_start.S
	ls -lh $@

build/qrexec.elf: qrexec_server/v2_main.c qrexec_server/qrexec_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ qrexec_server/v2_main.c qrexec_server/qrexec_start.S
	ls -lh $@

build/adminvm.elf: adminvm/v2_main.c adminvm/adminvm_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ adminvm/v2_main.c adminvm/adminvm_start.S
	ls -lh $@

build/firewall.elf: firewall/v2_main.c firewall/firewall_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ firewall/v2_main.c firewall/firewall_start.S
	ls -lh $@

build/net.elf: net/v2_main.c net/net_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ net/v2_main.c net/net_start.S
	ls -lh $@

build/vault.elf: vault/v2_main.c vault/vault_start.S v2_user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ vault/v2_main.c vault/vault_start.S
	ls -lh $@

build/cryptblk.elf: cryptblk/v2_main.c cryptblk/cryptblk_start.S v2_user.ld cryptblk/layout.h cryptblk/slot.h crypt/aead.h crypt/kdf.h crypt/sha256.h crypt/crypt_util.h
	@mkdir -p build
	$(CC) $(CFLAGS_V2) $(LDFLAGS_V2) -Wl,--no-undefined -o $@ cryptblk/v2_main.c cryptblk/cryptblk_start.S
	ls -lh $@

build/hello.elf: example/hello.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ example/hello.c $(LIB) lib/start.S
	ls -lh $@

build/moonsh.elf: sh/shell.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ sh/shell.c $(LIB) lib/start.S
	ls -lh $@

build/ls.elf: example/ls.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ example/ls.c $(LIB) lib/start.S
	ls -lh $@

build/cat.elf: example/cat.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ example/cat.c $(LIB) lib/start.S
	ls -lh $@

# Driver compile gate: every driver must build freestanding rv64 warning-free.
# (Linking happens at compartment load; here we prove target-compilability,
# including the __riscv transport paths host tests never execute.)
drivers: $(DRV_OBJ)

build/drivers/%.o: drivers/%.c drivers/virtio_mmio.h
	@mkdir -p build/drivers
	$(CC) $(CFLAGS_DRV) -c $< -o $@
	ls -lh $@

# libc objects (freestanding rv64) + standalone Linux demo ELF (_start).
libc: $(LIBC_OBJS)

build/src/%.o: libc/src/%.c
	@mkdir -p build/src
	$(CC) $(CFLAGS_LIBC) -c $< -o $@

build/src/%.o: libc/src/%.S
	@mkdir -p build/src
	$(CC) $(CFLAGS_LIBC) -c $< -o $@

build/linux_demo.elf: example/linux_demo.c $(LIBC_OBJS) libc/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_LIBC) $(LDFLAGS_U) -Wl,-e,_start -o $@ example/linux_demo.c $(LIBC_OBJS) libc/start.S
	ls -lh $@

# Host-sim objects for unit tests (shell logic runs on the build machine).
host-test-objs:
	@echo "host tests compile shell.c directly (see tests/test_shell.c)"

clean:
	rm -rf build

.PHONY: all clean drivers libc host-test-objs
