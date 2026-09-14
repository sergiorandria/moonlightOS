# Userspace build: freestanding RISC-V ELFs (no libc, no host headers).
# Same toolchain discipline as kernel/Makefile: clang resource dir only.
# NOTE: plain `=` (not `?=`) - make's built-in CC=cc would otherwise win.
CC = clang
CFLAGS_U = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
           -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
           -Wall -Wextra -I lib -I/usr/lib/clang/22/include \
           -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS_U = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib -T user.ld

LIB = lib/moonlight.c

# Moonlight C library (Linux-compatible): freestanding rv64 objects +
# standalone demo ELF. Same discipline as drivers; kernel headers supply
# the syscall numbers (linux_abi.h, single source of truth).
LIBC_INC = libc/include
LIBC_KINC = ../kernel/include
CFLAGS_LIBC = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
            -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
            -Wall -Wextra -I $(LIBC_INC) -I $(LIBC_KINC) -I/usr/lib/clang/22/include \
            -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
LIBC_SRCS = $(shell cat libc/SRCS)
LIBC_OBJS = $(patsubst src/%.c,build/src/%.o,$(filter %.c,$(LIBC_SRCS))) \
            $(patsubst src/%.S,build/src/%.o,$(filter %.S,$(LIBC_SRCS)))


all: build/hello.elf build/moonsh.elf libc

build/hello.elf: example/hello.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ example/hello.c $(LIB) lib/start.S
	ls -lh $@

build/moonsh.elf: sh/shell.c $(LIB) lib/start.S user.ld
	@mkdir -p build
	$(CC) $(CFLAGS_U) $(LDFLAGS_U) -o $@ sh/shell.c $(LIB) lib/start.S
	ls -lh $@

# libc objects (freestanding rv64) + standalone Linux demo ELF (_start).
libc: $(LIBC_OBJS)

build/src/%.o: libc/src/%.c
	@mkdir -p build/src
	$(CC) $(CFLAGS_LIBC) -c $< -o $@

build/src/%.o: libc/src/%.S
	@mkdir -p build/src
	$(CC) $(CFLAGS_LIBC) -c $< -o $@

# Host-sim objects for unit tests (shell logic runs on the build machine).
host-test-objs:
	@echo "host tests compile shell.c directly (see tests/test_shell.c)"

clean:
	rm -rf build

.PHONY: all clean libc host-test-objs
