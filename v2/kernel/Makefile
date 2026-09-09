# v2 kernel: S-mode under OpenSBI (QEMU -bios default). Freestanding.
# NOTE: plain `=` (not `?=`): make's built-in CC=cc would otherwise win.
CC = clang
CFLAGS_K = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
           -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
           -Wall -Wextra -Werror -I/usr/lib/clang/22/include \
           -fno-stack-protector \
           -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
# NOTE: -fno-stack-protector is explicit, not an omission. There is no libc
# to host __stack_chk_fail, and the mechanisms are paging/CHERI instead.
# A canary layer arrives with the Stage-3 C library; until then any
# -fstack-protector in these flags is a build break by design.
LDFLAGS_K = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib -T linker.ld

SRC_C = kboot.c user.c
SRC_S = start.S trap.S

all: build/v2.elf

build/v2.elf: $(SRC_C) $(SRC_S) linker.ld
	@mkdir -p build
	$(CC) $(CFLAGS_K) $(LDFLAGS_K) -o $@ $(SRC_C) $(SRC_S) -Wl,--no-undefined
	ls -lh $@

clean:
	rm -rf build

.PHONY: all clean
