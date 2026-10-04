# Moonlight kernel: S-mode under OpenSBI (QEMU -bios default). Freestanding.
# NOTE: plain `=` (not `?=`): make's built-in CC=cc would otherwise win.
CC = clang
CLANG_INC := $(shell $(CC) --print-resource-dir)/include
CFLAGS_K = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 \
           -O2 -ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax \
           -Wall -Wextra -Werror -I$(CLANG_INC) \
           -fno-stack-protector \
           -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast \
           -fno-delete-null-pointer-checks \
           -fwrapv \
           -fno-strict-aliasing \
           -fno-strict-overflow
# NOTE: -fno-stack-protector is explicit, not an omission. There is no libc
# to host __stack_chk_fail, and the mechanisms are paging/CHERI instead.
# A canary layer arrives with the Stage-3 C library; until then any
# -fstack-protector in these flags is a build break by design.
#
# Hardening flags (production-grade):
# -fno-delete-null-pointer-checks: Don't assume NULL deref is UB (safety-critical)
# -fwrapv: Signed integer overflow wraps (predictable behavior)
# -fno-strict-aliasing: Disable type-based alias analysis (safety-critical)
# -fno-strict-overflow: Don't optimize on signed overflow assumptions
LDFLAGS_K = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib -T linker.ld

SRC_C = kboot.c user.c elf.c initrd.c initrd_data.c irq.c
SRC_S = start.S trap.S

all: build/moonlight.elf

build/moonlight.elf: $(SRC_C) $(SRC_S) linker.ld *.h
	@mkdir -p build
	$(CC) $(CFLAGS_K) $(LDFLAGS_K) -o $@ $(SRC_C) $(SRC_S) -Wl,--no-undefined
	ls -lh $@

clean:
	rm -rf build

isabelle:
	isabelle build -D isabelle -v

verify:
	@../tools/verify.sh

.PHONY: all clean isabelle verify
