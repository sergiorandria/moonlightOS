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

SRC_C = kboot.c user.c elf.c initrd.c initrd_data.c irq.c device.c sched.c syscall.c elf_loader.c console.c vm.c syscall_ipc.c syscall_asend.c syscall_cap.c syscall_mem.c syscall_proc.c syscall_qube.c ipc_monitor.c ipc_deadlock.c ipc_flow_control.c ipc_priority.c kernel_monitor.c
SRC_S = start.S trap.S

all: build/moonlight.elf

build/moonlight.elf: $(SRC_C) $(SRC_S) linker.ld *.h
	@mkdir -p build
	$(CC) $(CFLAGS_K) $(LDFLAGS_K) -o $@ $(SRC_C) $(SRC_S) -Wl,--no-undefined
	ls -lh $@

# initrd_data.c is generated (tools/mkinitrd.sh) from userspace/build/*.elf;
# the committed blob can silently drift from the ELFs the build produces, so
# regenerate it whenever the generator or an ELF is newer.
#
# Guarded, NOT a hard prerequisite: a standalone `make -C kernel` (before
# userspace has ever been built) finds no required ELF, so the recipe degrades
# to a no-op and the committed blob compiles as-is — the kernel still builds.
# mkinitrd.sh resolves its paths from the repo root, hence the `cd ..`; its
# output is byte-deterministic, so on an up-to-date tree this rewrite is
# content-identical and leaves git clean. It is the gate (§1e2 of
# tools/verify.sh) that fails when the committed blob is stale.
INITRD_ELFS := $(wildcard ../userspace/build/*.elf)
initrd_data.c: ../tools/mkinitrd.sh $(INITRD_ELFS)
	@if [ -f ../userspace/build/mem_server.elf ]; then \
	  cd .. && tools/mkinitrd.sh; \
	else \
	  echo "initrd_data.c: userspace/build/mem_server.elf absent; using committed blob"; \
	fi

clean:
	rm -rf build

isabelle:
	isabelle build -D isabelle -v

verify:
	@../tools/verify.sh

.PHONY: all clean isabelle verify
