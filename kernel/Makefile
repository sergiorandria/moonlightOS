CC ?= riscv64-unknown-elf-clang
# Autodetect CHERI support (stock clang 22 lacks xcheri)
CHERI_CC := $(shell which $(CC) 2>/dev/null || which clang 2>/dev/null || echo cc)
CHERI_OK := $(shell echo | $(CHERI_CC) -march=rv64imacxcheri -E -dM - > /dev/null 2>&1 && echo yes || echo no)
ifeq (,$(shell which $(CC) 2>/dev/null))
  CC := clang
  CFLAGS_CHERI_DETECT := --target=riscv64-unknown-elf
else
  CFLAGS_CHERI_DETECT :=
endif
ifeq ($(CHERI_OK),yes)
  CFLAGS_CHERI = $(CFLAGS_CHERI_DETECT) -march=rv64imacxcheri -mabi=l64pc128d -cheri-bounds=conservative -mcmodel=medany -mno-relax
  LDFLAGS =
  LD = riscv64-unknown-elf-ld
else
  $(warning CHERI toolchain not found, falling back to stock QEMU hybrid sim - use tools/build_qemu.sh for full build)
  CC := clang
  CFLAGS_CHERI = --target=riscv64-unknown-elf -march=rv64imac -mabi=lp64 -mcmodel=medany -mno-relax -I/usr/include -I/usr/lib/clang/22/include
  LDFLAGS = --target=riscv64-unknown-elf -fuse-ld=lld -nostdlib
  LD = ld.lld
endif
CFLAGS_BASE = -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror \
              -fno-builtin -mcmodel=medany -mno-relax \
              -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
              -Wimplicit-fallthrough -Wcast-align -Wshadow
ifeq ($(CHERI_OK),yes)
CFLAGS ?= $(CFLAGS_CHERI) $(CFLAGS_BASE)
else
CFLAGS ?= $(CFLAGS_CHERI) $(CFLAGS_BASE) -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -Wno-cast-align
endif
SRC = src/cap.c src/cnode.c src/tcb.c src/vspace.c src/sched.c src/endpoint.c src/syscall.c src/cheri.c src/boot.c src/iommu.c src/irq.c src/alloc.c src/revoke.c src/process.c src/hardening.c src/notification.c src/minilib.c src/flush.c src/elf.c
ASM = src/start.S src/trap.S
LINKER = linker.ld

ISABELLE = isabelle
OBJ = $(SRC:.c=.o) $(ASM:.S=.o)
TARGET = build/moonlight.elf
TARGET_QEMU = build/moonlight.qemu.elf

all: $(TARGET)

$(TARGET): $(OBJ) $(LINKER)
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -T $(LINKER) -o $@ $(OBJ)

qemu: $(TARGET_QEMU)

$(TARGET_QEMU): $(SRC) $(ASM) $(LINKER)
	@mkdir -p build
	@echo "Building stock QEMU fallback (hybrid sim)..."
	@../tools/build_qemu.sh
	@cp /tmp/moonlight_trap.elf $@ 2>/dev/null || cp /tmp/moonlight_qemu.elf $@ 2>/dev/null || true
	@ls -lh $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

isabelle:
	$(ISABELLE) build -D isabelle -v

verify:
	@../tools/verify.sh

cbmc:
	@if command -v cbmc >/dev/null 2>&1; then \
		echo "CBMC: bounds/div/pointer for endpoint/vspace/sched"; \
		cbmc --bounds-check --pointer-check --div-by-zero-check --unwind 10 cbmc_harness.c 2>&1 | head -n 20; \
	else echo "SKIP: cbmc not found (pacman -S cbmc)"; fi
	@cbmc --bounds-check --pointer-check --div-by-zero-check src/cap.c src/cnode.c --unwind 10 2>&1 | head -n 20 || true

compcert:
	@if command -v ccomp >/dev/null 2>&1; then \
		echo "CompCert: ccomp -march rv64imacxcheri"; \
		ccomp -march rv64imacxcheri -c src/cap.c -o /tmp/cap.compcert.o && echo "CompCert OK"; \
	else echo "SKIP: ccomp not found (https://compcert.org)"; fi

clean:
	rm -f build/moonlight.elf build/moonlight.qemu.elf src/*.o build/moonlight.x86_64.elf
	@rmdir --ignore-fail-on-non-empty build 2>/dev/null || true

.PHONY: all qemu isabelle verify cbmc clean
