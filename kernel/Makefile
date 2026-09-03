ARCH ?= riscv
ifeq ($(ARCH),x86_64)
  CC ?= clang
  CFLAGS_CHERI =
  CFLAGS_BASE = -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror \
                -fno-builtin -mno-red-zone -mcmodel=large -no-pie -fno-pic -fno-PIE \
                -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                -Wimplicit-fallthrough -Wcast-align -Wshadow
  CFLAGS ?= $(CFLAGS_CHERI) $(CFLAGS_BASE) -DARCH_X86_64 -D__x86_64__
  LD = ld.lld
  SRC = src/cap.c src/cnode.c src/tcb.c src/vspace.c src/sched.c src/endpoint.c src/syscall.c src/cheri.c src/boot.c src/iommu.c src/irq.c src/alloc.c src/revoke.c src/process.c src/hardening.c src/notification.c src/minilib.c src/flush.c src/elf.c arch/x86_64/paging.c
  ASM = arch/x86_64/start.S arch/x86_64/trap.S
  LINKER = linker.x86_64.ld
else
  CC ?= riscv64-unknown-elf-clang
  # Autodetect CHERI support (stock clang 22 lacks xcheri)
  CHERI_CC := $(shell which $(CC) 2>/dev/null || which clang 2>/dev/null || echo cc)
  CHERI_OK := $(shell echo | $(CHERI_CC) -march=rv64imacxcheri -E -dM - > /dev/null 2>&1 && echo yes || echo no)
  # Fallback to stock clang --target=riscv64 if CHERI toolchain missing
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
endif

ISABELLE = isabelle
OBJ = $(SRC:.c=.o) $(ASM:.S=.o)
ifeq ($(ARCH),x86_64)
TARGET = build/moonlight.x86_64.elf
else
TARGET = build/moonlight.elf
endif
TARGET_QEMU = build/moonlight.qemu.elf

all: $(TARGET)

# CHERI build (requires CTSRD LLVM for riscv, stock clang for x86_64)
$(TARGET): $(OBJ) $(LINKER)
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -T $(LINKER) -o $@ $(OBJ)

# Stock QEMU fallback (hybrid sim, no CHERI LLVM) - riscv only
qemu: $(TARGET_QEMU)

$(TARGET_QEMU): $(SRC) $(ASM) $(LINKER)
	@mkdir -p build
	@echo "Building stock QEMU fallback (hybrid sim)..."
	@../tools/build_qemu.sh
	@cp /tmp/moonlight_trap.elf $@ 2>/dev/null || cp /tmp/moonlight_qemu.elf $@ 2>/dev/null || true
	@ls -lh $@

x86_64:
	$(MAKE) ARCH=x86_64 all
	@cp build/moonlight.elf build/moonlight.x86_64.elf
	@ls -lh build/moonlight.x86_64.elf

qemu-x86_64:
	$(MAKE) ARCH=x86_64 all
	@cp build/moonlight.elf build/moonlight.x86_64.elf
	@echo "x86_64 build OK - run: qemu-system-x86_64 -M q35 -m 256M -kernel build/moonlight.x86_64.elf -serial mon:stdio -display gtk"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

isabelle:
	$(ISABELLE) build -D isabelle -v

verify:
	@../tools/verify.sh

cbmc:
	@cbmc --bounds-check --pointer-check --div-by-zero-check src/cap.c src/cnode.c --unwind 10

clean:
ifeq ($(ARCH),x86_64)
	rm -f build/moonlight.x86_64.elf src/*.o arch/x86_64/*.o
else
	rm -f build/moonlight.elf build/moonlight.qemu.elf src/*.o
endif
	@rmdir --ignore-fail-on-non-empty build 2>/dev/null || true

.PHONY: all qemu isabelle verify cbmc clean
