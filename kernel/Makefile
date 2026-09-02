CC ?= riscv64-unknown-elf-clang
CFLAGS_CHERI = -march=rv64imacxcheri -mabi=l64pc128d -cheri-bounds=conservative
CFLAGS_BASE = -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror \
              -fno-builtin -mcmodel=medany -mno-relax \
              -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
              -Wimplicit-fallthrough -Wcast-align -Wshadow
CFLAGS ?= $(CFLAGS_CHERI) $(CFLAGS_BASE)

ISABELLE = isabelle
LD = riscv64-unknown-elf-ld
SRC = src/cap.c src/cnode.c src/tcb.c src/vspace.c src/sched.c src/endpoint.c src/syscall.c src/cheri.c src/boot.c src/iommu.c src/irq.c src/alloc.c src/revoke.c src/process.c src/hardening.c
ASM = src/start.S src/trap.S
OBJ = $(SRC:.c=.o) $(ASM:.S=.o)
TARGET = build/moonlight.elf
TARGET_QEMU = build/moonlight.qemu.elf

all: $(TARGET)

# CHERI build (requires CTSRD LLVM)
$(TARGET): $(OBJ) linker.ld
	@mkdir -p build
	$(CC) $(CFLAGS) -T linker.ld -o $@ $(OBJ)

# Stock QEMU fallback (hybrid sim, no CHERI LLVM)
qemu: $(TARGET_QEMU)

$(TARGET_QEMU): $(SRC) $(ASM) linker.ld
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
	@cbmc --bounds-check --pointer-check --div-by-zero-check src/cap.c src/cnode.c --unwind 10

clean:
	rm -rf build src/*.o ../build

.PHONY: all qemu isabelle verify cbmc clean
