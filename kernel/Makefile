CC = riscv64-unknown-elf-clang
CFLAGS = -march=rv64imacxcheri -mabi=l64pc128d -cheri-bounds=conservative \
         -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror \
         -fno-builtin -mcmodel=medany -mno-relax

ISABELLE = isabelle
LD = riscv64-unknown-elf-ld
SRC = src/cap.c src/cnode.c src/tcb.c src/vspace.c src/sched.c src/endpoint.c src/syscall.c src/cheri.c src/boot.c src/iommu.c src/irq.c src/alloc.c src/revoke.c src/process.c src/hardening.c
ASM = src/trap.S
OBJ = $(SRC:.c=.o) $(ASM:.S=.o)
TARGET = build/moonlight.elf

all: $(TARGET)

$(TARGET): $(OBJ) linker.ld
	@mkdir -p build
	$(CC) $(CFLAGS) -T linker.ld -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

isabelle:
	$(ISABELLE) build -D isabelle -v

clean:
	rm -rf build src/*.o

.PHONY: all clean isabelle
