#ifndef V2_ELF_H
#define V2_ELF_H

#include <stdint.h>
#include "caps.h"

/* ELF64 constants */
#define ELF_MAGIC 0x464C457FUL /* "\x7FELF" in little-endian */
#define ELF_CLASS_64 2
#define ELF_DATA_LSB 1
#define ELF_VERSION 1
#define ELF_OSABI_NONE 0
#define ELF_TYPE_EXEC 2
#define ELF_MACHINE_RISCV 243
#define ELF_PT_LOAD 1

#define ELF_PF_X 1
#define ELF_PF_W 2
#define ELF_PF_R 4

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) elf_phdr_t;

typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) elf_ehdr_t;

/* ELF validation and loading */
int v2_elf_load(const uint8_t *elf_data, size_t elf_size,
                v2_caps_t *caps, unsigned long cur_tid,
                uint64_t *out_entry, uint64_t *out_brk);

#endif