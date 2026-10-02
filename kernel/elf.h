#ifndef V2_ELF_H
#define V2_ELF_H

#include <stdint.h>
#include "caps.h"

/* System constants */
#define PAGE_SIZE 4096UL
#define PAGE_MASK (PAGE_SIZE - 1)

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

/* Comprehensive ELF header validation (magic, class, endianness, machine).
 * Guards against malformed/incompatible ELFs at multiple validation layers.
 * Returns 1 if header is valid for RISC-V 64-bit executable, 0 otherwise. */
static inline int elf_magic_ok(const elf_ehdr_t *hdr) {
    if (!hdr)
        return 0;
    /* Magic number check: 0x7F 'E' 'L' 'F' */
    if (*(const uint32_t*)hdr->e_ident != ELF_MAGIC)
        return 0;
    /* ELF class: must be 64-bit */
    if (hdr->e_ident[4] != ELF_CLASS_64)
        return 0;
    /* Data encoding: must be little-endian */
    if (hdr->e_ident[5] != ELF_DATA_LSB)
        return 0;
    /* ELF version: must be current */
    if (hdr->e_ident[6] != ELF_VERSION)
        return 0;
    /* OS/ABI: generic (NONE) */
    if (hdr->e_ident[7] != ELF_OSABI_NONE)
        return 0;
    /* Object file type: must be executable */
    if (hdr->e_type != ELF_TYPE_EXEC)
        return 0;
    /* Machine type: must be RISC-V */
    if (hdr->e_machine != ELF_MACHINE_RISCV)
        return 0;
    /* Version field: must be current */
    if (hdr->e_version != ELF_VERSION)
        return 0;
    return 1;
}

/* Validate ELF program header segment alignment.
 * Returns 1 if segment alignment is valid, 0 otherwise.
 * Guards: VMA and file offset must have same page alignment (ELF spec requirement),
 * and p_align must be 0 (unaligned) or PAGE_SIZE (page-aligned). */
static inline int elf_phdr_align_ok(const elf_phdr_t *ph) {
    if (!ph)
        return 0;
    /* VMA and file offset must be congruent modulo page size */
    if ((ph->p_vaddr & PAGE_MASK) != (ph->p_offset & PAGE_MASK))
        return 0;
    /* p_align must be 0 (no alignment) or PAGE_SIZE (page-aligned) */
    if (ph->p_align != 0 && ph->p_align != PAGE_SIZE)
        return 0;
    return 1;
}

int v2_elf_load(const uint8_t *elf_data, size_t elf_size,
                v2_caps_t *caps, unsigned long cur_tid,
                uint64_t *out_entry, uint64_t *out_brk);

#endif