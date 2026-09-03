#pragma once
#include "types.h"
#include <stdint.h>
#include <stddef.h>

// Minimal ELF64 loader for initrd/userspace binaries
#define ELF_MAGIC 0x464C457F
#define ELFCLASS64 2
#define ET_EXEC 2
#define PT_LOAD 1

typedef struct {
    uint32_t magic;
    uint8_t  cls, data, version, osabi;
    uint8_t  abiversion, pad[7];
    uint16_t type, machine;
    uint32_t version2;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} elf64_hdr_t;

typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
} elf64_phdr_t;

kerror_t elf_load(const void *elf_data, size_t elf_size, uintptr_t *out_entry, uintptr_t *out_vaddr);
bool elf_is_valid(const void *data, size_t size);
