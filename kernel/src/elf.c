#include "../include/elf.h"
#include "../include/vspace.h"
#include <string.h>

bool elf_is_valid(const void *data, size_t size){
    if(!data || size < sizeof(elf64_hdr_t)) return false;
    const elf64_hdr_t *h = data;
    if(h->magic != ELF_MAGIC) return false;
    if(h->cls != ELFCLASS64) return false;
    if(h->type != ET_EXEC) return false;
    return true;
}

kerror_t elf_load(const void *elf_data, size_t elf_size, uintptr_t *out_entry, uintptr_t *out_vaddr){
    if(!elf_data || !out_entry || !out_vaddr) return ERR_INVALID_ARG;
    if(!elf_is_valid(elf_data, elf_size)) return ERR_INVALID_ARG;
    const elf64_hdr_t *hdr = elf_data;
    if(hdr->phoff + hdr->phnum * sizeof(elf64_phdr_t) > elf_size) return ERR_INVALID_ARG;
    const elf64_phdr_t *phdrs = (const void*)((uintptr_t)elf_data + hdr->phoff);
    uintptr_t first_vaddr = 0xFFFFFFFFFFFFFFFF;
    for(int i=0;i<hdr->phnum;i++){
        if(phdrs[i].type != PT_LOAD) continue;
        if(phdrs[i].vaddr < first_vaddr) first_vaddr = phdrs[i].vaddr;
        // In production, map each segment via vspace_map and copy via cheri_memcpy_capped
        // For now, just validate
        if(phdrs[i].paddr + phdrs[i].memsz > 0x90000000) return ERR_INVALID_ARG;
    }
    *out_entry = hdr->entry;
    *out_vaddr = first_vaddr;
    return ERR_OK;
}
