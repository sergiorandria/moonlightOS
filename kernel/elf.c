#include "elf.h"
#include "ipc.h"
#include "caps.h"

#define V2_FRAME_PHYS_BASE 0x81000000UL

/* Frame allocation helper - uses existing frame_pool from kboot.c */
extern int frame_alloc_slot(v2_caps_t *caps, unsigned long tid);

/* Validate ELF header and program headers */
static int v2_elf_validate(const elf_ehdr_t *ehdr, size_t elf_size)
{
    if (elf_size < sizeof(elf_ehdr_t))
        return 0;
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F')
        return 0;
    if (ehdr->e_ident[4] != ELF_CLASS_64)
        return 0;
    if (ehdr->e_ident[5] != ELF_DATA_LSB)
        return 0;
    if (ehdr->e_ident[6] != ELF_VERSION)
        return 0;
    if (ehdr->e_type != ELF_TYPE_EXEC)
        return 0;
    if (ehdr->e_machine != ELF_MACHINE_RISCV)
        return 0;
    if (ehdr->e_version != ELF_VERSION)
        return 0;
    if (ehdr->e_phentsize != sizeof(elf_phdr_t))
        return 0;
    if (ehdr->e_phnum < 1 || ehdr->e_phnum > 8)
        return 0;
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(elf_phdr_t) > elf_size)
        return 0;
    return 1;
}

/* Validate a single PT_LOAD segment */
static int v2_elf_validate_phdr(const elf_phdr_t *ph, size_t elf_size)
{
    if (ph->p_type != ELF_PT_LOAD)
        return 1; /* ignore non-PT_LOAD */
    if (ph->p_filesz > ph->p_memsz)
        return 0;
    if (ph->p_offset + ph->p_filesz > elf_size)
        return 0;
    if (ph->p_vaddr + ph->p_memsz < ph->p_vaddr) /* overflow */
        return 0;
    if ((ph->p_flags & (ELF_PF_W | ELF_PF_X)) == (ELF_PF_W | ELF_PF_X))
        return 0; /* W^X violation */
    if (ph->p_align == 0 || (ph->p_align & (ph->p_align - 1)) != 0)
        return 0; /* alignment must be power of 2 */
    if (ph->p_vaddr % ph->p_align != 0)
        return 0;
    return 1;
}

/* Compute rights from p_flags */
static unsigned long v2_elf_rights_from_flags(uint32_t flags)
{
    unsigned long rights = 0;
    if (flags & ELF_PF_R) rights |= V2_RIGHT_R;
    if (flags & ELF_PF_W) rights |= V2_RIGHT_W;
    if (flags & ELF_PF_X) rights |= V2_RIGHT_X;
    return rights;
}

/* Find or allocate a frame and map it at vpn with rights */
static int v2_elf_map_page(v2_caps_t *caps, unsigned long tid,
                           unsigned long vpn, unsigned long rights,
                           unsigned long *out_frame)
{
    int slot;
    unsigned long frame;

    /* Find an empty cap slot for the frame */
    for (slot = 0; slot < V2_CAP_SLOTS; slot++) {
        if (!caps->caps[tid][slot].valid) break;
    }
    if (slot >= V2_CAP_SLOTS)
        return V2_ERR_OVERFLOW;

    /* Allocate frame */
    int rc = frame_alloc_slot(caps, tid);
    if (rc != V2_OK)
        return rc;
    /* frame_alloc_slot returns in caps->caps[tid][slot].obj - find it */
    for (slot = 0; slot < V2_CAP_SLOTS; slot++) {
        if (caps->caps[tid][slot].valid && !caps->caps[tid][slot].root) {
            frame = caps->caps[tid][slot].obj;
            caps->caps[tid][slot].valid = 0; /* we'll reinstall with proper rights */
            break;
        }
    }
    if (slot >= V2_CAP_SLOTS)
        return V2_ERR_OVERFLOW;

    /* Create cap with rights */
    for (slot = 0; slot < V2_CAP_SLOTS; slot++) {
        if (!caps->caps[tid][slot].valid) break;
    }
    if (slot >= V2_CAP_SLOTS)
        return V2_ERR_OVERFLOW;
    caps->caps[tid][slot].valid = 1;
    caps->caps[tid][slot].obj = frame;
    caps->caps[tid][slot].rights = rights;
    caps->caps[tid][slot].root = 0;

    /* Map the page */
    rc = v2_map(caps, tid, slot, vpn);
    if (rc != V2_OK)
        return rc;

    *out_frame = frame;
    return V2_OK;
}

/* Load ELF from frame pool (initrd) into current VSpace */
int v2_elf_load(const uint8_t *elf_data, size_t elf_size,
                v2_caps_t *caps, unsigned long cur_tid,
                uint64_t *out_entry, uint64_t *out_brk)
{
    const elf_ehdr_t *ehdr = (const elf_ehdr_t *)elf_data;
    const elf_phdr_t *phdrs;
    uint64_t brk = 0;
    unsigned long i, k;
    unsigned long frame;

    if (!v2_elf_validate(ehdr, elf_size))
        return V2_ERR_INVALID;

    phdrs = (const elf_phdr_t *)(elf_data + ehdr->e_phoff);

    /* Validate all PT_LOAD segments first */
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (!v2_elf_validate_phdr(&phdrs[i], elf_size))
            return V2_ERR_INVALID;
    }

    /* Load each PT_LOAD segment */
    for (i = 0; i < ehdr->e_phnum; i++) {
        const elf_phdr_t *ph = &phdrs[i];
        if (ph->p_type != ELF_PT_LOAD)
            continue;

        unsigned long rights = v2_elf_rights_from_flags(ph->p_flags);
        unsigned long vpn_start = ph->p_vaddr >> 12;
        unsigned long npages = (ph->p_memsz + 4095) >> 12;

        if (vpn_start + npages > V2_VPN_SLOTS)
            return V2_ERR_OVERFLOW;

        for (k = 0; k < npages; k++) {
            unsigned long vpn = vpn_start + k;
            int rc = v2_elf_map_page(caps, cur_tid, vpn, rights, &frame);
            if (rc != V2_OK)
                return rc;

            /* Copy page data from ELF to frame */
            uint64_t file_offset = ph->p_offset + k * 4096;
            uint64_t copy_size = 4096;
            if (k == npages - 1 && ph->p_filesz % 4096 != 0)
                copy_size = ph->p_filesz % 4096;

            /* Zero the frame first (BSS) */
            for (unsigned long b = 0; b < 4096; b++)
                ((volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096))[b] = 0;

            if (file_offset + copy_size <= elf_size && copy_size > 0) {
                for (unsigned long b = 0; b < copy_size; b++)
                    ((volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096))[b] = elf_data[file_offset + b];
            }
        }

        /* Track brk (end of writable segments) */
        if (ph->p_flags & ELF_PF_W) {
            uint64_t seg_end = ph->p_vaddr + ph->p_memsz;
            if (seg_end > brk) brk = seg_end;
        }
    }

    *out_entry = ehdr->e_entry;
    *out_brk = (brk + 4095) & ~4095UL; /* page-align brk */
    return V2_OK;
}