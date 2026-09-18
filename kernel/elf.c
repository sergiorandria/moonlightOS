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

/* Find or allocate a frame and map it at vpn with rights.
 * frame_alloc_slot returns the new cap slot index (>= 0) or a negative
 * errno; the kernel (allocator authority) then specializes the fresh RW
 * cap to the segment rights directly (minting X from RW would fail closed,
 * so attenuation is not used here). vpn is the frame-window index
 * (VA = V2_U_END + vpn*4096), already range-checked by the caller. */
static int v2_elf_map_page(v2_caps_t *caps, unsigned long tid,
                           unsigned long vpn, unsigned long rights,
                           unsigned long *out_frame)
{
    int slot;
    unsigned long frame;

    if (!caps || !out_frame)
        return V2_ERR_INVALID;
    if (rights & ~(V2_RIGHT_R | V2_RIGHT_W | V2_RIGHT_X))
        return V2_ERR_INVALID;
    if ((rights & V2_RIGHT_W) && (rights & V2_RIGHT_X))
        return V2_ERR_INVALID; /* W^X */
    if (vpn >= (unsigned long)V2_VPN_SLOTS)
        return V2_ERR_INVALID;
    if (v2_vm_find(caps, tid, vpn) >= 0)
        return V2_ERR_INVALID; /* duplicate vpn: fail before allocating */

    slot = frame_alloc_slot(caps, tid);
    if (slot < 0)
        return slot;
    if (slot >= V2_CAP_SLOTS)
        return V2_ERR_OVERFLOW;
    caps->caps[tid][slot].rights = rights;
    frame = caps->caps[tid][slot].obj;

    if (v2_map(caps, tid, (unsigned long)slot, vpn) != V2_OK) {
        /* Table full after a successful alloc: drop the cap so no
         * half-mapped state survives. The bitmap frame stays marked used
         * (one-frame leak on an already-failed load, fail-closed). */
        caps->caps[tid][slot].valid = 0;
        return V2_ERR_OVERFLOW;
    }

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
        unsigned long vpn_start, npages;
        /* PT_LOAD VAs live in the frame window (v2_user.ld BASE =
         * V2_U_END): the vpn is the window index, not the raw page number. */
        if (ph->p_vaddr < V2_U_END)
            return V2_ERR_INVALID;
        if (ph->p_vaddr & 0xFFFUL)
            return V2_ERR_INVALID; /* segments are page-aligned by link */
        if (ph->p_memsz > (unsigned long)V2_VPN_SLOTS * 4096UL)
            return V2_ERR_OVERFLOW;
        vpn_start = (unsigned long)((ph->p_vaddr - V2_U_END) >> 12);
        npages = (unsigned long)((ph->p_memsz + 4095) >> 12);

        if (vpn_start >= (unsigned long)V2_VPN_SLOTS ||
            npages > (unsigned long)V2_VPN_SLOTS - vpn_start)
            return V2_ERR_OVERFLOW;

        for (k = 0; k < npages; k++) {
            unsigned long vpn = vpn_start + k;
            int rc = v2_elf_map_page(caps, cur_tid, vpn, rights, &frame);
            if (rc != V2_OK)
                return rc;

            /* Copy this page's file bytes into the frame, zero the rest
             * (BSS). The file range [p_offset, p_offset+p_filesz) is
             * clamped against the page window [page_off, page_off+4096)
             * so BSS tail pages copy nothing instead of bytes past the
             * segment's file range. bound: npages, 4096-byte page loop. */
            uint64_t page_off = ph->p_offset + k * 4096;
            uint64_t file_end = ph->p_offset + ph->p_filesz;
            uint64_t copy_start = page_off < ph->p_offset ? ph->p_offset : page_off;
            uint64_t copy_end = page_off + 4096 < file_end ? page_off + 4096 : file_end;
            volatile uint8_t *dst =
                (volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096);

            for (unsigned long b = 0; b < 4096; b++)
                dst[b] = 0;

            if (copy_end > copy_start && copy_end <= elf_size) {
                unsigned long dst_off =
                    (unsigned long)(copy_start - page_off);
                unsigned long copy_len =
                    (unsigned long)(copy_end - copy_start);
                for (unsigned long b = 0; b < copy_len; b++)
                    dst[dst_off + b] = elf_data[copy_start + b];
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