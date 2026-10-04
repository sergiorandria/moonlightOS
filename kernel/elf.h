/* kernel/elf.h - ELF64 loader interface + the pure validation front end.
 *
 * v2_elf_plan() is the whole trust boundary for an ELF image: it parses and
 * bounds-checks the header and every PT_LOAD, and produces a plan the
 * loader executes without re-reading untrusted fields. It is pure C (no
 * asm, no MMIO, no allocation), so tests/test_elf.c runs it under
 * ASan/UBSan against malformed and randomly mutated images.
 *
 * Every size/offset comparison is written in subtraction form
 * (a <= limit && b <= limit - a): a + b can wrap on 64-bit fields, and a
 * wrapped sum used to pass the old `a + b > size` checks.
 *
 * Rejected up front (fail-closed, nothing allocated):
 *   - bad magic / class / endianness / version / type / machine
 *   - program-header table outside the file, wrong entry size, >8 entries
 *   - PT_LOAD with file range outside the image or filesz > memsz
 *   - PT_LOAD below the frame window, unaligned, or past V2_VPN_SLOTS
 *   - PT_LOAD with no permission bits, or W+X
 *   - overlapping PT_LOADs (two segments claiming one page)
 *   - an entry point that is not inside file-backed bytes of an X segment
 */
#ifndef V2_ELF_H
#define V2_ELF_H

#include <stddef.h>
#include <stdint.h>

#include "caps.h"
#include "ipc.h"

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

/* Program headers examined per image (also bounds the plan). */
#define V2_ELF_MAX_PHNUM 8

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

/* One validated PT_LOAD. vpn is the frame-window index (VA = V2_U_END +
 * vpn*4096), npages the page count; both are already range-checked. */
typedef struct {
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t offset;
    uint64_t filesz;
    unsigned long vpn;
    unsigned long npages;
    uint32_t flags;
} v2_elf_seg_t;

typedef struct {
    v2_elf_seg_t seg[V2_ELF_MAX_PHNUM];
    unsigned long nseg;
    uint64_t entry;
    uint64_t brk; /* page-aligned end of the writable segments (0 if none) */
} v2_elf_plan_t;

/* Memory rights for an ELF p_flags word (R/W/X only). */
static inline unsigned long v2_elf_rights(uint32_t flags)
{
    unsigned long r = 0;
    if (flags & ELF_PF_R)
        r |= V2_RIGHT_R;
    if (flags & ELF_PF_W)
        r |= V2_RIGHT_W;
    if (flags & ELF_PF_X)
        r |= V2_RIGHT_X;
    return r;
}

/* Validate an ELF image and build its load plan. V2_OK or V2_ERR_INVALID;
 * *out is only meaningful on V2_OK. */
static inline int v2_elf_plan(const uint8_t *data, size_t size, v2_elf_plan_t *out)
{
    const elf_ehdr_t *eh;
    const elf_phdr_t *ph;
    unsigned long i, j;
    int entry_ok = 0;

    if (!data || !out)
        return V2_ERR_INVALID;
    out->nseg = 0;
    out->entry = 0;
    out->brk = 0;
    if (size < sizeof(elf_ehdr_t))
        return V2_ERR_INVALID;
    eh = (const elf_ehdr_t *)data; /* packed: alignment 1, no cast hazard */

    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F')
        return V2_ERR_INVALID;
    if (eh->e_ident[4] != ELF_CLASS_64 || eh->e_ident[5] != ELF_DATA_LSB ||
        eh->e_ident[6] != ELF_VERSION || eh->e_ident[7] != ELF_OSABI_NONE)
        return V2_ERR_INVALID;
    if (eh->e_type != ELF_TYPE_EXEC || eh->e_machine != ELF_MACHINE_RISCV ||
        eh->e_version != ELF_VERSION)
        return V2_ERR_INVALID;
    if (eh->e_phentsize != sizeof(elf_phdr_t))
        return V2_ERR_INVALID;
    if (eh->e_phnum < 1 || eh->e_phnum > V2_ELF_MAX_PHNUM)
        return V2_ERR_INVALID;
    /* Table inside the file, overflow-safe (e_phoff is attacker-sized). */
    if (eh->e_phoff > size ||
        (size - (size_t)eh->e_phoff) / sizeof(elf_phdr_t) < eh->e_phnum)
        return V2_ERR_INVALID;
    ph = (const elf_phdr_t *)(data + eh->e_phoff);

    for (i = 0; i < eh->e_phnum; i++) { /* bound: V2_ELF_MAX_PHNUM */
        const elf_phdr_t *p = &ph[i];
        v2_elf_seg_t *s;
        unsigned long vpn_start, npages;

        if (p->p_type != ELF_PT_LOAD)
            continue;
        if (p->p_filesz > p->p_memsz)
            return V2_ERR_INVALID;
        if (p->p_offset > size || p->p_filesz > size - (size_t)p->p_offset)
            return V2_ERR_INVALID;
        if ((p->p_flags & (ELF_PF_W | ELF_PF_X)) == (ELF_PF_W | ELF_PF_X))
            return V2_ERR_INVALID; /* W^X */
        if ((p->p_flags & (ELF_PF_R | ELF_PF_W | ELF_PF_X)) == 0)
            return V2_ERR_INVALID; /* a segment nobody can touch is a bug */
        if (p->p_align == 0 || (p->p_align & (p->p_align - 1)) != 0)
            return V2_ERR_INVALID; /* alignment must be a power of 2 */
        if (p->p_vaddr % p->p_align != 0)
            return V2_ERR_INVALID;
        if ((p->p_vaddr & PAGE_MASK) != 0)
            return V2_ERR_INVALID; /* segments are page-aligned by link */
        if (p->p_vaddr < (uint64_t)V2_U_END)
            return V2_ERR_INVALID;
        if (p->p_memsz == 0)
            continue; /* maps nothing */
        if (p->p_memsz > (uint64_t)V2_VPN_SLOTS * PAGE_SIZE)
            return V2_ERR_OVERFLOW;
        vpn_start = (unsigned long)((p->p_vaddr - (uint64_t)V2_U_END) >> 12);
        npages = (unsigned long)((p->p_memsz + PAGE_MASK) >> 12);
        if (vpn_start >= (unsigned long)V2_VPN_SLOTS ||
            npages > (unsigned long)V2_VPN_SLOTS - vpn_start)
            return V2_ERR_OVERFLOW;

        s = &out->seg[out->nseg];
        s->vaddr = p->p_vaddr;
        s->memsz = p->p_memsz;
        s->offset = p->p_offset;
        s->filesz = p->p_filesz;
        s->vpn = vpn_start;
        s->npages = npages;
        s->flags = p->p_flags;
        out->nseg++;

        if (p->p_flags & ELF_PF_W) {
            uint64_t end = p->p_vaddr + p->p_memsz; /* both bounded above */
            end = (end + PAGE_MASK) & ~(uint64_t)PAGE_MASK;
            if (end > out->brk)
                out->brk = end;
        }
        if ((p->p_flags & ELF_PF_X) && eh->e_entry >= p->p_vaddr &&
            eh->e_entry - p->p_vaddr < p->p_filesz)
            entry_ok = 1;
    }

    if (out->nseg == 0 || !entry_ok || (eh->e_entry & 1UL) != 0)
        return V2_ERR_INVALID;
    out->entry = eh->e_entry;

    /* Overlap: two PT_LOADs must never claim the same page. */
    for (i = 0; i < out->nseg; i++) { /* bound: V2_ELF_MAX_PHNUM^2 */
        for (j = i + 1; j < out->nseg; j++) {
            const v2_elf_seg_t *a = &out->seg[i];
            const v2_elf_seg_t *b = &out->seg[j];
            if (a->vpn < b->vpn + b->npages && b->vpn < a->vpn + a->npages)
                return V2_ERR_INVALID;
        }
    }
    return V2_OK;
}

/* Load an initrd ELF into thread cur_tid's VSpace model (caps + mappings;
 * the caller syncs hardware PTEs). All-or-nothing: on any failure every
 * frame, cap slot and mapping this call created is rolled back. */
int v2_elf_load(const uint8_t *elf_data, size_t elf_size,
                v2_caps_t *caps, unsigned long cur_tid,
                uint64_t *out_entry, uint64_t *out_brk);

#endif /* V2_ELF_H */
