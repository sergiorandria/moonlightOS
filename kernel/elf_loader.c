/* elf_loader.c - initrd -> thread VSpace spawning (SRP: ELF lifecycle).
 *
 * Factor of the repeated spawn blocks from kboot() (SOLID Sprint 1).
 * v2_elf_load still lives in elf.c; this module only orchestrates the
 * lookup + load + PTE sync + state transition. */
#include <stdint.h>

#include "caps.h"
#include "elf.h"
#include "initrd.h"
#include "kinternal.h"

/* elf_loader_spawn: load initrd index into thread tid's VSpace.
 * On success: PTEs synced, stack reset, sepc=entry, thread runnable.
 * On failure: prints the caller-supplied fail suffix, thread keeps its
 * stub entry. Returns 1 on success, 0 on failure. */
int elf_loader_spawn(const char *name, unsigned index, unsigned tid,
                     const char *fail)
{
    const uint8_t *elf_data;
    uint32_t elf_size;
    uint64_t entry = 0, brk = 0;
    if (initrd_lookup(index, &elf_data, &elf_size) == 0 &&
        v2_elf_load(elf_data, (size_t)elf_size, &caps, tid, &entry,
                    &brk) == V2_OK && entry != 0)
    {
        v2_pte_sync(tid);
        threads[tid].regs[2] = u_sp[tid];
        threads[tid].sepc = entry;
        threads[tid].state = T_RUNNABLE;
        kputs("[spawn] ");
        kputs(name);
        kputs(" ELF ok\n");
        return 1;
    }
    kputs("[spawn] ");
    kputs(name);
    kputs(" ELF ");
    kputs(fail);
    kputs("\n");
    return 0;
}
