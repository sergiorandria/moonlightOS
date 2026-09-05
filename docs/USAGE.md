# MoonlightOS Usage Guide (Production)

This guide shows how to use the kernel from userspace. All userspace is purecap on CHERI HW, hybrid sim on host.

## 1. Capability Model (POLA)

Every kernel object is a sealed CHERI capability. Userspace never holds raw pointers to kernel memory.

```
Untyped (paddr,size) --retype--> Frame | CNode | TCB | VSpace | Endpoint | ...
```

Keep `Untyped` caps in `mem_server` (`userspace/mem_server/server.c:14`), not in apps. Apps request frames via IPC.

```c
// mem_server expects: label=1 (alloc), words[0]=partition, words[1]=size
ipc_msg_t msg = {.label=1, .words={part, 4096}, .length=2};
moonlight_call(mem_ep, &msg); // returns paddr, color
```

## 2. Threads (TCB)

```c
#include "lib/moonlight.h"
cap_t tcb_cap; // from Untyped retype
tcb_configure(&tcb, cspace, vspace_root, asid, partition);
tcb_set_regs(&tcb, pc, sp, pcc, csp); // PCC/CSP are CHERI code/data caps
moonlight_cnode_copy(parent_cnode, tcb_cap, CAP_RIGHTS_READ);
```

`TCB` state: `INACTIVE -> RUNNABLE -> BLOCKED_*`. Only `RUNNABLE` can syscall. See `kernel/include/tcb.h:10`.

## 3. Address Spaces

```c
vspace_t vs; vspace_init(&vs, asid, partition);
vspace_map(&vs, 0x100000, 0x800000, 4096, PTE_R|PTE_W, color); // color enforced
vspace_switch(&vs); // writes satp, sfence.vma
```

`color = (paddr>>12)%16` must match `vaddr` color or be 0 (kernel). See `kernel/src/vspace.c:39`.

## 4. IPC (copy-only, 120B)

```c
// Example hello (userspace/example/hello.c:5)
void _start(void){
  char *msg = "hello moonlight\n"; // purecap bounded string
  moonlight_call(1, msg); // ep_cptr=1, kernel copies via cheri_memcpy_capped
  moonlight_yield();
}
```

Limits: `IPC_MSG_MAX 30` words (`kernel/include/types.h:9`), `IPC_CAPS_MAX 3`. Cap transfer needs `GRANT` on endpoint.

## 5. Scheduling

Static ARINC-653 partitions verified in `kernel/isabelle/Sched_Verification.thy`.

```c
sched_partition_create(&sched, id, offset_us, budget_us, crit);
sched_context_bind(&sched, sc_id, tcb_id, part_id, budget, period, prio);
```

EDF within partition, WCET 5us enforced `wcet_check()`.

## 6. Full Example: Create Thread and Allocate Frame

```c
uint32_t untyped = 0, frame = 1, tcb = 2, vspace = 3;
moonlight_retype(untyped, CAP_FRAME, 4096, frame);
moonlight_retype(untyped, CAP_TCB, 0, tcb);
moonlight_retype(untyped, CAP_VSPACE, 0, vspace);
// map frame
handle_invoke(vspace_cap, INV_VSPACE_MAP, vaddr, paddr, perms);
tcb_configure(tcb_cap, cspace, vspace_root, 1, 0);
tcb_set_regs(tcb_cap, 0x100000, 0x800000, pcc, csp);
moonlight_cnode_copy(...);
```

See `tests/host_emul.c` for complete emulation.

## 7. Error Handling

All syscalls return `kerror_t` (`ERR_OK=0`, `ERR_INVALID_CAP`, `ERR_NO_RIGHTS`, `ERR_WCET_EXCEEDED` etc. `kernel/include/types.h:16`). Check `frame->a0` after `ecall`.

## 8. Debugging

- QEMU window: `tools/run_qemu.sh --nographic` vs `DISPLAY=:0 tools/run_qemu.sh` (GTK)
- GDB: `tools/run_qemu.sh --gdb` then `riscv64-unknown-elf-gdb kernel/build/moonlight.elf -ex 'target remote :1234'`
- UART at `0x10000000` - kernel prints `[BOOT]`, `[TRAP]`, `[PAGING]`, `[CHERI]`, `[FLUSH]`
