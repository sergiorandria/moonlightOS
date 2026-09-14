# MoonlightOS Usage Guide (Production)

> **v1-era reference** (historical). This document describes the removed
> v1 M-mode kernel's usage model. The v2 kernel runs in S-mode under
> OpenSBI with a smaller UABI; see `docs/V2_DESIGN.md` and `kernel/kboot.c`.

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

## 9. Keyboard and console

`run_qemu.sh` attaches `-device virtio-keyboard-device` whenever a display
is used (gtk/sdl/vnc); `--nographic` attaches neither display nor keyboard.
`kernel/src/kbd.c` negotiates the virtio-input device (MMIO transports at
`0x10001000+i*0x1000`, legacy v1 or modern v2: `GuestPageSize` is programmed
before `QueuePFN`) and merges its event queue with UART RX into one 256-byte
ring. EV_KEY codes translate with shift/caps/ctrl tracking; arrows arrive as
the same `ESC [ A..D` sequences a serial terminal sends.

Routing (`kernel/include/console.h`): with VGA + virtio-keyboard both up,
boot enables the **split** before entering moonsh - the shell prints only to
the framebuffer and reads only the window keyboard, while the launch terminal
keeps the boot log and stays usable for the QEMU monitor. Without either
device (`--nographic`) the console stays **mirrored** and the shell lives on
serial as before. `console` prints the current mode.

The framebuffer console (`kernel/src/vga.c`) keeps a shadow text buffer with
real scroll-up, an inverted-block cursor, and a true blanking `clear` (the
`clear` builtin calls the `moonsh_console_clear` hook; raw ANSI never reaches
the framebuffer). Interrupts are still polled (`kbd_poll` drains ≤32 events +
≤32 UART bytes per call); PLIC/`irq_bind` is the next step.

## 10. moonsh commands

`help [cmd]`, `echo [-n]`, `hex|hd <text>`, `clear|cls`, `history` (`!!`, `!n`,
8 entries, Up/Down recall, Left/Right/Home/End, Ctrl-U/Ctrl-D), `yield`,
`sleep <ticks>`, `uptime|ticks`, `ver|version|uname`, `kbd`, `ps` (live TCB
table + next pick), `mem` (pool/colors/PT pages), `kill [-STOP|-CONT] <tid>`
(destroy = SIGKILL-like teardown, or suspend/resume), `nice <tid> <prio>`
(retarget 0-255, 0 highest; budgets rotate via `sched_consume`),
`poweroff|reboot` (SiFive test-finisher at
`0x100000`), `console` (serial/VGA routing). Kernel-backed
extras (`kbd` status line, `poweroff`) are weak
hooks (`moonsh_kbd_status`, `moonsh_system_reset`): the `userspace` moonsh.elf
build runs without them and prints the fallback text instead.

## 11. Scheduler dispatch, ps, mem

Dispatch resumes via trap-frame snapshots (`kernel/src/sched.c`): every
`SYS_YIELD` snapshots the caller into its slot (thread `saved`/`has_frame`,
shell `shell_saved`) and installs the pick (`sched_pick_next`, priorities +
budgets + partitions) into the live frame, then `mret` — every trap
completes, so trap frames can never overlap suspended C frames (the old
mid-trap `context_switch` suspension tripped canaries via stale `mscratch`).
The shell is installed every 8th cooperative pick so it stays interactive;
the timer never installs the shell slot (it may hold mid-line input).
Per-TCB snapshots live in `tcb.saved`; fresh threads synthesize an initial
frame (`pc`/`sp` from the TCB, `thread_exit` parks INACTIVE on return).
`trap.S` passes the hart's current TCB (`g_current_tcb`, `TCB_NONE` for the
shell, which runs outside the table); the yield path bypasses cap/budget
gates (yield returns control, denying it would wedge the hart). Every
switch charges elapsed MMIO-mtime ticks to the outgoing context
(`sched_consume`; exhausted contexts are skipped until `sched_tick`
replenishes them), so same-priority threads rotate instead of starving.
Thread stacks are
carved from the alloc pool by `process_create` (top derived from the frame,
never caller-supplied) and the pool is identity-mapped at boot. `wfi` is
banned in dispatched threads (M-mode with no timer IRQ would sleep the hart
forever). Syscall stubs must declare the `a0` result clobber (the kernel
writes the return value there): hand-rolled `ecall` asm without an `a0`
in-out lets the compiler hoist address state across yields and fault on
resume (`userspace/lib/moonlight.c:11` `raw_ecall` is the correct pattern).
Timer preemption is live (CLINT MTIP, 100k-tick slice, ack + charge +
install in `timer_handler`); `ps` shows live states and
budgets, `mem` shows pool use, per-color counts and PT pages.

`kill <tid>` destroys via `process_destroy` (endpoint cleanup, cap revoke,
sched unbind, TCB scrub); `kill -STOP/-CONT` suspends/resumes without
teardown. `nice` retargets both the sched context and the TCB copy
(`sched_context_set_prio`, bitmap bits fixed). All three are weak hooks
(`moonsh_kill_tid`, `moonsh_nice_tid`), so the userspace build keeps honest
TODO fallbacks. A capability-mediated kill/nice (TCB/sched-context caps held
by the shell) waits on U-mode isolation; until then the M-mode shell is
trusted, like the rest of the `moonsh_*` hooks.

## 12. Filesystem (userspace VFS, kernel-grade validation)

`userspace/vfs_server/server.c` implements create/open/read/write/close/
unlink/stat/list with the same discipline as kernel code, because in M-mode
it shares the address space with clients: the kernel authenticates every
request (`ipc_msg_t.sender_tcb`, stamped by `endpoint_recv`, clamped to
`0xFFFFFFFF` when unknown and always denied), fd tables are per-client
(`fds[129][16]`, shell = slot 128), every fd resolves + rights-checks
(`READ`/`WRITE` bits, no silent downgrade), all bounds are wrap-safe
(`len` clamped into `[offset, used|size]` before pointer arithmetic, never
`offset + len`), names are validated (`[A-Za-z0-9._-]`, 1–31 chars, no
leading `-`), files are unique, unlink is owner-only and refuses open files
(no use-after-unlink), tables fail closed on exhaustion, and file data moves
only via transferred Frame caps (tag/length-checked under purecap).
`moonsh` exposes `ls`, `cat <file>`, `write <file> <text>` (creates from a
demo frame pool on first use, then overwrites from offset 0), `rm <file>`.
Security properties are proven in `kernel/isabelle/FS_Verification.thy`
(fd isolation across clients, rights confinement, bounds safety, owner-only
unlink, wf preservation — 25 facts, no axioms/sorry) and exercised in
`tests/test_vfs.c` (rights, cross-client cursors, overflow truncation,
lifecycle, exhaustion). True hardware isolation of the server waits on
U-mode; the API is unchanged by it.
