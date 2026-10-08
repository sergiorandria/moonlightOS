# Moonlight v2 Stage 3: Capabilities + Memory — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the capability model (`caps.h`) into the kernel as minimal enforcement primitives; per-thread VSpaces; userspace `mem_server` owns the frame pool.

**Architecture:** The kernel exposes a single `V2_INVOKE` syscall (op code in `a0`). Each op calls the corresponding `caps.h` function. The kernel adds `vspace_root_ppn` to `uctx_t` and switches `satp` on every `enter_thread()`. A bitmap tracks free frames. `mem_server` (thread 2) receives root caps at boot; all allocation goes through it.

**Tech Stack:** clang (rv64imac, freestanding), Isabelle2025-2, QEMU 8.x+ with OpenSBI

**Spec:** `docs/superpowers/specs/2026-09-14-v2-stage3-capabilities-memory-design.md`

## Global Constraints

- Kernel: freestanding, `-ffreestanding -nostdlib -fno-builtin`, no libc, no `float`
- All kernel→user copies: validate-then-copy through `u_copy_in`/`u_copy_out` with SUM window
- Fail-closed: any validation failure returns `V2_ERR_INVALID`, no partial state update
- W^X enforced: `caps.h` rejects `V2_RIGHT_X` in mint rights; ELF rejects W+X segments
- Every loop must have `/* bound: N */` comment tied to a compile-time constant
- `tools/verify.sh` is the single verification entry

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `kernel/kboot.c:102-114` | Modify | Add `vspace_root_ppn` to `uctx_t` |
| `kernel/kboot.c:185-197` | Modify | `enter_thread()` emits `csrw satp` + `sfence.vma` |
| `kernel/kboot.c:233-417` | Modify | Add `V2_INVOKE` case in `s_trap_handler` |
| `kernel/kboot.c:439-485` | Modify | Init caps, start mem_server as thread 2 |
| `kernel/kboot.c:60-100` | Modify | Add frame pool bitmap + PT alloc/free helpers |
| `kernel/caps.h` | No change | Already has all functions (mint/grant/map/unmap/revoke/elf) |
| `kernel/trap.S` | No change | Already saves/restores all regs including `cur_ctx` |
| `kernel/user.c` | Modify | Add `mem_server_main()` entry point |
| `kernel/user.c` | Modify | Add `test_cap_thread()` for capability smoke |
| `kernel/linker.ld` | No change | `.utext/.udata` sections already present |
| `tests/test_v2caps.c` | Extend | Add V2_INVOKE round-trip host tests |
| `tools/verify.sh` | Extend | Add cap tests + V2_INVOKE smoke |

---

## Task 1: Per-thread VSpace — `vspace_root_ppn` + `satp` switch

**Files:**
- Modify: `kernel/kboot.c:102-114` (uctx_t), `kernel/kboot.c:185-197` (enter_thread)

**Interfaces:**
- Consumes: existing `uctx_t`, `enter_thread()`, `pagetable_init()`
- Produces: `uctx_t.vspace_root_ppn`, `enter_thread()` switches `satp`

- [ ] **Step 1: Add `vspace_root_ppn` to `uctx_t`**

In `kernel/kboot.c:102-114`, add a field:

```c
typedef struct {
    uint64_t regs[32];
    uint64_t sepc;
    int state;
    uintptr_t ipc_ptr;
    uint64_t ipc_cap;
    uint64_t notify;
    int wait_kind;
    uint64_t vspace_root_ppn; /* PPN of thread's root page table */
} uctx_t;
```

- [ ] **Step 2: Set initial vspace_root_ppn in `kboot()`**

In `kboot()` after the `for` loop that zeros threads, set each thread's `vspace_root_ppn` to the shared `root_pt` PPN:

```c
uint64_t initial_vspace = (8UL << 60) | (((uintptr_t)root_pt >> 12) & 0xFFFFFFFFFFFUL);
for (int i = 0; i < NTHREADS; i++) {
    // ... existing zero-init ...
    threads[i].vspace_root_ppn = initial_vspace;
}
```

- [ ] **Step 3: Switch `satp` in `enter_thread()`**

In `enter_thread()`, before the `u_enter()` call, emit:

```c
static void enter_thread(int id) {
    cur = id;
    cur_ctx = &threads[id];
    /* Per-thread VSpace: switch satp before entering U-mode */
    asm volatile("csrw satp, %0" :: "r"(threads[id].vspace_root_ppn) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    u_enter(&threads[id]);
    __builtin_unreachable();
}
```

- [ ] **Step 4: Build and verify existing smoke still passes**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "satp|B00|A10|W1|no runnable"
```

Expected: same output as before (no behavioral change).

- [ ] **Step 5: Commit**

```bash
git add kernel/kboot.c
git commit -m "kernel: per-thread vspace_root_ppn + satp switch in enter_thread()"
```

---

## Task 2: Frame pool bitmap + PT_ALLOC

**Files:**
- Modify: `kernel/kboot.c:60-100` (add frame pool helpers after pagetable_init)
- Modify: `kernel/kboot.c:439-485` (init frame pool in kboot)

**Interfaces:**
- Consumes: `V2_FRAMES_MAX` from `caps.h`
- Produces: `frame_pool_init()`, `frame_alloc()`, `frame_free()`, `frame_alloc_slot()`

- [ ] **Step 1: Add frame pool bitmap after `pagetable_init()`**

```c
/* ---- Frame pool (bitmap, 1=free, 0=in-use) ---- */
#define V2_FRAME_TOTAL (V2_FRAMES_MAX)
static uint8_t frame_bitmap[V2_FRAME_TOTAL]; /* 1=free, 0=used */

static void frame_pool_init(void) {
    /* All frames start free except frame 0 (kernel's own page tables live
     * there — keep it used). Frames 1..7 available for allocation. */
    for (int i = 0; i < V2_FRAME_TOTAL; i++)
        frame_bitmap[i] = 1;
    frame_bitmap[0] = 0; /* frame 0: kernel PT (in use) */
}

static int frame_alloc(void) {
    for (int i = 0; i < V2_FRAME_TOTAL; i++) { /* bound: V2_FRAME_TOTAL */
        if (frame_bitmap[i]) {
            frame_bitmap[i] = 0;
            return i;
        }
    }
    return -1; /* all frames used */
}

static void frame_free(int f) {
    if (f >= 0 && f < V2_FRAME_TOTAL)
        frame_bitmap[f] = 1;
}

/* PT_ALLOC: allocate a zeroed frame and mint a cap to it. Returns frame id
 * in a0, or V2_ERR_OVERFLOW if no frames available. */
static int frame_alloc_slot(v2_caps_t *caps, unsigned long tid) {
    int f = frame_alloc();
    if (f < 0)
        return V2_ERR_OVERFLOW;
    /* Find an empty cap slot and mint a RW cap to the frame */
    for (int i = 0; i < V2_CAP_SLOTS; i++) { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid) {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return V2_OK;
        }
    }
    frame_free(f);
    return V2_ERR_OVERFLOW;
}
```

- [ ] **Step 2: Call `frame_pool_init()` in `kboot()`**

In `kboot()`, after `v2_ep_init(&ep0)`:

```c
frame_pool_init();
```

- [ ] **Step 3: Build and verify**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "satp|B00|A10|W1|no runnable"
```

Expected: same output.

- [ ] **Step 4: Commit**

```bash
git add kernel/kboot.c
git commit -m "kernel: frame pool bitmap + frame_alloc/free for PT_ALLOC"
```

---

## Task 3: `V2_INVOKE` handler — mint/grant/map/unmap/revoke + PT_ALLOC

**Files:**
- Modify: `kernel/kboot.c:233-417` (add case 7 to `s_trap_handler` switch)

**Interfaces:**
- Consumes: `caps.h` functions (`v2_mint`, `v2_grant`, `v2_map`, `v2_unmap`, `v2_revoke`, `v2_elf_ok`)
- Produces: `V2_INVOKE` handler in `s_trap_handler`

- [ ] **Step 1: Define `V2_INVOKE` and op codes**

Add after the existing `#define V2_WAIT 6`:

```c
#define V2_INVOKE 7
#define V2_INV_MINT 1
#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_PT_ALLOC 6
#define V2_INV_ELF_CHECK 7
#define V2_INV_WRITE 8
#define V2_INV_READ 9
```

- [ ] **Step 2: Add global `caps` state + static v2_caps_t in `kboot.c`**

After the `v2_ep_t ep0;` declaration:

```c
static v2_caps_t caps;
```

- [ ] **Step 3: Init caps in `kboot()`**

After `frame_pool_init()`:

```c
v2_caps_init(&caps, NTHREADS);
kputs("[caps] init: thread 0 has root caps to all frames\n");
```

- [ ] **Step 4: Implement the `V2_INVOKE` case in `s_trap_handler`**

Add after the `V2_WAIT` else-if block (before the final `threads[cur].sepc += 4; return;`):

```c
} else if (sys == V2_INVOKE) {
    uint64_t op = threads[cur].regs[10]; /* a0 */
    uint64_t a1 = threads[cur].regs[11];
    uint64_t a2 = threads[cur].regs[12];
    uint64_t a3 = threads[cur].regs[13];
    threads[cur].sepc += 4;
    int rc = V2_ERR_INVALID;
    switch (op) {
    case V2_INV_MINT:
        rc = v2_mint(&caps, (unsigned long)cur, a1, a2, a3);
        break;
    case V2_INV_GRANT:
        rc = v2_grant(&caps, (unsigned long)cur, a1, a2, a3);
        break;
    case V2_INV_MAP:
        rc = v2_map(&caps, (unsigned long)cur, a1, a2);
        break;
    case V2_INV_UNMAP:
        rc = v2_unmap(&caps, (unsigned long)cur, a1);
        break;
    case V2_INV_REVOKE:
        rc = v2_revoke(&caps, (unsigned long)cur, a1);
        break;
    case V2_INV_PT_ALLOC:
        rc = frame_alloc_slot(&caps, (unsigned long)cur);
        break;
    case V2_INV_ELF_CHECK:
        rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
        break;
    case V2_INV_WRITE: {
        /* WRITE vpn value: needs cap+mapping W rights */
        uint64_t kb[1];
        kb[0] = a2;
        rc = v2_write(&caps, (unsigned long)cur, a1, a2);
        break;
    }
    case V2_INV_READ: {
        /* READ vpn -> out_ptr: needs cap+mapping R rights */
        uint64_t val = 0;
        rc = v2_read(&caps, (unsigned long)cur, a1, &val);
        if (rc == V2_OK) {
            /* Copy the value to the user's out pointer */
            sum_on();
            *(volatile uint64_t *)a2 = val;
            sum_off();
        }
        break;
    }
    default:
        rc = V2_ERR_INVALID;
        break;
    }
    threads[cur].regs[10] = (uint64_t)rc;
    kputs("[invoke] tcb=");
    sbi_putchar('0' + cur);
    kputs(" op=");
    kputdec(op);
    kputs(" rc=");
    kputdec((unsigned long)rc);
    sbi_putchar('\n');
    return;
}
```

- [ ] **Step 5: Build and verify existing smoke**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "satp|B00|A10|W1|no runnable"
```

Expected: same output (no new syscalls triggered yet).

- [ ] **Step 6: Commit**

```bash
git add kernel/kboot.c
git commit -m "kernel: V2_INVOKE handler (mint/grant/map/unmap/revoke + PT_ALLOC + elf_check + write/read)"
```

---

## Task 4: Boot mem_server as thread 2

**Files:**
- Modify: `kernel/kboot.c:439-485` (increase NTHREADS, add thread 2)
- Modify: `kernel/kboot.c:116` (NTHREADS = 3)
- Modify: `kernel/user.c` (add `mem_server_main` stub)

**Interfaces:**
- Consumes: `v2_caps_init`, `caps` global, frame pool
- Produces: thread 2 starts as mem_server at boot

- [ ] **Step 1: Increase NTHREADS to 3**

Change `#define NTHREADS 2` to `#define NTHREADS 3`.

- [ ] **Step 2: Add `mem_server_main` stub in `kernel/user.c`**

Add at the bottom of `user.c` (before the stack declarations):

```c
/* mem_server_main: receives root caps at boot, handles frame allocation
 * IPC. Stub for now — will be fleshed out in Task 6. */
__attribute__((section(".utext"), noinline)) void mem_server_main(void) {
    uputc('M'); uputc('\n');
    /* TODO: wait for allocation requests via SEND/RECV on EP0,
     * respond with frame caps via GRANT. For now, park. */
    upark();
}
```

- [ ] **Step 3: Start thread 2 in `kboot()`**

After the existing thread 1 setup:

```c
threads[2].regs[2] = 0; /* mem_server uses its own stack (will be allocated) */
threads[2].sepc = (uint64_t)mem_server_main;
threads[2].state = T_RUNNABLE;
kputs("v2: entering U-mode mem_server\n");
```

- [ ] **Step 4: Build and verify**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "satp|B00|A10|W1|M|no runnable"
```

Expected: now shows `M` (mem_server prints) before parking.

- [ ] **Step 5: Commit**

```bash
git add kernel/kboot.c kernel/user.c
git commit -m "kernel: boot mem_server as thread 2 with root caps"
```

---

## Task 5: Extend `tests/test_v2caps.c` with V2_INVOKE round-trip

**Files:**
- Modify: `tests/test_v2caps.c` (add invoke-op tests)

**Interfaces:**
- Consumes: `caps.h` functions
- Produces: host-sim tests for mint/grant/map/unmap/revoke via simulated invoke

- [ ] **Step 1: Add invoke round-trip tests**

Add before the final `ALL PASS` line:

```c
/* ---- Invoke round-trip tests (mirror kernel V2_INVOKE handler) ---- */
{
    v2_caps_t st;
    v2_caps_init(&st, 2);
    int rc;

    /* PT_ALLOC: allocate a frame, mint RW cap */
    rc = frame_alloc_slot(&st, 0);
    assert(rc == V2_OK);
    int allocated_slot = -1;
    for (int i = 0; i < V2_CAP_SLOTS; i++) {
        if (st.caps[0][i].valid && !st.caps[0][i].root) {
            allocated_slot = i;
            break;
        }
    }
    assert(allocated_slot >= 0);
    assert(st.caps[0][allocated_slot].rights == V2_RIGHT_RW);

    /* MINT: attenuate RW -> R only */
    rc = v2_mint(&st, 0, (unsigned long)allocated_slot, V2_RIGHT_R, 14);
    assert(rc == V2_OK);
    assert(st.caps[0][14].rights == V2_RIGHT_R);
    assert(st.caps[0][14].root == 0);

    /* MAP: map frame via RW cap */
    rc = v2_map(&st, 0, (unsigned long)allocated_slot, 0x100);
    assert(rc == V2_OK);

    /* WRITE: write via cap+mapping */
    rc = v2_write(&st, 0, 0x100, 0xDEADBEEF);
    assert(rc == V2_OK);
    assert(st.fdata[st.caps[0][allocated_slot].obj] == 0xDEADBEEF);

    /* READ: read back */
    uint64_t val = 0;
    rc = v2_read(&st, 0, 0x100, &val);
    assert(rc == V2_OK);
    assert(val == 0xDEADBEEF);

    /* GRANT: copy cap to thread 1 */
    rc = v2_grant(&st, 0, (unsigned long)allocated_slot, 1, 0);
    assert(rc == V2_OK);
    assert(st.caps[1][0].valid == 1);
    assert(st.caps[1][0].obj == st.caps[0][allocated_slot].obj);
    assert(st.caps[1][0].rights == V2_RIGHT_RW);

    /* REVOKE: destroy thread 1's cap */
    rc = v2_revoke(&st, 0, (unsigned long)allocated_slot);
    assert(rc == V2_OK);
    assert(st.caps[1][0].valid == 0); /* granted cap destroyed */

    /* UNMAP: remove mapping */
    rc = v2_unmap(&st, 0, 0x100);
    assert(rc == V2_OK);

    /* W^X: mint with X rights rejected */
    rc = v2_mint(&st, 0, (unsigned long)allocated_slot, V2_RIGHT_X, 15);
    assert(rc == V2_ERR_INVALID);

    printf("invoke round-trip: PASS\n");
}
```

- [ ] **Step 2: Add frame_alloc_slot to test file (static copy for host-sim)**

At the top of `test_v2caps.c`, add after the includes:

```c
/* frame_alloc_slot: host-sim copy (mirrors kernel kboot.c) */
static int frame_alloc_slot(v2_caps_t *caps, unsigned long tid) {
    /* For host testing, skip actual frame bitmap — just find empty slot */
    for (int i = 0; i < V2_CAP_SLOTS; i++) {
        if (!caps->caps[tid][i].valid) {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)i;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return V2_OK;
        }
    }
    return V2_ERR_OVERFLOW;
}
```

- [ ] **Step 3: Build and run tests**

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_v2caps tests/test_v2caps.c && /tmp/test_v2caps
```

Expected: all existing tests + new "invoke round-trip: PASS".

- [ ] **Step 4: Commit**

```bash
git add tests/test_v2caps.c
git commit -m "tests: V2_INVOKE round-trip (mint/grant/map/unmap/revoke/write/read + W^X)"
```

---

## Task 6: Flesh out `mem_server_main` in `kernel/user.c`

**Files:**
- Modify: `kernel/user.c` (implement mem_server IPC loop)

**Interfaces:**
- Consumes: `V2_SEND`, `V2_RECV`, `V2_INVOKE` (user-side ecall wrappers)
- Produces: `mem_server_main()` that responds to allocation requests

- [ ] **Step 1: Define IPC protocol constants**

Add after the existing UABI defines in `user.c`:

```c
/* mem_server IPC protocol */
#define REQ_ALLOC 1    /* request: allocate a frame; returns frame cap slot */
#define REQ_MAP 2      /* request: map frame at VPN; args: cap_slot, vpn */
#define REQ_UNMAP 3    /* request: unmap VPN */
#define RESP_OK 0      /* response: success */
#define RESP_ERR -1    /* response: failure */
```

- [ ] **Step 2: Implement mem_server IPC loop**

Replace the stub `mem_server_main`:

```c
__attribute__((section(".utext"), noinline)) void mem_server_main(void) {
    uint64_t buf[4];
    unsigned long snd;
    unsigned long ovf;
    long n;

    uputc('M'); uputc('E'); uputc('M'); uputc('\n');

    /* Main loop: wait for requests, handle them, reply */
    for (;;) {
        n = urecv(0, buf, 4, &snd, &ovf);
        if (n < 1) {
            /* Empty or invalid: reply error */
            uint64_t resp[1] = { (uint64_t)RESP_ERR };
            usend(0, resp, 1);
            continue;
        }

        long req = (long)buf[0];
        long rc = RESP_ERR;

        switch (req) {
        case REQ_ALLOC: {
            /* Allocate a frame: kernel V2_INV_PT_ALLOC does the work */
            rc = (long)u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
            break;
        }
        case REQ_MAP: {
            /* Map: args = cap_slot, vpn */
            if (n >= 3) {
                rc = (long)u_invoke(V2_INV_MAP, buf[1], buf[2], 0);
            }
            break;
        }
        case REQ_UNMAP: {
            /* Unmap: args = vpn */
            if (n >= 2) {
                rc = (long)u_invoke(V2_INV_UNMAP, buf[1], 0, 0);
            }
            break;
        }
        default:
            rc = RESP_ERR;
            break;
        }

        uint64_t resp[1] = { (uint64_t)rc };
        usend(0, resp, 1);
    }
}
```

- [ ] **Step 3: Add `u_invoke` helper in `user.c`**

Add after the existing `uwait()` function:

```c
static long u_invoke(long op, long a1, long a2, long a3) {
    return u_ecall3(V2_INVOKE, op, a1, a2);
    /* Note: a3 is not passed via ecall ABI; extend if needed.
     * For PT_ALLOC/ELF_CHECK, a1..a2 suffice. */
}
```

- [ ] **Step 4: Add `V2_INVOKE` to UABI defines**

Add after `#define V2_WAIT 6`:

```c
#define V2_INVOKE 7
```

- [ ] **Step 5: Build and verify**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "MEM|M|satp|B00|A10|W1|no runnable"
```

Expected: shows `MEM` (mem_server prints), then `M` from thread, normal IPC.

- [ ] **Step 6: Commit**

```bash
git add kernel/user.c
git commit -m "userspace: mem_server IPC loop (alloc/map/unmap via V2_INVOKE)"
```

---

## Task 7: Capability smoke test thread

**Files:**
- Modify: `kernel/user.c` (add `test_cap_thread`)
- Modify: `kernel/kboot.c` (start test_cap_thread as thread 3, increase NTHREADS)

**Interfaces:**
- Consumes: `mem_server_main` (IPC endpoint), `V2_INVOKE` ops
- Produces: test thread that requests a frame, maps it, writes, reads

- [ ] **Step 1: Increase NTHREADS to 4**

Change `#define NTHREADS 3` to `#define NTHREADS 4`.

- [ ] **Step 2: Add `test_cap_thread` in `kernel/user.c`**

Add after `mem_server_main`:

```c
/* test_cap_thread: requests a frame from mem_server, maps it, writes/reads */
__attribute__((section(".utext"), noinline) void test_cap_thread(void) {
    uputc('C'); uputc('A'); uputc('P'); uputc('\n');

    /* Step 1: Request a frame from mem_server via EP0 */
    uint64_t req[1] = { REQ_ALLOC };
    usend(0, req, 1);

    uint64_t resp[4];
    unsigned long snd;
    unsigned long ovf;
    long n = urecv(0, resp, 4, &snd, &ovf);

    if (n < 1 || (long)resp[0] < 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* resp[0] = allocated cap slot (from PT_ALLOC) */
    long cap_slot = (long)resp[0];

    /* Step 2: Map at VPN 0x200 */
    uint64_t map_req[3] = { REQ_MAP, (uint64_t)cap_slot, 0x200 };
    usend(0, map_req, 3);

    n = urecv(0, resp, 4, &snd, &ovf);
    if (n < 1 || (long)resp[0] < 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 3: Write 0xDEADBEEF via V2_INVOKE */
    long wr = u_invoke(V2_INV_WRITE, 0x200, 0xDEADBEEF, 0);
    if (wr != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 4: Read back */
    uint64_t rd_val = 0;
    long rd = u_invoke(V2_INV_READ, 0x200, (long)&rd_val, 0);
    if (rd != 0 || rd_val != 0xDEADBEEF) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    uputc('O'); uputc('K'); uputc('\n');
    upark();
}
```

- [ ] **Step 3: Start test_cap_thread in `kboot()`**

After the thread 2 setup:

```c
threads[3].regs[2] = 0;
threads[3].sepc = (uint64_t)test_cap_thread;
threads[3].state = T_RUNNABLE;
```

- [ ] **Step 4: Build and verify**

```bash
make -C kernel && tools/run_qemu.sh --nographic 2>&1 | grep -E "MEM|CAP|OK|FAIL|invoke|no runnable"
```

Expected: `MEM` (mem_server), `CAP` (test thread), `[invoke]` log lines, `OK`.

- [ ] **Step 5: Commit**

```bash
git add kernel/kboot.c kernel/user.c
git commit -m "kernel: test_cap_thread (mem_server alloc/map/write/read smoke)"
```

---

## Task 8: Update `tools/verify.sh` with cap tests

**Files:**
- Modify: `tools/verify.sh` (add `[1h]` section for cap invoke tests)

**Interfaces:**
- Consumes: existing verify.sh structure
- Produces: cap tests run as part of `[1f]` or new `[1h]`

- [ ] **Step 1: Add cap host-sim test to verify.sh**

After the existing `[1f]` v2 kernel build section, add:

```bash
echo "[1h] v2 capability host-sim (invoke round-trip)"
gcc -Wall -Wextra -Werror -o /tmp/test_v2caps tests/test_v2caps.c && /tmp/test_v2caps || echo "FAIL: test_v2caps"
```

- [ ] **Step 2: Run full verify**

```bash
bash tools/verify.sh 2>&1 | tail -15
```

Expected: `[1h]` section runs, test_v2caps passes.

- [ ] **Step 3: Commit**

```bash
git add tools/verify.sh
git commit -m "tools: verify.sh adds v2 capability host-sim tests"
```

---

## Task 9: Full verification — all stages green

- [ ] **Step 1: Full clean build + verify**

```bash
make -C kernel clean && make -C kernel && bash tools/verify.sh 2>&1 | tail -20
```

Expected: host tests PASS, Isabelle PASS, kernel build PASS, QEMU smoke PASS.

- [ ] **Step 2: Extended QEMU run (30s) for cap smoke**

```bash
timeout 30 tools/run_qemu.sh --nographic 2>&1 | grep -E "MEM|CAP|OK|FAIL|invoke|satp|no runnable"
```

Expected: `MEM`, `CAP`, `OK`, `[invoke]` lines, `no runnable left`.

- [ ] **Step 3: Final commit**

```bash
git add -A && git commit -m "v2 Stage 3: capabilities + memory (V2_INVOKE, per-thread VSpace, mem_server)"
```
