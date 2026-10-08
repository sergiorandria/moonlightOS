# Qubes S3 Net/Firewall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Qubes net/firewall split in two shippable phases: granted-frame packet plane + firewall ruleset with a loopback net stub (Phase 1, no kernel changes), then virtio-net-device bring-up with a V2 UABI driver (Phase 2).

**Architecture:** Phase 1 moves packet bytes by capability grants (AppVM→firewall→net, zero-copy, hash-pinned) with control RPCs over qrexec; Phase 2 maps one virtio-MMIO page exact-bounds into the net qube only and delivers completion IRQs as NOTIFY badges via a new `scause=9` PLIC path.

**Tech Stack:** C (freestanding rv64imac stock clang, `-Werror`), RISC-V S-mode traps/pagetables (existing `trap.S` untouched — C handler + tables only), Isabelle/HOL (session V2), bash (verify.sh/mkinitrd.sh/run_qemu.sh), QEMU `virt` + SLIRP user-net.

**Spec:** `docs/superpowers/specs/2026-09-19-qubes-s3-net-firewall-design.md`

## Global Constraints

- Freestanding only: `-ffreestanding -nostdlib -fno-builtin -mcmodel=medany -mno-relax -Wall -Wextra -Werror`, includes from clang resource dir + in-tree headers only.
- C subset: no `float`, no function-pointer dispatch (switch on op/tag), no recursion, every loop carries a `/* bound: N */` comment tied to a named constant.
- Copy discipline: every kernel↔user pointer via `copy_from_user`/`copy_to_user` validate-then-copy; raw user-pointer dereference is a defect.
- Fail closed: validation failure returns `V2_ERR_INVALID`/`V2_ERR_OVERFLOW` with no partial state; reserved Invoke args must be zero; missing QEMU markers flip the smoke gate to FAIL.
- W^X preserved: QX never reaches PTE flags (`rights & 0x7` masking stays); no new W+X mapping.
- Bounds are `_Static_assert`ed; `NTHREADS` ends at 8 `== V2_CAP_THREADS` — any further growth forces WCET re-analysis + proof replay.
- `tools/verify.sh` is the single entry: new host tests in `[1f]`, new markers in `[4/4]`, single QEMU cmdline from Phase 2 on, no new SKIP branches.
- Proofs: zero `sorry`/`axiomatization`, no `True`-defined invariants, mutant witness per invariant, Allow+Deny outcomes pinned.

---

## File Map

| File | Responsibility |
|---|---|
| Modify `kernel/qube.h` | `v2_qask_t` gains `arg0`/`arg1` (frame + len survive ask/decide). No signature changes. |
| Create `tests/test_qargs.c` | Host test: args survive enqueue→decide→audit and destroy-drop preserves survivors' args. |
| Create `userspace/firewall/fw.h` | Pure-C firewall ruleset: match + reload-validate. Host-testable, included by the ELF. |
| Create `tests/test_netfw.c` | Host test for `fw.h` (matrix, malformed packets, reload validator). |
| Create `userspace/firewall/v2_main.c` + `firewall_start.S` | Firewall ELF (`firewall_main`): ruleset v0, grant-chain service loop. |
| Create `userspace/net/v2_main.c` + `net_start.S` | Net ELF (`net_main`): Phase-1 stub + Phase-2 driver (one file, two stages). |
| Modify `userspace/qrexec_server/v2_main.c` | 4 policy rows, new RPC ids, `T_DECIDE` forwards `arg0`/`arg1`. |
| Modify `userspace/Makefile` | `build/firewall.elf` + `build/net.elf` rules (`CFLAGS_V2`/`LDFLAGS_V2`, `-Werror`), added to `all:`. |
| Modify `tools/mkinitrd.sh` | Append `"firewall.elf" "net.elf"` after `"adminvm.elf"` (indexes 3, 4; index 0 stays `mem_server.elf`). |
| Modify `kernel/kboot.c` + `kernel/user.c` | Phase 1: `NTHREADS` 6→8, 2 stacks, spawns, labels 4/5, in-kernel demo. Phase 2: MMIO leaf, PLIC map, `scause=9` branch, `V2_INV_FRAME_PA (16)`. |
| Modify `tools/run_qemu.sh` + `tools/verify.sh` | `NET_ARGS` (`virtio-net-device` + SLIRP user-net); Phase-1 then Phase-2 smoke markers. |
| Create `kernel/isabelle/Qubes_C.thy` (+ `ROOT` line) | Packet integrity, firewall default-deny, net trust rule, arg-refinement. |
| Modify `docs/V2_DESIGN.md`, `docs/QUBES_ISOLATION_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/BUILD.md` | S3 BUILT entries with artifact links. |

**Scope note:** one plan, phased. Tasks 1–3 are Phase 1 (shippable alone: loopback demo green, zero kernel trap changes). Tasks 4–6 are Phase 2 + proofs + docs. Phase 2 builds on Phase 1 and must not start until Task 3's smoke is green.

---

### Task 1: `v2_qask_t` args + host test

**Files:**
- Modify: `kernel/qube.h:34-39`
- Create: `tests/test_qargs.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_qube_policy` line)
- Test: `tests/test_qargs.c`

**Interfaces:**
- Consumes: `qube_ask_enqueue` / `qube_decide_idx` / `qube_destroy_drop` semantics (S1/S2, unchanged).
- Produces: `v2_qask_t.arg0` (frame_id) + `arg1` (len) used by Task 3 (`T_DECIDE` forward) and Task 5 (refinement).

- [ ] **Step 1: Write the failing test `tests/test_qargs.c`**

```c
/* tests/test_qargs.c - ask args (frame+len) survive ask/decide/destroy. */
#include <stdio.h>
#include "../kernel/qube.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    v2_qpolicy_t q = {0};
    v2_qask_t a = {.src = 0, .dst = 4, .rpc = 3, .hash = 0xAB, .arg0 = 7, .arg1 = 64};
    v2_qask_t b = {.src = 1, .dst = 4, .rpc = 3, .hash = 0xCD, .arg0 = 9, .arg1 = 128};
    CHECK(qube_ask_enqueue(&q, &a) == 0);
    CHECK(qube_ask_enqueue(&q, &b) == 0);
    CHECK(q.pending[0].arg0 == 7 && q.pending[0].arg1 == 64);
    CHECK(q.pending[1].arg0 == 9 && q.pending[1].arg1 == 128);
    CHECK(qube_decide_idx(&q, 0, 1) == 0);       /* approve first */
    CHECK(q.npending == 1);
    CHECK(q.pending[0].arg0 == 9 && q.pending[0].arg1 == 128); /* survivor intact */
    CHECK(q.audit[0].allowed == 1);              /* hash-pinned approve audited */
    CHECK(qube_destroy_drop(&q, 4) == 0 && q.npending == 0);   /* drops dst==4 */
    printf("PASS: test_qargs\n");
    return 0;
}
```

- [ ] **Step 2: Run it, watch it fail (struct has no arg fields yet)**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_qargs tests/test_qargs.c 2>&1 | head -n 5`
Expected: FAIL — `no member named 'arg0'` errors.

- [ ] **Step 3: Extend the struct (minimal change, no logic touched)**

```c
typedef struct {
    unsigned long src;
    unsigned long dst;
    unsigned long rpc;
    uint64_t hash;
    unsigned long arg0; /* payload arg 0 (S3: frame_id) — carried, never interpreted */
    unsigned long arg1; /* payload arg 1 (S3: len) — carried, never interpreted */
} v2_qask_t;
```

`qube_ask_enqueue` (`q->pending[q->npending] = *ask`) and `qube_decide_idx` (struct shift-remove) carry the whole struct, so args survive with zero logic change. Designated initializers without `.arg0/.arg1` (existing `test_qube_policy.c`) default them to 0 — no test churn.

- [ ] **Step 4: Run green + regression**

Run: `clang -Wall -Wextra -Werror -o /tmp/test_qargs tests/test_qargs.c && /tmp/test_qargs`
Expected: `PASS: test_qargs`
Run: `clang -Wall -Wextra -Werror -o /tmp/test_qube_policy tests/test_qube_policy.c && /tmp/test_qube_policy`
Expected: `PASS: test_qube_policy` (no regression)

- [ ] **Step 5: Wire into `tools/verify.sh [1f]`** — after the `test_qube_policy` line insert:

```bash
clang -Wall -Wextra -Werror -o /tmp/test_qargs tests/test_qargs.c 2>&1 && /tmp/test_qargs || echo "FAIL: test_qargs"
```

- [ ] **Step 6: Commit**

```bash
git add kernel/qube.h tests/test_qargs.c tools/verify.sh
git commit -m "qubes s3: v2_qask_t carries frame+len args + host test"
```

### Task 2: `fw.h` ruleset + host tests (host-only, no boot)

**Files:**
- Create: `userspace/firewall/fw.h`
- Create: `tests/test_netfw.c`
- Modify: `tools/verify.sh` (`[1f]`, after the `test_qargs` line)
- Test: `tests/test_netfw.c`

**Interfaces:**
- Consumes: nothing from Task 1 (independent header; same `[1f]` harness pattern).
- Produces: `fw_decide` + `fw_reload_validate` + constants used by Task 3's ELF (identical names/signatures).

- [ ] **Step 1: Write `userspace/firewall/fw.h` (pure C, `stdint.h` only, no ecalls)**

```c
/* userspace/firewall/fw.h - header-only firewall ruleset (S3 Phase 1).
 * Pure C: host-testable (tests/test_netfw.c) and included by firewall/v2_main.c.
 * Header-only parse: ethertype + IPv4 proto/ports. Payload never inspected. */
#ifndef FW_H
#define FW_H

#include <stdint.h>

#define FW_MAX_RULES 16
#define FW_PKT_MAX 1514
#define FW_ETH_HDR 14
#define FW_IP_MIN 20

#define FW_PROTO_TCP 6
#define FW_PROTO_UDP 17

#define FW_ALLOW 0
#define FW_ASK 1
#define FW_DENY 2

#define FW_ANY_QUBE 0xFFFFFFFFUL
#define FW_ANY_PROTO 0xFF
#define FW_ANY_PORT 0xFFFF

typedef struct {
    unsigned long src_qube; /* FW_ANY_QUBE = wildcard */
    unsigned long proto;    /* FW_ANY_PROTO = wildcard */
    unsigned long dport;    /* FW_ANY_PORT = wildcard */
    int verdict;            /* FW_ALLOW / FW_ASK / FW_DENY */
} fw_rule_t;

/* First match wins; no match ==> FW_DENY. Malformed ==> FW_DENY. */
static inline int fw_decide(const fw_rule_t *rules, unsigned long n,
                            unsigned long src, const uint8_t *pkt, unsigned long len)
{
    unsigned long proto, dport;
    if (!rules || !pkt)
        return FW_DENY;
    if (len == 0 || len > (unsigned long)FW_PKT_MAX)
        return FW_DENY;
    if (len < (unsigned long)(FW_ETH_HDR + FW_IP_MIN))
        return FW_DENY;
    if (pkt[12] != 0x08 || pkt[13] != 0x00)
        return FW_DENY; /* IPv4 only; everything else is default-deny */
    proto = pkt[FW_ETH_HDR + 9];
    if (proto != (unsigned long)FW_PROTO_TCP && proto != (unsigned long)FW_PROTO_UDP)
        return FW_DENY;
    if (len < (unsigned long)(FW_ETH_HDR + FW_IP_MIN + 4))
        return FW_DENY; /* no room for ports */
    dport = ((unsigned long)pkt[FW_ETH_HDR + FW_IP_MIN + 2] << 8) |
            (unsigned long)pkt[FW_ETH_HDR + FW_IP_MIN + 3];
    for (unsigned long i = 0; i < n; i++) { /* bound: FW_MAX_RULES */
        const fw_rule_t *r;
        int ms, mp, md;
        if (i >= (unsigned long)FW_MAX_RULES)
            break;
        r = &rules[i];
        ms = (r->src_qube == FW_ANY_QUBE || r->src_qube == src);
        mp = (r->proto == FW_ANY_PROTO || r->proto == proto);
        md = (r->dport == FW_ANY_PORT || r->dport == dport);
        if (ms && md && mp)
            return r->verdict;
    }
    return FW_DENY;
}

/* Reload blob: byte 0 = count, then count * 8B entries
 * (src u32 LE, proto u8, dport u16 LE, verdict u8 — no pads).
 * Wire packet dports are big-endian; blob dports are little-endian
 * (fw_decide BE-decodes, fw_reload_validate LE-decodes — asymmetry is
 * pinned by test_netfw; ELFs must honor both sides).
 * Returns parsed count (0..FW_MAX_RULES) or -1 on any malformation.
 * Pure validation: the caller swaps tables only on count >= 0. */
static inline int fw_reload_validate(const uint8_t *blob, unsigned long len,
                                     fw_rule_t *out, unsigned long cap)
{
    unsigned long count, i;
    if (!blob || !out || len < 1)
        return -1;
    count = blob[0];
    if (count > (unsigned long)FW_MAX_RULES || count > cap)
        return -1;
    if (len < 1 + count * 8)
        return -1;
    for (i = 0; i < count; i++) { /* bound: FW_MAX_RULES */
        const uint8_t *e = blob + 1 + i * 8;
        unsigned long v = e[7];
        if (v != (unsigned long)FW_ALLOW && v != (unsigned long)FW_ASK &&
            v != (unsigned long)FW_DENY)
            return -1;
        out[i].src_qube = (unsigned long)e[0] | ((unsigned long)e[1] << 8) |
                          ((unsigned long)e[2] << 16) | ((unsigned long)e[3] << 24);
        out[i].proto = e[4];
        out[i].dport = (unsigned long)e[5] | ((unsigned long)e[6] << 8);
        out[i].verdict = (int)v;
    }
    return (int)count;
}

#endif /* FW_H */
```

- [ ] **Step 2: Write `tests/test_netfw.c`** covering: allow row hit (udp/53 from qube 0), ask row (tcp/443), default-deny (tcp/22 no row), wildcard rows, first-match-wins order (deny-before-allow for same key), zero-len, 1515B oversize, 30B short, non-IPv4 ethertype (0x86DD), non-TCP/UDP proto (ICMP 1), ports-truncated 36B packet, null rules/pkt, reload good blob (2 rules incl. wildcard `FF FF FF FF`), bad verdict byte, overcount (>16), truncated blob, count > cap. Each `CHECK`, final `printf("PASS: test_netfw\n")`.

- [ ] **Step 3: Run green**

Run: `gcc -Wall -Wextra -Werror -o /tmp/test_netfw tests/test_netfw.c && /tmp/test_netfw`
Expected: `PASS: test_netfw`

- [ ] **Step 4: Wire into `tools/verify.sh [1f]`** — after the `test_qargs` line insert:

```bash
gcc -Wall -Wextra -Werror -o /tmp/test_netfw tests/test_netfw.c 2>&1 && /tmp/test_netfw || echo "FAIL: test_netfw"
```

- [ ] **Step 5: Commit**

```bash
git add userspace/firewall/fw.h tests/test_netfw.c tools/verify.sh
git commit -m "qubes s3: firewall ruleset header + host tests"
```

### Task 3: Phase-1 ELFs + boot + demo + smoke (shippable S3 milestone)

**Files:**
- Create: `userspace/firewall/v2_main.c`, `userspace/firewall/firewall_start.S`
- Create: `userspace/net/v2_main.c`, `userspace/net/net_start.S`
- Modify: `userspace/qrexec_server/v2_main.c` (rows + RPC ids + T_DECIDE args)
- Modify: `userspace/Makefile`, `tools/mkinitrd.sh`
- Modify: `kernel/kboot.c` (NTHREADS 6→8, stacks wiring, spawns, labels, demo), `kernel/user.c` (2 stacks + tops + init)
- Modify: `tools/verify.sh` (`[4/4]`, 6 Phase-1 markers)
- Test: `make -C userspace`, `tools/mkinitrd.sh`, `make -C kernel`, QEMU smoke

**Interfaces:**
- Consumes: Task 1 (`arg0`/`arg1`), Task 2 (`fw.h` API), S1/S2 (`V2_INV_PT_ALLOC/GRANT/MAP`, RECV stamp, `T_CALL/T_DECIDE/T_ASK/T_DELIVER`, `qube_decide_idx`, `qube_fnv1a`).
- Produces: boot transcript + markers consumed by Task 6 docs; `NETQ:` label assertion; net TID 6 + firewall TID 5 consumed by Task 4 (MMIO leaf, IRQ badge target).

New constants (define once in each ELF that needs them; qrexec owns the RPC registry):
`RPC_NET_SEND 3`, `RPC_NET_FWD 4`, `RPC_FILTER_RELOAD 5`, `RPC_NET_DONE 6`, `T_FWD 6` (message tag; distinct from `T_DELIVER 5`), `T_DONE 7` (net→firewall completion tag), `FW_QUBE 4`, `NET_QUBE 5`, `NET_IRQ_BIT 0x1`, `FW_IN_SLOT 8` (firewall-table cap slot AppVMs grant into), `FW_SCRATCH_MAP_VPN 8`, `NET_IN_SLOT 8` (net-table cap slot firewall grants into), `NET_SCRATCH_MAP_VPN 8`, single-flight pipeline (one packet at a time; second arrival gets `V2_ERR_OVERFLOW` reply, never queued).

- [ ] **Step 1: qrexec rows + arg-forwarding** — in `userspace/qrexec_server/v2_main.c`: extend boot table to 4 rules (`nrules = 4`, `AUD: boot nrules=4`):
  existing `keys.sign ASK`, `clipboard DENY`, plus `{0, QREXEC_QUBE, RPC_NET_SEND, ASK}`, `{3, QREXEC_QUBE, RPC_FILTER_RELOAD, ASK}`.
  Rows are addressed to the broker because it collapses dst (`qube_decide(&pol, sqb, QREXEC_QUBE, rpc)` always — S2-established); there is deliberately NO `net.fwd` row (firewall forwards directly via QX grant + net `sender_qube` check) and NO catch-all (default-deny already covers unmatched rpcs).
  In the `T_DECIDE` approve path, build `fwd = {T_DELIVER, rpc, arg0, arg1}` from `pol.pending[idx].arg0/arg1` (replacing the current zeros) after the existing hash re-check. Deny path unchanged.

- [ ] **Step 2: Firewall ELF** — `userspace/firewall/v2_main.c` (`void firewall_main(void)`): include `fw.h`; boot ruleset v0 array (3 entries: `{0, UDP, 53, ALLOW}`, `{0, TCP, 443, ASK}`, `{ANY, ANY, ANY, DENY}`); print `FW: up`; service loop on EP0 with two accepted inputs, everything else replied DENY/ignored per tag:
  - `T_DELIVER` with `rpc==RPC_NET_SEND` AND `sender_qube==2` (true qrexec label, kernel-stamped — the approved path): take `(slot=buf[2], len=buf[3])`, require `slot==FW_IN_SLOT`, `MAP` it at `FW_SCRATCH_MAP_VPN` (model rejection ==> drop, no state change), `fw_decide` over the bytes via direct loads. ALLOW: `h=qube_fnv1a(bytes,len)`, `GRANT` R-only cap to `(net_tid, NET_IN_SLOT)`, `SEND T_FWD[6, NET_IN_SLOT, len, h]` direct to net (QX firewall→net minted at boot — see Step 5), `UNMAP` scratch, audit-note allow, print `FW: allow`. DENY (ruleset or malformed): `UNMAP`, audit-note deny, print `FW: deny`, no reply (one-way path — S2 `T_DECIDE` convention).
  - Direct `T_CALL(net.send, ...)` (any sender): reply INVALID. This forces the ASK path through qrexec; processing direct calls would bypass the ask the boot table mandates. Document with a one-line comment.
  - `FILTER_RELOAD` with `sender_qube==3` (AdminVM) only: `fw_reload_validate` → swap tables on `>=0` else `FW: reload kept`. Other senders: reply INVALID.
  - Frame-byte hash note: there is deliberately NO hash comparison at firewall — `T_DELIVER` carries no expected hash (control-word pinning lives in qrexec's ask/decide, S2 mechanism). Authorization here is approval + R-only grant + len bound; byte integrity is verified net-side (§Step 3) where the expected hash IS present. Trust root for grant provenance: only qube 0 holds QX→firewall in this boot (multi-AppVM provenance tracking is future work — state in a comment).
  `firewall_start.S`: byte-clone of `qrexec_start.S` with `call firewall_main`. While in `userspace/firewall/`, fix the `fw.h` comment to "8B, no pads" (carried Task-2 minor).

- [ ] **Step 3: Net stub ELF** — `userspace/net/v2_main.c` (`void net_main(void)`): print `NET: up`; loop: RECV → if `buf[0]==T_FWD`: require `sender_qube == FW_QUBE` (boot constant 4) else print `SPOOF: ignored` and continue (no reply — silent drop); require `buf[1]==NET_IN_SLOT` and `buf[2]<=1514` else drop silently; `MAP` slot at `NET_SCRATCH_MAP_VPN` (rejection ==> drop, grant-without-announcement race or stale slot); recompute `h'=qube_fnv1a` over `len` bytes via direct loads, compare to `buf[3]` — mismatch: `UNMAP`, silent drop (spoof-class: no oracle); match: print `NET: fwd ok`, `UNMAP`, `SEND [T_DONE, slot, 0, 0]` to firewall (QX net→firewall minted at boot — see Step 5; firewall audit-notes completion, closing ask→allow→forward→done). Other tags: ignore (no reply). `net_start.S`: clone calling `net_main`. (Phase-2 TX/link logic appends in Task 4 before this loop; the loop stays as the packet path.)

- [ ] **Step 4: Build + pack** — `userspace/Makefile`: add `build/firewall.elf` + `build/net.elf` rules (exact clone of the `build/qrexec.elf` rule with their sources) and extend `all:`; `tools/mkinitrd.sh`: append `"firewall.elf"` `"net.elf"` to `ELFS` after `"adminvm.elf"` (indexes 3, 4; index 0 unchanged).
  Run: `make -C userspace && tools/mkinitrd.sh`
  Expected: `build/firewall.elf` + `build/net.elf` listed; mkinitrd reports `mem_server.elf` first with `qrexec`/`adminvm`/`firewall`/`net` after.

- [ ] **Step 5: Kernel boot (NTHREADS 8, stacks, spawns, labels)** — `kernel/kboot.c`: `NTHREADS` 6→8 (comment updated; `_Static_assert` holds 8<=8); SPAWN initrd 3→tid 5 and initrd 4→tid 6 (mirror the qrexec/adminvm spawn blocks, `[spawn] firewall ELF ok` / `[spawn] net ELF ok`, FAIL→parked);   `qube_of[5]=4; qube_of[6]=5; qube_next=6;` + assert print `NETQ: labels ok` (fail closed: mismatch prints `[demo] FAIL` instead); mint QX grants qube0→firewall, firewall→net, and net→firewall at boot (via `v2_grant` on the boot tables, mirroring the S1/S2 boot-grant code that granted QX toward qrexec/AdminVM — document all three beside the asserts). `kernel/user.c`: `ustack_fw[4096]` + `ustack_net[4096]` (+ tops + `user_stacks_init` lines, mirror `ustack_adminvm`).
  Run: `make -C kernel`
  Expected: clean `-Werror` build.

- [ ] **Step 6: In-kernel Phase-1 demo + smoke gate** — straight-line, bounded, no IPC (mirror the S2 demo block after the label asserts): allow leg (alloc frame as tid 5? No — demo drives the model: `frame_alloc_slot` as a scratch tid, `v2_grant` R to tid 5, `fw`-equivalent header bytes + `qube_fnv1a`, grant to tid 6, hash verify → `FW: allow`); deny leg (TCP/22 header → model deny → `FW: deny`); leak leg (`qube_raw_ok(...,0 /*no QX*/)` AppVM→net → 0 → `LEAK: denied`); spoof leg (announcement with `sender_qube != 4` → ignored → `SPOOF: ignored`); audit leg (`AUD: 3 entries` — count the demo's Decide/Allow/Deny audits the same way Task 4 counted 3). Any unexpected result prints marker-free `[demo] FAIL`. `tools/verify.sh [4/4]`: after the `AUD:` line insert 7 lines asserting `NETQ: labels ok`, `FW: allow`, `FW: deny`, `FW: up`, `NET: up`, `LEAK: denied`, `SPOOF: ignored` (same `|| { ...; QEMU_FAIL=1; }` shape). `NET: fwd ok` is deliberately NOT gated: it prints only on live forwarded traffic, which Phase-1 does not generate — asserting it would be a phantom marker. It stays a specified live-traffic marker (Step 3) for Task 4+ to gate once live flow exists.
  Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke:|FAIL|verify done"`
  Expected: all old markers + 6 new PASS, zero FAIL.

- [ ] **Step 7: Commit**

```bash
git add userspace/firewall userspace/net userspace/qrexec_server userspace/Makefile tools/mkinitrd.sh kernel/kboot.c kernel/user.c kernel/initrd_data.c kernel/initrd.h tools/verify.sh
git commit -m "qubes s3: phase-1 packet plane + firewall/net loopback + demo"
```

### Task 4: Phase-2 NIC bring-up (kernel MMIO/IRQ + QEMU netdev + driver TX)

**Files:**
- Modify: `kernel/kboot.c` (MMIO leaf, PLIC map, `scause=9`, `V2_INV_FRAME_PA (16)`, boot prints)
- Modify: `userspace/net/v2_main.c` (link + TX + IRQ wait, appended to the stub loop)
- Modify: `tools/run_qemu.sh` (`NET_ARGS`), `tools/verify.sh` (smoke cmdline + 4 markers)
- Modify: `kernel/initrd_data.c` + `kernel/initrd.h` (regenerated by mkinitrd-equivalent rebuild — see Step 5)
- Test: `make -C kernel`, QEMU smoke with netdev

**Interfaces:**
- Consumes: Task 3 (net TID 6, `NET: up` stub loop, MMIO-free boot).
- Produces: `NET: link up` / `NET: tx ok` / `NET: irq ok` / `NETMMIO: tid=6 only` consumed by Task 6 docs.

Constants: `VIRTIO0_BASE 0x10001000UL`, `VIRTIO0_IRQ 1`, `PLIC_BASE 0x0c000000UL`, `PLIC_CLAIM_S 0x0c200004UL`, `PLIC_THRESH_S 0x0c200000UL`, `NET_UVA 0x80A00000UL` (VPN[1]=5 in tid-6 tables only), `NET_IRQ_BIT 0x1` (matches Task 3), `V2_INV_FRAME_PA 16`, `V2_FRAME_PHYS_BASE` (existing, frame→PA math).

- [ ] **Step 1: Kernel MMIO + PLIC maps** — pagetable init: add S-only RW leaves for the PLIC region (`l1_m[96]`, `l1_m[97]` covering `0x0c000000–0x0c3fffff`, flags `PTE_R|PTE_W|PTE_A|PTE_D`, no U — mirror the `l1_m[128]` UART line). UART's `l1_m[128]` megapage already covers `0x10001000` S-only, so no new kernel leaf is needed for the transport. Add a per-thread U-leaf table `l0_net[512]`-style single page: `l0_netmmio[512]` zeroed except `[0] = leaf(0x10001000, PTE_R|PTE_W|PTE_U|PTE_A|PTE_D)`; wire `l1_t[6][5] = table(l0_netmmio)` ONLY for tid 6 (guard: every other `l1_t[t][5]` stays 0 — assert at boot with a `/* bound: NTHREADS */` scan printing `NETMMIO: tid=6 only`, else `[demo] FAIL`). PLIC init at boot: priority[`VIRTIO0_IRQ`]=1, enable bit, threshold 0, enable SEI (`sie` bit 9) alongside the existing STIE setup.

- [ ] **Step 2: `scause=9` branch** — in `s_trap_handler`, after the `code == 5` timer block, add `if (code == 9)`: `claim = *(volatile uint32_t *)PLIC_CLAIM_S; if (claim == VIRTIO0_IRQ) { threads[6].notify |= NET_IRQ_BIT; if (WAIT-blocked) wake (mirror the NOTIFY wake pattern); kputs("NET: irq ok\n"); } else kputs("IRQ: unexpected\n"); *(volatile uint32_t *)PLIC_CLAIM_S = claim; return;`. No parking, no fault containment change, no new loops. Unknown sources never wake anyone.

- [ ] **Step 3: `V2_INV_FRAME_PA (16)`** — `case V2_INV_FRAME_PA:` args `(vpn, 0, 0, 0)` (nonzero reserved → INVALID): look up `caps.vm[cur]` for `vpn` (reuse `v2_vm_find`); miss → `V2_ERR_INVALID`; hit → `regs[10] = V2_FRAME_PHYS_BASE + frame*4096`. Pure address math, no state change, no copy. Host-testable logic is one line — no new host test file (covered by Task 2-style review + smoke).

- [ ] **Step 4: Net driver link + TX** — append to `userspace/net/v2_main.c` before its service loop: probe `NET_UVA` magic (`0x74726976` "virt" at offset 0x00 — read via volatile `uint32_t*`, fail closed to `NET: no link` + park if mismatch); negotiate (follow `userspace/drivers/virtio_net.c` + `virtio_mmio.h`: VERSION select, features, queue 0/1 setup — lift the queue-core functions, replacing the MMIO base with `NET_UVA` and dropping CHERI/ABI includes for V2 ecalls); `PT_ALLOC` 2 DMA frames + `MAP` + `FRAME_PA` each → program descriptors with PAs; link-status bit → `NET: link up`; send one 60B gratuitous ARP → `V2_WAIT` on `NET_IRQ_BIT` with a tick-count timeout (mirror the SBI-timer tick source: give up after ~2s of ticks → `NET: irq timeout` + park, never spin) → TX-complete → `NET: tx ok`. W^X: DMA frames RW only; MMIO page never executed (no X anywhere).

- [ ] **Step 5: QEMU netdev + rebuild + smoke** — `tools/run_qemu.sh`: add `NET_ARGS="-device virtio-net-device,netdev=n0 -netdev user,id=n0"` and splice into both exec lines + echo line. `tools/verify.sh` line 129 cmdline: append the same two flags (single cmdline — no forked configs). Rebuild (`make -C userspace && tools/mkinitrd.sh && make -C kernel`, commit regenerated `initrd_data.c`/`initrd.h` with the task). Smoke gate: after the `SPOOF:` line insert 4 lines asserting `NETMMIO: tid=6 only`, `NET: link up`, `NET: tx ok`, `NET: irq ok`.
  Run: `tools/verify.sh 2>&1 | grep -E "v2 smoke:|FAIL|verify done"`
  Expected: all Phase-1 markers + 4 new PASS, zero FAIL.

- [ ] **Step 6: Commit**

```bash
git add kernel/kboot.c userspace/net tools/run_qemu.sh tools/verify.sh kernel/initrd_data.c kernel/initrd.h
git commit -m "qubes s3: phase-2 virtio-net bring-up + tx/irq smoke"
```

### Task 5: `Qubes_C.thy` proofs

**Files:**
- Create: `kernel/isabelle/Qubes_C.thy`
- Modify: `kernel/isabelle/ROOT` (add `Qubes_C` after `Qubes_B`)
- Test: `isabelle build -D kernel/isabelle -v` + `verify.sh [2b/2c]` grep gates

**Interfaces:**
- Consumes: `Qubes_A` (`q_call/q_decide/q_destroy`, policy theorems), `Qubes_B` (label refinement, `raw_ok`, arg-carrying decide), Tasks 1–2 C semantics (`arg0/arg1` carry, `fw_decide` first-match/default-deny).
- Produces: integrity/default-deny/trust-rule theorem names consumed by Task 6 docs.

- [ ] **Step 1: Write the theory** — imports `Qubes_B`; model packets as `(bytes, len)` with `len ≤ 1514`; formalize grant-chain delivery (announce `(frame,len,hash)` + kernel-stamped labels), `fw` first-match/default-deny mirroring `fw.h` (ethertype/proto/ports guards), net accept rule (`sender_qube == firewall`); prove: (a) `packet_integrity` (delivered bytes == stored bytes when hash verifies, Allow path); (b) `fw_default_deny` (no match / malformed ==> deny); (c) `net_trust` (non-firewall announcements never acted on); (d) arg-refinement (`c_decide` with args == spec decide on `(src,dst,rpc)`, args carried verbatim — extend the `Qubes_B` equality pattern); (e) preservation of `q_unique/q_bounded/p_bounded` over the new ops. Mutant witness per invariant (duplicate qubes, 33-entry pending, forged label, oversized packet, spoofed announcement). Zero `sorry`, zero axioms, no `True` definitions; `eval` pins for allow/deny/ask-full/spoof/oversize demos; explicit C(≤8 qubes, 1-frame) ⇒ spec bounds lemma.

- [ ] **Step 2: Build**

Run: `isabelle build -D kernel/isabelle -v 2>&1 | tail -n 5`
Expected: clean build incl. `V2.Qubes_C` (or documented SKIP-handling per brief Step 2 pattern of the S1/S2 plan: if Isabelle is absent, report DONE_WITH_CONCERNS with grep evidence + CI job coverage).

- [ ] **Step 3: Anti-vacuity gates**

Run: `grep -rn "sorry\\|axiomatization\\|quick_and_dirty\\|oops" kernel/isabelle/; grep -rn "equiv> True" kernel/isabelle/*.thy; echo "gate done"`
Expected: no matches before `gate done`.

- [ ] **Step 4: Commit**

```bash
git add kernel/isabelle/Qubes_C.thy kernel/isabelle/ROOT
git commit -m "qubes s3: Qubes_C packet integrity + firewall proofs"
```

### Task 6: Docs + full verify (stage closure)

**Files:**
- Modify: `docs/V2_DESIGN.md` (§9 S3 → BUILT + refinements + S2-(c)-closed note), `docs/QUBES_ISOLATION_PLAN.md` (S3 rows `[TODO]`→`[HAVE]` with ELF paths; H-ext row stays `[TODO]`), `docs/ARCHITECTURE.md` (packet plane + MMIO/IRQ + new files), `docs/BUILD.md` (initrd order 0–4, netdev, new markers)
- Test: `tools/verify.sh` end-to-end

**Interfaces:**
- Consumes: Tasks 1–5 artifacts (test names, marker strings, lemma names, ELF paths).

- [ ] **Step 1: Update docs** — every BUILT/`[HAVE]` names its artifact (test/marker/lemma/path); refinements list: NTHREADS 6→8 at the cap bound, single-flight firewall pipeline, display-only Ask (inherited S2 discipline), deterministic link/tx/irq smoke (no external fetch), MMIO-leaf gate form (boot print), `v2_user.ld` untouched (no new LOAD-alignment issue — state explicitly if true, else the fix). Aspirational text only in roadmap sections.

- [ ] **Step 2: Full verification**

Run: `tools/verify.sh 2>&1 | tail -n 12`
Expected: host PASS (incl. `test_qargs`, `test_netfw`), gates PASS, kernel PASS, QEMU PASS with all Phase-1 + Phase-2 markers, Isabelle PASS or pre-existing SKIP only, zero FAIL.

- [ ] **Step 3: Commit**

```bash
git add docs/V2_DESIGN.md docs/QUBES_ISOLATION_PLAN.md docs/ARCHITECTURE.md docs/BUILD.md
git commit -m "qubes s3: docs mark stage built with proof/test links"
```

---

## Self-Review

- **Spec coverage:** §4.1 plane → Tasks 1–3 (args, grants, hash/length rules, lifecycle); §4.2 arg extension → Task 1 (+ Task 3 `T_DECIDE` forward); §4.3 ruleset → Tasks 2–3 (fw.h, v0, reload, leak tests); §4.4 policy rows → Task 3 Step 1; §4.5 NIC (MMIO/PLIC/IRQ/boot order/thread budget/labels) → Tasks 3–4; §5 demo legs → Task 3 Step 6; §6 error table → Tasks 2–4 (each row owned: hash/len/grant-without-announcement/exhaustion/link-down/IRQ-storm/reload-fail); §7 tests+gates → Tasks 1–5; §8 non-goals → none tasked (deliberate); §9 exit → Task 6.
- **Placeholder scan:** no TBD/TODO/later/appropriate/edge-cases/similar-to; every code step ships concrete signatures, constants (`0x10001000`, `0x0c200004`, `0x80A00000`, RPC ids 3–6, slots/vpns), commands and expected outputs. The one latitude the spec left (MMIO-leaf gate form) is pinned here to the boot-print option.
- **Type consistency:** `arg0/arg1` ULONG in `v2_qask_t`, test, and `T_DECIDE` forward; `FW_*` verdict ints match `V2_QDEC_*` positions (ALLOW 0/ASK 1/DENY 2 — same order, separate enums, never mixed); `FW_QUBE 4`/`NET_QUBE 5` match boot labels tids 5/6; `NET_IRQ_BIT 0x1` shared kboot↔net; `V2_INV_FRAME_PA 16` follows 14/15; `RPC_*` 3–6 extend 1–2 without collision; `T_FWD 6` extends tags 1–5.
