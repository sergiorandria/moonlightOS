# MoonlightOS — Production-Grade Microkernel + Qubes-Style Isolation Plan

Goal: turn the current MoonlightOS microkernel (RISC-V + CHERI, userspace
servers/drivers, Isabelle proofs) into a production-grade system that isolates
workloads the way Qubes OS does — security by compartmentalization — but built
on a capability microkernel instead of Xen/Linux, so the TCB stays small and
mechanically checked.

Status: PLAN (no code). Each stage ends with exit criteria: demo + tests +
proof deltas. Nothing here is claimed as built; existing assets are marked
`[HAVE]` with their tree paths, everything else is `[TODO]`.

## 0. What "like Qubes" means here (and what it doesn't)

Qubes OS in one paragraph: the machine runs a set of mutually distrustful
domains ("qubes"). There is no general-purpose OS with ambient authority;
`dom0`/AdminVM only administers, never runs user workloads or networking.
Each qube gets the devices, network paths, and data it needs and nothing else.
A typed RPC layer (`qrexec`) with an explicit policy engine mediates every
cross-domain action (open URL in another qube, copy/paste, file transfer).
Persistence is split: read-only TemplateVM roots + per-qube private overlays;
DisposableVMs boot clean every time. GUI, audio, USB, and networking are each
isolated behind dedicated service qubes with untrusted-input parsers.

Non-goals (deliberate): running Linux guests (no binary compat layer),
paravirtualized Windows, seamless GUI windows in v1 (start with explicit
qube-tagged switching), live migration, SMP guests (hart-per-qube first).

## 1. Starting assets [HAVE]

- Microkernel: 8 syscalls, 11 cap types, TCB ~3.5k LOC (`kernel/src/`,
  `docs/ARCHITECTURE.md`).
- Userspace servers: `mem_server`, `sched_server` (EDF), `vfs_server`
  (per-client FD tables, `FS_Verification.thy`), `sh/moonsh`.
- Drivers (capability-isolated, IOMMU windows, micro-reboot, host tests +
  freestanding rv64 `-Werror` gate in `tools/verify.sh [1b/1c]`):
  `virtio_net` (+TX/RX queues), `block` (virtio-blk), `vga` text,
  `uart`, `plic`, `timer` (CLINT), `rtc`, `power` (`userspace/drivers/`).
- Proven properties: CHERI monotonicity, cache coloring, IOMMU DMA
  confinement, EDF/partition isolation (`kernel/isabelle/`, 11/14 theorems).
- Measured boot scaffolding: `boot/dice.c` (see `PLAN.md` 1.1 — must be
  wired before it counts), reproducible build (`docs/REPRODUCIBLE.md`).
- Target: QEMU `riscv64`/`riscv64cheristd`, `-M virt`.

## 2. Threat model delta (extends `docs/THREAT_MODEL.md`)

New adversaries beyond A1–A4:

| ID | Capability | Mitigation (stage) |
|---|---|---|
| Q1 | Compromised NetVM sniffs/redirects all traffic | FirewallVM as separate qube, no NetVM→AppVM path except via firewall; net driver confined to NetVM IOMMU window (S3) |
| Q2 | Compromised USB device attacks stack (BadUSB) | USBVM owns the controller via IOMMU; only typed device-events cross to AdminVM (S3) |
| Q3 | Malicious qube escapes via hypervisor/VM boundary | H-ext two-stage translation + PMP + CHERI; escape requires breaking the capability derivation chain, covered by confinement proof (S1/S6) |
| Q4 | Cross-qube GUI spoofing (fake password prompt) | Trusted window chrome rendered by AdminVM/GUIVM from unforgeable qube labels; clients draw into bounded Frame caps only (S4) |
| Q5 | Clipboard/file-transfer exfiltration or comprimise | qrexec-equivalent policy engine: default-deny, per-pair rules, user confirmation for cross-label flows (S2) |
| Q6 | Persistent malware in a qube | Template roots read-only + verified at update; Disposables boot clean; per-qube overlay wipe on demand (S5) |
| Q7 | Evil-maid / boot tampering | DICE measured boot + sealed storage; attestation before releasing vault keys (S7) |

## 3. Qube taxonomy (target steady state)

```
vault (no net, sealed keys) ──policy──> work ──> firewall ──> net ──> wire
personal ──> firewall ──> net            usb ──policy──> AdminVM
disp1234 (disposable, overlay tmpfs)     templates (read-only roots)
AdminVM (no net, no user apps: policy + GUI chrome + updater only)
```

- `vault`: GPG/SSH keys, password store. No network cap, no clipboard-out
  without confirmation. Sealed storage bound to DICE measurement.
- `net`: owns `virtio_net` driver + NIC IOMMU window. Only peer: FirewallVM.
- `firewall`: owns filtering policy (nftables-equivalent ruleset as data,
  reviewable). Only peers: AppVMs in, NetVM out.
- `usb`: owns USB controller (needs USB HCI driver — new, S3). Exports
  per-device attach decisions, never raw URBs, to AdminVM.
- `work` / `personal`: AppVMs. Template root (ro) + private overlay (rw).
- `dispNNNN`: DisposableVMs. Overlay in RAM, destroyed on close.
- `templates`: read-only roots, updated atomically, hash-pinned.
- `AdminVM`: policy engine, GUI chrome, updater client. No user parsers.

Labeling: every qube has an immutable label (name + color + trust level)
minted at creation by AdminVM; the label travels on every IPC (like
`ipc_msg_t.sender_tcb` today) and is rendered by trusted chrome.

## 4. Mechanism map (Qubes concept → Moonlight implementation)

| Qubes mechanism | Moonlight implementation | State |
|---|---|---|
| Xen VM boundary | H-ext two-stage `satp` + per-qube VSpace + PMP + CHERI bounds per thread | [TODO] S1-deferred (VSpace+cap isolation shipped instead; see S1 BUILT note in §11) |
| dom0 | AdminVM (U-mode server, no ambient caps) | [HAVE] S2: `userspace/adminvm/v2_main.c` |
| qrexec + policy | `qrexec_server`: typed RPC over Endpoints, policy table, confirm path | [HAVE] S2: `userspace/qrexec_server/v2_main.c`; live T_CALL legs BUILT 2026-09-24 (markers `QREXEC: admin registered` + `VAULT: live ok` + `AUD: deny rpc=2`, see §11 S2 note) |
| NetVM/FirewallVM split | `net` qube (`userspace/net/v2_main.c` → `userspace/build/net.elf`, initrd 4, thread 6, qube 5) + `firewall` filter server (`userspace/firewall/fw.h` + `userspace/firewall/v2_main.c` → `userspace/build/firewall.elf`, initrd 3, thread 5, qube 4); host tests `tests/test_netfw.c` + `tests/test_qargs.c`; proofs `kernel/isabelle/Qubes_C.thy` | [HAVE] S3 (USB HCI still TODO) |
| Encrypted storage | `cryptblk` qube (blk MMIO+IRQ, sector AEAD, `/dev/blk0` ciphertext + `/` plaintext views: `userspace/cryptblk/v2_main.c` → `userspace/build/cryptblk.elf`, initrd 9, thread 9, qube 7) + `vault` qube (KEKs/VMK, per-label slot release: `userspace/vault/v2_main.c` → `userspace/build/vault.elf`, initrd 8, thread 8, qube 6); crypto `userspace/crypt/`; host tests `tests/test_aead.c` + `tests/test_crypt.c`; proofs `kernel/isabelle/Qubes_D.thy` | [HAVE] FDE (templates/overlays/disposables/updates/backup stay TODO) |
| USBVM | `usb` qube + new USB HCI driver (bulk-only first, no isochronous) | [TODO] S3 |
| GUI domain | `gui` server: per-qube Frame-capped surfaces + AdminVM chrome | [TODO] S4 |
| TemplateVM + overlays | `vfs_server` extensions: ro root caps + per-qube rw overlay, COW | [TODO] S5 |
| DisposableVMs | `mem_server` overlay-from-template + destroy-on-close | [TODO] S5 |
| Updates | atomic template swap + hash pin + rollback slot | [TODO] S5 |
| Backup | encrypted qube-export via vault-held keys | [TODO] S5 |
| AEM / boot trust | DICE (`boot/dice.c` wired) + sealed storage | [TODO] S7 |

## 5. IPC policy engine (`qrexec_server`, S2 — the load-bearing piece)

Everything cross-qube goes through typed RPC; raw IPC between qubes is
denied by default. Policy table lives in AdminVM-owned memory, entries:

```
<src-label> <dst-label> <rpc-name> <action> [confirm-text]
work        vault       keys.sign  ask      "work wants a signature"
*           *           clipboard  deny
usb         AdminVM     device.attach ask   "attach USB device?"
```

- RPC descriptors are data: name, schema (typed args, max lengths —
  adversarial-length tests from day one, cf. `V2_DESIGN.md` §4).
- Each call carries caller label (kernel-stamped, unforgeable).
- `ask` suspends the call and raises a trusted prompt in AdminVM chrome;
  the answer resumes or kills the call. No TOCTOU: args are copied at call
  time and hashed; the prompt shows the hash.
- Audit log: append-only, per-qube ring, exportable to vault.
- Unit tests: policy matrix (allow/ask/deny × label pairs), malformed
  lengths, caller-spoof attempts (must fail: label is kernel-stamped).

## 6. Device isolation rules (apply to every driver, S1–S3)

1. One driver, one qube: a driver compartment holds caps for exactly one
   device class instance (extends the current per-driver IOMMU windows).
2. DMA only inside the qube's IOMMU window (`iommu_check` on enqueue AND
   completion — already the `virtio_net`/`block` pattern; new drivers copy it).
3. IRQs terminate in the owning qube via PLIC (`plic.c` bindings); cross-qube
   signaling is Notification badges, never shared MMIO.
4. MMIO caps are exact-bounds (`cheri_bounds_set` pattern); `init` refuses
   unvalidated devices (already the `__riscv` probe rule).
5. New drivers needed: USB HCI (bulk-only), GUI framebuffer multiplexer
   (extends `vga.c` pattern: per-qube surfaces), virtio-console or GUI
   input routing for qube-tagged keyboard focus (extends `kbd.c` + `plic`).

## 7. Storage model (S5, extends `vfs_server`)

- FDE BUILT 2026-09-24 (S5-storage partial — full-disk encryption now,
  templates/overlays below still TODO): every disk byte is ciphertext
  (ChaCha20-Poly1305 per 4 KiB sector under a volume key,
  `userspace/crypt/`); per-qube keyslots (≤8, LUKS-like header) released
  by label only (`vault` qube, `T_KEY`-by-grant handoff); `cryptblk`
  serves raw ciphertext on `/dev/blk0` (label-independent) and plaintext
  under `/home/<own-label>` post-unlock. Proofs `Qubes_D.thy`
  (slot-release-only-to-label, ciphertext-view label-independence,
  no-ambient-decrypt). Honest limits: KDF-only stolen-disk gate, no
  rollback protection, test-grade DRBG, plaintext filenames, no
  re-encryption on revoke, no journaling (fail-closed `EIO`). Details +
  markers in `V2_DESIGN.md` §9 FDE entry.
- Template root: read-only Frame caps, content-hash pinned at update time.
- Private overlay: per-qube read-write, copy-on-write against the template.
- DisposableVM: overlay is RAM-only, destroyed with the qube; nothing persists.
- Update transaction: download → verify hash → stage slot B → atomic flip →
  keep slot A as rollback. A failed flip boots A and reports.
- Vault files: encrypted at rest with DICE-sealed keys; keys never leave vault.
- `FS_Verification.thy` extensions: overlay isolation (no qube reads
  another's overlay), ro-root immutability, atomic-flip correctness.

## 8. Network model (S3)

- `net` qube: only code with the NIC MMIO + DMA window. No policy
  exceptions, no direct AppVM path.
- `firewall` qube: declarative ruleset (default-deny outbound, DNS pinned,
  per-qube egress profiles). Ruleset is versioned data, diffable, auditable.
- Inter-qube networking: denied by default; explicit `netvm-link` policy
  entries create point-to-point channels via `qrexec_server`, never L2.
- Tests: leak tests (AppVM packet must egress only via firewall rules),
  firewall unit matrix, NetVM-compromise containment (attacker in NetVM
  sees ciphertext/metadata only — vault/work plaintext never traverses).

## 9. GUI isolation (S4)

- Each qube renders into its own Frame-capped surface; out-of-bounds traps.
- Trusted chrome (label, color border, focus indicator) is drawn ONLY by
  AdminVM/gui-server — clients cannot address chrome pixels (separate caps).
- Input focus is explicit: keystrokes go to the focused qube; focus switches
  only via a secure attention gesture routed through AdminVM (no qube can
  steal focus programmatically).
- Clipboard is a qrexec RPC (`clipboard.copy dst`), default-deny across
  labels, `ask` with content preview for vault-out flows.
- v1 scope: full-screen qube switching with trusted top bar (no seamless
  windows); seamless is explicitly post-1.0.

## 10. Boot, update, recovery (S7)

1. DICE measured boot first (`PLAN.md` 1.1 must close: wire `dice.c`,
   implement `sha256`, `PROVIDE(expected_hash)`, call from `kernel_boot`).
2. Sealed storage: vault keys bound to the measurement; re-measure on
   update, re-seal as part of the atomic-flip transaction (S5).
3. Recovery: slot-A rollback boots without network; AdminVM shows measured
   vs expected hashes for user verification.
4. Reproducible builds stay green (`docs/REPRODUCIBLE.md`): every release
   artifact hash-pinned, `verify.sh` asserts.

## 11. Staged roadmap (each stage: code + host tests + QEMU demo + proof delta)

- **S0 — Spec + policy model.** Isabelle: qube labels, allow/ask/deny
  semantics, confinement over labels (anti-vacuity rules from `V2_DESIGN.md`
  §6 apply). *Demo:* host simulator runs a 3-qube policy matrix.
  - BUILT 2026-09-12: `kernel/isabelle/Qubes_A.thy` (session `V2`,
    `isabelle build` clean, 0 axioms, 0 `sorry`, 35 lemmas). State =
    qube-label list + policy table (first-match-wins, default-deny) +
    bounded pending-ask queue + append-only audit; transitions
    `q_create/q_call/q_decide/q_destroy` (all total: full queues fail
    closed, bad indices no-ops). Theorems: deny-closed, default-deny,
    ask-suspends, ask-no-bypass, allow-only-by-rule, decide-approves,
    bad-index no-op, destroy-denies-inflight; uniqueness/boundedness
    preservation across all 4 transitions; mutant witnesses for all 3
    invariants; `eval` lemmas pinning the work/vault/net demo matrix
    (fetch allowed, vault→net denied, sign suspended then approved/denied).
    Gated by `verify.sh [2b/2c]` anti-vacuity checks like the other
    v2 theories.
- **S1 — H-ext isolation core.** Two-stage translation, per-qube VSpace,
  qube-create/destroy syscalls or Invoke ops, label stamping on IPC.
  *Theorem:* authority confinement over qube labels. *Demo:* two qubes,
  cross-read faults, contained.
  - BUILT 2026-09-19 (H-ext deferred, VSpace+cap isolation shipped):
    `kernel/qube.h` (labels, `V2_RIGHT_QX=0x8UL`, `V2_INV_QCREATE=14`/
    `V2_INV_QDESTROY=15`, `qube_raw_ok` gate, ask/audit ops) +
    `kernel/kboot.c` wiring (`qube_of[]`, SEND/RECV gate fail-closed
    with `QUB: xread denied`, QCREATE/QDESTROY, RECV stamp
    `(a0=nw,a1=sender,a2=qube,a3=ovf)`); NTHREADS 4→6.
    Host tests `tests/test_qlabels.c` + `tests/test_qube_policy.c`
    (`verify.sh [1f]`); smoke markers `QUB: qube0 qube1 up`,
    `QUB: xread denied`. Proofs: `Qubes_B.thy` (`raw_ok_same/cross`,
    `c_q_call_refines`, `c_q_destroy_refines`, preservation + mutants,
    C(8)-vs-spec(16) strictness pin (`mutant_b_c9_bad` +
    `mutant_b_c9_spec_ok`).
- **S2 — qrexec + AdminVM.** Policy engine, ask/confirm path, audit log,
  label chrome hooks. *Demo:* work→vault sign with prompt; denied
  clipboard exfil test.
  - BUILT 2026-09-19: `userspace/qrexec_server/v2_main.c` (boot policy
    work→vault `keys.sign` ask / `clipboard` deny, T_CALL/T_DECIDE broker
    path, `QREXEC:`/`AUD:` transcript) + `userspace/adminvm/v2_main.c`
    (HELLO-register, T_ASK prompt display, T_DECIDE verdict; auto-approve
    — no GETC in the UABI, so the Ask leg is display-only), initrd
    indexes 1–2 (`tools/mkinitrd.sh`: mem_server 0, qrexec 1, adminvm 2),
    SPAWNed at boot (`[spawn] qrexec/adminvm ELF ok`;
    `v2_user.ld` `ALIGN(4096)` fix for the second LOAD). Smoke markers
    `QREXEC: ask` / `QREXEC: allow` / `QREXEC: deny` + `AUD: 3 entries`; semantics pinned by
    `c_decide_eq` (`Qubes_B.thy`). Demo RPCs are arg-less (T_DECIDE
    forwards zeros).
  - Live T_CALL→ASK→DECIDE→DELIVER BUILT 2026-09-24 (deferred-A):
    per-thread EPs (`V2_NEP 10`, `eps[]`, RECV-own-EP rule,
    `kernel/kboot.c`; host tests `tests/test_v2ipc.c`; proofs
    `ep_separation_send` / `ep_separation_recv` + `no_cross_deliver`
    in `V2_C.thy`); broker `svc_of_qube` + as-built `rpc_svc` routing
    with collapsed-dst `QREXEC_QUBE` retired
    (`userspace/qrexec_server/v2_main.c`); grants (tid-3 FDE line
    reused + qube0→admin tid 4 slot 9); admin HELLO→EP3 / RECV EP4 /
    `NOTIFY(0,2)` / WAIT (`userspace/adminvm/v2_main.c`); thread-A
    SEND+RECV legs (`kernel/user.c`); vault rpc-switch
    (`userspace/vault/v2_main.c`); smoke markers `QREXEC: admin
    registered` + `VAULT: live ok` + `AUD: deny rpc=2` (`verify.sh
    [4/4]`). Refinements + closed holes (EP0 misdelivery, dead admin
    registration, collapsed-dst misrouting) + B/C/D remainder in
    `V2_DESIGN.md` §9 deferred-A entry.
- **S3 — Net/firewall/USB split.** `net` qube (existing driver), `firewall`
  filter server, USB HCI driver + `usb` qube. *Demo:* AppVM web fetch
  through the chain; USB attach prompt.
  - BUILT 2026-09-20 (net/firewall; USB HCI + `usb` qube stay `[TODO]`):
    `userspace/firewall/fw.h` + `userspace/firewall/v2_main.c` →
    `userspace/build/firewall.elf` (initrd 3, thread 5, qube 4) and
    `userspace/net/v2_main.c` → `userspace/build/net.elf` (initrd 4,
    thread 6, qube 5); NTHREADS 6→8 at the `V2_CAP_THREADS` cap bound.
    Host tests `tests/test_qargs.c` + `tests/test_netfw.c` (`verify.sh
    [1f]`); smoke markers `NETQ: labels ok`, `FW: allow` / `FW: deny` /
    `FW: up`, `NET: up`, `LEAK: denied`, `SPOOF: ignored`, `AUD:`,
    `NETMMIO: tid=6 only`, `NET: link up` / `NET: tx ok` / `NET: irq ok`
    (`verify.sh [4/4]`); proofs `kernel/isabelle/Qubes_C.thy` (69 lemmas:
    `packet_integrity`, `deliver_allow_pins`, `net_trust_deliver`,
    `fw_default_deny_nomatch`, `mmio_tid6_only`, `irq_of_index_valid`,
    `c_decide_args_eq`; hash reasoning over the `pkt_hash` byte-sum
    stand-in, not FNV-1a). Net reach is 8 pages tid-6-only, IRQ scanned
    1..8 (never hardcoded); S2 deferred (c) closed (`v2_qask_t`
    arg0/arg1, `T_DECIDE` re-attaches). Refinements + deferred list in
    `V2_DESIGN.md` §9 S3 entry.
- **S4 — GUI isolation.** Surfaces, trusted chrome, focus gesture,
  clipboard RPC. *Demo:* two qubes, spoofed prompt visibly untrusted.
- **FDE — encrypted storage (S5-storage partial).**
  - BUILT 2026-09-24: `userspace/crypt/` (ChaCha20-Poly1305, SHA-256,
    PBKDF2, test-grade DRBG) + `userspace/cryptblk/layout.h`/`slot.h` +
    `vault`/`cryptblk` ELFs (initrd 8–9, threads 8–9, qubes 6–7;
    NTHREADS 8→10, `V2_FRAMES_MAX` 16→32); qrexec rows
    `VAULT_UNWRAP 7`/`VAULT_REWRAP 8`/`VOL_FORMAT 9`; host tests
    `test_aead` + `test_crypt`; smoke markers `VAULT:`/`CRYPT:`/`BLKMMIO:`;
    proofs `kernel/isabelle/Qubes_D.thy` (0 sorry, 0 axioms,
    KAT-correspondence). Refinements + honest limits in `V2_DESIGN.md`
    §9 FDE entry. Templates/overlays/disposables/updates/backup below
    stay `[TODO]`.
- **S5 — Storage: templates/overlays/disposables/updates/backup.**
  *Demo:* disposable boots clean, template atomic flip + rollback.
- **S6 — Hardening + proofs replay.** Confinement/IPC-integrity/temporal
  theorems extended to qubes; CBMC in CI per `PRODUCTION.md`; fuzz the
  policy engine and all untrusted-input parsers.
- **S7 — Boot trust + release.** DICE wired, sealed vault, recovery flow,
  reproducible release artifacts, first versioned release.
- **Deferred-B/C BUILT 2026-09-25; D noted (harness-owned remainder
  still open):** (B) audit-cap `V2_AUDIT_MAX=64` overflow modeling —
  fail-closed allow via `qube_audit_room`/`qube_audit_allow`
  (`kernel/qube.h`) + the two broker allow arms
  (`userspace/qrexec_server/v2_main.c`); host test extended
  (`tests/test_qube_policy.c`, `verify.sh [1f]`); self-test marker
  `AUD: full ok` (`kernel/kboot.c`, `verify.sh [4/4]`); model
  `max_audit = 64` + `audit_full_blocks_allow` / deny-still-proceeds
  (`decide_always_dequeues`, `deny_appends_or_drops`) + preservation
  (`audit_preserved_capped`) in `kernel/isabelle/Qubes_A.thy` with
  C-mirrors (`c_full_blocks_allow`, `c_q_decide`) in `Qubes_B.thy`;
  destroy is the take-prefix rule. Non-allow-arm `qube_audit`
  returns are intentionally unchecked (best-effort by design). (C)
  qube-lifecycle aliases — `T_DEAD 3` distinct from `T_BLOCKED 2`
  (`kernel/kboot.c`), all state sites audited, the 3 SPAWN/FORK/
  QCREATE scans simplified to `state == T_DEAD` alone, gated by the
  byte-identical transcript (zero `verify.sh` change). (D)
  demo-convention brittleness — still open (minor; harness owner:
  `verify.sh`/`run_qemu.sh` hardening); the other 8 deferred minors
  are addressed (one rejected with reviewer sign-off — empty-take
  bare-`continue`, design spec §4 item 8 — the rest in code/lemmas/
  comments). Full disposition + closed holes (silent audit drop,
  alias fragility) + honest remainder in `V2_DESIGN.md` §9
  gap-closure entry. Deferred-A (live T_CALL→ASK→DECIDE→DELIVER
  traffic) BUILT 2026-09-24 — see the S2 note above; it closed EP0
  misdelivery, dead admin registration, and collapsed-dst
  misrouting.

## 12. Hardware + emulation requirements

- Primary: RISC-V with H extension + IOMMU + PMP + CHERI (or CHERI-QEMU
  `riscv64cheristd` until silicon). Base QEMU `-M virt` suffices through S2;
  S3 needs virtio-net + USB HCI devices attached in `tools/run_qemu.sh`.
- CI matrix: host unit (all current + new qube/policy tests), Isabelle
  (old + new theories), rv64 `-Werror` driver/server gates, QEMU text
  smokes per stage (assert banner + a qube interaction, cf. `verify.sh` §8
  rule: smoke asserts text, not bytes).

## 13. Open questions (decided late, deliberately)

1. H-ext vs. pure VSpace+cap isolation for qubes (hypervisor cost vs.
   proof reuse of the current VSpace model) — decide in S0, freeze after S1.
2. Whether `qrexec_server` lives in AdminVM or is its own qube (fault
   containment vs. extra IPC hops) — decide in S2.
3. GUI scope for 1.0: switching-only vs. seamless — default switching-only
   unless S4 finishes early.
4. SMP/hart-per-qube scheduling vs. time-sliced single hart — measure in
   S1, freeze in S3 (EDF partitions already exist: reuse, don't reinvent).

## 14. Definition of done (production grade)

- [ ] All S0–S7 exit criteria met with green `tools/verify.sh` + CI matrix.
- [ ] No aspirational doc claims: every `.md` claim links to a proof name,
  test name, or artifact hash (existing docs rule, extended to new docs).
- [ ] Qube-escape, policy-bypass, and DMA-exfiltration adversary tests exist
  and fail closed (Q1–Q7 each have at least one red test turned green).
- [ ] Release: versioned, reproducible, measured-boot attested, with
  rollback and recovery documented in `docs/`.
