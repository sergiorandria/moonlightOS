/* userspace/vault/v2_main.c - FDE vault ELF (U-mode, Task 3).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (vault/vault_start.S) which sets gp and calls vault_main.
 *
 * Role: holds KEKs + the VMK in memory only; unwraps slots, never touches
 * disk frames. Boot state is a zeroed KEK table (8 slots: label+key, none
 * valid) and an empty VMK slot (invalid until format/unlock, Task 4+).
 *
 * Addressed-EP protocol handled here (received on EP8; all messages <= V2_MSG_MAX = 4 words):
 *   T_CALL    [1, rpc, arg0, arg1]  any -> vault (ALWAYS INVALID, see below)
 *   T_DELIVER [5, 7, slot, recslot] qrexec -> vault (approved unwrap)
 *   T_DELIVER [5, 8, slot, kekslot] qrexec -> vault (approved rewrap)
 *   T_DELIVER [5, 9, ...]           qrexec -> vault (vol.format: IGNORED here;
 *                                   Task 4 cryptblk consumes it and writes
 *                                   the header; vault only supplies the fresh
 *                                   VMK through the T_KEY handoff)
 *   T_KEY     [8, slot, 0, 0]       vault -> cryptblk (keyless notice)
 *   T_KEY_ACK [10, slot, 0, 0]      cryptblk -> vault (handoff ack)
 *   RANDOM_REQ [11, nonce, 0, 0]    cryptblk -> vault (entropy reseed)
 *   reply     [0] = OK, [-1] = INVALID
 *
 * RANDOM arm (Task 3): cryptblk-qube7-only (sqb != 7 -> [-1] DENY,
 * GUI qube0-only precedent); the 32B device sample is mixed with
 * rdtime + service-delta via rng_mix_ok and reseeds the DRBG. Short
 * reads and timeouts also DENY, fail-closed.
 *
 * DENY-direct discipline (same as the S3 firewall, userspace/firewall/
 * v2_main.c: direct T_CALLs never carry approval, so every T_CALL gets
 * INVALID, forcing clients through the qrexec ASK path). A deliver is
 * honored only from the kernel-stamped sender_qube == QREXEC_QUBE (2):
 * approval provenance is the stamp, never client bytes. The original
 * requester is pinned by the qrexec row, not by the deliver (T_DELIVER
 * carries no src, same as the firewall's net.send path): rpc 7 rows pin
 * src == 0, rpc 8/9 rows pin src == 3.
 *
 * T_KEY handoff (pinned Task 3, reviewer checks): the 256-bit VMK never
 * travels in SEND words (4-word messages cannot hold it, and two-message
 * splits double rendezvous races). Instead vault PT_ALLOCs a frame, WRITEs
 * the 4 words via 4x V2_INV_WRITE, MINTs an R-only copy, GRANTs it to the
 * cryptblk tid, then SENDs the keyless [T_KEY, slot, 0, 0] notice.
 * Cryptblk MAPs + READs the 4 words (kputs-free path, Task 6 grep-gate),
 * SENDs [T_KEY_ACK, slot, 0, 0]; vault then zero-wipes the frame, UNMAPs
 * and REVOKEs it. Audit records the release event only, never key bytes.
 * The handoff helper below is print-free by construction (Task 6 greps
 * for puts inside it); the caller prints the release audit line after.
 *
 * Rewrap: the new KEK arrives identically via a granted frame (vault MAPs
 * the sender-named slot and READs 4 words), never via SEND words. The
 * rewrapped record's header writeback is Task 4 (cryptblk owns the disk);
 * the in-memory KEK table rotates immediately.
 *
 * Single-DRBG-owner rule (kdf.h): this TU defines CRYPT_DRBG_DEFINE and
 * is the only owner of the DRBG state in this ELF (vault_start.S is asm).
 * Fresh drbg_next bytes salt every rewrap (test-grade DRBG, disclosed in
 * the stage spec; TEST_KEYS seeding is Task 4).
 *
 * All key-bearing locals and one-shot buffers are crypt_wipe'd on every
 * exit path (handlers funnel to a single exit to keep the wipe sites
 * few). All loops carry bounds. State is stack-local; string literals
 * are private rodata (U-mapped).
 */
#define CRYPT_DRBG_DEFINE
#include <stdint.h>

#include "../../kernel/qube.h"
#include "../crypt/kdf.h"
#include "../cryptblk/slot.h"
#include "rng_mix.h"
#include "rng_scan.h"

#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_MINT 1
#define V2_INV_PT_ALLOC 6
#define V2_INV_WRITE 12
#define V2_INV_READ 13

#define V2_RIGHT_R 0x1UL

#define T_CALL 1
#define T_DELIVER 5
#define T_KEY 8
#define T_KEY_ACK 10

#define R_INVALID (-1L)

/* FDE RPC ids (qrexec namespace; T_KEY/T_KEY_ACK live in the tag space). */
#define VAULT_UNWRAP 7
#define VAULT_REWRAP 8
#define VOL_FORMAT 9

/* keys.sign live-traffic probe (qrexec S2 ASK row, rpc 1): NOT an
 * unwrap — prints the end-to-end marker only. */
#define KEYSSIGN_LIVE 1UL

#define QREXEC_QUBE 2
#define VAULT_QUBE 6
#define CRYPT_QUBE 7

/* Boot wiring (kernel/kboot.c Task 3): vault runs as tid 8, cryptblk as
 * tid 9. Cap ops address tids, so the GRANT names the cryptblk thread. */
#define VAULT_TID 8
#define CRYPT_TID 9

/* Scratch vpn for MAP/WRITE/READ windows (fw/net precedent: ELF image
 * occupies the low vpns only; the image stays < 8 pages by build). */
#define VAULT_SCRATCH_VPN 8

/* Vault cap-table temps: PT_ALLOC returns the first free slot; the R-only
 * copy is minted via a bounded ladder over high slots the ELF image never
 * reaches (image low slots + runtime allocs grow from 0). */
#define VAULT_MINT_LO 24UL
#define VAULT_MINT_HI 32UL

/* Task-4 contract: cryptblk keeps this cap-table slot free so the vault's
 * key-frame GRANT always has an empty dst (grant needs an empty dst). */
#define CRYPT_KEY_SLOT 20L

/* Ack-wait bound (Task 4 ratification): ~2s @10MHz timebase + an iteration
 * backstop (the time bound fires first while traffic flows). Each loop
 * pass blocks in RECV until some message arrives, then re-checks the
 * deadline: the bound fires on any wakeup after expiry, never while the
 * ack is still plausibly in flight. */
#define VAULT_ACK_TIMEOUT_TICKS 20000000UL
#define VAULT_ACK_POLL_BOUND 2000000

/* ---- Task-3 RNG bind + mixer + RANDOM service ----
 * Transport: virtio-rng on an MMIO transport, scanned through the tid-8
 * U-leaf (Task 2, kernel/kboot.c l1_t[8][5] = UVA 0x80A00000; QEMU
 * attaches backends last-first, so the device is found by scan, never
 * assumed at transport 0). Scan + negotiate shape is copied from the net
 * driver (userspace/net/v2_main.c net_find/net_phase2); the rng device
 * has no BAR/LFB, so the bind is magic + device-ID only.
 *
 * DIVERGENCE from rng_scan.h (ledger b): rng_scan.h names the PA window
 * (VIRTIO_MMIO_BASE 0x10000000, stride 0x2000), but U-mode cannot
 * address PA. The readable base below is ALWAYS the mapped RNG UVA
 * window (RNG_UVA + t*0x1000, one 4K page per transport, same layout as
 * the net tid-6 U-leaf). rng_trans_off(t) is still consulted as the
 * Task-1 bound/sentinel (t < 8, 0xFFFFFFFF = no transport), but its PA
 * is never dereferenced.
 *
 * Magic (ledger a): rng_scan.h defines no VIRTIO_MAGIC_VAL, so the
 * virtio-mmio magic ("virt") is defined inline in this TU only.
 *
 * RANDOM_REQ [11, nonce, 0, 0] arrives as its own tag (11), NOT as a
 * T_DELIVER, so its arm sits BEFORE the deliver gate below (after the
 * T_CALL DENY-direct arm). Allowlist is cryptblk qube7-only
 * (sqb != 7 -> R_DENY), mirroring the GUI qube0-only precedent
 * (userspace/gui/v2_main.c). On success the 32B device sample is mixed
 * with rdtime + service_delta via rng_mix_ok and reseeds this ELF's DRBG
 * (kdf.h single owner); the reply is [0] = OK, [-1] = DENY.
 *
 * service_delta note: the brief assumes an IRQ path, but the vault owns no
 * IRQ line (the kernel raises notify bits only for tids 6/9), so
 * rng_last_t tracks the last RANDOM service time (boot rdtime on the
 * first request); the delta is fresh rdtime per request, not IRQ jitter.
 *
 * drbg note: the brief names drbg_reseed, which does not exist in
 * kdf.h; the existing owner API drbg_seed(mixed, 32) is the reseed.
 */
#define RNG_TID 8
#define RNG_EP 8
#define RANDOM_REQ 11
#define RANDOM_RESP 12
#define R_OK 0L
#define R_DENY (-1L)

#define RNG_UVA 0x80A00000UL
#define RNG_UVA_STRIDE 0x1000UL
#define RNG_MAGIC_VAL 0x74726976u

/* virtio-mmio register offsets (mirrors net driver + virtio_mmio.h). */
#define RNG_R_MAGIC 0x000u
#define RNG_R_VERSION 0x004u
#define RNG_R_DEVICE_ID 0x008u
#define RNG_R_FEAT 0x010u
#define RNG_R_FEAT_SEL 0x014u
#define RNG_R_DRV_FEAT 0x020u
#define RNG_R_DRV_SEL 0x024u
#define RNG_R_QSEL 0x030u
#define RNG_R_QMAX 0x034u
#define RNG_R_QNUM 0x038u
#define RNG_R_QREADY 0x044u
#define RNG_R_QNOTIFY 0x050u
#define RNG_R_ISTATUS 0x060u
#define RNG_R_IACK 0x064u
#define RNG_R_STATUS 0x070u
#define RNG_R_QDESC_LO 0x080u
#define RNG_R_QDRV_LO 0x090u
#define RNG_R_QDEV_LO 0x0a0u

#define RNG_ST_ACK 1u
#define RNG_ST_DRIVER 2u
#define RNG_ST_DRIVER_OK 4u
#define RNG_ST_FEAT_OK 8u
#define RNG_ST_FAILED 128u

#define RNG_DESC_F_WRITE 2u
#define RNG_QNUM_WANT 1u

/* DMA frame vpn (net precedent: high vpns 16/17, far from the <8-page
 * ELF image) + frame-window base (kernel/ipc.h V2_U_FRAME_BASE). */
#define RNG_DMA_VPN 16
#define RNG_U_FRAME_BASE 0x80800000UL
#define RNG_DMA_VA (RNG_U_FRAME_BASE + ((unsigned long)RNG_DMA_VPN * 4096UL))

#define V2_INV_FRAME_PA 16

/* Poll bound + ~2s @10MHz deadline (net NET_POLL_BOUND precedent). */
#define RNG_POLL_BOUND 2000000
#define RNG_TIMEOUT_TICKS 20000000UL

/* Forward declarations: the RNG block above precedes the ecall helpers
 * (kept in net-driver order below); prototypes pin the linkage. */
static long u_invoke(long op, long a1, long a2, long a3);
static long u_yield(void);
static uint64_t u_rdtime(void);

struct rng_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct rng_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[1];
};

struct rng_used_elem {
    uint32_t id;
    uint32_t len;
};

struct rng_used {
    uint16_t flags;
    uint16_t idx;
    struct rng_used_elem ring[1];
};

static volatile uint32_t *rng_regs = 0;
static long rng_dma_pa = 0;
static uint16_t rng_seen = 0;
static uint64_t rng_last_t = 0;

static void rng_fence(void)
{
    asm volatile("fence iorw,iorw" ::: "memory");
}

static uint32_t rng_r(volatile uint32_t *regs, uint32_t off)
{
    return *(volatile uint32_t *)((uintptr_t)regs + off);
}

static void rng_w(volatile uint32_t *regs, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)((uintptr_t)regs + off) = v;
}

static void rng_w64(volatile uint32_t *regs, uint32_t lo_off, uint64_t v)
{
    rng_w(regs, lo_off, (uint32_t)(v & 0xffffffffu));
    rng_w(regs, lo_off + 4u, (uint32_t)(v >> 32));
    rng_fence();
}

/* Bind the virtio-rng transport (net net_find shape), negotiate the
 * modern transport, and set up queue 0 in one PT_ALLOC'd DMA frame.
 * Returns 1 live, 0 fail-closed (caller parks: no "RNG: up" without a
 * live queue). */
static int vault_rng_bind(void)
{
    unsigned long t;
    volatile uint32_t *regs = 0;
    long slot;
    long pa;
    volatile uint8_t *dma;
    unsigned long i;
    uint32_t max;
    for (t = 0u; t < 8u; t++) { /* bound: 8 (virtio transports) */
        unsigned long base = rng_trans_off(t);
        uint32_t magic;
        uint32_t dev;
        if (base == 0xFFFFFFFFUL)
            continue;
        regs = (volatile uint32_t *)(RNG_UVA + t * RNG_UVA_STRIDE);
        magic = rng_r(regs, RNG_R_MAGIC);
        if (magic != RNG_MAGIC_VAL)
            continue;
        dev = rng_r(regs, RNG_R_DEVICE_ID);
        if (!rng_dev_match(dev))
            continue;
        break;
    }
    if (t >= 8u || regs == 0)
        return 0;
    /* Modern-transport negotiate (net net_phase2 step-2 shape). */
    rng_w(regs, RNG_R_STATUS, 0u);
    rng_fence();
    rng_w(regs, RNG_R_STATUS, RNG_ST_ACK | RNG_ST_DRIVER);
    rng_fence();
    rng_w(regs, RNG_R_FEAT_SEL, 0u);
    (void)rng_r(regs, RNG_R_FEAT);
    rng_w(regs, RNG_R_DRV_SEL, 1u);
    rng_w(regs, RNG_R_DRV_FEAT, 1u);
    rng_w(regs, RNG_R_DRV_SEL, 0u);
    rng_w(regs, RNG_R_DRV_FEAT, 0u);
    rng_w(regs, RNG_R_STATUS,
           RNG_ST_ACK | RNG_ST_DRIVER | RNG_ST_FEAT_OK);
    rng_fence();
    if (!(rng_r(regs, RNG_R_STATUS) & RNG_ST_FEAT_OK)) {
        rng_w(regs, RNG_R_STATUS,
               RNG_ST_ACK | RNG_ST_DRIVER | RNG_ST_FAILED);
        return 0;
    }
    /* One DMA frame (RW only) for queue 0: desc[1] @0, avail @64,
     * used @1024, 32B data buffer @2048. */
    slot = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (slot < 0 || u_invoke(V2_INV_MAP, slot, (long)RNG_DMA_VPN, 0) != 0)
        return 0;
    pa = u_invoke(V2_INV_FRAME_PA, (long)RNG_DMA_VPN, 0, 0);
    if (pa <= 0)
        return 0;
    dma = (volatile uint8_t *)RNG_DMA_VA;
    for (i = 0; i < 4096UL; i++) /* bound: 4096 */
        dma[i] = 0;
    rng_w(regs, RNG_R_QSEL, 0u);
    max = rng_r(regs, RNG_R_QMAX);
    if (max < (uint32_t)RNG_QNUM_WANT || max > 1024u)
        return 0;
    rng_w(regs, RNG_R_QNUM, RNG_QNUM_WANT);
    rng_w64(regs, RNG_R_QDESC_LO, (uint64_t)pa + 0u);
    rng_w64(regs, RNG_R_QDRV_LO, (uint64_t)pa + 64u);
    rng_w64(regs, RNG_R_QDEV_LO, (uint64_t)pa + 1024u);
    rng_w(regs, RNG_R_QREADY, 1u);
    rng_fence();
    rng_w(regs, RNG_R_STATUS, RNG_ST_ACK | RNG_ST_DRIVER |
           RNG_ST_FEAT_OK | RNG_ST_DRIVER_OK);
    rng_fence();
    rng_regs = regs;
    rng_dma_pa = pa;
    rng_seen = 0;
    return 1;
}

/* Read 32B of device randomness through the bound queue 0 (one
 * device-writable descriptor per request; used-ring completion is polled
 * with an rdtime deadline + u_yield between polls, never a spin — the
 * kernel raises IRQ notify bits only for tids 6/9, so the vault polls).
 * Returns 1 with hw full, 0 fail-closed (short read, timeout, or no
 * bind): the caller replies R_DENY and wipes. */
static int vault_read_hw(uint8_t *hw)
{
    volatile struct rng_desc *d;
    volatile struct rng_avail *a;
    volatile struct rng_used *u;
    volatile uint8_t *buf;
    uint64_t t0;
    int p;
    int done = 0;
    unsigned long i;
    uint32_t isr;
    if (!hw || rng_regs == 0 || rng_dma_pa <= 0)
        return 0;
    d = (volatile struct rng_desc *)RNG_DMA_VA;
    a = (volatile struct rng_avail *)(RNG_DMA_VA + 64u);
    u = (volatile struct rng_used *)(RNG_DMA_VA + 1024u);
    buf = (volatile uint8_t *)(RNG_DMA_VA + 2048u);
    d[0].addr = (uint64_t)rng_dma_pa + 2048u;
    d[0].len = 32u;
    d[0].flags = (uint16_t)RNG_DESC_F_WRITE;
    d[0].next = 0u;
    rng_fence();
    a->ring[0] = rng_seen;
    rng_fence();
    a->idx = (uint16_t)(rng_seen + 1u);
    rng_fence();
    rng_w(rng_regs, RNG_R_QNOTIFY, 0u);
    rng_fence();
    t0 = u_rdtime();
    for (p = 0; p < RNG_POLL_BOUND; p++) { /* bound: RNG_POLL_BOUND */
        if (u->idx != rng_seen) {
            done = 1;
            break;
        }
        u_yield();
        if (u_rdtime() - t0 > (uint64_t)RNG_TIMEOUT_TICKS)
            break;
    }
    if (!done)
        return 0;
    if (u->ring[0].id != 0u || u->ring[0].len != 32u)
        return 0; /* short read: fail closed, no partial bytes out */
    rng_fence();
    for (i = 0u; i < 32u; i++) /* bound: 32 */
        hw[i] = buf[i];
    rng_seen = (uint16_t)(rng_seen + 1u);
    isr = rng_r(rng_regs, RNG_R_ISTATUS);
    if (isr)
        rng_w(rng_regs, RNG_R_IACK, isr);
    rng_fence();
    return 1;
}

static long u_ecall3(long sys, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
}

static long u_ecall4(long sys, long a0, long a1, long a2, long a3)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a3 asm("a3") = a3;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
}

static void u_putc(char c)
{
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}

static void u_puts(const char *s)
{
    while (*s) /* bound: NUL-terminated rodata literal */
        u_putc(*s++);
}

/* Single-digit print (slot ids are < 8): avoids a recursive helper. */
static void u_putdigit(unsigned long v)
{
    u_putc((char)('0' + (v & 0xFUL)));
}

static long u_send(unsigned long ep, const uint64_t *p, unsigned long n)
{
    return u_ecall3(V2_SEND, (long)ep, (long)p, (long)n);
}

/* RECV returns words-written in a0, kernel-stamped sender in a1,
 * sender qube in a2, truncation flag in a3 (explicit, never silent). */
static long u_recv(unsigned long ep, uint64_t *buf, unsigned long cap,
                   unsigned long *sender, unsigned long *qube,
                   unsigned long *ovf)
{
    register long r_a0 asm("a0") = (long)ep;
    register long r_a1 asm("a1") = (long)buf;
    register long r_a2 asm("a2") = (long)cap;
    register long r_a3 asm("a3") = 0;
    register long r_a7 asm("a7") = V2_RECV;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    *sender = (unsigned long)r_a1;
    *qube = (unsigned long)r_a2;
    *ovf = (unsigned long)r_a3;
    return r_a0;
}

static long u_invoke(long op, long a1, long a2, long a3)
{
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

static void u_reply(unsigned long dst, long v)
{
    uint64_t resp[1];
    resp[0] = (uint64_t)v;
    u_send(dst, resp, 1);
}

static long u_yield(void)
{
    return u_ecall3(V2_YIELD, 0, 0, 0);
}

static void u_park(void)
{
    u_ecall3(V2_PARK, 0, 0, 0);
    for (;;) /* bound: inf - parked, never rescheduled */
        u_ecall3(V2_PARK, 0, 0, 0);
}

static uint64_t u_rdtime(void)
{
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
}

/* T_KEY handoff: move the 32-byte VMK to cryptblk by GRANT, never by SEND.
 *
 * GREP-GATE BOUNDARY (Task 6): this function contains no u_puts/u_putc
 * calls. No key bytes reach any log: the notice carries (tag, slot) only,
 * the ack carries (tag, slot) only, and every failure path wipes.
 *
 * Sequence: PT_ALLOC frame -> MAP at scratch -> 4x WRITE words -> MINT
 * R-only copy -> GRANT to CRYPT_TID/CRYPT_KEY_SLOT -> SEND [T_KEY, slot]
 * (blocks until cryptblk RECVs: rendezvous backpressure, firewall
 * precedent) -> RECV [T_KEY_ACK, slot] from CRYPT_QUBE (T_CALLs seen here
 * get INVALID so direct waiters never wedge; strays drop silently),
 * tick-bounded: each wakeup re-checks an rdtime deadline (V2_YIELD between
 * passes so the acking peer is scheduled promptly); on expiry the frame
 * is zero-wiped, UNMAPped and REVOKEed, then this thread parks (never
 * wedges holding frame+grant; expiry prints NO marker — the missing
 * release audit fails the gate instead) -> zero-wipe frame -> UNMAP ->
 * REVOKE. Returns 0 ok, -1 fail-closed.
 */
static long key_release(unsigned long slot, const uint8_t *vmk32)
{
    long c0 = -1;
    long c1 = -1;
    unsigned long i;
    uint64_t zero = 0;
    uint64_t note[4];
    if (!vmk32 || slot >= 8UL)
        return -1;
    c0 = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (c0 < 0 || c0 >= 32L)
        return -1;
    if (u_invoke(V2_INV_MAP, c0, (long)VAULT_SCRATCH_VPN, 0) != 0)
        return -1;
    for (i = 0; i < 4UL; i++) { /* bound: 4 (VMK words) */
        if (u_invoke(V2_INV_WRITE, (long)VAULT_SCRATCH_VPN,
                     (long)(vmk32 + i * 8UL), 0) != 0) {
            u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
            (void)u_invoke(V2_INV_REVOKE, c0, 0, 0);
            return -1;
        }
    }
    /* Attenuate RW -> R-only: first free ladder slot wins (MINT fails
     * INVALID on occupied dst, fail-closed per try). */
    for (i = VAULT_MINT_LO; i < VAULT_MINT_HI; i++) { /* bound: 8 */
        if (u_invoke(V2_INV_MINT, c0, (long)V2_RIGHT_R, (long)i) == 0) {
            c1 = (long)i;
            break;
        }
    }
    if (c1 < 0 || u_invoke(V2_INV_GRANT, c1, (long)CRYPT_TID,
                           (long)CRYPT_KEY_SLOT) != 0) {
        u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
        (void)u_invoke(V2_INV_REVOKE, c0, 0, 0);
        return -1;
    }
    note[0] = (uint64_t)T_KEY;
    note[1] = (uint64_t)slot;
    note[2] = 0;
    note[3] = 0;
    if (u_send(9, note, 4) != 0) {
        u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
        (void)u_invoke(V2_INV_REVOKE, c0, 0, 0);
        return -1;
    }
    /* Tick-bounded ack wait (Task 4 ratification): each pass blocks in
     * RECV until some message arrives, then re-checks the deadline, so
     * the wait ends on any wakeup after expiry. V2_YIELD between passes
     * schedules the acking peer promptly (never a spin). */
    {
        uint64_t t0 = u_rdtime();
        int acked = 0;
        long p;
        for (p = 0; p < 2000000L; p++) { /* bound: VAULT_ACK_POLL_BOUND */
            uint64_t ack[4];
            unsigned long snd = 0;
            unsigned long sqb = 0;
            unsigned long ovf = 0;
            long n = u_recv(8, ack, 4, &snd, &sqb, &ovf);
            if (n >= 1 && ack[0] == (uint64_t)T_CALL) {
                u_reply(snd, R_INVALID);
            } else if (n >= 2 && ack[0] == (uint64_t)T_KEY_ACK &&
                       (unsigned long)ack[1] == slot &&
                       sqb == (unsigned long)CRYPT_QUBE) {
                acked = 1;
                break;
            }
            /* stray: silent drop, no reply (no waiter on ack/deliver paths) */
            u_yield();
            if (u_rdtime() - t0 > (uint64_t)VAULT_ACK_TIMEOUT_TICKS)
                break;
        }
        /* Cryptblk READ the words (ack is the proof): wipe the frame
         * before dropping the caps so no VMK bytes linger in a freed
         * frame. The wipe runs on the expiry path too: never wedge
         * holding frame+grant. */
        for (i = 0; i < 4UL; i++) /* bound: 4 (VMK words) */
            (void)u_invoke(V2_INV_WRITE, (long)VAULT_SCRATCH_VPN,
                           (long)&zero, 0);
        u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
        (void)u_invoke(V2_INV_REVOKE, c0, 0, 0);
        if (!acked)
            u_park(); /* expiry: NO marker; the missing audit fails the gate */
        return 0;
    }
}

typedef struct {
    uint32_t label;
    int valid;
    uint8_t key[32];
} vault_kek_t;

void vault_main(void)
{
    /* Explicit wipe loops at boot: `= {0}` on this struct array would
     * emit a memset call, which does not exist freestanding (-nostdlib). */
    vault_kek_t keks[8];
    uint8_t vmk[32];
    int vmk_valid = 0;
    unsigned long i;
    unsigned long j;
    for (i = 0; i < 8UL; i++) { /* bound: 8 (KEK slots) */
        keks[i].label = 0;
        keks[i].valid = 0;
        for (j = 0; j < 32UL; j++) /* bound: 32 (KEK bytes) */
            keks[i].key[j] = 0;
    }
    for (i = 0; i < 32UL; i++) /* bound: 32 (VMK bytes) */
        vmk[i] = 0;

    rng_last_t = u_rdtime();
    if (!vault_rng_bind())
        u_park();
    u_puts("RNG: up\n");
    u_puts("VAULT: up\n");

    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        unsigned long tag;
        long n = u_recv(8, buf, 4, &snd, &sqb, &ovf);

        if (n < 1) {
            u_reply(snd, R_INVALID);
            continue;
        }
        tag = (unsigned long)buf[0];

        if (tag == (unsigned long)T_CALL) {
            /* DENY-direct (firewall precedent, cited above): direct
             * calls never carry approval. No T_CALL form is honored. */
            u_puts("VAULT: deny\n");
            u_reply(snd, R_INVALID);
            continue;
        }

        /* RANDOM_REQ is its own tag (11), not a T_DELIVER, so it is
         * claimed here, before the deliver gate below (which would
         * silently drop it). Placed after the T_CALL arm: direct calls
         * stay DENY-direct. */
        if (n >= 2 && buf[0] == (uint64_t)RANDOM_REQ) {
            unsigned long req_qb;
            uint8_t hw[32];
            uint8_t mixed[32];
            uint64_t now;
            uint64_t service_delta;
            req_qb = sqb;
            if (req_qb != 7u) {
                u_reply(snd, R_DENY);
                continue;
            } /* cryptblk qube7-only */
            for (i = 0; i < 32UL; i++) { /* bound: 32 (RANDOM buffers) */
                hw[i] = 0;
                mixed[i] = 0;
            }
            now = u_rdtime();
            service_delta = now - rng_last_t;
            if (!vault_read_hw(hw) ||
                !rng_mix_ok(hw, 32u, now, service_delta, mixed)) {
                crypt_wipe(hw, sizeof(hw));
                crypt_wipe(mixed, sizeof(mixed));
                u_reply(snd, R_DENY);
                continue;
            }
            drbg_seed(mixed, 32u);
            rng_last_t = now;
            crypt_wipe(hw, sizeof(hw));
            crypt_wipe(mixed, sizeof(mixed));
            u_reply(snd, R_OK);
            continue;
        }

        if (tag != (unsigned long)T_DELIVER || n < 4 ||
            sqb != (unsigned long)QREXEC_QUBE)
            continue; /* not ours: silent drop, no reply (no waiter) */

        if ((unsigned long)buf[1] == (unsigned long)VAULT_UNWRAP) {
            /* Approved unwrap: broker row pins src == 0, so this deliver
             * releases only the slot naming that qube's KEK. arg0 = KEK
             * table slot, arg1 = our cap-table slot holding the
             * cryptblk-granted record frame (64B image: wrapped[48] |
             * salt[8] | iters LE32 | label LE32). Single exit: every
             * path below lands on the one audit print + one wipe set. */
            unsigned long slot = (unsigned long)buf[2];
            unsigned long recslot = (unsigned long)buf[3];
            uint8_t img[64];
            layout_slot_t rec;
            uint8_t oneshot[32];
            unsigned long got = 0;
            int done = 0;
            int iters0 = 0;
            for (i = 0; i < sizeof(img); i++) /* bound: 64 */
                img[i] = 0;
            for (i = 0; i < sizeof(oneshot); i++) /* bound: 32 */
                oneshot[i] = 0;
            if (slot < 8UL && keks[slot].valid &&
                u_invoke(V2_INV_MAP, (long)recslot,
                         (long)VAULT_SCRATCH_VPN, 0) == 0) {
                for (i = 0; i < 8UL; i++) { /* bound: 8 (record words) */
                    if (u_invoke(V2_INV_READ, (long)VAULT_SCRATCH_VPN,
                                 (long)(img + i * 8UL), 0) != 0)
                        break;
                    got++;
                }
            }
            /* UNMAP is a no-op unless the MAP above succeeded (fail-closed
             * model op); the scratch vpn never holds a live mapping here. */
            u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
            if (got == 8UL) {
                for (i = 0; i < 48UL; i++) /* bound: 48 (wrapped bytes) */
                    rec.wrapped[i] = img[i];
                for (i = 0; i < 8UL; i++) /* bound: 8 (slot salt) */
                    rec.salt[i] = img[48UL + i];
                rec.iters = layout_ld32le(img + 56);
                rec.label = layout_ld32le(img + 60);
                /* Policy check, explicit (parse-ok is not policy-ok: the
                 * layout codec accepts any u32 here; the vault refuses
                 * the zero work factor before any crypto runs). */
                if (rec.iters == 0) {
                    iters0 = 1;
                } else if (slot_unwrap(keks[slot].key, &rec, oneshot) == 0 &&
                           key_release(slot, oneshot) == 0) {
                    done = 1;
                }
                slot_wipe(&rec);
            }
            crypt_wipe(img, sizeof(img));
            crypt_wipe(oneshot, sizeof(oneshot));
            if (done) {
                /* Release audit: the event only, never key bytes. */
                u_puts("AUD: release slot=");
                u_putdigit(slot);
                u_putc('\n');
            } else if (iters0) {
                u_puts("VAULT: deny iters0\n");
            } else {
                u_puts("VAULT: deny\n");
            }
            continue;
        }

        if ((unsigned long)buf[1] == (unsigned long)VAULT_REWRAP) {
            /* Approved rewrap: broker row pins src == 3 (AdminVM), so
             * this deliver rotates only an admin-approved slot. arg0 =
             * KEK table slot, arg1 = our cap-table slot holding the
             * granted frame with the new 32B KEK (4 words, never SEND
             * words). Header writeback is Task 4 (cryptblk owns the
             * disk); the in-memory table rotates immediately. */
            unsigned long slot = (unsigned long)buf[2];
            unsigned long kekslot = (unsigned long)buf[3];
            uint8_t newkek[32];
            uint8_t salt[8];
            layout_slot_t newrec;
            unsigned long got = 0;
            int done = 0;
            for (i = 0; i < sizeof(newkek); i++) /* bound: 32 */
                newkek[i] = 0;
            for (i = 0; i < sizeof(salt); i++) /* bound: 8 */
                salt[i] = 0;
            if (slot < 8UL && keks[slot].valid && vmk_valid &&
                u_invoke(V2_INV_MAP, (long)kekslot,
                         (long)VAULT_SCRATCH_VPN, 0) == 0) {
                for (i = 0; i < 4UL; i++) { /* bound: 4 (KEK words) */
                    if (u_invoke(V2_INV_READ, (long)VAULT_SCRATCH_VPN,
                                 (long)(newkek + i * 8UL), 0) != 0)
                        break;
                    got++;
                }
            }
            u_invoke(V2_INV_UNMAP, (long)VAULT_SCRATCH_VPN, 0, 0);
            if (got == 4UL) {
                drbg_next(salt, sizeof(salt));
                if (slot_wrap(newkek, vmk, salt, keks[slot].label,
                              (uint32_t)KDF_ITERS_DEFAULT, &newrec) == 0) {
                    /* Rotation: the slot's KEK becomes the new KEK. The
                     * fresh record stages on-stack and is wiped; its
                     * header writeback rides Task 4's cryptblk path. */
                    for (i = 0; i < 32UL; i++) /* bound: 32 (KEK bytes) */
                        keks[slot].key[i] = newkek[i];
                    done = 1;
                    slot_wipe(&newrec);
                }
            }
            crypt_wipe(newkek, sizeof(newkek));
            crypt_wipe(salt, sizeof(salt));
            if (done) {
                u_puts("VAULT: rewrap ok\n");
            } else {
                u_puts("VAULT: deny\n");
            }
            continue;
        }

        if ((unsigned long)buf[1] == KEYSSIGN_LIVE) { /* keys.sign:
            * live-traffic probe (S2 row), NOT an unwrap — print the
            * end-to-end marker, no state change, no handoff (handoff
            * runs only for VAULT_UNWRAP). Boot unlock uses rpc 7, so
            * this marker is honest. */
            u_puts("VAULT: live ok\n");
            continue;
        }

        /* VOL_FORMAT (rpc 9) and any other rpc: not ours in this task.
         * Task 4 cryptblk consumes format delivers and writes the header;
         * silent drop, no reply (no waiter on deliver paths). */
    }
}
