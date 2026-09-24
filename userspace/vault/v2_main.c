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
 * EP0 protocol handled here (all messages <= V2_MSG_MAX = 4 words):
 *   T_CALL    [1, rpc, arg0, arg1]  any -> vault (ALWAYS INVALID, see below)
 *   T_DELIVER [5, 7, slot, recslot] qrexec -> vault (approved unwrap)
 *   T_DELIVER [5, 8, slot, kekslot] qrexec -> vault (approved rewrap)
 *   T_DELIVER [5, 9, ...]           qrexec -> vault (vol.format: IGNORED here;
 *                                   Task 4 cryptblk consumes it and writes
 *                                   the header; vault only supplies the fresh
 *                                   VMK through the T_KEY handoff)
 *   T_KEY     [8, slot, 0, 0]       vault -> cryptblk (keyless notice)
 *   T_KEY_ACK [10, slot, 0, 0]      cryptblk -> vault (handoff ack)
 *   reply     [0] = OK, [-1] = INVALID
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

        /* VOL_FORMAT (rpc 9) and any other rpc: not ours in this task.
         * Task 4 cryptblk consumes format delivers and writes the header;
         * silent drop, no reply (no waiter on deliver paths). */
    }
}
