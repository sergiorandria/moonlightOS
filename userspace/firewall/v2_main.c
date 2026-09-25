/* userspace/firewall/v2_main.c - S3 firewall ELF (U-mode, phase 1).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (firewall/firewall_start.S) which sets gp and calls firewall_main.
 *
 * Role: policy gate between the AppVM client (qube 0) and the net stub
 * (qube 5). Live packets arrive ONLY as broker-approved pushes:
 *   T_DELIVER [5, rpc, slot, len] from sender_qube == 2 (qrexec)
 * with rpc == RPC_NET_SEND. The kernel stamps the sender qube, so the
 * approval provenance is unforgable; a direct T_CALL(net.send) is answered
 * INVALID, forcing clients through the qrexec ASK path.
 *
 * Authorization at this layer is approval + R-only grant + len bound: the
 * T_DELIVER carries no expected frame hash (S2 pinning covers control words
 * only), so NO frame-hash comparison happens here. Byte integrity is
 * verified net-side against the firewall-computed h in T_FWD[slot,len,h].
 * The decide runs against the approved client label 0 (T_DELIVER carries no
 * src; the broker ASK row pinned src == 0 before approval).
 *
 * Addressed-EP protocol handled here (received on EP5; all messages <= 4 words):
 *   T_DELIVER [5, 3, slot, len]  qrexec -> firewall (approved net.send)
 *   T_CALL    [1, 5, slot, len]  adminvm -> firewall (filter reload, qube 3)
 *   T_DONE    [7, slot, 0, 0]    net -> firewall (forward complete)
 *   reply     [0] = OK, [-1] = INVALID
 * Forward path: MAP slot at scratch vpn 8 -> fw_decide over the bytes ->
 *   ALLOW: GRANT the cap to the net thread's IN slot + SEND
 *     T_FWD [6, NET_IN_SLOT, len, h] -> "FW: allow"
 *   ASK:   UNMAP, reply INVALID, "FW: deny" (no prompter path from
 *     the firewall; ASK rows document intent, resolve as deny)
 *   DENY:  UNMAP, reply INVALID, "FW: deny"
 * Single-flight is emergent: one RECV is processed per loop iteration;
 * no state is held across iterations (the scratch vpn is always UNMAPped
 * before continuing), so a second arrival simply processes next.
 *
 * Ruleset v0 (boot): {0, UDP, 53, ALLOW}, {0, TCP, 443, ASK},
 * {ANY, ANY, ANY, DENY}. Reload swaps the table only on
 * fw_reload_validate >= 0, else "FW: reload kept". All policy state is
 * stack-local (no globals cross qubes); string literals are private
 * rodata (U-mapped).
 */
#include <stdint.h>

#include "fw.h"
#include "../../kernel/qube.h"

#define V2_PUTC 1
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4

#define T_CALL 1
#define T_DELIVER 5
#define T_FWD 6
#define T_DONE 7

#define R_OK 0L
#define R_INVALID (-1L)

#define RPC_NET_SEND 3
#define RPC_FILTER_RELOAD 5

#define QREXEC_QUBE 2
#define ADMIN_QUBE 3
#define NET_QUBE 5

/* Boot wiring (kernel/kboot.c Step 5): firewall runs as tid 5, net as
 * tid 6. Cap ops address tids, so the GRANT names the net thread id. */
#define NET_TID 6

#define FW_IN_SLOT 8
#define FW_SCRATCH_MAP_VPN 8
#define NET_IN_SLOT 8

/* Frame-window base (kernel/ipc.h V2_U_FRAME_BASE): vpn N maps VA
 * base + N*4096. Scratch vpn 8 -> 0x80808000 (ELF image occupies the low
 * vpns only; verified < 8 pages at build). */
#define FW_U_FRAME_BASE 0x80800000UL
#define FW_SCRATCH_VA (FW_U_FRAME_BASE + (FW_SCRATCH_MAP_VPN * 4096UL))

/* Reload blob bound: 1 count byte + FW_MAX_RULES * 8B entries = 129 max;
 * 256 is a generous page-local bound for the pre-validate length check. */
#define FW_RELOAD_MAXLEN 256UL

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

void firewall_main(void)
{
    /* Boot ruleset v0: DNS out, HTTPS to Ask, everything else DENY.
     * Sized FW_MAX_RULES so a validated reload can swap in place. */
    fw_rule_t rules[FW_MAX_RULES];
    unsigned long nrules = 3;

    rules[0] = (fw_rule_t){.src_qube = 0,
                           .proto = (unsigned long)FW_PROTO_UDP,
                           .dport = 53,
                           .verdict = FW_ALLOW};
    rules[1] = (fw_rule_t){.src_qube = 0,
                           .proto = (unsigned long)FW_PROTO_TCP,
                           .dport = 443,
                           .verdict = FW_ASK};
    rules[2] = (fw_rule_t){.src_qube = FW_ANY_QUBE,
                           .proto = (unsigned long)FW_ANY_PROTO,
                           .dport = (unsigned long)FW_ANY_PORT,
                           .verdict = FW_DENY};

    u_puts("FW: up\n");

    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        unsigned long tag;
        long n = u_recv(5, buf, 4, &snd, &sqb, &ovf);

        if (n < 1) {
            u_reply(snd, R_INVALID);
            continue;
        }
        tag = (unsigned long)buf[0];

        if (tag == (unsigned long)T_DONE) {
            /* Net completion: net is never waiting (its SEND completed
             * at our RECV), so no reply is sent. Closes the audit trail. */
            if (sqb == (unsigned long)NET_QUBE)
                u_puts("FW: done\n");
            continue;
        }

        if (tag == (unsigned long)T_CALL) {
            /* Direct calls never carry approval: INVALID forces the ASK
             * path through qrexec. Sole exception: FILTER_RELOAD sent
             * directly by the AdminVM qube (kernel-stamped). */
            if (n >= 4 &&
                (unsigned long)buf[1] == (unsigned long)RPC_FILTER_RELOAD) {
                unsigned long slot = (unsigned long)buf[2];
                unsigned long len = (unsigned long)buf[3];
                const uint8_t *bp;
                fw_rule_t tmp[FW_MAX_RULES];
                unsigned long j;
                int rc;
                if (sqb != (unsigned long)ADMIN_QUBE) {
                    u_puts("FW: reload kept\n");
                    u_reply(snd, R_INVALID);
                    continue;
                }
                if (slot != (unsigned long)FW_IN_SLOT || len < 1 ||
                    len > (unsigned long)FW_RELOAD_MAXLEN ||
                    u_invoke(V2_INV_MAP, (long)slot,
                             (long)FW_SCRATCH_MAP_VPN, 0) != 0) {
                    u_puts("FW: reload kept\n");
                    u_reply(snd, R_INVALID);
                    continue;
                }
                bp = (const uint8_t *)FW_SCRATCH_VA;
                rc = fw_reload_validate(bp, len, tmp,
                                        (unsigned long)FW_MAX_RULES);
                u_invoke(V2_INV_UNMAP, (long)FW_SCRATCH_MAP_VPN, 0, 0);
                if (rc < 0) {
                    u_puts("FW: reload kept\n");
                    u_reply(snd, R_INVALID);
                    continue;
                }
                for (j = 0; j < (unsigned long)rc; j++) {
                    /* bound: FW_MAX_RULES (validate caps count) */
                    if (j >= (unsigned long)FW_MAX_RULES)
                        break;
                    rules[j] = tmp[j];
                }
                nrules = (unsigned long)rc;
                u_puts("FW: reload ok\n");
                u_reply(snd, R_OK);
                continue;
            }
            u_reply(snd, R_INVALID);
            continue;
        }

        if (tag == (unsigned long)T_DELIVER && n >= 4 &&
            (unsigned long)buf[1] == (unsigned long)RPC_FILTER_RELOAD) {
            /* Broker-forwarded reload: approval is not provenance.
             * Only a direct AdminVM T_CALL carries sqb == 3. */
            u_puts("FW: reload kept\n");
            continue;
        }

        if (tag != (unsigned long)T_DELIVER || n < 4 ||
            (unsigned long)buf[1] != (unsigned long)RPC_NET_SEND)
            continue; /* not ours: silent drop, no reply (no waiter) */
        if (sqb != (unsigned long)QREXEC_QUBE)
            continue; /* approval provenance is the kernel stamp */

        {
            unsigned long slot = (unsigned long)buf[2];
            unsigned long len = (unsigned long)buf[3];
            const uint8_t *pkt;
            uint64_t h;
            int dec;
            /* Single-flight slot + len bound before touching memory.
             * The hash loop and fw_decide both need len <= FW_PKT_MAX. */
            if (slot != (unsigned long)FW_IN_SLOT ||
                len > (unsigned long)FW_PKT_MAX ||
                u_invoke(V2_INV_MAP, (long)slot,
                         (long)FW_SCRATCH_MAP_VPN, 0) != 0) {
                u_reply(snd, R_INVALID);
                continue;
            }
            pkt = (const uint8_t *)FW_SCRATCH_VA;
            /* Computed for the net side (T_FWD[3]); never compared here:
             * no expected value exists on this path. */
            h = qube_fnv1a(pkt, len);
            dec = fw_decide(rules, nrules, 0UL, pkt, len);
            if (dec == FW_ALLOW) {
                uint64_t fwd[4];
                long grc;
                grc = u_invoke(V2_INV_GRANT, (long)slot, (long)NET_TID,
                               (long)NET_IN_SLOT);
                if (grc == 0) {
                    fwd[0] = (uint64_t)T_FWD;
                    fwd[1] = (uint64_t)NET_IN_SLOT;
                    fwd[2] = (uint64_t)len;
                    fwd[3] = h;
                    /* Handoff: blocks until net RECVs (backpressure). */
                    if (u_send(6, fwd, 4) == 0) {
                        u_puts("FW: allow\n");
                        u_invoke(V2_INV_UNMAP,
                                 (long)FW_SCRATCH_MAP_VPN, 0, 0);
                        continue;
                    }
                }
                /* Forwarding failed: fail closed, no allow marker. */
                u_invoke(V2_INV_UNMAP, (long)FW_SCRATCH_MAP_VPN, 0, 0);
                u_reply(snd, R_INVALID);
                continue;
            }
            if (dec == FW_ASK) {
                /* no prompter path from firewall; ASK rows document intent, resolve as deny */
                u_invoke(V2_INV_UNMAP, (long)FW_SCRATCH_MAP_VPN, 0, 0);
                u_reply(snd, R_INVALID);
                u_puts("FW: deny\n");
                continue;
            }
            u_invoke(V2_INV_UNMAP, (long)FW_SCRATCH_MAP_VPN, 0, 0);
            u_reply(snd, R_INVALID);
            u_puts("FW: deny\n");
        }
    }
}
