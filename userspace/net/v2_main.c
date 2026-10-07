/* userspace/net/v2_main.c - S3 net stub ELF (U-mode, phase 1).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (net/net_start.S) which sets gp and calls net_main.
 *
 * Role: receive forwarded packets from the firewall (qube 4) and verify
 * byte integrity. Only one message is honored:
 *   T_FWD [6, slot, len, h] from sender_qube == FW_QUBE
 * with slot == NET_IN_SLOT and len <= 1514. The slot names the granted cap
 * in our own table (the firewall GRANTed it before announcing); we MAP it
 * at the scratch vpn, recompute qube_fnv1a over len bytes, and compare to
 * h. Mismatch: UNMAP + silent drop (no reply, no marker -- a corrupt or
 * raced announcement is indistinguishable from noise). Match: print
 * "NET: fwd ok", UNMAP, and SEND [T_DONE, slot, 0, 0] back to the
 * firewall, closing the audit trail. All other tags (including T_CALL,
 * T_DELIVER, stray T_DONE) are silently ignored: nothing ever waits on a
 * net reply, so no reply is ever sent.
 *
 * Phase-2 TX/link logic appends here; this loop stays as the fallback when
 * the link is down. All state is stack-local; string literals are private
 * rodata (U-mapped).
 *
 * Task 4 (RX + live markers): RX-from-wire reuses the two DMA frames --
 * queue 0 gets one 2-desc chain mirroring the TX layout (12B virtio-net
 * header @2048, 1514B packet buffer @2060). The service loop observes the
 * RX used ring every iteration (level check, not only on IRQ bits: a
 * completion that landed before the first V2_WAIT must still be seen),
 * copies the frame, and feeds net_stack_rx (Tasks 1-3 sources are
 * included single-TU below; they are libc-free). First validated UDP
 * prints "NET: rx ok" once. A Phase-1 live loopback echoes unicast-to-self
 * UDP back to its sender (ports swapped); the send resolves via ARP
 * lookup, else emits ONE request (42B padded to 60B on TX) and parks ONE
 * datagram until reply (sent) or 2s timeout (dropped) -- exactly once.
 * The loop waits with V2_WAIT, which wakes on NIC IRQ (bit 0x1) or queued
 * firewall messages (bit 0x10); the T_FWD audit block itself is unchanged.
 *
 * Socket RPC (net-sockets Task 2, spec Sec 2): tag-switched S_OPEN /
 * S_SEND / S_TRYRECV / S_CLOSE beside T_FWD on the same ep, with S_OK /
 * S_DATA / S_EMPTY / S_ERR replies via T_DONE-style rendezvous SENDs to
 * the kernel-stamped sender (QX gating is the kernel rendezvous gate, as
 * for T_FWD; unknown tags/senders drop silently). S_SEND is two phases:
 * [S_SEND, sock, ip, port] pins routing (single-flight pending), then a
 * literal [T_FWD, slot, len, h] from the same sender carries the granted
 * payload under the same MAP/verify discipline. S_TRYRECV stages
 * dequeued bytes into a PT_ALLOC'd reply frame granted to the client's
 * RSVP slot. No new threads/endpoints; all state stays stack-local.
 */
#include <stdint.h>

#include "../../kernel/qube.h"

/* Tasks 1-3 stack shared single-TU: net.elf builds from this file only
 * (userspace/Makefile build/net.elf), so include the libc-free sources
 * directly instead of linking. Parse views (eth/ip/udp/arp headers) are
 * stdint-only per the Task 4 brief's include rule; the two implementations
 * below use byte loops only, safe for the freestanding U-mode ELF. */
#include "arp_cache.c"
#include "stack.c"
/* Task 1 socket table, same single-TU pattern as the host suite
 * (tests/test_net_stack.c includes sock.c beside stack.c): owner is the
 * kernel-stamped sender tid, unforgable by clients. */
#include "sock.c"

#define V2_PUTC 1
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_YIELD 0
#define V2_PARK 2
#define V2_WAIT 6

#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_PT_ALLOC 6
#define V2_INV_FRAME_PA 16
#define T_FWD 6
#define T_DONE 7

/* Net socket RPC tags on ep 6 (spec Sec 2, above T_DONE):
 *   S_OPEN    [S_OPEN, kind, port, 0]  -> [S_OK, id, 0, 0] / [S_ERR, 0,0,0]
 *   S_SEND    [S_SEND, sock, ip, port] -> [S_OK, 0,0,0] (routing phase only)
 *     then a literal [T_FWD, slot, len, h] payload announcement from the
 *     same sender ("announced like T_FWD": same MAP/verify discipline).
 *   S_TRYRECV [S_TRYRECV, sock, 0, 0]  -> [S_DATA, len, 0, 0] (+ payload in
 *     the client-RSVP frame, NET_SDATA_SLOT) / [S_EMPTY, 0,0,0].
 *   S_CLOSE   [S_CLOSE, sock, 0, 0]    -> [S_OK, sock, 0, 0] / [S_ERR, 0,0,0]
 * QX gate: the kernel rendezvous already required sender QX cross-qube
 * (same gate as T_FWD; a denied take fails the u_recv itself). The server
 * additionally honors only these known tags with full takes (n >= 4).
 * Unknown tags, short takes, and unowned sockets are silent drops, never
 * replies: a noise sender is owed nothing, and every u_send here blocks
 * until the peer RECVs, so replying to noise could wedge the server.
 * Every honored request gets exactly one reply; the requester is always
 * RECV-waiting per the client protocol. */
#define S_OPEN 8
#define S_SEND 9
#define S_TRYRECV 10
#define S_CLOSE 11
#define S_OK 12
#define S_DATA 13
#define S_EMPTY 14
#define S_ERR 15

/* Client-side RSVP slot for S_DATA payload grants: the S_TRYRECV client
 * keeps this slot of its own table empty; net GRANTs its reply frame
 * there, announces [S_DATA, len, 0, 0], and the client MAPs/copies then
 * REVOKEs the slot for reuse (client-side lifecycle; net never revokes,
 * mirroring the T_FWD UNMAP-only discipline). A grant fails while the
 * slot is occupied -> S_ERR (client protocol violation). */
#define NET_SDATA_SLOT 10

#define FW_QUBE 4

#define NET_IN_SLOT 8
#define NET_SCRATCH_MAP_VPN 8

/* Frame-window base (kernel/ipc.h V2_U_FRAME_BASE): vpn N maps VA
 * base + N*4096. Scratch vpn 8 -> 0x80808000 (ELF image occupies the low
 * vpns only; verified < 8 pages at build). */
#define NET_U_FRAME_BASE 0x80800000UL
#define NET_SCRATCH_VA (NET_U_FRAME_BASE + (NET_SCRATCH_MAP_VPN * 4096UL))

/* Wire bound: max Ethernet frame, matches fw.h FW_PKT_MAX. */
#define NET_PKT_MAX 1514UL

/* ---- Phase-2 TX/link prologue (S3 Task 4) ----
 * Transport: virtio-net on an MMIO transport, scanned through the tid-6
 * U-leaf (8 transport pages at NET_UVA + i*0x1000; the kernel maps that
 * VPN[1]=5 table only for this thread; the pages are RW, never X).
 * QEMU attaches backends last-first, so the NIC is found by scan, never
 * assumed at transport 0. Queue core lifted from userspace/drivers/virtio_net.c
 * + virtio_mmio.h with the MMIO base replaced by NET_UVA and the
 * CHERI/ABI includes dropped for V2 ecalls. Modern (version-2) transport
 * only: a legacy version-1 transport fails closed (no 8K-contiguous DMA
 * exists behind PT_ALLOC). Both queues live inside two PT_ALLOC'd DMA
 * frames (RW only): TX frame holds desc[2]/avail/used + 12B header + 60B
 * gratuitous ARP, RX frame holds its desc/avail/used with no buffers
 * posted (phase 2 sends only; RX-from-wire is post-S3). Completion is
 * observed in the used ring with an rdtime deadline (~2s @10MHz, mirroring
 * the kernel TICK_DELTA source) + V2_YIELD between polls, never a spin;
 * then a single V2_WAIT consumes the kernel IRQ notify bit. Any failure
 * before the link parks via "NET: no link"; a completion timeout parks
 * via "NET: irq timeout". All loops bounded; DMA frames are RW, the MMIO
 * page is never executed. */
#define NET_IRQ_BIT 0x1L
#define NET_UVA 0x80A00000UL

/* virtio-mmio register offsets (mirrors virtio_mmio.h). */
#define NET_R_MAGIC 0x000u
#define NET_R_VERSION 0x004u
#define NET_R_DEVICE_ID 0x008u
#define NET_R_FEAT 0x010u
#define NET_R_FEAT_SEL 0x014u
#define NET_R_DRV_FEAT 0x020u
#define NET_R_DRV_SEL 0x024u
#define NET_R_QSEL 0x030u
#define NET_R_QMAX 0x034u
#define NET_R_QNUM 0x038u
#define NET_R_QREADY 0x044u
#define NET_R_QNOTIFY 0x050u
#define NET_R_ISTATUS 0x060u
#define NET_R_IACK 0x064u
#define NET_R_STATUS 0x070u
#define NET_R_QDESC_LO 0x080u
#define NET_R_QDESC_HI 0x084u
#define NET_R_QDRV_LO 0x090u
#define NET_R_QDRV_HI 0x094u
#define NET_R_QDEV_LO 0x0a0u
#define NET_R_QDEV_HI 0x0a4u
#define NET_R_CONFIG 0x100u

#define NET_MAGIC_VAL 0x74726976u
#define NET_DEV_NET 1u

#define NET_ST_ACK 1u
#define NET_ST_DRIVER 2u
#define NET_ST_DRIVER_OK 4u
#define NET_ST_FEAT_OK 8u
#define NET_ST_FAILED 128u

#define NET_DESC_F_NEXT 1u

#define NET_QNUM_WANT 2u /* one 2-desc chain per queue */
#define NET_TX_VPN 16
#define NET_RX_VPN 17
#define NET_TX_VA (NET_U_FRAME_BASE + ((unsigned long)NET_TX_VPN * 4096UL))
#define NET_RX_VA (NET_U_FRAME_BASE + ((unsigned long)NET_RX_VPN * 4096UL))

/* ~2s @10MHz timebase + iteration backstop (the time bound fires first). */
#define NET_IRQ_TIMEOUT_TICKS 20000000UL
#define NET_POLL_BOUND 2000000

struct net_desc
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct net_avail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[2];
};

struct net_used_elem
{
    uint32_t id;
    uint32_t len;
};

struct net_used
{
    uint16_t flags;
    uint16_t idx;
    /* Sized for NET_QNUM_WANT: the device appends completion i at
     * ring[i % 2] (precedent: drivers/virtio_net.c drain uses
     * ring[seen % ndesc]); consumers must index, never assume ring[0]. */
    struct net_used_elem ring[2];
};

/* ---- Task 4 RX/wire constants ----
 * RX chain mirrors the TX layout inside the RX DMA frame: 12B virtio-net
 * header @2048, 1514B packet buffer @2060 (2060 + 1514 = 3574 < 4096).
 * TX frames shorter than 60B (ARP builds 42B) are zero-padded to the
 * Ethernet minimum, matching the phase-2 gratuitous ARP.
 * NET_MSG_BIT is the V2_WAIT return bit for a queued ep-6 message
 * (kernel/syscall_ipc.c sys_wait/sys_send use 1UL << 4). */
#define NET_MSG_BIT 0x10L
#define NET_VIRTIO_HDR 12u
#define NET_TX_HDR_OFF 2048u
#define NET_TX_PAY_OFF 2060u
#define NET_RX_HDR_OFF 2048u
#define NET_RX_PAY_OFF 2060u
#define NET_ETH_MIN 60u
#define NET_UDP_PARK_PAY 1472u /* max UDP payload: 1514 - 14 (eth) - 20 (IP) - 8 (UDP) */

/* Device context filled once by net_phase2; owned by net_main's stack
 * frame (no .bss state -- the file's stack-local discipline holds). */
struct net_wire
{
    volatile uint32_t *regs;
    uint64_t pa_tx;
    uint64_t pa_rx;
    uint8_t *txf;
    volatile uint8_t *rxf; /* device-written: volatile loads + fence on observe */
    struct net_avail *txa;
    volatile struct net_used *txu;
    struct net_avail *rxa;
    volatile struct net_used *rxu;
};

/* Stack budget: net_main's frame lives in the 4KB ustack_net
 * (kernel/user.c, no guard page): rxcopy 1514 + park_pay 1472 + wire and
 * scalars ≈ 3.1KB, callees add < 256B worst case. Enforced at build time
 * with 640B slack; shrink locals if this ever fires. */
_Static_assert(sizeof(struct net_wire) + (unsigned long)NET_PKT_MAX +
                       (unsigned long)NET_UDP_PARK_PAY + 640u <=
                   4096u,
               "net_main frame exceeds ustack_net");

static long u_ecall3(long sys, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2) : "r"(r_a7) : "memory");
    return r_a0;
}

static long u_ecall4(long sys, long a0, long a1, long a2, long a3)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a3 asm("a3") = a3;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3) : "r"(r_a7) : "memory");
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

/* T_DONE-style rendezvous reply: blocks until the requester RECVs
 * (backpressure, same as T_DONE). Call only for honored requests whose
 * sender is RECV-waiting per the client protocol. All replies share the
 * [w0, w1, 0, 0] shape. */
static void net_rpc_reply(unsigned long dst, uint64_t w0, uint64_t w1)
{
    uint64_t rep[4];
    rep[0] = w0;
    rep[1] = w1;
    rep[2] = 0;
    rep[3] = 0;
    u_send(dst, rep, 4);
}

/* Socket id usable by this sender: in range, open, owned by the
 * kernel-stamped tid. Same-TU view of sock.c (included above). */
static int net_sock_owned(long id, unsigned long owner)
{
    if (id < 0 || id >= (long)NET_SOCK_MAX)
        return 0;
    if (!net_socks[(int)id].used)
        return 0;
    return net_socks[(int)id].owner == (unsigned)owner;
}

/* RECV returns words-written in a0, kernel-stamped sender in a1,
 * sender qube in a2, truncation flag in a3 (explicit, never silent). */
static long u_recv(unsigned long ep, uint64_t *buf, unsigned long cap, unsigned long *sender,
                   unsigned long *qube, unsigned long *ovf)
{
    register long r_a0 asm("a0") = (long)ep;
    register long r_a1 asm("a1") = (long)buf;
    register long r_a2 asm("a2") = (long)cap;
    register long r_a3 asm("a3") = 0;
    register long r_a7 asm("a7") = V2_RECV;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3) : "r"(r_a7) : "memory");
    *sender = (unsigned long)r_a1;
    *qube = (unsigned long)r_a2;
    *ovf = (unsigned long)r_a3;
    return r_a0;
}

static long u_invoke(long op, long a1, long a2, long a3)
{
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

static long u_yield(void)
{
    return u_ecall3(V2_YIELD, 0, 0, 0);
}

static long u_wait(void)
{
    return u_ecall3(V2_WAIT, 0, 0, 0);
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

static void net_fence(void)
{
    asm volatile("fence iorw,iorw" ::: "memory");
}

static uint32_t net_r(volatile uint32_t *regs, uint32_t off)
{
    return *(volatile uint32_t *)((uintptr_t)regs + off);
}

static void net_w(volatile uint32_t *regs, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)((uintptr_t)regs + off) = v;
}

static void net_w64(volatile uint32_t *regs, uint32_t lo_off, uint64_t v)
{
    net_w(regs, lo_off, (uint32_t)(v & 0xffffffffu));
    net_w(regs, lo_off + 4u, (uint32_t)(v >> 32));
    net_fence();
}

/* Set up one modern split virtqueue (caller-owned memory inside a DMA
 * frame). Returns 1 on success, 0 on any transport refusal. */
static int net_queue(volatile uint32_t *regs, uint32_t q, uint64_t desc_pa, uint64_t avail_pa,
                     uint64_t used_pa)
{
    uint32_t max;
    net_w(regs, NET_R_QSEL, q);
    max = net_r(regs, NET_R_QMAX);
    if (max < (uint32_t)NET_QNUM_WANT || max > 1024u)
        return 0;
    net_w(regs, NET_R_QNUM, NET_QNUM_WANT);
    net_w64(regs, NET_R_QDESC_LO, desc_pa);
    net_w64(regs, NET_R_QDRV_LO, avail_pa);
    net_w64(regs, NET_R_QDEV_LO, used_pa);
    net_w(regs, NET_R_QREADY, 1u);
    net_fence();
    return 1;
}

/* Fail-closed helper: the link never came up. */
static void net_no_link(void)
{
    u_puts("NET: no link\n");
    u_park();
}

/* Find the modern net transport: QEMU attaches backends last-first, so
 * scan all 8 pages (NET_UVA + i*0x1000, all inside the tid-6 U-leaf) for
 * magic + version 2 + net device id. Returns the page or 0. */
static volatile uint32_t *net_find(void)
{
    unsigned j;
    for (j = 0; j < 8; j++)
    { /* bound: 8 */
        volatile uint32_t *r = (volatile uint32_t *)(NET_UVA + (unsigned long)j * 0x1000UL);
        if (net_r(r, NET_R_MAGIC) != NET_MAGIC_VAL)
            continue;
        if (net_r(r, NET_R_VERSION) != 2u)
            continue;
        if (net_r(r, NET_R_DEVICE_ID) != NET_DEV_NET)
            continue;
        return r;
    }
    return 0;
}

/* Synchronous wire transmit of one frame via the TX queue (queue 1).
 * The caller builds the frame bytes; frames shorter than 60B (ARP's 42B)
 * are zero-padded to the Ethernet minimum, mirroring the phase-2
 * gratuitous ARP. Returns 0 on used-ring completion, -1 on timeout
 * (silent: a dead device gets no marker, same as wire-noise discipline).
 * The device ISR is acked on success; the kernel IRQ notify bit is left
 * accumulated (no V2_WAIT here: it blocks, and nothing waits on it again).
 * Single outstanding chain only; callers serialize (one server thread),
 * so descriptor reuse is race-free. Same rdtime-deadline + V2_YIELD
 * bounded poll idiom as the phase-2 TX wait. */
static int net_tx_frame(struct net_wire *w, const uint8_t *frame, unsigned long len)
{
    struct net_desc *txd;
    unsigned long wlen;
    unsigned long i;
    uint64_t t0;
    int done, p;
    uint16_t want;
    uint32_t isr;
    if (!w || !w->regs || !w->txf || !w->txa || !w->txu || !frame)
        return -1;
    if (len < 14u || len > (unsigned long)NET_PKT_MAX)
        return -1;
    wlen = len < (unsigned long)NET_ETH_MIN ? (unsigned long)NET_ETH_MIN : len;
    txd = (struct net_desc *)(w->txf + 0);
    txd[0].addr = w->pa_tx + (uint64_t)NET_TX_HDR_OFF;
    txd[0].len = (uint32_t)NET_VIRTIO_HDR;
    txd[0].flags = NET_DESC_F_NEXT;
    txd[0].next = 1u;
    txd[1].addr = w->pa_tx + (uint64_t)NET_TX_PAY_OFF;
    txd[1].len = (uint32_t)wlen;
    txd[1].flags = 0u;
    txd[1].next = 0u;
    for (i = 0; i < len; i++) /* bound: 1514 */
        w->txf[NET_TX_PAY_OFF + i] = frame[i];
    for (; i < wlen; i++) /* bound: 60 -- pad to Ethernet minimum */
        w->txf[NET_TX_PAY_OFF + i] = 0;
    net_fence();
    w->txa->ring[w->txa->idx % 2u] = 0u;
    net_fence();
    w->txa->idx++;
    net_fence();
    net_w(w->regs, NET_R_QNOTIFY, 1u);
    net_fence();
    want = (uint16_t)(w->txu->idx + 1u);
    t0 = u_rdtime();
    done = 0;
    for (p = 0; p < NET_POLL_BOUND; p++)
    { /* bound: NET_POLL_BOUND */
        if (w->txu->idx == want)
        {
            done = 1;
            break;
        }
        u_yield();
        if (u_rdtime() - t0 > NET_IRQ_TIMEOUT_TICKS)
            break;
    }
    if (!done)
        return -1;
    isr = net_r(w->regs, NET_R_ISTATUS);
    if (isr)
        net_w(w->regs, NET_R_IACK, isr);
    net_fence();
    return 0;
}

/* Phase-2 bring-up: probe, negotiate, DMA, link, RX post, one gratuitous
 * ARP. Fills the caller's wire context on success; returns only on
 * success (any failure parks inside net_no_link or the IRQ-timeout
 * branch). Prints "NET: link up" then "NET: tx ok". The TX completion
 * poll, device ISR ack, and V2_WAIT consumption below are the unchanged
 * phase-2 pattern (Task 4 checklist). */
static void net_phase2(struct net_wire *w)
{
    volatile uint32_t *regs = net_find();
    long slot_tx, slot_rx;
    long pa_tx, pa_rx;
    uint8_t *txf, *rxf;
    struct net_desc *txd;
    struct net_avail *txa;
    volatile struct net_used *txu;
    uint8_t *arp;
    unsigned i;
    uint64_t t0;
    int done, p;
    uint16_t lsts;
    uint32_t isr;
    long bits;

    /* 1. Probe: no modern net transport behind the U-leaf. */
    if (!regs)
        net_no_link();

    /* 2. Acknowledge + feature negotiate (VERSION_1 only, like vmm_feat_ok). */
    net_w(regs, NET_R_STATUS, 0u);
    net_fence();
    net_w(regs, NET_R_STATUS, NET_ST_ACK | NET_ST_DRIVER);
    net_fence();
    net_w(regs, NET_R_FEAT_SEL, 0u);
    (void)net_r(regs, NET_R_FEAT);
    net_w(regs, NET_R_DRV_SEL, 1u);
    net_w(regs, NET_R_DRV_FEAT, 1u);
    net_w(regs, NET_R_DRV_SEL, 0u);
    net_w(regs, NET_R_DRV_FEAT, 0u);
    net_w(regs, NET_R_STATUS, NET_ST_ACK | NET_ST_DRIVER | NET_ST_FEAT_OK);
    net_fence();
    if (!(net_r(regs, NET_R_STATUS) & NET_ST_FEAT_OK))
    {
        net_w(regs, NET_R_STATUS, NET_ST_ACK | NET_ST_DRIVER | NET_ST_FAILED);
        net_no_link();
    }

    /* 3. Two DMA frames (RW only): TX ring+buffers, RX ring. */
    slot_tx = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    slot_rx = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (slot_tx < 0 || slot_rx < 0 || u_invoke(V2_INV_MAP, slot_tx, NET_TX_VPN, 0) != 0 ||
        u_invoke(V2_INV_MAP, slot_rx, NET_RX_VPN, 0) != 0)
        net_no_link();
    pa_tx = u_invoke(V2_INV_FRAME_PA, NET_TX_VPN, 0, 0);
    pa_rx = u_invoke(V2_INV_FRAME_PA, NET_RX_VPN, 0, 0);
    if (pa_tx <= 0 || pa_rx <= 0)
        net_no_link();

    /* 4. Zero both pages, then lay out rings: desc[2] @0, avail @64,
     * used @1024, TX header @2048 (12B zeros), TX payload @2060. */
    txf = (uint8_t *)NET_TX_VA;
    rxf = (uint8_t *)NET_RX_VA;
    for (i = 0; i < 4096; i++)
    { /* bound: 4096 */
        txf[i] = 0;
        rxf[i] = 0;
    }
    if (!net_queue(regs, 0u, (uint64_t)pa_rx + 0u, (uint64_t)pa_rx + 64u, (uint64_t)pa_rx + 1024u))
        net_no_link();
    txd = (struct net_desc *)(txf + 0);
    txa = (struct net_avail *)(txf + 64);
    txu = (volatile struct net_used *)(txf + 1024);
    if (!net_queue(regs, 1u, (uint64_t)pa_tx + 0u, (uint64_t)pa_tx + 64u, (uint64_t)pa_tx + 1024u))
        net_no_link();
    net_w(regs, NET_R_STATUS, NET_ST_ACK | NET_ST_DRIVER | NET_ST_FEAT_OK | NET_ST_DRIVER_OK);
    net_fence();

    /* 5. Link status (config @0x100: MAC[6] + u16 status, bit0 = LINK_UP). */
    lsts = *(volatile uint16_t *)((uintptr_t)regs + NET_R_CONFIG + 6u);
    if (!(lsts & 1u))
        net_no_link();
    u_puts("NET: link up\n");

    /* Task 4: post one RX chain on queue 0, mirroring the TX layout (12B
     * virtio-net header @2048, 1514B packet buffer @2060). Posted after the
     * queue setup + DRIVER_OK above; the device consumes it on QNOTIFY 0.
     * RX completions land in the RX used ring and are drained (copied then
     * net_stack_rx) by the service loop's level check. */
    {
        struct net_desc *rxd = (struct net_desc *)(rxf + 0);
        struct net_avail *rxa = (struct net_avail *)(rxf + 64);
        rxd[0].addr = (uint64_t)pa_rx + (uint64_t)NET_RX_HDR_OFF;
        rxd[0].len = (uint32_t)NET_VIRTIO_HDR;
        rxd[0].flags = NET_DESC_F_NEXT;
        rxd[0].next = 1u;
        rxd[1].addr = (uint64_t)pa_rx + (uint64_t)NET_RX_PAY_OFF;
        rxd[1].len = (uint32_t)NET_PKT_MAX;
        rxd[1].flags = 0u;
        rxd[1].next = 0u;
        rxa->ring[0] = 0u;
        net_fence();
        rxa->idx = 1u;
        net_fence();
        net_w(regs, NET_R_QNOTIFY, 0u);
        net_fence();
    }

    /* 6. One 60B gratuitous ARP: broadcast dst, QEMU OUI src,
     * ethertype ARP, request, spa == tpa == 10.0.2.15, 18B pad. */
    txd[0].addr = (uint64_t)pa_tx + 2048u;
    txd[0].len = 12u;
    txd[0].flags = NET_DESC_F_NEXT;
    txd[0].next = 1u;
    txd[1].addr = (uint64_t)pa_tx + 2060u;
    txd[1].len = 60u;
    txd[1].flags = 0u;
    txd[1].next = 0u;
    arp = txf + 2060;
    arp[0] = 0xff;
    arp[1] = 0xff;
    arp[2] = 0xff;
    arp[3] = 0xff;
    arp[4] = 0xff;
    arp[5] = 0xff;
    arp[6] = 0x52;
    arp[7] = 0x54;
    arp[8] = 0x00;
    arp[9] = 0x12;
    arp[10] = 0x34;
    arp[11] = 0x56;
    arp[12] = 0x08;
    arp[13] = 0x06;
    arp[14] = 0x00;
    arp[15] = 0x01;
    arp[16] = 0x08;
    arp[17] = 0x00;
    arp[18] = 0x06;
    arp[19] = 0x04;
    arp[20] = 0x00;
    arp[21] = 0x01;
    arp[22] = 0x52;
    arp[23] = 0x54;
    arp[24] = 0x00;
    arp[25] = 0x12;
    arp[26] = 0x34;
    arp[27] = 0x56;
    arp[28] = 0x0a;
    arp[29] = 0x00;
    arp[30] = 0x02;
    arp[31] = 0x0f;
    arp[32] = 0x00;
    arp[33] = 0x00;
    arp[34] = 0x00;
    arp[35] = 0x00;
    arp[36] = 0x00;
    arp[37] = 0x00;
    arp[38] = 0x0a;
    arp[39] = 0x00;
    arp[40] = 0x02;
    arp[41] = 0x0f;
    for (i = 42; i < 60; i++) /* bound: 18 */
        arp[i] = 0;
    txa->ring[0] = 0u;
    net_fence();
    txa->idx = 1u;
    net_fence();
    net_w(regs, NET_R_QNOTIFY, 1u);
    net_fence();

    /* 7. TX completion: poll the used ring with an rdtime deadline and a
     * V2_YIELD between polls (never a spin). Timeout parks fail-closed. */
    t0 = u_rdtime();
    done = 0;
    for (p = 0; p < NET_POLL_BOUND; p++)
    { /* bound: NET_POLL_BOUND */
        if (txu->idx != 0u)
        {
            done = 1;
            break;
        }
        u_yield();
        if (u_rdtime() - t0 > NET_IRQ_TIMEOUT_TICKS)
            break;
    }
    if (!done)
    {
        u_puts("NET: irq timeout\n");
        u_park();
    }

    /* 8. Ack the device ISR, then consume the kernel IRQ notify bit
     * (pending: the kernel claimed at the PLIC before waking us). */
    isr = net_r(regs, NET_R_ISTATUS);
    if (isr)
        net_w(regs, NET_R_IACK, isr);
    net_fence();
    bits = u_wait();
    if ((bits & NET_IRQ_BIT) == 0)
        u_park(); /* completion unconfirmed: park with no marker */
    u_puts("NET: tx ok\n");

    /* Hand the live device context to the service loop (still our stack:
     * the caller's struct, filled here). */
    w->regs = regs;
    w->pa_tx = (uint64_t)pa_tx;
    w->pa_rx = (uint64_t)pa_rx;
    w->txf = txf;
    w->rxf = rxf;
    w->txa = txa;
    w->txu = txu;
    w->rxa = (struct net_avail *)(rxf + 64);
    w->rxu = (volatile struct net_used *)(rxf + 1024);
}

void net_main(void)
{
    struct net_wire wire;
    uint8_t rxcopy[NET_PKT_MAX];        /* RX frame copy (max 1514B wire frame) */
    uint8_t park_pay[NET_UDP_PARK_PAY]; /* parked payload: persists across iterations */
    uint32_t park_ip;
    uint16_t park_dport;
    uint16_t park_sport;
    unsigned long park_len;
    uint64_t park_t0;
    int park_valid;
    uint16_t rx_seen;
    int rx_ok_done;
    int pend_valid;         /* S_SEND routing phase outstanding */
    unsigned long pend_snd; /* ... from this kernel-stamped sender */
    int pend_sock;          /* ... for this socket */
    uint32_t pend_ip;       /* ... to this destination */
    uint16_t pend_port;
    long reply_slot; /* PT_ALLOC'd S_DATA reply frame (-1 when none) */

    u_puts("NET: up\n");
    /* Boot-once stack init: reseeds the ARP table (gateway) and flushes
     * the datagram queue. Called exactly once, never per-frame. */
    net_stack_init();
    net_phase2(&wire);

    park_valid = 0;
    park_ip = 0;
    park_dport = 0;
    park_sport = 0;
    park_len = 0;
    park_t0 = 0;
    rx_seen = 0;
    rx_ok_done = 0;
    pend_valid = 0;
    pend_snd = 0;
    pend_sock = 0;
    pend_ip = 0;
    pend_port = 0;
    reply_slot = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    /* PT_ALLOC failure (~impossible: pool-sized): TRYRECV hits answer
     * S_ERR below; the server otherwise runs. The reply frame is never
     * persistently mapped (transient scratch MAP per hit) and never
     * revoked; grants copy the cap, the frame itself persists. */

    for (;;)
    {                         /* bound: inf - service loop */
        long bits = u_wait(); /* wakes on NIC IRQ (0x1) or queued message (0x10) */
        uint64_t now = u_rdtime();

        /* ARP-table expiry runs on the same timebase as the IRQ timeout. */
        net_arp_tick(now);

        /* Parked-send timeout: drop exactly once. (The ARP-learn path
         * below sends exactly once; park_valid clears in exactly one of
         * the two places per parked datagram.) */
        if (park_valid && now - park_t0 > (uint64_t)NET_IRQ_TIMEOUT_TICKS)
            park_valid = 0;

        /* Queued firewall message. V2_WAIT reports 0x10 without consuming,
         * so this u_recv takes without blocking. The T_FWD audit logic is
         * the unchanged phase-1 block, only nested under the bit (early
         * drops fold into the nesting instead of continue, so the RX drain
         * below still runs every iteration). */
        if (bits & NET_MSG_BIT)
        {
            uint64_t buf[4];
            unsigned long snd = 0;
            unsigned long sqb = 0;
            unsigned long ovf = 0;
            long n = u_recv(6, buf, 4, &snd, &sqb, &ovf);

            /* Tag demultiplex beside T_FWD. Only a full T_FWD from the
             * firewall qube enters the audit block below (byte-unchanged);
             * S_OPEN/S_SEND/S_TRYRECV/S_CLOSE chain after it. Everything
             * else (short takes, unknown tags, unprivileged senders) is a
             * silent drop: no reply is ever sent. */
            if (n >= 4 && (unsigned long)buf[0] == (unsigned long)T_FWD &&
                sqb == (unsigned long)FW_QUBE)
            {
                unsigned long slot = (unsigned long)buf[1];
                unsigned long len = (unsigned long)buf[2];
                uint64_t h = buf[3];
                const uint8_t *pkt;
                uint64_t done[4];
                if (slot == (unsigned long)NET_IN_SLOT && len >= 1 &&
                    len <= (unsigned long)NET_PKT_MAX)
                {
                    /* Live-grant check: INVALID means no granted cap behind the
                     * announcement (grant-without-announcement race) -> drop. */
                    if (u_invoke(V2_INV_MAP, (long)slot, (long)NET_SCRATCH_MAP_VPN, 0) == 0)
                    {
                        pkt = (const uint8_t *)NET_SCRATCH_VA;
                        if (qube_fnv1a(pkt, len) != h)
                        {
                            u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                            /* corrupt/raced bytes: UNMAP + silent drop */
                        }
                        else
                        {
                            u_puts("NET: fwd ok\n");
                            u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                            done[0] = (uint64_t)T_DONE;
                            done[1] = (uint64_t)slot;
                            done[2] = 0;
                            done[3] = 0;
                            /* Completion handoff: blocks until the firewall RECVs.
                             * Cross-qube gate needs our QX (Step-5 boot grant); without
                             * it SEND fails INVALID here, fail closed, loop continues. */
                            u_send(5, done, 4);
                        }
                    }
                }
            }
            else if (n >= 4 && (unsigned long)buf[0] == (unsigned long)T_FWD &&
                     sqb != (unsigned long)FW_QUBE && pend_valid && snd == pend_snd)
            {
                /* S_SEND payload phase: a literal T_FWD announcement
                 * [slot, len, h] from the phase-1 sender ("announced like
                 * T_FWD": same MAP/verify discipline). Firewall T_FWDs can
                 * never land here (first branch + sqb guard); replying is
                 * safe because the phase-1 S_OK promised exactly one
                 * completion reply to this waiter. Anything else shaped
                 * like T_FWD (no pending, other sender) falls through to
                 * the silent drop. */
                unsigned long slot = (unsigned long)buf[1];
                unsigned long len = (unsigned long)buf[2];
                uint64_t h = buf[3];
                int sid = pend_sock;
                uint32_t dip = pend_ip;
                uint16_t dport = pend_port;
                uint16_t sport;
                const uint8_t *pay;
                unsigned long flen = 0;
                int rc;
                pend_valid = 0; /* consume exactly once, before any TX */
                if (!net_sock_owned((long)sid, snd))
                {
                    /* Socket closed or reowned between phases: error,
                     * no cap touched. */
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else if (len < 1 || len > (unsigned long)NET_UDP_PARK_PAY)
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else if (u_invoke(V2_INV_MAP, (long)slot, (long)NET_SCRATCH_MAP_VPN, 0) != 0)
                {
                    /* No granted cap behind the announcement (same race
                     * the T_FWD INVALID check drops); here the sender
                     * waits, so answer instead of dropping. */
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else
                {
                    pay = (const uint8_t *)NET_SCRATCH_VA;
                    if (qube_fnv1a(pay, len) != h)
                    {
                        u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                        net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                    }
                    else
                    {
                        sport = net_socks[sid].port;
                        rc = net_stack_udp_send(dip, dport, sport, pay, len,
                                                wire.txf + NET_TX_PAY_OFF, &flen);
                        u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                        if (rc != 0)
                        {
                            /* ARP miss (-1) or oversize (-2, unreachable
                             * by the len bound): fail closed, no park --
                             * the single park slot belongs to the RX
                             * loopback path below, never to RPC. */
                            net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                        }
                        else
                        {
                            /* TX-completion timeout stays silent
                             * (loopback precedent); acceptance is the
                             * reply. */
                            (void)net_tx_frame(&wire, wire.txf + NET_TX_PAY_OFF, flen);
                            net_rpc_reply(snd, (uint64_t)S_OK, 0);
                        }
                    }
                }
            }
            else if (n >= 4 && (unsigned long)buf[0] == (unsigned long)S_OPEN)
            {
                /* S_OPEN [S_OPEN, kind, port, 0]: UDP only; duplicate bind
                 * and a full fair-share pool fail via error reply, never
                 * a wedge. Owner is the kernel-stamped sender tid. */
                uint64_t kind = buf[1];
                uint64_t portw = buf[2];
                int id;
                if (kind != (uint64_t)NET_SOCK_UDP || (portw >> 16) != 0)
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else
                {
                    id = net_sock_open((unsigned)kind, (uint16_t)portw, (unsigned)snd);
                    if (id < 0)
                        net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                    else
                        net_rpc_reply(snd, (uint64_t)S_OK, (uint64_t)id);
                }
            }
            else if (n >= 4 && (unsigned long)buf[0] == (unsigned long)S_SEND)
            {
                /* S_SEND routing phase [S_SEND, sock, ip, port]: validate
                 * ownership now; the payload follows as a T_FWD
                 * announcement (branch above). Exactly one reply. A
                 * single-flight pending held by another sender is kept;
                 * the newcomer gets S_ERR and sends no payload. */
                long sid = (long)buf[1];
                uint64_t ipw = buf[2];
                uint64_t ptw = buf[3];
                if (!net_sock_owned(sid, snd) || (ipw >> 32) != 0 || (uint32_t)ipw == 0 ||
                    (ptw >> 16) != 0 || (uint16_t)ptw == 0)
                {
                    /* Unknown/foreign socket or malformed route: error,
                     * pending untouched, never a wedge. */
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else if (pend_valid && pend_snd != snd)
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else
                {
                    pend_valid = 1;
                    pend_snd = snd;
                    pend_sock = (int)sid;
                    pend_ip = (uint32_t)ipw;
                    pend_port = (uint16_t)ptw;
                    net_rpc_reply(snd, (uint64_t)S_OK, 0);
                }
            }
            else if (n >= 4 && (unsigned long)buf[0] == (unsigned long)S_TRYRECV)
            {
                /* S_TRYRECV [S_TRYRECV, sock, 0, 0]: only the owner's own
                 * socket drains (shared-FIFO head; single-socket exact).
                 * Hit: dequeue into rxcopy (free for reuse here: the RX
                 * block below runs later in the iteration), stage into
                 * the reply frame, grant it to the client's RSVP slot,
                 * answer S_DATA. Miss: S_EMPTY, no grant touched. The
                 * source address has no room in [S_DATA, len, 0, 0] and
                 * is dropped (single-peer DNS needs none). */
                long sid = (long)buf[1];
                if (!net_sock_owned(sid, snd))
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else if (reply_slot < 0)
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else
                {
                    int trunc = 0;
                    long ngot;
                    unsigned long k;
                    uint8_t *dst;
                    ngot = net_udp_recv(rxcopy, sizeof(rxcopy), 0, 0, &trunc);
                    if (ngot == -(NET_ERR_EMPTY))
                    {
                        net_rpc_reply(snd, (uint64_t)S_EMPTY, 0);
                    }
                    else if (ngot < 0 || trunc)
                    {
                        /* TRUNC is unreachable (1514 cap > 1472 max);
                         * defensive error. */
                        net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                    }
                    else if (u_invoke(V2_INV_MAP, reply_slot, (long)NET_SCRATCH_MAP_VPN, 0) != 0)
                    {
                        net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                    }
                    else
                    {
                        dst = (uint8_t *)NET_SCRATCH_VA;
                        for (k = 0; k < (unsigned long)ngot; k++) /* bound: 1472 */
                            dst[k] = rxcopy[k];
                        u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                        if (u_invoke(V2_INV_GRANT, reply_slot, (long)snd, (long)NET_SDATA_SLOT) !=
                            0)
                        {
                            /* Client RSVP slot occupied (protocol
                             * violation): datagram already dequeued,
                             * dropped fail-closed. */
                            net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                        }
                        else
                        {
                            net_rpc_reply(snd, (uint64_t)S_DATA, (uint64_t)ngot);
                        }
                    }
                }
            }
            else if (n >= 4 && (unsigned long)buf[0] == (unsigned long)S_CLOSE)
            {
                /* S_CLOSE [S_CLOSE, sock, 0, 0]: free the entry and discard
                 * its queued datagrams so the fair-share pool slot
                 * returns. The RX queue is one shared FIFO (no per-socket
                 * carve), so the close drains it whole (bounded: depth 4
                 * + terminal EMPTY take); with one socket outstanding
                 * this is exact. */
                long sid = (long)buf[1];
                int k;
                if (!net_sock_owned(sid, snd))
                {
                    net_rpc_reply(snd, (uint64_t)S_ERR, 0);
                }
                else
                {
                    net_sock_close((int)sid);
                    for (k = 0; k <= (int)NET_UDP_QDEPTH; k++) /* bound: 4+1 */
                    {
                        if (net_udp_recv(rxcopy, sizeof(rxcopy), 0, 0, 0) == -(NET_ERR_EMPTY))
                            break;
                    }
                    net_rpc_reply(snd, (uint64_t)S_OK, (uint64_t)sid);
                }
            }
            /* else: unknown tag/sender or short take: silent drop. */
        }

        /* Wire RX: level-check the RX used ring every iteration (not only
         * when an IRQ bit is set: a completion that landed before this
         * loop's first V2_WAIT must still be observed). Completions are
         * counted, not edge-compared: completion i lands at ring[i % 2]
         * with used len = 12 (virtio header) + pktlen, packet bytes at
         * rxf+2060. */
        if (wire.rxu->idx != rx_seen)
        {
            unsigned long wlen = (unsigned long)wire.rxu->ring[rx_seen % 2u].len;
            uint32_t isr;
            net_fence(); /* acquire: DMA bytes land before the idx bump */
            rx_seen++;   /* consume one completion (wrap-safe uint16_t count) */
            /* Ack the device latch on every RX observation, even drops:
             * pure-RX iterations (foreign/broadcast, non-UDP, invalid
             * wlen) must not leave ISTATUS asserted or the device may
             * suppress further interrupts. */
            isr = net_r(wire.regs, NET_R_ISTATUS);
            if (isr)
                net_w(wire.regs, NET_R_IACK, isr);
            net_fence();
            if (wlen >= (unsigned long)NET_VIRTIO_HDR + 14u &&
                wlen <= (unsigned long)NET_VIRTIO_HDR + (unsigned long)NET_PKT_MAX)
            {
                unsigned long pktlen = wlen - (unsigned long)NET_VIRTIO_HDR;
                unsigned long i;
                int cls;
                for (i = 0; i < pktlen; i++) /* bound: 1514 */
                    rxcopy[i] = wire.rxf[NET_RX_PAY_OFF + i];
                cls = net_stack_rx(rxcopy, pktlen);
                if (cls == NET_CLASS_UDP)
                {
                    /* Live-wire proof: first validated UDP only. */
                    if (!rx_ok_done)
                    {
                        u_puts("NET: rx ok\n");
                        rx_ok_done = 1;
                    }
                    /* Phase-1 live loopback: echo the datagram to its
                     * sender with ports swapped, exercising the UDP send
                     * path on live traffic. Reflected only when addressed
                     * to us (never broadcast/foreign floods). The queue is
                     * drained on EVERY validated UDP (foreign included, by
                     * the unconditional dequeue below): entries can never
                     * accumulate to the 4-slot drop point, so the echo
                     * always pairs this frame's sip/sport/payload with its
                     * own local port. rxcopy is free for reuse as the
                     * dequeue buffer (classification is done). */
                    {
                        uint32_t sip = 0;
                        uint16_t sport = 0;
                        uint16_t local = 0;
                        unsigned ihl;
                        uint32_t dip;
                        int trunc = 0;
                        int ngot;
                        unsigned long flen = 0;
                        int rc;
                        ihl = (unsigned)(rxcopy[14] & 0x0Fu) * 4u;
                        dip =
                            (uint32_t)(((uint32_t)rxcopy[30] << 24) | ((uint32_t)rxcopy[31] << 16) |
                                       ((uint32_t)rxcopy[32] << 8) | (uint32_t)rxcopy[33]);
                        /* Always drain the queue: net_stack_rx enqueues every
                         * validated UDP (foreign/broadcast included); leaving
                         * entries behind would fill the 4 slots and make a
                         * later echo misdeliver a stale datagram. Anything
                         * not addressed to us is dequeued and discarded.
                         * Port/addr views are captured before the dequeue
                         * overwrites rxcopy with the payload. */
                        if (ihl >= 20u && dip == NET_IP_SELF)
                            local = (uint16_t)(((unsigned)rxcopy[14 + ihl + 2] << 8) |
                                               (unsigned)rxcopy[14 + ihl + 3]);
                        ngot = net_udp_recv(rxcopy, sizeof(rxcopy), &sip, &sport, &trunc);
                        if (ihl >= 20u && dip == NET_IP_SELF && ngot >= 0 && !trunc)
                        {
                            rc = net_stack_udp_send(sip, sport, local, rxcopy, (unsigned long)ngot,
                                                    wire.txf + NET_TX_PAY_OFF, &flen);
                            if (rc == 0)
                            {
                                (void)net_tx_frame(&wire, wire.txf + NET_TX_PAY_OFF, flen);
                            }
                            else if (rc == -1 && !park_valid)
                            {
                                /* ARP miss with a free park slot: emit
                                 * ONE request, park ONE datagram. While
                                 * parked, further misses drop newest
                                 * (same discipline as the RX queue). */
                                unsigned long k;
                                for (k = 0; k < (unsigned long)ngot; k++) /* bound: 1472 */
                                    park_pay[k] = rxcopy[k];
                                park_ip = sip;
                                park_dport = sport;
                                park_sport = local;
                                park_len = (unsigned long)ngot;
                                park_t0 = now;
                                park_valid = 1;
                                if (net_arp_build_request(sip, wire.txf + NET_TX_PAY_OFF) !=
                                    (int)NET_ARP_FRAME_LEN)
                                    park_valid = 0; /* build failed: drop at once */
                                else
                                    (void)net_tx_frame(&wire, wire.txf + NET_TX_PAY_OFF,
                                                       (unsigned long)NET_ARP_FRAME_LEN);
                            }
                            /* rc == -2 is impossible (ngot <= 1472);
                             * occupied park: drop newest, silent. */
                        }
                    }
                }
                else if (cls == NET_CLASS_ARP)
                {
                    uint32_t rip = 0;
                    uint8_t rmac[6];
                    /* Answer requests for our IP (reply built from the
                     * copied request; 42B padded to 60B on TX). */
                    if (net_arp_need_reply(&rip, rmac) &&
                        net_arp_build_reply(rxcopy, pktlen, wire.txf + NET_TX_PAY_OFF) ==
                            (int)NET_ARP_FRAME_LEN)
                        (void)net_tx_frame(&wire, wire.txf + NET_TX_PAY_OFF,
                                           (unsigned long)NET_ARP_FRAME_LEN);
                    /* Parked-send flush: this learn may have resolved it.
                     * The flag clears before TX so the datagram sends
                     * (here) or times out (above) exactly once. A -1 here
                     * is impossible (lookup just hit, no tick between on
                     * one thread); -2 is impossible by length. */
                    if (park_valid)
                    {
                        uint8_t dmac[6];
                        if (net_arp_lookup(park_ip, dmac) == 0)
                        {
                            unsigned long flen2 = 0;
                            park_valid = 0;
                            if (net_stack_udp_send(park_ip, park_dport, park_sport, park_pay,
                                                   park_len, wire.txf + NET_TX_PAY_OFF,
                                                   &flen2) == 0)
                                (void)net_tx_frame(&wire, wire.txf + NET_TX_PAY_OFF, flen2);
                        }
                    }
                }
                /* All other classes: classify-and-drop preserved (no marker). */
            }
            /* Repost the RX chain for the next frame. */
            wire.rxa->ring[wire.rxa->idx % 2u] = 0u;
            net_fence();
            wire.rxa->idx++;
            net_fence();
            net_w(wire.regs, NET_R_QNOTIFY, 0u);
            net_fence();
        }
    }
}
