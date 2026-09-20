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
 */
#include <stdint.h>

#include "../../kernel/qube.h"

#define V2_PUTC 1
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_YIELD 0
#define V2_PARK 2
#define V2_WAIT 6

#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_PT_ALLOC 6
#define V2_INV_FRAME_PA 16

#define T_FWD 6
#define T_DONE 7

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

struct net_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct net_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[2];
};

struct net_used_elem {
    uint32_t id;
    uint32_t len;
};

struct net_used {
    uint16_t flags;
    uint16_t idx;
    struct net_used_elem ring[1];
};

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
static int net_queue(volatile uint32_t *regs, uint32_t q, uint64_t desc_pa,
                     uint64_t avail_pa, uint64_t used_pa)
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
    for (j = 0; j < 8; j++) { /* bound: 8 */
        volatile uint32_t *r =
            (volatile uint32_t *)(NET_UVA + (unsigned long)j * 0x1000UL);
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

/* Phase-2 bring-up: probe, negotiate, DMA, link, one gratuitous ARP.
 * Returns only on success (any failure parks inside net_no_link or the
 * IRQ-timeout branch). Prints "NET: link up" then "NET: tx ok". */
static void net_phase2(void)
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
    net_w(regs, NET_R_STATUS,
           NET_ST_ACK | NET_ST_DRIVER | NET_ST_FEAT_OK);
    net_fence();
    if (!(net_r(regs, NET_R_STATUS) & NET_ST_FEAT_OK)) {
        net_w(regs, NET_R_STATUS,
               NET_ST_ACK | NET_ST_DRIVER | NET_ST_FAILED);
        net_no_link();
    }

    /* 3. Two DMA frames (RW only): TX ring+buffers, RX ring. */
    slot_tx = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    slot_rx = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (slot_tx < 0 || slot_rx < 0 ||
        u_invoke(V2_INV_MAP, slot_tx, NET_TX_VPN, 0) != 0 ||
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
    for (i = 0; i < 4096; i++) { /* bound: 4096 */
        txf[i] = 0;
        rxf[i] = 0;
    }
    if (!net_queue(regs, 0u, (uint64_t)pa_rx + 0u,
                   (uint64_t)pa_rx + 64u, (uint64_t)pa_rx + 1024u))
        net_no_link();
    txd = (struct net_desc *)(txf + 0);
    txa = (struct net_avail *)(txf + 64);
    txu = (volatile struct net_used *)(txf + 1024);
    if (!net_queue(regs, 1u, (uint64_t)pa_tx + 0u,
                   (uint64_t)pa_tx + 64u, (uint64_t)pa_tx + 1024u))
        net_no_link();
    net_w(regs, NET_R_STATUS, NET_ST_ACK | NET_ST_DRIVER |
           NET_ST_FEAT_OK | NET_ST_DRIVER_OK);
    net_fence();

    /* 5. Link status (config @0x100: MAC[6] + u16 status, bit0 = LINK_UP). */
    lsts = *(volatile uint16_t *)((uintptr_t)regs + NET_R_CONFIG + 6u);
    if (!(lsts & 1u))
        net_no_link();
    u_puts("NET: link up\n");

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
    arp[0] = 0xff; arp[1] = 0xff; arp[2] = 0xff;
    arp[3] = 0xff; arp[4] = 0xff; arp[5] = 0xff;
    arp[6] = 0x52; arp[7] = 0x54; arp[8] = 0x00;
    arp[9] = 0x12; arp[10] = 0x34; arp[11] = 0x56;
    arp[12] = 0x08; arp[13] = 0x06;
    arp[14] = 0x00; arp[15] = 0x01; arp[16] = 0x08; arp[17] = 0x00;
    arp[18] = 0x06; arp[19] = 0x04; arp[20] = 0x00; arp[21] = 0x01;
    arp[22] = 0x52; arp[23] = 0x54; arp[24] = 0x00;
    arp[25] = 0x12; arp[26] = 0x34; arp[27] = 0x56;
    arp[28] = 0x0a; arp[29] = 0x00; arp[30] = 0x02; arp[31] = 0x0f;
    arp[32] = 0x00; arp[33] = 0x00; arp[34] = 0x00;
    arp[35] = 0x00; arp[36] = 0x00; arp[37] = 0x00;
    arp[38] = 0x0a; arp[39] = 0x00; arp[40] = 0x02; arp[41] = 0x0f;
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
    for (p = 0; p < NET_POLL_BOUND; p++) { /* bound: NET_POLL_BOUND */
        if (txu->idx != 0u) {
            done = 1;
            break;
        }
        u_yield();
        if (u_rdtime() - t0 > NET_IRQ_TIMEOUT_TICKS)
            break;
    }
    if (!done) {
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
}

void net_main(void)
{
    u_puts("NET: up\n");
    net_phase2();

    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        long n = u_recv(0, buf, 4, &snd, &sqb, &ovf);

        /* Only a full T_FWD from the firewall qube is actionable.
         * Everything else (short takes, other tags, spoofed sender)
         * is a silent drop: no reply is ever sent. */
        if (n < 4 || (unsigned long)buf[0] != (unsigned long)T_FWD ||
            sqb != (unsigned long)FW_QUBE)
            continue;

        {
            unsigned long slot = (unsigned long)buf[1];
            unsigned long len = (unsigned long)buf[2];
            uint64_t h = buf[3];
            const uint8_t *pkt;
            uint64_t done[4];
            if (slot != (unsigned long)NET_IN_SLOT || len < 1 ||
                len > (unsigned long)NET_PKT_MAX)
                continue;
            /* Live-grant check: INVALID means no granted cap behind the
             * announcement (grant-without-announcement race) -> drop. */
            if (u_invoke(V2_INV_MAP, (long)slot,
                         (long)NET_SCRATCH_MAP_VPN, 0) != 0)
                continue;
            pkt = (const uint8_t *)NET_SCRATCH_VA;
            if (qube_fnv1a(pkt, len) != h) {
                u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                continue; /* corrupt/raced bytes: UNMAP + silent drop */
            }
            u_puts("NET: fwd ok\n");
            u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
            done[0] = (uint64_t)T_DONE;
            done[1] = (uint64_t)slot;
            done[2] = 0;
            done[3] = 0;
            /* Completion handoff: blocks until the firewall RECVs.
             * Cross-qube gate needs our QX (Step-5 boot grant); without
             * it SEND fails INVALID here, fail closed, loop continues. */
            u_send(0, done, 4);
        }
    }
}
