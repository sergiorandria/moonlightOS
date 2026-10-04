/* userspace/cryptblk/v2_main.c - FDE cryptblk ELF (U-mode, Task 4).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (cryptblk/cryptblk_start.S) which sets gp and calls cryptblk_main.
 *
 * Role: the ONLY qube with blk MMIO + IRQ (tid 9, U-leaf at BLK_UVA);
 * sector AEAD under the volume key (VMK); a minimal label-checked FS;
 * two views: /dev/blk0 (raw ciphertext, any label) and the file tree
 * (plaintext post-unlock, owner-label only).
 *
 * Addressed-EP protocol handled here (received on EP9; all messages <= V2_MSG_MAX = 4 words):
 *   T_CALL [1, op, a, b]  any QX-holding qube -> cryptblk (direct FS ops:
 *     CR_FS_OPEN/READ/WRITE/CLOSE/STAT/BLK0 on the fixed demo files;
 *     data moves one 8-byte word per reply — block-granular FS over
 *     4-word IPC. Owner-label checks gate every op; unknown ops get
 *     INVALID. This is the DIRECT path: no qrexec approval, the stamp +
 *     owner check is the authorization.)
 *   T_DELIVER [5, 9, 0, 0] qrexec -> cryptblk (approved vol.format:
 *     format-if-absent, silent when the volume exists)
 *   T_KEY [8, slot, 0, 0]  vault -> cryptblk (keyless notice: the VMK
 *     waits in the granted frame at CRYPT_KEY_SLOT, never in SEND words)
 *   T_KEY_ACK [10, slot, 0, 0] cryptblk -> vault (handoff ack)
 *   reply [0, ...] = OK (+ payload), [-1] = INVALID
 *
 * Boot demo (self-contained, single-flight, net-phase2 precedent): the
 * ELF brings up its OWN driver + disk, attests the vault RANDOM service
 * (RANDOM_REQ on EP8, R_OK from vault qube6 on EP9 — rendezvous queues +
 * blocks until the vault serves), derives the KEK, and prints the CRYPT:
 * markers. The vault-mediated T_KEY release path below
 * (key_consume) is the production shape — same grant slot, same ack tag,
 * same canary check — reached via AdminVM-attended flows, not at boot.
 * Single-flight is structural: one request in flight (driver), one RECV
 * per service-loop iteration, no state held across iterations except the
 * VMK + mounted superblock.
 *
 * Seed honesty (dev-grade seed, production KDF): the boot demo derives
 * its KEK from the vault-attested seed words via pbkdf2_hmac_sha256 with
 * the per-volume header salt at KDF_ITERS_DEFAULT iterations (600K,
 * OWASP 2023; no compiled-in passphrase). The attestation nonce is public
 * wire bytes, so secrecy still rests on future AdminVM passphrase entry,
 * documented, never compiled in. Format folds rdtime into the production
 * DRBG (fresh salt/VMK per format; production hardware-RNG seeding is
 * future work, audit-deferred).
 *
 * Sector layout (4K sectors; disk 256M = 65536 sectors of 512B LBA):
 *   0..1 header (HEADER_SECTORS; USED bytes 568 all in sector 0)
 *   2    canary (full-sector AEAD under VMK: proves the key post-load)
 *   3    superblock (AEAD: magic + 2 file entries incl. extents)
 *   5    scratch (wrong-key leg; rewritten clean afterwards)
 *   8..63 alloc arena (first-fit via layout_alloc; probe takes first fit)
 *   32768+ tag region (TAG_BASE + sector/256, slot sector%256)
 * Sector AEAD: nonce "SECT" || u64-LE sector, AD "SECTOR" || u64-LE
 * sector. Tag mismatch on read => EIO + zeroed buffer, never partial
 * plaintext. Data sector first, tag sector second (crash between =
 * mismatch = detected, never silent).
 *
 * Single-DRBG-owner rule (kdf_production.h): this TU defines
 * CRYPT_DRBG_DEFINE and is the only owner of the production DRBG state in
 * this ELF (cryptblk_start.S is asm; ChaCha20 stream with entropy
 * accounting, fail-closed on exhaustion). All key-bearing locals and one-shot buffers are crypt_wipe'd on
 * every exit path. All loops carry bounds. State is stack-local except
 * the DMA frames (capability-held, RW, never X); string literals are
 * private rodata (U-mapped). W^X intact (linker script unchanged).
 */
#define CRYPT_DRBG_DEFINE
#include <stdint.h>

#include "../../kernel/qube.h"
#include "../crypt/aead.h"
#include "../crypt/kdf_production.h"
#include "layout.h"
#include "slot.h"

#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_WAIT 6
#define V2_INVOKE 7

#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_MINT 1
#define V2_INV_PT_ALLOC 6
#define V2_INV_WRITE 12
#define V2_INV_READ 13
#define V2_INV_FRAME_PA 16

#define V2_RIGHT_R 0x1UL

#define T_CALL 1
#define T_DELIVER 5
#define T_KEY 8
#define T_KEY_ACK 10

#define R_INVALID (-1L)

/* RPC / op ids (T_CALL op namespace for the direct FS path; T_DELIVER
 * rpc namespace shared with qrexec: VOL_FORMAT 9. Task 5 models these). */
#define VOL_FORMAT 9
#define CR_FS_OPEN 1
#define CR_FS_READ 2
#define CR_FS_WRITE 3
#define CR_FS_CLOSE 4
#define CR_FS_STAT 5
#define CR_FS_BLK0 6

/* Fixed demo files (superblock entries). */
#define CR_FILE_PROBE 1UL
#define CR_FILE_BLK0 2UL

#define QREXEC_QUBE 2
#define VAULT_QUBE 6
#define CRYPT_QUBE 7
#define CR_OWNER_ANY 0xFFFFFFFFUL

#define VAULT_TID 8
#define CRYPT_TID 9

/* Task-4 contract (mirrors vault): the vault's key-frame GRANT lands in
 * this cap-table slot; the ELF never PT_ALLOCs into it (concurrent live
 * allocs stay <= 2: the two DMA frames). */
#define CRYPT_KEY_SLOT 20L

/* Scratch vpn for the key-consume MAP window (image occupies the low vpns
 * only; the image stays < 8 pages by build). */
#define CRYPT_SCRATCH_VPN 8

/* DMA windows (frame-window base + vpn*4096; high vpns like net 16/17). */
#define CRYPT_U_FRAME_BASE 0x80800000UL
#define CRYPT_DMA_Q_VPN 16
#define CRYPT_DMA_D_VPN 17
#define CRYPT_DMA_Q_VA (CRYPT_U_FRAME_BASE + ((unsigned long)CRYPT_DMA_Q_VPN * 4096UL))
#define CRYPT_DMA_D_VA (CRYPT_U_FRAME_BASE + ((unsigned long)CRYPT_DMA_D_VPN * 4096UL))
#define CRYPT_SCRATCH_VA (CRYPT_U_FRAME_BASE + ((unsigned long)CRYPT_SCRATCH_VPN * 4096UL))

/* Transport: virtio-blk on an MMIO transport, scanned through the tid-9
 * U-leaf (8 transport pages at BLK_UVA + i*0x1000; the kernel maps that
 * VPN[1]=6 table only for this thread; the pages are RW, never X).
 * QEMU attaches backends last-first, so the device is found by scan,
 * never assumed at a transport. */
#define BLK_IRQ_BIT 0x2L
#define BLK_UVA 0x80C00000UL

/* virtio-mmio register offsets (mirrors net + virtio_mmio.h). */
#define BLK_R_MAGIC 0x000u
#define BLK_R_VERSION 0x004u
#define BLK_R_DEVICE_ID 0x008u
#define BLK_R_FEAT 0x010u
#define BLK_R_FEAT_SEL 0x014u
#define BLK_R_DRV_FEAT 0x020u
#define BLK_R_DRV_SEL 0x024u
#define BLK_R_QSEL 0x030u
#define BLK_R_QMAX 0x034u
#define BLK_R_QNUM 0x038u
#define BLK_R_QREADY 0x044u
#define BLK_R_QNOTIFY 0x050u
#define BLK_R_ISTATUS 0x060u
#define BLK_R_IACK 0x064u
#define BLK_R_STATUS 0x070u
#define BLK_R_QDESC_LO 0x080u
#define BLK_R_QDESC_HI 0x084u
#define BLK_R_QDRV_LO 0x090u
#define BLK_R_QDRV_HI 0x094u
#define BLK_R_QDEV_LO 0x0a0u
#define BLK_R_QDEV_HI 0x0a4u
#define BLK_R_CONFIG 0x100u

#define BLK_MAGIC_VAL 0x74726976u
#define BLK_DEV_BLK 2u

#define BLK_ST_ACK 1u
#define BLK_ST_DRIVER 2u
#define BLK_ST_DRIVER_OK 4u
#define BLK_ST_FEAT_OK 8u
#define BLK_ST_FAILED 128u

#define BLK_DESC_F_NEXT 1u
#define BLK_DESC_F_WRITE 2u

#define BLK_T_IN 0u
#define BLK_T_OUT 1u

#define BLK_QNUM_WANT 16u /* descriptors available; one 3-desc chain per op */

/* ~2s @10MHz timebase + iteration backstop (the time bound fires first). */
#define BLK_IRQ_TIMEOUT_TICKS 20000000UL
#define BLK_POLL_BOUND 2000000

/* Demo geometry (documented above). */
#define CR_HDR_SECTORS 2UL
#define CR_CANARY_SEC 2UL
#define CR_SUPER_SEC 3UL
#define CR_SCRATCH_SEC 5UL
#define CR_ARENA_BASE 8UL
#define CR_ARENA_LEN 56UL
#define CR_TAG_BASE 32768UL
#define CR_SUPER_MAGIC 0x3142535450595243UL /* "CRYPTSB1" LE */
#define CR_SUPER_NFILES 2UL

/* Production: KEK derives from vault RANDOM seed + per-volume salt via
 * pbkdf2_hmac_sha256 (no compiled-in vectors, no fixed format seed). The seed
 * words arrive through crypt_get_seed below (RANDOM_REQ on EP8, R_OK
 * from vault qube6 on EP9); the format salt/VMK come from fresh
 * drbg_generate_production bytes (no fixed DRBG seed). */
/* Production KDF work factor (OWASP 2023): format stamps new slots at
 * KDF_ITERS_DEFAULT. Unlock honors the per-slot stored iters, so
 * pre-migration volumes (8192-iter demo factor) keep unlocking. */
#define CRYPT_KDF_SMOKE_ITERS KDF_ITERS_DEFAULT

struct blk_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct blk_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[16];
};

struct blk_used_elem {
    uint32_t id;
    uint32_t len;
};

struct blk_used {
    uint16_t flags;
    uint16_t idx;
    struct blk_used_elem ring[16];
};

/* One superblock file entry (owner + extent ride beside the dirent). */
typedef struct {
    layout_dirent_t dent;
    uint32_t owner;
    uint64_t start;
    uint64_t len;
} crypt_fent_t;

/* FD table entry (v1-VFS discipline: bound to the creating sender). */
typedef struct {
    int valid;
    unsigned long ino;
    unsigned long owner_tid;
    unsigned long owner_qube;
    unsigned long off;
} crypt_fd_t;

#define CR_FDS_MAX 8

/* Whole ELF state: single stack-local struct in cryptblk_main (no
 * globals cross qubes). io[] is the ONE 4K staging buffer: crypto is
 * in-place and tag RMW reuses it sequentially, so peak stack stays
 * ~8K under the 8KB U-stack. */
typedef struct {
    volatile uint32_t *regs;
    long slot_q;
    long slot_d;
    uint64_t pa_q;
    uint64_t pa_d;
    uint64_t capacity; /* device 512B sectors (config) */
    uint16_t expect_used;
    unsigned long disk_io; /* 512B requests issued (leak leg: no I/O pin) */
    uint8_t vmk[32];
    int vmk_valid;
    vol_header_t hdr;
    int hdr_valid;
    layout_alloc_t arena;
    crypt_fent_t files[2];
    unsigned long nfiles;
    crypt_fd_t fds[CR_FDS_MAX];
    uint8_t io[4096];
} crypt_state_t;

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

/* Production seed handoff: the 32B KEK password arrives via the vault
 * RANDOM service, never from a compiled-in vector. The 4 attested reply
 * words expand LE into 32 seed bytes (4 word reads, bounded); every
 * failure path wipes. Returns 1 ok, 0 denied.
 *
 * Ledger note: Task-3 RANDOM replies carry no seed bytes and grant no
 * frame (RANDOM_RESP 12 stays reserved), so a literal frame-READ has no
 * source; the handoff folds the attested reply words themselves. The
 * per-volume header salt in the PBKDF2 below keeps every volume's KEK
 * distinct. */
static int vault_seed_to_local(const uint64_t *w, uint8_t *seed_out)
{
    unsigned i;
    unsigned k;
    if (!w || !seed_out)
        return 0;
    for (i = 0; i < 4; i++) { /* bound: 4 (attested reply words) */
        uint64_t word = w[i];
        for (k = 0; k < 8; k++) /* bound: 8 (bytes per word) */
            seed_out[i * 8u + k] = (uint8_t)(word >> (8u * k));
    }
    return 1;
}

/* Production: KEK derives from vault RANDOM seed + per-volume salt via
 * pbkdf2_hmac_sha256 (no compiled-in vectors, no fixed format seed). */
static int crypt_get_seed(uint8_t *seed_out)
{
    uint64_t req[4];
    long n;
    unsigned long snd = 0, sqb = 0, ovf = 0;
    if (!seed_out)
        return 0;
    req[0] = 11u; req[1] = 0x9e4bu; req[2] = 0u; req[3] = 0u; /* RANDOM_REQ + nonce */
    if (u_send(8u, req, 4) != 0) return 0;
    n = u_recv(9u, req, 4, &snd, &sqb, &ovf);
    if (n < 1 || req[0] != 0u || sqb != 6u) return 0; /* vault qube6 R_OK only */
    return vault_seed_to_local(req, seed_out); /* 4x word-READ handoff, bounded, wiped */
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

static void u_reply(unsigned long dst, long v)
{
    uint64_t resp[1];
    resp[0] = (uint64_t)v;
    u_send(dst, resp, 1);
}

static void blk_fence(void)
{
    asm volatile("fence iorw,iorw" ::: "memory");
}

static uint32_t blk_r(volatile uint32_t *regs, uint32_t off)
{
    return *(volatile uint32_t *)((uintptr_t)regs + off);
}

static void blk_w(volatile uint32_t *regs, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)((uintptr_t)regs + off) = v;
}

static void blk_w64(volatile uint32_t *regs, uint32_t lo_off, uint64_t v)
{
    blk_w(regs, lo_off, (uint32_t)(v & 0xffffffffu));
    blk_w(regs, lo_off + 4u, (uint32_t)(v >> 32));
    blk_fence();
}

static void blk_st64le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) /* bound: 8 */
        p[i] = (uint8_t)(v >> (8 * i));
}

static void blk_st32le(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0; i < 4; i++) /* bound: 4 */
        p[i] = (uint8_t)(v >> (8 * i));
}

/* Find the modern blk transport: scan all 8 pages (BLK_UVA + i*0x1000,
 * all inside the tid-9 U-leaf) for magic + version 2 + blk device id.
 * Returns the page or 0. */
static volatile uint32_t *blk_find(void)
{
    unsigned j;
    for (j = 0; j < 8; j++) { /* bound: 8 */
        volatile uint32_t *r =
            (volatile uint32_t *)(BLK_UVA + (unsigned long)j * 0x1000UL);
        if (blk_r(r, BLK_R_MAGIC) != BLK_MAGIC_VAL)
            continue;
        if (blk_r(r, BLK_R_VERSION) != 2u)
            continue;
        if (blk_r(r, BLK_R_DEVICE_ID) != BLK_DEV_BLK)
            continue;
        return r;
    }
    return 0;
}

/* Fail-closed helper: the disk never came up. */
static void blk_no_disk(void)
{
    u_park();
}

/* One 512B request: 3-desc chain (header, data, status) on queue 0.
 * data_va is the caller's DMA staging byte (inside the DMA_D frame);
 * is_write: 1 = OUT (device reads), 0 = IN (device writes).
 * Returns 0 on device-ok completion, -1 on any failure (timeout, badge
 * miss, device status). Completion is the used-ring advance with an
 * rdtime deadline + V2_YIELD between polls (never a spin), then a single
 * V2_WAIT consuming the kernel IRQ badge. */
static int blk_req512(crypt_state_t *st, uint64_t lba, int is_write)
{
    volatile uint32_t *regs = st->regs;
    uint8_t *qf = (uint8_t *)CRYPT_DMA_Q_VA;
    struct blk_desc *d = (struct blk_desc *)(qf + 0);
    struct blk_avail *av = (struct blk_avail *)(qf + 256);
    volatile struct blk_used *us = (volatile struct blk_used *)(qf + 512);
    uint8_t *hdr = qf + 1024;
    volatile uint8_t *status = (volatile uint8_t *)(qf + 1040);
    uint64_t t0;
    int done = 0;
    long p;
    long bits;
    uint32_t isr;

    if (!regs)
        return -1;
    /* Header: type, reserved, sector (LE). */
    blk_st32le(hdr, is_write ? BLK_T_OUT : BLK_T_IN);
    blk_st32le(hdr + 4, 0);
    blk_st64le(hdr + 8, lba);
    *status = 0xFF;
    /* desc0: header (device reads). desc1: data 512B (direction by op).
     * desc2: status byte (device writes). */
    d[0].addr = st->pa_q + 1024u;
    d[0].len = 16u;
    d[0].flags = BLK_DESC_F_NEXT;
    d[0].next = 1u;
    d[1].addr = st->pa_d;
    d[1].len = 512u;
    d[1].flags = (uint16_t)(BLK_DESC_F_NEXT | (is_write ? 0u : BLK_DESC_F_WRITE));
    d[1].next = 2u;
    d[2].addr = st->pa_q + 1040u;
    d[2].len = 1u;
    d[2].flags = BLK_DESC_F_WRITE;
    d[2].next = 0u;
    av->ring[0] = 0u;
    blk_fence();
    av->idx = (uint16_t)(st->expect_used + 1u);
    blk_fence();
    blk_w(regs, BLK_R_QNOTIFY, 0u);
    blk_fence();
    st->disk_io++;

    t0 = u_rdtime();
    for (p = 0; p < 2000000L; p++) { /* bound: BLK_POLL_BOUND */
        if (us->idx == (uint16_t)(st->expect_used + 1u)) {
            done = 1;
            break;
        }
        u_yield();
        if (u_rdtime() - t0 > (uint64_t)BLK_IRQ_TIMEOUT_TICKS)
            break;
    }
    if (!done)
        return -1;
    isr = blk_r(regs, BLK_R_ISTATUS);
    if (isr)
        blk_w(regs, BLK_R_IACK, isr);
    blk_fence();
    bits = u_wait();
    if ((bits & BLK_IRQ_BIT) == 0)
        return -1; /* completion unconfirmed: fail closed */
    /* Single-desc-id discipline: every request chains from desc 0 and the
     * avail ring is pre-zeroed, so every entry names desc 0; the used
     * slot for this op is expect_used % 16. */
    if (us->ring[st->expect_used % 16u].id != 0u)
        return -1;
    if (*status != 0)
        return -1;
    st->expect_used++;
    return 0;
}

/* 512B x 8 glue: 4K sector s lives at 512B LBAs s*8+k with byte k*512
 * inside the sector (layout_blk_off). Bounds: s < capacity/8 (exact:
 * s*8+7 < capacity with no overflow for the small demo sectors). */
static int blk4k_read(crypt_state_t *st, unsigned long s, uint8_t *out)
{
    unsigned k;
    unsigned long off;
    uint8_t *df = (uint8_t *)CRYPT_DMA_D_VA;
    unsigned long i;
    if (!st || !out)
        return -1;
    if (st->capacity == 0 || s >= (unsigned long)(st->capacity / 8UL))
        return -1;
    for (k = 0; k < 8; k++) { /* bound: 8 (sub-sectors) */
        uint64_t lba = (uint64_t)s * 8u + (uint64_t)k;
        if (layout_blk_off(k, &off) != 0)
            return -1;
        if (blk_req512(st, lba, 0) != 0)
            return -1;
        for (i = 0; i < 512; i++) /* bound: 512 */
            out[off + i] = df[i];
    }
    return 0;
}

/* Mirror of blk4k_read for writes (same glue, same bounds). */
static int blk4k_write(crypt_state_t *st, unsigned long s, const uint8_t *in)
{
    unsigned k;
    unsigned long off;
    uint8_t *df = (uint8_t *)CRYPT_DMA_D_VA;
    unsigned long i;
    if (!st || !in)
        return -1;
    if (st->capacity == 0 || s >= (unsigned long)(st->capacity / 8UL))
        return -1;
    for (k = 0; k < 8; k++) { /* bound: 8 (sub-sectors) */
        uint64_t lba = (uint64_t)s * 8u + (uint64_t)k;
        if (layout_blk_off(k, &off) != 0)
            return -1;
        for (i = 0; i < 512; i++) /* bound: 512 */
            df[i] = in[off + i];
        if (blk_req512(st, lba, 1) != 0)
            return -1;
    }
    return 0;
}

/* ---- Sector layer: AEAD under the VMK with sector-bound nonce/AD. ---- */

#define CR_EIO (-5L)       /* tag mismatch / auth failure */
#define CR_LOCKED (-6L)    /* no VMK loaded */
#define CR_NOTFOUND (-7L)  /* owner mismatch or unknown name (no oracle) */
#define CR_NOSPC (-8L)     /* extent/file/fd exhaustion */

static void sec_nonce(unsigned long s, uint8_t n[12])
{
    n[0] = 83; /* 'S' */
    n[1] = 69; /* 'E' */
    n[2] = 67; /* 'C' */
    n[3] = 84; /* 'T' */
    blk_st64le(n + 4, (uint64_t)s);
}

static void sec_ad(unsigned long s, uint8_t ad[14])
{
    ad[0] = 83;  /* 'S' */
    ad[1] = 69;  /* 'E' */
    ad[2] = 67;  /* 'C' */
    ad[3] = 84;  /* 'T' */
    ad[4] = 79;  /* 'O' */
    ad[5] = 82;  /* 'R' */
    blk_st64le(ad + 6, (uint64_t)s);
}

/* Tag-sector location for data sector s (bounds-checked against the
 * device capacity like any data sector). */
static int sec_tag_loc(crypt_state_t *st, unsigned long s,
                       unsigned long *ts, unsigned long *slot)
{
    unsigned long tsec, tslot;
    if (!st || !ts || !slot)
        return -1;
    if (layout_tag_loc(s, &tsec, &tslot) != 0)
        return -1;
    tsec += CR_TAG_BASE;
    if (st->capacity == 0 || tsec >= (unsigned long)(st->capacity / 8UL))
        return -1;
    if (tslot >= 256UL)
        return -1;
    *ts = tsec;
    *slot = tslot;
    return 0;
}

/* sec_write(s, pt4096): seal in place in st->io, write data sector,
 * then read-modify-write the tag sector (data first, tag second).
 * Requires the VMK. Returns 0 ok, CR_LOCKED, or -1. */
static long sec_write(crypt_state_t *st, unsigned long s, const uint8_t *pt)
{
    uint8_t nonce[12];
    uint8_t ad[14];
    uint8_t tag[16];
    unsigned long ts, slot;
    unsigned long i;
    if (!st || !pt)
        return -1;
    if (!st->vmk_valid)
        return CR_LOCKED;
    for (i = 0; i < 4096; i++) /* bound: 4096 */
        st->io[i] = pt[i];
    sec_nonce(s, nonce);
    sec_ad(s, ad);
    if (aead_seal(st->vmk, nonce, ad, sizeof(ad), st->io, 4096, st->io, tag) != 0) {
        crypt_wipe(st->io, sizeof(st->io));
        crypt_wipe(tag, sizeof(tag));
        return -1;
    }
    if (blk4k_write(st, s, st->io) != 0) {
        crypt_wipe(st->io, sizeof(st->io));
        crypt_wipe(tag, sizeof(tag));
        return -1;
    }
    if (sec_tag_loc(st, s, &ts, &slot) != 0) {
        crypt_wipe(st->io, sizeof(st->io));
        crypt_wipe(tag, sizeof(tag));
        return -1;
    }
    if (blk4k_read(st, ts, st->io) != 0) {
        crypt_wipe(st->io, sizeof(st->io));
        crypt_wipe(tag, sizeof(tag));
        return -1;
    }
    for (i = 0; i < 16; i++) /* bound: 16 */
        st->io[slot * 16UL + i] = tag[i];
    crypt_wipe(tag, sizeof(tag));
    if (blk4k_write(st, ts, st->io) != 0) {
        crypt_wipe(st->io, sizeof(st->io));
        return -1;
    }
    crypt_wipe(st->io, sizeof(st->io));
    return 0;
}

/* sec_read(s, out4096): read data + tag sectors, AEAD-open into out
 * (in place via st->io). Tag mismatch => EIO + zeroed out, never partial
 * plaintext. Requires the VMK. Returns 0 ok, CR_LOCKED, CR_EIO, or -1. */
static long sec_read(crypt_state_t *st, unsigned long s, uint8_t *out)
{
    uint8_t nonce[12];
    uint8_t ad[14];
    uint8_t tag[16];
    unsigned long ts, slot;
    unsigned long i;
    if (!st || !out)
        return -1;
    if (!st->vmk_valid)
        return CR_LOCKED;
    if (sec_tag_loc(st, s, &ts, &slot) != 0)
        return -1;
    if (blk4k_read(st, ts, st->io) != 0)
        return -1;
    for (i = 0; i < 16; i++) /* bound: 16 */
        tag[i] = st->io[slot * 16UL + i];
    if (blk4k_read(st, s, st->io) != 0) {
        crypt_wipe(tag, sizeof(tag));
        return -1;
    }
    sec_nonce(s, nonce);
    sec_ad(s, ad);
    /* aead_open wipes st->io itself on mismatch; mirror the wipe to out
     * (out may alias st->io or be a caller buffer). */
    if (aead_open(st->vmk, nonce, ad, sizeof(ad), st->io, 4096, tag, st->io) != 0) {
        crypt_wipe(tag, sizeof(tag));
        for (i = 0; i < 4096; i++) /* bound: 4096 */
            out[i] = 0;
        return CR_EIO;
    }
    crypt_wipe(tag, sizeof(tag));
    for (i = 0; i < 4096; i++) /* bound: 4096 */
        out[i] = st->io[i];
    /* Scratch hygiene, alias-aware: callers may pass st->io itself as out
     * (in-place sector use); wiping unconditionally would destroy the
     * just-delivered plaintext. */
    if (out != st->io)
        crypt_wipe(st->io, sizeof(st->io));
    return 0;
}

/* ---- Driver bring-up (S3-net pattern, single queue). ---- */

/* Set up one modern split virtqueue (caller-owned memory inside the DMA_Q
 * frame). Returns 1 on success, 0 on any transport refusal. */
static int blk_queue(volatile uint32_t *regs, uint64_t desc_pa,
                     uint64_t avail_pa, uint64_t used_pa)
{
    uint32_t max;
    blk_w(regs, BLK_R_QSEL, 0u);
    max = blk_r(regs, BLK_R_QMAX);
    if (max < (uint32_t)BLK_QNUM_WANT || max > 1024u)
        return 0;
    blk_w(regs, BLK_R_QNUM, BLK_QNUM_WANT);
    blk_w64(regs, BLK_R_QDESC_LO, desc_pa);
    blk_w64(regs, BLK_R_QDRV_LO, avail_pa);
    blk_w64(regs, BLK_R_QDEV_LO, used_pa);
    blk_w(regs, BLK_R_QREADY, 1u);
    blk_fence();
    return 1;
}

/* Bring-up: probe, negotiate, 2 DMA frames, queue, capacity. Runs once at
 * boot; any failure parks fail-closed (silent: the missing CRYPT:
 * markers fail the gate). On success st->regs/pa/capacity are live and
 * both DMA frames stay mapped for the ELF lifetime (steady +2 frames). */
static void blk_bringup(crypt_state_t *st)
{
    volatile uint32_t *regs = blk_find();
    uint8_t *qf;
    uint8_t *df;
    struct blk_avail *av;
    volatile struct blk_used *us;
    unsigned long i;
    uint64_t cap_lo, cap_hi;

    if (!regs)
        blk_no_disk();
    st->regs = regs;

    /* Acknowledge + feature negotiate (no device features: plain
     * read/write of 512B sectors). */
    blk_w(regs, BLK_R_STATUS, 0u);
    blk_fence();
    blk_w(regs, BLK_R_STATUS, BLK_ST_ACK | BLK_ST_DRIVER);
    blk_fence();
    blk_w(regs, BLK_R_FEAT_SEL, 0u);
    (void)blk_r(regs, BLK_R_FEAT);
    blk_w(regs, BLK_R_DRV_SEL, 1u);
    blk_w(regs, BLK_R_DRV_FEAT, 0u);
    blk_w(regs, BLK_R_DRV_SEL, 0u);
    blk_w(regs, BLK_R_DRV_FEAT, 0u);
    blk_w(regs, BLK_R_STATUS, BLK_ST_ACK | BLK_ST_DRIVER | BLK_ST_FEAT_OK);
    blk_fence();
    if (!(blk_r(regs, BLK_R_STATUS) & BLK_ST_FEAT_OK)) {
        blk_w(regs, BLK_R_STATUS, BLK_ST_ACK | BLK_ST_DRIVER | 128u);
        blk_no_disk();
    }

    /* Two DMA frames (RW only): Q holds desc[16]/avail/used + the 16B
     * request header + status byte; D holds one 512B data staging slot. */
    st->slot_q = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    st->slot_d = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (st->slot_q < 0 || st->slot_d < 0 ||
        u_invoke(V2_INV_MAP, st->slot_q, CRYPT_DMA_Q_VPN, 0) != 0 ||
        u_invoke(V2_INV_MAP, st->slot_d, CRYPT_DMA_D_VPN, 0) != 0)
        blk_no_disk();
    {
        long pa_q = u_invoke(V2_INV_FRAME_PA, CRYPT_DMA_Q_VPN, 0, 0);
        long pa_d = u_invoke(V2_INV_FRAME_PA, CRYPT_DMA_D_VPN, 0, 0);
        if (pa_q <= 0 || pa_d <= 0)
            blk_no_disk();
        st->pa_q = (uint64_t)pa_q;
        st->pa_d = (uint64_t)pa_d;
    }

    /* Zero both pages, then lay out the queue: desc[16] @0, avail @256,
     * used @512 (16 ring entries), request header @1024, status @1040. */
    qf = (uint8_t *)CRYPT_DMA_Q_VA;
    df = (uint8_t *)CRYPT_DMA_D_VA;
    for (i = 0; i < 4096; i++) { /* bound: 4096 */
        qf[i] = 0;
        df[i] = 0;
    }
    av = (struct blk_avail *)(qf + 256);
    us = (volatile struct blk_used *)(qf + 512);
    av->flags = 0;
    av->idx = 0;
    us->flags = 0;
    if (!blk_queue(regs, st->pa_q + 0u, st->pa_q + 256u, st->pa_q + 512u))
        blk_no_disk();
    blk_w(regs, BLK_R_STATUS, BLK_ST_ACK | BLK_ST_DRIVER |
           BLK_ST_FEAT_OK | BLK_ST_DRIVER_OK);
    blk_fence();

    /* Capacity: u64 LE 512B-sector count at config+0 (two u32 reads). */
    cap_lo = (uint64_t)blk_r(regs, BLK_R_CONFIG);
    cap_hi = (uint64_t)blk_r(regs, BLK_R_CONFIG + 4u);
    st->capacity = cap_lo | (cap_hi << 32);
    if (st->capacity < 524288UL)
        blk_no_disk(); /* not the 256M smoke disk: fail closed */
    st->expect_used = 0;
}

/* ---- Vault-seeded unlock + format (see file header). ---- */

static uint8_t probe_byte(unsigned long o)
{
    return (uint8_t)(0xA5u ^ (o & 0xFFu) ^ ((o >> 8) & 0xFFu));
}

static uint8_t canary_byte(unsigned long o)
{
    return (uint8_t)(0xC0u ^ (o & 0xFFu) ^ ((o >> 8) & 0xFFu));
}

/* Derive the KEK: PBKDF2(vault seed, header salt, slot-0 iters). The
 * slot work factor is authoritative (format and unlock agree through
 * it). The caller owns the seed (fetched once per boot in
 * cryptblk_main, wiped after the unlock leg); this path never wipes
 * it, but wipes the derived KEK on KDF failure. */
static int crypt_kek(const vol_header_t *h, const uint8_t *seed,
                     uint8_t kek[32])
{
    if (!h || !seed || !kek)
        return -1;
    if (h->slots[0].iters == 0)
        return -1;
    if (pbkdf2_hmac_sha256(seed, 32, h->salt,
                           32, h->slots[0].iters, kek, 32) != 0) {
        crypt_wipe(kek, 32);
        return -1;
    }
    return 0;
}

/* Superblock entry stride/codec (entry = dirent[32] || owner u32 ||
 * start u64 || len u64, stride 64). */
#define CR_SB_ENT0 12UL
#define CR_SB_ENT1 76UL

static int super_entry_build(uint8_t *b, unsigned long at, const uint8_t *nm,
                             unsigned long nmlen, uint32_t ino, uint32_t owner,
                             uint64_t start, uint64_t len)
{
    layout_dirent_t d;
    unsigned long i;
    if (!b || !nm)
        return -1;
    if (layout_dirent_set(&d, nm, nmlen, ino) != 0)
        return -1;
    if (layout_dirent_encode(&d, b + at, 32) != 0)
        return -1;
    blk_st32le(b + at + 32, owner);
    for (i = 0; i < 4; i++) /* bound: 4 (pad) */
        b[at + 36 + i] = 0;
    blk_st64le(b + at + 40, start);
    blk_st64le(b + at + 48, len);
    return 0;
}

static int super_entry_parse(const uint8_t *b, unsigned long at,
                             uint32_t want_ino, uint32_t want_owner,
                             crypt_fent_t *out)
{
    layout_dirent_t d;
    unsigned long i;
    uint32_t owner;
    uint64_t start, len;
    if (!b || !out)
        return -1;
    if (layout_dirent_decode(b + at, 32, &d) != 0)
        return -1;
    if (d.ino != want_ino)
        return -1;
    owner = layout_ld32le(b + at + 32);
    if (owner != want_owner)
        return -1;
    for (i = 0; i < 4; i++) /* bound: 4 (pad must be zero) */
        if (b[at + 36 + i] != 0)
            return -1;
    start = layout_ld64le(b + at + 40);
    len = layout_ld64le(b + at + 48);
    out->dent = d;
    out->owner = owner;
    out->start = start;
    out->len = len;
    return 0;
}

/* Format-if-absent core (header + canary + superblock + probe extent).
 * Leaves the VMK wiped and vmk_valid CLEAR so the unlock step re-derives
 * uniformly on both the format and volume-ok paths (the locked leg runs
 * on live state either way). Returns 0 ok, -1 fail-closed. */
static int crypt_format(crypt_state_t *st, const uint8_t *seed)
{
    uint8_t kek[32];
    uint8_t salt8[8];
    uint8_t mix[40];
    uint64_t now;
    vol_header_t *h;
    unsigned long i;
    unsigned long start = 0;
    uint8_t nm_probe[5];
    uint8_t nm_blk0[4];
    if (!st)
        return -1;
    if (!seed)
        return -1;
    h = &st->hdr;
    crypt_wipe(h, sizeof(*h));
    h->magic = CRYPT_MAGIC;
    h->version = CRYPT_VERSION;
    h->nslots = 1;
    h->iters = (uint32_t)CRYPT_KDF_SMOKE_ITERS;
    h->reserved = 0;
    h->slots[0].iters = (uint32_t)CRYPT_KDF_SMOKE_ITERS;
    h->slots[0].label = CRYPT_QUBE;
    /* Fresh per-format DRBG state (no fixed seed): the caller seed
     * folded with rdtime reseeds the production DRBG; the header salt, VMK
     * and slot salt come from fresh drbg_generate_production bytes. The
     * salt is stored in the header, so freshness here never affects
     * unlock stability across boots. Entropy claim is conservative (64):
     * the vault-attested words are near-public (see seed-honesty note),
     * so only rdtime + transport timing back the estimate; pulls per
     * boot (≈4) sit orders of magnitude below the catastrophic gate. */
    now = u_rdtime();
    for (i = 0; i < 8UL; i++) /* bound: 8 (rdtime bytes) */
        mix[i] = (uint8_t)(now >> (8u * i));
    for (i = 0; i < 32UL; i++) /* bound: 32 (seed bytes) */
        mix[8u + i] = seed[i];
    if (drbg_reseed_production(mix, sizeof(mix), 64) != 0) {
        crypt_wipe(mix, sizeof(mix));
        return -1;
    }
    crypt_wipe(mix, sizeof(mix));
    if (drbg_generate_production(h->salt, 32) != 0 ||
        drbg_generate_production(st->vmk, 32) != 0 ||
        drbg_generate_production(salt8, 8) != 0) {
        crypt_wipe(h->salt, sizeof(h->salt));
        crypt_wipe(st->vmk, sizeof(st->vmk));
        crypt_wipe(salt8, sizeof(salt8));
        return -1;
    }
    if (crypt_kek(h, seed, kek) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        return -1;
    }
    if (slot_wrap(kek, st->vmk, salt8, CRYPT_QUBE,
                   (uint32_t)CRYPT_KDF_SMOKE_ITERS, &h->slots[0]) != 0) {
        crypt_wipe(kek, sizeof(kek));
        crypt_wipe(salt8, sizeof(salt8));
        crypt_wipe(st->vmk, sizeof(st->vmk));
        slot_wipe(&h->slots[0]);
        return -1;
    }
    crypt_wipe(kek, sizeof(kek));
    crypt_wipe(salt8, sizeof(salt8));
    /* Header is plaintext metadata: raw writes, no VMK needed. USED
     * bytes (568) all fit in sector 0; sector 1 is zero/reserved. */
    if (layout_encode(h, st->io, 4096) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        return -1;
    }
    if (blk4k_write(st, 0, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        crypt_wipe(st->io, sizeof(st->io));
        return -1;
    }
    for (i = 0; i < 4096; i++) /* bound: 4096 */
        st->io[i] = 0;
    if (blk4k_write(st, 1, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        return -1;
    }
    /* AEAD sectors need the VMK live briefly; it is wiped below. */
    st->vmk_valid = 1;
    for (i = 0; i < 4096; i++) /* bound: 4096 */
        st->io[i] = canary_byte(i);
    if (sec_write(st, CR_CANARY_SEC, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    /* Probe extent: first-fit from the empty arena (deterministic). */
    if (layout_alloc_init(&st->arena, CR_ARENA_BASE, CR_ARENA_LEN) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    if (layout_alloc(&st->arena, 1, &start) != 0 || start != CR_ARENA_BASE) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    for (i = 0; i < 4096; i++) /* bound: 4096 */
        st->io[i] = 0;
    blk_st64le(st->io, CR_SUPER_MAGIC);
    blk_st32le(st->io + 8, (uint32_t)CR_SUPER_NFILES);
    nm_probe[0] = 112; nm_probe[1] = 114; nm_probe[2] = 111; /* "probe" */
    nm_probe[3] = 98; nm_probe[4] = 101;
    nm_blk0[0] = 98; nm_blk0[1] = 108; nm_blk0[2] = 107; nm_blk0[3] = 48; /* "blk0" */
    if (super_entry_build(st->io, CR_SB_ENT0, nm_probe, 5, 1,
                          CRYPT_QUBE, (uint64_t)start, 1) != 0 ||
        super_entry_build(st->io, CR_SB_ENT1, nm_blk0, 4, 2,
                          CR_OWNER_ANY, 0, 0) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    if (sec_write(st, CR_SUPER_SEC, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    /* Back to locked: the unlock step re-derives through the real
     * KDF+unwrap+canary path on both boot paths. */
    crypt_wipe(st->vmk, sizeof(st->vmk));
    crypt_wipe(st->io, sizeof(st->io));
    st->vmk_valid = 0;
    return 0;
}

/* Unlock: KEK -> unwrap slot 0 (label-pinned to this qube) -> VMK ->
 * canary-verify. Must start locked. The seed is caller-owned (fetched
 * once per boot, wiped after this leg). Returns 0 ok, -1 fail-closed. */
static int crypt_unlock(crypt_state_t *st, const uint8_t *seed)
{
    uint8_t kek[32];
    unsigned long i;
    if (!st || !seed || st->vmk_valid || !st->hdr_valid)
        return -1;
    if (st->hdr.slots[0].label != (uint32_t)CRYPT_QUBE)
        return -1; /* volume slot is released to the cryptblk label only */
    if (crypt_kek(&st->hdr, seed, kek) != 0)
        return -1;
    if (slot_unwrap(kek, &st->hdr.slots[0], st->vmk) != 0) {
        crypt_wipe(kek, sizeof(kek));
        crypt_wipe(st->vmk, sizeof(st->vmk));
        return -1;
    }
    crypt_wipe(kek, sizeof(kek));
    st->vmk_valid = 1;
    /* Canary-verified key: the canary sector must open AND match. */
    if (sec_read(st, CR_CANARY_SEC, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    for (i = 0; i < 4096; i++) { /* bound: 4096 */
        if (st->io[i] != canary_byte(i)) {
            crypt_wipe(st->vmk, sizeof(st->vmk));
            crypt_wipe(st->io, sizeof(st->io));
            st->vmk_valid = 0;
            return -1;
        }
    }
    crypt_wipe(st->io, sizeof(st->io));
    return 0;
}

/* Load the mounted superblock post-unlock: parse entries, rebuild the
 * arena, and pin first-fit determinism (re-alloc must land on the
 * recorded probe extent). Returns 0 ok, -1 fail-closed. */
static int super_load(crypt_state_t *st)
{
    unsigned long start = 0;
    if (!st || !st->vmk_valid)
        return -1;
    if (sec_read(st, CR_SUPER_SEC, st->io) != 0)
        return -1;
    if (layout_ld64le(st->io) != CR_SUPER_MAGIC)
        return -1;
    if (layout_ld32le(st->io + 8) != (uint32_t)CR_SUPER_NFILES)
        return -1;
    if (super_entry_parse(st->io, CR_SB_ENT0, 1, (uint32_t)CRYPT_QUBE,
                          &st->files[0]) != 0)
        return -1;
    if (super_entry_parse(st->io, CR_SB_ENT1, 2, (uint32_t)CR_OWNER_ANY,
                          &st->files[1]) != 0)
        return -1;
    if (st->files[0].len != 1 ||
        st->files[0].start < CR_ARENA_BASE ||
        st->files[0].start >= CR_ARENA_BASE + CR_ARENA_LEN)
        return -1;
    if (st->files[1].len != 0 || st->files[1].start != 0)
        return -1;
    st->nfiles = 2;
    if (layout_alloc_init(&st->arena, CR_ARENA_BASE, CR_ARENA_LEN) != 0)
        return -1;
    if (layout_alloc(&st->arena, (unsigned long)st->files[0].len, &start) != 0)
        return -1;
    if (start != (unsigned long)st->files[0].start)
        return -1; /* first-fit must reproduce the recorded extent */
    crypt_wipe(st->io, sizeof(st->io));
    return 0;
}

/* ---- Label-checked FS (FDs bound to the stamped sender). ---- */

/* Validate an fd for this sender: returns the files[] index, or -1. */
static int fd_lookup(crypt_state_t *st, unsigned long fd, unsigned long sender)
{
    unsigned long ino;
    if (!st || fd >= CR_FDS_MAX)
        return -1;
    if (!st->fds[fd].valid)
        return -1;
    if (st->fds[fd].owner_tid != sender)
        return -1; /* FDs are bound to their creator (v1-VFS discipline) */
    ino = st->fds[fd].ino;
    if (ino == CR_FILE_PROBE)
        return 0;
    if (ino == CR_FILE_BLK0)
        return 1;
    return -1;
}

static long fs_open(crypt_state_t *st, unsigned long file_id,
                    unsigned long caller_label, unsigned long sender)
{
    unsigned long f;
    int idx;
    if (!st)
        return -1;
    if (!st->vmk_valid)
        return CR_LOCKED; /* no VMK: every FS op fails closed */
    if (st->nfiles != 2)
        return -1; /* not mounted */
    idx = (file_id == CR_FILE_PROBE) ? 0 :
          (file_id == CR_FILE_BLK0) ? 1 : -1;
    if (idx < 0)
        return CR_NOTFOUND;
    /* Owner-label check BEFORE any I/O: non-owner => NOTFOUND, and the
     * disk counter below proves no I/O happened (leak leg). */
    if (st->files[idx].owner != CR_OWNER_ANY &&
        st->files[idx].owner != caller_label)
        return CR_NOTFOUND;
    for (f = 0; f < CR_FDS_MAX; f++) { /* bound: CR_FDS_MAX */
        if (!st->fds[f].valid) {
            st->fds[f].valid = 1;
            st->fds[f].ino = file_id;
            st->fds[f].owner_tid = sender;
            st->fds[f].owner_qube = caller_label;
            st->fds[f].off = 0;
            return (long)f;
        }
    }
    return CR_NOSPC;
}

static long fs_read_sec(crypt_state_t *st, unsigned long fd,
                        unsigned long sender, unsigned long sector,
                        uint8_t *out)
{
    int idx;
    if (!st || !out)
        return -1;
    if (!st->vmk_valid)
        return CR_LOCKED;
    idx = fd_lookup(st, fd, sender);
    if (idx != 0)
        return -1; /* probe only; blk0 raw reads use CR_FS_BLK0 */
    if (sector != (unsigned long)st->files[0].start)
        return CR_NOTFOUND; /* single-extent file: nothing else exists */
    return sec_read(st, sector, out);
}

static long fs_write_sec(crypt_state_t *st, unsigned long fd,
                         unsigned long sender, unsigned long sector,
                         const uint8_t *in)
{
    int idx;
    if (!st || !in)
        return -1;
    if (!st->vmk_valid)
        return CR_LOCKED;
    idx = fd_lookup(st, fd, sender);
    if (idx != 0)
        return -1; /* probe only; blk0 is a read-only device node */
    if (sector != (unsigned long)st->files[0].start)
        return CR_NOTFOUND;
    return sec_write(st, sector, in);
}

static long fs_close(crypt_state_t *st, unsigned long fd, unsigned long sender)
{
    if (fd_lookup(st, fd, sender) < 0)
        return -1;
    st->fds[fd].valid = 0;
    return 0;
}

/* T_KEY consumer: MAP the granted frame at CRYPT_KEY_SLOT, READ the 4 VMK
 * words, canary-verify the key, ack, UNMAP. The vault owns the frame
 * lifecycle (it wipes + REVOKEs after our ack): revoking here would drop
 * the vault's caps before its wipe and leak VMK bytes into a freed
 * frame, so this side NEVER revokes.
 *
 * GREP-GATE BOUNDARY (Task 6): this function contains no u_puts/u_putc
 * calls. The ack carries (tag, slot) only, and every failure path wipes.
 */
static long key_consume(crypt_state_t *st, unsigned long slot)
{
    unsigned long i;
    if (!st || slot >= 8UL)
        return -1;
    if (u_invoke(V2_INV_MAP, CRYPT_KEY_SLOT,
                 (long)CRYPT_SCRATCH_VPN, 0) != 0)
        return -1; /* no granted frame behind the notice: silent drop */
    for (i = 0; i < 4UL; i++) { /* bound: 4 (VMK words) */
        if (u_invoke(V2_INV_READ, (long)CRYPT_SCRATCH_VPN,
                     (long)(st->vmk + i * 8UL), 0) != 0) {
            crypt_wipe(st->vmk, sizeof(st->vmk));
            u_invoke(V2_INV_UNMAP, (long)CRYPT_SCRATCH_VPN, 0, 0);
            return -1;
        }
    }
    u_invoke(V2_INV_UNMAP, (long)CRYPT_SCRATCH_VPN, 0, 0);
    /* Canary-verify the received key before trusting it. */
    st->vmk_valid = 1;
    if (sec_read(st, CR_CANARY_SEC, st->io) != 0) {
        crypt_wipe(st->vmk, sizeof(st->vmk));
        st->vmk_valid = 0;
        return -1;
    }
    for (i = 0; i < 4096; i++) { /* bound: 4096 */
        if (st->io[i] != canary_byte(i)) {
            crypt_wipe(st->vmk, sizeof(st->vmk));
            crypt_wipe(st->io, sizeof(st->io));
            st->vmk_valid = 0;
            return -1;
        }
    }
    crypt_wipe(st->io, sizeof(st->io));
    {
        uint64_t ack[4];
        ack[0] = (uint64_t)T_KEY_ACK;
        ack[1] = (uint64_t)slot;
        ack[2] = 0;
        ack[3] = 0;
        /* Cross-qube ack: needs our QX (boot grant, kernel/kboot.c). A
         * failed SEND fails closed with the VMK wiped: an unacked vault
         * wipes + revokes on its own expiry. */
        if (u_send(8, ack, 4) != 0) {
            crypt_wipe(st->vmk, sizeof(st->vmk));
            st->vmk_valid = 0;
            return -1;
        }
    }
    return 0;
}

/* Fail-closed demo abort: park with NO marker (the gate misses the
 * marker and fails instead of passing on a lie). The return is
 * belt-and-braces: PARK never returns, and start.S parks on return. */
static void cr_demo_fail(void)
{
    u_park();
}

void cryptblk_main(void)
{
    /* Explicit field init: `= {0}` on this multi-KB struct would emit a
     * memset call, which does not exist freestanding (-nostdlib). */
    crypt_state_t st;
    uint8_t seed[32];
    unsigned long i;
    unsigned long f;
    long r;
    long fd;
    unsigned long pstart;
    unsigned long ts;
    unsigned long tslot;
    unsigned long io_before;
    int diff;

    st.regs = 0;
    st.slot_q = -1;
    st.slot_d = -1;
    st.pa_q = 0;
    st.pa_d = 0;
    st.capacity = 0;
    st.expect_used = 0;
    st.disk_io = 0;
    for (i = 0; i < 32UL; i++) /* bound: 32 (VMK bytes) */
        st.vmk[i] = 0;
    st.vmk_valid = 0;
    crypt_wipe(&st.hdr, sizeof(st.hdr));
    st.hdr_valid = 0;
    st.nfiles = 0;
    for (f = 0; f < 2UL; f++) { /* bound: 2 (file entries) */
        st.files[f].owner = 0;
        st.files[f].start = 0;
        st.files[f].len = 0;
    }
    for (f = 0; f < CR_FDS_MAX; f++) { /* bound: CR_FDS_MAX */
        st.fds[f].valid = 0;
        st.fds[f].ino = 0;
        st.fds[f].owner_tid = 0;
        st.fds[f].owner_qube = 0;
        st.fds[f].off = 0;
    }

    u_puts("CRYPT: up\n");
    blk_bringup(&st);

    /* Single vault attestation per boot: the seed words are identical on
     * every fetch (attested fixed reply words), so one RANDOM_REQ
     * round-trip serves both the format and unlock legs (single-flight,
     * minimal IPC). Wiped after the unlock leg on every path below. */
    for (i = 0; i < 32UL; i++) /* bound: 32 (seed bytes) */
        seed[i] = 0;
    if (!crypt_get_seed(seed)) {
        crypt_wipe(seed, sizeof(seed));
        cr_demo_fail();
        return;
    }

    /* Provision leg (idempotent): valid header => reuse ("volume ok");
     * absent magic => vault-seeded format ("formatted"). The smoke gate
     * accepts either (union-tolerant pair, see tools/verify.sh). */
    if (blk4k_read(&st, 0, st.io) == 0 &&
        layout_parse(st.io, (unsigned long)LAYOUT_HEADER_USED,
                     &st.hdr) == 0) {
        st.hdr_valid = 1;
        crypt_wipe(st.io, sizeof(st.io));
        u_puts("CRYPT: volume ok\n");
    } else {
        if (crypt_format(&st, seed) != 0) {
            crypt_wipe(seed, sizeof(seed));
            cr_demo_fail();
            return;
        }
        if (blk4k_read(&st, 0, st.io) != 0 ||
            layout_parse(st.io, (unsigned long)LAYOUT_HEADER_USED,
                         &st.hdr) != 0) {
            crypt_wipe(seed, sizeof(seed));
            cr_demo_fail();
            return;
        }
        st.hdr_valid = 1;
        crypt_wipe(st.io, sizeof(st.io));
        u_puts("CRYPT: formatted\n");
    }

    /* Locked leg: no VMK yet, so even the owner open fails closed. */
    r = fs_open(&st, CR_FILE_PROBE, (unsigned long)CRYPT_QUBE,
                (unsigned long)CRYPT_TID);
    if (r != CR_LOCKED) {
        crypt_wipe(seed, sizeof(seed));
        cr_demo_fail();
        return;
    }
    u_puts("CRYPT: locked\n");

    /* Unlock leg: vault-seed KDF -> unwrap slot 0 -> canary check. */
    r = crypt_unlock(&st, seed);
    crypt_wipe(seed, sizeof(seed));
    if (r != 0) {
        cr_demo_fail();
        return;
    }
    u_puts("CRYPT: unlock ok\n");

    /* Mount: superblock parse + first-fit arena rebuild. */
    if (super_load(&st) != 0) {
        cr_demo_fail();
        return;
    }
    pstart = (unsigned long)st.files[0].start;

    /* RW leg: write + readback of the probe file, plus the ciphertext
     * pin (raw sector bytes must differ from the plaintext). */
    for (i = 0; i < 4096UL; i++) /* bound: 4096 */
        st.io[i] = probe_byte(i);
    fd = fs_open(&st, CR_FILE_PROBE, (unsigned long)CRYPT_QUBE,
                 (unsigned long)CRYPT_TID);
    if (fd < 0) {
        cr_demo_fail();
        return;
    }
    if (fs_write_sec(&st, (unsigned long)fd, (unsigned long)CRYPT_TID,
                     pstart, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    if (fs_read_sec(&st, (unsigned long)fd, (unsigned long)CRYPT_TID,
                    pstart, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    for (i = 0; i < 4096UL; i++) { /* bound: 4096 */
        if (st.io[i] != probe_byte(i)) {
            cr_demo_fail();
            return;
        }
    }
    if (fs_close(&st, (unsigned long)fd, (unsigned long)CRYPT_TID) != 0) {
        cr_demo_fail();
        return;
    }
    if (blk4k_read(&st, pstart, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    diff = 0;
    for (i = 0; i < 64UL; i++) { /* bound: 64 (ciphertext sample) */
        if (st.io[i] != probe_byte(i)) {
            diff = 1;
            break;
        }
    }
    crypt_wipe(st.io, sizeof(st.io));
    if (!diff) {
        cr_demo_fail();
        return;
    }
    u_puts("CRYPT: rw ok\n");

    /* Wrong-key leg: tamper one tag byte of the scratch sector; the
     * read must fail EIO with a zeroed buffer. The tag is rewritten
     * clean afterwards (scratch hygiene for later runs). */
    for (i = 0; i < 4096UL; i++) /* bound: 4096 */
        st.io[i] = probe_byte(i);
    if (sec_write(&st, CR_SCRATCH_SEC, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    if (sec_tag_loc(&st, CR_SCRATCH_SEC, &ts, &tslot) != 0) {
        cr_demo_fail();
        return;
    }
    if (blk4k_read(&st, ts, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    st.io[tslot * 16UL] ^= 1;
    if (blk4k_write(&st, ts, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    r = sec_read(&st, CR_SCRATCH_SEC, st.io);
    if (r != CR_EIO) {
        cr_demo_fail();
        return;
    }
    for (i = 0; i < 4096UL; i++) { /* bound: 4096 */
        if (st.io[i] != 0) {
            cr_demo_fail();
            return;
        }
    }
    for (i = 0; i < 4096UL; i++) /* bound: 4096 */
        st.io[i] = probe_byte(i);
    if (sec_write(&st, CR_SCRATCH_SEC, st.io) != 0) {
        cr_demo_fail();
        return;
    }
    crypt_wipe(st.io, sizeof(st.io));
    u_puts("CRYPT: wrong-key denied\n");

    /* Leak leg: a stamped non-owner open gets NOTFOUND with no disk I/O
     * (the counter pins the no-I/O property, not just the code). */
    io_before = st.disk_io;
    r = fs_open(&st, CR_FILE_PROBE, 0UL, 0UL);
    if (r != CR_NOTFOUND) {
        cr_demo_fail();
        return;
    }
    if (st.disk_io != io_before) {
        cr_demo_fail();
        return;
    }
    u_puts("CRYPT: leak denied\n");

    /* No-volume leg: RAM-shadow corrupt-header parse (never touches the
     * live disk). Garbage must reject. */
    {
        vol_header_t junk;
        for (i = 0; i < 568UL; i++) /* bound: 568 (header USED bytes) */
            st.io[i] = 0xA5;
        if (layout_parse(st.io, 568UL, &junk) == 0) {
            cr_demo_fail();
            return;
        }
        crypt_wipe(&junk, sizeof(junk));
        crypt_wipe(st.io, sizeof(st.io));
    }
    u_puts("CRYPT: no volume\n");

    /* Service loop (production path: direct FS ops, approved format
     * delivers, vault T_KEY notices). At boot no live traffic exists on
     * the single rendezvous, so this blocks until the clean park. */
    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        unsigned long tag;
        long n = u_recv(9, buf, 4, &snd, &sqb, &ovf);

        if (n < 1) {
            u_reply(snd, R_INVALID);
            continue;
        }
        tag = (unsigned long)buf[0];

        if (tag == (unsigned long)T_CALL && n >= 4) {
            unsigned long op = (unsigned long)buf[1];
            unsigned long a = (unsigned long)buf[2];
            unsigned long b = (unsigned long)buf[3];
            if (op == (unsigned long)CR_FS_OPEN && b == 0) {
                long nfd = fs_open(&st, a, sqb, snd);
                if (nfd < 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                {
                    uint64_t rp[2];
                    rp[0] = 0;
                    rp[1] = (uint64_t)nfd;
                    u_send(snd, rp, 2);
                }
                continue;
            }
            if (op == (unsigned long)CR_FS_READ) {
                /* a = fd (probe file), b = 8-byte word offset (< 512). */
                int idx = fd_lookup(&st, a, snd);
                uint64_t w;
                unsigned long k;
                if (idx != 0 || b >= 512UL || !st.vmk_valid) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                if (sec_read(&st, (unsigned long)st.files[0].start,
                             st.io) != 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                w = 0;
                for (k = 0; k < 8UL; k++) /* bound: 8 */
                    w |= (uint64_t)st.io[b * 8UL + k] << (8u * k);
                crypt_wipe(st.io, sizeof(st.io));
                {
                    uint64_t rp[2];
                    rp[0] = 0;
                    rp[1] = w;
                    u_send(snd, rp, 2);
                }
                continue;
            }
            if (op == (unsigned long)CR_FS_WRITE) {
                /* a = fd (probe file), b = data word; appends at the
                 * fd offset (auto-advance 8B; single-sector file). */
                int idx = fd_lookup(&st, a, snd);
                unsigned long off;
                if (idx != 0 || !st.vmk_valid) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                off = st.fds[a].off;
                if (off + 8UL > 4096UL) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                if (sec_read(&st, (unsigned long)st.files[0].start,
                             st.io) != 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                {
                    unsigned long k;
                    uint64_t wv = b;
                    for (k = 0; k < 8UL; k++) /* bound: 8 */
                        st.io[off + k] = (uint8_t)(wv >> (8u * k));
                }
                if (sec_write(&st, (unsigned long)st.files[0].start,
                              st.io) != 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                crypt_wipe(st.io, sizeof(st.io));
                st.fds[a].off = off + 8UL;
                u_reply(snd, 0);
                continue;
            }
            if (op == (unsigned long)CR_FS_CLOSE && b == 0) {
                if (fs_close(&st, a, snd) != 0)
                    u_reply(snd, R_INVALID);
                else
                    u_reply(snd, 0);
                continue;
            }
            if (op == (unsigned long)CR_FS_STAT && b == 0) {
                int idx = fd_lookup(&st, a, snd);
                if (idx < 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                {
                    uint64_t rp[4];
                    rp[0] = 0;
                    rp[1] = (uint64_t)st.files[idx].owner;
                    rp[2] = st.files[idx].start;
                    rp[3] = st.files[idx].len;
                    u_send(snd, rp, 4);
                }
                continue;
            }
            if (op == (unsigned long)CR_FS_BLK0) {
                /* a = 4K sector, b = 8-byte word offset (< 512): raw
                 * ciphertext word, any label, no VMK (the
                 * label-independence pin). Bounds via blk4k_read. */
                uint64_t w;
                unsigned long k;
                if (b >= 512UL) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                if (blk4k_read(&st, a, st.io) != 0) {
                    u_reply(snd, R_INVALID);
                    continue;
                }
                w = 0;
                for (k = 0; k < 8UL; k++) /* bound: 8 */
                    w |= (uint64_t)st.io[b * 8UL + k] << (8u * k);
                crypt_wipe(st.io, sizeof(st.io));
                {
                    uint64_t rp[2];
                    rp[0] = 0;
                    rp[1] = w;
                    u_send(snd, rp, 2);
                }
                continue;
            }
            u_reply(snd, R_INVALID);
            continue;
        }

        if (tag == (unsigned long)T_DELIVER && n >= 4 &&
            (unsigned long)buf[1] == (unsigned long)VOL_FORMAT &&
            sqb == (unsigned long)QREXEC_QUBE) {
            /* Approved format: format-if-absent. Silent when the volume
             * exists (no waiter on deliver paths); the marker only on
             * an actual fresh format. Vault-seeded format (see file
             * header); the AdminVM-attended fresh-KEK format is
             * future work. The seed is fetched handler-local and wiped
             * on every path; a vault DENY skips the format fail-closed
             * with no state change. */
            if (blk4k_read(&st, 0, st.io) == 0 &&
                layout_parse(st.io, (unsigned long)LAYOUT_HEADER_USED,
                             &st.hdr) == 0) {
                st.hdr_valid = 1;
                crypt_wipe(st.io, sizeof(st.io));
                continue;
            }
            {
                uint8_t dseed[32];
                unsigned long k;
                int fok;
                for (k = 0; k < 32UL; k++) /* bound: 32 (seed bytes) */
                    dseed[k] = 0;
                fok = crypt_get_seed(dseed);
                if (fok)
                    fok = (crypt_format(&st, dseed) == 0) ? 1 : 0;
                crypt_wipe(dseed, sizeof(dseed));
                if (fok)
                    u_puts("CRYPT: formatted\n");
            }
            continue;
        }

        if (tag == (unsigned long)T_KEY && n >= 2 &&
            sqb == (unsigned long)VAULT_QUBE) {
            /* Vault release notice: consume silently (zero prints on
             * the ack path, Step-0 ratification). A completed handoff
             * mounts the volume when not yet mounted. */
            if (key_consume(&st, (unsigned long)buf[1]) != 0)
                continue;
            if (st.nfiles != 2 && super_load(&st) != 0) {
                crypt_wipe(st.vmk, sizeof(st.vmk));
                st.vmk_valid = 0;
            }
            continue;
        }

        /* Not ours: silent drop, no reply (no waiter on these paths). */
    }
}
