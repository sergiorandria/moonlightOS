/* tests/test_elf.c - host test for the kernel ELF front end + loader
 * (kernel/elf.h v2_elf_plan, kernel/elf.c v2_elf_load).
 *
 * Build with sanitizers (see `make -C kernel hosttest` / tools/verify.sh):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all ...
 *
 * What it proves:
 *   - a well-formed image plans and loads; bytes, BSS zeroing, rights,
 *     entry and brk are exact
 *   - every real userspace ELF named on the command line still loads
 *   - each malformed-header class is rejected BEFORE any frame is taken
 *   - a load that fails halfway (pool or table exhaustion) rolls back to
 *     the exact prior state: free-frame count, cap slots, mappings
 *   - exhaustive single-field mutation and seeded random mutation never
 *     crash, never leak a frame, and never produce a W+X mapping
 *
 * Frames are individually malloc'd pages, so ASan catches a one-byte
 * overrun of any frame (a flat array would hide it inside the pool). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kernel/frames.h"

#define PAGE_SIZE_HOST 4096

static uint8_t *frame_mem[V2_FRAMES_MAX];
#define V2_FRAME_PTR(f) ((volatile uint8_t *)frame_mem[(f)])

static v2_frames_t pool;

int frame_alloc_slot(v2_caps_t *caps, unsigned long tid)
{
    int f = v2_frames_alloc(&pool, tid);
    int i;
    if (f < 0)
        return V2_ERR_OVERFLOW;
    memset(frame_mem[f], 0, PAGE_SIZE_HOST);
    for (i = 0; i < V2_CAP_SLOTS; i++) {
        if (!caps->caps[tid][i].valid) {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i;
        }
    }
    (void)v2_frames_release(&pool, (unsigned long)f);
    return V2_ERR_OVERFLOW;
}

void frame_release(unsigned long frame)
{
    if (v2_frames_is_allocated(&pool, frame)) {
        memset(frame_mem[frame], 0, PAGE_SIZE_HOST);
        (void)v2_frames_release(&pool, frame);
    }
}

#include "../kernel/elf.c"

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

#define IMG_MAX 0x4000
#define TID 3UL

typedef struct {
    uint8_t b[IMG_MAX];
    size_t size;
} img_t;

static elf_ehdr_t *EH(img_t *m) { return (elf_ehdr_t *)m->b; }
static elf_phdr_t *PH(img_t *m, int i) { return (elf_phdr_t *)(m->b + 64) + i; }

/* Two segments: RX (2 pages, file-backed) and RW (2 pages, 0x100 file
 * bytes + BSS). Entry inside the RX file bytes. */
static void good_image(img_t *m)
{
    size_t i;
    memset(m->b, 0, sizeof m->b);
    for (i = 0x1000; i < 0x3100; i++)
        m->b[i] = (uint8_t)(i * 7u + 3u);
    m->size = 0x3100;
    m->b[0] = 0x7F; m->b[1] = 'E'; m->b[2] = 'L'; m->b[3] = 'F';
    m->b[4] = ELF_CLASS_64; m->b[5] = ELF_DATA_LSB; m->b[6] = ELF_VERSION;
    EH(m)->e_type = ELF_TYPE_EXEC;
    EH(m)->e_machine = ELF_MACHINE_RISCV;
    EH(m)->e_version = ELF_VERSION;
    EH(m)->e_entry = V2_U_END + 0x10;
    EH(m)->e_phoff = 64;
    EH(m)->e_phentsize = sizeof(elf_phdr_t);
    EH(m)->e_phnum = 2;
    PH(m, 0)->p_type = ELF_PT_LOAD;
    PH(m, 0)->p_flags = ELF_PF_R | ELF_PF_X;
    PH(m, 0)->p_offset = 0x1000;
    PH(m, 0)->p_vaddr = V2_U_END;
    PH(m, 0)->p_filesz = 0x1800;
    PH(m, 0)->p_memsz = 0x1800;
    PH(m, 0)->p_align = 0x1000;
    PH(m, 1)->p_type = ELF_PT_LOAD;
    PH(m, 1)->p_flags = ELF_PF_R | ELF_PF_W;
    PH(m, 1)->p_offset = 0x3000;
    PH(m, 1)->p_vaddr = V2_U_END + 0x2000;
    PH(m, 1)->p_filesz = 0x100;
    PH(m, 1)->p_memsz = 0x1800;
    PH(m, 1)->p_align = 0x1000;
}

static void reset(v2_caps_t *caps)
{
    int i;
    v2_caps_init(caps, V2_CAP_THREADS);
    for (i = 0; i < V2_CAP_SLOTS; i++) /* thread 0's init roots are not ours */
        caps->caps[0][i].valid = 0;
    v2_frames_init(&pool);
}

static int load(const img_t *m, v2_caps_t *caps, uint64_t *entry, uint64_t *brk)
{
    return v2_elf_load(m->b, m->size, caps, TID, entry, brk);
}

static int n_rejects;

/* Reject case: plan must fail and a load must not take a single frame. */
static void expect_reject(const char *what, img_t *m)
{
    v2_elf_plan_t plan;
    v2_caps_t caps;
    uint64_t e, b;
    unsigned long before;
    n_rejects++;
    reset(&caps);
    before = v2_frames_free_count(&pool);
    if (v2_elf_plan(m->b, m->size, &plan) == V2_OK) {
        printf("FAIL: %s accepted\n", what);
        exit(1);
    }
    CHECK(load(m, &caps, &e, &b) != V2_OK);
    CHECK(v2_frames_free_count(&pool) == before);
    CHECK(v2_vm_find(&caps, TID, 0) < 0);
}

static unsigned long valid_caps(const v2_caps_t *c, unsigned long t)
{
    unsigned long n = 0;
    int i;
    for (i = 0; i < V2_CAP_SLOTS; i++)
        n += c->caps[t][i].valid ? 1UL : 0UL;
    return n;
}

static unsigned long valid_maps(const v2_caps_t *c, unsigned long t)
{
    unsigned long n = 0;
    int i;
    for (i = 0; i < V2_VPN_SLOTS; i++)
        n += c->vm[t][i].valid ? 1UL : 0UL;
    return n;
}

static void test_good(void)
{
    img_t m;
    v2_caps_t caps;
    uint64_t entry = 0, brk = 0;
    int i;

    good_image(&m);
    reset(&caps);
    CHECK(load(&m, &caps, &entry, &brk) == V2_OK);
    CHECK(entry == V2_U_END + 0x10);
    CHECK(brk == V2_U_END + 0x4000); /* RW seg ends at +0x3800 -> page up */
    CHECK(valid_maps(&caps, TID) == 4);
    CHECK(valid_caps(&caps, TID) == 4);
    CHECK(v2_frames_free_count(&pool) == (unsigned long)(V2_FRAMES_MAX - 1 - 4));
    CHECK(v2_vm_noexec(&caps));

    /* vpn 0,1 = RX (R|X, never W); vpn 2,3 = RW (never X). */
    for (i = 0; i < 4; i++) {
        int s = v2_vm_find(&caps, TID, (unsigned long)i);
        CHECK(s >= 0);
        CHECK(caps.vm[TID][s].rights == (i < 2 ? (V2_RIGHT_R | V2_RIGHT_X) : V2_RIGHT_RW));
    }
    /* Bytes: page 0 = file 0x1000..0x1fff, page 1 = 0x2000..0x27ff then 0. */
    {
        int s0 = v2_vm_find(&caps, TID, 0), s1 = v2_vm_find(&caps, TID, 1);
        int s2 = v2_vm_find(&caps, TID, 2), s3 = v2_vm_find(&caps, TID, 3);
        const uint8_t *p0 = frame_mem[caps.vm[TID][s0].frame];
        const uint8_t *p1 = frame_mem[caps.vm[TID][s1].frame];
        const uint8_t *p2 = frame_mem[caps.vm[TID][s2].frame];
        const uint8_t *p3 = frame_mem[caps.vm[TID][s3].frame];
        size_t b;
        for (b = 0; b < 4096; b++)
            CHECK(p0[b] == m.b[0x1000 + b]);
        for (b = 0; b < 4096; b++)
            CHECK(p1[b] == (b < 0x800 ? m.b[0x2000 + b] : 0));
        for (b = 0; b < 4096; b++)
            CHECK(p2[b] == (b < 0x100 ? m.b[0x3000 + b] : 0));
        for (b = 0; b < 4096; b++)
            CHECK(p3[b] == 0);
    }
    printf("good image: PASS\n");
}

static void test_rejects(void)
{
    img_t m;

    good_image(&m); m.b[0] = 0x7E;                       expect_reject("bad magic", &m);
    good_image(&m); m.b[4] = 1;                          expect_reject("32-bit class", &m);
    good_image(&m); m.b[5] = 2;                          expect_reject("big endian", &m);
    good_image(&m); m.b[6] = 2;                          expect_reject("ident version", &m);
    good_image(&m); m.b[7] = 3;                          expect_reject("osabi", &m);
    good_image(&m); EH(&m)->e_type = 3;                  expect_reject("ET_DYN", &m);
    good_image(&m); EH(&m)->e_machine = 62;              expect_reject("x86-64", &m);
    good_image(&m); EH(&m)->e_version = 2;               expect_reject("e_version", &m);
    good_image(&m); EH(&m)->e_phentsize = 32;            expect_reject("phentsize", &m);
    good_image(&m); EH(&m)->e_phnum = 0;                 expect_reject("phnum 0", &m);
    good_image(&m); EH(&m)->e_phnum = V2_ELF_MAX_PHNUM + 1; expect_reject("phnum too big", &m);
    good_image(&m); EH(&m)->e_phoff = 0xFFFFFFFFFFFFFFF0ULL; expect_reject("phoff wraps", &m);
    good_image(&m); EH(&m)->e_phoff = m.size;            expect_reject("phoff at EOF", &m);
    good_image(&m); EH(&m)->e_phoff = m.size - 56;       EH(&m)->e_phnum = 2; expect_reject("phtable runs past EOF", &m);
    good_image(&m); m.size = 63;                         expect_reject("short ehdr", &m);
    good_image(&m); PH(&m, 0)->p_filesz = 0x2000;        expect_reject("filesz > memsz", &m);
    good_image(&m); PH(&m, 1)->p_offset = 0xFFFFFFFFFFFFFFF0ULL; PH(&m, 1)->p_filesz = 0x20; PH(&m, 1)->p_memsz = 0x20;
                                                         expect_reject("offset+filesz wraps", &m);
    good_image(&m); PH(&m, 1)->p_offset = 0x3080;        expect_reject("file range past EOF", &m);
    good_image(&m); PH(&m, 0)->p_vaddr = V2_U_END - 0x1000; expect_reject("below frame window", &m);
    good_image(&m); PH(&m, 0)->p_vaddr = V2_U_END + 0x10;   expect_reject("unaligned vaddr", &m);
    good_image(&m); PH(&m, 1)->p_vaddr = V2_U_END + (uint64_t)V2_VPN_SLOTS * 4096; expect_reject("past window", &m);
    good_image(&m); PH(&m, 1)->p_vaddr = 0xFFFFFFFFFFFFF000ULL; expect_reject("vaddr near 2^64", &m);
    good_image(&m); PH(&m, 1)->p_memsz = (uint64_t)V2_VPN_SLOTS * 4096 + 1; expect_reject("memsz too big", &m);
    good_image(&m); PH(&m, 1)->p_memsz = 0xFFFFFFFFFFFFFFFFULL; expect_reject("memsz 2^64-1", &m);
    good_image(&m); PH(&m, 1)->p_flags = ELF_PF_R | ELF_PF_W | ELF_PF_X; expect_reject("W+X", &m);
    good_image(&m); PH(&m, 1)->p_flags = 0;              expect_reject("no permission bits", &m);
    good_image(&m); PH(&m, 1)->p_align = 0;              expect_reject("align 0", &m);
    good_image(&m); PH(&m, 1)->p_align = 3;              expect_reject("align not pow2", &m);
    good_image(&m); PH(&m, 1)->p_vaddr = V2_U_END + 0x1000; expect_reject("overlapping segments", &m);
    good_image(&m); EH(&m)->e_entry = V2_U_END + 0x1800; expect_reject("entry past file bytes", &m);
    good_image(&m); EH(&m)->e_entry = V2_U_END + 0x2000; expect_reject("entry in data segment", &m);
    good_image(&m); EH(&m)->e_entry = V2_U_END + 0x11;   expect_reject("odd entry", &m);
    good_image(&m); EH(&m)->e_entry = 0;                 expect_reject("entry 0", &m);
    good_image(&m); PH(&m, 0)->p_type = 0; PH(&m, 1)->p_type = 0; expect_reject("no PT_LOAD", &m);
    printf("reject classes (%d): PASS\n", n_rejects);
}

/* Failure halfway through a load must restore the exact prior state. */
static void test_rollback(void)
{
    img_t m;
    v2_caps_t caps;
    uint64_t e = 0, b = 0;
    int i, held[V2_FRAMES_MAX], nheld;

    good_image(&m);

    /* (a) pool exhaustion after 2 of 4 pages */
    reset(&caps);
    nheld = 0;
    while (v2_frames_free_count(&pool) > 2)
        held[nheld++] = v2_frames_alloc(&pool, 9);
    CHECK(load(&m, &caps, &e, &b) == V2_ERR_OVERFLOW);
    CHECK(v2_frames_free_count(&pool) == 2);
    CHECK(valid_maps(&caps, TID) == 0);
    CHECK(valid_caps(&caps, TID) == 0);
    /* The two frames the failed load took are reusable. */
    CHECK(v2_frames_alloc(&pool, 4) > 0);
    CHECK(v2_frames_alloc(&pool, 4) > 0);
    CHECK(v2_frames_alloc(&pool, 4) == V2_ERR_OVERFLOW);
    for (i = 0; i < nheld; i++)
        CHECK(v2_frames_release(&pool, (unsigned long)held[i]) == V2_OK);

    /* (b) cap-table exhaustion: only 3 free slots for 4 pages */
    reset(&caps);
    for (i = 0; i < V2_CAP_SLOTS - 3; i++) {
        caps.caps[TID][i].valid = 1;
        caps.caps[TID][i].obj = 0;
        caps.caps[TID][i].rights = V2_RIGHT_R;
    }
    CHECK(load(&m, &caps, &e, &b) == V2_ERR_OVERFLOW);
    CHECK(v2_frames_free_count(&pool) == (unsigned long)(V2_FRAMES_MAX - 1));
    CHECK(valid_maps(&caps, TID) == 0);
    CHECK(valid_caps(&caps, TID) == (unsigned long)(V2_CAP_SLOTS - 3));

    /* (c) a vpn already mapped: dup is caught before allocating */
    reset(&caps);
    CHECK(load(&m, &caps, &e, &b) == V2_OK);
    {
        unsigned long used = V2_FRAMES_MAX - 1 - v2_frames_free_count(&pool);
        CHECK(load(&m, &caps, &e, &b) == V2_ERR_INVALID);
        CHECK(V2_FRAMES_MAX - 1 - v2_frames_free_count(&pool) == used);
        CHECK(valid_maps(&caps, TID) == 4);
    }
    printf("rollback: PASS\n");
}

/* Deterministic xorshift: reproducible failures. */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void mutate_and_check(img_t *m)
{
    v2_caps_t caps;
    uint64_t e = 0, b = 0;
    unsigned long before;
    int rc;
    reset(&caps);
    before = v2_frames_free_count(&pool);
    rc = load(m, &caps, &e, &b);
    if (rc != V2_OK) {
        /* No leak, no residue. */
        CHECK(v2_frames_free_count(&pool) == before);
        CHECK(valid_maps(&caps, TID) == 0);
        CHECK(valid_caps(&caps, TID) == 0);
    } else {
        v2_elf_plan_t plan;
        unsigned long pages = 0, i;
        CHECK(v2_elf_plan(m->b, m->size, &plan) == V2_OK);
        for (i = 0; i < plan.nseg; i++)
            pages += plan.seg[i].npages;
        CHECK(valid_maps(&caps, TID) == pages);
        CHECK(before - v2_frames_free_count(&pool) == pages);
        CHECK(v2_vm_noexec(&caps));
        CHECK(e >= V2_U_END);
    }
}

static void test_fuzz(void)
{
    img_t base, m;
    size_t off, v;
    unsigned long n = 0;
    static const uint8_t vals[] = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0x10, 0x20};

    good_image(&base);
    /* Exhaustive: every header + phdr byte x a set of values. */
    for (off = 0; off < 64 + 2 * sizeof(elf_phdr_t); off++) {
        for (v = 0; v < sizeof vals; v++) {
            m = base;
            m.b[off] = vals[v];
            mutate_and_check(&m);
            n++;
        }
    }
    /* Random: multi-byte mutation, random truncation. */
    for (v = 0; v < 200000; v++) {
        unsigned k = 1 + (unsigned)(rnd() % 4);
        m = base;
        while (k--)
            m.b[rnd() % (64 + 2 * sizeof(elf_phdr_t))] = (uint8_t)rnd();
        if (rnd() % 8 == 0)
            m.size = (size_t)(rnd() % (base.size + 1));
        mutate_and_check(&m);
        n++;
    }
    printf("mutation fuzz (%lu images): PASS\n", n);
}

static int load_real(const char *path)
{
    static uint8_t buf[1 << 20];
    FILE *f = fopen(path, "rb");
    size_t n;
    v2_caps_t caps;
    uint64_t e, b;
    if (!f)
        return 0;
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    reset(&caps);
    if (v2_elf_load(buf, n, &caps, TID, &e, &b) != V2_OK) {
        printf("FAIL: real ELF %s rejected\n", path);
        exit(1);
    }
    CHECK(v2_vm_noexec(&caps));
    printf("  real ELF %-34s ok (%lu pages, entry %#llx)\n", path,
           valid_maps(&caps, TID), (unsigned long long)e);
    return 1;
}

int main(int argc, char **argv)
{
    int i, real = 0;
    for (i = 0; i < V2_FRAMES_MAX; i++)
        frame_mem[i] = (uint8_t *)calloc(1, PAGE_SIZE_HOST);
    test_good();
    test_rejects();
    test_rollback();
    test_fuzz();
    for (i = 1; i < argc; i++)
        real += load_real(argv[i]);
    printf("real ELFs loaded: %d\n", real);
    for (i = 0; i < V2_FRAMES_MAX; i++)
        free(frame_mem[i]);
    printf("test_elf: ALL PASS\n");
    return 0;
}
