/* tests/test_v2caps.c — host unit test for kernel/caps.h (Stage 3).
 * Mirrors kernel/isabelle/V2_D.thy: init roots, grant/map/write/read demo,
 * mint attenuation, revoke clearing (roots survive), escalation rejection,
 * W^X (noexec + RWX ELF rejection), table-full fail-closed, confinement
 * (mint touches only the actor). */
#include <assert.h>
#include <stdio.h>

#include "../kernel/caps.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

static int caps_equal_slot(const v2_caps_t *a, const v2_caps_t *b,
                           unsigned long t, unsigned long s)
{
    return a->caps[t][s].valid == b->caps[t][s].valid &&
           a->caps[t][s].obj == b->caps[t][s].obj &&
           a->caps[t][s].rights == b->caps[t][s].rights &&
           a->caps[t][s].root == b->caps[t][s].root;
}

int main(void) {
    v2_caps_t st, snap;
    uint64_t v;
    unsigned long i;
    v2_phdr_t ph[4];
    unsigned long vpns[8];
    int ws[8];
    unsigned long n;

    /* Init: thread 0 holds root caps on frames 0..7, rest empty. */
    v2_caps_init(&st, 2);
    CHECK(st.nthreads == 2);
    for (i = 0; i < 8; i++) {
        CHECK(v2_has_cap(&st, 0, i));
        CHECK(st.caps[0][i].root);
        CHECK(st.caps[0][i].obj == i);
        CHECK(st.caps[0][i].rights == V2_RIGHT_RW);
    }
    for (i = 8; i < 16; i++)
        CHECK(!v2_has_cap(&st, 0, i));
    for (i = 0; i < 16; i++)
        CHECK(!v2_has_cap(&st, 1, i));
    CHECK(!v2_has_cap(&st, 2, 0)); /* beyond live count: fail-closed */
    CHECK(!v2_has_cap(&st, 0, 16));

    /* No access before any grant/map (mirrors d_init_noaccess). */
    CHECK(v2_write(&st, 1, 9, 42) == V2_ERR_INVALID);
    CHECK(v2_read(&st, 1, 9, &v) == V2_ERR_INVALID && v == 0);
    CHECK(v2_write(&st, 0, 9, 42) == V2_ERR_INVALID); /* unmapped */
    CHECK(v2_vm_noexec(&st));

    /* Grant frame 0 to thread 1, map, write, read (d_demo_grant_map_rw). */
    CHECK(v2_grant(&st, 0, 0, 1, 0) == V2_OK);
    CHECK(v2_has_cap(&st, 1, 0));
    CHECK(!st.caps[1][0].root); /* grant clears root */
    CHECK(v2_map(&st, 1, 0, 9) == V2_OK);
    CHECK(v2_write(&st, 1, 9, 42) == V2_OK);
    CHECK(v2_read(&st, 1, 9, &v) == V2_OK && v == 42);
    CHECK(v2_vm_noexec(&st));

    /* Double-map of the same vpn is rejected. */
    CHECK(v2_map(&st, 1, 0, 9) == V2_ERR_INVALID);
    /* Unmap then I/O fails closed again. */
    CHECK(v2_unmap(&st, 1, 9) == V2_OK);
    CHECK(v2_write(&st, 1, 9, 7) == V2_ERR_INVALID);
    CHECK(v2_read(&st, 1, 9, &v) == V2_ERR_INVALID && v == 0);
    CHECK(v2_unmap(&st, 1, 9) == V2_ERR_INVALID); /* already gone */
    CHECK(v2_map(&st, 1, 0, 9) == V2_OK); /* re-map for revoke test */

    /* Mint attenuation: R-only copy in slot 1, RW kept in slot 0. */
    CHECK(v2_mint(&st, 1, 0, V2_RIGHT_R, 1) == V2_OK);
    CHECK(st.caps[1][1].rights == V2_RIGHT_R && !st.caps[1][1].root);
    CHECK(v2_map(&st, 1, 1, 10) == V2_OK); /* R-only mapping */
    CHECK(v2_write(&st, 1, 10, 7) == V2_ERR_INVALID); /* mapping lacks W */
    CHECK(v2_read(&st, 1, 10, &v) == V2_OK && v == 42); /* R works */
    /* Escalation attempts fail closed (d_mint_rejects_escalation/exec). */
    CHECK(v2_mint(&st, 1, 0, V2_RIGHT_RW, 2) == V2_OK); /* RW copy is fine */
    CHECK(v2_mint(&st, 1, 1, V2_RIGHT_RW, 3) == V2_ERR_INVALID); /* R->RW no */
    CHECK(v2_mint(&st, 1, 0, V2_RIGHT_X, 3) == V2_ERR_INVALID); /* X never */
    CHECK(v2_mint(&st, 1, 0, V2_RIGHT_RW | V2_RIGHT_X, 3) == V2_ERR_INVALID);
    CHECK(v2_mint(&st, 1, 9, V2_RIGHT_R, 3) == V2_ERR_INVALID); /* no slot */
    CHECK(v2_mint(&st, 0, 0, V2_RIGHT_R, 0) == V2_ERR_INVALID); /* occupied */
    CHECK(v2_grant(&st, 1, 9, 0, 4) == V2_ERR_INVALID); /* non-holder */
    CHECK(v2_grant(&st, 0, 0, 9, 0) == V2_ERR_INVALID); /* bad target */
    CHECK(v2_vm_noexec(&st));

    /* Revoke clears granted caps + mappings; roots survive
     * (d_demo_revoke + d_revoke_roots_survive). */
    CHECK(v2_revoke(&st, 0, 0) == V2_OK);
    CHECK(!v2_has_cap(&st, 1, 0));
    CHECK(!v2_has_cap(&st, 1, 1));
    CHECK(!v2_has_cap(&st, 1, 2));
    CHECK(v2_read(&st, 1, 9, &v) == V2_ERR_INVALID);
    CHECK(v2_read(&st, 1, 10, &v) == V2_ERR_INVALID);
    CHECK(v2_has_cap(&st, 0, 0)); /* root survives */
    CHECK(st.caps[0][0].root);
    CHECK(v2_revoke(&st, 1, 0) == V2_ERR_INVALID); /* nothing to revoke */
    /* Re-issue after revoke works (roots survived for the allocator). */
    CHECK(v2_grant(&st, 0, 0, 1, 0) == V2_OK);
    CHECK(v2_map(&st, 1, 0, 9) == V2_OK);
    CHECK(v2_write(&st, 1, 9, 7) == V2_OK);
    CHECK(v2_read(&st, 1, 9, &v) == V2_OK && v == 7);

    /* Mint touches only the actor (d_mint_local / d_no_grant_no_gain). */
    snap = st;
    CHECK(v2_mint(&st, 0, 1, V2_RIGHT_R, 8) == V2_OK);
    for (i = 0; i < 16; i++)
        CHECK(caps_equal_slot(&st, &snap, 1, i));
    CHECK(!caps_equal_slot(&st, &snap, 0, 8)); /* actor's own slot changed */

    /* Mapping table full is fail-closed (implementation bound). */
    v2_caps_init(&st, 2);
    CHECK(v2_grant(&st, 0, 0, 1, 0) == V2_OK);
    for (i = 0; i < (unsigned long)V2_VPN_SLOTS; i++)
        CHECK(v2_map(&st, 1, 0, 100 + i) == V2_OK);
    CHECK(v2_map(&st, 1, 0, 999) == V2_ERR_OVERFLOW);
    CHECK(v2_vm_noexec(&st));

    /* ELF validation (elf_ok mutants + mapping). */
    ph[0].vpn = 5; ph[0].len = 1; ph[0].write = 0; ph[0].exec = 1;
    ph[1].vpn = 6; ph[1].len = 2; ph[1].write = 1; ph[1].exec = 0;
    CHECK(v2_elf_ok(1, ph, 2));
    CHECK(v2_elf_map_count(ph, 2) == 3);
    CHECK(v2_elf_map(ph, 2, vpns, ws, 8, &n) == V2_OK && n == 3);
    CHECK(vpns[0] == 5 && ws[0] == 0);
    CHECK(vpns[1] == 6 && ws[1] == 1 && vpns[2] == 7 && ws[2] == 1);
    CHECK(v2_elf_map(ph, 2, vpns, ws, 2, &n) == V2_ERR_OVERFLOW); /* too small */
    ph[0].write = 1; ph[0].exec = 1;
    CHECK(!v2_elf_ok(1, ph, 2)); /* RWX rejected (d_mutant_rwx) */
    ph[0].write = 0; ph[0].exec = 1;
    CHECK(!v2_elf_ok(0, ph, 2)); /* bad magic */
    CHECK(!v2_elf_ok(1, ph, 0)); /* no segments */
    CHECK(!v2_elf_ok(1, ph, 5)); /* too many */
    ph[0].len = 0;
    CHECK(!v2_elf_ok(1, ph, 2)); /* empty segment */
    ph[0].len = 513;
    CHECK(!v2_elf_ok(1, ph, 2)); /* oversize segment */
    CHECK(v2_elf_map(0, 2, vpns, ws, 8, &n) == V2_ERR_INVALID);
    CHECK(v2_elf_map(ph, 2, 0, ws, 8, &n) == V2_ERR_INVALID);

    printf("test_v2caps: ALL PASS\n");
    return 0;
}
