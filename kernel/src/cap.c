#include "../include/cap.h"
#include "../include/types.h"

cap_t cap_derive(cap_t parent, uint32_t new_rights, uint32_t new_badge) {
    cap_t child = parent;
    /* Attenuation: cannot gain rights - proven in Moonlight_A.thy */
    if ((new_rights & ~parent.rights) != 0) {
        child.is_valid = 0;
        return child;
    }
    child.rights = new_rights;
    child.badge = new_badge;
    /* CHERI monotonicity: perms_and only removes */
#ifdef __CHERI_PURE_CAPABILITY__
    child.hw_cap = cheri_perms_and(parent.hw_cap, new_rights);
    if (!cheri_tag_get(child.hw_cap)) child.is_valid = 0;
#endif
    return child;
}

bool cap_can_retype(cap_t untyped, cap_type_t new_type, size_t size) {
    if (untyped.type != CAP_UNTYPED) return false;
    if (!untyped.is_valid) return false;
    if (untyped.u.untyped.size < size) return false;
    if (new_type == CAP_UNTYPED) return false;
    /* Size alignment checks - prevents overlap */
    if ((size & (size-1)) != 0) return false; /* power of two */
    if (size < 4096) return false;
    return true;
}

cap_t cap_retype(cap_t untyped, cap_type_t new_type, uintptr_t paddr, size_t size) {
    cap_t c = {0};
    if (!cap_can_retype(untyped, new_type, size)) return c;
    c.type = new_type;
    c.rights = 0xF; /* full rights initially, then mint attenuates */
    c.is_valid = 1;
    c.is_sealed = 1;
    c.u.frame.paddr = paddr;
#ifdef __CHERI_PURE_CAPABILITY__
    c.hw_cap = cheri_bounds_set((CHERI_CAP)(uintptr_t)paddr, size);
    /* Seal with otype matching new_type */
    uint32_t otype = OTYPE_FRAME + (new_type - CAP_FRAME);
    c.hw_cap = cheri_seal(c.hw_cap, otype);
#else
    c.hw_cap.base = paddr;
    c.hw_cap.top = paddr + size;
    c.hw_cap.addr = paddr;
    c.hw_cap.tag = 1;
    c.hw_cap.sealed = 1;
    c.hw_cap.otype = OTYPE_FRAME + (new_type - CAP_FRAME);
#endif
    return c;
}
