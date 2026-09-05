#include "../include/cnode.h"
#include <string.h>

kerror_t cnode_init(cnode_t *cn, uint32_t guard, uint8_t radix) {
  if (!cn)
    return ERR_INVALID_ARG;
  if (radix > 8 || radix == 0)
    return ERR_INVALID_ARG;
  memset(cn, 0, sizeof(*cn)); // TODO: Use low level secure_zero
  cn->guard = guard;
  cn->radix = radix;
  return ERR_OK;
}

cap_t *cnode_lookup(cnode_t *cn, cptr_t idx) {
  if (!cn)
    return NULL;
  // Production: guard/radix decode (seL4-style)
  // For radix=8, guard_size=0, idx is direct. For larger, validate guard.
  if (cn->radix == 0 || cn->radix > 8)
    return NULL;
  uint32_t mask = (1u << cn->radix) - 1;
  if (cn->guard_size > 0) {
    uint32_t guard_bits = idx >> cn->radix;
    if (guard_bits != (cn->guard & ((1u << cn->guard_size) - 1)))
      return NULL;
  }
  uint32_t slot = idx & mask;
  // Also support full 256 when radix=8
  if (cn->radix == 8)
    slot = idx & 0xFF;
  if (slot >= MAX_CAPS_PER_CNODE)
    return NULL;
  cap_t *c = &cn->slots[slot];
  if (!c->is_valid)
    return NULL;
  if (!cheri_tag_get(c->hw_cap))
    return NULL;
  return c;
}

kerror_t cnode_copy(cnode_t *dst, cptr_t dst_idx, cnode_t *src, cptr_t src_idx,
                    uint32_t rights) {
  if (!dst || !src)
    return ERR_INVALID_ARG;
  if (dst_idx >= MAX_CAPS_PER_CNODE || src_idx >= MAX_CAPS_PER_CNODE)
    return ERR_INVALID_ARG;
  cap_t *sc = cnode_lookup(src, src_idx);
  if (!sc)
    return ERR_INVALID_CAP;
  if ((rights & ~sc->rights) != 0)
    return ERR_NO_RIGHTS;
  cap_t derived = cap_derive(*sc, rights, sc->badge);
  if (!derived.is_valid)
    return ERR_INVALID_CAP;
  if (dst->slots[dst_idx].is_valid)
    return ERR_REVOKE_NEEDED;
  dst->slots[dst_idx] = derived;
  dst->used++;
  return ERR_OK;
}

kerror_t cnode_mint(cnode_t *dst, cptr_t dst_idx, cnode_t *src, cptr_t src_idx,
                    uint32_t rights, uint32_t badge) {
  if (!dst || !src)
    return ERR_INVALID_ARG;
  if (dst_idx >= MAX_CAPS_PER_CNODE || src_idx >= MAX_CAPS_PER_CNODE)
    return ERR_INVALID_ARG;
  cap_t *sc = cnode_lookup(src, src_idx);
  if (!sc)
    return ERR_INVALID_CAP;
  if (!cap_has_right(*sc, CAP_RIGHTS_GRANT))
    return ERR_NO_RIGHTS;
  if (dst->slots[dst_idx].is_valid)
    return ERR_REVOKE_NEEDED;
  cap_t derived = cap_derive(*sc, rights, badge);
  if (!derived.is_valid)
    return ERR_INVALID_CAP;
  dst->slots[dst_idx] = derived;
  dst->used++;
  return ERR_OK;
}

kerror_t cnode_move(cnode_t *dst, cptr_t dst_idx, cnode_t *src,
                    cptr_t src_idx) {
  if (!dst || !src)
    return ERR_INVALID_ARG;
  cap_t *sc = cnode_lookup(src, src_idx);
  if (!sc)
    return ERR_INVALID_CAP;
  if (dst->slots[dst_idx].is_valid)
    return ERR_REVOKE_NEEDED;
  dst->slots[dst_idx] = *sc;
  memset(sc, 0, sizeof(cap_t));
  return ERR_OK;
}

kerror_t cnode_delete(cnode_t *cn, cptr_t idx) {
  if (!cn)
    return ERR_INVALID_ARG;
  if (idx >= MAX_CAPS_PER_CNODE)
    return ERR_INVALID_ARG;
  if (!cn->slots[idx].is_valid)
    return ERR_INVALID_CAP;
  /* Clear CHERI tag - architectural revoke */
  memset(&cn->slots[idx], 0, sizeof(cap_t));
  cn->used--;
  return ERR_OK;
}
