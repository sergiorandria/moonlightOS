# Capabilities (CHERI-Sealed, Production)

`kernel/include/cap.h:30` `cap_t` = sealed `CHERI_CAP hw_cap` + metadata.

| Type | Value | Rights | Fields |
|---|---|---|---|
| `CAP_UNTYPED` |1| - | `paddr,size,free_idx` |
| `CAP_CNODE` |2| `READ` | `guard,radix,guard_size` |
| `CAP_TCB` |3| `READ` | `tcb_ptr` |
| `CAP_VSPACE` |4| `READ` | `root_pt,asid` |
| `CAP_FRAME` |5| `READ|WRITE|GRANT` | `paddr,perms,color` |
| `CAP_ENDPOINT` |6| `READ|WRITE|GRANT` | `ep_ptr,badge` |
| `CAP_IRQ` |8| - | `irq, badge` |
| `CAP_IOMMU` |9| - | `window` |
| `CAP_SCHED_CONTEXT` |10| - | `budget,period,crit` |

HW enforcement:

```c
cap_is_valid(c) // cap.h:55
  -> c->is_valid && c->type!=NULL && cheri_tag_get(c->hw_cap)==1

cheri_cap_is_valid(cap, base, len, perms) // cheri.h:5
  hybrid sim: base==cap.base && top==base+len && (perms&cap.perms)==perms
  purecap: cheri_tag_get && cheri_base_get && cheri_length_get && cheri_perms_get
```

Sealing:

```c
hw_cap = cheri_bounds_set((void*)paddr, size); // CC128
hw_cap = cheri_seal(hw_cap, OTYPE_FRAME); // 0x105
```

`OTYPE_*` at `cheri.h:50`: `CNode 0x100`, `TCB 0x101`, `VSpace 0x102`, `Endpoint 0x103`, `Frame 0x105`, `SchedContext 0x106`.

Derivation (proven attenuation):

```c
cap_t cap_derive(parent, new_rights, new_badge){
  // new_rights ⊆ parent.rights, else ERR_NO_RIGHTS
  // cheri_perms_and(parent.hw_cap, new_rights)
}
```

Retype:

```c
cap_can_retype(untyped, new_type, size) // cap.c
  -> untyped.type==CAP_UNTYPED && size <= untyped.size
cap_retype(...) // creates sealed cap with new otype
```

Cache coloring:

- 16 colors, `color = (paddr>>12)%16`
- `alloc_color_for_partition(pid) = pid*2 %16` (`alloc.h:12`)
- `vspace_map` checks `vcolor==color || color==0` (`vspace.c:39`)
- `CacheColoring.thy: no_cache_interference` proved

Revocation:

- MDB tree (`kernel/src/revoke.c`), `revoke()` clears tag, `process.c` destroys `pid`
- `tests/test_revoke_process.c` verifies

Example:

```c
cap_t parent = cnode_lookup(root, 0); // Untyped
cap_t child = cap_derive(parent, CAP_RIGHTS_READ, 0);
if (!cap_is_valid(&child)) panic();
```

No ambient authority: every `syscall_handler` does `cnode_lookup` + `cheri_tag_get`.

