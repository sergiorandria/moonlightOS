#include "../include/revoke.h"
#include <string.h>
#define NIL 0xFFFF

void mdb_init(mdb_tree_t *mdb) {
    memset(mdb, 0, sizeof(*mdb));
    for (uint32_t i=0;i<MAX_MDB_NODES;i++) mdb->nodes[i].parent = NIL;
    mdb->free_head = 0;
    mdb->count = 0;
}

kerror_t mdb_insert(mdb_tree_t *mdb, uint32_t parent_idx, cptr_t cptr, cap_t cap, uint32_t *out_idx) {
    if (!mdb || !out_idx) return ERR_INVALID_ARG;
    if (mdb->count >= MAX_MDB_NODES) return ERR_NO_MEM;
    uint32_t idx = mdb->free_head;
    while (idx < MAX_MDB_NODES && mdb->nodes[idx].valid) idx++;
    if (idx >= MAX_MDB_NODES) return ERR_NO_MEM;
    mdb_node_t *n = &mdb->nodes[idx];
    memset(n, 0, sizeof(*n));
    n->valid = true;
    n->cptr = cptr;
    n->cap = cap;
    n->parent = parent_idx;
    n->first_child = NIL;
    n->next_sibling = NIL;
    n->revocable = true;
    if (parent_idx != NIL && parent_idx < MAX_MDB_NODES && mdb->nodes[parent_idx].valid) {
        n->next_sibling = mdb->nodes[parent_idx].first_child;
        mdb->nodes[parent_idx].first_child = idx;
    }
    mdb->count++;
    if (idx == mdb->free_head) mdb->free_head = idx+1;
    *out_idx = idx;
    return ERR_OK;
}

static void mdb_revoke_recursive(mdb_tree_t *mdb, uint32_t idx) {
    mdb_node_t *n = &mdb->nodes[idx];
    uint32_t child = n->first_child;
    while (child != NIL) {
        uint32_t next = mdb->nodes[child].next_sibling;
        mdb_revoke_recursive(mdb, child);
        child = next;
    }
    /* Clear CHERI tag - architectural revoke */
    memset(&n->cap, 0, sizeof(cap_t));
    n->valid = false;
    if (idx < mdb->free_head) mdb->free_head = idx;
    mdb->count--;
}

kerror_t mdb_revoke(mdb_tree_t *mdb, uint32_t idx) {
    if (!mdb || idx >= MAX_MDB_NODES) return ERR_INVALID_ARG;
    if (!mdb->nodes[idx].valid) return ERR_INVALID_CAP;
    /* Revoke all descendants first, then self - depth-first */
    uint32_t child = mdb->nodes[idx].first_child;
    while (child != NIL) {
        uint32_t next = mdb->nodes[child].next_sibling;
        mdb_revoke_recursive(mdb, child);
        child = next;
    }
    /* Keep parent node but clear its cap? No - revoke means delete subtree excluding parent */
    /* For full revoke including self, caller deletes parent separately */
    mdb->nodes[idx].first_child = NIL;
    return ERR_OK;
}

kerror_t mdb_delete(mdb_tree_t *mdb, uint32_t idx) {
    if (!mdb || idx >= MAX_MDB_NODES) return ERR_INVALID_ARG;
    if (!mdb->nodes[idx].valid) return ERR_INVALID_CAP;
    if (mdb->nodes[idx].first_child != NIL) return ERR_REVOKE_NEEDED;
    uint32_t parent = mdb->nodes[idx].parent;
    if (parent != NIL) {
        uint32_t *p = &mdb->nodes[parent].first_child;
        while (*p != NIL) {
            if (*p == idx) { *p = mdb->nodes[idx].next_sibling; break; }
            p = &mdb->nodes[*p].next_sibling;
        }
    }
    memset(&mdb->nodes[idx], 0, sizeof(mdb_node_t));
    mdb->nodes[idx].parent = NIL;
    mdb->nodes[idx].first_child = NIL;
    mdb->nodes[idx].next_sibling = NIL;
    if (idx < mdb->free_head) mdb->free_head = idx;
    mdb->count--;
    return ERR_OK;
}

uint32_t mdb_lookup(mdb_tree_t *mdb, uint32_t cnode_id, cptr_t slot) {
    for (uint32_t i=0;i<MAX_MDB_NODES;i++) {
        if (!mdb->nodes[i].valid) continue;
        // cptr encodes cnode_id<<8 | slot, also check explicit fields
        if (mdb->nodes[i].cnode_id == cnode_id && mdb->nodes[i].slot == slot) return i;
        if (mdb->nodes[i].cptr == slot && cnode_id == 0) return i; // legacy: process uses cptr=tcb_id
        if (mdb->nodes[i].cptr == ((cnode_id<<8) | slot)) return i;
    }
    return NIL;
}

bool mdb_is_descendant(mdb_tree_t *mdb, uint32_t ancestor, uint32_t descendant) {
    uint32_t cur = descendant;
    while (cur != NIL && cur < MAX_MDB_NODES) {
        if (cur == ancestor) return true;
        cur = mdb->nodes[cur].parent;
    }
    return false;
}
