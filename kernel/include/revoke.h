#pragma once
#include "cap.h"
#include "types.h"

#define MAX_MDB_NODES 1024

typedef struct mdb_node {
    bool valid;
    cptr_t cptr;          /* where cap lives: cnode_id<<8 | slot */
    uint32_t cnode_id;
    cptr_t slot;
    uint32_t parent;      /* index of parent node, 0xFFFF = root */
    uint32_t first_child;
    uint32_t next_sibling;
    cap_t cap;
    bool revocable;
} mdb_node_t;

typedef struct mdb_tree {
    mdb_node_t nodes[MAX_MDB_NODES];
    uint32_t count;
    uint32_t free_head;
} mdb_tree_t;

void mdb_init(mdb_tree_t *mdb);
kerror_t mdb_insert(mdb_tree_t *mdb, uint32_t parent_idx, cptr_t cptr, cap_t cap, uint32_t *out_idx);
kerror_t mdb_revoke(mdb_tree_t *mdb, uint32_t idx);
kerror_t mdb_delete(mdb_tree_t *mdb, uint32_t idx);
uint32_t mdb_lookup(mdb_tree_t *mdb, uint32_t cnode_id, cptr_t slot);
bool mdb_is_descendant(mdb_tree_t *mdb, uint32_t ancestor, uint32_t descendant);
