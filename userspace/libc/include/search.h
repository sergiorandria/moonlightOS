/* Moonlight libc - search.h (hash tables + binary trees). */
#pragma once

#include <stddef.h>

typedef struct entry {
    char *key;
    void *data;
} ENTRY;

typedef enum { FIND, ENTER } ACTION;
typedef enum { preorder, postorder, endorder, leaf } VISIT;

typedef struct node_t {
    char *key;
    struct node_t *left, *right;
} *NODE_PTR;

int hcreate(size_t nel);
void hdestroy(void);
ENTRY *hsearch(ENTRY item, ACTION action);

void *tsearch(const void *key, void **rootp,
              int (*compar)(const void *, const void *));
void *tfind(const void *key, void *const *rootp,
            int (*compar)(const void *, const void *));
void *tdelete(const void *key, void **rootp,
              int (*compar)(const void *, const void *));
void twalk(const void *root,
           void (*action)(const void *nodep, VISIT which, int depth));

void *lsearch(const void *key, void *base, size_t *nelp, size_t width,
              int (*compar)(const void *, const void *));
void *lfind(const void *key, const void *base, size_t *nelp, size_t width,
            int (*compar)(const void *, const void *));

void insque(void *elem, void *prev);
void remque(void *elem);

struct qelem {
    struct qelem *q_forw;
    struct qelem *q_back;
    char q_data[1];
};
