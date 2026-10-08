/* libc search: hsearch hash table, tsearch BST, lsearch list,
 * insque/remque queues. All pure in-memory structures. */
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ---- hsearch (open addressing, single global table) ---- */

static ENTRY *ml_htab = 0;
static size_t ml_hn = 0;

static unsigned long ml_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}

int hcreate(size_t nel) {
    size_t n = 16;
    if (ml_htab) {
        errno = EEXIST;
        return 0;
    }
    if (nel == 0) nel = 1;
    while (n < nel * 2) n *= 2;
    ml_htab = calloc(n, sizeof(ENTRY));
    if (!ml_htab) return 0;
    ml_hn = n;
    return 1;
}

void hdestroy(void) {
    free(ml_htab);
    ml_htab = 0;
    ml_hn = 0;
}

ENTRY *hsearch(ENTRY item, ACTION action) {
    size_t i, h;
    if (!ml_htab || !item.key) {
        errno = ESRCH;
        return 0;
    }
    h = ml_hash(item.key) & (ml_hn - 1);
    for (i = 0; i < ml_hn; i++) {
        size_t k = (h + i) & (ml_hn - 1);
        if (!ml_htab[k].key) {
            if (action == ENTER) {
                ml_htab[k].key = item.key;
                ml_htab[k].data = item.data;
                return &ml_htab[k];
            }
            errno = ESRCH;
            return 0;
        }
        if (strcmp(ml_htab[k].key, item.key) == 0) return &ml_htab[k];
    }
    errno = ENOMEM;
    return 0;
}

/* ---- tsearch (unbalanced BST is fine; rotations not required) ---- */

typedef struct tnode {
    const void *key;
    struct tnode *l, *r;
} tnode_t;

void *tsearch(const void *key, void **rootp,
              int (*compar)(const void *, const void *)) {
    tnode_t **p = (tnode_t **)rootp, *n;
    if (!rootp || !compar) return 0;
    while (*p) {
        int c = compar(key, (*p)->key);
        if (c == 0) return *p;
        p = c < 0 ? &(*p)->l : &(*p)->r;
    }
    n = malloc(sizeof(*n));
    if (!n) return 0;
    n->key = key;
    n->l = n->r = 0;
    *p = n;
    return n;
}

void *tfind(const void *key, void *const *rootp,
            int (*compar)(const void *, const void *)) {
    const tnode_t *p;
    if (!rootp || !compar) return 0;
    p = *(const tnode_t *const *)rootp;
    while (p) {
        int c = compar(key, p->key);
        if (c == 0) return (void *)p;
        p = c < 0 ? p->l : p->r;
    }
    return 0;
}

void *tdelete(const void *key, void **rootp,
              int (*compar)(const void *, const void *)) {
    tnode_t **p, *t, *rep, **repp;
    if (!rootp || !compar) return 0;
    p = (tnode_t **)rootp;
    while (*p) {
        int c = compar(key, (*p)->key);
        if (c == 0) break;
        p = c < 0 ? &(*p)->l : &(*p)->r;
    }
    if (!*p) return 0;
    t = *p;
    if (!t->l) {
        *p = t->r;
    } else if (!t->r) {
        *p = t->l;
    } else {
        /* Both children: splice the left subtree onto the
         * leftmost node of the right subtree. */
        repp = &t->r;
        while ((*repp)->l) repp = &(*repp)->l;
        rep = *repp;
        *repp = rep->r;
        rep->l = t->l;
        rep->r = t->r;
        *p = rep;
    }
    {
        const void *k = t->key;
        free(t);
        return (void *)k;
    }
}

static void ml_twalk(const tnode_t *p,
                     void (*action)(const void *, VISIT, int), int depth) {
    if (!p) return;
    if (p->l || p->r) action(p, preorder, depth);
    else action(p, leaf, depth);
    if (p->l) ml_twalk(p->l, action, depth + 1);
    if (p->l || p->r) action(p, postorder, depth);
    if (p->r) ml_twalk(p->r, action, depth + 1);
    if (p->l || p->r) action(p, endorder, depth);
}

void twalk(const void *root, void (*action)(const void *, VISIT, int)) {
    if (root && action) ml_twalk(root, action, 0);
}

/* ---- lsearch / lfind (linear over caller array) ---- */

void *lsearch(const void *key, void *base, size_t *nelp, size_t width,
              int (*compar)(const void *, const void *)) {
    size_t i;
    char *b;
    if (!key || !base || !nelp || !width || !compar) return 0;
    b = base;
    for (i = 0; i < *nelp; i++)
        if (compar(key, b + i * width) == 0) return b + i * width;
    memcpy(b + (*nelp) * width, key, width);
    (*nelp)++;
    return b + (*nelp - 1) * width;
}

void *lfind(const void *key, const void *base, size_t *nelp, size_t width,
            int (*compar)(const void *, const void *)) {
    size_t i;
    const char *b;
    if (!key || !base || !nelp || !width || !compar) return 0;
    b = base;
    for (i = 0; i < *nelp; i++)
        if (compar(key, b + i * width) == 0)
            return (void *)(b + i * width);
    return 0;
}

/* ---- insque / remque (doubly linked, BSD qelem layout) ---- */

void insque(void *elem, void *prev) {
    struct qelem *e = elem, *p = prev;
    if (!e || !p) return;
    e->q_forw = p->q_forw;
    e->q_back = p;
    if (p->q_forw) p->q_forw->q_back = e;
    p->q_forw = e;
}

void remque(void *elem) {
    struct qelem *e = elem;
    if (!e) return;
    if (e->q_forw) e->q_forw->q_back = e->q_back;
    if (e->q_back) e->q_back->q_forw = e->q_forw;
}
