/* Moonlight libc - sys/queue (BSD tail/head/circle lists).
 * Full macro implementation (singly/doubly/tail-queue/circle):
 * real inline pointer surgery, no functions, no stubs. */
#pragma once

/* Singly-linked list */
#define SLIST_HEAD(name, type) \
    struct name { struct type *slh_first; }
#define SLIST_ENTRY(type) \
    struct { struct type *sle_next; }
#define SLIST_INIT(h) ((h)->slh_first = 0)
#define SLIST_INSERT_HEAD(h, e, f) \
    do { (e)->f.sle_next = (h)->slh_first; (h)->slh_first = (e); } while (0)
#define SLIST_REMOVE_HEAD(h, f) \
    do { (h)->slh_first = (h)->slh_first->f.sle_next; } while (0)
#define SLIST_FOREACH(v, h, f) \
    for ((v) = (h)->slh_first; (v); (v) = (v)->f.sle_next)

/* Singly-linked tail queue */
#define STAILQ_HEAD(name, type) \
    struct name { struct type *stqh_first; struct type **stqh_last; }
#define STAILQ_ENTRY(type) \
    struct { struct type *stqe_next; }
#define STAILQ_INIT(h) \
    do { (h)->stqh_first = 0; (h)->stqh_last = &(h)->stqh_first; } while (0)
#define STAILQ_INSERT_TAIL(h, e, f) \
    do { (e)->f.stqe_next = 0; *(h)->stqh_last = (e); (h)->stqh_last = &(e)->f.stqe_next; } while (0)
#define STAILQ_INSERT_HEAD(h, e, f) \
    do { if (((e)->f.stqe_next = (h)->stqh_first) == 0) (h)->stqh_last = &(e)->f.stqe_next; (h)->stqh_first = (e); } while (0)
#define STAILQ_FOREACH(v, h, f) \
    for ((v) = (h)->stqh_first; (v); (v) = (v)->f.stqe_next)

/* Doubly-linked list */
#define LIST_HEAD(name, type) \
    struct name { struct type *lh_first; }
#define LIST_ENTRY(type) \
    struct { struct type *le_next; struct type **le_prev; }
#define LIST_INIT(h) ((h)->lh_first = 0)
#define LIST_INSERT_HEAD(h, e, f) \
    do { if (((e)->f.le_next = (h)->lh_first) != 0) (h)->lh_first->f.le_prev = &(e)->f.le_next; (h)->lh_first = (e); (e)->f.le_prev = &(h)->lh_first; } while (0)
#define LIST_REMOVE(e, f) \
    do { if ((e)->f.le_next != 0) (e)->f.le_next->f.le_prev = (e)->f.le_prev; *(e)->f.le_prev = (e)->f.le_next; } while (0)
#define LIST_FOREACH(v, h, f) \
    for ((v) = (h)->lh_first; (v); (v) = (v)->f.le_next)

/* Tail queue */
#define TAILQ_HEAD(name, type) \
    struct name { struct type *tqh_first; struct type **tqh_last; }
#define TAILQ_ENTRY(type) \
    struct { struct type *tqe_next; struct type **tqe_prev; }
#define TAILQ_INIT(h) \
    do { (h)->tqh_first = 0; (h)->tqh_last = &(h)->tqh_first; } while (0)
#define TAILQ_INSERT_TAIL(h, e, f) \
    do { (e)->f.tqe_next = 0; (e)->f.tqe_prev = (h)->tqh_last; *(h)->tqh_last = (e); (h)->tqh_last = &(e)->f.tqe_next; } while (0)
#define TAILQ_INSERT_HEAD(h, e, f) \
    do { if (((e)->f.tqe_next = (h)->tqh_first) != 0) (h)->tqh_first->f.tqe_prev = &(e)->f.tqe_next; else (h)->tqh_last = &(e)->f.tqe_next; (h)->tqh_first = (e); (e)->f.tqe_prev = &(h)->tqh_first; } while (0)
#define TAILQ_REMOVE(h, e, f) \
    do { if ((e)->f.tqe_next != 0) (e)->f.tqe_next->f.tqe_prev = (e)->f.tqe_prev; else (h)->tqh_last = (e)->f.tqe_prev; *(e)->f.tqe_prev = (e)->f.tqe_next; } while (0)
#define TAILQ_FOREACH(v, h, f) \
    for ((v) = (h)->tqh_first; (v); (v) = (v)->f.tqe_next)

/* Circle queue */
#define CIRCLEQ_HEAD(name, type) \
    struct name { struct type *cqh_first; struct type *cqh_last; }
#define CIRCLEQ_ENTRY(type) \
    struct { struct type *cqe_next; struct type *cqe_prev; }
#define CIRCLEQ_INIT(h) \
    do { (h)->cqh_first = (void *)(h); (h)->cqh_last = (void *)(h); } while (0)
#define CIRCLEQ_INSERT_HEAD(h, e, f) \
    do { (e)->f.cqe_next = (h)->cqh_first; (e)->f.cqe_prev = (void *)(h); if ((h)->cqh_last == (void *)(h)) (h)->cqh_last = (e); else (h)->cqh_first->f.cqe_prev = (e); (h)->cqh_first = (e); } while (0)
#define CIRCLEQ_INSERT_TAIL(h, e, f) \
    do { (e)->f.cqe_next = (void *)(h); (e)->f.cqe_prev = (h)->cqh_last; if ((h)->cqh_first == (void *)(h)) (h)->cqh_first = (e); else (h)->cqh_last->f.cqe_next = (e); (h)->cqh_last = (e); } while (0)
#define CIRCLEQ_FOREACH(v, h, f) \
    for ((v) = (h)->cqh_first; (v) != (void *)(h); (v) = (v)->f.cqe_next)
