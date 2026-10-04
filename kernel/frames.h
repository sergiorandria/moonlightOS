/* kernel/frames.h - physical frame pool bookkeeping (allocation state +
 * owner tracking).
 *
 * Pure C, no asm, no MMIO: host-testable (tests/test_frames.c) and
 * included by kboot.c. The pool is the bitmap half of the frame story;
 * caps.h is the authority half. This file only answers "which frames are
 * handed out, and to whom".
 *
 * Why owners are tracked: revoke drops caps and mappings but never returns
 * a frame to the pool. Without an owner, destroying a qube (QDESTROY) or
 * failing an ELF load leaks every frame the dead thread allocated, and a
 * 40-frame pool does not survive more than a few such cycles. The owner is
 * the thread that asked frame_alloc_slot() for the frame; ownership is not
 * transferred by GRANT.
 *
 * Invariants (checked by tests/test_frames.c):
 *   - frame 0 is kernel-reserved: never handed out, never released
 *   - a free frame has no owner; a used frame has at most one owner
 *   - release of a free / reserved / out-of-range frame is an error and
 *     changes nothing (double free is fail-closed, not silent)
 */
#ifndef V2_FRAMES_H
#define V2_FRAMES_H

#include <stdint.h>

#include "caps.h"

#define V2_FRAME_NO_OWNER 0xFFu

typedef struct {
    uint8_t used[V2_FRAMES_MAX];  /* 1 = handed out (frame 0: reserved) */
    uint8_t owner[V2_FRAMES_MAX]; /* allocating tid, or V2_FRAME_NO_OWNER */
} v2_frames_t;

static inline void v2_frames_init(v2_frames_t *p)
{
    int i;
    if (!p)
        return;
    for (i = 0; i < V2_FRAMES_MAX; i++) { /* bound: V2_FRAMES_MAX */
        p->used[i] = 0;
        p->owner[i] = V2_FRAME_NO_OWNER;
    }
    p->used[0] = 1; /* frame 0: kernel-reserved, never allocatable */
}

/* First free frame in [1, V2_FRAMES_MAX). Returns the frame index, or
 * V2_ERR_OVERFLOW when the pool is exhausted, V2_ERR_INVALID on a bad
 * argument. */
static inline int v2_frames_alloc(v2_frames_t *p, unsigned long owner)
{
    int i;
    if (!p || owner >= (unsigned long)V2_CAP_THREADS)
        return V2_ERR_INVALID;
    for (i = 1; i < V2_FRAMES_MAX; i++) { /* bound: V2_FRAMES_MAX */
        if (!p->used[i]) {
            p->used[i] = 1;
            p->owner[i] = (uint8_t)owner;
            return i;
        }
    }
    return V2_ERR_OVERFLOW;
}

static inline int v2_frames_is_allocated(const v2_frames_t *p, unsigned long f)
{
    return p && f >= 1UL && f < (unsigned long)V2_FRAMES_MAX && p->used[f];
}

/* Return a frame to the pool. V2_ERR_INVALID (no state change) for frame
 * 0, out-of-range indices and frames that are already free. */
static inline int v2_frames_release(v2_frames_t *p, unsigned long f)
{
    if (!v2_frames_is_allocated(p, f))
        return V2_ERR_INVALID;
    p->used[f] = 0;
    p->owner[f] = V2_FRAME_NO_OWNER;
    return V2_OK;
}

/* Next frame at index >= from that is owned by `owner`, or -1. Drives the
 * "free everything a dead thread allocated" loop. */
static inline int v2_frames_next_owned(const v2_frames_t *p, unsigned long owner,
                                       int from)
{
    int i;
    if (!p || owner >= (unsigned long)V2_CAP_THREADS)
        return -1;
    for (i = from < 1 ? 1 : from; i < V2_FRAMES_MAX; i++) { /* bound: V2_FRAMES_MAX */
        if (p->used[i] && p->owner[i] == (uint8_t)owner)
            return i;
    }
    return -1;
}

static inline unsigned long v2_frames_free_count(const v2_frames_t *p)
{
    unsigned long n = 0;
    int i;
    if (!p)
        return 0;
    for (i = 1; i < V2_FRAMES_MAX; i++) /* bound: V2_FRAMES_MAX */
        if (!p->used[i])
            n++;
    return n;
}

#endif /* V2_FRAMES_H */
