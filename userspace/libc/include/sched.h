/* Moonlight libc - sched (cooperative yield + affinity/clock queries). */
#pragma once

struct timespec;

int sched_yield(void);
int sched_getaffinity(int pid, unsigned n, void *mask);
int sched_setaffinity(int pid, unsigned n, const void *mask);
int sched_get_priority_max(int policy);
int sched_get_priority_min(int policy);
#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2

typedef struct {
    unsigned long bits[1];
} cpu_set_t;
#define CPU_SETSIZE 32
#define CPU_ZERO(s) ((s)->bits[0] = 0)
#define CPU_SET(c, s) ((s)->bits[0] |= 1ul << (c))
#define CPU_CLR(c, s) ((s)->bits[0] &= ~(1ul << (c)))
#define CPU_ISSET(c, s) ((((s)->bits[0] >> (c)) & 1) ? 1 : 0)
#define CPU_COUNT(s) __ml_cpu_count(s)
static inline int __ml_cpu_count(const cpu_set_t *s) {
    unsigned long v = s->bits[0];
    int n = 0;
    while (v) {
        n += (int)(v & 1);
        v >>= 1;
    }
    return n;
}
