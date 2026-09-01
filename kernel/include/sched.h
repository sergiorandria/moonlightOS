#pragma once
#include "types.h"
#include "cap.h"
#include <stdbool.h>

#define MAJOR_FRAME_US 10000  /* 10ms major frame */
#define MAX_SCHED_CONTEXTS 64
#define NSEC_PER_USEC 1000

/* Time partition - ARINC-653 style, statically verified */
typedef struct {
    uint32_t id;
    const char *name;
    uint64_t offset_us;   /* offset in major frame */
    uint64_t budget_us;   /* budget in major frame */
    uint64_t used_us;
    uint8_t  criticality; /* 0 lowest .. 3 highest */
    uint16_t color_base;  /* cache color base for isolation */
    bool     active;
} time_partition_t;

/* Scheduling context - EDF + Fixed Priority within partition */
typedef struct {
    bool     bound;
    uint32_t tcb_id;
    uint32_t partition_id;
    uint64_t budget_us;   /* WCET budget */
    uint64_t period_us;   /* period */
    uint64_t remaining_us;
    uint64_t deadline;    /* absolute deadline ticks */
    uint8_t  priority;    /* 0..255, 0 highest */
    bool     is_realtime;
    uint64_t consumed_this_period;
} sched_context_t;

typedef struct {
    time_partition_t partitions[MAX_PARTITIONS];
    uint32_t num_partitions;
    uint64_t major_frame_start;
    uint32_t current_partition;
    sched_context_t contexts[MAX_SCHED_CONTEXTS];
    /* ready queues per partition: 256 priority levels, bitmap */
    uint32_t ready_bitmap[MAX_PARTITIONS];
    uint32_t ready_queues[MAX_PARTITIONS][256];
} sched_state_t;

void sched_init(sched_state_t *s);
kerror_t sched_partition_create(sched_state_t *s, uint32_t id, uint64_t offset, uint64_t budget, uint8_t crit);
kerror_t sched_context_bind(sched_state_t *s, uint32_t sc_id, uint32_t tcb_id, uint32_t part_id, uint64_t budget, uint64_t period, uint8_t prio);
void sched_tick(sched_state_t *s, uint64_t now_us);
uint32_t sched_pick_next(sched_state_t *s, uint64_t now_us);
bool sched_is_schedulable(sched_state_t *s); /* EDF utilization test proven in Isabelle */
void sched_flush_partition(sched_state_t *s, uint32_t old_part);

/* WCET enforcement - kernel preemption point */
#define WCET_KERNEL_MAX_US 5
bool wcet_check(uint64_t entry_us);
