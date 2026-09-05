#!/bin/bash
set -e
# Stock QEMU build (no CHERI LLVM needed) - hybrid sim
CC="clang --target=riscv64-unknown-elf"
CFLAGS="-march=rv64imac -mabi=lp64 -O2 -ffreestanding -nostdlib -Wall -mcmodel=medany -mno-relax -fno-builtin -I$(dirname $0)/../kernel/include -I/usr/lib/clang/22/include -I/usr/include -include stdbool.h -fno-stack-protector"
SRC="cap.c cnode.c tcb.c vspace.c endpoint.c syscall.c cheri.c iommu.c irq.c alloc.c revoke.c process.c hardening.c notification.c flush.c elf.c vga.c"
# sched int to avoid float
cat > /tmp/sched_qemu.c <<'C'
#include "../include/sched.h"
#include "../include/cheri.h"
#include <string.h>
void sched_init(sched_state_t *s){ memset(s,0,sizeof(*s)); s->major_frame_start=0; s->current_partition=0; }
kerror_t sched_partition_create(sched_state_t *s, uint32_t id, uint64_t offset, uint64_t budget, uint8_t crit){ if (!s || id >= MAX_PARTITIONS) return ERR_INVALID_ARG; if (offset+budget>MAJOR_FRAME_US) return ERR_INVALID_ARG; for(uint32_t i=0;i<s->num_partitions;i++){ uint64_t a=s->partitions[i].offset_us; uint64_t b=a+s->partitions[i].budget_us; if(!((offset+budget)<=a || offset>=b)) return ERR_INVALID_ARG; } s->partitions[id].id=id; s->partitions[id].offset_us=offset; s->partitions[id].budget_us=budget; s->partitions[id].criticality=crit; s->partitions[id].color_base=id*2; s->partitions[id].active=true; if(id>=s->num_partitions) s->num_partitions=id+1; return ERR_OK; }
bool sched_is_schedulable(sched_state_t *s){ for(uint32_t p=0;p<s->num_partitions;p++){ uint64_t sum=0; for(uint32_t i=0;i<MAX_SCHED_CONTEXTS;i++){ if(!s->contexts[i].bound) continue; if(s->contexts[i].partition_id!=p) continue; sum+= s->contexts[i].budget_us*100 / s->contexts[i].period_us; } if(sum>99) return false; } return true; }
void sched_flush_partition(sched_state_t *s,uint32_t o){ (void)s;(void)o; cheri_flush_microarch(); }
uint32_t sched_pick_next(sched_state_t *s,uint64_t now){ (void)now; uint32_t part=s->current_partition; for(int prio=0;prio<256;prio++) for(uint32_t i=0;i<MAX_SCHED_CONTEXTS;i++){ sched_context_t *sc=&s->contexts[i]; if(!sc->bound) continue; if(sc->partition_id!=part) continue; if(sc->priority!=prio) continue; if(sc->remaining_us==0) continue; return sc->tcb_id; } return 0xFFFFFFFF; }
void sched_tick(sched_state_t *s,uint64_t now){ uint64_t off=(now-s->major_frame_start)%MAJOR_FRAME_US; uint32_t np=s->current_partition; for(uint32_t i=0;i<s->num_partitions;i++){ uint64_t o=s->partitions[i].offset_us; uint64_t e=o+s->partitions[i].budget_us; if(off>=o&&off<e){np=i;break;}} if(np!=s->current_partition){sched_flush_partition(s,s->current_partition); s->current_partition=np;} for(uint32_t i=0;i<MAX_SCHED_CONTEXTS;i++){ if(!s->contexts[i].bound) continue; if(now>=s->contexts[i].deadline){ s->contexts[i].remaining_us=s->contexts[i].budget_us; s->contexts[i].deadline+=s->contexts[i].period_us; s->contexts[i].consumed_this_period=0;}}}
bool wcet_check(uint64_t e){ uint64_t now=0; __asm__ volatile("rdtime %0":"=r"(now)); return (now-e) <= 5000; }
kerror_t sched_context_bind(sched_state_t *s,uint32_t sc,uint32_t tcb,uint32_t part,uint64_t budg,uint64_t per,uint8_t prio){ if(!s||sc>=MAX_SCHED_CONTEXTS) return ERR_INVALID_ARG; if(part>=MAX_PARTITIONS||!s->partitions[part].active) return ERR_INVALID_ARG; if(budg==0||per==0||budg>per) return ERR_INVALID_ARG; if(budg>s->partitions[part].budget_us) return ERR_INVALID_ARG; s->contexts[sc].bound=true; s->contexts[sc].tcb_id=tcb; s->contexts[sc].partition_id=part; s->contexts[sc].budget_us=budg; s->contexts[sc].period_us=per; s->contexts[sc].priority=prio; s->contexts[sc].remaining_us=budg; s->contexts[sc].deadline=per; return ERR_OK; }
C
cat > /tmp/minilib_qemu.c <<'C'
void *memcpy(void *d, const void *s, unsigned long n){ char *dd=d; const char *ss=s; while(n--) *dd++=*ss++; return d;}
void *memset(void *s,int c,unsigned long n){ char *p=s; while(n--) *p++=c; return s;}
C
$CC $CFLAGS -c /tmp/minilib_qemu.c -o /tmp/minilib_qemu.o
$CC $CFLAGS -c /tmp/sched_qemu.c -o /tmp/sched_qemu.o
$CC $CFLAGS -c kernel/src/start.S -o /tmp/start_qemu.o
$CC $CFLAGS -c kernel/src/trap.S -o /tmp/trap_qemu.o
OBJ="/tmp/start_qemu.o /tmp/trap_qemu.o /tmp/minilib_qemu.o /tmp/sched_qemu.o"
for s in $SRC; do $CC $CFLAGS -c kernel/src/$s -o /tmp/${s%.c}_qemu.o; OBJ="$OBJ /tmp/${s%.c}_qemu.o"; done
$CC $CFLAGS -c kernel/src/boot.c -o /tmp/boot_qemu.o
OBJ="$OBJ /tmp/boot_qemu.o"
mkdir -p kernel/build
$CC $CFLAGS -fuse-ld=lld -T kernel/linker.ld -o kernel/build/moonlight.elf $OBJ -Wl,--no-undefined -nostdlib
ls -lh kernel/build/moonlight.elf
echo "qemu build OK"
