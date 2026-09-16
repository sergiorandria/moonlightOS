#ifndef INITRD_H
#define INITRD_H
#include <stdint.h>
extern uint8_t initrd_data[];
extern uint32_t initrd_size;
extern uint32_t initrd_num_frames;
void initrd_init(void);
#endif
