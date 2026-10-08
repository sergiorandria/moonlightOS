#ifndef INITRD_H
#define INITRD_H
#include <stdint.h>
typedef struct { const char *name; uint32_t offset; uint32_t size; } initrd_file_t;
extern uint8_t initrd_data[];
extern uint32_t initrd_size;
extern uint32_t initrd_num_frames;
extern initrd_file_t initrd_files[];
extern uint32_t initrd_num_files;
void initrd_init(void);
int initrd_lookup(uint32_t idx, const uint8_t **out_ptr, uint32_t *out_size);
#endif
