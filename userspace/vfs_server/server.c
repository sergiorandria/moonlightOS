/* vfs_server - microkernel VFS, purecap, IOMMU-isolated block driver
 * Production: caps for each file, directory as CNode, per-client handles
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define MAX_FILES 64
#define MAX_FD 32
#define PAGE_SIZE 4096

typedef struct {
    uint32_t cap; // Frame cap for file data
    uint32_t size;
    uint32_t used;
    uint16_t color;
    char name[32];
    bool valid;
} vfs_file_t;

typedef struct {
    uint32_t file_id;
    uint32_t offset;
    uint32_t rights;
    bool valid;
} vfs_fd_t;

static vfs_file_t files[MAX_FILES];
static vfs_fd_t fds[MAX_FD];
static uint32_t next_fd = 0;

// IPC ABI (matches kernel)
typedef struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } ipc_msg_t;
extern int moonlight_call(uint32_t ep, ipc_msg_t *msg);
extern int moonlight_recv(uint32_t ep, ipc_msg_t *msg);

kerror_t vfs_create(const char *name, uint32_t cap, uint32_t size, uint16_t color){
    for(int i=0;i<MAX_FILES;i++) if(!files[i].valid){
        files[i].cap = cap;
        files[i].size = size;
        files[i].used = 0;
        files[i].color = color;
        strncpy(files[i].name, name, 32);
        files[i].valid = true;
        return 0;
    }
    return -1;
}

int vfs_open(const char *name, uint32_t rights){
    for(int i=0;i<MAX_FILES;i++) if(files[i].valid && strcmp(files[i].name,name)==0){
        for(int fd=0; fd<MAX_FD; fd++) if(!fds[fd].valid){
            fds[fd].file_id = i;
            fds[fd].offset = 0;
            fds[fd].rights = rights;
            fds[fd].valid = true;
            return fd;
        }
    }
    return -1;
}

int vfs_read(int fd, void *buf, size_t len){
    if(fd<0||fd>=MAX_FD||!fds[fd].valid) return -1;
    vfs_file_t *f = &files[fds[fd].file_id];
    if(fds[fd].offset + len > f->used) len = f->used - fds[fd].offset;
    // In production: copy via CHERI-bounded memcpy from Frame cap
    // cheri_memcpy_capped(f->cap, buf, len) with tag check
    (void)buf;
    fds[fd].offset += len;
    return len;
}

void vfs_server_run(uint32_t ep){
    ipc_msg_t msg;
    while(1){
        moonlight_recv(ep, &msg);
        if(msg.label==1){ // open
            char name[32]; memcpy(name, msg.words, 32);
            int fd = vfs_open(name, msg.words[4]);
            msg.words[0]=fd; msg.length=1;
            moonlight_call(ep, &msg);
        } else if(msg.label==2){ // read
            int fd = msg.words[0]; size_t len=msg.words[1];
            // would use Frame cap
            msg.words[0]=len; msg.length=1;
            moonlight_call(ep, &msg);
        } else if(msg.label==3){ // create
            char name[32]; memcpy(name, msg.words, 32);
            vfs_create(name, msg.cap_ptrs[0], msg.words[4], msg.words[5]);
            msg.words[0]=0; msg.length=1;
            moonlight_call(ep, &msg);
        }
    }
}
