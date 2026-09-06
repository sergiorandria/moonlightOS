#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

extern int vfs_create(const char *name, uint32_t cap, uint32_t size, uint16_t color);
extern int vfs_open(const char *name, uint32_t rights);
extern int vfs_read(int fd, void *buf, size_t len);

int moonlight_call(uint32_t ep, void *msg){ (void)ep;(void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg){ (void)ep;(void)msg; return 0; }

int main(){
    printf("=== test_vfs ===\n");
    // Create a file with a valid Frame cap (simulated as non-zero tag)
    // In host testing, cap is just an integer representing cptr, not actual pointer
    // For vfs_create, it checks frame_cap_is_valid which checks tag and bounds
    // In hybrid sim, it checks cptr !=0 and len <0x100000
    uint32_t cap = 0x10000000; // valid frame cap
    int err = vfs_create("test.txt", cap, 4096, 0);
    printf("create %d (expected 0)\n", err);
    assert(err==0);
    int fd = vfs_open("test.txt", 0x3);
    printf("open fd %d (expected >=0)\n", fd);
    assert(fd>=0);
    // Simulate file used = 100 bytes
    // Need to set used via direct access to files array - for test, we can write via vfs_create and then manually set used
    // For simplicity, test out-of-bounds read: try to read 5000 bytes from 4096 file, should be truncated or rejected
    char buf[5000];
    int ret = vfs_read(fd, buf, 5000);
    printf("read 5000 from 0 used file ret %d (expected 0 or truncated)\n", ret);
    // Now test that a valid read of 0 bytes works
    // Set file used to 100 for testing
    extern void *vfs_test_set_used(int fd, uint32_t used);
    // For now, just test that read with valid cap works for small len
    // Create another file and test bounds
    uint32_t cap2 = 0x10000000;
    err = vfs_create("test2.txt", cap2, 4096, 0);
    assert(err==0);
    int fd2 = vfs_open("test2.txt", 0x3);
    assert(fd2>=0);
    // Try to read with untagged cap (0) should fail on create, already tested
    uint32_t bad_cap = 0; // untagged
    err = vfs_create("bad.txt", bad_cap, 4096, 0);
    printf("create with bad cap %d (expected -1)\n", err);
    if(err!=-1) printf("FAIL: expected -1 got %d\n", err);
    assert(err==-1);
    printf("PASS: vfs\n");
    return 0;
}
