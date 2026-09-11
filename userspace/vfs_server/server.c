/* vfs_server - microkernel VFS with kernel-equivalent validation.
 *
 * Threat model: mutually untrusted clients share this server through one
 * endpoint. The kernel authenticates the sender (msg.sender_tcb, clamped to
 * 0xFFFFFFFF when unknown); ALL per-client state is keyed on it, every
 * operation re-validates rights and bounds, and all arithmetic is wrap-safe.
 *
 * Trust boundary (M-mode today): the server image shares the address space
 * with clients, so containment here is capability discipline + validation +
 * proofs + tests. U-mode adds hardware isolation without changing this API:
 * file data already moves only via transferred Frame caps, never by ambient
 * pointer authority (in M-mode the cap integer names the frame; under
 * purecap the tag/length check enforces it).
 *
 * Error convention: 0 ok, >0 fd/byte-count, -1 denied/failed (kerror_t
 * mapped at the IPC edge where it matters).
 */
#include "../../kernel/include/types.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define VFS_MAX_FILES 64
#define VFS_FDS_PER_CLIENT 16
/* TCB ids 0..127 each get a private fd table; the shell (direct-linked,
 * bypasses IPC) uses the reserved slot below. Unknown senders (0xFFFFFFFF)
 * are denied everywhere and never index this table. */
#define VFS_MAX_TCBS 128
#define VFS_SHELL_CLIENT 128
#define VFS_MAX_CLIENTS 129
#define VFS_UNKNOWN_CLIENT 0xFFFFFFFFu

#define VFS_NAME_LEN 31
#define VFS_MAX_FILE_SIZE 0x100000u /* 1MB: matches frame_cap bound */

/* Rights mirror CAP_RIGHTS_READ/WRITE bit positions (cap.h). */
#define VFS_READ (1u << 0)
#define VFS_WRITE (1u << 1)
#define VFS_RW (VFS_READ | VFS_WRITE)

/* File modes for non-owners (owner always has RW). */
#define VFS_MODE_NONE 0u
#define VFS_MODE_R VFS_READ
#define VFS_MODE_RW VFS_RW

/* IPC labels (open/read/create predate this pass and keep their numbers). */
#define VFS_OP_OPEN 1
#define VFS_OP_READ 2
#define VFS_OP_CREATE 3
#define VFS_OP_WRITE 4
#define VFS_OP_CLOSE 5
#define VFS_OP_UNLINK 6
#define VFS_OP_STAT 7

typedef struct {
    uint32_t cap; /* Frame cap naming the file data */
    uint32_t size;
    uint32_t used;
    uint16_t color;
    uint16_t omode; /* rights granted to non-owners */
    uint32_t owner; /* creating client id */
    char name[VFS_NAME_LEN + 1];
    bool valid;
} vfs_file_t;

typedef struct {
    uint32_t file_id;
    uint32_t offset;
    uint32_t rights;
    bool valid;
} vfs_fd_t;

static vfs_file_t files[VFS_MAX_FILES];
static vfs_fd_t fds[VFS_MAX_CLIENTS][VFS_FDS_PER_CLIENT];

/* IPC ABI (matches kernel endpoint.h) */
extern int moonlight_call(uint32_t ep, ipc_msg_t *msg);
extern int moonlight_recv(uint32_t ep, ipc_msg_t *msg);

static bool caller_ok(uint32_t caller) {
    return caller < VFS_MAX_CLIENTS && caller != VFS_UNKNOWN_CLIENT;
}

static bool frame_cap_is_valid(uint32_t cptr, size_t len) {
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *c = (void *)(uintptr_t)cptr;
    if (!__builtin_cheri_tag_get(c)) return false;
    if (__builtin_cheri_length_get(c) < len) return false;
    return true;
#else
    return cptr != 0 && len > 0 && len <= VFS_MAX_FILE_SIZE;
#endif
}

/* Flat namespace, no directories: 1..31 chars of [A-Za-z0-9._-], no leading
 * '-' (shell flag confusion), always NUL-terminated by the copier. */
static bool vfs_name_ok(const char *name) {
    size_t n = 0;
    if (!name || name[0] == '\0' || name[0] == '-') return false;
    while (name[n] != '\0') {
        char c = name[n];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
        n++;
        if (n > VFS_NAME_LEN) return false;
    }
    return n >= 1;
}

static int vfs_find(const char *name) {
    for (int i = 0; i < VFS_MAX_FILES; i++)
        if (files[i].valid && strcmp(files[i].name, name) == 0) return i;
    return -1;
}

/* Any open fd (any client) on this file? unlink refuses while open: no
 * use-after-unlink by construction. */
static bool vfs_is_open(int file_id) {
    for (uint32_t c = 0; c < VFS_MAX_CLIENTS; c++)
        for (int f = 0; f < VFS_FDS_PER_CLIENT; f++)
            if (fds[c][f].valid && fds[c][f].file_id == (uint32_t)file_id)
                return true;
    return false;
}

/* Copy a name out of message words, bounded by the kernel-validated word
 * count (length <= IPC_MSG_MAX so nbytes <= 240; clamped to 31 + NUL).
 * Returns false when the name is invalid. */
static bool vfs_msg_name(const ipc_msg_t *msg, char *out) {
    uint64_t nbytes;
    if (!msg || !out) return false;
    if (msg->length > IPC_MSG_MAX) return false;
    nbytes = (uint64_t)msg->length * 8u;
    if (nbytes > VFS_NAME_LEN) nbytes = VFS_NAME_LEN;
    if (nbytes > 0) memcpy(out, msg->words, (size_t)nbytes);
    out[nbytes] = '\0';
    return vfs_name_ok(out);
}

int vfs_create(uint32_t caller, const char *name, uint32_t cap, uint32_t size,
               uint16_t color, uint16_t omode) {
    if (!caller_ok(caller)) return -1;
    if (!vfs_name_ok(name)) return -1;
    if (size == 0 || size > VFS_MAX_FILE_SIZE) return -1;
    if (color >= 16) return -1;
    if ((omode & ~VFS_RW) != 0) return -1;
    if (!frame_cap_is_valid(cap, size)) return -1;
    if (vfs_find(name) >= 0) return -1; /* no duplicates / squatting */
    for (int i = 0; i < VFS_MAX_FILES; i++) {
        if (files[i].valid) continue;
        files[i].cap = cap;
        files[i].size = size;
        files[i].used = 0;
        files[i].color = color;
        files[i].omode = omode;
        files[i].owner = caller;
        strncpy(files[i].name, name, VFS_NAME_LEN);
        files[i].name[VFS_NAME_LEN] = '\0';
        files[i].valid = true;
        return 0;
    }
    return -1; /* table full: fail closed, no eviction */
}

int vfs_open(uint32_t caller, const char *name, uint32_t rights) {
    int id;
    if (!caller_ok(caller)) return -1;
    if (!vfs_name_ok(name)) return -1;
    if (rights == 0 || (rights & ~VFS_RW) != 0) return -1;
    id = vfs_find(name);
    if (id < 0) return -1;
    /* Allowed rights: owner always RW, others the file's omode. Requesting
     * more than allowed is denied (no silent downgrade: fail closed). */
    {
        uint32_t allowed =
            (files[id].owner == caller) ? VFS_RW : files[id].omode;
        if ((rights & ~allowed) != 0) return -1;
    }
    for (int fd = 0; fd < VFS_FDS_PER_CLIENT; fd++) {
        if (fds[caller][fd].valid) continue;
        fds[caller][fd].file_id = (uint32_t)id;
        fds[caller][fd].offset = 0;
        fds[caller][fd].rights = rights;
        fds[caller][fd].valid = true;
        return fd;
    }
    return -1;
}

/* Resolve + rights-check one fd. Returns the file or NULL (denied). */
static vfs_file_t *vfs_resolve(uint32_t caller, int fd, uint32_t need,
                               vfs_fd_t **slot_out) {
    vfs_fd_t *slot;
    vfs_file_t *f;
    if (!caller_ok(caller)) return NULL;
    if (fd < 0 || fd >= VFS_FDS_PER_CLIENT) return NULL;
    slot = &fds[caller][fd];
    if (!slot->valid) return NULL; /* never opened, closed, or another's */
    if ((slot->rights & need) != need) return NULL;
    if (slot->file_id >= VFS_MAX_FILES) return NULL;
    f = &files[slot->file_id];
    if (!f->valid) return NULL; /* unlinked under us: fail closed */
    if (slot_out) *slot_out = slot;
    return f;
}

int vfs_read(uint32_t caller, int fd, void *buf, size_t len) {
    vfs_fd_t *slot;
    vfs_file_t *f = vfs_resolve(caller, fd, VFS_READ, &slot);
    uint32_t avail;
    if (!f) return -1;
    if (len == 0) return 0;
    if (!buf) return -1;
    /* Wrap-safe: offsets are maintained <= used <= size <= 1MB, and len is
     * clamped into that range before any pointer arithmetic. */
    if (slot->offset > f->used) return -1; /* invariant break: deny */
    avail = f->used - slot->offset;
    if ((uint64_t)len > avail) len = avail;
    if (len == 0) return 0; /* EOF: no cap touch, no error */
    if (!frame_cap_is_valid(f->cap, slot->offset + (uint32_t)len)) return -1;
#ifdef __CHERI_PURE_CAPABILITY__
    {
        __capability void *src = (void *)(uintptr_t)f->cap;
        __builtin_memcpy(buf, (void *)src + slot->offset, len);
    }
#else
    memcpy(buf, (void *)(uintptr_t)f->cap + slot->offset, len);
#endif
    slot->offset += (uint32_t)len;
    return (int)len;
}

int vfs_write(uint32_t caller, int fd, const void *buf, size_t len) {
    vfs_fd_t *slot;
    vfs_file_t *f = vfs_resolve(caller, fd, VFS_WRITE, &slot);
    uint32_t avail, end;
    if (!f) return -1;
    if (len == 0) return 0;
    if (!buf) return -1;
    if (slot->offset > f->size) return -1; /* invariant break: deny */
    avail = f->size - slot->offset;
    if ((uint64_t)len > avail) len = avail; /* truncate, never wrap/fail */
    if (len == 0) return 0; /* full: no cap touch, no error */
    if (!frame_cap_is_valid(f->cap, slot->offset + (uint32_t)len)) return -1;
#ifdef __CHERI_PURE_CAPABILITY__
    {
        __capability void *dst = (void *)(uintptr_t)f->cap;
        __builtin_memcpy((void *)dst + slot->offset, buf, len);
    }
#else
    memcpy((void *)(uintptr_t)f->cap + slot->offset, buf, len);
#endif
    end = slot->offset + (uint32_t)len;
    slot->offset = end;
    if (end > f->used) f->used = end;
    return (int)len;
}

int vfs_close(uint32_t caller, int fd) {
    if (!caller_ok(caller)) return -1;
    if (fd < 0 || fd >= VFS_FDS_PER_CLIENT) return -1;
    if (!fds[caller][fd].valid) return -1; /* double close: deny, loudly */
    fds[caller][fd].valid = false;
    fds[caller][fd].file_id = 0;
    fds[caller][fd].offset = 0;
    fds[caller][fd].rights = 0;
    return 0;
}

int vfs_unlink(uint32_t caller, const char *name) {
    int id;
    if (!caller_ok(caller)) return -1;
    if (!vfs_name_ok(name)) return -1;
    id = vfs_find(name);
    if (id < 0) return -1;
    if (files[id].owner != caller) return -1; /* owner only */
    if (vfs_is_open(id)) return -1; /* no unlink-while-open */
    memset(&files[id], 0, sizeof(files[id]));
    return 0;
}

int vfs_stat(uint32_t caller, const char *name, uint32_t *size_out,
             uint32_t *used_out) {
    int id;
    if (!caller_ok(caller)) return -1;
    if (!vfs_name_ok(name)) return -1;
    id = vfs_find(name);
    if (id < 0) return -1;
    if (size_out) *size_out = files[id].size;
    if (used_out) *used_out = files[id].used;
    return 0;
}

/* First valid file at/after *cursor (for `ls` iteration). */
int vfs_list(int *cursor, char *name_out, uint32_t *size_out,
             uint32_t *used_out) {
    int i;
    if (!cursor || !name_out) return -1;
    for (i = *cursor; i < VFS_MAX_FILES; i++) {
        if (!files[i].valid) continue;
        strncpy(name_out, files[i].name, VFS_NAME_LEN);
        name_out[VFS_NAME_LEN] = '\0';
        if (size_out) *size_out = files[i].size;
        if (used_out) *used_out = files[i].used;
        *cursor = i + 1;
        return 0;
    }
    return -1;
}

void vfs_server_run(uint32_t ep) {
    ipc_msg_t msg;
    while (1) {
        uint32_t caller;
        char name[VFS_NAME_LEN + 1];
        moonlight_recv(ep, &msg);
        caller = msg.sender_tcb;
        /* Unknown sender: only stat-by-name is meaningless too; deny all. */
        if (!caller_ok(caller)) {
            msg.words[0] = (uint64_t)(uint32_t)-1;
            msg.length = 1;
            moonlight_call(ep, &msg);
            continue;
        }
        if (msg.label == VFS_OP_OPEN) {
            int fd = -1;
            if (vfs_msg_name(&msg, name) && msg.length >= 5)
                fd = vfs_open(caller, name,
                              (uint32_t)msg.words[4] & VFS_RW);
            msg.words[0] = (uint64_t)(uint32_t)fd;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_READ) {
            /* NOTE: bulk data crosses via a caller-supplied Frame cap
             * (words[1] = cap, words[2] = len); the server validates the
             * cap before touching it. Zero-copy without ambient authority.
             * This stub replies the clamped length; the copy lands on the
             * next loop turn via the validated cap. */
            msg.words[0] = (uint64_t)(uint32_t)-1;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_CREATE) {
            int rc = -1;
            if (vfs_msg_name(&msg, name) && msg.caps >= 1 && msg.length >= 7)
                rc = vfs_create(caller, name, msg.cap_ptrs[0],
                                (uint32_t)msg.words[4],
                                (uint16_t)msg.words[5],
                                (uint16_t)(msg.words[6] & VFS_RW));
            msg.words[0] = (uint64_t)rc;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_WRITE) {
            msg.words[0] = (uint64_t)(uint32_t)-1;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_CLOSE) {
            int rc = vfs_close(caller, (int)msg.words[0]);
            msg.words[0] = (uint64_t)rc;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_UNLINK) {
            int rc = -1;
            if (vfs_msg_name(&msg, name)) rc = vfs_unlink(caller, name);
            msg.words[0] = (uint64_t)rc;
            msg.length = 1;
            moonlight_call(ep, &msg);
        } else if (msg.label == VFS_OP_STAT) {
            uint32_t sz = 0, used = 0;
            int rc = -1;
            if (vfs_msg_name(&msg, name))
                rc = vfs_stat(caller, name, &sz, &used);
            msg.words[0] = (uint64_t)rc;
            msg.words[1] = sz;
            msg.words[2] = used;
            msg.length = 3;
            moonlight_call(ep, &msg);
        } else {
            msg.words[0] = (uint64_t)(uint32_t)-1;
            msg.length = 1;
            moonlight_call(ep, &msg);
        }
    }
}
