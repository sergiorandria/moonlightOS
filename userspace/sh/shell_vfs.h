/*
 * shell_vfs.h - Embedded in-memory Virtual File System for moonsh
 *
 * Provides a lightweight, zero-allocation hierarchical VFS with:
 * - Directories and files in RAM
 * - Dynamic /proc virtual files (version, uptime, meminfo, cpuinfo, threads, mounts)
 * - Pre-populated system files (/etc/os-release, /etc/motd, /readme.txt, /bin/demo.sh)
 * - Canonical path resolution (., .., relative paths, cwd)
 */

#ifndef SHELL_VFS_H
#define SHELL_VFS_H

#include <stddef.h>
#include <stdint.h>

#define VFS_MAX_NODES 32
#define VFS_NAME_MAX 28
#define VFS_FILE_MAX 1024
#define VFS_PATH_MAX 96

typedef struct
{
    char name[VFS_NAME_MAX];
    uint8_t is_dir;
    uint8_t in_use;
    uint16_t parent_idx;
    uint32_t size;
    uint64_t mtime;
    char data[VFS_FILE_MAX];
} vfs_node_t;

static vfs_node_t vfs_nodes[VFS_MAX_NODES];
static int vfs_initialized = 0;

/* Helper string routines */
static inline int vfs_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b)
    {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int vfs_strncmp(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (a[i] != b[i] || a[i] == '\0')
            return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

static inline int vfs_strlen(const char *s)
{
    int len = 0;
    while (s && s[len])
        len++;
    return len;
}

static inline void vfs_strcpy(char *dst, const char *src, int max)
{
    int i = 0;
    while (src && src[i] && i < max - 1)
    {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static inline void vfs_strcat(char *dst, const char *src, int max)
{
    int dlen = vfs_strlen(dst);
    int i = 0;
    while (src && src[i] && (dlen + i) < max - 1)
    {
        dst[dlen + i] = src[i];
        i++;
    }
    dst[dlen + i] = '\0';
}

/* Time getter for mtime */
static inline uint64_t vfs_get_time(void)
{
#ifdef __riscv
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
#else
    static uint64_t tick = 100;
    return ++tick;
#endif
}

/* Path canonicalization: combines cwd and rel_path into canonical absolute path */
static inline void vfs_resolve_path(const char *cwd, const char *rel, char *out, int max_len)
{
    char temp[VFS_PATH_MAX];

    if (!rel || rel[0] == '\0')
    {
        vfs_strcpy(out, cwd ? cwd : "/", max_len);
        return;
    }

    if (rel[0] == '/')
    {
        vfs_strcpy(temp, rel, sizeof(temp));
    }
    else
    {
        vfs_strcpy(temp, cwd ? cwd : "/", sizeof(temp));
        if (temp[vfs_strlen(temp) - 1] != '/')
        {
            vfs_strcat(temp, "/", sizeof(temp));
        }
        vfs_strcat(temp, rel, sizeof(temp));
    }

    /* Tokenize segments by '/' and resolve . and .. */
    char segs[16][VFS_NAME_MAX];
    int nsegs = 0;
    const char *p = temp;

    while (*p)
    {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        int l = 0;
        char seg[VFS_NAME_MAX];
        while (*p && *p != '/' && l < VFS_NAME_MAX - 1)
        {
            seg[l++] = *p++;
        }
        seg[l] = '\0';

        if (vfs_strcmp(seg, ".") == 0)
        {
            /* ignore */
        }
        else if (vfs_strcmp(seg, "..") == 0)
        {
            if (nsegs > 0)
                nsegs--;
        }
        else
        {
            if (nsegs < 16)
            {
                vfs_strcpy(segs[nsegs++], seg, VFS_NAME_MAX);
            }
        }
    }

    if (nsegs == 0)
    {
        vfs_strcpy(out, "/", max_len);
        return;
    }

    out[0] = '\0';
    for (int i = 0; i < nsegs; i++)
    {
        vfs_strcat(out, "/", max_len);
        vfs_strcat(out, segs[i], max_len);
    }
}

/* Find node index by path */
static inline int vfs_find(const char *path)
{
    if (!vfs_initialized || !path)
        return -1;
    if (vfs_strcmp(path, "/") == 0)
        return 0; /* root */

    /* Normalize path */
    char norm[VFS_PATH_MAX];
    vfs_resolve_path("/", path, norm, sizeof(norm));

    /* Walk path components */
    int cur_idx = 0;
    const char *p = norm;
    while (*p == '/')
        p++;

    while (*p)
    {
        char seg[VFS_NAME_MAX];
        int l = 0;
        while (*p && *p != '/' && l < VFS_NAME_MAX - 1)
        {
            seg[l++] = *p++;
        }
        seg[l] = '\0';
        while (*p == '/')
            p++;

        int found = -1;
        for (int i = 0; i < VFS_MAX_NODES; i++)
        {
            if (vfs_nodes[i].in_use && vfs_nodes[i].parent_idx == (uint16_t)cur_idx &&
                vfs_strcmp(vfs_nodes[i].name, seg) == 0)
            {
                found = i;
                break;
            }
        }
        if (found < 0)
            return -1;
        cur_idx = found;
    }
    return cur_idx;
}

/* Allocate a new node */
static inline int vfs_alloc_node(int parent_idx, const char *name, uint8_t is_dir)
{
    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        if (!vfs_nodes[i].in_use)
        {
            vfs_nodes[i].in_use = 1;
            vfs_nodes[i].is_dir = is_dir;
            vfs_nodes[i].parent_idx = (uint16_t)parent_idx;
            vfs_nodes[i].size = 0;
            vfs_nodes[i].mtime = vfs_get_time();
            vfs_nodes[i].data[0] = '\0';
            vfs_strcpy(vfs_nodes[i].name, name, VFS_NAME_MAX);
            return i;
        }
    }
    return -1;
}

/* Create a file or directory at path */
static inline int vfs_create_node(const char *path, uint8_t is_dir)
{
    char norm[VFS_PATH_MAX];
    vfs_resolve_path("/", path, norm, sizeof(norm));

    if (vfs_strcmp(norm, "/") == 0)
        return 0;
    if (vfs_find(norm) >= 0)
        return -1; /* already exists */

    /* Find parent directory */
    char parent_path[VFS_PATH_MAX];
    char child_name[VFS_NAME_MAX];
    int len = vfs_strlen(norm);
    int last_slash = -1;
    for (int i = len - 1; i >= 0; i--)
    {
        if (norm[i] == '/')
        {
            last_slash = i;
            break;
        }
    }
    if (last_slash <= 0)
    {
        vfs_strcpy(parent_path, "/", sizeof(parent_path));
        vfs_strcpy(child_name, norm + 1, sizeof(child_name));
    }
    else
    {
        int i;
        for (i = 0; i < last_slash; i++)
            parent_path[i] = norm[i];
        parent_path[i] = '\0';
        vfs_strcpy(child_name, norm + last_slash + 1, sizeof(child_name));
    }

    int pidx = vfs_find(parent_path);
    if (pidx < 0 || !vfs_nodes[pidx].is_dir)
        return -2; /* parent not found or not dir */

    return vfs_alloc_node(pidx, child_name, is_dir);
}

/* Write content to a file node */
static inline int vfs_write_file(int idx, const char *buf, int len, int append)
{
    if (idx < 0 || idx >= VFS_MAX_NODES || !vfs_nodes[idx].in_use || vfs_nodes[idx].is_dir)
        return -1;

    vfs_node_t *node = &vfs_nodes[idx];
    int start_pos = append ? (int)node->size : 0;
    int write_len = len;

    if (start_pos + write_len >= VFS_FILE_MAX)
    {
        write_len = VFS_FILE_MAX - 1 - start_pos;
        if (write_len < 0)
            write_len = 0;
    }

    for (int i = 0; i < write_len; i++)
    {
        node->data[start_pos + i] = buf[i];
    }
    node->size = (uint32_t)(start_pos + write_len);
    node->data[node->size] = '\0';
    node->mtime = vfs_get_time();
    return write_len;
}

/* Dynamic procfs file contents generator */
static inline int vfs_read_proc(const char *name, char *buf, int max_len)
{
    int len = 0;
    buf[0] = '\0';

    if (vfs_strcmp(name, "version") == 0)
    {
        const char *v =
            "MoonlightOS version 0.3.0 (rv64imac-Sv39, microkernel) #1 Mon Oct 5 2026\n";
        vfs_strcpy(buf, v, max_len);
        len = vfs_strlen(buf);
    }
    else if (vfs_strcmp(name, "uptime") == 0)
    {
        uint64_t t = vfs_get_time();
        uint32_t secs = (uint32_t)(t / 10000000ULL);
        /* Simple format */
        char sbuf[32];
        int si = 0;
        uint32_t temp = secs;
        if (temp == 0)
            sbuf[si++] = '0';
        else
        {
            char digits[16];
            int di = 0;
            while (temp > 0)
            {
                digits[di++] = '0' + (temp % 10);
                temp /= 10;
            }
            while (di > 0)
                sbuf[si++] = digits[--di];
        }
        sbuf[si++] = '.';
        sbuf[si++] = '0';
        sbuf[si++] = '0';
        sbuf[si++] = '\n';
        sbuf[si] = '\0';
        vfs_strcpy(buf, sbuf, max_len);
        len = vfs_strlen(buf);
    }
    else if (vfs_strcmp(name, "meminfo") == 0)
    {
        const char *m = "MemTotal:        262144 kB\n"
                        "MemFree:         245760 kB\n"
                        "MemAvailable:    245760 kB\n"
                        "Buffers:           4096 kB\n"
                        "Cached:           12288 kB\n"
                        "Active:            8192 kB\n"
                        "Inactive:          8192 kB\n";
        vfs_strcpy(buf, m, max_len);
        len = vfs_strlen(buf);
    }
    else if (vfs_strcmp(name, "cpuinfo") == 0)
    {
        const char *c = "processor       : 0\n"
                        "hart            : 0\n"
                        "isa             : rv64imafdc_sstc_zicntr\n"
                        "mmu             : sv39\n"
                        "uabi            : v2\n"
                        "model           : riscv-virtio,qemu\n";
        vfs_strcpy(buf, c, max_len);
        len = vfs_strlen(buf);
    }
    else if (vfs_strcmp(name, "threads") == 0)
    {
        const char *th = "TID  NAME         STATE    PRIO  ROLE\n"
                         "  1  moonsh       RUNNING     0  Shell Application\n"
                         "  2  mem_server   SLEEPING    0  Memory Allocator\n"
                         "  3  console      SLEEPING    0  Virtual Console Service\n"
                         "  4  tty          SLEEPING    0  Line Discipline Service\n"
                         " 10  gui          SLEEPING    0  Display & Input Driver\n";
        vfs_strcpy(buf, th, max_len);
        len = vfs_strlen(buf);
    }
    else if (vfs_strcmp(name, "mounts") == 0)
    {
        const char *mo = "rootfs / ramfs rw,relatime 0 0\n"
                         "proc /proc procfs rw,nosuid,nodev,noexec 0 0\n"
                         "dev /dev devtmpfs rw,nosuid 0 0\n"
                         "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
        vfs_strcpy(buf, mo, max_len);
        len = vfs_strlen(buf);
    }
    else
    {
        return -1;
    }
    return len;
}

/* Read from a file node */
static inline int vfs_read_file(int idx, char *buf, int max_len)
{
    if (idx < 0 || idx >= VFS_MAX_NODES || !vfs_nodes[idx].in_use || vfs_nodes[idx].is_dir)
        return -1;

    /* Check if inside /proc (parent is /proc) */
    int pidx = vfs_nodes[idx].parent_idx;
    if (pidx >= 0 && vfs_strcmp(vfs_nodes[pidx].name, "proc") == 0)
    {
        int r = vfs_read_proc(vfs_nodes[idx].name, buf, max_len);
        if (r >= 0)
            return r;
    }

    vfs_node_t *node = &vfs_nodes[idx];
    int len = (int)node->size;
    if (len > max_len - 1)
        len = max_len - 1;

    for (int i = 0; i < len; i++)
    {
        buf[i] = node->data[i];
    }
    buf[len] = '\0';
    return len;
}

/* Delete a node (file or empty directory) */
static inline int vfs_unlink_node(const char *path)
{
    int idx = vfs_find(path);
    if (idx <= 0)
        return -1; /* root cannot be unlinked, not found */

    if (vfs_nodes[idx].is_dir)
    {
        /* Check if directory is empty */
        for (int i = 0; i < VFS_MAX_NODES; i++)
        {
            if (vfs_nodes[i].in_use && vfs_nodes[i].parent_idx == (uint16_t)idx)
            {
                return -2; /* not empty */
            }
        }
    }

    vfs_nodes[idx].in_use = 0;
    vfs_nodes[idx].name[0] = '\0';
    return 0;
}

/* Initialize VFS structure and pre-populate files */
static inline void vfs_init(void)
{
    if (vfs_initialized)
        return;

    for (int i = 0; i < VFS_MAX_NODES; i++)
    {
        vfs_nodes[i].in_use = 0;
    }

    /* Root / */
    vfs_nodes[0].in_use = 1;
    vfs_nodes[0].is_dir = 1;
    vfs_nodes[0].parent_idx = 0;
    vfs_nodes[0].size = 0;
    vfs_nodes[0].mtime = vfs_get_time();
    vfs_strcpy(vfs_nodes[0].name, "/", VFS_NAME_MAX);

    vfs_initialized = 1;

    /* Create standard directories */
    vfs_create_node("/etc", 1);
    vfs_create_node("/bin", 1);
    vfs_create_node("/proc", 1);
    vfs_create_node("/tmp", 1);
    vfs_create_node("/dev", 1);

    /* /etc/os-release */
    int fd = vfs_create_node("/etc/os-release", 0);
    if (fd >= 0)
    {
        const char *os_rel = "NAME=\"MoonlightOS\"\n"
                             "VERSION=\"0.3.0\"\n"
                             "ID=\"moonlight\"\n"
                             "PRETTY_NAME=\"MoonlightOS 0.3.0 (RISC-V Sv39 Microkernel)\"\n"
                             "ARCH=\"riscv64\"\n"
                             "HOME_URL=\"https://github.com/sergiorandria/moonlightOS\"\n";
        vfs_write_file(fd, os_rel, vfs_strlen(os_rel), 0);
    }

    /* /etc/motd */
    fd = vfs_create_node("/etc/motd", 0);
    if (fd >= 0)
    {
        const char *motd = "==========================================================\n"
                           "  MoonlightOS 0.3 - Production Microkernel Shell (moonsh) \n"
                           "  Built with pure inline IPC & unified BusyBox applets   \n"
                           "==========================================================\n"
                           "Type 'help' or 'busybox' to list available commands.\n";
        vfs_write_file(fd, motd, vfs_strlen(motd), 0);
    }

    /* /etc/version */
    fd = vfs_create_node("/etc/version", 0);
    if (fd >= 0)
    {
        const char *ver = "0.3.0\n";
        vfs_write_file(fd, ver, vfs_strlen(ver), 0);
    }

    /* /etc/hostname */
    fd = vfs_create_node("/etc/hostname", 0);
    if (fd >= 0)
    {
        const char *host = "moonlight\n";
        vfs_write_file(fd, host, vfs_strlen(host), 0);
    }

    /* /readme.txt */
    fd = vfs_create_node("/readme.txt", 0);
    if (fd >= 0)
    {
        const char *readme =
            "MoonlightOS Production Shell (moonsh)\n"
            "-------------------------------------\n"
            "Features:\n"
            "  - In-memory VFS with dynamic /proc filesystem\n"
            "  - Command chaining (';'), pipes ('|'), and output redirection ('>', '>>')\n"
            "  - Variable expansion ($?, $$, $USER, $HOSTNAME, $PWD)\n"
            "  - Built-in arithmetic evaluator ('calc' / 'expr')\n"
            "  - Over 50 BusyBox-compatible commands\n";
        vfs_write_file(fd, readme, vfs_strlen(readme), 0);
    }

    /* /bin/demo.sh */
    fd = vfs_create_node("/bin/demo.sh", 0);
    if (fd >= 0)
    {
        const char *demo = "# MoonlightOS demonstration script\n"
                           "echo \"[+] System architecture:\"\n"
                           "uname -a\n"
                           "echo \"[+] System uptime:\"\n"
                           "uptime\n"
                           "echo \"[+] Process list:\"\n"
                           "ps\n"
                           "echo \"[+] Finished demo.\"\n";
        vfs_write_file(fd, demo, vfs_strlen(demo), 0);
    }

    /* Register virtual files inside /proc */
    vfs_create_node("/proc/version", 0);
    vfs_create_node("/proc/uptime", 0);
    vfs_create_node("/proc/meminfo", 0);
    vfs_create_node("/proc/cpuinfo", 0);
    vfs_create_node("/proc/threads", 0);
    vfs_create_node("/proc/mounts", 0);
}

#endif /* SHELL_VFS_H */
