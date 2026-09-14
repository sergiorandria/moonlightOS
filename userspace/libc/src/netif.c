/* libc netif: loopback interface table (lo, index 1) + getifaddrs.
 * The kernel socket table speaks AF_UNIX and loopback AF_INET, so the
 * one real interface is lo (127.0.0.1/8, UP+LOOPBACK+RUNNING); every
 * query walks this table, no stubs. */
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define ML_IF_LO_INDEX 1
#define ML_IF_LO_NAME "lo"
#define ML_IF_LO_FLAGS \
    (IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_MULTICAST)
#define ML_IF_LO_MTU 65536

unsigned if_nametoindex(const char *name) {
    if (!name) {
        errno = EFAULT;
        return 0;
    }
    if (strcmp(name, ML_IF_LO_NAME) == 0) return ML_IF_LO_INDEX;
    errno = ENXIO;
    return 0;
}

char *if_indextoname(unsigned idx, char *buf) {
    if (idx != ML_IF_LO_INDEX) {
        errno = ENXIO;
        return 0;
    }
    if (!buf) {
        errno = EFAULT;
        return 0;
    }
    memcpy(buf, ML_IF_LO_NAME, sizeof(ML_IF_LO_NAME));
    return buf;
}

struct if_nameindex *if_nameindex(void) {
    struct if_nameindex *list;
    char *name;
    list = malloc(2 * sizeof(*list));
    if (!list) {
        errno = ENOMEM;
        return 0;
    }
    name = strdup(ML_IF_LO_NAME);
    if (!name) {
        free(list);
        errno = ENOMEM;
        return 0;
    }
    list[0].if_index = ML_IF_LO_INDEX;
    list[0].if_name = name;
    list[1].if_index = 0;
    list[1].if_name = 0;
    return list;
}

void if_freenameindex(struct if_nameindex *p) {
    unsigned i;
    if (!p) return;
    for (i = 0; p[i].if_name || p[i].if_index; i++) free(p[i].if_name);
    free(p);
}

/* Fill a loopback AF_INET sockaddr without depending on inet.c:
 * network order is byte order, so store the bytes directly (correct
 * on either endianness). */
static void ml_fill_sin(struct sockaddr_in *sin, unsigned char a,
                        unsigned char b, unsigned char c,
                        unsigned char d) {
    unsigned char *p;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    p = (unsigned char *)&sin->sin_addr;
    p[0] = a;
    p[1] = b;
    p[2] = c;
    p[3] = d;
}

int getifaddrs(struct ifaddrs **list) {
    struct ifaddrs *ifa;
    struct sockaddr_in *addr, *mask;
    char *name;
    if (!list) {
        errno = EFAULT;
        return -1;
    }
    ifa = malloc(sizeof(*ifa));
    addr = malloc(sizeof(*addr));
    mask = malloc(sizeof(*mask));
    name = strdup(ML_IF_LO_NAME);
    if (!ifa || !addr || !mask || !name) {
        free(ifa);
        free(addr);
        free(mask);
        free(name);
        errno = ENOMEM;
        return -1;
    }
    ml_fill_sin(addr, 127, 0, 0, 1);
    ml_fill_sin(mask, 255, 0, 0, 0);
    memset(ifa, 0, sizeof(*ifa));
    ifa->ifa_next = 0;
    ifa->ifa_name = name;
    ifa->ifa_flags = ML_IF_LO_FLAGS;
    ifa->ifa_addr = (struct sockaddr *)addr;
    ifa->ifa_netmask = (struct sockaddr *)mask;
    ifa->ifa_dstaddr = 0;
    ifa->ifa_data = 0;
    *list = ifa;
    return 0;
}

void freeifaddrs(struct ifaddrs *list) {
    while (list) {
        struct ifaddrs *next = list->ifa_next;
        free(list->ifa_name);
        free(list->ifa_addr);
        free(list->ifa_netmask);
        free(list->ifa_dstaddr);
        free(list);
        list = next;
    }
}
