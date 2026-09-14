/* libc ether: Ethernet address text conversion + /etc/ethers
 * lookup. All pure string/file logic. */
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int ml_hexdig(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr) {
    int i;
    if (!asc || !addr) return 0;
    for (i = 0; i < 6; i++) {
        int hi, lo;
        if (!isxdigit((unsigned char)asc[0])) return 0;
        hi = ml_hexdig(asc[0]);
        if (isxdigit((unsigned char)asc[1]) && asc[1] != ':' &&
            asc[1] != '-' && asc[1] != 0) {
            lo = ml_hexdig(asc[1]);
            addr->ether_addr_octet[i] = (uint8_t)((hi << 4) | lo);
            asc += 2;
        } else {
            addr->ether_addr_octet[i] = (uint8_t)hi;
            asc += 1;
        }
        if (i < 5) {
            if (*asc != ':' && *asc != '-') return 0;
            asc++;
        }
    }
    if (*asc != '\0' && !isspace((unsigned char)*asc)) return 0;
    return addr;
}

struct ether_addr *ether_aton(const char *asc) {
    static struct ether_addr a;
    return ether_aton_r(asc, &a);
}

char *ether_ntoa_r(const struct ether_addr *addr, char *buf) {
    static const char dig[] = "0123456789abcdef";
    int i, o = 0;
    uint8_t b;
    if (!addr || !buf) return 0;
    /* glibc format: first octet unpadded (%x), the rest zero-padded
     * (%02x), colon-separated. */
    b = addr->ether_addr_octet[0];
    if (b >= 16) buf[o++] = dig[b >> 4];
    buf[o++] = dig[b & 15];
    for (i = 1; i < 6; i++) {
        b = addr->ether_addr_octet[i];
        buf[o++] = ':';
        buf[o++] = dig[b >> 4];
        buf[o++] = dig[b & 15];
    }
    buf[o] = '\0';
    return buf;
}

char *ether_ntoa(const struct ether_addr *addr) {
    static char b[18];
    return ether_ntoa_r(addr, b);
}

int ether_line(const char *line, struct ether_addr *addr, char *hostname) {
    const char *p;
    char tmp[18];
    int i = 0;
    if (!line || !addr || !hostname) return -1;
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '#' || *line == '\0' || *line == '\n') return -1;
    /* /etc/ethers format: address first, hostname second. */
    p = line;
    {
        int k = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && k < 17)
            tmp[k++] = *p++;
        tmp[k] = '\0';
        if (!ether_aton_r(tmp, addr)) return -1;
    }
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n') return -1;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && i < 255) {
        hostname[i] = *p;
        i++;
        p++;
    }
    hostname[i] = '\0';
    return 0;
}

int ether_hostton(const char *hostname, struct ether_addr *addr) {
    FILE *fp;
    char line[512], name[256];
    struct ether_addr a;
    if (!hostname || !addr) return -1;
    fp = fopen("/etc/ethers", "r");
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        if (ether_line(line, &a, name) != 0) continue;
        if (strcmp(name, hostname) == 0) {
            *addr = a;
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

int ether_ntohost(char *hostname, const struct ether_addr *addr) {
    FILE *fp;
    char line[512], name[256];
    struct ether_addr a;
    if (!hostname || !addr) return -1;
    fp = fopen("/etc/ethers", "r");
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        if (ether_line(line, &a, name) != 0) continue;
        if (memcmp(a.ether_addr_octet, addr->ether_addr_octet, 6) == 0) {
            strcpy(hostname, name);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}
