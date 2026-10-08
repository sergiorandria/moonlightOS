/* libc inet: byte order + dotted-decimal + getaddrinfo/getnameinfo
 * (numeric + localhost; service names for well-known ports). */
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

uint16_t htons(uint16_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (uint16_t)((x << 8) | (x >> 8));
#else
    return x;
#endif
}

uint16_t ntohs(uint16_t x) { return htons(x); }

uint32_t htonl(uint32_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) |
           ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24);
#else
    return x;
#endif
}

uint32_t ntohl(uint32_t x) { return htonl(x); }

static int ml_parse_ip4(const char *s, uint8_t out[4]) {
    int i;
    for (i = 0; i < 4; i++) {
        unsigned v = 0;
        int digits = 0;
        if (!*s) return -1;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s - '0');
            if (v > 255) return -1;
            s++;
            digits++;
        }
        if (digits == 0) return -1;
        out[i] = (uint8_t)v;
        if (i < 3) {
            if (*s != '.') return -1;
            s++;
        }
    }
    return *s == '\0' ? 0 : -1;
}

int inet_pton(int af, const char *src, void *dst) {
    uint8_t b[4];
    if (!src || !dst) {
        errno = EFAULT;
        return -1;
    }
    if (af == AF_INET) {
        uint32_t v;
        if (ml_parse_ip4(src, b) != 0) return 0;
        v = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
            (uint32_t)b[2] << 8 | b[3];
        *(uint32_t *)dst = htonl(v);
        return 1;
    }
    errno = EAFNOSUPPORT;
    return -1;
}

const char *inet_ntop(int af, const void *src, char *dst, unsigned n) {
    uint32_t v;
    char tmp[16];
    int i, pos = 0;
    if (!src || !dst) {
        errno = EFAULT;
        return 0;
    }
    if (af != AF_INET) {
        errno = EAFNOSUPPORT;
        return 0;
    }
    if (n < 16) {
        errno = ENOSPC;
        return 0;
    }
    v = ntohl(*(const uint32_t *)src);
    for (i = 3; i >= 0; i--) {
        unsigned o = (v >> (i * 8)) & 0xFF;
        char num[4];
        int len = 0, k;
        if (o == 0) num[len++] = '0';
        else {
            while (o > 0) {
                num[len++] = (char)('0' + o % 10);
                o /= 10;
            }
        }
        if (i != 3) tmp[pos++] = '.';
        for (k = len - 1; k >= 0; k--) tmp[pos++] = num[k];
    }
    tmp[pos] = '\0';
    memcpy(dst, tmp, (size_t)pos + 1);
    return dst;
}

uint32_t inet_addr(const char *s) {
    uint8_t b[4];
    if (!s || ml_parse_ip4(s, b) != 0) return INADDR_NONE;
    return htonl((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
                 (uint32_t)b[2] << 8 | b[3]);
}

char *inet_ntoa(struct in_addr a) {
    static char buf[16];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

/* ---- netdb ---- */

static int ml_parse_service(const char *s, int socktype, int *port_out) {
    static const struct {
        const char *name;
        int port;
    } well_known[] = {{"echo", 7},   {"daytime", 13}, {"ftp", 21},
                      {"ssh", 22},   {"telnet", 23},  {"smtp", 25},
                      {"http", 80},  {"pop3", 110},   {"ntp", 123},
                      {"https", 443}, {0, 0}};
    int i;
    unsigned long v;
    char *end;
    (void)socktype;
    if (!s || !*s) return -1;
    v = strtoul(s, &end, 10);
    if (*end == '\0' && v <= 65535) {
        *port_out = (int)v;
        return 0;
    }
    for (i = 0; well_known[i].name; i++) {
        if (strcmp(s, well_known[i].name) == 0) {
            *port_out = well_known[i].port;
            return 0;
        }
    }
    return -1;
}

static int ml_resolve_host(const char *node, uint32_t *ip_out,
                           char *canon, size_t canon_n) {
    uint8_t b[4];
    if (!node || !*node) return -1;
    if (strcmp(node, "localhost") == 0) {
        *ip_out = htonl(INADDR_LOOPBACK);
        if (canon && canon_n > 0) {
            strncpy(canon, "localhost", canon_n - 1);
            canon[canon_n - 1] = '\0';
        }
        return 0;
    }
    if (ml_parse_ip4(node, b) == 0) {
        *ip_out = htonl((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
                        (uint32_t)b[2] << 8 | b[3]);
        if (canon && canon_n > 0) {
            strncpy(canon, node, canon_n - 1);
            canon[canon_n - 1] = '\0';
        }
        return 0;
    }
    return -1; /* no DNS transport: only numeric + localhost */
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    struct addrinfo *ai = 0;
    uint32_t ip = htonl(INADDR_LOOPBACK);
    int port = 0, family = AF_INET, socktype = SOCK_STREAM, proto = 0;
    char canon[64] = "";
    if (!res) return EAI_SYSTEM;
    *res = 0;
    if (hints) {
        if (hints->ai_family != 0 && hints->ai_family != AF_INET &&
            hints->ai_family != AF_UNSPEC)
            return EAI_FAMILY;
        if (hints->ai_socktype != 0 &&
            hints->ai_socktype != SOCK_STREAM &&
            hints->ai_socktype != SOCK_DGRAM)
            return EAI_SOCKTYPE;
        if (hints->ai_socktype) socktype = hints->ai_socktype;
        if (hints->ai_flags & ~(AI_PASSIVE | AI_CANONNAME |
                                AI_NUMERICHOST | AI_NUMERICSERV))
            return EAI_BADFLAGS;
    }
    if (!node && !service) return EAI_NONAME;
    if (service && ml_parse_service(service, socktype, &port) != 0)
        return EAI_SERVICE;
    if (node) {
        if (ml_resolve_host(node, &ip, canon, sizeof(canon)) != 0)
            return EAI_NONAME;
    } else if (hints && (hints->ai_flags & AI_PASSIVE)) {
        ip = htonl(INADDR_ANY);
    }
    ai = calloc(1, sizeof(*ai) + sizeof(struct sockaddr_in) +
                       (canon[0] ? 64 : 0));
    if (!ai) return EAI_MEMORY;
    {
        struct sockaddr_in *sin =
            (struct sockaddr_in *)(ai + 1);
        sin->sin_family = (sa_family_t)family;
        sin->sin_port = htons((uint16_t)port);
        sin->sin_addr = ip;
        ai->ai_family = family;
        ai->ai_socktype = socktype;
        ai->ai_protocol = proto;
        ai->ai_addrlen = sizeof(*sin);
        ai->ai_addr = (struct sockaddr *)sin;
        if (canon[0] && hints && (hints->ai_flags & AI_CANONNAME)) {
            char *c = (char *)(sin + 1);
            memcpy(c, canon, 64);
            ai->ai_canonname = c;
        }
    }
    *res = ai;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *n = res->ai_next;
        free(res);
        res = n;
    }
}

int getnameinfo(const struct sockaddr *addr, unsigned addrlen, char *host,
                unsigned hostlen, char *serv, unsigned servlen,
                int flags) {
    if (!addr) return EAI_FAMILY;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin =
            (const struct sockaddr_in *)addr;
        if (host && hostlen > 0) {
            if (flags & NI_NUMERICHOST) {
                if (!inet_ntop(AF_INET, &sin->sin_addr, host, hostlen))
                    return EAI_SYSTEM;
            } else {
                uint32_t ip = ntohl(sin->sin_addr);
                const char *name =
                    ip == INADDR_LOOPBACK ? "localhost" : 0;
                if (!name) {
                    if (flags & NI_NAMEREQD) return EAI_NONAME;
                    if (!inet_ntop(AF_INET, &sin->sin_addr, host,
                                   hostlen))
                        return EAI_SYSTEM;
                } else {
                    size_t n = strlen(name) + 1;
                    if (n > hostlen) return EAI_MEMORY;
                    memcpy(host, name, n);
                }
            }
        }
        if (serv && servlen > 0) {
            /* Numeric service always (no reverse table beyond ports). */
            unsigned p = ntohs(sin->sin_port);
            char tmp[8];
            int len = 0, k;
            if (p == 0) tmp[len++] = '0';
            else {
                while (p > 0) {
                    tmp[len++] = (char)('0' + p % 10);
                    p /= 10;
                }
            }
            if ((unsigned)len + 1 > servlen) return EAI_MEMORY;
            for (k = 0; k < len; k++) serv[k] = tmp[len - 1 - k];
            serv[len] = '\0';
        }
        return 0;
    }
    if (addr->sa_family == AF_UNIX) {
        if (host && hostlen > 0) {
            if (hostlen < 8) return EAI_MEMORY;
            memcpy(host, "localhost", 10);
        }
        return 0;
    }
    return EAI_FAMILY;
}

static char *ml_alias_none[] = {0};

static struct hostent ml_he;
static char *ml_he_addrs[2];
static char ml_he_ip[4];

struct hostent *gethostbyname(const char *name) {
    uint32_t ip;
    char canon[64];
    if (!name || ml_resolve_host(name, &ip, canon, sizeof(canon)) != 0)
        return 0;
    memcpy(ml_he_ip, &ip, 4);
    ml_he_addrs[0] = ml_he_ip;
    ml_he_addrs[1] = 0;
    ml_he.h_name = canon[0] ? "localhost" : (char *)name;
    ml_he.h_aliases = ml_alias_none;
    ml_he.h_addrtype = AF_INET;
    ml_he.h_length = 4;
    ml_he.h_addr_list = ml_he_addrs;
    return &ml_he;
}

const char *gai_strerror(int code) {
    switch (code) {
    case 0:
        return "Success";
    case EAI_BADFLAGS:
        return "Bad flags";
    case EAI_NONAME:
        return "Name or service not known";
    case EAI_FAMILY:
        return "Family not supported";
    case EAI_SOCKTYPE:
        return "Socket type not supported";
    case EAI_SERVICE:
        return "Service not supported";
    case EAI_MEMORY:
        return "Memory allocation failure";
    default:
        return "System error";
    }
}

static char *ml_serv_alias[] = {0};
static struct servent ml_se;

struct servent *getservbyname(const char *name, const char *proto) {
    int port;
    (void)proto;
    if (!name || ml_parse_service(name, 0, &port) != 0) return 0;
    ml_se.s_name = (char *)name;
    ml_se.s_aliases = ml_serv_alias;
    ml_se.s_port = (int)htons((uint16_t)port);
    ml_se.s_proto = 0;
    return &ml_se;
}

struct servent *getservbyport(int port, const char *proto) {
    static const struct {
        const char *name;
        int p;
    } tab[] = {{"echo", 7},  {"ftp", 21},   {"ssh", 22},
               {"smtp", 25}, {"http", 80},  {"https", 443},
               {0, 0}};
    int i, want = (int)ntohs((uint16_t)port);
    (void)proto;
    for (i = 0; tab[i].name; i++) {
        if (tab[i].p == want) {
            ml_se.s_name = (char *)tab[i].name;
            ml_se.s_aliases = ml_serv_alias;
            ml_se.s_port = port;
            ml_se.s_proto = 0;
            return &ml_se;
        }
    }
    return 0;
}

/* ---- host/protocol/network databases ---- */

static int ml_h_errno = 0;
int h_errno = 0;

struct hostent *gethostbyaddr(const void *addr, unsigned len, int type) {
    char canon[64];
    if (!addr || len != 4 || type != AF_INET) {
        h_errno = ml_h_errno = NO_RECOVERY;
        return 0;
    }
    {
        uint32_t ip;
        memcpy(&ip, addr, 4);
        if (ip == htonl(INADDR_LOOPBACK)) {
            memcpy(ml_he_ip, &ip, 4);
            ml_he_addrs[0] = ml_he_ip;
            ml_he_addrs[1] = 0;
            ml_he.h_name = "localhost";
            ml_he.h_aliases = ml_alias_none;
            ml_he.h_addrtype = AF_INET;
            ml_he.h_length = 4;
            ml_he.h_addr_list = ml_he_addrs;
            h_errno = ml_h_errno = 0;
            return &ml_he;
        }
        /* Reverse-resolve numerically (no DNS transport). */
        snprintf(canon, sizeof(canon), "%u.%u.%u.%u",
                 ((unsigned char *)&ip)[0], ((unsigned char *)&ip)[1],
                 ((unsigned char *)&ip)[2], ((unsigned char *)&ip)[3]);
        memcpy(ml_he_ip, &ip, 4);
        ml_he_addrs[0] = ml_he_ip;
        ml_he_addrs[1] = 0;
        ml_he.h_name = canon;
        ml_he.h_aliases = ml_alias_none;
        ml_he.h_addrtype = AF_INET;
        ml_he.h_length = 4;
        ml_he.h_addr_list = ml_he_addrs;
        h_errno = ml_h_errno = 0;
        return &ml_he;
    }
}

const char *hstrerror(int code) {
    switch (code) {
    case 0:
        return "Success";
    case HOST_NOT_FOUND:
        return "Host not found";
    case TRY_AGAIN:
        return "Try again";
    case NO_RECOVERY:
        return "Non-recoverable error";
    case NO_DATA:
        return "No data";
    default:
        return "Unknown resolver error";
    }
}

struct hostent *gethostent(void) {
    /* Single static entry: localhost (no enumerator source). */
    return gethostbyname("localhost");
}

void sethostent(int stayopen) { (void)stayopen; }

void endhostent(void) {}

static char *ml_proto_alias[] = {0};
static struct protoent ml_pe;

struct protoent *getprotobyname(const char *name) {
    static const struct {
        const char *n;
        int p;
    } tab[] = {{"ip", 0},     {"icmp", 1},   {"tcp", 6},
               {"udp", 17},   {"ipv6", 41},  {"icmpv6", 58},
               {"raw", 255},  {0, 0}};
    int i;
    if (!name) return 0;
    for (i = 0; tab[i].n; i++) {
        if (strcmp(name, tab[i].n) == 0) {
            ml_pe.p_name = (char *)tab[i].n;
            ml_pe.p_aliases = ml_proto_alias;
            ml_pe.p_proto = tab[i].p;
            return &ml_pe;
        }
    }
    return 0;
}

struct protoent *getprotobynumber(int proto) {
    static const struct {
        const char *n;
        int p;
    } tab[] = {{"ip", 0},     {"icmp", 1},   {"tcp", 6},
               {"udp", 17},   {"ipv6", 41},  {"icmpv6", 58},
               {"raw", 255},  {0, 0}};
    int i;
    for (i = 0; tab[i].n; i++) {
        if (tab[i].p == proto) {
            ml_pe.p_name = (char *)tab[i].n;
            ml_pe.p_aliases = ml_proto_alias;
            ml_pe.p_proto = tab[i].p;
            return &ml_pe;
        }
    }
    return 0;
}

struct protoent *getprotoent(void) { return getprotobyname("tcp"); }

void setprotoent(int stayopen) { (void)stayopen; }

void endprotoent(void) {}

static char *ml_net_alias[] = {0};
static struct netent ml_ne;

struct netent *getnetbyname(const char *name) {
    if (!name) return 0;
    if (strcmp(name, "loopback") == 0 || strcmp(name, "loopback-net") == 0) {
        ml_ne.n_name = "loopback";
        ml_ne.n_aliases = ml_net_alias;
        ml_ne.n_addrtype = AF_INET;
        ml_ne.n_net = htonl(0x7F000000u);
        return &ml_ne;
    }
    return 0;
}

struct netent *getnetbyaddr(uint32_t net, int type) {
    if (type != AF_INET) return 0;
    if (net == htonl(0x7F000000u) || net == 0x7F000000u) {
        ml_ne.n_name = "loopback";
        ml_ne.n_aliases = ml_net_alias;
        ml_ne.n_addrtype = AF_INET;
        ml_ne.n_net = htonl(0x7F000000u);
        return &ml_ne;
    }
    return 0;
}

struct netent *getnetent(void) { return getnetbyname("loopback"); }

void setnetent(int stayopen) { (void)stayopen; }

void endnetent(void) {}
