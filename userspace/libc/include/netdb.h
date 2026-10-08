/* Moonlight libc - netdb. Numeric + localhost resolution only
 * (no DNS transport on this target); service names for well-known ports. */
#pragma once

#include <stdint.h>
#include <sys/socket.h>

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    unsigned ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct servent {
    char *s_name;
    char **s_aliases;
    int s_port;
    char *s_proto;
};

#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#define AI_NUMERICSERV 8
#define EAI_BADFLAGS -1
#define EAI_NONAME -2
#define EAI_FAMILY -6
#define EAI_SOCKTYPE -7
#define EAI_SERVICE -8
#define EAI_MEMORY -10
#define EAI_SYSTEM -11
#define NI_MAXHOST 64
#define NI_MAXSERV 16
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NI_NAMEREQD 4

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
int getnameinfo(const struct sockaddr *addr, unsigned addrlen, char *host,
                unsigned hostlen, char *serv, unsigned servlen, int flags);
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, unsigned len, int type);
extern int h_errno;
struct hostent *gethostent(void);
void sethostent(int stayopen);
void endhostent(void);
const char *hstrerror(int code);
#define HOST_NOT_FOUND 1
#define NO_DATA 4
#define NO_RECOVERY 3
#define TRY_AGAIN 2
struct protoent {
    char *p_name;
    char **p_aliases;
    int p_proto;
};
struct protoent *getprotobyname(const char *name);
struct protoent *getprotobynumber(int proto);
struct protoent *getprotoent(void);
void setprotoent(int stayopen);
void endprotoent(void);
struct netent {
    char *n_name;
    char **n_aliases;
    int n_addrtype;
    uint32_t n_net;
};
struct netent *getnetbyname(const char *name);
struct netent *getnetbyaddr(uint32_t net, int type);
struct netent *getnetent(void);
void setnetent(int stayopen);
void endnetent(void);
const char *gai_strerror(int code);
struct servent *getservbyname(const char *name, const char *proto);
struct servent *getservbyport(int port, const char *proto);
